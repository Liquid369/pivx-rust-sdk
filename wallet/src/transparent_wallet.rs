//! Transparent wallet: HD address management, UTXO tracking (from a block
//! scan or caller-supplied), coin selection, and sending. Complements the
//! shielded [`ShieldWallet`](crate::ShieldWallet); both derive from the seed.
//!
//! PIVX has no address index, so UTXOs are discovered either by scanning
//! blocks ([`scan`](TransparentWallet::scan)) or supplied by the caller
//! ([`add_utxo`](TransparentWallet::add_utxo)).
//!
//! Output recognition is deliberately narrow: only standard P2PKH outputs
//! (and the OP_EXCHANGEADDR-prefixed EXM encoding, which pays the same key)
//! are credited. P2PK outputs and cold-staking (P2CS) delegations paying our
//! keys are NOT detected — this wallet's transaction builder can only spend
//! P2PKH/EXM inputs, so crediting them would create unspendable balance.

use std::collections::{HashMap, HashSet};

use pivx_primitives::consensus::Network;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::error::WalletError;
use crate::transparent::{decode_address, derive_key, hash160, AddressKind};
use crate::transparent_tx::{build_transparent_tx, script_pubkey_for_address, TxInput, TxOutput};

/// Blocks a detected stale-tip reorg resets below the last-scanned height
/// before re-scanning. Any reorg at/below our tip changes that block's hash;
/// resetting a fixed window and re-scanning lets the UTXO model self-heal.
/// Identical to the JS SDK's `REORG_WINDOW` for cross-SDK parity.
const REORG_WINDOW: i64 = 100;

/// Upper bound for persisted heights/counters: JS `Number.MAX_SAFE_INTEGER`.
/// Both SDKs cap heights here so a saved state loads in both or neither.
const MAX_JS_SAFE: i64 = (1 << 53) - 1;

/// A tracked unspent transparent output we can spend.
#[derive(Clone)]
pub struct OwnedUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    /// hash160 of the key that controls it (index into the key map).
    pub key_hash: [u8; 20],
    /// True if this is a coinbase/coinstake output (spend-gated by maturity).
    pub coinbase: bool,
    /// Block height the output was confirmed at (0 if caller-supplied).
    pub height: i64,
}

/// PIVX dust threshold (sats) for an output whose scriptPubKey is `script_len`
/// bytes. Matches `GetDustThreshold` in src/policy/policy.cpp: the output plus
/// the 148-byte input to spend it, priced at dustRelayFee = 30000 sat/kB. For
/// our scripts (< 253 bytes) the CScript length prefix is one byte, so the
/// serialized output is `8 + 1 + script_len`. A standard 25-byte P2PKH gives
/// `(8+1+25+148) * 30000 / 1000 = 5460`.
fn dust_threshold(script_len: usize) -> u64 {
    (30_000 * (8 + 1 + script_len as u64 + 148)) / 1000
}

/// Coinbase/coinstake maturity in blocks (consensus.nCoinbaseMaturity,
/// src/chainparams.cpp): mainnet 100, testnet 15.
fn coinbase_maturity(network: Network) -> i64 {
    match network {
        Network::MainNetwork => 100,
        Network::TestNetwork => 15,
    }
}

/// 64 lowercase-or-uppercase hex chars — the only txid shape
/// [`save`](TransparentWallet::save)'s state format round-trips.
fn is_txid(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A confirmed transparent output as seen in a scanned transaction.
pub struct ScannedOutput {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

/// A spent transparent input as seen in a scanned transaction.
pub struct ScannedInput {
    pub txid: String,
    pub vout: u32,
}

/// Serialized transparent wallet state (version 1). Field names match the JS
/// SDK's format — states are interchangeable between the SDKs. No key
/// material: [`load`](TransparentWallet::load) re-derives keys from the seed.
#[derive(Serialize, Deserialize)]
struct TransparentState {
    version: u32,
    network: String,
    account: u32,
    gap: u32,
    #[serde(rename = "nextExternal")]
    next_external: usize,
    #[serde(rename = "nextChange")]
    next_change: usize,
    #[serde(rename = "lastScanned")]
    last_scanned: i64,
    #[serde(rename = "lastScannedHash")]
    last_scanned_hash: Option<String>,
    #[serde(rename = "scannedHashes", default)]
    scanned_hashes: Vec<ScannedHash>,
    utxos: Vec<StateUtxo>,
    pending: Vec<StateOutpoint>,
}

/// One `(height, hash)` in the rolling reorg window. Field order (height then
/// hash) is the JSON emission order — must match the JS SDK for byte parity.
#[derive(Serialize, Deserialize)]
struct ScannedHash {
    height: i64,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct StateUtxo {
    txid: String,
    vout: u32,
    amount: u64,
    #[serde(rename = "scriptPubKey")]
    script_pubkey: String,
    #[serde(rename = "keyHash")]
    key_hash: String,
    coinbase: bool,
    height: i64,
}

#[derive(Serialize, Deserialize)]
struct StateOutpoint {
    txid: String,
    vout: u32,
}

pub struct TransparentWallet {
    network: Network,
    /// BIP44 account / gap used at derivation, persisted so
    /// [`load`](Self::load) can re-derive the same keys.
    account: u32,
    gap: u32,
    /// hash160 → secret key, for our derived addresses (external + change).
    keys: HashMap<[u8; 20], SecretKey>,
    /// Ordered external receive addresses (for new_address / display).
    external: Vec<([u8; 20], String)>,
    next_external: usize,
    change: Vec<[u8; 20]>,
    next_change: usize,
    utxos: HashMap<(String, u32), OwnedUtxo>,
    /// Height of the last block passed to [`scan_block`](Self::scan_block).
    last_scanned: i64,
    /// Hash of that block, for reorg detection on the next scan.
    last_scanned_hash: Option<String>,
    /// Rolling window of the most recent `(height, hash)` pairs (at most
    /// REORG_WINDOW), walked back on a tip mismatch to locate the true fork.
    scanned_hashes: Vec<(i64, String)>,
    /// Outpoints reserved by an unfinalized [`build_send`](Self::build_send):
    /// excluded from selection and balance until `mark_spent` or `release`.
    pending: HashSet<(String, u32)>,
}

impl TransparentWallet {
    /// Derive `gap` external and `gap` change addresses from `seed` under
    /// account `account`. Only outputs to these addresses are recognized, so
    /// `gap` bounds how many unused addresses ahead are watched.
    pub fn new(seed: &[u8], network: Network, account: u32, gap: u32) -> Result<Self, WalletError> {
        // Accept a 32-byte raw seed OR a 64-byte BIP39 seed (MyPIVXWallet /
        // BIP39 seed-phrase wallets). BIP32 transparent derivation uses the
        // FULL seed, so a 64-byte BIP39 seed reproduces MyPIVXWallet (MPW) /
        // BIP39 seed-phrase wallet addresses.
        if seed.len() != 32 && seed.len() != 64 {
            return Err(WalletError::Other(
                "seed must be 32 bytes (raw) or 64 bytes (BIP39)".into(),
            ));
        }
        let mut keys = HashMap::new();
        let mut external = Vec::new();
        let mut change = Vec::new();
        for i in 0..gap {
            let ext = derive_key(seed, network, account, 0, i)?;
            let eh = hash160(&ext.public_key.serialize());
            external.push((eh, ext.address()));
            keys.insert(eh, ext.secret_key);
            let ch = derive_key(seed, network, account, 1, i)?;
            let chh = hash160(&ch.public_key.serialize());
            change.push(chh);
            keys.insert(chh, ch.secret_key);
        }
        Ok(Self {
            network,
            account,
            gap,
            keys,
            external,
            next_external: 0,
            change,
            next_change: 0,
            utxos: HashMap::new(),
            last_scanned: 0,
            last_scanned_hash: None,
            scanned_hashes: Vec::new(),
            pending: HashSet::new(),
        })
    }

    /// Next unused external receive address.
    pub fn new_address(&mut self) -> Result<String, WalletError> {
        let (_, addr) = self
            .external
            .get(self.next_external)
            .ok_or_else(|| WalletError::Other("address gap limit reached; increase gap".into()))?;
        let addr = addr.clone();
        self.next_external += 1;
        Ok(addr)
    }

    /// Next unused external address in the exchange (EXM/EXT) encoding, for
    /// receiving from an exchange that enforces transparent withdrawals.
    /// Shares the cursor with [`new_address`](Self::new_address): the same
    /// index's key backs both encodings, so its P2PKH form also pays this
    /// wallet.
    pub fn new_exchange_address(&mut self) -> Result<String, WalletError> {
        let (hash, _) = self
            .external
            .get(self.next_external)
            .ok_or_else(|| WalletError::Other("address gap limit reached; increase gap".into()))?;
        let addr = crate::transparent::encode_address(hash, self.network, AddressKind::Exchange);
        self.next_external += 1;
        Ok(addr)
    }

    fn next_change_hash(&mut self) -> Result<[u8; 20], WalletError> {
        let h = *self
            .change
            .get(self.next_change)
            .ok_or_else(|| WalletError::Other("change gap limit reached; increase gap".into()))?;
        self.next_change += 1;
        Ok(h)
    }

    /// hash160 from a scriptPubKey we can own: standard 25-byte P2PKH
    /// (76a914<20>88ac) or the 26-byte exchange script with an
    /// OP_EXCHANGEADDR (0xe0) prefix (e076a914<20>88ac) — PIVX
    /// src/script/standard.cpp Solver TX_EXCHANGEADDR.
    fn owned_script_hash(script: &[u8]) -> Option<[u8; 20]> {
        let body = match script.len() {
            25 => script,
            26 if script[0] == 0xe0 => &script[1..],
            _ => return None,
        };
        if body[0] == 0x76
            && body[1] == 0xa9
            && body[2] == 0x14
            && body[23] == 0x88
            && body[24] == 0xac
        {
            let mut h = [0u8; 20];
            h.copy_from_slice(&body[3..23]);
            Some(h)
        } else {
            None
        }
    }

    /// Add a caller-supplied UTXO if it pays one of our addresses. Assumed a
    /// normal (non-coinbase) spendable output; use `scan_block` for chain data
    /// where coinbase maturity is tracked.
    ///
    /// Returns false (not ours / not accepted) for values
    /// [`save`](Self::save)'s state format cannot round-trip: a non-64-hex
    /// txid, or an amount above the JS safe-integer bound (2^53 - 1).
    /// Accepting them would brick a later [`load`](Self::load).
    pub fn add_utxo(&mut self, txid: &str, vout: u32, amount: u64, script_pubkey: Vec<u8>) -> bool {
        self.insert_utxo(txid, vout, amount, script_pubkey, false, 0)
    }

    fn insert_utxo(
        &mut self,
        txid: &str,
        vout: u32,
        amount: u64,
        script_pubkey: Vec<u8>,
        coinbase: bool,
        height: i64,
    ) -> bool {
        // Apply load()'s validation predicates at insertion: anything the
        // state format cannot round-trip (in either SDK) is rejected here
        // instead of bricking a later load().
        if !is_txid(txid) || amount > (1u64 << 53) - 1 {
            return false;
        }
        match Self::owned_script_hash(&script_pubkey) {
            Some(h) if self.keys.contains_key(&h) => {
                self.utxos.insert(
                    (txid.to_string(), vout),
                    OwnedUtxo {
                        txid: txid.to_string(),
                        vout,
                        amount,
                        script_pubkey,
                        key_hash: h,
                        coinbase,
                        height,
                    },
                );
                true
            }
            _ => false,
        }
    }

    /// Apply a scanned block's transparent outputs (added if ours) and spent
    /// inputs (removed). Feed these from a decoded block (getblock verbosity 2).
    pub fn scan(&mut self, outputs: &[ScannedOutput], spent: &[ScannedInput]) {
        for o in outputs {
            self.add_utxo(&o.txid, o.vout, o.amount, o.script_pubkey.clone());
        }
        for s in spent {
            self.remove_utxo(&(s.txid.clone(), s.vout));
        }
    }

    /// Drop a UTXO and any reservation on it (spent on-chain — nothing left
    /// to reserve).
    fn remove_utxo(&mut self, key: &(String, u32)) {
        self.utxos.remove(key);
        self.pending.remove(key);
    }

    /// Scan one decoded block (`getblock <hash> 2`): credit every output that
    /// pays us and remove every tracked UTXO the block spends. Coinbase vins
    /// (no prevout `txid`) are skipped. Records the block's height and hash
    /// as the last scanned. Malformed tx/vout/vin entries are skipped, not
    /// fatal.
    ///
    /// Returns [`WalletError::ScanDiverged`] — before mutating anything — if
    /// this block claims to extend the last scanned one (height is exactly
    /// `last_scanned + 1`) but its `previousblockhash` differs from the hash
    /// we recorded: the chain reorganized under us. Recover with
    /// [`reset_scan`](Self::reset_scan) below the fork point and re-sync.
    /// Height jumps skip the continuity check. Also errors (state untouched)
    /// when `height` is missing or not an integer in [0, 2^53-1] — the bound
    /// both SDKs' state formats round-trip.
    pub fn scan_block(&mut self, block: &serde_json::Value) -> Result<(), WalletError> {
        // A missing/negative/fractional height would poison last_scanned and
        // brick the next load(), and one above 2^53-1 would load here but not
        // in the JS SDK. Both SDKs bound heights to [0, 2^53-1] so a saved
        // state loads in both or neither. Reject before mutating anything.
        let height = match block["height"].as_i64() {
            Some(h) if (0..=MAX_JS_SAFE).contains(&h) => h,
            _ => {
                return Err(WalletError::Other(format!(
                    "scan_block: block height must be an integer in [0, 2^53-1], got {}",
                    block["height"]
                )));
            }
        };
        if let Some(local) = self.last_scanned_hash.as_ref() {
            if height == self.last_scanned + 1 {
                if let Some(prev) = block["previousblockhash"].as_str() {
                    if prev != local {
                        return Err(WalletError::ScanDiverged {
                            height,
                            local: local.clone(),
                            node: prev.to_string(),
                        });
                    }
                }
            }
        }
        self.last_scanned = height;
        self.last_scanned_hash = block["hash"].as_str().map(str::to_string);
        // Record this block in the rolling window (same hash guard as
        // last_scanned_hash), trimming to the last REORG_WINDOW entries.
        // Re-scanning an already-recorded height (e.g. replaying a block
        // after a manual reset) first drops stale entries at/above it —
        // mirroring reset_scan's trim — so the window stays strictly
        // ascending, which load() requires.
        if let Some(hash) = self.last_scanned_hash.clone() {
            while self
                .scanned_hashes
                .last()
                .is_some_and(|(h, _)| *h >= self.last_scanned)
            {
                self.scanned_hashes.pop();
            }
            self.scanned_hashes.push((self.last_scanned, hash));
            let overflow = self
                .scanned_hashes
                .len()
                .saturating_sub(REORG_WINDOW as usize);
            if overflow > 0 {
                self.scanned_hashes.drain(0..overflow);
            }
        }
        let Some(txs) = block["tx"].as_array() else {
            return Ok(());
        };
        for tx in txs {
            let Some(txid) = tx["txid"].as_str() else {
                continue;
            };
            // Coinbase: first vin carries `coinbase` and no prevout. Coinstake
            // (PoS): a spending vin plus an EMPTY vout[0] — zero value AND
            // empty script, per CTxOut::IsEmpty (src/primitives/transaction.h).
            // Checking value alone would maturity-gate e.g. a zero-value
            // OP_RETURN tx paying us. Both are maturity-gated for spending
            // (src/txmempool.cpp).
            let first_vin = tx["vin"].get(0);
            let is_coinbase = first_vin.is_some_and(|v| v.get("coinbase").is_some());
            let is_coinstake = first_vin.is_some_and(|v| v.get("txid").is_some())
                && tx["vout"][0]["value"].as_f64() == Some(0.0)
                && tx["vout"][0]["scriptPubKey"]["hex"].as_str() == Some("");
            let coinbase = is_coinbase || is_coinstake;
            for vout in tx["vout"].as_array().into_iter().flatten() {
                let (Some(n), Some(value), Some(hex_str)) = (
                    vout["n"].as_u64(),
                    vout["value"].as_f64(),
                    vout["scriptPubKey"]["hex"].as_str(),
                ) else {
                    continue;
                };
                // Skip hostile vouts rather than mangling them: an
                // out-of-u32 index must not be truncated into someone
                // else's outpoint, and a negative value must not be
                // clamped to 0 (same skip semantics as the JS scanner).
                let Ok(n) = u32::try_from(n) else {
                    continue;
                };
                if value < 0.0 {
                    continue;
                }
                let Ok(script) = hex::decode(hex_str) else {
                    continue;
                };
                self.insert_utxo(
                    txid,
                    n,
                    (value * 1e8).round() as u64,
                    script,
                    coinbase,
                    height,
                );
            }
            for vin in tx["vin"].as_array().into_iter().flatten() {
                // Coinbase vins have no prevout `txid`.
                let (Some(prev), Some(vout)) = (vin["txid"].as_str(), vin["vout"].as_u64()) else {
                    continue;
                };
                self.remove_utxo(&(prev.to_string(), vout as u32));
            }
        }
        Ok(())
    }

    /// Height of the last block passed to [`scan_block`](Self::scan_block) (0 if none).
    pub fn last_scanned_block(&self) -> i64 {
        self.last_scanned
    }

    /// Recovery after [`scan_block`](Self::scan_block) returns
    /// [`ScanDiverged`](WalletError::ScanDiverged): reset to a height below
    /// the fork point, then re-sync. Drops every scanned UTXO (height > 0)
    /// above `height` and trims the reorg window to `height` — restoring the
    /// stored block hash from the retained window entry at `height`, or
    /// clearing it if none. Caller-supplied UTXOs (height 0) are kept.
    /// Reservations made by [`build_send`](Self::build_send) are PRESERVED:
    /// the re-scan may re-credit the same outpoints, and releasing them here
    /// would let a second send double-select inputs of a still-in-flight
    /// transaction. A reservation to an outpoint that never comes back is
    /// inert; a scan that observes the spend clears it, as do
    /// [`mark_spent`](Self::mark_spent) and [`release`](Self::release).
    ///
    /// Errors if `height` is above the last scanned block: reset_scan can
    /// only rewind — "resetting" forward would silently skip the blocks in
    /// between.
    pub fn reset_scan(&mut self, height: i64) -> Result<(), WalletError> {
        // A negative reset height would poison last_scanned (and drop UTXOs)
        // before bricking the next load(). Reject before mutating.
        if height < 0 {
            return Err(WalletError::Other(format!(
                "reset_scan height must be non-negative, got {height}"
            )));
        }
        if height > self.last_scanned {
            return Err(WalletError::Other(format!(
                "reset_scan height {height} is above the last scanned block {}",
                self.last_scanned
            )));
        }
        let dropped: Vec<(String, u32)> = self
            .utxos
            .iter()
            .filter(|(_, u)| u.height > 0 && u.height > height)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &dropped {
            self.utxos.remove(k);
        }
        self.last_scanned = height;
        // Trim the window to entries at/below the reset height and restore the
        // stored hash from the retained entry AT `height` (keeps continuity
        // when resetting to a known fork); a reset to a height not in the
        // window yields None, preserving prior behavior.
        self.scanned_hashes.retain(|(h, _)| *h <= height);
        self.last_scanned_hash = self
            .scanned_hashes
            .iter()
            .rev()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| hash.clone());
        Ok(())
    }

    /// Total transparent balance in satoshis, excluding outpoints reserved
    /// by an unfinalized [`build_send`](Self::build_send). Immature coinbase/
    /// coinstake outputs ARE counted here even though `build_send` cannot
    /// spend them yet — use [`spendable_balance`](Self::spendable_balance)
    /// for what a send can use.
    pub fn balance(&self) -> u64 {
        self.utxos
            .values()
            .filter(|u| !self.pending.contains(&(u.txid.clone(), u.vout)))
            .map(|u| u.amount)
            .fold(0u64, |a, v| a.saturating_add(v))
    }

    /// Balance actually selectable by [`build_send`](Self::build_send) right
    /// now: like [`balance`](Self::balance) but also excluding immature
    /// coinbase/coinstake outputs (the same maturity filter build_send
    /// applies).
    pub fn spendable_balance(&self) -> u64 {
        let maturity = coinbase_maturity(self.network);
        self.utxos
            .values()
            .filter(|u| !self.pending.contains(&(u.txid.clone(), u.vout)))
            .filter(|u| {
                !(u.coinbase
                    && self.last_scanned.saturating_sub(u.height).saturating_add(1) < maturity)
            })
            .map(|u| u.amount)
            .fold(0u64, |a, v| a.saturating_add(v))
    }

    /// All tracked UTXOs — including ones reserved by an unfinalized
    /// [`build_send`](Self::build_send), which [`balance`](Self::balance)
    /// excludes.
    pub fn utxos(&self) -> impl Iterator<Item = &OwnedUtxo> {
        self.utxos.values()
    }

    /// Serialized size (bytes) of one output: 8-byte value + scriptPubKey
    /// varint + script. An EXM output is a 26-byte script (35 bytes total),
    /// not the 34 a flat P2PKH assumes — undercounting it makes min-feerate
    /// exchange sends underpay and get node-rejected.
    fn output_size(script_len: usize) -> u64 {
        8 + if script_len < 0xfd { 1 } else { 3 } + script_len as u64
    }

    /// Estimated tx size (bytes) for `n_in` P2PKH inputs and `out_bytes` of
    /// serialized outputs (summed via [`output_size`](Self::output_size)).
    fn est_size(n_in: usize, out_bytes: u64) -> u64 {
        // +2: the input-count varint grows from 1 to 3 bytes at 253 inputs.
        (n_in as u64) * 148 + out_bytes + 10 + if n_in >= 253 { 2 } else { 0 }
    }

    /// Build and sign a transparent send of `amount` sats to `to`, selecting
    /// UTXOs largest-first and returning change to a fresh change address.
    /// `fee_per_byte` defaults to 100 sats/byte if None (well above relay).
    /// Returns the raw tx hex and the txids/vouts of the inputs it spends.
    pub fn build_send(
        &mut self,
        to: &str,
        amount: u64,
        fee_per_byte: Option<u64>,
    ) -> Result<(String, Vec<(String, u32)>), WalletError> {
        if amount == 0 {
            return Err(WalletError::Other(
                "amount must be greater than zero".into(),
            ));
        }
        // Below 10 sat/byte the node will not relay the tx: minRelayTxFee is
        // 10000 sat/kB (PIVX src/validation.cpp).
        if fee_per_byte.is_some_and(|f| f < 10) {
            return Err(WalletError::Other(
                "fee_per_byte must be at least 10 sat/byte (node minRelayTxFee = 10000 sat/kB)"
                    .into(),
            ));
        }
        let dest = decode_address(to)?;
        // A mainnet wallet must not build a send to a testnet-encoded address
        // (or vice versa): the 20-byte hash would be spent to this network's
        // equivalent of it — a silent loss. Reject the mismatch up front.
        if dest.network != self.network {
            return Err(WalletError::Other(
                "destination address is for a different network".into(),
            ));
        }
        // Reject cold-staking / unsupported destinations early.
        if matches!(dest.kind, AddressKind::Staking) {
            return Err(WalletError::Other(
                "sending to a cold-staking address is not supported".into(),
            ));
        }
        // Reject a recipient amount the node would drop as dust.
        let to_script = script_pubkey_for_address(to)?;
        if amount < dust_threshold(to_script.len()) {
            return Err(WalletError::Other(
                "amount is below the dust threshold".into(),
            ));
        }
        let feerate = fee_per_byte.unwrap_or(100);
        // Size outputs by their real scriptPubKey length: the recipient's actual
        // script (P2PKH 25, EXM 26, P2SH 23) plus a P2PKH change output (25).
        // Selection conservatively assumes change is emitted (2 outputs).
        let out_bytes = Self::output_size(to_script.len()) + Self::output_size(25);

        // Exclude immature coinbase/coinstake outputs: the node rejects a spend
        // of one before nCoinbaseMaturity confirmations. Depth is measured
        // against the last scanned block. Also exclude outpoints reserved by
        // an earlier build_send that has not been finalized or released.
        let maturity = coinbase_maturity(self.network);
        let mut avail: Vec<&OwnedUtxo> = self
            .utxos
            .values()
            .filter(|u| {
                !(u.coinbase
                    && self.last_scanned.saturating_sub(u.height).saturating_add(1) < maturity)
            })
            .filter(|u| !self.pending.contains(&(u.txid.clone(), u.vout)))
            .collect();
        avail.sort_by_key(|u| std::cmp::Reverse(u.amount)); // largest first

        // An absurd fee_per_byte must error, not wrap in release builds.
        let checked_fee = |n_in: usize| {
            feerate
                .checked_mul(Self::est_size(n_in, out_bytes))
                .ok_or_else(|| {
                    WalletError::Other(
                        "fee computation overflows: fee_per_byte is too large".into(),
                    )
                })
        };
        let mut selected: Vec<OwnedUtxo> = Vec::new();
        let mut total: u64 = 0;
        for u in avail {
            selected.push(u.clone());
            total = total.saturating_add(u.amount);
            // At/above MAX_STANDARD_TX_SIZE (100000, PIVX src/validation.h)
            // the node will never relay or mine the tx — policy rejects at
            // `sz >= 100000` (src/policy/policy.cpp) — so building it would
            // only doom it.
            if Self::est_size(selected.len(), out_bytes) >= 100_000 {
                return Err(WalletError::Other(
                    "transaction would exceed the 100kB standard size (too many small inputs); consolidate UTXOs first".into(),
                ));
            }
            let fee = checked_fee(selected.len())?;
            if total >= amount.saturating_add(fee) {
                break;
            }
        }
        let fee = checked_fee(selected.len())?;
        if total < amount.saturating_add(fee) {
            return Err(WalletError::InsufficientBalance);
        }
        let change_val = total - amount - fee;

        let mut outputs = vec![TxOutput {
            address: to.to_string(),
            amount,
        }];
        // Emit change only above both floors: the node's fixed dust threshold
        // (else the whole tx is rejected as dust) and the fee to later spend
        // the change input (else it is not economically worth keeping). Change
        // is always P2PKH (25-byte script).
        // saturating_mul: cannot exceed `fee` (est_size >= 226 > 148), which
        // checked_mul above already proved fits — saturation is belt-and-braces.
        if change_val > std::cmp::max(feerate.saturating_mul(148), dust_threshold(25)) {
            let ch_hash = self.next_change_hash()?;
            let ch_addr =
                crate::transparent::encode_address(&ch_hash, self.network, AddressKind::P2pkh);
            outputs.push(TxOutput {
                address: ch_addr,
                amount: change_val,
            });
        }

        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                txid: u.txid.clone(),
                vout: u.vout,
                amount: u.amount,
                script_pubkey: u.script_pubkey.clone(),
                secret_key: *self
                    .keys
                    .get(&u.key_hash)
                    .expect("selected utxo has a known key"),
            })
            .collect();
        let spent: Vec<(String, u32)> = selected.iter().map(|u| (u.txid.clone(), u.vout)).collect();
        let hex = build_transparent_tx(&inputs, &outputs, 0)?;
        // Reserve the inputs so a second build_send before mark_spent/release
        // cannot double-select them.
        self.pending.extend(spent.iter().cloned());
        Ok((hex, spent))
    }

    /// Mark inputs spent after a confirmed broadcast: removes them from the
    /// UTXO set and finalizes their reservation.
    pub fn mark_spent(&mut self, spent: &[(String, u32)]) {
        for key in spent {
            self.utxos.remove(key);
            self.pending.remove(key);
        }
    }

    /// Un-reserve outpoints from a [`build_send`](Self::build_send) whose
    /// broadcast was DEFINITIVELY rejected: they become selectable again.
    /// Do not release while the tx might still confirm — a later send could
    /// double-spend the inputs.
    pub fn release(&mut self, spent: &[(String, u32)]) {
        for key in spent {
            self.pending.remove(key);
        }
    }

    /// Serialize wallet state to JSON (same format as the JS SDK, version 1).
    /// No key material is included — restore with [`load`](Self::load) and
    /// the seed.
    pub fn save(&self) -> String {
        let mut utxos: Vec<StateUtxo> = self
            .utxos
            .values()
            .map(|u| StateUtxo {
                txid: u.txid.clone(),
                vout: u.vout,
                amount: u.amount,
                script_pubkey: hex::encode(&u.script_pubkey),
                key_hash: hex::encode(u.key_hash),
                coinbase: u.coinbase,
                height: u.height,
            })
            .collect();
        utxos.sort_unstable_by(|a, b| (a.txid.as_str(), a.vout).cmp(&(b.txid.as_str(), b.vout)));
        let mut pending: Vec<StateOutpoint> = self
            .pending
            .iter()
            .map(|(txid, vout)| StateOutpoint {
                txid: txid.clone(),
                vout: *vout,
            })
            .collect();
        pending.sort_unstable_by(|a, b| (a.txid.as_str(), a.vout).cmp(&(b.txid.as_str(), b.vout)));
        let scanned_hashes: Vec<ScannedHash> = self
            .scanned_hashes
            .iter()
            .map(|(height, hash)| ScannedHash {
                height: *height,
                hash: hash.clone(),
            })
            .collect();
        serde_json::to_string(&TransparentState {
            version: 1,
            network: match self.network {
                Network::MainNetwork => "mainnet".into(),
                Network::TestNetwork => "testnet".into(),
            },
            account: self.account,
            gap: self.gap,
            next_external: self.next_external,
            next_change: self.next_change,
            last_scanned: self.last_scanned,
            last_scanned_hash: self.last_scanned_hash.clone(),
            scanned_hashes,
            utxos,
            pending,
        })
        .expect("wallet state is always serializable")
    }

    /// Restore from [`save`](Self::save) output, re-deriving keys from
    /// `seed`. The state must belong to this seed: a UTXO whose key hash is
    /// not among the derived keys is rejected ("state does not match seed").
    pub fn load(seed: &[u8], state: &str) -> Result<Self, WalletError> {
        let s: TransparentState = serde_json::from_str(state)?;
        if s.version != 1 {
            return Err(WalletError::Other(format!(
                "unsupported wallet state version {}",
                s.version
            )));
        }
        let network = match s.network.as_str() {
            "mainnet" => Network::MainNetwork,
            "testnet" => Network::TestNetwork,
            other => return Err(WalletError::Other(format!("unknown network {other}"))),
        };
        // Bound attacker-controlled derivation work: load() re-derives 2*gap
        // keys, so an oversized gap in a hostile state file is a hang-on-load
        // DoS. account must fit a hardened BIP32 index. (Same caps as JS.)
        if s.gap > 10_000 {
            return Err(WalletError::Other(
                "wallet state gap exceeds the supported maximum (10000)".into(),
            ));
        }
        if s.account >= 0x8000_0000 {
            return Err(WalletError::Other(
                "wallet state account exceeds the BIP32 hardened range".into(),
            ));
        }
        // Bound last_scanned to [0, 2^53-1], symmetric with scan_block, so a
        // hostile huge height can't overflow the maturity math or load here but
        // not in the JS SDK.
        if !(0..=MAX_JS_SAFE).contains(&s.last_scanned) {
            return Err(WalletError::Other(
                "wallet state last-scanned height must be in [0, 2^53-1]".into(),
            ));
        }
        let mut w = Self::new(seed, network, s.account, s.gap)?;
        w.next_external = s.next_external;
        w.next_change = s.next_change;
        w.last_scanned = s.last_scanned;
        w.last_scanned_hash = s.last_scanned_hash;
        // Restore the reorg window (absent in older states → empty via serde
        // default). Honest save() output is sorted ascending, unique, at most
        // REORG_WINDOW entries, every height <= last_scanned; the sync walk-back
        // trusts that shape, so reject any window that violates it. Keep the
        // per-entry negative-height check (matching the last_scanned guard).
        if s.scanned_hashes.len() as i64 > REORG_WINDOW {
            return Err(WalletError::Other(
                "wallet state contains an invalid scanned-hash window".into(),
            ));
        }
        let mut prev: Option<i64> = None;
        for e in &s.scanned_hashes {
            if e.height < 0 {
                return Err(WalletError::Other(
                    "wallet state has a negative scanned-hash height".into(),
                ));
            }
            // Strictly ascending (implies unique) and no future entry (the
            // newest window entry is the last scanned block).
            if e.height > s.last_scanned || prev.is_some_and(|p| e.height <= p) {
                return Err(WalletError::Other(
                    "wallet state contains an invalid scanned-hash window".into(),
                ));
            }
            prev = Some(e.height);
        }
        w.scanned_hashes = s
            .scanned_hashes
            .into_iter()
            .map(|e| (e.height, e.hash))
            .collect();
        for u in s.utxos {
            // Same bounds as the JS SDK so a state either loads in both or
            // neither: 64-hex txid, amount within JS safe-integer range,
            // non-negative height.
            if !is_txid(&u.txid)
                || u.amount > (1u64 << 53) - 1
                || !(0..=MAX_JS_SAFE).contains(&u.height)
            {
                return Err(WalletError::Other("malformed utxo in state".into()));
            }
            let script_pubkey = hex::decode(&u.script_pubkey)
                .map_err(|_| WalletError::Other("invalid scriptPubKey hex in state".into()))?;
            // Lowercase-only, like the JS SDK (which compares the hex string
            // against its lowercase key map): a state loads in both or neither.
            if u.key_hash.chars().any(|c| c.is_ascii_uppercase()) {
                return Err(WalletError::Other("invalid keyHash in state".into()));
            }
            let key_hash: [u8; 20] = hex::decode(&u.key_hash)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| WalletError::Other("invalid keyHash in state".into()))?;
            if !w.keys.contains_key(&key_hash) {
                return Err(WalletError::Other(
                    "state does not match seed: unknown key hash".into(),
                ));
            }
            // The scriptPubKey must actually pay the claimed key: otherwise a
            // hostile state file could make build_send sign an arbitrary
            // foreign script (used verbatim as the sighash scriptCode) with
            // our key.
            if Self::owned_script_hash(&script_pubkey) != Some(key_hash) {
                return Err(WalletError::Other(
                    "wallet state contains a utxo whose script does not pay its key hash".into(),
                ));
            }
            w.utxos.insert(
                (u.txid.clone(), u.vout),
                OwnedUtxo {
                    txid: u.txid,
                    vout: u.vout,
                    amount: u.amount,
                    script_pubkey,
                    key_hash,
                    coinbase: u.coinbase,
                    height: u.height,
                },
            );
        }
        for p in &s.pending {
            if !is_txid(&p.txid) {
                return Err(WalletError::Other(
                    "malformed pending entry in state".into(),
                ));
            }
        }
        w.pending = s.pending.into_iter().map(|p| (p.txid, p.vout)).collect();
        Ok(w)
    }
}

#[cfg(feature = "rpc")]
impl TransparentWallet {
    /// Scan the node's chain into the wallet, from `max(from_height,
    /// last_scanned + 1)` up to the current tip, fetching each block with
    /// `getblockhash` + `getblock(hash, 2)` and feeding it to
    /// [`scan_block`](Self::scan_block). Fetches in windows of `batch_size`.
    ///
    /// Like the shield wallet's sync this is a chain-data pull, not chain
    /// authentication: point it at a node you trust. See SECURITY.md.
    pub async fn sync(
        &mut self,
        client: &pivx_rpc::PivxClient,
        from_height: i64,
        batch_size: i64,
    ) -> Result<(), WalletError> {
        let tip = client.get_block_count().await?;
        let batch = batch_size.max(1);
        // Stale-tip reorg self-heal: the forward scan below only re-examines
        // blocks above last_scanned, so a reorg at/below our tip (which changes
        // that block's hash without changing the tip height) would go unnoticed
        // and leave an orphaned deposit credited. Compare the node's current
        // hash for last_scanned against the stored one; on a mismatch, walk the
        // recorded hash window back to the true fork and reset there.
        if self.last_scanned > 0 {
            if let Some(local) = self.last_scanned_hash.clone() {
                let node_tip = client.get_block_hash(self.last_scanned).await?;
                if node_tip != local {
                    // Reorg: walk the stored window newest→oldest for the
                    // highest height the node still agrees on (the true fork).
                    // Found → rewind there and forward-scan. None matches → the
                    // reorg is deeper than the window; fail safe rather than
                    // silently retain orphaned UTXOs below a fixed reset floor.
                    let mut fork = None;
                    for (h, hash) in self.scanned_hashes.clone().into_iter().rev() {
                        if client.get_block_hash(h).await? == hash {
                            fork = Some(h);
                            break;
                        }
                    }
                    match fork {
                        Some(f) => self.reset_scan(f)?,
                        None => {
                            return Err(WalletError::ScanDiverged {
                                height: self.last_scanned,
                                local,
                                node: node_tip,
                            });
                        }
                    }
                }
            }
        }
        let mut from = from_height.max(self.last_scanned + 1);
        while from <= tip {
            let to = (from + batch - 1).min(tip);
            for h in from..=to {
                let hash = client.get_block_hash(h).await?;
                let block = client.get_block(&hash, 2).await?;
                // getblock verbosity 2 always carries these; a block without
                // them would silently disable the reorg continuity check, so
                // treat it as a malformed node response.
                if block["hash"].as_str().is_none() || block["previousblockhash"].as_str().is_none()
                {
                    return Err(WalletError::Other(format!(
                        "node returned a block without hash/previousblockhash at height {h}"
                    )));
                }
                self.scan_block(&block)?;
            }
            from = to + 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::p2pkh_address;
    use crate::transparent_tx::script_pubkey_for_address;
    use pivx_primitives::consensus::Network::MainNetwork;

    fn spk(addr: &str) -> Vec<u8> {
        script_pubkey_for_address(addr).unwrap()
    }

    #[test]
    fn tracks_and_selects_utxos() {
        let seed = [3u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 20).unwrap();
        // Our first external address' scriptPubKey.
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        assert!(w.add_utxo("aa".repeat(32).as_str(), 0, 200_000_000, s0.clone()));
        // A UTXO not ours is ignored.
        let other = derive_key(&[9u8; 32], MainNetwork, 0, 0, 0).unwrap();
        assert!(!w.add_utxo(
            "bb".repeat(32).as_str(),
            0,
            5,
            spk(&p2pkh_address(&other.public_key, MainNetwork))
        ));
        assert_eq!(w.balance(), 200_000_000);

        // Send half; expect a valid tx and one input selected.
        let dest = p2pkh_address(&other.public_key, MainNetwork);
        let (hex, spent) = w.build_send(&dest, 100_000_000, Some(100)).unwrap();
        assert!(hex.starts_with("01000000"));
        assert_eq!(spent.len(), 1);
        w.mark_spent(&spent);
        assert_eq!(w.balance(), 0);
    }

    #[test]
    fn scan_block_credits_and_spends() {
        let seed = [7u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 20).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let spk_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));

        // Block 100: a tx paying us 1.5 PIV at vout 0 (coinbase vin skipped).
        let block1 = serde_json::json!({
            "height": 100,
            "tx": [{
                "txid": "aa".repeat(32),
                "vin": [{ "coinbase": "00" }],
                "vout": [{ "n": 0, "value": 1.5, "scriptPubKey": { "hex": spk_hex } }],
            }],
        });
        w.scan_block(&block1).unwrap();
        assert_eq!(w.balance(), 150_000_000);
        assert_eq!(w.last_scanned_block(), 100);

        // Block 101: a tx spending that UTXO (aa:0).
        let block2 = serde_json::json!({
            "height": 101,
            "tx": [{
                "txid": "bb".repeat(32),
                "vin": [{ "txid": "aa".repeat(32), "vout": 0 }],
                "vout": [],
            }],
        });
        w.scan_block(&block2).unwrap();
        assert_eq!(w.balance(), 0);
        assert_eq!(w.last_scanned_block(), 101);
    }

    #[test]
    fn insufficient_balance_errs() {
        let seed = [4u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        w.add_utxo(
            "cc".repeat(32).as_str(),
            0,
            1000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        assert!(matches!(
            w.build_send(&dest, 100_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
    }

    #[test]
    fn build_send_rejects_bad_destinations_and_dust() {
        use pivx_primitives::consensus::Network::TestNetwork;
        let seed = [5u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        w.add_utxo(
            "cc".repeat(32).as_str(),
            0,
            200_000_000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        // Wrong-network destination is rejected, not silently sent.
        let testnet_dest = p2pkh_address(&a0.public_key, TestNetwork);
        assert!(w.build_send(&testnet_dest, 100_000_000, Some(100)).is_err());
        // Below the 5460-sat dust threshold is rejected.
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        assert!(w.build_send(&dest, 5000, Some(100)).is_err());
        // At/above dust it builds.
        assert!(w.build_send(&dest, 100_000_000, Some(100)).is_ok());
    }

    #[test]
    fn build_send_rejects_zero_fee_per_byte() {
        let seed = [8u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        w.add_utxo(
            "cc".repeat(32).as_str(),
            0,
            200_000_000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        // Some(0) would build a zero-fee tx the network won't relay.
        let err = w.build_send(&dest, 100_000_000, Some(0)).unwrap_err();
        assert!(err.to_string().contains("fee_per_byte"));
        // None (default feerate) still builds.
        assert!(w.build_send(&dest, 100_000_000, None).is_ok());
    }

    #[test]
    fn immature_coinbase_is_not_spendable() {
        let seed = [6u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let spk_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        // Coinbase output at height 100.
        let coinbase_block = serde_json::json!({
            "height": 100,
            "tx": [{
                "txid": "dd".repeat(32),
                "vin": [{ "coinbase": "00" }],
                "vout": [{ "n": 0, "value": 5.0, "scriptPubKey": { "hex": spk_hex } }],
            }],
        });
        w.scan_block(&coinbase_block).unwrap();
        assert_eq!(w.balance(), 500_000_000);
        // Only 1 confirmation: immature, cannot be selected.
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        assert!(matches!(
            w.build_send(&dest, 100_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
        // Advance to maturity (100 confirmations): now spendable.
        w.scan_block(&serde_json::json!({ "height": 199, "tx": [] }))
            .unwrap();
        assert!(w.build_send(&dest, 100_000_000, Some(100)).is_ok());
    }

    #[test]
    fn exchange_script_credits_and_spends() {
        let seed = [10u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        // 26-byte exchange script: OP_EXCHANGEADDR (0xe0) + standard P2PKH.
        let mut exm = vec![0xe0];
        exm.extend_from_slice(&spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        // scan_block credits it (non-coinbase tx: spendable immediately).
        let block = serde_json::json!({
            "height": 10,
            "tx": [{
                "txid": "ee".repeat(32),
                "vin": [{ "txid": "ff".repeat(32), "vout": 0 }],
                "vout": [{ "n": 0, "value": 2.0, "scriptPubKey": { "hex": hex::encode(&exm) } }],
            }],
        });
        w.scan_block(&block).unwrap();
        assert_eq!(w.balance(), 200_000_000);
        // add_utxo accepts the exchange encoding too.
        assert!(w.add_utxo("ab".repeat(32).as_str(), 1, 100_000_000, exm.clone()));
        assert_eq!(w.balance(), 300_000_000);
        // Spending exchange-script UTXOs builds a valid tx.
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        let (hex, spent) = w.build_send(&dest, 250_000_000, Some(100)).unwrap();
        assert!(hex.starts_with("01000000"));
        assert_eq!(spent.len(), 2);
    }

    #[test]
    fn new_exchange_address_matches_next_index() {
        let seed = [11u8; 32];
        let mut a = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let mut b = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let exm = a.new_exchange_address().unwrap();
        let p2pkh = b.new_address().unwrap();
        assert!(exm.starts_with("EXM"));
        // Same underlying hash as the same index's P2PKH form.
        let dx = decode_address(&exm).unwrap();
        let dp = decode_address(&p2pkh).unwrap();
        assert_eq!(dx.kind, AddressKind::Exchange);
        assert_eq!(dx.hash, dp.hash);
        // The shared cursor advanced past index 0.
        assert_ne!(a.new_address().unwrap(), p2pkh);
    }

    #[test]
    fn save_load_round_trip() {
        let seed = [12u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        w.new_address().unwrap();
        w.add_utxo("aa".repeat(32).as_str(), 0, 300_000_000, s0.clone());
        // A scanned coinbase UTXO with a height, plus a recorded block hash.
        let block = serde_json::json!({
            "height": 50,
            "hash": "0b".repeat(32),
            "tx": [{
                "txid": "cd".repeat(32),
                "vin": [{ "coinbase": "00" }],
                "vout": [{ "n": 0, "value": 4.0, "scriptPubKey": { "hex": hex::encode(&s0) } }],
            }],
        });
        w.scan_block(&block).unwrap();
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        // Reserve aa:0 so pending is non-empty in the saved state.
        let (_, spent) = w.build_send(&dest, 100_000_000, Some(100)).unwrap();
        let json = w.save();
        assert!(!json.contains("secret") && !json.contains(&hex::encode(seed)));
        // The reorg window (block 50) is persisted and round-trips.
        assert!(json.contains(
            "\"scannedHashes\":[{\"height\":50,\"hash\":\"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\"}]"
        ));

        let mut r = TransparentWallet::load(&seed, &json).unwrap();
        assert_eq!(r.last_scanned_block(), 50);
        assert_eq!(r.utxos().count(), 2);
        // Pending reservation preserved: balance excludes aa:0 in both.
        assert_eq!(r.balance(), w.balance());
        // Everything (cursors, hash, utxos, pending) survives: saving the
        // loaded wallet reproduces the exact same state.
        assert_eq!(r.save(), json);
        // The loaded wallet can spend: release the reservation and rebuild.
        r.release(&spent);
        assert!(r.build_send(&dest, 100_000_000, Some(100)).is_ok());
    }

    #[test]
    fn load_with_wrong_seed_rejects() {
        let seed = [12u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        w.add_utxo(
            "aa".repeat(32).as_str(),
            0,
            300_000_000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        let json = w.save();
        // (match, not unwrap_err: the wallet holds keys and derives no Debug)
        let Err(err) = TransparentWallet::load(&[99u8; 32], &json) else {
            panic!("load with the wrong seed must fail");
        };
        assert!(err.to_string().contains("does not match"));
    }

    /// load must reject a scanned-hash window that violates the shape honest
    /// save() always emits (ascending, unique, ≤ REORG_WINDOW, all ≤ lastScanned),
    /// because the sync walk-back trusts array order and entry heights.
    fn state_with_window(last_scanned: i64, heights: &[i64]) -> ([u8; 32], String) {
        let seed = [21u8; 32];
        let w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let mut st: serde_json::Value = serde_json::from_str(&w.save()).unwrap();
        st["lastScanned"] = serde_json::json!(last_scanned);
        st["scannedHashes"] = serde_json::json!(heights
            .iter()
            .map(|h| serde_json::json!({ "height": h, "hash": "0b".repeat(32) }))
            .collect::<Vec<_>>());
        (seed, st.to_string())
    }

    #[test]
    fn load_rejects_future_window_entry() {
        let (seed, state) = state_with_window(50, &[51]);
        let Err(err) = TransparentWallet::load(&seed, &state) else {
            panic!("load must reject a window entry above lastScanned");
        };
        assert!(err.to_string().contains("invalid scanned-hash window"));
    }

    #[test]
    fn load_rejects_non_ascending_window() {
        let (seed, state) = state_with_window(60, &[50, 50]);
        let Err(err) = TransparentWallet::load(&seed, &state) else {
            panic!("load must reject a duplicate/non-ascending window");
        };
        assert!(err.to_string().contains("invalid scanned-hash window"));
    }

    #[test]
    fn load_rejects_oversized_window() {
        let heights: Vec<i64> = (1..=REORG_WINDOW + 1).collect();
        let (seed, state) = state_with_window(REORG_WINDOW + 10, &heights);
        let Err(err) = TransparentWallet::load(&seed, &state) else {
            panic!("load must reject a window longer than REORG_WINDOW");
        };
        assert!(err.to_string().contains("invalid scanned-hash window"));
    }

    #[test]
    fn reservation_excludes_and_releases() {
        let seed = [13u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        w.add_utxo("aa".repeat(32).as_str(), 0, 200_000_000, s0.clone());
        w.add_utxo("bb".repeat(32).as_str(), 0, 200_000_000, s0.clone());
        let dest = p2pkh_address(&a0.public_key, MainNetwork);

        // Two sends without mark_spent select disjoint UTXOs.
        let (_, s1) = w.build_send(&dest, 100_000_000, Some(100)).unwrap();
        assert_eq!(w.balance(), 200_000_000); // reserved outpoint excluded
        let (_, s2) = w.build_send(&dest, 100_000_000, Some(100)).unwrap();
        assert_ne!(s1, s2);
        assert_eq!(w.balance(), 0);
        // Everything reserved: a third send has nothing to select.
        assert!(matches!(
            w.build_send(&dest, 100_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
        // Release the second (definitively rejected): selectable again.
        w.release(&s2);
        assert_eq!(w.balance(), 200_000_000);
        assert!(w.build_send(&dest, 100_000_000, Some(100)).is_ok());
        // Finalize the first: gone from the UTXO set entirely.
        w.mark_spent(&s1);
        assert_eq!(w.utxos().count(), 1);
    }

    #[test]
    fn reorg_detection_and_reset() {
        let seed = [14u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        // Caller-supplied UTXO (height 0): must survive reset_scan.
        w.add_utxo("00".repeat(32).as_str(), 0, 50_000_000, s0.clone());
        // Block 100 (hash aa..) pays us 1 PIV.
        let block_a = serde_json::json!({
            "height": 100,
            "hash": "aa".repeat(32),
            "tx": [{
                "txid": "e1".repeat(32),
                "vin": [{ "txid": "f1".repeat(32), "vout": 0 }],
                "vout": [{ "n": 0, "value": 1.0, "scriptPubKey": { "hex": hex::encode(&s0) } }],
            }],
        });
        w.scan_block(&block_a).unwrap();
        assert_eq!(w.balance(), 150_000_000);
        // Reserve the scanned UTXO (largest-first selects the 1-PIV one).
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        let (_, spent) = w.build_send(&dest, 60_000_000, Some(100)).unwrap();
        assert_eq!(spent[0].0, "e1".repeat(32));

        // Block 101 claims a different parent: divergence, nothing mutated —
        // the UTXO this block would have spent is still tracked.
        let bad = serde_json::json!({
            "height": 101,
            "hash": "cc".repeat(32),
            "previousblockhash": "bb".repeat(32),
            "tx": [{
                "txid": "d1".repeat(32),
                "vin": [{ "txid": "e1".repeat(32), "vout": 0 }],
                "vout": [],
            }],
        });
        let err = w.scan_block(&bad).unwrap_err();
        assert!(matches!(err, WalletError::ScanDiverged { .. }));
        assert_eq!(w.last_scanned_block(), 100);
        assert_eq!(w.utxos().count(), 2);

        // Recover below the fork: the scanned UTXO is dropped but its
        // reservation is PRESERVED (the tx spending it may still be in
        // flight); the caller-supplied UTXO is kept.
        w.reset_scan(99).unwrap();
        assert_eq!(w.last_scanned_block(), 99);
        assert_eq!(w.balance(), 50_000_000);
        let st: serde_json::Value = serde_json::from_str(&w.save()).unwrap();
        assert_eq!(st["pending"].as_array().unwrap().len(), 1);
        assert!(st["lastScannedHash"].is_null());

        // Re-scan block 100, then a height jump (105) with an unrelated
        // parent hash: continuity is only checked for exactly +1.
        w.scan_block(&block_a).unwrap();
        let jump = serde_json::json!({
            "height": 105,
            "hash": "dd".repeat(32),
            "previousblockhash": "99".repeat(32),
            "tx": [],
        });
        w.scan_block(&jump).unwrap();
        assert_eq!(w.last_scanned_block(), 105);
    }

    // Cross-SDK state fixture: this exact JSON is what BOTH SDKs' save() must
    // emit for the recipe below (the JS suite byte-compares the same string).
    // Any change to the state format must update both suites together.
    const CROSS_SDK_STATE: &str = "{\"version\":1,\"network\":\"mainnet\",\"account\":0,\"gap\":3,\"nextExternal\":1,\"nextChange\":1,\"lastScanned\":7,\"lastScannedHash\":\"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\",\"scannedHashes\":[{\"height\":7,\"hash\":\"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\"}],\"utxos\":[{\"txid\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"vout\":0,\"amount\":123456789,\"scriptPubKey\":\"76a9149fae9617b8665480001546cf2825fcc6465e0c3288ac\",\"keyHash\":\"9fae9617b8665480001546cf2825fcc6465e0c32\",\"coinbase\":false,\"height\":0},{\"txid\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"vout\":0,\"amount\":100000000,\"scriptPubKey\":\"76a9149fae9617b8665480001546cf2825fcc6465e0c3288ac\",\"keyHash\":\"9fae9617b8665480001546cf2825fcc6465e0c32\",\"coinbase\":true,\"height\":7}],\"pending\":[{\"txid\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"vout\":0}]}";

    #[test]
    fn save_is_byte_identical_to_js_sdk_for_shared_recipe() {
        let seed = [1u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 3).unwrap();
        let addr0 = w.new_address().unwrap();
        assert_eq!(addr0, "DKhR8EBzgqFh7D98cxS1FDJYtdgEMyWvZ9"); // locked cross-SDK
        w.add_utxo("aa".repeat(32).as_str(), 0, 123_456_789, spk(&addr0));
        let spk_hex = hex::encode(spk(&addr0));
        let block = serde_json::json!({
            "height": 7,
            "hash": "0b".repeat(32),
            "tx": [{
                "txid": "cd".repeat(32),
                "vin": [{ "coinbase": "00" }],
                "vout": [{ "n": 0, "value": 1.0, "scriptPubKey": { "hex": spk_hex } }],
            }],
        });
        w.scan_block(&block).unwrap();
        w.build_send(&addr0, 50_000_000, Some(100)).unwrap();
        assert_eq!(w.save(), CROSS_SDK_STATE);
    }

    #[test]
    fn loads_js_sdk_saved_state_and_restores_every_field() {
        let seed = [1u8; 32];
        let w = TransparentWallet::load(&seed, CROSS_SDK_STATE).unwrap();
        assert_eq!(w.last_scanned_block(), 7);
        // The reorg window survived the load: re-saving reproduces it exactly.
        assert_eq!(w.save(), CROSS_SDK_STATE);
        // aa:0 reserved; coinbase counted (maturity gates spend, not balance).
        assert_eq!(w.balance(), 100_000_000);
        assert_eq!(w.utxos().count(), 2);
        // Reservation survived: only the immature coinbase remains.
        let mut w = w;
        assert!(matches!(
            w.build_send("DKhR8EBzgqFh7D98cxS1FDJYtdgEMyWvZ9", 50_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
        // Cursors survived: next external is index 1, not 0.
        assert_ne!(
            w.new_address().unwrap(),
            "DKhR8EBzgqFh7D98cxS1FDJYtdgEMyWvZ9"
        );
    }

    #[test]
    fn load_rejects_hostile_states() {
        let seed = [1u8; 32];
        // Foreign scriptPubKey paired with a valid (seed-derived) keyHash: the
        // wallet must not sign an arbitrary script with its key.
        let foreign = CROSS_SDK_STATE.replace(
            "76a9149fae9617b8665480001546cf2825fcc6465e0c3288ac",
            "76a914000000000000000000000000000000000000000088ac",
        );
        // (.err().unwrap(): the wallet holds keys and derives no Debug, so
        // Result::unwrap_err is unavailable.)
        assert!(TransparentWallet::load(&seed, &foreign)
            .err()
            .unwrap()
            .to_string()
            .contains("does not pay its key hash"));
        // Oversized gap: hang-on-load derivation DoS.
        let big_gap = CROSS_SDK_STATE.replace("\"gap\":3", "\"gap\":20000");
        assert!(TransparentWallet::load(&seed, &big_gap)
            .err()
            .unwrap()
            .to_string()
            .contains("gap"));
        // Malformed txid (not 64-hex).
        let bad_txid = CROSS_SDK_STATE.replace(
            "\"txid\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"vout\":0,\"amount\":123456789",
            "\"txid\":\"aa:aa\",\"vout\":0,\"amount\":123456789",
        );
        assert!(TransparentWallet::load(&seed, &bad_txid).is_err());
        // Amount above the JS safe-integer bound must fail in BOTH SDKs.
        let big_amount = CROSS_SDK_STATE.replace("123456789", "9007199254740993");
        assert!(TransparentWallet::load(&seed, &big_amount).is_err());
    }

    #[test]
    fn scan_spend_clears_reservation() {
        let seed = [3u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 20).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        w.add_utxo(
            "aa".repeat(32).as_str(),
            0,
            200_000_000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        w.build_send(&dest, 100_000_000, Some(100)).unwrap(); // reserves aa:0
                                                              // Someone spends aa:0 on-chain (e.g. our own broadcast confirming):
                                                              // the reservation must not outlive the UTXO in the saved state.
        let block = serde_json::json!({
            "height": 50,
            "hash": "0c".repeat(32),
            "tx": [{ "txid": "bb".repeat(32), "vin": [{ "txid": "aa".repeat(32), "vout": 0 }], "vout": [] }],
        });
        w.scan_block(&block).unwrap();
        let st: serde_json::Value = serde_json::from_str(&w.save()).unwrap();
        assert!(st["pending"].as_array().unwrap().is_empty());
        assert!(st["utxos"].as_array().unwrap().is_empty());
    }

    /// Minimal loopback JSON-RPC stub: `handler` maps a raw request body to
    /// the JSON `result` value, served until the client stops. Lets a test
    /// answer per-height (e.g. getblockhash) instead of one value per method.
    #[cfg(feature = "rpc")]
    fn stub_node_fn<F>(handler: F) -> String
    where
        F: Fn(&str) -> String + Send + 'static,
    {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let req = String::from_utf8_lossy(&buf[..n]);
                let result = handler(&req);
                // Echo the request id: the client verifies response id ==
                // request id and rejects a mismatched reply.
                let id: u64 = req
                    .split("\"id\":")
                    .nth(1)
                    .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let body = format!("{{\"result\":{result},\"error\":null,\"id\":{id}}}");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
        url
    }

    /// Convenience over [`stub_node_fn`]: one canned result per method, matched
    /// by the request's `"method"` field. Params are ignored, so the same value
    /// answers every height.
    #[cfg(feature = "rpc")]
    fn stub_node(results: std::collections::HashMap<&'static str, String>) -> String {
        stub_node_fn(move |req| {
            let method = results
                .keys()
                .find(|m| req.contains(&format!("\"method\":\"{m}\"")))
                .copied()
                .unwrap_or("");
            results
                .get(method)
                .cloned()
                .unwrap_or_else(|| "null".into())
        })
    }

    /// No reorg: the node's hash for last_scanned matches the stored one, so
    /// sync must NOT reset — it just scans the one new block forward.
    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn sync_no_reorg_does_not_reset() {
        use pivx_rpc::{Auth, PivxClient};
        let seed = [21u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        // Scanned block 1 (hash aa..) credited us 1 PIV.
        w.scan_block(&serde_json::json!({
            "height": 1, "hash": "aa".repeat(32),
            "tx": [{ "txid": "e1".repeat(32), "vin": [{ "txid": "f1".repeat(32), "vout": 0 }],
                     "vout": [{ "n": 0, "value": 1.0, "scriptPubKey": { "hex": s0_hex } }] }],
        }))
        .unwrap();
        assert_eq!(w.balance(), 100_000_000);

        // Node: getblockhash(1) still returns aa.. (no reorg); tip is now 2 and
        // block 2 extends aa.. crediting another 0.5 PIV.
        let mut results = std::collections::HashMap::new();
        results.insert("getblockcount", "2".to_string());
        results.insert("getblockhash", format!("\"{}\"", "aa".repeat(32)));
        results.insert(
            "getblock",
            serde_json::json!({
                "height": 2, "hash": "bb".repeat(32), "previousblockhash": "aa".repeat(32),
                "tx": [{ "txid": "e2".repeat(32), "vin": [{ "txid": "f2".repeat(32), "vout": 0 }],
                         "vout": [{ "n": 0, "value": 0.5, "scriptPubKey": { "hex": s0_hex } }] }],
            })
            .to_string(),
        );
        let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
        w.sync(&client, 0, 10).await.unwrap();
        // No reset: original UTXO kept AND the new block credited on top.
        assert_eq!(w.balance(), 150_000_000);
        assert_eq!(w.utxos().count(), 2);
        assert_eq!(w.last_scanned_block(), 2);
    }

    /// Beyond-window reorg: the fork lies below the earliest stored hash
    /// (here the window holds only height 1, and the node disagrees there),
    /// so the walk-back finds no common block. sync must fail safe with
    /// ScanDiverged rather than silently resetting a fixed floor — the S4 bug
    /// was that a reorg deeper than REORG_WINDOW retained orphaned UTXOs.
    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn sync_beyond_window_reorg_diverges() {
        use pivx_rpc::{Auth, PivxClient};
        let seed = [22u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        // A caller-supplied UTXO (height 0) plus a scanned orphan (height 1).
        w.add_utxo("00".repeat(32).as_str(), 0, 50_000_000, s0.clone());
        w.scan_block(&serde_json::json!({
            "height": 1, "hash": "aa".repeat(32),
            "tx": [{ "txid": "e1".repeat(32), "vin": [{ "txid": "f1".repeat(32), "vout": 0 }],
                     "vout": [{ "n": 0, "value": 1.0, "scriptPubKey": { "hex": hex::encode(&s0) } }] }],
        }))
        .unwrap();
        assert_eq!(w.balance(), 150_000_000);
        assert_eq!(w.last_scanned_block(), 1);

        // Node: getblockhash returns cc.. at every height (never the stored
        // aa..), so no window entry matches and the walk-back exhausts.
        let mut results = std::collections::HashMap::new();
        results.insert("getblockcount", "1".to_string());
        results.insert("getblockhash", format!("\"{}\"", "cc".repeat(32)));
        let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
        let err = w.sync(&client, 0, 10).await.unwrap_err();
        assert!(matches!(err, WalletError::ScanDiverged { .. }));
        // Fail-safe: nothing mutated — the orphan is surfaced to the caller,
        // not silently retained below a blind reset.
        assert_eq!(w.balance(), 150_000_000);
        assert_eq!(w.utxos().count(), 2);
        assert_eq!(w.last_scanned_block(), 1);
    }

    /// Within-window reorg: the node replaced the tip block (height 3) but
    /// still agrees at height 2. sync must walk the window back to the TRUE
    /// fork (2, not a blind lastScanned-100), drop the orphan on the old
    /// chain, and credit the replacement chain.
    #[cfg(feature = "rpc")]
    #[tokio::test]
    async fn sync_within_window_reorg_resets_to_true_fork() {
        use pivx_rpc::{Auth, PivxClient};
        let seed = [23u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        // Node's canonical hash for a height (matches the stub below).
        let nh = |h: i64| format!("{h:064x}");
        // Scan the node's chain 1→3, storing its canonical hashes for 1,2 but
        // the OLD (orphan) hash for 3, which credited us 1 PIV.
        w.scan_block(&serde_json::json!({ "height": 1, "hash": nh(1), "tx": [] }))
            .unwrap();
        w.scan_block(
            &serde_json::json!({ "height": 2, "hash": nh(2), "previousblockhash": nh(1), "tx": [] }),
        )
        .unwrap();
        w.scan_block(&serde_json::json!({
            "height": 3, "hash": "ab".repeat(32), "previousblockhash": nh(2),
            "tx": [{ "txid": "e3".repeat(32), "vin": [{ "txid": "f3".repeat(32), "vout": 0 }],
                     "vout": [{ "n": 0, "value": 1.0, "scriptPubKey": { "hex": hex::encode(&s0) } }] }],
        }))
        .unwrap();
        assert_eq!(w.balance(), 100_000_000);
        assert_eq!(w.last_scanned_block(), 3);

        // Node: getblockhash(h) = the canonical hash for h, so height 3 no
        // longer matches the stored orphan while height 2 still does. The
        // replacement block 3 (fetched during forward-scan) pays us 2 PIV.
        let new_block3 = serde_json::json!({
            "height": 3, "hash": nh(3), "previousblockhash": nh(2),
            "tx": [{ "txid": "e9".repeat(32), "vin": [{ "txid": "f9".repeat(32), "vout": 0 }],
                     "vout": [{ "n": 0, "value": 2.0, "scriptPubKey": { "hex": hex::encode(&s0) } }] }],
        })
        .to_string();
        let url = stub_node_fn(move |req| {
            if req.contains("\"method\":\"getblockcount\"") {
                "3".to_string()
            } else if req.contains("\"method\":\"getblockhash\"") {
                let h: i64 = req
                    .split("\"params\":[")
                    .nth(1)
                    .and_then(|s| s.split(']').next())
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                format!("\"{h:064x}\"")
            } else {
                new_block3.clone()
            }
        });
        let client = PivxClient::new(url, Auth::None).unwrap();
        w.sync(&client, 0, 10).await.unwrap();

        // Reset to the true fork (2): the orphan (old block 3) is dropped and
        // the replacement chain's 2 PIV credited; last_scanned back at the tip.
        assert_eq!(w.last_scanned_block(), 3);
        assert_eq!(w.balance(), 200_000_000);
        assert_eq!(w.utxos().count(), 1);
        assert!(w.utxos().all(|u| u.txid == "e9".repeat(32)));
    }

    /// C1: selecting past MAX_STANDARD_TX_SIZE (100000, PIVX validation.h)
    /// must error with consolidation guidance instead of building a tx the
    /// network will never relay.
    #[test]
    fn build_send_caps_at_standard_tx_size() {
        let seed = [30u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        // 700 dust UTXOs: satisfying the send needs > 675 inputs (> 100kB).
        for i in 0..700u32 {
            assert!(w.add_utxo(&format!("{i:064x}"), 0, 10_000, s0.clone()));
        }
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        let err = w.build_send(&dest, 6_000_000, Some(10)).unwrap_err();
        assert!(err.to_string().contains("100kB"), "got: {err}");
        assert!(err.to_string().contains("consolidate"));
    }

    /// C2: an absurd fee_per_byte must yield a labeled error, not wrap
    /// (release) or panic (debug) in the fee multiplication.
    #[test]
    fn build_send_errors_on_fee_overflow() {
        let seed = [31u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        w.add_utxo(
            "cc".repeat(32).as_str(),
            0,
            200_000_000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        let err = w
            .build_send(&dest, 100_000_000, Some(u64::MAX))
            .unwrap_err();
        assert!(err.to_string().contains("overflows"), "got: {err}");
    }

    /// C3: coinstake detection requires vout[0] to be EMPTY (zero value AND
    /// empty script, CTxOut::IsEmpty). A zero-value OP_RETURN vout[0] tx
    /// paying us must NOT be maturity-gated; a true coinstake still is.
    #[test]
    fn zero_value_opreturn_vout0_is_not_coinstake() {
        let seed = [32u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let spk_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        // Zero-value OP_RETURN at vout[0] (script "6a", not empty), pays us at
        // vout 1: an ordinary tx, spendable with one confirmation.
        w.scan_block(&serde_json::json!({
            "height": 100,
            "tx": [{
                "txid": "55".repeat(32),
                "vin": [{ "txid": "44".repeat(32), "vout": 0 }],
                "vout": [
                    { "n": 0, "value": 0.0, "scriptPubKey": { "hex": "6a" } },
                    { "n": 1, "value": 2.0, "scriptPubKey": { "hex": spk_hex } },
                ],
            }],
        }))
        .unwrap();
        assert_eq!(w.balance(), 200_000_000);
        assert!(w.build_send(&dest, 100_000_000, Some(100)).is_ok());

        // A true coinstake (empty vout[0]: value 0 AND script "") IS gated.
        let mut w2 = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        w2.scan_block(&serde_json::json!({
            "height": 100,
            "tx": [{
                "txid": "66".repeat(32),
                "vin": [{ "txid": "44".repeat(32), "vout": 0 }],
                "vout": [
                    { "n": 0, "value": 0.0, "scriptPubKey": { "hex": "" } },
                    { "n": 1, "value": 2.0, "scriptPubKey": { "hex": spk_hex } },
                ],
            }],
        }))
        .unwrap();
        assert_eq!(w2.balance(), 200_000_000);
        assert!(matches!(
            w2.build_send(&dest, 100_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
    }

    /// C4: add_utxo must reject what load() rejects — otherwise a wallet can
    /// save() a state it can never load() again.
    #[test]
    fn add_utxo_rejects_what_load_rejects() {
        let seed = [33u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        // Non-hex and short txids.
        assert!(!w.add_utxo("zz".repeat(32).as_str(), 0, 1000, s0.clone()));
        assert!(!w.add_utxo("abcd", 0, 1000, s0.clone()));
        // Amount above the JS safe-integer bound (2^53 - 1).
        assert!(!w.add_utxo("aa".repeat(32).as_str(), 0, 1u64 << 53, s0.clone()));
        assert_eq!(w.utxos().count(), 0);
        // A valid UTXO is still accepted and the state round-trips.
        assert!(w.add_utxo("aa".repeat(32).as_str(), 0, 1000, s0.clone()));
        assert!(TransparentWallet::load(&seed, &w.save()).is_ok());
    }

    /// C5: re-scanning an already-scanned block must not push a duplicate
    /// window entry that load() then rejects (save/load self-brick).
    #[test]
    fn rescan_same_block_saves_and_loads() {
        let seed = [34u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let block = serde_json::json!({ "height": 100, "hash": "aa".repeat(32), "tx": [] });
        w.scan_block(&block).unwrap();
        w.scan_block(&block).unwrap(); // e.g. a replay after a crash-restore
        assert_eq!(w.last_scanned_block(), 100);
        let json = w.save();
        let r = TransparentWallet::load(&seed, &json);
        assert!(r.is_ok(), "state after a re-scan must load");
        assert_eq!(r.map(|r| r.save()).ok().as_deref(), Some(json.as_str()));
    }

    /// C6: a build_send reservation must survive reset_scan — after the
    /// re-scan re-credits the outpoint, a second send must not double-select
    /// the inputs of the still-in-flight first send.
    #[test]
    fn reservation_survives_reset_scan() {
        let seed = [35u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        let block = serde_json::json!({
            "height": 100,
            "hash": "aa".repeat(32),
            "tx": [{
                "txid": "e1".repeat(32),
                "vin": [{ "txid": "f1".repeat(32), "vout": 0 }],
                "vout": [{ "n": 0, "value": 2.0, "scriptPubKey": { "hex": hex::encode(&s0) } }],
            }],
        });
        w.scan_block(&block).unwrap();
        let (_, spent) = w.build_send(&dest, 100_000_000, Some(100)).unwrap(); // reserves e1:0
        w.reset_scan(99).unwrap(); // reorg walk-back: drops the UTXO, keeps the reservation
        w.scan_block(&block).unwrap(); // re-scan re-credits e1:0
                                       // Still reserved: the only UTXO must not be selectable again.
        assert!(matches!(
            w.build_send(&dest, 100_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
        // release (or a scan-observed spend / mark_spent) frees it.
        w.release(&spent);
        assert!(w.build_send(&dest, 100_000_000, Some(100)).is_ok());
    }

    /// C7: feerates below the node's relay floor (minRelayTxFee = 10000/kB =
    /// 10 sat/byte, PIVX validation.cpp) are rejected with the minimum named.
    #[test]
    fn build_send_rejects_sub_relay_feerate() {
        let seed = [36u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        w.add_utxo(
            "cc".repeat(32).as_str(),
            0,
            200_000_000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        let err = w.build_send(&dest, 100_000_000, Some(9)).unwrap_err();
        assert!(err.to_string().contains("minRelayTxFee"), "got: {err}");
        assert!(w.build_send(&dest, 100_000_000, Some(10)).is_ok());
    }

    /// C8: reset_scan can only rewind — a height above last_scanned would
    /// silently skip the blocks in between.
    #[test]
    fn reset_scan_rejects_forward_height() {
        let seed = [37u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        w.scan_block(&serde_json::json!({ "height": 100, "hash": "aa".repeat(32), "tx": [] }))
            .unwrap();
        let err = w.reset_scan(150).unwrap_err();
        assert!(
            err.to_string().contains("above the last scanned"),
            "got: {err}"
        );
        assert_eq!(w.last_scanned_block(), 100); // nothing mutated
        w.reset_scan(100).unwrap(); // rewind-to-current is a no-op, still fine
    }

    /// C9: hostile vout entries are SKIPPED, never mangled — a negative value
    /// must not be clamped to 0 and an out-of-u32 index must not be truncated
    /// into another outpoint.
    #[test]
    fn scan_skips_negative_value_and_oversized_vout() {
        let seed = [38u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let spk_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        w.scan_block(&serde_json::json!({
            "height": 10,
            "tx": [{
                "txid": "ee".repeat(32),
                "vin": [{ "txid": "ff".repeat(32), "vout": 0 }],
                "vout": [
                    { "n": 0, "value": -1.0, "scriptPubKey": { "hex": spk_hex } },
                    { "n": 4_294_967_296u64, "value": 1.0, "scriptPubKey": { "hex": spk_hex } },
                    { "n": 1, "value": 1.0, "scriptPubKey": { "hex": spk_hex } },
                ],
            }],
        }))
        .unwrap();
        assert_eq!(w.utxos().count(), 1); // only the valid vout credited
        assert_eq!(w.balance(), 100_000_000);
        assert!(TransparentWallet::load(&seed, &w.save()).is_ok());
    }

    /// C12: spendable_balance applies build_send's maturity filter; balance
    /// deliberately does not.
    #[test]
    fn spendable_balance_excludes_immature_coinbase() {
        let seed = [39u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let spk_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        w.scan_block(&serde_json::json!({
            "height": 100,
            "tx": [{
                "txid": "dd".repeat(32),
                "vin": [{ "coinbase": "00" }],
                "vout": [{ "n": 0, "value": 5.0, "scriptPubKey": { "hex": spk_hex } }],
            }],
        }))
        .unwrap();
        assert_eq!(w.balance(), 500_000_000); // counted...
        assert_eq!(w.spendable_balance(), 0); // ...but not yet spendable
        w.scan_block(&serde_json::json!({ "height": 199, "tx": [] }))
            .unwrap(); // 100 confirmations: mature
        assert_eq!(w.spendable_balance(), 500_000_000);
    }

    /// W2: an invalid block height (negative/fractional/missing/above 2^53-1)
    /// must be a labeled error with state untouched — before the fix it
    /// poisoned last_scanned, bricking save→load or producing a state the JS
    /// SDK rejects. Both SDKs bound heights to [0, 2^53-1] so a state loads
    /// in both or neither (cross-SDK parity for the 2^53 rejection).
    #[test]
    fn scan_block_rejects_invalid_heights_before_mutating() {
        let seed = [40u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let spk_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        w.scan_block(&serde_json::json!({
            "height": 100,
            "hash": "aa".repeat(32),
            "tx": [{
                "txid": "bb".repeat(32),
                "vin": [{ "coinbase": "00" }],
                "vout": [{ "n": 0, "value": 1.0, "scriptPubKey": { "hex": spk_hex } }],
            }],
        }))
        .unwrap();
        assert_eq!(w.balance(), 100_000_000);
        let pay = serde_json::json!([{
            "txid": "cc".repeat(32),
            "vin": [{ "txid": "dd".repeat(32), "vout": 0 }],
            "vout": [{ "n": 0, "value": 2.0, "scriptPubKey": { "hex": spk_hex } }],
        }]);
        for height in [
            serde_json::json!(-1),
            serde_json::json!(100.5),
            serde_json::json!(9_007_199_254_740_992i64), // 2^53: JS-unsafe
            serde_json::Value::Null,                     // missing height
        ] {
            let err = w
                .scan_block(&serde_json::json!({
                    "height": height, "hash": "ee".repeat(32), "tx": pay,
                }))
                .unwrap_err();
            assert!(err.to_string().contains("height"), "got {err}");
        }
        assert_eq!(w.last_scanned_block(), 100, "scan position untouched");
        assert_eq!(
            w.balance(),
            100_000_000,
            "nothing credited from rejected blocks"
        );
        // The state still saves and loads (a poisoned height used to brick it).
        let r = TransparentWallet::load(&seed, &w.save()).unwrap();
        assert_eq!(r.last_scanned_block(), 100);
    }

    /// W2: reset_scan(-1) used to drop every scanned UTXO and set a negative
    /// scan position that bricked the next load(); now it rejects before
    /// mutating.
    #[test]
    fn reset_scan_rejects_negative_height_before_mutating() {
        let seed = [41u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let spk_hex = hex::encode(spk(&p2pkh_address(&a0.public_key, MainNetwork)));
        w.scan_block(&serde_json::json!({
            "height": 100,
            "hash": "aa".repeat(32),
            "tx": [{
                "txid": "bb".repeat(32),
                "vin": [{ "txid": "dd".repeat(32), "vout": 0 }],
                "vout": [{ "n": 0, "value": 1.0, "scriptPubKey": { "hex": spk_hex } }],
            }],
        }))
        .unwrap();
        assert_eq!(w.balance(), 100_000_000);
        let err = w.reset_scan(-1).unwrap_err();
        assert!(err.to_string().contains("non-negative"), "got {err}");
        assert_eq!(w.last_scanned_block(), 100, "scan position untouched");
        assert_eq!(w.balance(), 100_000_000, "scanned UTXOs kept");
        TransparentWallet::load(&seed, &w.save()).unwrap(); // state still loads
    }

    // W1: account in the hardened range aliases a lower account; reject it.
    #[test]
    fn new_rejects_hardened_range_account() {
        assert!(TransparentWallet::new(&[1u8; 32], MainNetwork, 0x8000_0000, 2).is_err());
        assert!(TransparentWallet::new(&[1u8; 32], MainNetwork, 0x7fff_ffff, 2).is_ok());
    }

    // W-SEED: accept a 32-byte raw seed OR a 64-byte BIP39 seed; reject others.
    #[test]
    fn new_accepts_32_or_64_byte_seed() {
        assert!(TransparentWallet::new(&[1u8; 32], MainNetwork, 0, 2).is_ok());
        assert!(TransparentWallet::new(&[1u8; 64], MainNetwork, 0, 2).is_ok());
        assert!(TransparentWallet::new(&[1u8; 16], MainNetwork, 0, 2).is_err());
        assert!(TransparentWallet::new(&[1u8; 33], MainNetwork, 0, 2).is_err());
    }

    // W2: load bounds heights to [0, 2^53-1], symmetric with scan_block.
    #[test]
    fn load_rejects_out_of_range_heights() {
        let seed = [1u8; 32];
        assert!(TransparentWallet::load(&seed, CROSS_SDK_STATE).is_ok());
        let huge_scan =
            CROSS_SDK_STATE.replace("\"lastScanned\":7", "\"lastScanned\":9007199254740993");
        assert!(TransparentWallet::load(&seed, &huge_scan).is_err());
        let neg_scan = CROSS_SDK_STATE.replace("\"lastScanned\":7", "\"lastScanned\":-1");
        assert!(TransparentWallet::load(&seed, &neg_scan).is_err());
        let huge_height = CROSS_SDK_STATE.replace(
            "\"coinbase\":true,\"height\":7",
            "\"coinbase\":true,\"height\":9007199254740993",
        );
        assert!(TransparentWallet::load(&seed, &huge_height).is_err());
    }

    // W2 belt: spendable_balance/build_send after a max-height load do not panic.
    #[test]
    fn max_height_load_does_not_panic() {
        let seed = [1u8; 32];
        let state =
            CROSS_SDK_STATE.replace("\"lastScanned\":7", "\"lastScanned\":9007199254740991");
        let mut w = TransparentWallet::load(&seed, &state).unwrap();
        let _ = w.spendable_balance();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        // Just exercising the maturity math; result (Ok/Err) is irrelevant.
        let _ = w.build_send(&p2pkh_address(&a0.public_key, MainNetwork), 1_000, Some(10));
    }

    // W4: an EXM output is 35 bytes (26-byte script), not the 34 a flat P2PKH
    // assumes. At 10 sat/byte the EXM send must pay 10 sats more fee than the
    // P2PKH send (so 10 sats less change) — before the fix both were identical.
    #[test]
    fn est_size_counts_exm_output_at_full_length() {
        let change_after = |to_exm: bool| -> u64 {
            let seed = [5u8; 32];
            let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
            let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
            let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
            assert!(w.add_utxo(&"aa".repeat(32), 0, 1_000_000_000, s0));
            let other = derive_key(&[9u8; 32], MainNetwork, 0, 0, 0).unwrap();
            let hash = hash160(&other.public_key.serialize());
            let to = if to_exm {
                crate::transparent::encode_address(&hash, MainNetwork, AddressKind::Exchange)
            } else {
                p2pkh_address(&other.public_key, MainNetwork)
            };
            let (hex, _) = w.build_send(&to, 100_000_000, Some(10)).unwrap();
            let bytes = hex::decode(&hex).unwrap();
            // The change output is last: [8-byte value][0x19 scriptlen][25 script][4 locktime].
            let off = bytes.len() - 38;
            assert_eq!(bytes[off + 8], 0x19, "last output is 25-byte P2PKH change");
            u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
        };
        let change_exm = change_after(true);
        let change_p2pkh = change_after(false);
        assert_eq!(change_p2pkh - change_exm, 10);
    }
}
