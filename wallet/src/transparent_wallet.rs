//! Transparent wallet: HD address management, UTXO tracking (from a block
//! scan or caller-supplied), coin selection, and sending. Complements the
//! shielded [`ShieldWallet`](crate::ShieldWallet); both derive from the seed.
//!
//! PIVX has no address index, so UTXOs are discovered either by scanning
//! blocks ([`scan`](TransparentWallet::scan)) or supplied by the caller
//! ([`add_utxo`](TransparentWallet::add_utxo)).

use std::collections::HashMap;

use pivx_primitives::consensus::Network;
use secp256k1::SecretKey;

use crate::error::WalletError;
use crate::transparent::{decode_address, derive_key, hash160, AddressKind};
use crate::transparent_tx::{build_transparent_tx, script_pubkey_for_address, TxInput, TxOutput};

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

pub struct TransparentWallet {
    network: Network,
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
}

impl TransparentWallet {
    /// Derive `gap` external and `gap` change addresses from `seed` under
    /// account `account`. Only outputs to these addresses are recognized, so
    /// `gap` bounds how many unused addresses ahead are watched.
    pub fn new(seed: &[u8], network: Network, account: u32, gap: u32) -> Result<Self, WalletError> {
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
            keys,
            external,
            next_external: 0,
            change,
            next_change: 0,
            utxos: HashMap::new(),
            last_scanned: 0,
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

    fn next_change_hash(&mut self) -> Result<[u8; 20], WalletError> {
        let h = *self
            .change
            .get(self.next_change)
            .ok_or_else(|| WalletError::Other("change gap limit reached; increase gap".into()))?;
        self.next_change += 1;
        Ok(h)
    }

    /// hash160 of a standard P2PKH scriptPubKey (76a914<20>88ac), if it is one.
    fn p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
        if script.len() == 25
            && script[0] == 0x76
            && script[1] == 0xa9
            && script[2] == 0x14
            && script[23] == 0x88
            && script[24] == 0xac
        {
            let mut h = [0u8; 20];
            h.copy_from_slice(&script[3..23]);
            Some(h)
        } else {
            None
        }
    }

    /// Add a caller-supplied UTXO if it pays one of our addresses. Assumed a
    /// normal (non-coinbase) spendable output; use `scan_block` for chain data
    /// where coinbase maturity is tracked.
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
        match Self::p2pkh_hash(&script_pubkey) {
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
            self.utxos.remove(&(s.txid.clone(), s.vout));
        }
    }

    /// Scan one decoded block (`getblock <hash> 2`): credit every output that
    /// pays us and remove every tracked UTXO the block spends. Coinbase vins
    /// (no prevout `txid`) are skipped. Records the block's height as the last
    /// scanned. Malformed tx/vout/vin entries are skipped, not fatal.
    pub fn scan_block(&mut self, block: &serde_json::Value) {
        if let Some(h) = block["height"].as_i64() {
            self.last_scanned = h;
        }
        let height = self.last_scanned;
        let Some(txs) = block["tx"].as_array() else {
            return;
        };
        for tx in txs {
            let Some(txid) = tx["txid"].as_str() else {
                continue;
            };
            // Coinbase: first vin carries `coinbase` and no prevout. Coinstake
            // (PoS): a spending vin plus an empty vout[0] (zero value). Both
            // are maturity-gated for spending (src/txmempool.cpp).
            let first_vin = tx["vin"].get(0);
            let is_coinbase = first_vin.is_some_and(|v| v.get("coinbase").is_some());
            let is_coinstake = first_vin.is_some_and(|v| v.get("txid").is_some())
                && tx["vout"][0]["value"].as_f64() == Some(0.0);
            let coinbase = is_coinbase || is_coinstake;
            for vout in tx["vout"].as_array().into_iter().flatten() {
                let (Some(n), Some(value), Some(hex_str)) = (
                    vout["n"].as_u64(),
                    vout["value"].as_f64(),
                    vout["scriptPubKey"]["hex"].as_str(),
                ) else {
                    continue;
                };
                let Ok(script) = hex::decode(hex_str) else {
                    continue;
                };
                self.insert_utxo(
                    txid,
                    n as u32,
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
                self.utxos.remove(&(prev.to_string(), vout as u32));
            }
        }
    }

    /// Height of the last block passed to [`scan_block`](Self::scan_block) (0 if none).
    pub fn last_scanned_block(&self) -> i64 {
        self.last_scanned
    }

    /// Total tracked transparent balance in satoshis.
    pub fn balance(&self) -> u64 {
        self.utxos
            .values()
            .map(|u| u.amount)
            .fold(0u64, |a, v| a.saturating_add(v))
    }

    pub fn utxos(&self) -> impl Iterator<Item = &OwnedUtxo> {
        self.utxos.values()
    }

    /// Estimated size (bytes) of a P2PKH tx with the given input/output counts.
    fn est_size(n_in: usize, n_out: usize) -> u64 {
        (n_in as u64) * 148 + (n_out as u64) * 34 + 10
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
        // A zero feerate would build a valid-looking but unrelayable tx.
        if fee_per_byte == Some(0) {
            return Err(WalletError::Other(
                "fee_per_byte must be greater than zero".into(),
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

        // Exclude immature coinbase/coinstake outputs: the node rejects a spend
        // of one before nCoinbaseMaturity confirmations. Depth is measured
        // against the last scanned block.
        let maturity = coinbase_maturity(self.network);
        let mut avail: Vec<&OwnedUtxo> = self
            .utxos
            .values()
            .filter(|u| !(u.coinbase && self.last_scanned - u.height + 1 < maturity))
            .collect();
        avail.sort_by_key(|u| std::cmp::Reverse(u.amount)); // largest first

        let mut selected: Vec<OwnedUtxo> = Vec::new();
        let mut total: u64 = 0;
        for u in avail {
            selected.push(u.clone());
            total = total.saturating_add(u.amount);
            let fee = feerate * Self::est_size(selected.len(), 2);
            if total >= amount.saturating_add(fee) {
                break;
            }
        }
        let fee = feerate * Self::est_size(selected.len(), 2);
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
        if change_val > std::cmp::max(feerate * 148, dust_threshold(25)) {
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
        Ok((hex, spent))
    }

    /// Mark inputs spent after a successful broadcast.
    pub fn mark_spent(&mut self, spent: &[(String, u32)]) {
        for key in spent {
            self.utxos.remove(key);
        }
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
        let mut from = from_height.max(self.last_scanned + 1);
        while from <= tip {
            let to = (from + batch - 1).min(tip);
            for h in from..=to {
                let hash = client.get_block_hash(h).await?;
                let block = client.get_block(&hash, 2).await?;
                self.scan_block(&block);
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
        w.scan_block(&block1);
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
        w.scan_block(&block2);
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
        w.scan_block(&coinbase_block);
        assert_eq!(w.balance(), 500_000_000);
        // Only 1 confirmation: immature, cannot be selected.
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        assert!(matches!(
            w.build_send(&dest, 100_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
        // Advance to maturity (100 confirmations): now spendable.
        w.scan_block(&serde_json::json!({ "height": 199, "tx": [] }));
        assert!(w.build_send(&dest, 100_000_000, Some(100)).is_ok());
    }
}
