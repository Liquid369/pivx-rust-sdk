use std::collections::{HashMap, HashSet};

use pivx_primitives::consensus::Network;
use sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use serde::{Deserialize, Serialize};

use crate::checkpoint::get_checkpoint;
use crate::error::{Result, WalletError};
use crate::keys;
use crate::prover;
use crate::transaction::{self, sapling_root, BuiltTransaction, SerializedNote, TxOptions, Utxo};

/// A block to scan: raw tx hexes plus the block height.
pub struct WalletBlock {
    pub height: i64,
    pub tx_hexes: Vec<String>,
}

/// Where a transaction's funds come from.
pub enum Inputs {
    /// Spend the wallet's shielded notes (default).
    Shield,
    /// Shield transparent funds: spend these UTXOs (change stays transparent).
    Transparent {
        utxos: Vec<Utxo>,
        change_address: String,
    },
}

pub struct SendOptions {
    /// Recipient: shield (ps1…) or transparent address.
    pub to: String,
    /// Amount in satoshis.
    pub amount: u64,
    /// UTF-8 memo (shield recipients only, max 512 bytes).
    pub memo: Option<String>,
    pub inputs: Inputs,
    /// Sweep semantics: when the balance covers `amount` but not
    /// `amount + fee`, pay the fee out of the recipient's amount instead of
    /// failing. Default false — an exact payout that leaves no fee headroom
    /// returns `InsufficientBalance` rather than silently underpaying.
    pub subtract_fee_from_amount: bool,
}

impl SendOptions {
    /// A shield send of `amount` sats to `to`, no memo, fee paid by the sender.
    pub fn shield(to: impl Into<String>, amount: u64) -> Self {
        Self {
            to: to.into(),
            amount,
            memo: None,
            inputs: Inputs::Shield,
            subtract_fee_from_amount: false,
        }
    }
}

/// Serialized wallet state. Field names match the JS `pivx-wallet` package's
/// state format (version 1) — states are interchangeable between the SDKs.
/// The spending key is deliberately excluded.
#[derive(Serialize, Deserialize)]
struct WalletState {
    version: u32,
    network: String,
    extfvk: String,
    #[serde(rename = "lastProcessedBlock")]
    last_processed_block: i64,
    #[serde(rename = "commitmentTree")]
    commitment_tree: String,
    #[serde(rename = "diversifierIndex")]
    diversifier_index: Vec<u8>,
    notes: Vec<SerializedNote>,
    #[serde(rename = "nullifierMap")]
    nullifier_map: HashMap<String, AttributedNote>,
    /// Persisted so a crash between broadcast and finalize can't resurrect
    /// spent notes. `default` keeps older/JS states without the field loadable.
    #[serde(rename = "pendingSpends", default)]
    pending_spends: HashMap<String, Vec<String>>,
}

/// Note attribution kept per nullifier (payment attribution for spends).
#[derive(Clone, Serialize, Deserialize)]
pub struct AttributedNote {
    pub recipient: String,
    pub value: u64,
}

/// Sapling (UPGRADE_V5_0) activation height, inclusive. Below it consensus
/// rejects any tx carrying shielded DATA (IsShieldedTx, PIVX transaction.h /
/// sapling_validation.cpp "bad-txns-invalid-sapling-act") — the version byte
/// alone is legal — and the node reports a zero finalsaplingroot, so the
/// sapling root check is skipped there and '03'-prefixed txs are skipped
/// rather than scanned; at/above it an honest node always reports a real,
/// matchable root. Mainnet V5_0 is 2_700_500; testnet is 201.
fn sapling_activation(network: Network) -> i64 {
    match network {
        Network::MainNetwork => 2_700_500,
        Network::TestNetwork => 201,
    }
}

/// Standalone PIVX wallet: owns keys, scans blocks, tracks shielded notes,
/// and builds fully-proved transactions locally. A node is only a chain-data
/// source and broadcast endpoint.
///
/// Capabilities follow the key material: constructed from a seed or spending
/// key the wallet can spend; from a viewing key it is watch-only — and can
/// be upgraded in place with [`load_spending_key`](Self::load_spending_key).
pub struct ShieldWallet {
    network: Network,
    extsk: Option<ExtendedSpendingKey>,
    extfvk: ExtendedFullViewingKey,
    commitment_tree: String,
    last_processed_block: i64,
    diversifier_index: [u8; 11],
    notes: Vec<SerializedNote>,
    nullifier_map: HashMap<String, AttributedNote>,
    /// txid → nullifiers awaiting broadcast confirmation.
    pending_spends: HashMap<String, Vec<String>>,
    /// Whether the starting checkpoint has been confirmed against the node.
    start_validated: bool,
}

impl ShieldWallet {
    /// Full-capability wallet from a seed: a 32-byte raw seed OR a 64-byte
    /// BIP39 seed (ZIP32 over its first 32 bytes, matching the pivx-shield
    /// WASM). Scanning starts at the checkpoint nearest `birth_height`.
    pub fn from_seed(
        seed: &[u8],
        network: Network,
        birth_height: i64,
        account_index: u32,
    ) -> Result<Self> {
        let extsk = keys::spending_key_from_seed(seed, network, account_index)?;
        Self::from_parts(Some(extsk), None, network, birth_height)
    }

    /// Full-capability wallet from a bech32 extended spending key.
    pub fn from_spending_key(enc_extsk: &str, network: Network, birth_height: i64) -> Result<Self> {
        let extsk = keys::decode_extsk(enc_extsk, network)?;
        Self::from_parts(Some(extsk), None, network, birth_height)
    }

    /// Watch-only wallet from a bech32 extended full viewing key: scans,
    /// derives receive addresses, tracks balance; cannot spend.
    pub fn from_viewing_key(enc_extfvk: &str, network: Network, birth_height: i64) -> Result<Self> {
        let extfvk = keys::decode_extended_full_viewing_key(enc_extfvk, network)?;
        Self::from_parts(None, Some(extfvk), network, birth_height)
    }

    fn from_parts(
        extsk: Option<ExtendedSpendingKey>,
        extfvk: Option<ExtendedFullViewingKey>,
        network: Network,
        birth_height: i64,
    ) -> Result<Self> {
        let extfvk = match (&extsk, extfvk) {
            (_, Some(fvk)) => fvk,
            (Some(sk), None) => keys::extfvk_from_extsk(sk),
            (None, None) => unreachable!("constructors always pass a key"),
        };
        // Reject a birth_height outside [0, i32::MAX] rather than clamping it:
        // a huge birth_height clamped to i32::MAX would silently start scanning
        // near the chain tip and MISS every deposit below it, and a negative one
        // is never valid. The JS SDK's create() rejects the same range. Every
        // public constructor routes through from_parts, so this one guard covers
        // from_seed / from_spending_key / from_viewing_key.
        if !(0..=i32::MAX as i64).contains(&birth_height) {
            return Err(WalletError::Other(format!(
                "birth height must be an integer in [0, 2^31-1], got {birth_height}"
            )));
        }
        // Resume from the checkpoint's own height, not birth_height: the tree
        // is the committed state AT the checkpoint, so scanning must start at
        // checkpoint_height + 1. Starting higher would leave the tree missing
        // every shield output in the gap and diverge on the first real block.
        let (checkpoint_height, checkpoint_tree) = get_checkpoint(birth_height as i32, network);
        let (_, diversifier_index) = keys::default_address(&extfvk, network);
        Ok(Self {
            network,
            extsk,
            extfvk,
            commitment_tree: checkpoint_tree.to_string(),
            last_processed_block: checkpoint_height as i64,
            diversifier_index,
            notes: vec![],
            nullifier_map: HashMap::new(),
            pending_spends: HashMap::new(),
            start_validated: false,
        })
    }

    /// Upgrade a watch-only wallet. The key must match the stored viewing key.
    pub fn load_spending_key(&mut self, enc_extsk: &str) -> Result<()> {
        if self.extsk.is_some() {
            return Err(WalletError::InvalidKey(
                "wallet already has a spending key".into(),
            ));
        }
        let extsk = keys::decode_extsk(enc_extsk, self.network)?;
        if keys::encode_extended_full_viewing_key(&keys::extfvk_from_extsk(&extsk), self.network)
            != keys::encode_extended_full_viewing_key(&self.extfvk, self.network)
        {
            return Err(WalletError::InvalidKey(
                "spending key does not match this wallet's viewing key".into(),
            ));
        }
        self.extsk = Some(extsk);
        Ok(())
    }

    /// True when the wallet holds spend authority.
    pub fn can_spend(&self) -> bool {
        self.extsk.is_some()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    // ── Addresses & balance ─────────────────────────────────────────────

    /// Next diversified shield receive address.
    pub fn new_address(&mut self) -> Result<String> {
        let (address, index) =
            keys::next_address(&self.extfvk, self.diversifier_index, self.network)?;
        self.diversifier_index = index;
        Ok(address)
    }

    /// Confirmed shielded balance in satoshis (scanned notes minus pending spends).
    pub fn balance(&self) -> u64 {
        let pending: HashSet<&String> = self.pending_spends.values().flatten().collect();
        // Saturating so a tampered state file with absurd note values can't
        // overflow (debug panic / release wrap). Such values can't actually be
        // spent — the proof binds each note's real value — but the sum stays sane.
        self.notes
            .iter()
            .filter(|n| !pending.contains(&n.nullifier))
            .map(|n| n.note.value().inner())
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    /// Currently tracked unspent notes.
    pub fn notes(&self) -> &[SerializedNote] {
        &self.notes
    }

    pub fn last_synced_block(&self) -> i64 {
        self.last_processed_block
    }

    /// Look up a note by its on-chain nullifier.
    pub fn note_from_nullifier(&self, nullifier: &str) -> Option<&AttributedNote> {
        self.nullifier_map.get(nullifier)
    }

    /// Drop every nullifier-map entry not referenced by a currently tracked
    /// unspent note or by a pending spend, returning how many were removed.
    ///
    /// The map keeps one entry per note ever received so that
    /// [`note_from_nullifier`](Self::note_from_nullifier) can attribute
    /// spends; left alone it grows forever. Pruning is explicit and opt-in:
    /// pruned nullifiers can no longer be attributed, so callers that use
    /// nullifier→note attribution for reconciliation should call this only
    /// AFTER reconciling. Deterministic — the same wallet state prunes to the
    /// same result here and in the JS SDK. Save/load format is unchanged.
    pub fn prune_nullifiers(&mut self) -> usize {
        let referenced: HashSet<&String> = self
            .notes
            .iter()
            .map(|n| &n.nullifier)
            .chain(self.pending_spends.values().flatten())
            .collect();
        let before = self.nullifier_map.len();
        self.nullifier_map.retain(|nf, _| referenced.contains(nf));
        before - self.nullifier_map.len()
    }

    // ── Scanning ────────────────────────────────────────────────────────

    /// Scan blocks (strictly ascending heights, all above the last synced
    /// block). Returns the raw hexes of wallet-relevant transactions.
    /// Use directly with your own block feed, or see [`sync`](Self::sync).
    pub fn handle_blocks(&mut self, blocks: &[WalletBlock]) -> Result<Vec<String>> {
        let mut prev = self.last_processed_block;
        let activation = sapling_activation(self.network);
        for b in blocks {
            // Reject a height that couldn't round-trip through save()/load()
            // (bounded to [0, 2^53-1], symmetric with the JS SDK's
            // Number.isSafeInteger guard in applyBlocks): otherwise a scan would
            // advance last_processed_block to a value load() later rejects,
            // leaving the saved state unloadable. Checked before any state is
            // touched, so the wallet is left intact on error.
            if !(0..=(1i64 << 53) - 1).contains(&b.height) {
                return Err(WalletError::Other(format!(
                    "block height must be in [0, 2^53-1], got {}",
                    b.height
                )));
            }
            if b.height <= prev {
                return Err(WalletError::NonAscendingBlocks);
            }
            prev = b.height;
        }
        let Some(last) = blocks.last() else {
            return Ok(vec![]);
        };
        let last_height = last.height;

        // Below sapling activation, '03'-prefixed txs are SKIPPED rather than
        // scanned: consensus forbids shielded DATA below activation
        // (IsShieldedTx = sapling version AND sapling data, PIVX
        // transaction.h / sapling_validation.cpp), not the version byte
        // itself, so a bare-v3 empty-sapdata tx is consensus-legal and must
        // not fail the sync. Bare v3 is excluded from real chains by
        // serialization history and carries no shield data, so skipping loses
        // nothing; fabricated sapling data below activation is unverifiable
        // (the root check is skipped down there) and stays uncredited because
        // it never reaches the scanner.
        let tx_hexes: Vec<String> = blocks
            .iter()
            .flat_map(|b| {
                let below_activation = b.height < activation;
                b.tx_hexes
                    .iter()
                    .filter(move |h| !(below_activation && h.starts_with("03")))
                    .cloned()
            })
            .collect();
        // Clone rather than move the notes out: if the scan fails (bad tx hex
        // from the node, corrupt witness in loaded state), `?` returns before
        // we reassign, and `self.notes` must be left intact for the caller.
        let result = transaction::scan_transactions(
            &self.commitment_tree,
            &tx_hexes,
            &self.extfvk,
            self.network,
            self.notes.clone(),
        )?;

        self.commitment_tree = result.commitment_tree;
        for n in &result.new_notes {
            // Skip sub-dust notes (same gate as the JS SDK and as the tracked-
            // note purge below): a dust note is never spendable, so keeping its
            // attribution would only let a dust flood grow nullifier_map without
            // bound between prune_nullifiers() calls.
            if n.note.value().inner() <= transaction::DUST_NOTE_SATS {
                continue;
            }
            let addr = sapling::PaymentAddress::from_bytes(&n.note.recipient().to_bytes())
                .map(|a| keys::encode_payment_address(&a, self.network))
                .unwrap_or_default();
            self.nullifier_map.insert(
                n.nullifier.clone(),
                AttributedNote {
                    recipient: addr,
                    value: n.note.value().inner(),
                },
            );
        }
        let spent: HashSet<&String> = result.spent_nullifiers.iter().collect();
        // Purge sub-dust notes from tracked state on every scan pass — not
        // only newly decrypted ones — so a dust flood can't grow state or
        // per-block witness cost, and a state carrying dust (e.g. loaded from
        // an older save) converges with the JS SDK after one sync. Same
        // threshold as spend selection; the commitments stay in the tree.
        self.notes = result
            .notes
            .into_iter()
            .chain(result.new_notes)
            .filter(|n| {
                !spent.contains(&n.nullifier)
                    && n.note.value().inner() > transaction::DUST_NOTE_SATS
            })
            .collect();
        // Drop pending-spend entries whose notes are now gone (their tx
        // confirmed and was scanned out), so pending_spends can't leak.
        let tracked: HashSet<&String> = self.notes.iter().map(|n| &n.nullifier).collect();
        self.pending_spends
            .retain(|_, nulls| nulls.iter().any(|n| tracked.contains(n)));
        self.last_processed_block = last_height;
        Ok(result.wallet_transactions)
    }

    /// Root of the local commitment tree, byte-reversed to match the node's
    /// `finalsaplingroot` display order.
    pub fn sapling_root(&self) -> Result<String> {
        let natural = sapling_root(&self.commitment_tree)?;
        let mut bytes = hex::decode(&natural).map_err(|e| WalletError::Other(e.to_string()))?;
        bytes.reverse();
        Ok(hex::encode(bytes))
    }

    // ── Spending ────────────────────────────────────────────────────────

    /// Build and prove a transaction locally. Nothing is broadcast; spent
    /// notes are held pending until [`finalize_transaction`](Self::finalize_transaction)
    /// or [`discard_transaction`](Self::discard_transaction).
    ///
    /// Proving is multi-second CPU-bound Groth16 work and runs inline: this
    /// future blocks its executor thread until the proof completes. On an
    /// async server prefer `send` (rpc feature), which proves on a blocking
    /// thread — or run this future on a dedicated thread yourself.
    pub async fn create_transaction(&mut self, opts: &SendOptions) -> Result<BuiltTransaction> {
        let job = self.plan_transaction(opts)?;
        let built = job.prove()?;
        self.track_pending_spend(opts, &built);
        Ok(built)
    }

    /// Fast planning phase (guards, input selection, change address). Returns
    /// an owned CPU-only proving job so the caller decides where the
    /// multi-second proving runs.
    fn plan_transaction(&mut self, opts: &SendOptions) -> Result<transaction::ProvingJob> {
        if self.extsk.is_none() {
            return Err(WalletError::NoSpendAuthority);
        }
        if !prover::prover_is_loaded() {
            return Err(WalletError::ProverNotLoaded);
        }
        let pending: HashSet<String> = self.pending_spends.values().flatten().cloned().collect();

        // Deriving the shield change address advances diversifier_index, but
        // planning can still fail (e.g. insufficient balance). Roll the index
        // back on failure so a failed send does not grow the address gap —
        // the JS SDK likewise only consumes an address on a successful plan.
        let saved_diversifier_index = self.diversifier_index;
        let (notes, utxos, change_address) = match &opts.inputs {
            Inputs::Shield => {
                let spendable: Vec<SerializedNote> = self
                    .notes
                    .iter()
                    .filter(|n| !pending.contains(&n.nullifier))
                    .cloned()
                    .collect();
                (Some(spendable), None, self.new_address()?)
            }
            Inputs::Transparent {
                utxos,
                change_address,
            } => (None, Some(utxos.clone()), change_address.clone()),
        };
        let extsk = self.extsk.as_ref().expect("checked above");

        let planned = transaction::plan_transaction(TxOptions {
            notes,
            utxos,
            extsk,
            to_address: &opts.to,
            change_address: &change_address,
            amount: opts.amount,
            block_height: (self.last_processed_block + 1) as u32,
            network: self.network,
            memo: opts.memo.clone().unwrap_or_default(),
            subtract_fee_from_amount: opts.subtract_fee_from_amount,
        });
        if planned.is_err() {
            self.diversifier_index = saved_diversifier_index;
        }
        planned
    }

    /// Pending-spend bookkeeping once a transaction is built: shield inputs
    /// hold their notes pending until finalize/discard.
    fn track_pending_spend(&mut self, opts: &SendOptions, built: &BuiltTransaction) {
        if matches!(opts.inputs, Inputs::Shield) {
            self.pending_spends
                .insert(built.txid.clone(), built.nullifiers.clone());
        }
    }

    /// Mark a broadcast transaction's notes as spent.
    pub fn finalize_transaction(&mut self, txid: &str) {
        if let Some(nullifiers) = self.pending_spends.remove(txid) {
            let spent: HashSet<String> = nullifiers.into_iter().collect();
            self.notes.retain(|n| !spent.contains(&n.nullifier));
        }
    }

    /// Release a failed transaction's notes back to the spendable set.
    pub fn discard_transaction(&mut self, txid: &str) {
        self.pending_spends.remove(txid);
    }

    /// Transactions built and broadcast but not yet finalized or discarded
    /// (txid → the nullifiers they spend). After a broadcast error left a
    /// spend ambiguous, use this to find the txid, confirm it on-chain, then
    /// [`finalize_transaction`](Self::finalize_transaction) or
    /// [`discard_transaction`](Self::discard_transaction).
    pub fn pending_transactions(&self) -> &HashMap<String, Vec<String>> {
        &self.pending_spends
    }

    // ── Persistence ─────────────────────────────────────────────────────

    /// Serialize wallet state to JSON (same format as the JS SDK, v1). The
    /// spending key is excluded — persist it separately (encrypted) and
    /// restore with [`load_spending_key`](Self::load_spending_key).
    pub fn save(&self) -> Result<String> {
        Ok(serde_json::to_string(&WalletState {
            version: 1,
            network: match self.network {
                Network::MainNetwork => "mainnet".into(),
                Network::TestNetwork => "testnet".into(),
            },
            extfvk: keys::encode_extended_full_viewing_key(&self.extfvk, self.network),
            last_processed_block: self.last_processed_block,
            commitment_tree: self.commitment_tree.clone(),
            diversifier_index: self.diversifier_index.to_vec(),
            notes: self.notes.clone(),
            nullifier_map: self.nullifier_map.clone(),
            pending_spends: self.pending_spends.clone(),
        })?)
    }

    /// Restore from [`save`](Self::save) output (watch-only until a spending
    /// key is loaded).
    pub fn load(json: &str) -> Result<Self> {
        Self::load_inner(json, None)
    }

    /// Restore, requiring the state's viewing key to equal `expected_viewing_key`.
    ///
    /// For a watch-only deposit scanner, verify against the key you know this
    /// wallet should have: a tampered state file that swapped in an attacker's
    /// viewing key would otherwise silently repoint deposit addresses. Saved-
    /// state integrity is theft-critical for a watch-only scanner.
    pub fn load_verified(json: &str, expected_viewing_key: &str) -> Result<Self> {
        Self::load_inner(json, Some(expected_viewing_key))
    }

    fn load_inner(json: &str, expected_viewing_key: Option<&str>) -> Result<Self> {
        let state: WalletState = serde_json::from_str(json)?;
        if let Some(expected) = expected_viewing_key {
            if expected != state.extfvk {
                return Err(WalletError::Other(
                    "wallet state viewing key does not match the expected key".into(),
                ));
            }
        }
        if state.version != 1 {
            return Err(WalletError::Other(format!(
                "unsupported wallet state version {}",
                state.version
            )));
        }
        let network = match state.network.as_str() {
            "mainnet" => Network::MainNetwork,
            "testnet" => Network::TestNetwork,
            other => return Err(WalletError::Other(format!("unknown network {other}"))),
        };
        let extfvk = keys::decode_extended_full_viewing_key(&state.extfvk, network)?;
        // Bound the sync position to [0, 2^53-1], symmetric with the scan-height
        // bounds and the JS SDK (a state loads in both or neither), so downstream
        // block-height math can't underflow/overflow on a tampered state.
        if !(0..=(1i64 << 53) - 1).contains(&state.last_processed_block) {
            return Err(WalletError::Other(
                "wallet state last-processed block must be in [0, 2^53-1]".into(),
            ));
        }
        Ok(Self {
            network,
            extsk: None,
            extfvk,
            commitment_tree: state.commitment_tree,
            last_processed_block: state.last_processed_block,
            diversifier_index: state
                .diversifier_index
                .try_into()
                .map_err(|_| WalletError::Other("bad diversifier index".into()))?,
            notes: state.notes,
            nullifier_map: state.nullifier_map,
            pending_spends: state.pending_spends,
            start_validated: false,
        })
    }

    /// Reset scan state to the checkpoint at or below `height` and drop all
    /// tracked notes. This is the recovery path after a divergence error:
    /// call it, then re-sync. It needs no keys.
    ///
    /// Rejects a `height` outside `[0, i32::MAX]` — the same guard the
    /// constructors apply to `birth_height` — rather than clamping: a clamped
    /// height would silently reset to a valid-but-wrong checkpoint instead of
    /// surfacing the bad input.
    pub fn reload_from_checkpoint(&mut self, height: i64) -> Result<()> {
        if !(0..=i32::MAX as i64).contains(&height) {
            return Err(WalletError::Other(format!(
                "checkpoint height must be an integer in [0, 2^31-1], got {height}"
            )));
        }
        let (cp_height, cp_tree) = get_checkpoint(height as i32, self.network);
        self.commitment_tree = cp_tree.to_string();
        self.last_processed_block = cp_height as i64;
        self.notes.clear();
        self.nullifier_map.clear();
        self.pending_spends.clear();
        self.start_validated = false;
        Ok(())
    }
}

#[cfg(test)]
impl ShieldWallet {
    pub(crate) fn set_commitment_tree_for_test(&mut self, tree_hex: &str) {
        self.commitment_tree = tree_hex.to_string();
    }

    /// Place the wallet at a synced height and skip checkpoint confirmation,
    /// so a stub-node test can exercise the per-batch sync guards directly.
    pub(crate) fn prime_for_sync_test(&mut self, height: i64) {
        self.last_processed_block = height;
        self.start_validated = true;
    }
}

#[cfg(feature = "rpc")]
mod rpc_sync {
    use super::*;
    use pivx_rpc::PivxClient;

    /// The node's `finalsaplingroot` at height `h`, or None below activation.
    /// Above activation an omitted root is an error, not "no root" — otherwise
    /// a node could suppress the checkpoint check or force a full rewind by
    /// simply withholding the field.
    async fn node_sapling_root(
        client: &PivxClient,
        h: i64,
        network: Network,
    ) -> Result<Option<String>> {
        if h < sapling_activation(network) {
            return Ok(None);
        }
        let hash = client.get_block_hash(h).await?;
        let block = client.get_block(&hash, 1).await?;
        match block["finalsaplingroot"].as_str() {
            Some(r) => Ok(Some(r.to_string())),
            None => Err(WalletError::Other(format!(
                "node omitted finalsaplingroot at height {h} (past sapling activation)"
            ))),
        }
    }

    /// Root of a checkpoint tree in the node's display byte order.
    fn reversed_root(tree_hex: &str) -> Result<String> {
        let natural = transaction::sapling_root(tree_hex)?;
        let mut bytes = hex::decode(&natural).map_err(|e| WalletError::Other(e.to_string()))?;
        bytes.reverse();
        Ok(hex::encode(bytes))
    }

    impl ShieldWallet {
        /// Confirm the starting commitment tree against the node before
        /// scanning forward. A fresh wallet begins at a bundled checkpoint;
        /// if that checkpoint's tree does not match the node's sapling root
        /// at that height (some near-tip checkpoints are captured on stale
        /// blocks), walk back to the newest checkpoint the node confirms. A
        /// wallet that already holds scanned notes and no longer matches is
        /// treated as diverged rather than silently rewound.
        async fn ensure_valid_checkpoint(&mut self, client: &PivxClient) -> Result<()> {
            if self.start_validated {
                return Ok(());
            }
            let local = reversed_root(&self.commitment_tree)?;
            match node_sapling_root(client, self.last_processed_block, self.network).await? {
                None => {}
                Some(n) if n == local => {}
                Some(n) => {
                    // A rewind is only appropriate for a fresh wallet still
                    // sitting on a bundled checkpoint. A wallet that scanned
                    // forward (past a checkpoint, or holding notes) and no
                    // longer matches is diverged — rewinding would silently
                    // discard correct progress.
                    let (nearest, _) =
                        get_checkpoint(self.last_processed_block as i32, self.network);
                    let at_checkpoint = nearest as i64 == self.last_processed_block;
                    if !self.notes.is_empty() || !self.pending_spends.is_empty() || !at_checkpoint {
                        return Err(WalletError::ScanDiverged {
                            height: self.last_processed_block,
                            local,
                            node: n,
                        });
                    }
                    let mut probe = self.last_processed_block - 1;
                    let mut last_cp = self.last_processed_block;
                    let mut adopted = false;
                    while probe > 0 {
                        let (cp_h, cp_tree) = get_checkpoint(probe as i32, self.network);
                        let cp_h = cp_h as i64;
                        if cp_h >= last_cp {
                            break; // no older checkpoint available
                        }
                        last_cp = cp_h;
                        let node_root = node_sapling_root(client, cp_h, self.network).await?;
                        let cp_root = reversed_root(cp_tree)?;
                        if node_root.is_none() || node_root.as_deref() == Some(cp_root.as_str()) {
                            self.commitment_tree = cp_tree.to_string();
                            self.last_processed_block = cp_h;
                            adopted = true;
                            break;
                        }
                        probe = cp_h - 1;
                    }
                    // No bundled checkpoint matched the node: do not proceed on
                    // an unconfirmed tree. Surface it rather than "validating".
                    if !adopted {
                        return Err(WalletError::ScanDiverged {
                            height: self.last_processed_block,
                            local,
                            node: n,
                        });
                    }
                }
            }
            self.start_validated = true;
            Ok(())
        }

        /// Sync from the node to its tip.
        ///
        /// Each batch checks the locally-built tree against the node's own
        /// `finalsaplingroot`. That catches malformed or mis-ordered data,
        /// but it is a self-consistency check, not chain authentication: the
        /// SDK does not validate proof-of-stake, so a dishonest node can serve
        /// a self-consistent fabricated chain. Point this at a node you trust.
        /// See SECURITY.md.
        pub async fn sync(&mut self, client: &PivxClient, batch_size: i64) -> Result<()> {
            // batch_size <= 0 would make an empty range and a misleading
            // error; clamp like the transparent wallet's sync.
            let batch_size = batch_size.max(1);
            let tip = client.get_block_count().await?;
            self.ensure_valid_checkpoint(client).await?;
            // Stale-tip reorg detection: when the tip height hasn't advanced
            // past ours the batch loop below never runs, so its per-batch root
            // check can't notice a same-height reorg that rewrote the shielded
            // set at our tip. The commitment tree can't be cheaply rewound, so
            // re-verify the tip's finalsaplingroot against our local root (the
            // same comparison the batch loop makes) and diverge on mismatch;
            // the caller recovers via reload_from_checkpoint. Run this whenever
            // last_processed == tip, including at an exact checkpoint height: a
            // fresh wallet still on its checkpoint has a tree whose root equals
            // the node's finalsaplingroot there (ensure_valid_checkpoint just
            // confirmed it), so the match is a clean no-op, not a false positive.
            // Route the fetch through node_sapling_root so the check is skipped
            // below the sapling_activation threshold: below real V5_0 the node
            // reports a zero root our non-zero empty tree can't match, so an
            // honest wallet would false-diverge — the same activation exception
            // ensure_valid_checkpoint already relies on.
            if self.last_processed_block == tip {
                if let Some(node_root) = node_sapling_root(client, tip, self.network).await? {
                    let local = self.sapling_root()?;
                    if local != node_root {
                        return Err(WalletError::ScanDiverged {
                            height: tip,
                            local,
                            node: node_root,
                        });
                    }
                }
            }
            while self.last_processed_block < tip {
                let from = self.last_processed_block + 1;
                let to = (from + batch_size - 1).min(tip);
                let mut blocks = Vec::with_capacity((to - from + 1) as usize);
                let mut node_root: Option<String> = None;
                for h in from..=to {
                    let hash = client.get_block_hash(h).await?;
                    let block = client.get_block(&hash, 2).await?;
                    // Trust the height we asked for, not the one the node
                    // echoes, and reject a mismatch — otherwise a lying node
                    // can fast-forward last_processed_block past real deposits.
                    if block["height"].as_i64() != Some(h) {
                        return Err(WalletError::Other(format!(
                            "node returned block height {:?} for requested height {h}",
                            block["height"].as_i64()
                        )));
                    }
                    // A tx object without "hex" is malformed: fail rather than
                    // silently dropping it (dropping desyncs the tree).
                    let tx_hexes = block["tx"]
                        .as_array()
                        .ok_or_else(|| WalletError::Other(format!("block {h} has no tx array")))?
                        .iter()
                        .map(|t| {
                            t["hex"].as_str().map(String::from).ok_or_else(|| {
                                WalletError::Other(format!("block {h} has a tx without hex"))
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    node_root = block["finalsaplingroot"].as_str().map(String::from);
                    blocks.push(WalletBlock {
                        height: h,
                        tx_hexes,
                    });
                }

                // Snapshot so a failed root check can't leave partial state.
                // Includes pending_spends because handle_blocks reconciles it.
                let snapshot = (
                    self.commitment_tree.clone(),
                    self.last_processed_block,
                    self.notes.clone(),
                    self.nullifier_map.clone(),
                    self.pending_spends.clone(),
                );
                let result = (|| {
                    self.handle_blocks(&blocks)?;
                    // Verify the locally-built tree against the node's
                    // finalsaplingroot, except below the sapling_activation
                    // threshold, where we skip: below real V5_0 the node reports
                    // a zero root our non-zero empty tree can't match, and no
                    // shielded txs exist below activation anyway, so there is
                    // nothing to verify. Both networks can scan into the skip
                    // window: a testnet wallet with a below-activation birth
                    // height resumes from the height-0 empty-tree checkpoint,
                    // and a mainnet wallet resumes from checkpoint 2_700_000 and
                    // scans the empty [2_700_001, 2_700_500) gap below its real
                    // activation. Same exception node_sapling_root encodes.
                    if to >= sapling_activation(self.network) {
                        // A shielded chain always reports a sapling root; a
                        // missing one past activation means the node is lying.
                        // Refuse to advance unverified rather than skipping the
                        // only check.
                        let node_root = node_root.ok_or_else(|| {
                            WalletError::Other(format!(
                                "node omitted finalsaplingroot at height {to}"
                            ))
                        })?;
                        let local = self.sapling_root()?;
                        if local != node_root {
                            return Err(WalletError::ScanDiverged {
                                height: to,
                                local,
                                node: node_root,
                            });
                        }
                    }
                    Ok(())
                })();
                if result.is_err() {
                    self.commitment_tree = snapshot.0;
                    self.last_processed_block = snapshot.1;
                    self.notes = snapshot.2;
                    self.nullifier_map = snapshot.3;
                    self.pending_spends = snapshot.4;
                }
                result?;
            }
            Ok(())
        }

        /// Build, broadcast, and finalize in one step.
        ///
        /// The CPU-bound proving step runs via `tokio::task::spawn_blocking`,
        /// so the runtime's worker threads stay live for other tasks during
        /// the multi-second proof.
        pub async fn send(&mut self, client: &PivxClient, opts: &SendOptions) -> Result<String> {
            let job = self.plan_transaction(opts)?;
            let tx = tokio::task::spawn_blocking(move || job.prove())
                .await
                .map_err(|e| WalletError::Other(format!("proving task failed: {e}")))??;
            self.track_pending_spend(opts, &tx);
            match client.send_raw_transaction(&tx.txhex).await {
                Ok(txid) => {
                    self.finalize_transaction(&tx.txid);
                    Ok(txid)
                }
                Err(err) => {
                    // Only release the notes when the node definitively
                    // rejected the transaction. On a transport error the node
                    // may have accepted it, and some RPC "errors" mean the
                    // node already HAS the transaction (or a conflicting one):
                    // -27 = already in chain (PIVX rpc/protocol.h), the
                    // reject reasons txn-already-in-mempool / txn-already-known
                    // / txn-mempool-conflict, and the shield-specific
                    // bad-txns-nullifier-double-spent (a mempool tx already
                    // spends a nullifier of ours — possibly this very tx,
                    // rebroadcast or raced) and
                    // bad-txns-shielded-requirements-not-met
                    // (HaveShieldedRequirements: an anchor/nullifier already
                    // spent on-chain) — all PIVX validation.cpp. The -27
                    // already-in-chain probe scans vout only
                    // (rawtransaction.cpp), so it can never fire for a z→z
                    // spend; the shield-specific reasons fire instead. Keep
                    // those pending too — discarding could let a retry
                    // double-spend or an operator double-pay; the txid stays
                    // visible in pending_transactions(). Recover per
                    // docs/deployment.md.
                    if let pivx_rpc::Error::Rpc { code, message, .. } = &err {
                        let node_may_have_tx = *code == -27
                            || message.contains("txn-already-in-mempool")
                            || message.contains("txn-already-known")
                            || message.contains("txn-mempool-conflict")
                            || message.contains("bad-txns-nullifier-double-spent")
                            || message.contains("bad-txns-shielded-requirements-not-met");
                        if !node_may_have_tx {
                            self.discard_transaction(&tx.txid);
                        }
                    }
                    Err(err.into())
                }
            }
        }
    }
}
