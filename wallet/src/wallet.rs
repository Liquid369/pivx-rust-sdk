use std::collections::{HashMap, HashSet};

use pivx_primitives::consensus::Network;
use sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use serde::{Deserialize, Serialize};

use crate::checkpoint::get_checkpoint;
use crate::error::{Result, WalletError};
use crate::keys;
use crate::prover;
use crate::transaction::{
    self, sapling_root, BuiltTransaction, SerializedNote, TxOptions, Utxo,
};

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
}

/// Note attribution kept per nullifier (payment attribution for spends).
#[derive(Clone, Serialize, Deserialize)]
pub struct AttributedNote {
    pub recipient: String,
    pub value: u64,
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
}

impl ShieldWallet {
    /// Full-capability wallet from 32 bytes of seed entropy (ZIP32, PIVX
    /// coin type). Scanning starts at the checkpoint nearest `birth_height`.
    pub fn from_seed(seed: &[u8; 32], network: Network, birth_height: i64, account_index: u32) -> Result<Self> {
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
        let (_, checkpoint_tree) = get_checkpoint(birth_height as i32, network);
        let (_, diversifier_index) = keys::default_address(&extfvk, network);
        Ok(Self {
            network,
            extsk,
            extfvk,
            commitment_tree: checkpoint_tree.to_string(),
            last_processed_block: birth_height,
            diversifier_index,
            notes: vec![],
            nullifier_map: HashMap::new(),
            pending_spends: HashMap::new(),
        })
    }

    /// Upgrade a watch-only wallet. The key must match the stored viewing key.
    pub fn load_spending_key(&mut self, enc_extsk: &str) -> Result<()> {
        if self.extsk.is_some() {
            return Err(WalletError::InvalidKey("wallet already has a spending key".into()));
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
        let (address, index) = keys::next_address(&self.extfvk, self.diversifier_index, self.network)?;
        self.diversifier_index = index;
        Ok(address)
    }

    /// Confirmed shielded balance in satoshis (scanned notes minus pending spends).
    pub fn balance(&self) -> u64 {
        let pending: HashSet<&String> = self.pending_spends.values().flatten().collect();
        self.notes
            .iter()
            .filter(|n| !pending.contains(&n.nullifier))
            .map(|n| n.note.value().inner())
            .sum()
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

    // ── Scanning ────────────────────────────────────────────────────────

    /// Scan blocks (strictly ascending heights, all above the last synced
    /// block). Returns the raw hexes of wallet-relevant transactions.
    /// Use directly with your own block feed, or see [`sync`](Self::sync).
    pub fn handle_blocks(&mut self, blocks: &[WalletBlock]) -> Result<Vec<String>> {
        let mut prev = self.last_processed_block;
        for b in blocks {
            if b.height <= prev {
                return Err(WalletError::NonAscendingBlocks);
            }
            prev = b.height;
        }
        let Some(last) = blocks.last() else { return Ok(vec![]) };
        let last_height = last.height;

        let tx_hexes: Vec<String> = blocks.iter().flat_map(|b| b.tx_hexes.iter().cloned()).collect();
        let result = transaction::scan_transactions(
            &self.commitment_tree,
            &tx_hexes,
            &self.extfvk,
            self.network,
            std::mem::take(&mut self.notes),
        )?;

        self.commitment_tree = result.commitment_tree;
        for n in &result.new_notes {
            let addr = sapling::PaymentAddress::from_bytes(&n.note.recipient().to_bytes())
                .map(|a| keys::encode_payment_address(&a, self.network))
                .unwrap_or_default();
            self.nullifier_map.insert(
                n.nullifier.clone(),
                AttributedNote { recipient: addr, value: n.note.value().inner() },
            );
        }
        let spent: HashSet<&String> = result.spent_nullifiers.iter().collect();
        self.notes = result
            .notes
            .into_iter()
            .chain(result.new_notes)
            .filter(|n| !spent.contains(&n.nullifier))
            .collect();
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
    pub async fn create_transaction(&mut self, opts: &SendOptions) -> Result<BuiltTransaction> {
        if self.extsk.is_none() {
            return Err(WalletError::NoSpendAuthority);
        }
        if !prover::prover_is_loaded() {
            return Err(WalletError::ProverNotLoaded);
        }
        let pending: HashSet<String> = self.pending_spends.values().flatten().cloned().collect();

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
            Inputs::Transparent { utxos, change_address } => {
                (None, Some(utxos.clone()), change_address.clone())
            }
        };
        let extsk = self.extsk.as_ref().expect("checked above");

        let built = transaction::create_transaction(TxOptions {
            notes,
            utxos,
            extsk,
            to_address: &opts.to,
            change_address: &change_address,
            amount: opts.amount,
            block_height: (self.last_processed_block + 1) as u32,
            network: self.network,
            memo: opts.memo.clone().unwrap_or_default(),
        })
        .await?;

        if matches!(opts.inputs, Inputs::Shield) {
            self.pending_spends.insert(built.txid.clone(), built.nullifiers.clone());
        }
        Ok(built)
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
        })?)
    }

    /// Restore from [`save`](Self::save) output (watch-only until a spending
    /// key is loaded).
    pub fn load(json: &str) -> Result<Self> {
        let state: WalletState = serde_json::from_str(json)?;
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
            pending_spends: HashMap::new(),
        })
    }
}

#[cfg(test)]
impl ShieldWallet {
    pub(crate) fn set_commitment_tree_for_test(&mut self, tree_hex: &str) {
        self.commitment_tree = tree_hex.to_string();
    }
}

#[cfg(feature = "rpc")]
mod rpc_sync {
    use super::*;
    use pivx_rpc::PivxClient;

    impl ShieldWallet {
        /// Sync from the node to its tip, verifying the local tree against
        /// the node's `finalsaplingroot` each batch.
        pub async fn sync(&mut self, client: &PivxClient, batch_size: i64) -> Result<()> {
            let tip = client.get_block_count().await?;
            while self.last_processed_block < tip {
                let from = self.last_processed_block + 1;
                let to = (from + batch_size - 1).min(tip);
                let mut blocks = Vec::with_capacity((to - from + 1) as usize);
                let mut node_root: Option<String> = None;
                for h in from..=to {
                    let hash = client.get_block_hash(h).await?;
                    let block = client.get_block(&hash, 2).await?;
                    let tx_hexes = block["tx"]
                        .as_array()
                        .map(|txs| {
                            txs.iter()
                                .filter_map(|t| t["hex"].as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    node_root = block["finalsaplingroot"].as_str().map(String::from);
                    blocks.push(WalletBlock { height: h, tx_hexes });
                }
                self.handle_blocks(&blocks)?;
                if let Some(node_root) = node_root {
                    let local = self.sapling_root()?;
                    if local != node_root {
                        return Err(WalletError::ScanDiverged { height: to, local, node: node_root });
                    }
                }
            }
            Ok(())
        }

        /// Build, broadcast, and finalize in one step.
        pub async fn send(&mut self, client: &PivxClient, opts: &SendOptions) -> Result<String> {
            let tx = self.create_transaction(opts).await?;
            match client.send_raw_transaction(&tx.txhex).await {
                Ok(txid) => {
                    self.finalize_transaction(&tx.txid);
                    Ok(txid)
                }
                Err(err) => {
                    self.discard_transaction(&tx.txid);
                    Err(err.into())
                }
            }
        }
    }
}
