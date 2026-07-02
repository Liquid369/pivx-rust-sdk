//! Shielded scanning and transaction building.
//!
//! Adapted from PIVX-Labs/pivx-shield `src/transaction.rs` (MIT): wasm-bindgen
//! shims removed, native types throughout, single-threaded proving. If server
//! proving latency ever matters, enable pivx_proofs/multicore and add a rayon
//! build path.

use std::collections::HashMap;
use std::error::Error;
use std::io::Cursor;
use std::str::FromStr;

use either::Either;
use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use pivx_client_backend::decrypt_transaction;
use pivx_client_backend::keys::UnifiedFullViewingKey;
use pivx_primitives::consensus::{BlockHeight, BranchId, Network, NetworkConstants};
use pivx_primitives::legacy::Script;
use pivx_primitives::memo::{Memo, MemoBytes};
use pivx_primitives::merkle_tree::{
    read_commitment_tree as zcash_read_commitment_tree, read_incremental_witness,
    write_commitment_tree, write_incremental_witness,
};
use pivx_primitives::transaction::builder::{BuildConfig, Builder};
use pivx_primitives::transaction::components::transparent::builder::TransparentSigningSet;
use pivx_primitives::transaction::fees::fixed::FeeRule;
use pivx_primitives::transaction::Transaction;
use pivx_primitives::zip32::{AccountId, Scope};
use pivx_protocol::value::Zatoshis;
use rand_core::OsRng;
use sapling::builder::ProverProgress;
use sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use sapling::{note::Note, Anchor, Node, Nullifier, NullifierDerivingKey};
use secp256k1::{Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use zcash_transparent::bundle::{OutPoint, TxOut};

use crate::error::WalletError;
use crate::keys::{decode_generic_address, GenericAddress};
use crate::prover::get_loaded_prover;

pub const DEPTH: u8 = 32;

/// Height passed to note decryption; PIVX constant inherited from upstream.
const DECRYPT_HEIGHT: u32 = 320;

/// A tracked shielded note in wire/persisted form (witness hex-serialized).
/// Field names match the JS `pivx-wallet` state format.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializedNote {
    pub note: Note,
    /// Hex-serialized incremental merkle witness.
    pub witness: String,
    /// Hex nullifier — how spends of this note are recognized on-chain.
    pub nullifier: String,
    /// Decoded text memo, when the note carried one.
    pub memo: Option<String>,
}

pub(crate) struct SpendableNote {
    pub note: Note,
    pub witness: IncrementalWitness<Node, DEPTH>,
    pub nullifier: String,
    pub memo: Option<String>,
}

impl SpendableNote {
    fn from_serialized(n: SerializedNote) -> Result<SpendableNote, Box<dyn Error>> {
        let wit = Cursor::new(hex::decode(&n.witness)?);
        Ok(SpendableNote {
            note: n.note,
            witness: read_incremental_witness(wit)?,
            nullifier: n.nullifier,
            memo: n.memo,
        })
    }

    fn into_serialized(self) -> Result<SerializedNote, Box<dyn Error>> {
        let mut buff = Vec::new();
        write_incremental_witness(&self.witness, &mut buff)?;
        Ok(SerializedNote {
            note: self.note,
            witness: hex::encode(&buff),
            nullifier: self.nullifier,
            memo: self.memo,
        })
    }
}

pub fn read_commitment_tree(tree_hex: &str) -> Result<CommitmentTree<Node, DEPTH>, Box<dyn Error>> {
    let buff = Cursor::new(hex::decode(tree_hex)?);
    Ok(zcash_read_commitment_tree(buff)?)
}

pub fn commitment_tree_to_hex(
    tree: &CommitmentTree<Node, DEPTH>,
) -> Result<String, Box<dyn Error>> {
    let mut buff = Vec::new();
    write_commitment_tree(tree, &mut buff)?;
    Ok(hex::encode(buff))
}

/// Root of a hex-serialized commitment tree, natural byte order (the node's
/// `finalsaplingroot` is the byte-reversed form).
pub fn sapling_root(tree_hex: &str) -> Result<String, WalletError> {
    use pivx_primitives::merkle_tree::HashSer;
    let tree = read_commitment_tree(tree_hex).map_err(WalletError::from)?;
    let mut root = Vec::new();
    tree.root()
        .write(&mut root)
        .map_err(|e| WalletError::Other(e.to_string()))?;
    Ok(hex::encode(root))
}

pub struct ScanResult {
    /// Previously-known notes, witnesses advanced.
    pub notes: Vec<SerializedNote>,
    /// Newly decrypted notes.
    pub new_notes: Vec<SerializedNote>,
    /// All nullifiers spent in the scanned transactions.
    pub spent_nullifiers: Vec<String>,
    /// Updated commitment tree (hex).
    pub commitment_tree: String,
    /// Hexes of transactions relevant to this wallet.
    pub wallet_transactions: Vec<String>,
}

/// Scan raw transactions (hex) against a viewing key, advancing the
/// commitment tree and all note witnesses.
pub fn scan_transactions(
    tree_hex: &str,
    tx_hexes: &[String],
    extfvk: &ExtendedFullViewingKey,
    network: Network,
    known_notes: Vec<SerializedNote>,
) -> Result<ScanResult, WalletError> {
    let mut tree = read_commitment_tree(tree_hex).map_err(WalletError::from)?;
    let key = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk.clone())
        .map_err(|_| WalletError::InvalidKey("cannot build unified viewing key".into()))?;
    let nullif_key = key
        .sapling()
        .ok_or_else(|| WalletError::InvalidKey("cannot derive nullifier key".into()))?
        .to_nk(Scope::External);
    let mut accounts = HashMap::new();
    accounts.insert(AccountId::default(), key.clone());

    let mut notes = known_notes
        .into_iter()
        .map(SpendableNote::from_serialized)
        .collect::<Result<Vec<_>, _>>()
        .map_err(WalletError::from)?;

    let mut spent_nullifiers = vec![];
    let mut new_notes = vec![];
    let mut wallet_transactions = vec![];

    for hex_tx in tx_hexes {
        // Only version-3 transactions carry sapling data; skip the rest. They
        // contribute nothing to the tree and the parser rejects some of them.
        if !hex_tx.starts_with("03") {
            continue;
        }
        let tx = Transaction::read(
            Cursor::new(
                hex::decode(hex_tx).map_err(|_| WalletError::Other("invalid tx hex".into()))?,
            ),
            BranchId::Sapling,
        )
        .map_err(|e| WalletError::Other(format!("cannot parse tx: {e}")))?;
        let decrypted = decrypt_transaction(
            &network,
            BlockHeight::from_u32(DECRYPT_HEIGHT),
            &tx,
            &accounts,
        );

        let old_note_count = new_notes.len();
        let tx_nullifiers = handle_transaction(
            &mut tree,
            &tx,
            &decrypted,
            &nullif_key,
            &mut notes,
            &mut new_notes,
        )
        .map_err(WalletError::from)?
        .into_iter()
        .map(|n| hex::encode(n.0))
        .collect::<Vec<_>>();

        let is_wallet_tx = old_note_count != new_notes.len()
            || notes
                .iter()
                .chain(new_notes.iter())
                .any(|n| tx_nullifiers.contains(&n.nullifier));
        if is_wallet_tx {
            wallet_transactions.push(hex_tx.clone());
        }
        spent_nullifiers.extend(tx_nullifiers);
    }

    Ok(ScanResult {
        notes: serialize_notes(notes).map_err(WalletError::from)?,
        new_notes: serialize_notes(new_notes).map_err(WalletError::from)?,
        spent_nullifiers,
        commitment_tree: commitment_tree_to_hex(&tree).map_err(WalletError::from)?,
        wallet_transactions,
    })
}

fn serialize_notes(notes: Vec<SpendableNote>) -> Result<Vec<SerializedNote>, Box<dyn Error>> {
    notes
        .into_iter()
        .map(SpendableNote::into_serialized)
        .collect()
}

/// Add a tx to the commitment tree, advance every witness, and collect any
/// newly decrypted notes with fresh witnesses. (Upstream logic, verbatim.)
pub fn handle_transaction(
    tree: &mut CommitmentTree<Node, DEPTH>,
    tx: &Transaction,
    decrypted_tx: &pivx_client_backend::data_api::DecryptedTransaction<'_, AccountId>,
    nullif_key: &NullifierDerivingKey,
    witnesses: &mut [SpendableNote],
    new_witnesses: &mut Vec<SpendableNote>,
) -> Result<Vec<Nullifier>, Box<dyn Error>> {
    let mut nullifiers: Vec<Nullifier> = vec![];
    if let Some(sapling) = tx.sapling_bundle() {
        for x in sapling.shielded_spends() {
            nullifiers.push(*x.nullifier());
        }

        for (i, out) in sapling.shielded_outputs().iter().enumerate() {
            tree.append(Node::from_cmu(out.cmu()))
                .map_err(|_| "Failed to add cmu to tree")?;
            for &mut SpendableNote {
                ref mut witness, ..
            } in witnesses.iter_mut().chain(new_witnesses.iter_mut())
            {
                witness
                    .append(Node::from_cmu(out.cmu()))
                    .map_err(|_| "Failed to add cmu to witness")?;
            }
            for output in decrypted_tx.sapling_outputs() {
                let (note, index) = (output.note(), output.index());
                if index == i {
                    let witness = IncrementalWitness::<Node, DEPTH>::from_tree(tree.clone());
                    let nullifier = nullifier_for_note(nullif_key, note, &witness)?;
                    let memo = Memo::from_bytes(output.memo().as_slice())
                        .map(|m| {
                            if let Memo::Text(e) = m {
                                e.to_string()
                            } else {
                                String::new()
                            }
                        })
                        .ok();

                    new_witnesses.push(SpendableNote {
                        note: note.clone(),
                        witness,
                        nullifier,
                        memo,
                    });
                    break;
                }
            }
        }
    }
    Ok(nullifiers)
}

pub fn nullifier_for_note(
    nullif_key: &NullifierDerivingKey,
    note: &Note,
    witness: &IncrementalWitness<Node, DEPTH>,
) -> Result<String, Box<dyn Error>> {
    let path = witness.path().ok_or("Cannot find witness path")?;
    Ok(hex::encode(note.nf(nullif_key, path.position().into()).0))
}

/// A fully proved transaction, ready for `sendrawtransaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltTransaction {
    pub txid: String,
    pub txhex: String,
    /// Nullifiers this tx spends (for pending-spend tracking).
    pub nullifiers: Vec<String>,
}

/// Transparent UTXO used as input when shielding funds.
#[derive(Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    /// 32-byte private key controlling the UTXO.
    pub private_key: Vec<u8>,
    /// scriptPubKey bytes of the UTXO.
    pub script: Vec<u8>,
}

pub struct TxOptions<'a> {
    /// Shield-note inputs (mutually exclusive with `utxos`).
    pub notes: Option<Vec<SerializedNote>>,
    /// Transparent inputs for shielding (mutually exclusive with `notes`).
    pub utxos: Option<Vec<Utxo>>,
    pub extsk: &'a ExtendedSpendingKey,
    pub to_address: &'a str,
    pub change_address: &'a str,
    /// Satoshis.
    pub amount: u64,
    pub block_height: u32,
    pub network: Network,
    pub memo: String,
    /// Allow paying the fee out of the recipient's amount when the inputs
    /// cover `amount` but not `amount + fee` (sweep semantics). Default false:
    /// such a case returns `InsufficientBalance` rather than silently
    /// underpaying the recipient.
    pub subtract_fee_from_amount: bool,
}

/// Build and prove a transaction. Inputs are consumed smallest-first.
pub async fn create_transaction(options: TxOptions<'_>) -> Result<BuiltTransaction, WalletError> {
    let TxOptions {
        notes,
        utxos,
        extsk,
        to_address,
        change_address,
        amount,
        block_height,
        network,
        memo,
        subtract_fee_from_amount,
    } = options;
    assert!(
        !(notes.is_some() && utxos.is_some()),
        "Notes and UTXOs were both provided"
    );
    if amount == 0 {
        return Err(WalletError::Other(
            "amount must be greater than zero".into(),
        ));
    }
    if memo.len() > 512 {
        return Err(WalletError::Other("memo must be at most 512 bytes".into()));
    }

    let input = if let Some(notes) = notes {
        let mut notes: Vec<(Note, String)> =
            notes.into_iter().map(|n| (n.note, n.witness)).collect();
        notes.sort_by_key(|(note, _)| note.value().inner());
        Either::Left(notes)
    } else if let Some(mut utxos) = utxos {
        utxos.sort_by_key(|u| u.amount);
        Either::Right(utxos)
    } else {
        return Err(WalletError::Other("no inputs provided".into()));
    };

    create_transaction_internal(TxInternalArgs {
        inputs: input,
        extsk,
        to_address,
        change_address,
        amount,
        block_height: BlockHeight::from_u32(block_height),
        network,
        memo,
        subtract_fee_from_amount,
    })
    .await
}

struct TxInternalArgs<'a> {
    inputs: Either<Vec<(Note, String)>, Vec<Utxo>>,
    extsk: &'a ExtendedSpendingKey,
    to_address: &'a str,
    change_address: &'a str,
    amount: u64,
    block_height: BlockHeight,
    network: Network,
    memo: String,
    subtract_fee_from_amount: bool,
}

async fn create_transaction_internal(
    args: TxInternalArgs<'_>,
) -> Result<BuiltTransaction, WalletError> {
    let TxInternalArgs {
        inputs,
        extsk,
        to_address,
        change_address,
        mut amount,
        block_height,
        network,
        memo,
        subtract_fee_from_amount,
    } = args;

    let anchor = if let Either::Left(ref notes) = inputs {
        match notes.first() {
            Some((_, witness)) => {
                let witness = Cursor::new(
                    hex::decode(witness).map_err(|e| WalletError::Other(e.to_string()))?,
                );
                let witness = read_incremental_witness::<Node, _, DEPTH>(witness)
                    .map_err(|e| WalletError::Other(e.to_string()))?;
                Anchor::from_bytes(witness.root().to_bytes()).into_option()
            }
            None => None,
        }
    } else {
        None
    };

    let mut builder = Builder::new(
        network,
        block_height,
        BuildConfig::Standard {
            sapling_anchor: Some(anchor.unwrap_or(Anchor::empty_tree())),
            orchard_anchor: None,
        },
    );

    let mut transparent_signing_set = TransparentSigningSet::new();

    let (mut transparent_output_count, sapling_output_count) =
        if to_address.starts_with(network.hrp_sapling_payment_address()) {
            (0, 2)
        } else {
            (1, 2)
        };
    if !change_address.starts_with(network.hrp_sapling_payment_address()) {
        transparent_output_count += 1;
    }

    let (nullifiers, change, fee) = match inputs {
        Either::Left(notes) => choose_notes(
            &mut builder,
            &notes,
            extsk,
            &mut amount,
            transparent_output_count,
            sapling_output_count,
            subtract_fee_from_amount,
        )?,
        Either::Right(utxos) => choose_utxos(
            &mut builder,
            &utxos,
            &mut amount,
            transparent_output_count,
            sapling_output_count,
            &mut transparent_signing_set,
            subtract_fee_from_amount,
        )?,
    };

    let amount =
        Zatoshis::from_u64(amount).map_err(|_| WalletError::Other("invalid amount".into()))?;
    match decode_generic_address(network, to_address)? {
        GenericAddress::Transparent(x) => builder
            .add_transparent_output(&x, amount)
            .map_err(|e| WalletError::Other(e.to_string()))?,
        GenericAddress::Shield(x) => builder
            .add_sapling_output::<FeeRule>(
                None,
                x,
                amount,
                Memo::from_str(&memo)
                    .map(|m| m.encode())
                    .unwrap_or(MemoBytes::empty()),
            )
            .map_err(|_| WalletError::Other("failed to add output".into()))?,
    }

    if change.is_positive() {
        match decode_generic_address(network, change_address)? {
            GenericAddress::Transparent(x) => builder
                .add_transparent_output(&x, change)
                .map_err(|_| WalletError::Other("failed to add transparent change".into()))?,
            GenericAddress::Shield(x) => builder
                .add_sapling_output::<FeeRule>(None, x, change, MemoBytes::empty())
                .map_err(|_| WalletError::Other("failed to add shield change".into()))?,
        }
    }

    let prover = get_loaded_prover().ok_or(WalletError::ProverNotLoaded)?;
    prove_transaction(
        builder,
        extsk.clone(),
        &transparent_signing_set,
        nullifiers,
        fee,
        prover,
    )
    .map_err(WalletError::from)
}

fn choose_utxos(
    builder: &mut Builder<Network, impl ProverProgress>,
    utxos: &[Utxo],
    amount: &mut u64,
    transparent_output_count: u64,
    sapling_output_count: u64,
    transparent_signing_set: &mut TransparentSigningSet,
    subtract_fee_from_amount: bool,
) -> Result<(Vec<String>, Zatoshis, u64), WalletError> {
    let mut total: u64 = 0;
    let mut used_utxos = vec![];
    let mut transparent_input_count = 0;
    let mut fee = 0;
    let secp = Secp256k1::new();
    for utxo in utxos {
        used_utxos.push(format!("{},{}", utxo.txid, utxo.vout));
        let key = SecretKey::from_slice(&utxo.private_key)
            .map_err(|e| WalletError::InvalidKey(e.to_string()))?;
        builder
            .add_transparent_input(
                key.public_key(&secp),
                OutPoint::new(
                    hex::decode(&utxo.txid)
                        .map_err(|e| WalletError::Other(e.to_string()))?
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .try_into()
                        .map_err(|_| WalletError::Other("failed to decode txid".into()))?,
                    utxo.vout,
                ),
                TxOut {
                    value: Zatoshis::from_u64(utxo.amount)
                        .map_err(|_| WalletError::Other("invalid utxo amount".into()))?,
                    script_pubkey: Script(utxo.script.clone()),
                },
            )
            .map_err(|_| WalletError::Other("failed to use utxo".into()))?;
        transparent_signing_set.add_key(key);
        transparent_input_count += 1;
        fee = fee_calculator(
            transparent_input_count,
            transparent_output_count,
            0,
            sapling_output_count,
        );
        total = total.saturating_add(utxo.amount);
        if total >= amount.saturating_add(fee) {
            break;
        }
    }
    finish_input_selection(total, amount, fee, subtract_fee_from_amount)
        .map(|change| (used_utxos, change, fee))
}

fn choose_notes(
    builder: &mut Builder<Network, impl ProverProgress>,
    notes: &[(Note, String)],
    extsk: &ExtendedSpendingKey,
    amount: &mut u64,
    transparent_output_count: u64,
    sapling_output_count: u64,
    subtract_fee_from_amount: bool,
) -> Result<(Vec<String>, Zatoshis, u64), WalletError> {
    let mut total: u64 = 0;
    let mut nullifiers = vec![];
    let mut sapling_input_count = 0;
    let mut fee = 0;
    for (note, witness) in notes {
        let witness =
            Cursor::new(hex::decode(witness).map_err(|e| WalletError::Other(e.to_string()))?);
        let witness = read_incremental_witness::<Node, _, DEPTH>(witness)
            .map_err(|e| WalletError::Other(e.to_string()))?;
        builder
            .add_sapling_spend::<FeeRule>(
                extsk.to_diversifiable_full_viewing_key().fvk().clone(),
                note.clone(),
                witness
                    .path()
                    .ok_or_else(|| WalletError::Other("commitment tree is empty".into()))?,
            )
            .map_err(|_| WalletError::Other("failed to add sapling spend".into()))?;
        let nullifier = note.nf(
            &extsk
                .to_diversifiable_full_viewing_key()
                .to_nk(Scope::External),
            witness.witnessed_position().into(),
        );
        nullifiers.push(hex::encode(nullifier.to_vec()));
        sapling_input_count += 1;
        fee = fee_calculator(
            0,
            transparent_output_count,
            sapling_input_count,
            sapling_output_count,
        );
        total = total.saturating_add(note.value().inner());
        if total >= amount.saturating_add(fee) {
            break;
        }
    }
    finish_input_selection(total, amount, fee, subtract_fee_from_amount)
        .map(|change| (nullifiers, change, fee))
}

/// Shared tail of input selection. When the inputs cover `amount` but not
/// `amount + fee`, the fee is deducted from `amount` only if the caller opted
/// into sweep semantics — otherwise this is `InsufficientBalance` rather than
/// a silent underpayment. All arithmetic is overflow-checked so an
/// adversarial `amount` can neither panic (debug) nor wrap (release).
fn finish_input_selection(
    total: u64,
    amount: &mut u64,
    fee: u64,
    subtract_fee_from_amount: bool,
) -> Result<Zatoshis, WalletError> {
    let needed = amount
        .checked_add(fee)
        .ok_or(WalletError::InsufficientBalance)?;
    if total < needed {
        if subtract_fee_from_amount && total >= *amount && *amount > fee {
            *amount -= fee;
        } else {
            return Err(WalletError::InsufficientBalance);
        }
    }
    let change = total
        .checked_sub(*amount)
        .and_then(|v| v.checked_sub(fee))
        .ok_or(WalletError::InsufficientBalance)?;
    Zatoshis::from_u64(change).map_err(|_| WalletError::Other("invalid change".into()))
}

/// Upstream fee model: 1000 per byte over a fixed size model.
fn fee_calculator(
    transparent_input_count: u64,
    transparent_output_count: u64,
    sapling_input_count: u64,
    sapling_output_count: u64,
) -> u64 {
    let fee_per_byte = 1000;
    let transparent_input_size = 150;
    let transparent_output_size = 34;
    let tx_offset_size = 85;
    let sapling_output_size = 948;
    let sapling_input_size = 384;
    fee_per_byte
        * (sapling_output_count * sapling_output_size
            + sapling_input_count * sapling_input_size
            + transparent_input_count * transparent_input_size
            + transparent_output_count * transparent_output_size
            + tx_offset_size)
}

fn prove_transaction(
    builder: Builder<'_, Network, impl ProverProgress>,
    extsk: ExtendedSpendingKey,
    transparent_keys: &TransparentSigningSet,
    nullifiers: Vec<String>,
    fee: u64,
    prover: &crate::prover::ImplTxProver,
) -> Result<BuiltTransaction, Box<dyn Error>> {
    let result = builder.build(
        transparent_keys,
        &[extsk],
        &[],
        OsRng,
        &prover.1,
        &prover.0,
        &FeeRule::non_standard(Zatoshis::from_u64(fee).map_err(|_| "Invalid fee")?),
    )?;

    let mut tx_hex = vec![];
    let tx = result.transaction();
    tx.write(&mut tx_hex)?;

    Ok(BuiltTransaction {
        txid: tx.txid().to_string(),
        txhex: hex::encode(tx_hex),
        nullifiers,
    })
}
