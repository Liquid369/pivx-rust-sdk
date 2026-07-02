//! Wallet-level tests on real fixtures (a regtest tx decrypting to a known
//! note) plus the upstream tx-builder test (MockProver under cfg(test)).

use crate::test_fixtures::*;
use crate::transaction::{self, TxOptions};
use crate::wallet::{SendOptions, ShieldWallet, WalletBlock};
use crate::{keys, WalletError};
use pivx_primitives::consensus::Network::TestNetwork;

const BIRTH: i64 = 100;

fn fixture_block() -> Vec<WalletBlock> {
    vec![WalletBlock {
        height: BIRTH + 1,
        tx_hexes: vec![TX_HEX.to_string()],
    }]
}

#[test]
fn key_derivation_is_deterministic() {
    let seed = [7u8; 32];
    let mut a = ShieldWallet::from_seed(&seed, TestNetwork, BIRTH, 0).unwrap();
    let mut b = ShieldWallet::from_seed(&seed, TestNetwork, BIRTH, 0).unwrap();
    let addr = a.new_address().unwrap();
    assert_eq!(addr, b.new_address().unwrap());
    assert!(addr.starts_with("ptestsapling1"));
    assert!(a.can_spend());
}

#[test]
fn scans_real_tx_into_spendable_note() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    let wallet_txs = wallet.handle_blocks(&fixture_block()).unwrap();

    assert_eq!(wallet_txs.len(), 1, "fixture tx is wallet-relevant");
    assert_eq!(wallet.balance(), 1_000_000_000);
    assert_eq!(wallet.notes().len(), 1);
    assert_eq!(wallet.last_synced_block(), BIRTH + 1);

    let nullifier = wallet.notes()[0].nullifier.clone();
    let attributed = wallet.note_from_nullifier(&nullifier).unwrap();
    assert_eq!(attributed.recipient, SHIELD_ADDRESS);
    assert_eq!(attributed.value, 1_000_000_000);
}

#[test]
fn handle_blocks_keeps_notes_when_scan_fails() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();
    assert_eq!(wallet.notes().len(), 1);

    // A v3-prefixed but malformed tx hex makes the scan fail. The tracked
    // note must survive the error, not be silently dropped.
    let bad = vec![WalletBlock {
        height: BIRTH + 2,
        tx_hexes: vec!["03zzzz".into()],
    }];
    assert!(wallet.handle_blocks(&bad).is_err());
    assert_eq!(wallet.notes().len(), 1, "notes preserved on scan failure");
    assert_eq!(wallet.balance(), 1_000_000_000);
}

#[tokio::test]
async fn watch_only_scans_but_cannot_spend() {
    let extsk = keys::decode_extsk(EXTSK, TestNetwork).unwrap();
    let extfvk =
        keys::encode_extended_full_viewing_key(&keys::extfvk_from_extsk(&extsk), TestNetwork);

    let mut watch = ShieldWallet::from_viewing_key(&extfvk, TestNetwork, BIRTH).unwrap();
    assert!(!watch.can_spend());
    watch.handle_blocks(&fixture_block()).unwrap();
    assert_eq!(watch.balance(), 1_000_000_000);

    let send = SendOptions::shield(SHIELD_ADDRESS, 1);
    assert!(matches!(
        watch.create_transaction(&send).await,
        Err(WalletError::NoSpendAuthority)
    ));

    // wrong key rejected, right key upgrades in place
    assert!(watch.load_spending_key(TX2_EXTSK).is_err());
    watch.load_spending_key(EXTSK).unwrap();
    assert!(watch.can_spend());
}

#[test]
fn save_load_round_trip_excludes_spending_key() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();

    let json = wallet.save().unwrap();
    assert!(!json.contains(EXTSK), "spending key must not be serialized");

    let mut restored = ShieldWallet::load(&json).unwrap();
    assert_eq!(restored.balance(), 1_000_000_000);
    assert_eq!(restored.last_synced_block(), BIRTH + 1);
    assert!(!restored.can_spend());
    restored.load_spending_key(EXTSK).unwrap();

    // non-ascending blocks rejected after restore
    assert!(matches!(
        restored.handle_blocks(&fixture_block()),
        Err(WalletError::NonAscendingBlocks)
    ));
}

/// Upstream test_create_transaction, on our native API (MockProver).
#[tokio::test]
async fn builds_transaction_with_expected_nullifier() {
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();

    let extsk = keys::decode_extsk(TX2_EXTSK, TestNetwork).unwrap();
    let extfvk =
        keys::encode_extended_full_viewing_key(&keys::extfvk_from_extsk(&extsk), TestNetwork);

    // scan the input tx from the fixture tree to obtain the note + witness
    let scan = transaction::scan_transactions(
        TX2_TREE,
        &[TX2_INPUT_TX.to_string()],
        &keys::decode_extended_full_viewing_key(&extfvk, TestNetwork).unwrap(),
        TestNetwork,
        vec![],
    )
    .unwrap();
    assert_eq!(scan.new_notes.len(), 1);

    let tx = transaction::create_transaction(TxOptions {
        notes: Some(scan.new_notes),
        utxos: None,
        extsk: &extsk,
        to_address: "yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D",
        change_address: TX2_CHANGE_ADDRESS,
        amount: 5 * 10e6 as u64,
        block_height: 317,
        network: TestNetwork,
        memo: "Test memo".into(),
        subtract_fee_from_amount: false,
    })
    .await
    .unwrap();

    assert_eq!(tx.nullifiers.len(), 1);
    assert_eq!(tx.nullifiers[0], TX2_EXPECTED_NULLIFIER);
    assert!(!tx.txhex.is_empty());
}

/// Fee must not be silently taken from the recipient unless opted in.
#[tokio::test]
async fn refuses_silent_fee_subtraction() {
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();
    let extsk = keys::decode_extsk(TX2_EXTSK, TestNetwork).unwrap();
    let extfvk =
        keys::encode_extended_full_viewing_key(&keys::extfvk_from_extsk(&extsk), TestNetwork);
    let scan = transaction::scan_transactions(
        TX2_TREE,
        &[TX2_INPUT_TX.to_string()],
        &keys::decode_extended_full_viewing_key(&extfvk, TestNetwork).unwrap(),
        TestNetwork,
        vec![],
    )
    .unwrap();
    let note_value = scan.new_notes[0].note.value().inner();

    // Ask for the entire note value: covers amount but not amount+fee.
    let opts = |sweep| TxOptions {
        notes: Some(scan.new_notes.clone()),
        utxos: None,
        extsk: &extsk,
        to_address: "yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D",
        change_address: TX2_CHANGE_ADDRESS,
        amount: note_value,
        block_height: 317,
        network: TestNetwork,
        memo: String::new(),
        subtract_fee_from_amount: sweep,
    };
    assert!(matches!(
        transaction::create_transaction(opts(false)).await,
        Err(WalletError::InsufficientBalance)
    ));
    // With sweep opt-in it succeeds (fee comes out of the amount).
    assert!(transaction::create_transaction(opts(true)).await.is_ok());
}

/// Zero amount and oversized memo are rejected up front.
#[tokio::test]
async fn rejects_zero_amount_and_oversized_memo() {
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();
    let extsk = keys::decode_extsk(TX2_EXTSK, TestNetwork).unwrap();
    let base = |amount, memo: String| TxOptions {
        notes: Some(vec![]),
        utxos: None,
        extsk: &extsk,
        to_address: "yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D",
        change_address: TX2_CHANGE_ADDRESS,
        amount,
        block_height: 317,
        network: TestNetwork,
        memo,
        subtract_fee_from_amount: false,
    };
    assert!(transaction::create_transaction(base(0, String::new()))
        .await
        .is_err());
    assert!(transaction::create_transaction(base(1, "x".repeat(513)))
        .await
        .is_err());
}

/// End-to-end through the wallet: scan then build a spend (MockProver).
#[tokio::test]
async fn wallet_creates_and_finalizes_spend() {
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();

    let mut wallet = ShieldWallet::from_spending_key(TX2_EXTSK, TestNetwork, BIRTH).unwrap();
    // seed the wallet's tree with the fixture tree so witnesses line up
    wallet_set_tree_for_test(&mut wallet, TX2_TREE);
    wallet
        .handle_blocks(&[WalletBlock {
            height: BIRTH + 1,
            tx_hexes: vec![TX2_INPUT_TX.to_string()],
        }])
        .unwrap();
    let balance_before = wallet.balance();
    assert!(balance_before > 0);

    let built = wallet
        .create_transaction(&SendOptions::shield(
            "yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D",
            5 * 10e6 as u64,
        ))
        .await
        .unwrap();

    // pending: the note is excluded from balance until finalize/discard
    assert_eq!(wallet.balance(), 0);
    wallet.discard_transaction(&built.txid);
    assert_eq!(wallet.balance(), balance_before);
    let built = wallet
        .create_transaction(&SendOptions::shield(
            "yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D",
            5 * 10e6 as u64,
        ))
        .await
        .unwrap();
    wallet.finalize_transaction(&built.txid);
    assert_eq!(wallet.balance(), 0);
    assert_eq!(wallet.notes().len(), 0);
}

/// Test hook: overwrite the wallet's commitment tree.
fn wallet_set_tree_for_test(wallet: &mut ShieldWallet, tree_hex: &str) {
    wallet.set_commitment_tree_for_test(tree_hex);
}
