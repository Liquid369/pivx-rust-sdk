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
fn load_verified_rejects_swapped_viewing_key() {
    let wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    let json = wallet.save().unwrap();
    let extfvk = keys::encode_extended_full_viewing_key(
        &keys::extfvk_from_extsk(&keys::decode_extsk(EXTSK, TestNetwork).unwrap()),
        TestNetwork,
    );
    // Correct expected key loads.
    assert!(ShieldWallet::load_verified(&json, &extfvk).is_ok());
    // A different key is rejected.
    let other = keys::encode_extended_full_viewing_key(
        &keys::extfvk_from_extsk(&keys::decode_extsk(TX2_EXTSK, TestNetwork).unwrap()),
        TestNetwork,
    );
    assert!(ShieldWallet::load_verified(&json, &other).is_err());
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

/// Sub-dust notes are purged from tracked state on every scan pass (dust-flood
/// defense; JS SDK parity), even when they arrived via load() of an older save.
#[test]
fn scan_purges_dust_notes_from_tracked_state() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();

    // Shrink the tracked note to exactly the dust threshold via the persisted
    // state, as an old save carrying a sub-dust note would.
    let mut state: serde_json::Value = serde_json::from_str(&wallet.save().unwrap()).unwrap();
    state["notes"][0]["note"]["value"] = 384_000.into();
    let mut wallet = ShieldWallet::load(&state.to_string()).unwrap();
    assert_eq!(wallet.balance(), 384_000, "dust note loads");

    // Any scan pass purges it, even one with no wallet-relevant transactions.
    wallet
        .handle_blocks(&[WalletBlock {
            height: BIRTH + 2,
            tx_hexes: vec![],
        }])
        .unwrap();
    assert_eq!(wallet.notes().len(), 0, "dust purged on scan");
    assert_eq!(wallet.balance(), 0);
}

/// prune_nullifiers drops exactly the entries referenced by neither a tracked
/// unspent note nor a pending spend.
#[test]
fn prunes_only_unreferenced_nullifiers() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();
    let nullifier = wallet.notes()[0].nullifier.clone();

    // Entry backed by a tracked note: kept.
    assert_eq!(wallet.prune_nullifiers(), 0);
    assert!(wallet.note_from_nullifier(&nullifier).is_some());

    // Craft a state where the note is gone but its spend is still pending,
    // plus a stale entry referenced by nothing.
    let mut state: serde_json::Value = serde_json::from_str(&wallet.save().unwrap()).unwrap();
    state["notes"] = serde_json::json!([]);
    state["pendingSpends"] = serde_json::json!({ "sometxid": [nullifier] });
    state["nullifierMap"]["00ff"] = serde_json::json!({ "recipient": "x", "value": 1 });
    let mut wallet = ShieldWallet::load(&state.to_string()).unwrap();

    assert_eq!(wallet.prune_nullifiers(), 1, "only the stale entry goes");
    assert!(wallet.note_from_nullifier("00ff").is_none());
    assert!(
        wallet.note_from_nullifier(&nullifier).is_some(),
        "pending-spend attribution survives"
    );
    assert_eq!(wallet.prune_nullifiers(), 0, "idempotent");
}

/// Minimal loopback JSON-RPC stub: dispatches by method name, one canned
/// result per method, serving requests until the client stops.
#[cfg(feature = "rpc")]
fn stub_node(results: std::collections::HashMap<&'static str, String>) -> String {
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
            let method = results
                .keys()
                .find(|m| req.contains(&format!("\"method\":\"{m}\"")))
                .copied()
                .unwrap_or("");
            let result = results
                .get(method)
                .cloned()
                .unwrap_or_else(|| "null".into());
            let body = format!("{{\"result\":{result},\"error\":null,\"id\":0}}");
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

/// A lying node that echoes the wrong block height must be rejected before the
/// wallet advances past real deposits.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_rejects_wrong_block_height() {
    use pivx_rpc::{Auth, PivxClient};
    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{}", BIRTH + 1));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // Requested height BIRTH+1, but the block claims a far-off height.
    results.insert(
        "getblock",
        "{\"height\":999999,\"tx\":[],\"finalsaplingroot\":\"00\"}".to_string(),
    );
    let url = stub_node(results);

    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(BIRTH);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = wallet.sync(&client, 10).await.unwrap_err();
    assert!(
        matches!(&err, WalletError::Other(m) if m.contains("block height")),
        "got {err:?}"
    );
}

/// A node that omits finalsaplingroot past activation must not let the wallet
/// advance unverified.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_rejects_missing_sapling_root() {
    use pivx_rpc::{Auth, PivxClient};
    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{}", BIRTH + 1));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // Correct height, empty block, but no finalsaplingroot field.
    results.insert(
        "getblock",
        format!("{{\"height\":{},\"tx\":[]}}", BIRTH + 1),
    );
    let url = stub_node(results);

    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(BIRTH);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = wallet.sync(&client, 10).await.unwrap_err();
    assert!(
        matches!(&err, WalletError::Other(m) if m.contains("finalsaplingroot")),
        "got {err:?}"
    );
}

/// last_processed == tip with a MATCHING tip root: nothing new to scan and the
/// node's finalsaplingroot agrees with our tree, so the same-height reorg
/// guard is a clean no-op.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_match_is_noop() {
    use pivx_rpc::{Auth, PivxClient};
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(BIRTH);
    let local_root = wallet.sapling_root().unwrap();

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{BIRTH}"));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    results.insert(
        "getblock",
        format!("{{\"finalsaplingroot\":\"{local_root}\"}}"),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    wallet.sync(&client, 10).await.unwrap();
    assert_eq!(wallet.last_synced_block(), BIRTH);
}

/// last_processed == tip but the node's tip finalsaplingroot DIFFERS (a
/// same-height reorg changed the shielded set): the batch loop never runs, so
/// this tip-root check is the only thing that catches it. sync must diverge;
/// recovery via reload_from_checkpoint still works.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_mismatch_diverges() {
    use pivx_rpc::{Auth, PivxClient};
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(BIRTH);

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{BIRTH}"));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // A root that cannot equal the wallet's local tree root.
    results.insert(
        "getblock",
        format!("{{\"finalsaplingroot\":\"{}\"}}", "ff".repeat(32)),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    let err = wallet.sync(&client, 10).await.unwrap_err();
    assert!(
        matches!(err, WalletError::ScanDiverged { .. }),
        "got {err:?}"
    );
    // Recovery path still works.
    wallet.reload_from_checkpoint(BIRTH);
    assert!(wallet.last_synced_block() <= BIRTH);
}

/// send() must prove on the blocking pool, not the async runtime. On a
/// single-threaded runtime a 10ms ticker task runs concurrently with send();
/// if the 300ms (mock-delayed) proof ran inline on the worker thread the
/// ticker could not advance. Control: the sync-proving create_transaction on
/// the same runtime does block, so the ticker stands still.
#[cfg(feature = "rpc")]
#[tokio::test(flavor = "current_thread")]
async fn send_proves_off_the_async_runtime() {
    use pivx_rpc::{Auth, PivxClient};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();
    crate::prover::set_mock_prove_delay_ms(300);

    let make_wallet = || {
        let mut w = ShieldWallet::from_spending_key(TX2_EXTSK, TestNetwork, BIRTH).unwrap();
        wallet_set_tree_for_test(&mut w, TX2_TREE);
        w.handle_blocks(&[WalletBlock {
            height: BIRTH + 1,
            tx_hexes: vec![TX2_INPUT_TX.to_string()],
        }])
        .unwrap();
        w
    };
    let send_opts = || SendOptions::shield("yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D", 5 * 10e6 as u64);

    let counter = Arc::new(AtomicU64::new(0));
    let ticker = {
        let counter = counter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                counter.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // Positive: the worker thread stays live while send() proves.
    let mut results = std::collections::HashMap::new();
    results.insert("sendrawtransaction", "\"aa11\"".to_string());
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    let mut wallet = make_wallet();
    let before = counter.load(Ordering::Relaxed);
    wallet.send(&client, &send_opts()).await.unwrap();
    let ticks = counter.load(Ordering::Relaxed) - before;
    assert!(
        ticks >= 10,
        "runtime was blocked during send: {ticks} ticks over a 300ms prove"
    );

    // Control: inline proving blocks the only worker thread, so the ticker
    // cannot advance during create_transaction.
    let mut wallet = make_wallet();
    let before = counter.load(Ordering::Relaxed);
    wallet.create_transaction(&send_opts()).await.unwrap();
    let ticks = counter.load(Ordering::Relaxed) - before;
    assert!(
        ticks < 5,
        "create_transaction unexpectedly yielded during proving: {ticks} ticks"
    );

    ticker.abort();
    crate::prover::set_mock_prove_delay_ms(0);
}
