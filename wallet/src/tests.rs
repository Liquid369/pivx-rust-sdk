//! Wallet-level tests on real fixtures (a regtest tx decrypting to a known
//! note) plus the upstream tx-builder test (MockProver under cfg(test)).

use crate::test_fixtures::*;
use crate::transaction::{self, TxOptions};
use crate::wallet::{SendOptions, ShieldWallet, WalletBlock};
use crate::{keys, WalletError};
use pivx_primitives::consensus::Network::{MainNetwork, TestNetwork};

// Above testnet sapling activation (201): the fixture blocks carry a shielded
// tx, which handle_blocks silently skips below activation (W3), so it must
// land at/above activation to be credited.
const BIRTH: i64 = 300;

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

/// W-SEED reference lock (funds-critical): the BIP39 seed of the standard test
/// mnemonic "abandon abandon … about" derives m/44'/119'/0'/0/0 to the address
/// MyPIVXWallet (MPW) / BIP39 seed-phrase wallets produce, and the shield spending
/// key from the full 64-byte seed equals the one from its first 32 bytes
/// (WASM-truncation parity).
#[test]
fn bip39_seed_reference_vector() {
    // BIP39 seed (empty passphrase) of "abandon abandon abandon abandon abandon
    // abandon abandon abandon abandon abandon abandon about".
    let seed = hex::decode(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
         9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    )
    .unwrap();
    assert_eq!(seed.len(), 64);

    // Transparent BIP32 uses the FULL 64-byte seed.
    let k = crate::transparent::derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
    assert_eq!(k.address(), "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ");

    // Shield ZIP32 uses only the first 32 bytes: 64-byte seed == its first 32.
    let sk_full = keys::encode_extsk(
        &keys::spending_key_from_seed(&seed, MainNetwork, 0).unwrap(),
        MainNetwork,
    );
    let sk_32 = keys::encode_extsk(
        &keys::spending_key_from_seed(&seed[..32], MainNetwork, 0).unwrap(),
        MainNetwork,
    );
    assert_eq!(sk_full, sk_32);
}

#[test]
fn shield_from_seed_accepts_32_or_64_rejects_others() {
    assert!(ShieldWallet::from_seed(&[0u8; 32], TestNetwork, BIRTH, 0).is_ok());
    assert!(ShieldWallet::from_seed(&[0u8; 64], TestNetwork, BIRTH, 0).is_ok());
    assert!(ShieldWallet::from_seed(&[0u8; 31], TestNetwork, BIRTH, 0).is_err());
    assert!(ShieldWallet::from_seed(&[0u8; 48], TestNetwork, BIRTH, 0).is_err());
    // A 64-byte seed and its first 32 bytes derive the same shield wallet.
    let mut s64 = [0u8; 64];
    s64[..32].copy_from_slice(&[3u8; 32]);
    let a = ShieldWallet::from_seed(&s64, TestNetwork, BIRTH, 0).unwrap();
    let b = ShieldWallet::from_seed(&[3u8; 32], TestNetwork, BIRTH, 0).unwrap();
    assert_eq!(a.save().unwrap(), b.save().unwrap());
}

/// A3 (missed deposits): a birth height outside [0, i32::MAX] must be REJECTED,
/// not clamped. Clamping a huge birth height to i32::MAX would silently start
/// scanning near the chain tip and miss every deposit below it. FAILS before
/// the fix (clamped to an Ok wallet at the tip), PASSES after (Err). Covers
/// every public constructor since all route through from_parts.
#[test]
fn constructors_reject_out_of_range_birth_height() {
    for bad in [1i64 << 40, -1, i64::MAX, i32::MAX as i64 + 1] {
        assert!(
            ShieldWallet::from_seed(&[7u8; 32], TestNetwork, bad, 0).is_err(),
            "from_seed birth_height {bad} must be rejected"
        );
        assert!(
            ShieldWallet::from_spending_key(EXTSK, TestNetwork, bad).is_err(),
            "from_spending_key birth_height {bad} must be rejected"
        );
    }
    // A valid birth height still constructs, at both ends of the range.
    assert!(ShieldWallet::from_seed(&[7u8; 32], TestNetwork, 0, 0).is_ok());
    assert!(ShieldWallet::from_spending_key(EXTSK, TestNetwork, i32::MAX as i64).is_ok());
}

#[test]
fn load_rejects_out_of_range_last_processed_block() {
    let w = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    let n = w.last_synced_block();
    let json = w.save().unwrap();
    let field = format!("\"lastProcessedBlock\":{n}");
    let huge = json.replace(&field, "\"lastProcessedBlock\":9007199254740993"); // 2^53+1
    assert_ne!(huge, json, "field must be present to tamper");
    assert!(ShieldWallet::load(&huge).is_err());
    let neg = json.replace(&field, "\"lastProcessedBlock\":-1");
    assert!(ShieldWallet::load(&neg).is_err());
    // The untampered state still loads.
    assert!(ShieldWallet::load(&json).is_ok());
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

/// A1: handle_blocks must reject a block height outside [0, 2^53-1] — the same
/// bound load() enforces — so a scan can't advance last_processed_block to a
/// value that would make the saved state unloadable. FAILS before the fix
/// (height 2^53 was scanned and persisted, then save()/load() rejected it),
/// PASSES after (rejected up front, state untouched, save round-trips).
#[test]
fn handle_blocks_rejects_out_of_range_height() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    let before = wallet.last_synced_block();
    let bad = vec![WalletBlock {
        height: 1i64 << 53,
        tx_hexes: vec![TX_HEX.to_string()],
    }];
    assert!(matches!(
        wallet.handle_blocks(&bad),
        Err(WalletError::Other(_))
    ));
    assert_eq!(wallet.notes().len(), 0, "no note credited");
    assert_eq!(wallet.last_synced_block(), before, "sync position unmoved");
    // The saved state still round-trips through load() (no unloadable height).
    assert!(ShieldWallet::load(&wallet.save().unwrap()).is_ok());
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
            // Echo the request id: the client rejects a mismatched id.
            let id = req
                .split("\r\n\r\n")
                .nth(1)
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .map(|v| v["id"].clone())
                .unwrap_or_default();
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
/// advance unverified. Scan a block above activation, where the per-batch root
/// check runs (below activation the check is skipped, so this would be a no-op).
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_rejects_missing_sapling_root() {
    use pivx_rpc::{Auth, PivxClient};
    const H: i64 = 43_200; // well above real V5_0 activation (201), so the check runs
    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{}", H + 1));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // Correct height, empty block, but no finalsaplingroot field.
    results.insert("getblock", format!("{{\"height\":{},\"tx\":[]}}", H + 1));
    let url = stub_node(results);

    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(H);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = wallet.sync(&client, 10).await.unwrap_err();
    assert!(
        matches!(&err, WalletError::Other(m) if m.contains("finalsaplingroot")),
        "got {err:?}"
    );
}

/// last_processed == tip with a MATCHING tip root: nothing new to scan and the
/// node's finalsaplingroot agrees with our tree, so the same-height reorg guard
/// is a clean no-op. Runs at a height >= 201 (testnet V5_0 activation) so the
/// stale-tip check actually compares local vs node root — below activation it
/// would skip and pass without ever comparing.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_match_is_noop() {
    use pivx_rpc::{Auth, PivxClient};
    const H: i64 = 43_200; // above testnet V5_0 activation (201), so the check runs
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(H);
    let local_root = wallet.sapling_root().unwrap();

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{H}"));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    results.insert(
        "getblock",
        format!("{{\"finalsaplingroot\":\"{local_root}\"}}"),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    wallet.sync(&client, 10).await.unwrap();
    assert_eq!(wallet.last_synced_block(), H);
}

/// last_processed == tip but the node's tip finalsaplingroot DIFFERS (a
/// same-height reorg changed the shielded set): the batch loop never runs, so
/// this tip-root check is the only thing that catches it. sync must diverge;
/// recovery via reload_from_checkpoint still works. At/above activation, where
/// the stale-tip check runs (below it the node reports a zero root our non-zero
/// empty tree can't match, so the check is skipped).
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_mismatch_diverges() {
    use pivx_rpc::{Auth, PivxClient};
    const H: i64 = 43_200; // well above real V5_0 activation (201), so the check runs
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(H);

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{H}"));
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
    wallet.reload_from_checkpoint(H).unwrap();
    assert!(wallet.last_synced_block() <= H);
}

/// An honest wallet at last_processed == tip == H BELOW real V5_0 activation
/// (testnet 201): PIVX reports finalsaplingroot = 0 (UINT256_ZERO) there while
/// our empty tree carries the non-zero sapling empty root. The stale-tip check
/// must skip below activation, so sync is a clean no-op — not a false divergence.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_below_activation_is_noop() {
    use pivx_rpc::{Auth, PivxClient};
    const H: i64 = 100; // below testnet V5_0 activation (201)
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(H); // empty tree, honest below-activation tip

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{H}"));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // Pre-activation nodes report an all-zero finalsaplingroot.
    results.insert(
        "getblock",
        format!("{{\"finalsaplingroot\":\"{}\"}}", "00".repeat(32)),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    // Must not throw: the zero root mismatches our non-zero empty-tree root, but
    // the check is skipped below activation.
    wallet.sync(&client, 10).await.unwrap();
    assert_eq!(wallet.last_synced_block(), H);
}

/// The fail-open gap the old 43_200 constant left: a testnet wallet at a height
/// in [201, 43_200) is at/above real V5_0 activation (201) but below the old
/// constant, so the stale-tip check was skipped and a divergence went uncaught.
/// With testnet activation set to its real 201 the check now runs and catches
/// it: FAILS before (10_000 < 43_200 → skipped → no divergence), PASSES after
/// (10_000 >= 201 → ScanDiverged).
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_in_activation_gap_diverges() {
    use pivx_rpc::{Auth, PivxClient};
    const H: i64 = 10_000; // in [201, 43_200): above real activation, below old constant
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.prime_for_sync_test(H);

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{H}"));
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
}

/// MAINNET regression for the corrected V5_0 activation (2_700_500, not
/// 2_700_000). A wallet resolving to the base checkpoint 2_700_000 with node tip
/// == 2_700_000 sits BELOW real activation, where PIVX reports finalsaplingroot
/// = 0. The stale-tip check must skip, so sync is a clean no-op. With the old
/// 2_700_000 constant the guard ran (2_700_000 >= 2_700_000) and false-diverged:
/// FAILS before the constant fix, PASSES after.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_below_activation_is_noop_mainnet() {
    use pivx_rpc::{Auth, PivxClient};
    const CP: i64 = 2_700_000; // base mainnet checkpoint, below real V5_0 (2_700_500)
    let mut wallet = ShieldWallet::from_seed(&[7u8; 32], MainNetwork, CP, 0).unwrap();
    wallet.prime_for_sync_test(CP); // empty tree at the base checkpoint

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{CP}"));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // Pre-activation nodes report an all-zero finalsaplingroot.
    results.insert(
        "getblock",
        format!("{{\"finalsaplingroot\":\"{}\"}}", "00".repeat(32)),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    // Must not throw: 2_700_000 < corrected activation 2_700_500, so skip.
    wallet.sync(&client, 10).await.unwrap();
    assert_eq!(wallet.last_synced_block(), CP);
}

/// last_processed == tip == an EXACT bundled-checkpoint height, node reports a
/// DIFFERENT finalsaplingroot there (same-height reorg). The old
/// closest-checkpoint gate (`last_processed > cp_height`) skipped the tip-root
/// check at exactly a checkpoint height, letting orphaned shield state survive;
/// this must diverge. FAILS before the gate removal, PASSES after.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_mismatch_at_checkpoint_diverges() {
    use pivx_rpc::{Auth, PivxClient};
    // A testnet checkpoint height well above real V5_0 activation (201), so
    // get_checkpoint(CP).0 == CP and the old `> cp_height` gate was false.
    const CP: i64 = 43200;
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.reload_from_checkpoint(CP).unwrap();
    assert_eq!(
        wallet.last_synced_block(),
        CP,
        "CP must be an exact checkpoint"
    );
    wallet.prime_for_sync_test(CP);

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{CP}"));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // A root that cannot equal the checkpoint tree's root.
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
}

/// Guard against a false positive from removing the gate: a fresh wallet sitting
/// on its bundled checkpoint (last_processed == tip == checkpointHeight) whose
/// node reports the MATCHING checkpoint root is a clean no-op, not a divergence.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_tip_root_match_at_checkpoint_is_noop() {
    use pivx_rpc::{Auth, PivxClient};
    const CP: i64 = 43200;
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.reload_from_checkpoint(CP).unwrap();
    wallet.prime_for_sync_test(CP);
    let local_root = wallet.sapling_root().unwrap();

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{CP}"));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    results.insert(
        "getblock",
        format!("{{\"finalsaplingroot\":\"{local_root}\"}}"),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    wallet.sync(&client, 10).await.unwrap();
    assert_eq!(wallet.last_synced_block(), CP);
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

/// W3 (reworks D1/#28): consensus forbids shielded DATA below V5_0 activation
/// (IsShieldedTx = sapling version AND sapling data, PIVX transaction.h), not
/// the '03' version byte itself, so a below-activation v3 tx must not brick
/// sync. handle_blocks SKIPS '03'-prefixed txs below activation: the batch
/// succeeds, nothing reaches the scanner, nothing is credited. Regression for
/// the original D1 fail-open: fabricated sapling data below activation is
/// still never credited.
#[test]
fn handle_blocks_skips_shielded_tx_below_activation() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    let relevant = wallet
        .handle_blocks(&[WalletBlock {
            height: 150, // below testnet activation (201)
            tx_hexes: vec![TX_HEX.to_string()],
        }])
        .unwrap();
    assert!(relevant.is_empty(), "skipped tx is not wallet-relevant");
    assert!(
        wallet.notes().is_empty(),
        "fabricated below-activation note never credited"
    );
    assert_eq!(wallet.balance(), 0);
    assert_eq!(
        wallet.last_synced_block(),
        150,
        "sync position advances: success, not failure"
    );
    // The same tx at/above activation still credits normally.
    wallet.handle_blocks(&fixture_block()).unwrap();
    assert_eq!(wallet.balance(), 1_000_000_000);
}

/// W3 through sync: a node serving a below-activation block that carries a
/// '03'-prefixed tx must sync CLEANLY with nothing credited (the tx is
/// filtered out before the scanner), not error out.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn sync_skips_below_activation_shielded_block() {
    use pivx_rpc::{Auth, PivxClient};
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    assert_eq!(wallet.last_synced_block(), 0); // starts on the height-0 checkpoint

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", "1".to_string());
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    results.insert(
        "getblock",
        format!(
            "{{\"height\":1,\"tx\":[{{\"hex\":\"{TX_HEX}\"}}],\"finalsaplingroot\":\"{}\"}}",
            "00".repeat(32)
        ),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    wallet.sync(&client, 10).await.unwrap();
    assert_eq!(
        wallet.last_synced_block(),
        1,
        "sync succeeded past the skipped tx"
    );
    assert!(
        wallet.notes().is_empty(),
        "fabricated below-activation note never credited"
    );
    assert_eq!(wallet.balance(), 0);
}

/// D5: a failed (insufficient) spend must not advance the diversifier index —
/// the change address is only consumed when planning succeeds.
/// FAILS before the fix (the index advanced on the error path), PASSES after.
#[tokio::test]
async fn failed_spend_leaves_diversifier_index_unchanged() {
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();
    let index = |w: &ShieldWallet| -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(&w.save().unwrap()).unwrap()["diversifierIndex"]
            .clone()
    };
    let before = index(&wallet);

    let err = wallet
        .create_transaction(&SendOptions::shield(SHIELD_ADDRESS, 2_000_000_000))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WalletError::InsufficientBalance),
        "got {err:?}"
    );
    assert_eq!(index(&wallet), before, "diversifier index rolled back");

    // The next address is therefore the same one a fresh wallet would derive.
    let mut fresh = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    assert_eq!(wallet.new_address().unwrap(), fresh.new_address().unwrap());
}

/// D6: the keyless reload_from_checkpoint recovery path REJECTS an out-of-i32-
/// range height instead of clamping it — a clamped height would silently reset
/// to a valid-but-wrong checkpoint. Mirrors the JS reloadFromCheckpoint guard
/// and the key-bearing constructors (see
/// constructors_reject_out_of_range_birth_height). Fails before the fix
/// (out-of-range clamped to an Ok reload), passes after (Err).
#[test]
fn reload_from_checkpoint_rejects_out_of_range_height() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    assert!(wallet.reload_from_checkpoint(1i64 << 40).is_err());
    assert!(wallet.reload_from_checkpoint(-1).is_err());
    // A valid in-range height still succeeds and resets the scan position.
    assert!(wallet.reload_from_checkpoint(BIRTH).is_ok());
    assert!(wallet.last_synced_block() <= BIRTH);
}

/// T7: decrypt-time notes are, and stay, Rseed::BeforeZip212 through
/// save/load. Both SDKs persist the note's rcm as a BeforeZip212 scalar; an
/// upstream switch to ZIP212 rseeds must surface as this test failing, not
/// as silent cross-SDK state corruption.
#[test]
fn notes_round_trip_as_before_zip212() {
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();
    let note = wallet.notes()[0].note.clone();
    assert!(
        matches!(note.rseed(), sapling::Rseed::BeforeZip212(_)),
        "decryption produced a non-BeforeZip212 note"
    );

    let json = wallet.save().unwrap();
    let state: serde_json::Value = serde_json::from_str(&json).unwrap();
    let rseed = &state["notes"][0]["note"]["rseed"];
    assert_eq!(
        rseed.as_array().map(Vec::len),
        Some(32),
        "rseed persists as the 32 BeforeZip212 scalar bytes, got {rseed}"
    );

    let restored = ShieldWallet::load(&json).unwrap();
    let rnote = &restored.notes()[0].note;
    assert!(matches!(rnote.rseed(), sapling::Rseed::BeforeZip212(_)));
    assert_eq!(
        rnote.cmu(),
        note.cmu(),
        "note commitment survives the round-trip"
    );
    assert_eq!(restored.notes()[0].nullifier, wallet.notes()[0].nullifier);
}

/// T6: a ≤512-byte memo lands in the built transaction — proved by
/// decrypting the built tx with the wallet's own viewing key.
#[tokio::test]
async fn memo_round_trips_through_built_transaction() {
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();
    let mut wallet = ShieldWallet::from_spending_key(TX2_EXTSK, TestNetwork, BIRTH).unwrap();
    wallet_set_tree_for_test(&mut wallet, TX2_TREE);
    wallet
        .handle_blocks(&[WalletBlock {
            height: BIRTH + 1,
            tx_hexes: vec![TX2_INPUT_TX.to_string()],
        }])
        .unwrap();

    let to = wallet.new_address().unwrap(); // one of our own diversified addresses
    let memo = "T6 memo round-trip \u{2713}".to_string();
    let amount = 5 * 10e6 as u64;
    let mut opts = SendOptions::shield(&to, amount);
    opts.memo = Some(memo.clone());
    let built = wallet.create_transaction(&opts).await.unwrap();

    let extfvk = keys::extfvk_from_extsk(&keys::decode_extsk(TX2_EXTSK, TestNetwork).unwrap());
    let scan = transaction::scan_transactions(
        TX2_TREE,
        std::slice::from_ref(&built.txhex),
        &extfvk,
        TestNetwork,
        vec![],
    )
    .unwrap();
    let recipient_note = scan
        .new_notes
        .iter()
        .find(|n| n.note.value().inner() == amount)
        .expect("recipient note decrypts from the built tx");
    assert_eq!(recipient_note.memo.as_deref(), Some(memo.as_str()));
}

/// Loopback JSON-RPC stub with real dispatch: the handler receives
/// (method, params) and returns the full JSON-RPC response body, so tests
/// can vary responses per height and return error bodies.
#[cfg(feature = "rpc")]
fn stub_node_fn(handler: impl Fn(&str, &serde_json::Value) -> String + Send + 'static) -> String {
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
            let mut buf = [0u8; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                continue;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let method = parsed["method"].as_str().unwrap_or("").to_string();
            // Echo the request id: the client rejects a mismatched id.
            let mut resp: serde_json::Value =
                serde_json::from_str(&handler(&method, &parsed["params"])).unwrap_or_default();
            resp["id"] = parsed["id"].clone();
            let body = resp.to_string();
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

/// T1: a note-bearing batch that fails the root check must roll back
/// completely — notes, nullifier-map inserts, AND pending-spend
/// reconciliation (a pending entry the batch dropped must come back).
#[cfg(feature = "rpc")]
#[tokio::test]
async fn failed_batch_restores_notes_nullifiers_and_pending_spends() {
    use pivx_rpc::{Auth, PivxClient};
    const H: i64 = 43_200;
    // Pre-seed a pending spend whose nullifiers are untracked: the batch's
    // reconciliation deletes it, so only a full rollback restores it.
    let base = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    let mut state: serde_json::Value = serde_json::from_str(&base.save().unwrap()).unwrap();
    state["pendingSpends"] = serde_json::json!({ "inflight": ["aa00"] });
    let mut wallet = ShieldWallet::load(&state.to_string()).unwrap();
    wallet.prime_for_sync_test(H);
    let before: serde_json::Value = serde_json::from_str(&wallet.save().unwrap()).unwrap();

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{}", H + 1));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    // The batch credits the fixture note, then fails the root check.
    results.insert(
        "getblock",
        format!(
            "{{\"height\":{},\"tx\":[{{\"hex\":\"{TX_HEX}\"}}],\"finalsaplingroot\":\"{}\"}}",
            H + 1,
            "ff".repeat(32)
        ),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    let err = wallet.sync(&client, 10).await.unwrap_err();
    assert!(
        matches!(err, WalletError::ScanDiverged { .. }),
        "got {err:?}"
    );

    let after: serde_json::Value = serde_json::from_str(&wallet.save().unwrap()).unwrap();
    assert_eq!(before, after, "state fully restored after the failed batch");
    assert!(wallet.notes().is_empty());
    assert_eq!(wallet.balance(), 0);
    assert!(
        wallet.pending_transactions().contains_key("inflight"),
        "reconciled-away pending entry restored"
    );
}

/// T2: a fresh wallet on a stale near-tip checkpoint walks back to an older
/// checkpoint the node confirms, and adopts it.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn checkpoint_walk_back_adopts_older_confirmed_checkpoint() {
    use pivx_rpc::{Auth, PivxClient};
    // Fresh wallet on the 86_400 checkpoint; the node only confirms 43_200.
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, 100_000).unwrap();
    assert_eq!(wallet.last_synced_block(), 86_400);
    let older = ShieldWallet::from_spending_key(EXTSK, TestNetwork, 50_000).unwrap();
    assert_eq!(older.last_synced_block(), 43_200);
    let older_root = older.sapling_root().unwrap();

    let url = stub_node_fn(move |method, params| {
        let result = match method {
            "getblockcount" => "43200".into(),
            "getblockhash" => format!("\"hash{}\"", params[0].as_i64().unwrap_or(-1)),
            "getblock" => {
                // Only the 43_200 checkpoint matches; everything else is stale.
                let root = if params[0].as_str() == Some("hash43200") {
                    older_root.clone()
                } else {
                    "00".repeat(32)
                };
                format!("{{\"finalsaplingroot\":\"{root}\"}}")
            }
            _ => "null".into(),
        };
        format!("{{\"result\":{result},\"error\":null,\"id\":0}}")
    });
    let client = PivxClient::new(url, Auth::None).unwrap();
    wallet.sync(&client, 10).await.unwrap();
    assert_eq!(
        wallet.last_synced_block(),
        43_200,
        "older node-confirmed checkpoint adopted"
    );
    assert!(wallet.notes().is_empty());
}

/// T3: crash-recovery reconciliation. A spend was broadcast-accepted but the
/// process died before finalize; the persisted pending entry survives the
/// restart, and syncing the confirming block scans the note out and
/// auto-drops the pending entry.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn crash_recovery_reconciles_confirmed_pending_spend() {
    use pivx_rpc::{Auth, PivxClient};
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();

    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();

    // Full-balance sweep to a transparent address: no change note comes back.
    let mut opts = SendOptions::shield("yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D", wallet.balance());
    opts.subtract_fee_from_amount = true;
    let built = wallet.create_transaction(&opts).await.unwrap();
    assert_eq!(wallet.pending_transactions().len(), 1);

    // Crash: persist mid-flight (pending included), restore.
    let saved = wallet.save().unwrap();
    let mut restored = ShieldWallet::load(&saved).unwrap();
    assert_eq!(restored.balance(), 0, "pending spend survives the restart");
    restored.prime_for_sync_test(BIRTH + 1);

    // Learn the post-spend root from a reference scan of the same state.
    let mut reference = ShieldWallet::load(&saved).unwrap();
    reference
        .handle_blocks(&[WalletBlock {
            height: BIRTH + 2,
            tx_hexes: vec![built.txhex.clone()],
        }])
        .unwrap();
    let root = reference.sapling_root().unwrap();

    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{}", BIRTH + 2));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    results.insert(
        "getblock",
        format!(
            "{{\"height\":{},\"tx\":[{{\"hex\":\"{}\"}}],\"finalsaplingroot\":\"{root}\"}}",
            BIRTH + 2,
            built.txhex
        ),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    restored.sync(&client, 10).await.unwrap();

    assert!(restored.notes().is_empty(), "spent note scanned out");
    assert!(
        restored.pending_transactions().is_empty(),
        "pending entry auto-dropped once the spend confirmed"
    );
    assert_eq!(restored.balance(), 0);
}

/// T4: reorg re-credit. A credited note, a tip-root divergence, recovery via
/// reload_from_checkpoint, and a rescan must credit the note exactly once.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn reorg_recovery_recredits_note_exactly_once() {
    use pivx_rpc::{Auth, PivxClient};
    let mut wallet = ShieldWallet::from_spending_key(EXTSK, TestNetwork, BIRTH).unwrap();
    let empty_root = wallet.sapling_root().unwrap();
    wallet.handle_blocks(&fixture_block()).unwrap();
    wallet.prime_for_sync_test(BIRTH + 1);
    let fixture_root = wallet.sapling_root().unwrap();

    // Same-height reorg: the node's tip root differs from ours → diverge.
    let mut results = std::collections::HashMap::new();
    results.insert("getblockcount", format!("{}", BIRTH + 1));
    results.insert("getblockhash", "\"deadbeef\"".to_string());
    results.insert(
        "getblock",
        format!("{{\"finalsaplingroot\":\"{}\"}}", "ff".repeat(32)),
    );
    let client = PivxClient::new(stub_node(results), Auth::None).unwrap();
    let err = wallet.sync(&client, 100).await.unwrap_err();
    assert!(
        matches!(err, WalletError::ScanDiverged { .. }),
        "got {err:?}"
    );

    // Recover: back to the checkpoint (height 0), then rescan a healthy chain.
    wallet.reload_from_checkpoint(BIRTH + 1).unwrap();
    assert_eq!(wallet.last_synced_block(), 0);
    assert!(wallet.notes().is_empty());

    let tip = BIRTH + 1;
    let url = stub_node_fn(move |method, params| {
        let result = match method {
            "getblockcount" => format!("{tip}"),
            "getblockhash" => format!("\"hash{}\"", params[0].as_i64().unwrap_or(-1)),
            "getblock" => {
                let h: i64 = params[0]
                    .as_str()
                    .and_then(|s| s.strip_prefix("hash"))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(-1);
                if h == tip {
                    format!(
                        "{{\"height\":{h},\"tx\":[{{\"hex\":\"{TX_HEX}\"}}],\"finalsaplingroot\":\"{fixture_root}\"}}"
                    )
                } else {
                    format!("{{\"height\":{h},\"tx\":[],\"finalsaplingroot\":\"{empty_root}\"}}")
                }
            }
            _ => "null".into(),
        };
        format!("{{\"result\":{result},\"error\":null,\"id\":0}}")
    });
    let client = PivxClient::new(url, Auth::None).unwrap();
    wallet.sync(&client, 100).await.unwrap();
    assert_eq!(wallet.notes().len(), 1, "note credited exactly once");
    assert_eq!(wallet.balance(), 1_000_000_000);
    assert_eq!(wallet.last_synced_block(), tip);
}

/// T5/D4: send() error branches. A transport error keeps the spend pending;
/// an "accepted-tx" RpcError (already-in-mempool/-chain) keeps it pending
/// (FAILS before the D4 fix, which discarded on every RpcError); a genuine
/// validation RpcError frees the notes.
#[cfg(feature = "rpc")]
#[tokio::test]
async fn send_error_branches_gate_pending_release() {
    use pivx_rpc::{Auth, PivxClient};
    crate::prover::load_prover_from_bytes(&[], &[])
        .await
        .unwrap();
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
    let opts = || SendOptions::shield("yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D", 5 * 10e6 as u64);
    let error_node = |code: i64, message: &str| {
        let body = format!(
            "{{\"result\":null,\"error\":{{\"code\":{code},\"message\":\"{message}\"}},\"id\":0}}"
        );
        stub_node_fn(move |_, _| body.clone())
    };

    // Accepted-tx RpcError: the node already has the tx → spend stays pending.
    let mut w = make_wallet();
    let balance = w.balance();
    let client = PivxClient::new(error_node(-26, "txn-already-in-mempool: "), Auth::None).unwrap();
    assert!(w.send(&client, &opts()).await.is_err());
    assert_eq!(
        w.pending_transactions().len(),
        1,
        "kept on already-in-mempool"
    );
    assert_eq!(w.balance(), 0);

    // -27 already-in-chain: same.
    let mut w = make_wallet();
    let client = PivxClient::new(
        error_node(-27, "transaction already in block chain"),
        Auth::None,
    )
    .unwrap();
    assert!(w.send(&client, &opts()).await.is_err());
    assert_eq!(
        w.pending_transactions().len(),
        1,
        "kept on already-in-chain"
    );

    // W4: shield-specific reject reasons meaning the network already has a
    // transaction spending these nullifiers — possibly OURS, rebroadcast or
    // raced (PIVX validation.cpp: bad-txns-nullifier-double-spent from the
    // mempool nullifier check, bad-txns-shielded-requirements-not-met from
    // HaveShieldedRequirements; -27 cannot fire for z→z, its already-in-chain
    // probe scans vout only). Keep pending. FAIL before the W4 fix (both
    // discarded), PASS after.
    for reason in [
        "bad-txns-nullifier-double-spent",
        "bad-txns-shielded-requirements-not-met",
    ] {
        let mut w = make_wallet();
        let client = PivxClient::new(error_node(-26, reason), Auth::None).unwrap();
        assert!(w.send(&client, &opts()).await.is_err());
        assert_eq!(w.pending_transactions().len(), 1, "kept on {reason}");
        assert_eq!(w.balance(), 0);
    }

    // Genuine validation rejection: notes freed.
    let mut w = make_wallet();
    let client = PivxClient::new(error_node(-26, "bad-txns-inputs-duplicate"), Auth::None).unwrap();
    assert!(w.send(&client, &opts()).await.is_err());
    assert!(
        w.pending_transactions().is_empty(),
        "validation reject frees the notes"
    );
    assert_eq!(w.balance(), balance);

    // Transport error: ambiguous → pending kept.
    let mut w = make_wallet();
    let client = PivxClient::new("http://127.0.0.1:1".to_string(), Auth::None).unwrap();
    assert!(w.send(&client, &opts()).await.is_err());
    assert_eq!(w.pending_transactions().len(), 1, "kept on transport error");
}
