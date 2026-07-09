use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use pivx_rpc::{Auth, Error, PivxClient, ShieldTxValue, ShieldWatcher, WatchOptions};

// PivxClient must stay Send + Sync (shared across tasks); the cookie-refresh
// interior mutability must not regress this.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PivxClient>();
};

/// Sequential HTTP stub: serves one canned raw response per accepted
/// connection, returns the captured requests. No mock-server dependency.
fn stub_node(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap();
            requests.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            stream.write_all(response.as_bytes()).unwrap();
        }
        requests
    });
    (url, handle)
}

fn http(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn temp_cookie(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pivx-rpc-{name}-{}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

#[tokio::test]
async fn parses_shield_notes_and_sends_auth() {
    // Real field names as emitted by pivxd's listshieldunspent.
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":[{"txid":"ab12","outindex":1,"confirmations":12,"spendable":false,
            "address":"ps1watchaddr","amount":4.20000000,"memo":"48690000",
            "change":false,"nullifier":"ff00"}],"error":null,"id":0}"#,
    )]);

    let client = PivxClient::new(
        url,
        Auth::UserPass {
            user: "u".into(),
            pass: "p".into(),
        },
    )
    .unwrap();
    let notes = client
        .list_shield_unspent(1, 9_999_999, true, None)
        .await
        .unwrap();

    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].txid, "ab12");
    assert_eq!(notes[0].amount, 4.2);
    assert_eq!(notes[0].change, Some(false));

    let request = handle.join().unwrap().remove(0);
    // Basic dTpw = base64("u:p"); trailing null (addresses=None) trimmed.
    assert!(
        request.contains("Basic dTpw"),
        "missing auth header: {request}"
    );
    assert!(
        request.contains(r#""params":[1,9999999,true]"#),
        "bad params: {request}"
    );
    assert!(request.contains(r#""method":"listshieldunspent""#));
}

#[tokio::test]
async fn node_error_surfaces_with_code() {
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":null,"error":{"code":-13,"message":"Please enter the wallet passphrase"},"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = client.get_shield_balance("*", 1, false).await.unwrap_err();
    match err {
        Error::Rpc {
            code,
            message,
            method,
        } => {
            assert_eq!(code, -13);
            assert!(message.contains("passphrase"));
            assert_eq!(method, "getshieldbalance");
        }
        other => panic!("expected Rpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn http_500_with_rpc_body_is_rpc_error() {
    // pivxd (src/httprpc.cpp JSONErrorReply) sends RPC errors as HTTP 500
    // with a JSON-RPC error body: the code must survive.
    let (url, _handle) = stub_node(vec![http(
        "500 Internal Server Error",
        r#"{"result":null,"error":{"code":-32603,"message":"boom"},"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = client.get_block_count().await.unwrap_err();
    match err {
        Error::Rpc { code, .. } => assert_eq!(code, -32603),
        other => panic!("expected Rpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn non_json_http_error_includes_status() {
    let (url, _handle) = stub_node(vec![http("503 Service Unavailable", "overloaded")]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = client.get_block_count().await.unwrap_err();
    match err {
        Error::Http { status, method } => {
            assert_eq!(status, 503);
            assert_eq!(method, "getblockcount");
        }
        other => panic!("expected Http error, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_credentials_yield_auth_error() {
    // pivxd replies 401 with an empty body on bad credentials.
    let (url, _handle) = stub_node(vec![http("401 Unauthorized", "")]);
    let client = PivxClient::new(
        url,
        Auth::UserPass {
            user: "u".into(),
            pass: "wrong".into(),
        },
    )
    .unwrap();
    let err = client.get_block_count().await.unwrap_err();
    match err {
        Error::Auth { status } => assert_eq!(status, 401),
        other => panic!("expected Auth error, got {other:?}"),
    }
}

#[tokio::test]
async fn cookie_rotation_refreshes_and_retries_once() {
    let (url, handle) = stub_node(vec![
        http("401 Unauthorized", ""),
        http("200 OK", r#"{"result":42,"error":null,"id":0}"#),
    ]);
    let path = temp_cookie("rotate", "u:old");
    let client = PivxClient::new(url, Auth::CookieFile(path.clone())).unwrap();

    // Simulate a pivxd restart: cookie rotated on disk after construction.
    std::fs::write(&path, "u:new").unwrap();
    assert_eq!(client.get_block_count().await.unwrap(), 42);
    std::fs::remove_file(&path).ok();

    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 2);
    // base64("u:old") / base64("u:new")
    assert!(
        requests[0].contains("Basic dTpvbGQ="),
        "first request should use stale creds: {}",
        requests[0]
    );
    assert!(
        requests[1].contains("Basic dTpuZXc="),
        "retry should use fresh creds: {}",
        requests[1]
    );
}

#[tokio::test]
async fn unchanged_cookie_yields_auth_error_without_retry() {
    let (url, handle) = stub_node(vec![http("401 Unauthorized", "")]);
    let path = temp_cookie("stale", "u:same");
    let client = PivxClient::new(url, Auth::CookieFile(path.clone())).unwrap();

    let err = client.get_block_count().await.unwrap_err();
    std::fs::remove_file(&path).ok();
    match err {
        Error::Auth { status } => assert_eq!(status, 401),
        other => panic!("expected Auth error, got {other:?}"),
    }
    assert_eq!(handle.join().unwrap().len(), 1);
}

#[test]
fn oversized_cookie_file_is_rejected() {
    let path = temp_cookie("huge", &format!("u:{}", "x".repeat(5000)));
    let err = PivxClient::new(
        "http://127.0.0.1:1".to_string(),
        Auth::CookieFile(path.clone()),
    );
    std::fs::remove_file(&path).ok();
    assert!(matches!(err, Err(Error::InvalidCookie(_))));
}

#[tokio::test]
async fn oversized_response_is_capped_via_content_length() {
    let big = format!(r#"{{"result":"{}","error":null,"id":0}}"#, "x".repeat(2048));
    let (url, _handle) = stub_node(vec![http("200 OK", &big)]);
    let client = PivxClient::new(url, Auth::None)
        .unwrap()
        .with_max_response_size(1024);
    let err = client.get_best_block_hash().await.unwrap_err();
    match err {
        Error::ResponseTooLarge { limit, method } => {
            assert_eq!(limit, 1024);
            assert_eq!(method, "getbestblockhash");
        }
        other => panic!("expected ResponseTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_response_is_capped_while_streaming() {
    // No content-length header: the cap must trip in the chunk loop.
    let big = format!(r#"{{"result":"{}","error":null,"id":0}}"#, "x".repeat(2048));
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{big}"
    );
    let (url, _handle) = stub_node(vec![response]);
    let client = PivxClient::new(url, Auth::None)
        .unwrap()
        .with_max_response_size(1024);
    let err = client.get_best_block_hash().await.unwrap_err();
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: 1024, .. }),
        "expected ResponseTooLarge, got {err:?}"
    );
}

// ── Typed return shapes ──────────────────────────────────────────────────

#[tokio::test]
async fn parses_block_header() {
    // previousblockhash present, nextblockhash absent (Option → None).
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"hash":"0abc","confirmations":10,"height":100,"version":8,
            "merkleroot":"mr","time":1600000000,"mediantime":1599999000,"nonce":42,
            "bits":"1d00ffff","difficulty":1.5,"chainwork":"00ff","acc_checkpoint":"aa",
            "shield_pool_value":{"chainValue":12.5,"valueDelta":0.5},
            "previousblockhash":"prev","chainlock":true},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let h = client.get_block_header("0abc").await.unwrap();
    assert_eq!(h.height, 100);
    assert_eq!(h.bits, "1d00ffff");
    assert_eq!(h.shield_pool_value.chain_value, 12.5);
    assert_eq!(h.previousblockhash.as_deref(), Some("prev"));
    assert_eq!(h.nextblockhash, None);
    assert!(h.chainlock);
}

#[tokio::test]
async fn get_tx_out_object_then_null() {
    // First call → object (reqSigs + addresses present); second → null → None.
    let (url, _handle) = stub_node(vec![
        http(
            "200 OK",
            r#"{"result":{"bestblock":"bb","confirmations":3,"value":1.23,
                "scriptPubKey":{"asm":"OP_DUP","hex":"76a9","reqSigs":1,
                    "type":"pubkeyhash","addresses":["D123"]},
                "coinbase":false},"error":null,"id":0}"#,
        ),
        http("200 OK", r#"{"result":null,"error":null,"id":1}"#),
    ]);
    let client = PivxClient::new(url, Auth::None).unwrap();

    let out = client.get_tx_out("t", 0, None).await.unwrap().unwrap();
    assert_eq!(out.value, 1.23);
    assert_eq!(out.script_pub_key.req_sigs, Some(1));
    assert_eq!(
        out.script_pub_key.addresses.as_deref(),
        Some(&["D123".to_string()][..])
    );
    assert!(!out.coinbase);

    let spent = client.get_tx_out("t", 1, None).await.unwrap();
    assert!(spent.is_none());
}

#[tokio::test]
async fn parses_decoded_transaction_verbose() {
    // chainlock present (Option Some); blockhash + vout reqSigs absent (None).
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"txid":"t1","version":1,"type":0,"size":200,"locktime":0,
            "vin":[{"txid":"p1","vout":0,"scriptSig":{"asm":"a","hex":"b"},
                "sequence":4294967295}],
            "vout":[{"value":9.99,"n":0,
                "scriptPubKey":{"asm":"OP","hex":"76","type":"pubkeyhash"}}],
            "hex":"deadbeef","chainlock":false},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let tx = client
        .get_raw_transaction_verbose("t1", None)
        .await
        .unwrap();
    assert_eq!(tx.txid, "t1");
    assert_eq!(tx.tx_type, 0);
    assert_eq!(tx.vin[0].txid.as_deref(), Some("p1"));
    assert!(tx.vin[0].script_sig.is_some());
    assert_eq!(tx.vout[0].value, 9.99);
    assert_eq!(tx.vout[0].script_pub_key.req_sigs, None);
    assert_eq!(tx.chainlock, Some(false));
    assert_eq!(tx.blockhash, None);
}

#[tokio::test]
async fn validate_address_valid_then_invalid() {
    let (url, _handle) = stub_node(vec![
        http(
            "200 OK",
            r#"{"result":{"isvalid":true,"address":"D123","scriptPubKey":"76a9",
                "ismine":true,"isstaking":false,"iswatchonly":false,"isscript":false},
                "error":null,"id":0}"#,
        ),
        http(
            "200 OK",
            r#"{"result":{"isvalid":false},"error":null,"id":1}"#,
        ),
    ]);
    let client = PivxClient::new(url, Auth::None).unwrap();

    let v = client.validate_address("D123").await.unwrap();
    assert!(v.isvalid);
    assert_eq!(v.address.as_deref(), Some("D123"));
    assert_eq!(v.ismine, Some(true));

    let bad = client.validate_address("nope").await.unwrap();
    assert!(!bad.isvalid);
    assert_eq!(bad.address, None);
}

#[tokio::test]
async fn parses_list_transactions_long_form() {
    // involvesWatchonly absent (None); fee present; unmodeled `to` mapValue key
    // flows into `extra`.
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":[{"category":"send","amount":-1.5,"vout":0,"fee":-0.0001,
            "confirmations":5,"txid":"tx1","time":1600000000,"timereceived":1600000001,
            "blockhash":"bh","blockindex":2,"blocktime":1600000002,"to":"memo",
            "walletconflicts":[]}],"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    // The all-default call must send the node's concrete defaults, NOT nulls,
    // which the node's unguarded getters would reject.
    let txs = client
        .list_transactions(None, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].category, "send");
    assert_eq!(txs[0].involves_watchonly, None);
    assert_eq!(txs[0].fee, Some(-0.0001));
    assert_eq!(
        txs[0].extra.get("to").and_then(|v| v.as_str()),
        Some("memo")
    );

    let request = handle.join().unwrap().remove(0);
    assert!(
        request.contains(r#""params":["*",10,0,false,true,true]"#),
        "list_transactions default must send concrete defaults: {request}"
    );
}

#[tokio::test]
async fn parses_list_since_block() {
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"transactions":[{"category":"receive","amount":2.0,"vout":1,
            "confirmations":1,"txid":"tx2","time":1,"timereceived":2,
            "blockhash":"b","blockindex":0,"blocktime":3,"walletconflicts":[]}],
            "lastblock":"lb"},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    // No blockhash → the node rejects a null params[0], so we must send NO
    // params (lists all wallet txs).
    let r = client.list_since_block(None, None, None).await.unwrap();
    assert_eq!(r.lastblock, "lb");
    assert_eq!(r.transactions.len(), 1);
    assert_eq!(r.transactions[0].category, "receive");
    assert_eq!(r.transactions[0].fee, None);

    let request = handle.join().unwrap().remove(0);
    assert!(
        request.contains(r#""params":[]"#),
        "list_since_block(None) must send no params: {request}"
    );
}

#[tokio::test]
async fn send_many_wire_params_use_defaults_not_null() {
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":"txid123","error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let mut amounts = HashMap::new();
    amounts.insert("Daddr".to_string(), 1.0);
    // min_conf None + a later Some(subtract): min_conf must become 1, not null.
    let subtract = vec!["Daddr".to_string()];
    let txid = client
        .send_many(&amounts, None, None, Some(true), Some(&subtract))
        .await
        .unwrap();
    assert_eq!(txid, "txid123");
    let request = handle.join().unwrap().remove(0);
    // dummy "", amounts, minconf 1 (not null), comment null (node-tolerated),
    // include_delegated true, subtract array.
    assert!(
        request.contains(r#",1,null,true,["Daddr"]]"#),
        "send_many must send minconf=1 not null: {request}"
    );
}

#[tokio::test]
async fn parses_get_transaction() {
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"amount":-1.5,"fee":-0.0001,"confirmations":5,"txid":"tx1",
            "time":1600000000,"timereceived":1600000001,"blockhash":"bh",
            "blockindex":2,"blocktime":1600000002,"walletconflicts":[],
            "details":[{"category":"send","amount":-1.5,"vout":0,"fee":-0.0001}],
            "hex":"aa"},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let tx = client.get_transaction("tx1", false).await.unwrap();
    assert_eq!(tx.amount, -1.5);
    assert_eq!(tx.fee, Some(-0.0001));
    assert_eq!(tx.details.len(), 1);
    assert_eq!(tx.details[0].category, "send");
    assert_eq!(tx.hex, "aa");
    // B2 wire: include_watch_only rides on the wire (gettransaction txid, include_watchonly).
    let request = handle.join().unwrap().remove(0);
    assert!(
        request.contains(r#""params":["tx1",false]"#),
        "gettransaction must send include_watch_only: {request}"
    );
}

#[tokio::test]
async fn list_unspent_sends_maxconf_and_addresses() {
    // B2 wire: min_conf, max_conf, addresses reach the wire in that positional
    // order (rpcwallet.cpp listunspent {minconf, maxconf, addresses}).
    let (url, handle) = stub_node(vec![
        http("200 OK", r#"{"result":[],"error":null,"id":0}"#),
        http("200 OK", r#"{"result":[],"error":null,"id":1}"#),
    ]);
    let client = PivxClient::new(url, Auth::None).unwrap();

    let addrs = vec!["D1".to_string(), "D2".to_string()];
    client.list_unspent(6, 100, Some(&addrs)).await.unwrap();
    // addresses=None trims to a trailing null → node default (all addresses).
    client.list_unspent(1, 9_999_999, None).await.unwrap();

    let requests = handle.join().unwrap();
    assert!(
        requests[0].contains(r#""params":[6,100,["D1","D2"]]"#),
        "listunspent must send minconf, maxconf, addresses: {}",
        requests[0]
    );
    assert!(
        requests[1].contains(r#""params":[1,9999999]"#),
        "addresses=None must trim to a trailing null: {}",
        requests[1]
    );
}

#[tokio::test]
async fn abandon_transaction_null_is_ok() {
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":null,"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    client.abandon_transaction("tx1").await.unwrap();
}

// ── Batch JSON-RPC ───────────────────────────────────────────────────────

#[tokio::test]
async fn call_batch_maps_results_in_order() {
    // A JSON array: first call succeeds, second returns a node error.
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"[{"result":42,"error":null,"id":0},
            {"result":null,"error":{"code":-5,"message":"nope"},"id":1}]"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let results = client
        .call_batch(&[
            ("getblockcount", vec![]),
            ("getrawtransaction", vec![serde_json::json!("bad")]),
        ])
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].as_ref().unwrap().as_i64(), Some(42));
    match results[1].as_ref().unwrap_err() {
        Error::Rpc { code, method, .. } => {
            assert_eq!(*code, -5);
            assert_eq!(method, "getrawtransaction");
        }
        other => panic!("expected Rpc error, got {other:?}"),
    }

    // Payload is a top-level JSON array of two request objects.
    let request = handle.join().unwrap().remove(0);
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(
        body.trim_start().starts_with('['),
        "batch body not an array: {body}"
    );
    assert!(body.contains(r#""method":"getblockcount""#));
    assert!(body.contains(r#""method":"getrawtransaction""#));
}

#[tokio::test]
async fn call_batch_empty_slice_is_rejected() {
    let client = PivxClient::new("http://127.0.0.1:1".to_string(), Auth::None).unwrap();
    let err = client.call_batch(&[]).await.unwrap_err();
    assert!(
        matches!(err, Error::Rpc { code: -32600, .. }),
        "expected invalid-request Rpc error, got {err:?}"
    );
}

#[tokio::test]
async fn call_batch_reordered_ids_are_attributed_by_id() {
    // Node returns the elements out of request order (ids 1 then 0). Matching
    // by id must still attribute each result to the correct call. (A fresh
    // client's id counter starts at 0, so the two requests carry ids 0 and 1.)
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"[{"result":"second","error":null,"id":1},
            {"result":42,"error":null,"id":0}]"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let results = client
        .call_batch(&[("getblockcount", vec![]), ("getbestblockhash", vec![])])
        .await
        .unwrap();
    assert_eq!(results[0].as_ref().unwrap().as_i64(), Some(42));
    assert_eq!(results[1].as_ref().unwrap().as_str(), Some("second"));
}

#[tokio::test]
async fn call_batch_mismatched_id_is_rejected() {
    // The second element carries an id that matches no request (999), so
    // request id 1 has no reply — the batch cannot be safely attributed and
    // fails with a labeled error rather than mis-mapping by position.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"[{"result":42,"error":null,"id":0},
            {"result":7,"error":null,"id":999}]"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = client
        .call_batch(&[("getblockcount", vec![]), ("getbestblockhash", vec![])])
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Json { method, .. } if method == "batch"),
        "expected labeled Json error, got {err:?}"
    );
}

#[tokio::test]
async fn call_batch_non_object_element_is_rejected() {
    // A bare primitive where an object is expected must be rejected, not
    // silently turned into Ok(Null).
    let (url, _handle) = stub_node(vec![http("200 OK", r#"[42]"#)]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = client
        .call_batch(&[("getblockcount", vec![])])
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Json { method, .. } if method == "batch"),
        "expected labeled Json error, got {err:?}"
    );
}

// ── v0.5 typed returns ───────────────────────────────────────────────────

#[tokio::test]
async fn parses_network_info_with_nested_and_extra() {
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"version":5030000,"subversion":"/PIVX:5.3.0/","protocolversion":70927,
            "localservices":"0000000000000005","timeoffset":0,"networkactive":true,"connections":8,
            "networks":[{"name":"ipv4","limited":false,"reachable":true,"proxy":"",
                "proxy_randomize_credentials":false}],
            "relayfee":0.00001,"localaddresses":[{"address":"1.2.3.4","port":51472,"score":1}],
            "warnings":"","futurefield":42},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let ni = client.get_network_info().await.unwrap();
    assert_eq!(ni.version, 5030000);
    assert_eq!(ni.connections, Some(8));
    assert_eq!(ni.networks[0].name, "ipv4");
    assert_eq!(ni.localaddresses[0].port, 51472);
    assert_eq!(
        ni.extra.get("futurefield").and_then(|v| v.as_i64()),
        Some(42)
    );
}

#[tokio::test]
async fn parses_peer_info_optionals_and_permsg_maps() {
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":[{"id":1,"addr":"1.2.3.4:51472","services":"5","lastsend":1,"lastrecv":2,
            "bytessent":100,"bytesrecv":200,"conntime":3,"timeoffset":0,"pingtime":0.05,
            "version":70927,"subver":"/PIVX/","inbound":false,"addnode":false,"masternode":false,
            "startingheight":1000,"whitelisted":false,
            "bytessent_per_msg":{"ping":32},"bytesrecv_per_msg":{"pong":32}}],"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let peers = client.get_peer_info().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].id, 1);
    assert_eq!(peers[0].addrlocal, None);
    assert_eq!(peers[0].synced_headers, None);
    assert_eq!(peers[0].bytessent_per_msg.get("ping"), Some(&32));
}

#[tokio::test]
async fn parses_raw_mempool_verbose_descendantfees_raw_i64() {
    // descendantfees is raw satoshis (i64), while fee/modifiedfee are PIV f64.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"abcd":{"size":200,"fee":0.0001,"modifiedfee":0.0001,"time":1600000000,
            "height":1000,"descendantcount":1,"descendantsize":200,"descendantfees":10000,
            "depends":[]}},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let m = client.get_raw_mempool_verbose().await.unwrap();
    let e = m.get("abcd").unwrap();
    assert_eq!(e.fee, 0.0001);
    assert_eq!(e.descendantfees, 10000);
    assert!(e.depends.is_empty());
}

#[tokio::test]
async fn parses_raw_mempool_nonverbose_sends_false() {
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":["tx1","tx2"],"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let txids = client.get_raw_mempool().await.unwrap();
    assert_eq!(txids, vec!["tx1".to_string(), "tx2".to_string()]);
    let request = handle.join().unwrap().remove(0);
    assert!(
        request.contains(r#""method":"getrawmempool""#) && request.contains(r#""params":[false]"#),
        "non-verbose must send [false]: {request}"
    );
}

#[tokio::test]
async fn parses_block_index_stats_string_money_and_space_keys() {
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"Starting block":100,"Ending block":200,"txcount":50,"txcount_all":52,
            "txbytes":12345,"ttlfee":"1.23456789","feeperkb":"0.00010000"},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let s = client.get_block_index_stats(200, 100).await.unwrap();
    assert_eq!(s.starting_block, 100);
    assert_eq!(s.ending_block, 200);
    assert_eq!(s.ttlfee, "1.23456789");
    assert_eq!(s.feeperkb, "0.00010000");
}

#[tokio::test]
async fn parses_mining_info_errors_and_warnings() {
    // Normal mode emits both errors and warnings.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"blocks":1000,"currentblocksize":0,"currentblocktx":0,"difficulty":1.5,
            "genproclimit":-1,"networkhashps":1234.5,"pooledtx":3,"testnet":false,"chain":"main",
            "errors":"","warnings":"heads up"},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let mi = client.get_mining_info().await.unwrap();
    assert_eq!(mi.genproclimit, -1);
    assert_eq!(mi.errors, "");
    assert_eq!(mi.warnings.as_deref(), Some("heads up"));
    assert_eq!(mi.generate, None);
}

#[tokio::test]
async fn parses_estimate_smart_fee_sentinel() {
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"feerate":-1.0,"blocks":6},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let f = client.estimate_smart_fee(6).await.unwrap();
    assert_eq!(f.feerate, -1.0);
    assert_eq!(f.blocks, 6);
}

#[tokio::test]
async fn parses_budget_projection_flatten() {
    // BudgetProjection = BudgetProposal fields (flattened) + TotalBudgetAllotted.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":[{"Name":"prop","URL":"http://x","Hash":"h","FeeHash":"fh","BlockStart":100,
            "BlockEnd":200,"TotalPaymentCount":3,"RemainingPaymentCount":2,"PaymentAddress":"D1",
            "Ratio":1.0,"Yeas":10,"Nays":1,"Abstains":0,"TotalPayment":300.0,"MonthlyPayment":100.0,
            "IsEstablished":true,"IsValid":true,"Allotted":100.0,
            "TotalBudgetAllotted":100.0}],"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let p = client.get_budget_projection().await.unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].proposal.name, "prop");
    assert_eq!(p[0].proposal.monthly_payment, 100.0);
    assert_eq!(p[0].proposal.is_invalid_reason, None);
    assert_eq!(p[0].total_budget_allotted, 100.0);
}

#[tokio::test]
async fn parses_staking_status_optional_lastattempt() {
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"staking_status":true,"staking_enabled":true,"coldstaking_enabled":false,
            "haveconnections":true,"mnsync":true,"walletunlocked":true,"stakeablecoins":5,
            "stakingbalance":123.0,"stakesplitthreshold":500.0},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let s = client.get_staking_status().await.unwrap();
    assert!(s.staking_status);
    assert_eq!(s.stakeablecoins, 5);
    assert_eq!(s.lastattempt_age, None);
}

// ── v0.5 stability: Clone + interior-null wire fixes ─────────────────────

#[tokio::test]
async fn cloned_client_shares_auth_state() {
    // A cookie refresh triggered by a 401 on one clone must be visible to the
    // other, because both share the same Arc<RwLock> of credentials.
    let (url, handle) = stub_node(vec![
        http("401 Unauthorized", ""), // c2 first try (stale)
        http("200 OK", r#"{"result":42,"error":null,"id":0}"#), // c2 retry (fresh)
        // c1 call (must be fresh); id 1 — the clones share the id counter.
        http("200 OK", r#"{"result":7,"error":null,"id":1}"#),
    ]);
    let path = temp_cookie("cloneshare", "u:old");
    let c1 = PivxClient::new(url, Auth::CookieFile(path.clone())).unwrap();
    let c2 = c1.clone();

    // Rotate the cookie on disk, then let c2 hit the 401 → refresh shared auth.
    std::fs::write(&path, "u:new").unwrap();
    assert_eq!(c2.get_block_count().await.unwrap(), 42);
    // c1 shares the Arc, so it now uses the refreshed creds without its own 401.
    assert_eq!(c1.get_block_count().await.unwrap(), 7);
    std::fs::remove_file(&path).ok();

    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0].contains("Basic dTpvbGQ="),
        "c2 first should be stale"
    );
    assert!(
        requests[1].contains("Basic dTpuZXc="),
        "c2 retry should be fresh"
    );
    assert!(
        requests[2].contains("Basic dTpuZXc="),
        "c1 must see c2's refresh via shared auth: {}",
        requests[2]
    );
}

#[tokio::test]
async fn import_sapling_key_height_without_rescan_no_interior_null() {
    let (url, handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"address":"ps1abc"},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let imported = client
        .import_sapling_key("skey", None, Some(30000))
        .await
        .unwrap();
    assert_eq!(imported.address, "ps1abc");
    let request = handle.join().unwrap().remove(0);
    // rescan default substituted (never a null before the height param).
    assert!(
        request.contains(r#""params":["skey","whenkeyisnew",30000]"#),
        "must substitute rescan default, no interior null: {request}"
    );
}

#[tokio::test]
async fn import_sapling_viewing_key_wire_forms() {
    let (url, handle) = stub_node(vec![
        http(
            "200 OK",
            r#"{"result":{"address":"a1"},"error":null,"id":0}"#,
        ),
        http(
            "200 OK",
            r#"{"result":{"address":"a2"},"error":null,"id":1}"#,
        ),
    ]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    // Both None → just the key (trailing trimmed).
    client
        .import_sapling_viewing_key("vk", None, None)
        .await
        .unwrap();
    // Height only → default rescan substituted, no interior null.
    client
        .import_sapling_viewing_key("vk", None, Some(5))
        .await
        .unwrap();
    let requests = handle.join().unwrap();
    assert!(
        requests[0].contains(r#""params":["vk"]"#),
        "both None → [vk]: {}",
        requests[0]
    );
    assert!(
        requests[1].contains(r#""params":["vk","whenkeyisnew",5]"#),
        "height only → default rescan, no null: {}",
        requests[1]
    );
}

// ── Round-1 fixes: B1-B7 ─────────────────────────────────────────────────

#[tokio::test]
async fn parses_masternode_count_object() {
    // B1: real getmasternodecount shape (src/rpc/masternode.cpp) — an object
    // with 7 numeric fields, never a bare number.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"total":1743,"stable":1698,"enabled":1721,"inqueue":1650,
            "ipv4":1500,"ipv6":193,"onion":50},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let c = client.get_masternode_count().await.unwrap();
    assert_eq!(c.total, 1743);
    assert_eq!(c.stable, 1698);
    assert_eq!(c.enabled, 1721);
    assert_eq!(c.inqueue, 1650);
    assert_eq!(c.ipv4, 1500);
    assert_eq!(c.ipv6, 193);
    assert_eq!(c.onion, 50);
}

#[tokio::test]
async fn masternode_count_no_tip_unknown_is_labeled_error() {
    // B1: before the node has a chain tip, getmasternodecount returns the
    // bare STRING "unknown" (masternode.cpp `if (!pChainTip) return
    // "unknown";`) — surfaced as a labeled error, same contract as the JS SDK.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":"unknown","error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    match client.get_masternode_count().await.unwrap_err() {
        Error::Rpc {
            message, method, ..
        } => {
            assert!(message.contains("no chain tip"), "got: {message}");
            assert_eq!(method, "getmasternodecount");
        }
        other => panic!("expected labeled Rpc error, got {other:?}"),
    }
}

#[tokio::test]
async fn parses_view_shield_transaction_string_fee_and_unknown_value() {
    // B2: fee is a FormatMoney STRING and spend/output value can be the
    // literal string "unknown" with valueSat 0 (rpcwallet.cpp
    // viewshieldtransaction) — this payload mirrors a real node response.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"txid":"aa11","fee":"0.00010000",
            "spends":[
                {"spend":0,"txidPrev":"bb22","outputPrev":1,"address":"unknown",
                 "value":"unknown","valueSat":0},
                {"spend":1,"txidPrev":"cc33","outputPrev":0,
                 "address":"ps1sender","value":1.50000000,"valueSat":150000000}],
            "outputs":[
                {"output":0,"outgoing":false,"address":"ps1receiver",
                 "value":1.49990000,"valueSat":149990000,"memo":"6869","memoStr":"hi"}]},
            "error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let v = client.view_shield_transaction("aa11").await.unwrap();
    assert_eq!(v.fee, "0.00010000");
    assert_eq!(v.spends[0].value, ShieldTxValue::Unknown);
    assert_eq!(v.spends[0].value.as_piv(), None);
    assert_eq!(v.spends[0].value_sat, 0);
    assert_eq!(v.spends[0].address, "unknown");
    assert_eq!(v.spends[1].value, ShieldTxValue::Piv(1.5));
    assert_eq!(v.spends[1].value_sat, 150_000_000);
    assert_eq!(v.outputs[0].value.as_piv(), Some(1.4999));
    assert_eq!(v.outputs[0].memo_str.as_deref(), Some("hi"));
}

#[test]
fn auth_debug_redacts_password() {
    // B3: Debug must never print the RPC password.
    let auth = Auth::UserPass {
        user: "rpcuser".into(),
        pass: "s3cr3t-hunter2".into(),
    };
    let dbg = format!("{auth:?}");
    assert!(!dbg.contains("s3cr3t-hunter2"), "password leaked: {dbg}");
    assert!(dbg.contains("rpcuser"), "user should stay visible: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "expected redaction marker: {dbg}"
    );
}

#[tokio::test]
async fn wallet_info_missing_optional_balances_are_none_not_zero() {
    // B4: nodes/wallets that omit delegated/cold-staking/shield balances must
    // yield None, not a fake 0.0 indistinguishable from a real zero balance.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":{"walletname":"w","walletversion":170000,"balance":10.5,
            "shield_balance":2.25,"unconfirmed_balance":0.0,"immature_balance":0.0,
            "txcount":12},"error":null,"id":0}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let wi = client.get_wallet_info().await.unwrap();
    assert_eq!(wi.balance, 10.5);
    assert_eq!(wi.delegated_balance, None);
    assert_eq!(wi.cold_staking_balance, None);
    assert_eq!(wi.shield_balance, Some(2.25));
}

#[tokio::test]
async fn mismatched_response_id_is_rejected() {
    // B5: a success response must echo the request id (belt-and-braces
    // against broken proxies / desynced pipelines).
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":42,"error":null,"id":999}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    match client.get_block_count().await.unwrap_err() {
        Error::Json { method, source } => {
            assert_eq!(method, "getblockcount");
            assert!(source.to_string().contains("id"), "got: {source}");
        }
        other => panic!("expected Json error, got {other:?}"),
    }
}

#[tokio::test]
async fn mismatched_response_id_on_error_reply_is_rejected() {
    // R5-1: pivxd echoes the request id on error replies too, so a wrong-id
    // error body is malformed and must be rejected as Error::Json — not
    // surfaced as this call's Error::Rpc.
    let (url, _handle) = stub_node(vec![http(
        "200 OK",
        r#"{"result":null,"error":{"code":-1,"message":"boom"},"id":999}"#,
    )]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    match client.get_block_count().await.unwrap_err() {
        Error::Json { method, source } => {
            assert_eq!(method, "getblockcount");
            assert!(source.to_string().contains("id"), "got: {source}");
        }
        other => panic!("expected Json error (id mismatch), got {other:?}"),
    }
}

#[tokio::test]
async fn shield_watcher_default_min_conf_one_explicit_zero_passes_through() {
    // P3: WatchOptions::default() polls with min_conf 1 — the JS SDK default —
    // while an explicit 0 (include unconfirmed notes; the node accepts it)
    // still reaches the wire as 0, not coerced to 1.
    let (url, handle) = stub_node(vec![
        http("200 OK", r#"{"result":"besthash","error":null,"id":0}"#),
        http("200 OK", r#"{"result":[],"error":null,"id":1}"#),
        http("200 OK", r#"{"result":"besthash2","error":null,"id":2}"#),
        http("200 OK", r#"{"result":[],"error":null,"id":3}"#),
    ]);
    let client = PivxClient::new(url, Auth::None).unwrap();

    let mut default_watcher = ShieldWatcher::new(&client, WatchOptions::default());
    default_watcher.poll().await.unwrap();

    let mut zero_conf_watcher = ShieldWatcher::new(
        &client,
        WatchOptions {
            min_conf: 0,
            ..WatchOptions::default()
        },
    );
    zero_conf_watcher.poll().await.unwrap();

    let requests = handle.join().unwrap();
    assert!(
        requests[1].contains(r#""params":[1,9999999,true]"#),
        "default min_conf must be sent as 1: {}",
        requests[1]
    );
    assert!(
        requests[3].contains(r#""params":[0,9999999,true]"#),
        "explicit min_conf 0 must be sent as 0: {}",
        requests[3]
    );
}

#[tokio::test]
async fn shield_watcher_watch_only_polarity() {
    // B3: WatchOptions::default() now polls with watch-only INCLUDED (wire
    // `true`, matching the JS `includeWatchOnly` default); an explicit
    // include_watch_only=false excludes it (wire `false`).
    let (url, handle) = stub_node(vec![
        http("200 OK", r#"{"result":"besthash","error":null,"id":0}"#),
        http("200 OK", r#"{"result":[],"error":null,"id":1}"#),
        http("200 OK", r#"{"result":"besthash2","error":null,"id":2}"#),
        http("200 OK", r#"{"result":[],"error":null,"id":3}"#),
    ]);
    let client = PivxClient::new(url, Auth::None).unwrap();

    let mut default_watcher = ShieldWatcher::new(&client, WatchOptions::default());
    default_watcher.poll().await.unwrap();

    let mut exclude_watcher = ShieldWatcher::new(
        &client,
        WatchOptions {
            include_watch_only: false,
            ..WatchOptions::default()
        },
    );
    exclude_watcher.poll().await.unwrap();

    let requests = handle.join().unwrap();
    assert!(
        requests[1].contains(r#""params":[1,9999999,true]"#),
        "default must include watch-only (wire true): {}",
        requests[1]
    );
    assert!(
        requests[3].contains(r#""params":[1,9999999,false]"#),
        "include_watch_only=false must exclude watch-only (wire false): {}",
        requests[3]
    );
}

#[test]
fn credentials_in_url_are_rejected() {
    // B7: URL userinfo is unsupported — reject at construction with a clear
    // error pointing at Auth, before anything can log the URL.
    let err = PivxClient::new("http://user:pass@127.0.0.1:51473".to_string(), Auth::None).err();
    assert!(
        matches!(err, Some(Error::CredentialsInUrl)),
        "user:pass@ must be rejected, got {err:?}"
    );
    let err = PivxClient::new("http://user@127.0.0.1:51473".to_string(), Auth::None).err();
    assert!(
        matches!(err, Some(Error::CredentialsInUrl)),
        "user-only userinfo must be rejected, got {err:?}"
    );
    // S5: a scheme-less "user:pass@host:port" parses with "user" as the URL
    // scheme, so the userinfo check never sees the credentials; without the
    // scheme guard reqwest would fail at send time and leak the password
    // through its error. Reject it at construction instead.
    let err = PivxClient::new("user:pass@127.0.0.1:51473".to_string(), Auth::None).err();
    assert!(
        matches!(err, Some(Error::CredentialsInUrl)),
        "scheme-less user:pass@host must be rejected, got {err:?}"
    );
    // A non-http(s) scheme is likewise refused (only http/https are supported).
    assert!(matches!(
        PivxClient::new("ftp://127.0.0.1:51473".to_string(), Auth::None),
        Err(Error::CredentialsInUrl)
    ));
    // A clean URL still constructs.
    assert!(PivxClient::new("http://127.0.0.1:51473".to_string(), Auth::None).is_ok());
    assert!(PivxClient::new("https://127.0.0.1:51473".to_string(), Auth::None).is_ok());
}

#[tokio::test]
async fn protx_list_method_name_and_defaults_not_null() {
    let (url, handle) = stub_node(vec![http("200 OK", r#"{"result":[],"error":null,"id":0}"#)]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    // height set but the earlier bools omitted: they must become concrete
    // defaults, never nulls.
    client
        .protx_list(None, None, None, Some(200000))
        .await
        .unwrap();
    let request = handle.join().unwrap().remove(0);
    assert!(
        request.contains(r#""method":"protx_list""#),
        "wire method is protx_list (flat command), not a subcommand: {request}"
    );
    assert!(
        request.contains(r#""params":[true,false,false,200000]"#),
        "protx_list must send node defaults, no interior null: {request}"
    );
}

/// Like `stub_node` but sleeps `delay` before answering each connection, and
/// tolerates the client hanging up early (a timed-out request).
fn slow_stub_node(
    delay: std::time::Duration,
    responses: Vec<String>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            std::thread::sleep(delay);
            let _ = stream.write_all(response.as_bytes()); // client may have timed out
        }
    });
    (url, handle)
}

#[tokio::test]
async fn sapling_import_rescan_outlives_short_client_timeout() {
    // P1: a rescan blocks the node well past any sane client timeout, so both
    // sapling imports get a per-request timeout of max(client timeout, 600s)
    // unless rescan == Some("no") — mirroring the JS SDK. The stub answers
    // after 600ms against a 200ms client timeout.
    let (url, _handle) = slow_stub_node(
        std::time::Duration::from_millis(600),
        vec![
            http(
                "200 OK",
                r#"{"result":{"address":"ps1"},"error":null,"id":0}"#,
            ),
            http(
                "200 OK",
                r#"{"result":{"address":"ps1"},"error":null,"id":1}"#,
            ),
            // Served to the rescan="no" call below, which times out first: the
            // stub must still accept its connection, otherwise the client sees
            // a connection refusal instead of its own (short) timeout.
            http(
                "200 OK",
                r#"{"result":{"address":"ps1"},"error":null,"id":2}"#,
            ),
        ],
    );
    let client =
        PivxClient::with_timeout(url, Auth::None, std::time::Duration::from_millis(200)).unwrap();

    // Default rescan ("whenkeyisnew") → raised timeout: the call succeeds.
    let imported = client.import_sapling_key("skey", None, None).await.unwrap();
    assert_eq!(imported.address, "ps1");
    // Explicit rescan="yes" on the viewing-key import: same raised timeout.
    let imported = client
        .import_sapling_viewing_key("vk", Some("yes"), None)
        .await
        .unwrap();
    assert_eq!(imported.address, "ps1");
    // rescan="no" keeps the client-wide (short) timeout: times out.
    let err = client
        .import_sapling_key("skey", Some("no"), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Transport(e) if e.is_timeout()),
        "rescan=\"no\" must keep the short client timeout, got {err:?}"
    );
}

#[tokio::test]
async fn raw_shield_send_many_min_conf_fee_defaults_and_pass_through() {
    // P5: omitted min_conf/fee become the node defaults on the wire (1, and
    // fee=0 = "node computes the minimum"), never interior nulls; explicit
    // values pass through — matching the JS SDK's rawShieldSendMany.
    let (url, handle) = stub_node(vec![
        http("200 OK", r#"{"result":"rawhex","error":null,"id":0}"#),
        http("200 OK", r#"{"result":"rawhex","error":null,"id":1}"#),
    ]);
    let client = PivxClient::new(url, Auth::None).unwrap();
    let recipients = [pivx_rpc::ShieldRecipient::new("ps1x", 1.0)];

    let hex = client
        .raw_shield_send_many("from_shield", &recipients, None, None)
        .await
        .unwrap();
    assert_eq!(hex, "rawhex");
    client
        .raw_shield_send_many("from_shield", &recipients, Some(5), Some(0.5))
        .await
        .unwrap();

    let requests = handle.join().unwrap();
    assert!(
        requests[0].contains(r#""params":["from_shield",[{"address":"ps1x","amount":1.0}],1,0.0]"#),
        "omitted min_conf/fee must become node defaults 1/0: {}",
        requests[0]
    );
    assert!(
        requests[1].contains(r#""params":["from_shield",[{"address":"ps1x","amount":1.0}],5,0.5]"#),
        "explicit min_conf/fee must pass through: {}",
        requests[1]
    );
}
