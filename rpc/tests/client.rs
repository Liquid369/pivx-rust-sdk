use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use pivx_rpc::{Auth, Error, PivxClient};

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
