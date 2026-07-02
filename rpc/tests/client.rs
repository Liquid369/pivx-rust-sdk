use std::io::{Read, Write};
use std::net::TcpListener;

use pivx_rpc::{Auth, Error, PivxClient};

/// One-shot HTTP stub: accepts a single connection, captures the request,
/// returns `body` as JSON. No mock-server dependency needed.
fn stub_node(body: &'static str) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).into_owned();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        request
    });
    (url, handle)
}

#[tokio::test]
async fn parses_shield_notes_and_sends_auth() {
    // Real field names as emitted by pivxd's listshieldunspent.
    let (url, handle) = stub_node(
        r#"{"result":[{"txid":"ab12","outindex":1,"confirmations":12,"spendable":false,
            "address":"ps1watchaddr","amount":4.20000000,"memo":"48690000",
            "change":false,"nullifier":"ff00"}],"error":null,"id":0}"#,
    );

    let client = PivxClient::new(
        url,
        Auth::UserPass { user: "u".into(), pass: "p".into() },
    )
    .unwrap();
    let notes = client.list_shield_unspent(1, 9_999_999, true, None).await.unwrap();

    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].txid, "ab12");
    assert_eq!(notes[0].amount, 4.2);
    assert_eq!(notes[0].change, Some(false));

    let request = handle.join().unwrap();
    // Basic dTpw = base64("u:p"); trailing null (addresses=None) trimmed.
    assert!(request.contains("Basic dTpw"), "missing auth header: {request}");
    assert!(request.contains(r#""params":[1,9999999,true]"#), "bad params: {request}");
    assert!(request.contains(r#""method":"listshieldunspent""#));
}

#[tokio::test]
async fn node_error_surfaces_with_code() {
    let (url, _handle) = stub_node(
        r#"{"result":null,"error":{"code":-13,"message":"Please enter the wallet passphrase"},"id":0}"#,
    );
    let client = PivxClient::new(url, Auth::None).unwrap();
    let err = client.get_shield_balance("*", 1, false).await.unwrap_err();
    match err {
        Error::Rpc { code, message, method } => {
            assert_eq!(code, -13);
            assert!(message.contains("passphrase"));
            assert_eq!(method, "getshieldbalance");
        }
        other => panic!("expected Rpc error, got {other:?}"),
    }
}
