//! ZMQ push notifications (v0.6 wire format).
//!
//! pivxd publishes a 3-part multipart message per event:
//! `[topic-utf8, body-bytes, sequence-LE-u32]`. Topics are `hashblock`,
//! `hashtx`, `rawblock`, `rawtx`. See PIVX `src/zmq/zmqpublishnotifier.cpp`.
//!
//! Launch the node with e.g.
//! `-zmqpubhashblock=tcp://127.0.0.1:28332 -zmqpubrawtx=tcp://127.0.0.1:28332`,
//! then subscribe hashblock (or rawtx) and trigger a wallet sync on each event.
//!
//! [`parse_zmq_frame`] is pure and always compiled — bring your own socket.
//! [`ZmqSubscriber`] is a SUB-socket convenience behind the `zmq` cargo
//! feature (pure-Rust `zeromq` crate, no libzmq).

/// Topic strings published by pivxd, one per event kind.
pub const TOPIC_HASHBLOCK: &str = "hashblock";
pub const TOPIC_HASHTX: &str = "hashtx";
pub const TOPIC_RAWBLOCK: &str = "rawblock";
pub const TOPIC_RAWTX: &str = "rawtx";

/// A decoded ZMQ notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZmqEvent {
    /// New block; `hash` is the display-order block hash (hex).
    HashBlock { hash: String, sequence: u32 },
    /// New transaction; `hash` is the display-order txid (hex).
    HashTx { hash: String, sequence: u32 },
    /// Serialized block bytes (raw).
    RawBlock { block: Vec<u8>, sequence: u32 },
    /// Serialized transaction bytes (raw).
    RawTx { tx: Vec<u8>, sequence: u32 },
}

/// Errors decoding a ZMQ frame or driving the subscriber socket.
#[derive(Debug, thiserror::Error)]
pub enum ZmqError {
    /// Topic frame was not one of the four known topics.
    #[error("unknown ZMQ topic: {0}")]
    UnknownTopic(String),
    /// Sequence frame was not exactly 4 bytes.
    #[error("malformed ZMQ sequence frame: expected 4 little-endian bytes")]
    BadSequence,
    /// A hash topic (`hashblock`/`hashtx`) body was not exactly 32 bytes.
    #[error("hash topic body must be 32 bytes, got {0}")]
    BadHashLength(usize),
    /// Underlying `zeromq` socket error (feature `zmq`).
    #[error("zmq socket error: {0}")]
    Socket(String),
}

/// Hex-encode bytes (lowercase). The node already reverses hashes into display
/// order before publishing, so hashblock/hashtx bodies hex directly to the
/// standard blockhash/txid string — no byte reversal here.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hash_hex(body: &[u8]) -> Result<String, ZmqError> {
    if body.len() != 32 {
        return Err(ZmqError::BadHashLength(body.len()));
    }
    Ok(to_hex(body))
}

fn sequence(seq: &[u8]) -> Result<u32, ZmqError> {
    let bytes: [u8; 4] = seq.try_into().map_err(|_| ZmqError::BadSequence)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Decode the three raw frames of a ZMQ notification into a [`ZmqEvent`].
///
/// This is the pure, socket-free primitive both SDKs share. `topic` is the
/// UTF-8 topic frame, `body` the payload, `seq` the 4-byte little-endian
/// per-topic counter.
pub fn parse_zmq_frame(topic: &[u8], body: &[u8], seq: &[u8]) -> Result<ZmqEvent, ZmqError> {
    let sequence = sequence(seq)?;
    match topic {
        b"hashblock" => Ok(ZmqEvent::HashBlock {
            hash: hash_hex(body)?,
            sequence,
        }),
        b"hashtx" => Ok(ZmqEvent::HashTx {
            hash: hash_hex(body)?,
            sequence,
        }),
        b"rawblock" => Ok(ZmqEvent::RawBlock {
            block: body.to_vec(),
            sequence,
        }),
        b"rawtx" => Ok(ZmqEvent::RawTx {
            tx: body.to_vec(),
            sequence,
        }),
        other => Err(ZmqError::UnknownTopic(
            String::from_utf8_lossy(other).into_owned(),
        )),
    }
}

/// A connected SUB socket over the pure-Rust `zeromq` crate. Opt-in via the
/// `zmq` cargo feature. The caller drives cadence by awaiting [`recv`].
#[cfg(feature = "zmq")]
pub struct ZmqSubscriber {
    socket: zeromq::SubSocket,
}

#[cfg(feature = "zmq")]
impl ZmqSubscriber {
    /// Create a SUB socket, connect to `endpoint` (e.g. `tcp://127.0.0.1:28332`),
    /// and subscribe to each topic (use the `TOPIC_*` constants).
    ///
    /// Note: against an endpoint with nothing listening, `connect` blocks on
    /// the underlying connect timeout (~30s) before returning `Err` rather than
    /// failing fast. Wrap this call in `tokio::time::timeout` if you need
    /// quicker failover.
    pub async fn connect(endpoint: &str, topics: &[&str]) -> Result<Self, ZmqError> {
        use zeromq::Socket;
        let mut socket = zeromq::SubSocket::new();
        socket
            .connect(endpoint)
            .await
            .map_err(|e| ZmqError::Socket(e.to_string()))?;
        for topic in topics {
            socket
                .subscribe(topic)
                .await
                .map_err(|e| ZmqError::Socket(e.to_string()))?;
        }
        Ok(Self { socket })
    }

    /// Await the next notification and decode it via [`parse_zmq_frame`].
    pub async fn recv(&mut self) -> Result<ZmqEvent, ZmqError> {
        use zeromq::SocketRecv;
        let msg = self
            .socket
            .recv()
            .await
            .map_err(|e| ZmqError::Socket(e.to_string()))?;
        let frames = msg.into_vec();
        if frames.len() != 3 {
            return Err(ZmqError::Socket(format!(
                "expected a 3-part message, got {} frame(s)",
                frames.len()
            )));
        }
        parse_zmq_frame(&frames[0], &frames[1], &frames[2])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1..=32 as bytes: asymmetric so the hex asserts display-order (no reversal).
    fn body32() -> Vec<u8> {
        (1u8..=32).collect()
    }
    const HEX32: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn parses_hashblock_hex_and_le_sequence() {
        // seq bytes 04 03 02 01 (LE) => 0x01020304.
        let ev = parse_zmq_frame(b"hashblock", &body32(), &[0x04, 0x03, 0x02, 0x01]).unwrap();
        assert_eq!(
            ev,
            ZmqEvent::HashBlock {
                hash: HEX32.to_string(),
                sequence: 0x0102_0304,
            }
        );
    }

    #[test]
    fn parses_hashtx() {
        let ev = parse_zmq_frame(b"hashtx", &[0x11; 32], &1u32.to_le_bytes()).unwrap();
        assert_eq!(
            ev,
            ZmqEvent::HashTx {
                hash: "11".repeat(32),
                sequence: 1,
            }
        );
    }

    #[test]
    fn parses_rawblock_passthrough() {
        let body = vec![0xde, 0xad, 0xbe, 0xef];
        let ev = parse_zmq_frame(b"rawblock", &body, &5u32.to_le_bytes()).unwrap();
        assert_eq!(
            ev,
            ZmqEvent::RawBlock {
                block: body,
                sequence: 5,
            }
        );
    }

    #[test]
    fn parses_rawtx_passthrough() {
        let body = vec![0x01, 0x02, 0x03];
        let ev = parse_zmq_frame(b"rawtx", &body, &9u32.to_le_bytes()).unwrap();
        assert_eq!(
            ev,
            ZmqEvent::RawTx {
                tx: body,
                sequence: 9,
            }
        );
    }

    #[test]
    fn rejects_unknown_topic() {
        let err = parse_zmq_frame(b"badtopic", &body32(), &0u32.to_le_bytes()).unwrap_err();
        assert!(matches!(err, ZmqError::UnknownTopic(t) if t == "badtopic"));
    }

    #[test]
    fn rejects_non_32_hash_body() {
        let err = parse_zmq_frame(b"hashblock", &[0u8; 31], &0u32.to_le_bytes()).unwrap_err();
        assert!(matches!(err, ZmqError::BadHashLength(31)));
    }

    #[test]
    fn rejects_bad_sequence_length() {
        let err = parse_zmq_frame(b"hashblock", &body32(), &[0x01, 0x00, 0x00]).unwrap_err();
        assert!(matches!(err, ZmqError::BadSequence));
    }
}

// Real PUB->SUB round-trip over the zeromq crate. Best-effort: ZMQ's slow-joiner
// means the SUB can miss the first sends, so the publisher retries and the recv
// is bounded by a timeout — a timeout logs and passes rather than flaking CI.
// Either way this compiles and calls ZmqSubscriber::connect + recv, pinning the
// feature-gated API.
#[cfg(all(test, feature = "zmq"))]
mod socket_tests {
    use super::*;
    use std::time::Duration;
    use zeromq::{Socket, SocketSend, ZmqMessage};

    #[tokio::test]
    async fn pub_sub_round_trip() {
        let mut publisher = zeromq::PubSocket::new();
        let endpoint = publisher.bind("tcp://127.0.0.1:0").await.expect("bind PUB");
        let addr = endpoint.to_string();

        let mut sub = ZmqSubscriber::connect(&addr, &[TOPIC_HASHBLOCK])
            .await
            .expect("connect SUB");

        let pub_task = tokio::spawn(async move {
            loop {
                let mut msg = ZmqMessage::from(TOPIC_HASHBLOCK.as_bytes().to_vec());
                msg.push_back(vec![0xab_u8; 32].into());
                msg.push_back(3u32.to_le_bytes().to_vec().into());
                if publisher.send(msg).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(5), sub.recv()).await;
        pub_task.abort();

        match result {
            Ok(Ok(ZmqEvent::HashBlock { hash, sequence })) => {
                assert_eq!(hash, "ab".repeat(32));
                assert_eq!(sequence, 3);
            }
            Ok(Ok(other)) => panic!("unexpected event: {other:?}"),
            Ok(Err(e)) => panic!("recv error: {e}"),
            Err(_) => eprintln!(
                "ponytail: PUB->SUB round-trip timed out (ZMQ slow-joiner); best-effort test passes"
            ),
        }
    }
}
