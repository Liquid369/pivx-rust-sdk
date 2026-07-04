//! PIVX SDK: typed JSON-RPC client for pivxd with first-class support for
//! shielded (SHIELD/Sapling) balances and transactions.
//!
//! ```no_run
//! use pivx_rpc::{Auth, PivxClient, ShieldRecipient, ShieldWatcher, WatchOptions};
//!
//! # async fn demo() -> Result<(), pivx_rpc::Error> {
//! let client = PivxClient::new(
//!     "http://127.0.0.1:51473",
//!     Auth::UserPass { user: "rpcuser".into(), pass: "rpcpass".into() },
//! )?;
//!
//! // Watch a shielded address via its viewing key (no spend key needed).
//! let imported = client.import_sapling_viewing_key("p-view-key...", None, None).await?;
//! let mut watcher = ShieldWatcher::new(&client, WatchOptions {
//!     addresses: vec![imported.address],
//!     ..Default::default()
//! });
//! let events = watcher.poll().await?; // first poll primes silently
//!
//! // Send shielded funds (node wallet holds the keys and builds the proof).
//! let txid = client
//!     .shield_send_many(
//!         pivx_rpc::FromAddress::AnyShield,
//!         &[ShieldRecipient::new("ps1...", 1.5).with_memo("hello")],
//!     )
//!     .await?;
//! # Ok(()) }
//! ```

mod client;
mod shield;
mod types;
pub mod zmq;

pub use client::{Auth, Error, PivxClient, Result};
pub use shield::{ShieldEvent, ShieldWatcher, WatchOptions};
pub use types::*;
#[cfg(feature = "zmq")]
pub use zmq::ZmqSubscriber;
pub use zmq::{parse_zmq_frame, ZmqError, ZmqEvent};
