# pivx-rpc

Typed async JSON-RPC client for [PIVX](https://pivx.org) `pivxd` nodes:
blockchain, wallet, and the full shielded (SHIELD/Sapling) RPC surface,
plus a poll-based `ShieldWatcher` for deposit detection.

Part of the [PIVX Rust SDK](https://github.com/Liquid369/pivx-rust-sdk).
For a standalone wallet where your application owns the keys, see the
companion `pivx-wallet` crate.

## Install

```toml
[dependencies]
pivx-rpc = "0.1"
```

## Usage

```rust,no_run
use pivx_rpc::{Auth, PivxClient, ShieldRecipient, ShieldWatcher, WatchOptions};

# async fn demo() -> Result<(), pivx_rpc::Error> {
let client = PivxClient::new(
    "http://127.0.0.1:51473",
    Auth::UserPass { user: "rpcuser".into(), pass: "rpcpass".into() },
)?;

// Watch a shielded address via its viewing key (no spend key needed).
let imported = client.import_sapling_viewing_key("p-view-key...", None, None).await?;
let mut watcher = ShieldWatcher::new(&client, WatchOptions {
    addresses: vec![imported.address],
    ..Default::default()
});
let events = watcher.poll().await?; // first poll primes silently

// Send shielded funds (node wallet holds the keys and builds the proof).
let txid = client
    .shield_send_many(
        pivx_rpc::FromAddress::AnyShield,
        &[ShieldRecipient::new("ps1...", 1.5).with_memo("hello")],
    )
    .await?;
# Ok(()) }
```

License: MIT.
