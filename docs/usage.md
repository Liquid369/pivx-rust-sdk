# Usage

Two crates. `pivx-rpc` talks to a pivxd node you trust with keys.
`pivx-wallet` holds keys itself and uses the node only as a chain-data
source. That node must be one you trust — the SDK does not validate
proof-of-stake or the header chain, so a malicious node can fabricate
deposits (see `SECURITY.md`). Most integrations want `pivx-wallet`; use
`pivx-rpc` alone when the node's built-in wallet already does what you need.

`pivx-wallet` depends on git crates (librustpivx), so install both via git:

```toml
[dependencies]
pivx-rpc = { git = "https://github.com/Liquid369/pivx-rust-sdk" }
pivx-wallet = { git = "https://github.com/Liquid369/pivx-rust-sdk" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Both crates are async; examples assume tokio.

## Trust model

The wallet does not validate proof-of-stake or the header chain. Its only
sync check — comparing the local commitment-tree root to the block's
`finalsaplingroot` — proves the tree matches *the node's own reported root*,
not that the chain is real. A malicious node can therefore fabricate a
deposit to a known address. Point the wallet at a node you control (or
corroborate across independent nodes), require confirmations before
crediting. Full detail and the integrator checklist are in
[`SECURITY.md`](../SECURITY.md).

## Units

`pivx-rpc` amounts are PIV as `f64`, exactly as pivxd emits them
(`5.12345678`). `pivx-wallet` amounts are integer satoshis as `u64`
(`512345678`), the unit of the underlying cryptography. 1 PIV =
100_000_000 sats. Mixing these up is the classic integration bug; check
twice at the boundary between the two layers.

## pivx-rpc

### Connecting

```rust
use pivx_rpc::{Auth, PivxClient, Error};

let client = PivxClient::new(
    "http://127.0.0.1:51473",   // testnet: 51475
    Auth::UserPass { user: "rpcuser".into(), pass: "rpcpass".into() },
)?;

// or read credentials from the node's cookie file
let client = PivxClient::new(
    "http://127.0.0.1:51473",
    Auth::CookieFile("/home/pivx/.pivx/.cookie".into()),
)?;
```

pivxd rewrites the cookie on every restart. With `Auth::CookieFile`, an HTTP
401 makes the client re-read the file and retry the request once if the
credentials changed, so a node restart doesn't require rebuilding the client.
A 403 (an IP/ACL denial a cookie can't fix) is not retried.

`PivxClient` is cheaply `Clone` — clones share the same connection pool and
credential store — so hand a clone to each task rather than rebuilding the
client, and a cookie refresh on any one clone is visible to all.

For multiwallet nodes append `/wallet/<name>` to the URL. There is no TLS:
run the node on localhost or tunnel the connection; do not expose the RPC
port.

### Calling the node

```rust
let height = client.get_block_count().await?;
let balance = client.get_shield_balance("*", 1, false).await?;   // PIV
let mn_count = client.get_masternode_count().await?;             // masternode count
let fee = client.estimate_smart_fee(6).await?;                   // smart fee estimate
let addr = client.get_new_shield_address(None).await?;
```

v0.4 widened the typed surface across blockchain introspection, raw
transactions, and exchange-grade wallet calls:

```rust
let best = client.get_best_block_hash().await?;
let header = client.get_block_header(&best).await?;
let utxo = client.get_tx_out(&txid, 0, None).await?;   // None once the output is spent

// Verbose getrawtransaction decodes ANY txid — not just wallet ones — and
// carries confirmations. Needs -txindex, or pass Some(blockhash) to look in one block:
let tx = client.get_raw_transaction_verbose(&txid, None).await?;
println!("{:?}", tx.confirmations);

// Reorg-safe deposit cursor for exchanges: page new wallet txs from the last
// block you processed; the returned lastblock is your next cursor.
let since = client.list_since_block(Some(&last_processed), None, None).await?;

// Batch payout to many recipients in one transaction.
let mut amounts = std::collections::HashMap::new();
amounts.insert("D1...".to_string(), 1.5);
amounts.insert("D2...".to_string(), 2.0);
let payout_txid = client.send_many(&amounts, None, None, None, None).await?;

// Build → sign → broadcast a raw transaction (the node's RPC is
// signrawtransaction, 4 params; extra args are None here).
let raw_hex = client.create_raw_transaction(&inputs, &outputs, None).await?;
let signed = client.sign_raw_transaction(&raw_hex, None, None, None).await?;
if signed.complete {
    client.send_raw_transaction(&signed.hex).await?;
}
```

`gettransaction` and `validateaddress` are typed too, now returning
structured results (`Transaction`, `ValidateAddress`) rather than a raw
`serde_json::Value`.

Typed methods now reach the masternode, deterministic-masternode (`protx`),
budget, staking, and network/mempool/mining/util surface as well:

```rust
let fee = client.estimate_smart_fee(6).await?;
println!("{}", fee.feerate);                  // PIV/kB; -1.0 when the node has no estimate

let staking = client.get_staking_status().await?;
if staking.staking_status {
    println!("actively staking");
}

// non-verbose returns txids; verbose returns a txid → entry map:
let txids = client.get_raw_mempool().await?;              // Vec<String>
let entries = client.get_raw_mempool_verbose().await?;    // HashMap<String, MempoolEntry>
for (txid, e) in &entries {
    println!("{txid} {}", e.fee);
}
```

Each typed status struct keeps a flattened `extra` map, so a field a newer
node adds is preserved rather than dropped. `get_masternode_status`,
`masternode_current`, and `list_masternodes` stay a raw `serde_json::Value`
on purpose — their shape is polymorphic.

Anything still not wrapped goes through `call`, with positional params exactly
as `pivx-cli` would take them:

```rust
let decoded: serde_json::Value =
    client.call("decodescript", vec![serde_json::json!(script_hex)]).await?;
```

Node errors surface as `Error::Rpc { code, message, .. }` with the node's
own code; transport failures are `Error::Transport`, so retry logic can
tell them apart. An HTTP 401/403 that survives the cookie refresh is
`Error::Auth { status }` — a distinct variant, so a credentials problem is
matchable rather than retried (an oversized body is `Error::ResponseTooLarge`
and other non-2xx responses without a JSON-RPC error body are `Error::Http`).
`Error` is `#[non_exhaustive]`, so a `match` on it needs a trailing catch-all
arm (`other =>` below):

```rust
match client.shield_send_many(FromAddress::AnyShield, &recipients).await {
    Err(Error::Rpc { code: -13, .. }) => { /* wallet locked */ }
    other => { /* ... */ }
}
```

### Batch calls

`call_batch` sends several calls in one HTTP round-trip. It returns one entry
per call in request order: `Ok(value)` on success, `Err(Error::Rpc { .. })`
for a per-call node error that does not fail the batch — only a
transport/auth failure returns an outer `Err`. Handy for fanning out a set of
lookups, e.g. several block hashes or txids at once:

```rust
use serde_json::json;

let results = client.call_batch(&[
    ("getblockhash", vec![json!(100)]),
    ("getblockhash", vec![json!(200)]),
    ("gettxout", vec![json!(txid), json!(0)]),
]).await?;
for r in results {
    match r {
        Ok(value) => println!("{value}"),
        Err(e) => eprintln!("{e}"),
    }
}
```

### Watching the node wallet

`ShieldWatcher` polls per block and diffs the node wallet's unspent shield
notes. Import a viewing key first to monitor an address whose spending key
the node never sees:

```rust
use pivx_rpc::{ShieldEvent, ShieldWatcher, WatchOptions};

let imported = client.import_sapling_viewing_key(&vkey, Some("whenkeyisnew"), Some(4_800_000)).await?;
let mut watcher = ShieldWatcher::new(&client, WatchOptions {
    addresses: vec![imported.address],
    ..Default::default()
});

loop {
    for event in watcher.poll().await? {
        match event {
            ShieldEvent::Note(n) => println!("+{} PIV in {}", n.amount, n.txid),
            ShieldEvent::Spent(n) => println!("-{} PIV", n.amount),
            ShieldEvent::Balance { current, previous } => println!("{previous} -> {current}"),
        }
    }
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;  // ~60s blocks
}
```

The watcher owns no background task; you choose the cadence. Caveat,
straight from the node: with only an incoming viewing key, spends made
elsewhere are invisible, so a watch-only balance can over-report. Reconcile
against note events rather than the balance number when the spending key
lives somewhere else.

### Sending from the node wallet

`shieldsendmany` proves and broadcasts in one call and returns the txid.
Expect seconds; proving is expensive.

```rust
use pivx_rpc::{FromAddress, ShieldRecipient};

let txid = client.shield_send_many(
    FromAddress::AnyShield,
    &[ShieldRecipient::new("ps1...", 5.0).with_memo("invoice 42")],
).await?;
let view = client.view_shield_transaction(&txid).await?;  // decrypted amounts + memos
```

### ZMQ push notifications

v0.6 adds ZMQ push notifications: pivxd can push a notification on every new
block or transaction, so you can trigger a wallet `sync` the moment the chain
moves instead of polling `ShieldWatcher`. (v0.6.0 ships pivx-rpc 0.5.0.) Launch
the node with the matching endpoints, e.g.
`-zmqpubhashblock=tcp://127.0.0.1:28332 -zmqpubrawtx=tcp://127.0.0.1:28332`
(topics: `hashblock`, `hashtx`, `rawblock`, `rawtx`).

`ZmqSubscriber` is behind the off-by-default `zmq` cargo feature (a pure-Rust
`zeromq` crate, no libzmq), so enable it to pull the socket in:

```toml
pivx-rpc = { git = "https://github.com/Liquid369/pivx-rust-sdk", features = ["zmq"] }
```

It owns a SUB socket; drive the cadence by awaiting `recv`:

```rust
use pivx_rpc::{ZmqEvent, ZmqSubscriber};

let mut sub = ZmqSubscriber::connect("tcp://127.0.0.1:28332", &["hashblock"]).await?;
loop {
    match sub.recv().await? {
        ZmqEvent::HashBlock { hash, .. } => {
            println!("new block {hash}");
            wallet.sync(&client, 100).await?;
        }
        _ => {}
    }
}
```

`connect` blocks on the underlying ~30s connect timeout against a dead endpoint
before returning `Err` rather than failing fast; wrap it in
`tokio::time::timeout` if you need quicker failover. `HashBlock`/`HashTx` carry
`hash` (display-order hex); `RawBlock`/`RawTx` carry raw bytes as `block` / `tx`;
every variant carries a little-endian `sequence`.

If you already have a socket, skip the subscriber and decode frames yourself
with the pure `parse_zmq_frame(topic, body, seq)` — always compiled, no feature
needed — which returns the same typed `ZmqEvent`.

## pivx-wallet

### Creating a wallet

A wallet is built from whichever key material you have. Capability follows
the key:

```rust
use pivx_wallet::{Network, ShieldWallet};

// full capability: 32 bytes of entropy, ZIP32 derivation (coin type 119)
let mut w1 = ShieldWallet::from_seed(&seed, Network::MainNetwork, 4_800_000, 0)?;

// full capability: an exported extended spending key (p-secret-spending-key-...)
let mut w2 = ShieldWallet::from_spending_key(&extsk, Network::MainNetwork, 4_800_000)?;

// watch-only: scan, derive addresses, track balance; cannot spend
let mut w3 = ShieldWallet::from_viewing_key(&extfvk, Network::MainNetwork, 4_800_000)?;
```

The birth height is the height the wallet's keys first existed. Scanning
starts at the nearest checkpoint at or below it; blocks before that are
never seen. For a new wallet, pass the current chain height. Setting it too
low costs sync time; too high loses funds received before it.

A watch-only wallet upgrades in place, and rejects a key that doesn't match
its viewing key:

```rust
w3.load_spending_key(&extsk)?;
```

Get a viewing key for a watch-only host from the node
(`exportsaplingviewingkey`) or from a full wallet's saved state (the
`extfvk` field).

### Receive addresses

```rust
let addr = wallet.new_address()?;   // next diversified address, ps1...
```

Diversified addresses all decrypt with the same keys; hand out a fresh one
per deposit and match incoming notes by address or memo.

### Syncing

```rust
let client = PivxClient::new("http://127.0.0.1:51473", auth)?;
wallet.sync(&client, 100).await?;   // 100 blocks per batch
```

`sync` walks from the last synced block to the node's tip, decrypts every
transaction, and verifies the local commitment tree against the block
header's `finalsaplingroot` after each batch. Call it again any time; it
picks up where it left off. A first sync from an old birth height fetches
every block since, so budget minutes, not milliseconds.

With your own block feed (ZMQ, an indexer), skip `sync` and push blocks
yourself; heights must be strictly ascending:

```rust
use pivx_wallet::WalletBlock;
wallet.handle_blocks(&[WalletBlock { height, tx_hexes }])?;
```

If the tree check fails, `sync` returns `WalletError::ScanDiverged`. This
means a chain reorg crossed a batch boundary, the node lied, or the saved
state is corrupt. Recovery is mechanical: recreate the wallet from its keys
with the same birth height and sync again. The `rpc` feature (on by
default) provides `sync` and `send`; disable it to bring your own
transport.

Rust's borrow rules prevent concurrent syncs on one wallet. Keep it that
way across tasks: one wallet, one writer. To cancel a long sync, drop its
future — e.g. wrap the call in `tokio::time::timeout` or race it in a
`select!`. Cancellation lands at an `.await` between batches, so the state
kept is the last fully applied, root-verified batch; call `sync` again to
resume. (The JS SDK exposes the same via an `AbortSignal` option.)

### Detecting deposits

Confirmed deposits are new entries in `notes()` after a sync. Track
nullifiers you've already credited:

```rust
let seen: HashSet<String> = credited_nullifiers();
wallet.sync(&client, 100).await?;
for n in wallet.notes().iter().filter(|n| !seen.contains(&n.nullifier)) {
    credit(n.note.value().inner(), n.memo.as_deref());  // sats; memo may carry your payment id
}
```

Credit balances only from synced, confirmed notes, at whatever confirmation
depth your risk model wants (PIVX targets 60-second blocks).

### Persistence

```rust
let json = wallet.save()?;                    // no spending key inside
// ... later, possibly on another host or in the JS SDK
let mut restored = ShieldWallet::load(&json)?;
restored.load_spending_key(&extsk)?;          // only where spending happens
```

`save()` output contains the viewing key, sync position, commitment tree,
notes, and pending spends. It cannot spend, but it can see: anyone holding
it can decrypt this wallet's transaction history. Store it with the same
care as customer data. Store the spending key separately, encrypted,
ideally on fewer hosts.

Save after every sync and after every send. Pending spends are persisted:
notes committed to a broadcast-but-unconfirmed transaction survive
`save()`/`load()`, so a crash between broadcast and finalize cannot
resurrect them into a double-spend — provided the state you restore was
saved after the send. After a crash, wait for the in-flight txid to
confirm or clearly disappear, sync, then resume sending. The spending key
is never persisted, as above.

The state format is versioned JSON, identical across the JS and Rust SDKs.

### Sending

Spending needs the sapling proving parameters (~50MB, one-time per
process):

```rust
pivx_wallet::load_prover_from_path("/var/lib/pivx-params").await?;  // sapling-*.params
// or: load_prover_from_url("https://pivxla.bz")  — SHA256-pinned download
// or: load_prover_from_bytes(&output, &spend)
```

Then:

```rust
use pivx_wallet::SendOptions;

let txid = wallet.send(&client, &SendOptions {
    memo: Some("payout 991".into()),          // shield recipients only, <= 512 bytes UTF-8
    ..SendOptions::shield("ps1...", 150_000_000)   // amount in sats
}).await?;
```

`send` builds and proves locally, broadcasts through the client, and
settles the pending state. On an async server prefer it: `send` runs the
multi-second proof on `tokio::task::spawn_blocking`, so it does not block the
runtime's worker threads. To broadcast yourself:

```rust
let tx = wallet.create_transaction(&opts).await?;
match client.send_raw_transaction(&tx.txhex).await {
    Ok(_) => wallet.finalize_transaction(&tx.txid),
    // Discard only on a definitive node rejection.
    Err(e @ pivx_rpc::Error::Rpc { .. }) => {
        wallet.discard_transaction(&tx.txid);
        return Err(e.into());
    }
    Err(e) => return Err(e.into()),
}
```

Discard only on `Error::Rpc` (a definitive node rejection): a transport
failure is ambiguous — the node may have accepted the transaction — so the
notes must stay pending until the txid confirms or clearly disappears, or
a retry could double-spend them.

Fee behavior to know before wiring withdrawals: the fee is size-based
(1000 sats/byte over a fixed model; a typical 1-in-2-out shield spend pays
about 0.024 PIV). When the wallet's funds cover the amount but not
amount + fee, the send is rejected (`InsufficientBalance`) rather than
silently underpaying the recipient. To empty a wallet, opt in with
`subtract_fee_from_amount: true`, which deducts the fee from the
recipient's amount instead. For exact payouts, keep fee headroom above the
requested amount.

Notes selected into a transaction are excluded from `balance()` until you
finalize or discard. Change returns to a fresh address of this wallet and
appears as a new note once the transaction confirms and is scanned.

Shielding transparent funds — spending UTXOs into a shield address — passes
transparent inputs explicitly:

```rust
Inputs::Transparent {
    utxos: vec![Utxo { txid, vout, amount, private_key, script }],
    change_address: "D...".into(),
}
```

Proving is native and takes a few seconds per transaction on server
hardware. Build with `--release`; debug-profile proving is an order of
magnitude slower. Unlike `send`, `create_transaction` proves inline and
blocks its executor thread for the duration (documented on the method); if
you call it on an async runtime, wrap it in `tokio::task::spawn_blocking`
yourself, or run it on a dedicated thread.

### Testing your integration

Unit-test against fixtures the way this repo's own tests do
(`wallet/src/tests.rs`). For end-to-end validation run a regtest node, mine
past the sapling activation height, and drive real deposits and sends;
nothing else exercises consensus acceptance of locally-built transactions.

## Transparent wallet

`pivx-wallet` also manages PIVX's transparent (non-shielded, UTXO) funds,
separately from the shield wallet. Transparent sends are plain ECDSA-signed
legacy transactions — no proving parameters. Amounts are integer satoshis,
same as the shield wallet.

### Addressing

```rust
use pivx_wallet::{decode_address, derive_key, is_valid_address, p2pkh_address, AddressKind, Network};

// BIP44 m/44'/119'/account'/change/index — change 0 = receive, 1 = internal
let key = derive_key(&seed, Network::MainNetwork, 0, 0, 0)?;
let addr = key.address();                       // "D..."  (also key.wif())

assert!(is_valid_address(&addr));
match decode_address(&addr)?.kind {
    AddressKind::P2pkh => { /* standard */ }
    AddressKind::Exchange => { /* EXM / EXT */ }
    AddressKind::Staking | AddressKind::P2sh => { /* ... */ }
}
```

### Creating and receiving

PIVX has no address index, so a transparent wallet learns about incoming
coins two ways — scan the chain, or hand it UTXOs you already know about.

```rust
use pivx_wallet::TransparentWallet;

let mut wallet = TransparentWallet::new(&seed, Network::MainNetwork, 0, 100)?;  // account 0, gap 100
let addr = wallet.new_address()?;               // fresh receive address per deposit

// (a) scan the chain
wallet.sync(&client, 4_800_000, 100).await?;    // from_height, batch_size
// or feed one decoded block (getblock <hash> 2) from your own source:
wallet.scan_block(&block)?;

// (b) or register a UTXO yourself; returns false if it isn't ours
wallet.add_utxo(&txid, vout, 200_000_000, script_pubkey);

wallet.balance();                                // sats (u64) — excludes outpoints reserved by build_send
wallet.utxos().collect::<Vec<_>>();              // all tracked outputs, reserved ones included
```

`scan_block` checks parent-hash continuity: when a block claims to extend
the last scanned one (height exactly one higher) but its
`previousblockhash` differs from the hash recorded, it returns
`WalletError::ScanDiverged` before mutating any state — the chain
reorganized under the wallet. This is why `scan_block` now returns
`Result`, a breaking change from 0.1. Recover with `reset_scan(height)`,
which drops scanned UTXOs above `height` along with their reservations
(caller-supplied UTXOs are kept) and re-sync from below the fork point:

```rust
use pivx_wallet::WalletError;

match wallet.sync(&client, 4_800_000, 100).await {
    Err(WalletError::ScanDiverged { height, .. }) => {
        wallet.reset_scan(height - 20);   // a height below the fork point
        wallet.sync(&client, 0, 100).await?;
    }
    other => other?,
}
```

### Sending

```rust
let (hex, spent) = wallet.build_send("D...recipient", 150_000_000, Some(100))?;  // 100 sats/byte
match client.send_raw_transaction(&hex).await {
    Ok(_) => wallet.mark_spent(&spent),          // finalize: inputs dropped for good
    // Release only on a definitive node rejection.
    Err(e @ pivx_rpc::Error::Rpc { .. }) => {
        wallet.release(&spent);
        return Err(e.into());
    }
    Err(e) => return Err(e.into()),
}
```

`build_send` selects UTXOs largest-first, signs locally (ECDSA), sizes the
fee from `fee_per_byte` (defaults to 100 when `None`), and sends change to a
fresh internal address. It errors if funds can't cover amount + fee rather
than underpaying. The inputs it selects are reserved: a second `build_send`
cannot double-spend them before broadcast, and `balance()` excludes them
(`utxos()` still lists them). `mark_spent(&spent)` finalizes after a
successful broadcast; `release(&spent)` un-reserves after a definitive node
rejection (`Error::Rpc`). A transport failure is ambiguous — the node may
have accepted the transaction — so keep the reservation until the txid
confirms or clearly disappears, the same rule as the shield wallet's
discard. This send path is verified against real mainnet transactions.

### Persistence

`save()` returns versioned JSON (version 1) holding the address cursors,
the UTXO set (with coinbase heights), reservations (pending spends), and
the last-scanned height and block hash — no key material.
`load(seed, state)` re-derives the keys from the seed and rejects a state
that does not match it. The output is byte-identical across the JS and
Rust SDKs — a state saved by one loads in the other (the test suites
byte-compare a shared fixture).

```rust
let json = wallet.save();
// ... crash, restart, maybe another host or the JS SDK
let mut restored = TransparentWallet::load(&seed, &json)?;
```

Reservations survive save/load, so a crash between broadcast and
`mark_spent` cannot resurrect the inputs into a double-spend — provided the
state was saved after the send. Save after every sync and every send.

### Exchange addresses

Exchange addresses (`EXM` mainnet, `EXT` testnet) encode the same hash160
as a P2PKH address behind an `OP_EXCHANGEADDR` (`0xe0`) prefix on an
otherwise standard P2PKH script, reported as `AddressKind::Exchange`. The
wallet both sends to them and receives on them.

Sending — validate and pay them like any address:

```rust
assert!(is_valid_address("EXM..."));
assert_eq!(decode_address("EXM...")?.kind, AddressKind::Exchange);
let (hex, spent) = wallet.build_send("EXM...", 150_000_000, Some(100))?;
```

Receiving — `new_exchange_address()` hands out the next external index
encoded as an exchange address. It shares the cursor and key with
`new_address()`: the same index's P2PKH form pays this wallet too, the two
encodings differ only in scriptPubKey. Deposits through the 26-byte
exchange script are credited by `scan_block` and `add_utxo` exactly like
P2PKH, and the UTXOs spend like any other:

```rust
let exm = wallet.new_exchange_address()?;   // "EXM..."
// after the deposit confirms and a sync/scan picks it up:
wallet.balance();                            // includes the exchange-script UTXO
```

This path is verified on mainnet: a deposit to an exchange address was
detected by a real block scan and the received output spent, accepted by
the network.

Sending to a cold-staking address is rejected.
