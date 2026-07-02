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

Typed methods now reach the masternode, deterministic-masternode (`protx`),
budget, staking, and network/mempool/mining/util surface as well. Anything
still not wrapped goes through `call`, with positional params exactly as
`pivx-cli` would take them:

```rust
let tips: serde_json::Value = client.call("getchaintips", vec![]).await?;
```

Node errors surface as `Error::Rpc { code, message, .. }` with the node's
own code; transport failures are `Error::Transport`, so retry logic can
tell them apart:

```rust
match client.shield_send_many(FromAddress::AnyShield, &recipients).await {
    Err(Error::Rpc { code: -13, .. }) => { /* wallet locked */ }
    other => { /* ... */ }
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
way across tasks: one wallet, one writer.

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
settles the pending state. To broadcast yourself:

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
magnitude slower.

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
wallet.scan_block(&block);

// (b) or register a UTXO yourself; returns false if it isn't ours
wallet.add_utxo(&txid, vout, 200_000_000, script_pubkey);

wallet.balance();                                // sats (u64)
wallet.utxos().collect::<Vec<_>>();              // tracked unspent outputs
```

### Sending

```rust
let (hex, spent) = wallet.build_send("D...recipient", 150_000_000, Some(100))?;  // 100 sats/byte
client.send_raw_transaction(&hex).await?;
wallet.mark_spent(&spent);                       // only after a successful broadcast
```

`build_send` selects UTXOs largest-first, signs locally (ECDSA), sizes the
fee from `fee_per_byte` (defaults to 100 when `None`), and sends change to a
fresh internal address. It errors if funds can't cover amount + fee rather
than underpaying. Call `mark_spent(&spent)` only once the broadcast succeeds
— until then the UTXOs stay spendable, so a failed broadcast can be retried.
This send path is verified against real mainnet transactions.

### Exchange addresses

Exchange addresses (`EXM` mainnet, `EXT` testnet) are a receive-only
transparent variant, reported as `AddressKind::Exchange`. Validate them and
send to them like any address; the output carries an `OP_EXCHANGEADDR` prefix
on an otherwise standard P2PKH script.

```rust
assert!(is_valid_address("EXM..."));
assert_eq!(decode_address("EXM...")?.kind, AddressKind::Exchange);
let (hex, spent) = wallet.build_send("EXM...", 150_000_000, Some(100))?;
```

Sending to a cold-staking address is rejected.
