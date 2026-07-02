# PIVX Rust SDK

Rust SDK for the [PIVX](https://pivx.org) blockchain with first-class
shielded (SHIELD/Sapling) support.

| Crate | What it does |
|---|---|
| [`rpc/`](rpc/) — `pivx-rpc` | Typed async JSON-RPC client for `pivxd`: blockchain, wallet, full shield RPC surface, plus masternode, staking, budget, and network dev-kit methods; poll-based `ShieldWatcher`. |
| [`wallet/`](wallet/) — `pivx-wallet` | **Standalone wallet: the application owns the keys.** ZIP32 derivation, block scanning with note decryption, checkpointed sync verified against `finalsaplingroot`, locally-proved shielded transactions (native speed). Also a transparent (BIP44 HD, UTXO) wallet for non-shielded funds — block-scan or supplied-UTXO receive, ECDSA-signed legacy sends, exchange-address support. The node is only a chain-data source. |

A wallet is constructed from a seed, spending key, **or viewing key** —
watch-only is a capability level (scan/receive/balance, no spend),
upgradeable in place. Wallet state JSON is interchangeable with the
[JS SDK](https://github.com/PIVX-Project/pivx-js-sdk).

```rust
use pivx_rpc::{Auth, PivxClient};
use pivx_wallet::{Inputs, Network, SendOptions, ShieldWallet};

// exchange deposit detection: keys never on this host
let mut wallet = ShieldWallet::from_viewing_key(&vkey, Network::MainNetwork, 4_800_000)?;
wallet.sync(&client, 100).await?;
println!("{} sats", wallet.balance());

// standalone send (spending key + prover)
pivx_wallet::load_prover().await?;
let txid = wallet.send(&client, &SendOptions {
    to: "ps1…".into(), amount: 150_000_000, memo: Some("hi".into()), inputs: Inputs::Shield,
}).await?;
```

Examples: [`wallet/examples/`](wallet/examples/) (deposit watcher,
standalone send), [`rpc/examples/`](rpc/examples/) (node-wallet flows).

The wallet crypto core is adapted from
[PIVX-Labs/pivx-shield](https://github.com/PIVX-Labs/pivx-shield) (MIT) on
the [librustpivx](https://github.com/Duddino/librustpivx) crates. Those are
git dependencies, so install `pivx-wallet` via git until librustpivx lands
on crates.io. **Do not delete `Cargo.lock`** — it pins `core2 0.3.x`, which
is yanked upstream.

Full usage guide: [docs/usage.md](docs/usage.md).
Feature list: [docs/FEATURES.md](docs/FEATURES.md). Deployment + safety: [docs/deployment.md](docs/deployment.md), [SECURITY.md](SECURITY.md).

## Develop

```
cargo test
```

Tests decrypt a real regtest transaction natively and reproduce an exact
expected nullifier — no crypto mocks (the tx-builder tests use the upstream
MockProver pattern for speed). Units: `pivx-rpc` uses PIV floats (as the
node emits); `pivx-wallet` uses integer satoshis.
