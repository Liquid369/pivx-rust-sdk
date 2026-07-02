# pivx-wallet

Standalone [PIVX](https://pivx.org) wallet SDK: local key management (seed,
spending key, or watch-only viewing key), shielded (SHIELD/Sapling) block
scanning with checkpointed sync, balances, and locally-proved transaction
building — plus a transparent (BIP44 HD, UTXO) wallet. A `pivxd` node is
only a chain-data source and broadcast endpoint.

Part of the [PIVX Rust SDK](https://github.com/Liquid369/pivx-rust-sdk).
Crypto core adapted from [PIVX-Labs/pivx-shield](https://github.com/PIVX-Labs/pivx-shield) (MIT).

## Install

The crypto core depends on the [librustpivx](https://github.com/Duddino/librustpivx)
crates, which are git dependencies — so install `pivx-wallet` via git until
librustpivx lands on crates.io:

```toml
[dependencies]
pivx-wallet = { git = "https://github.com/Liquid369/pivx-rust-sdk" }
```

**Do not delete `Cargo.lock`** — it pins `core2 0.3.x`, which is yanked upstream.

## Usage

```rust,no_run
use pivx_wallet::{Network, SendOptions, ShieldWallet};

# async fn demo() -> Result<(), pivx_wallet::WalletError> {
// Watch-only from a viewing key (exchanges: keys never touch this host)…
let mut watcher = ShieldWallet::from_viewing_key("p-view…", Network::MainNetwork, 4_800_000)?;

// …or full capability from a seed / spending key.
let mut wallet = ShieldWallet::from_seed(&[0u8; 32], Network::MainNetwork, 4_800_000, 0)?;

let client = pivx_rpc::PivxClient::new("http://127.0.0.1:51473", pivx_rpc::Auth::None)?;
wallet.sync(&client, 100).await?;
pivx_wallet::load_prover().await.map_err(|e| pivx_wallet::WalletError::Other(e.to_string()))?;
let txid = wallet
    .send(&client, &SendOptions {
        memo: Some("hello".into()),
        ..SendOptions::shield("ps1…", 150_000_000)
    })
    .await?;
# Ok(()) }
```

License: MIT.
