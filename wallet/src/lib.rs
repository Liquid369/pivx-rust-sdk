//! Standalone PIVX wallet SDK: local key management, shielded
//! (SHIELD/Sapling) scanning, balances, and transaction building. A pivxd
//! node is only a chain-data source and broadcast endpoint.
//!
//! Crypto core adapted from [PIVX-Labs/pivx-shield](https://github.com/PIVX-Labs/pivx-shield)
//! (MIT), on the same librustpivx crates, with the WASM layer removed.
//!
//! ```no_run
//! use pivx_wallet::{Network, SendOptions, ShieldWallet};
//!
//! # async fn demo() -> Result<(), pivx_wallet::WalletError> {
//! // Watch-only from a viewing key (exchanges: keys never touch this host)…
//! let mut watcher = ShieldWallet::from_viewing_key("p-view…", Network::MainNetwork, 4_800_000)?;
//!
//! // …or full capability from a seed / spending key.
//! let mut wallet = ShieldWallet::from_seed(&[0u8; 32], Network::MainNetwork, 4_800_000, 0)?;
//!
//! # #[cfg(feature = "rpc")] {
//! let client = pivx_rpc::PivxClient::new("http://127.0.0.1:51473", pivx_rpc::Auth::None)?;
//! wallet.sync(&client, 100).await?;
//! pivx_wallet::load_prover().await.map_err(|e| pivx_wallet::WalletError::Other(e.to_string()))?;
//! let txid = wallet
//!     .send(&client, &SendOptions {
//!         memo: Some("hello".into()),
//!         ..SendOptions::shield("ps1…", 150_000_000)
//!     })
//!     .await?;
//! # }
//! # Ok(()) }
//! ```

mod checkpoint;
mod error;
mod keys;
mod mainnet_checkpoints;
mod prover;
mod testnet_checkpoints;
mod transaction;
mod transparent;
mod transparent_tx;
mod transparent_wallet;
mod wallet;

#[cfg(test)]
mod test_fixtures;
#[cfg(test)]
mod tests;

pub use pivx_primitives::consensus::Network;

pub use checkpoint::get_checkpoint;
pub use error::{Result, WalletError};
pub use keys::{
    coin_type, decode_extended_full_viewing_key, decode_extsk, default_address,
    encode_extended_full_viewing_key, encode_extsk, next_address, spending_key_from_seed,
};
pub use prover::{
    load_prover, load_prover_from_bytes, load_prover_from_path, load_prover_from_url,
    prover_is_loaded,
};
pub use transaction::{BuiltTransaction, SerializedNote, Utxo};
pub use transparent::{
    decode_address, derive_key, hash160, is_valid_address, p2pkh_address, AddressKind,
    DecodedAddress, TransparentKey,
};
pub use transparent_tx::{build_transparent_tx, script_pubkey_for_address, TxInput, TxOutput};
pub use transparent_wallet::{OwnedUtxo, ScannedInput, ScannedOutput, TransparentWallet};
pub use wallet::{AttributedNote, Inputs, SendOptions, ShieldWallet, WalletBlock};
