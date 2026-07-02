//! Key derivation and address encoding.
//!
//! Adapted from PIVX-Labs/pivx-shield `src/keys.rs` (MIT), with the
//! wasm-bindgen shims removed.

use pivx_client_backend::encoding::{decode_payment_address, decode_transparent_address};
use pivx_client_backend::keys::sapling as sapling_keys;
use pivx_primitives::consensus::{Network, NetworkConstants};
use pivx_primitives::legacy::TransparentAddress;
use pivx_primitives::zip32::{AccountId, DiversifierIndex};
use sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use sapling::PaymentAddress;
use zcash_keys::encoding;

use crate::error::WalletError;

/// PIVX BIP44 coin types (mainnet 119, testnet 1).
pub fn coin_type(network: Network) -> u32 {
    match network {
        Network::MainNetwork => 119,
        Network::TestNetwork => 1,
    }
}

pub enum GenericAddress {
    Shield(PaymentAddress),
    Transparent(TransparentAddress),
}

pub fn decode_generic_address(network: Network, enc_addr: &str) -> Result<GenericAddress, WalletError> {
    if enc_addr.starts_with(network.hrp_sapling_payment_address()) {
        let to_address = decode_payment_address(network.hrp_sapling_payment_address(), enc_addr)
            .map_err(|_| WalletError::InvalidAddress(enc_addr.into()))?;
        Ok(GenericAddress::Shield(to_address))
    } else {
        let to_address = decode_transparent_address(
            &network.b58_pubkey_address_prefix(),
            &network.b58_script_address_prefix(),
            enc_addr,
        )
        .map_err(|_| WalletError::InvalidAddress(enc_addr.into()))?
        .ok_or_else(|| WalletError::InvalidAddress(enc_addr.into()))?;
        Ok(GenericAddress::Transparent(to_address))
    }
}

/// Derive the ZIP32 extended spending key for `seed` (32 bytes of entropy).
pub fn spending_key_from_seed(seed: &[u8; 32], network: Network, account_index: u32) -> Result<ExtendedSpendingKey, WalletError> {
    let account = AccountId::try_from(account_index).map_err(|_| WalletError::InvalidKey("invalid account index".into()))?;
    Ok(sapling_keys::spending_key(seed, coin_type(network), account))
}

pub fn decode_extsk(enc_extsk: &str, network: Network) -> Result<ExtendedSpendingKey, WalletError> {
    encoding::decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), enc_extsk)
        .map_err(|_| WalletError::InvalidKey("cannot decode extended spending key".into()))
}

pub fn encode_extsk(extsk: &ExtendedSpendingKey, network: Network) -> String {
    encoding::encode_extended_spending_key(network.hrp_sapling_extended_spending_key(), extsk)
}

pub fn decode_extended_full_viewing_key(enc_extfvk: &str, network: Network) -> Result<ExtendedFullViewingKey, WalletError> {
    encoding::decode_extended_full_viewing_key(network.hrp_sapling_extended_full_viewing_key(), enc_extfvk)
        .map_err(|_| WalletError::InvalidKey("cannot decode extended full viewing key".into()))
}

pub fn encode_extended_full_viewing_key(extfvk: &ExtendedFullViewingKey, network: Network) -> String {
    encoding::encode_extended_full_viewing_key(network.hrp_sapling_extended_full_viewing_key(), extfvk)
}

#[allow(deprecated)]
pub fn extfvk_from_extsk(extsk: &ExtendedSpendingKey) -> ExtendedFullViewingKey {
    extsk.to_extended_full_viewing_key()
}

pub fn encode_payment_address(addr: &PaymentAddress, network: Network) -> String {
    encoding::encode_payment_address(network.hrp_sapling_payment_address(), addr)
}

/// The default (first) diversified address and its index.
pub fn default_address(extfvk: &ExtendedFullViewingKey, network: Network) -> (String, [u8; 11]) {
    let (index, address) = extfvk.to_diversifiable_full_viewing_key().default_address();
    (encode_payment_address(&address, network), *index.as_bytes())
}

/// The next valid diversified address after `diversifier_index`.
pub fn next_address(
    extfvk: &ExtendedFullViewingKey,
    diversifier_index: [u8; 11],
    network: Network,
) -> Result<(String, [u8; 11]), WalletError> {
    let mut index = DiversifierIndex::from(diversifier_index);
    index
        .increment()
        .map_err(|_| WalletError::InvalidKey("no valid diversifier indices left".into()))?;
    let (new_index, address) = extfvk
        .to_diversifiable_full_viewing_key()
        .find_address(index)
        .ok_or_else(|| WalletError::InvalidKey("no valid diversifier indices left".into()))?;
    Ok((encode_payment_address(&address, network), *new_index.as_bytes()))
}
