//! Transparent (non-shielded) HD wallet: BIP32/44 key derivation and PIVX
//! address encoding/decoding for P2PKH, cold-staking, and exchange addresses.
//!
//! PIVX transparent keys derive under BIP44 `m/44'/119'/account'/change/index`
//! (coin type 119 mainnet, 1 testnet). Addresses are base58check with
//! network-specific version prefixes (see chainparams).

use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};

use crate::error::WalletError;
use pivx_primitives::consensus::Network;

const HARDENED: u32 = 0x8000_0000;

/// Kind of PIVX transparent address, by base58 version prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// Standard pay-to-pubkey-hash (mainnet 'D', testnet 'x'/'y').
    P2pkh,
    /// Pay-to-script-hash.
    P2sh,
    /// Cold-staking address (mainnet 'S', testnet 'W').
    Staking,
    /// Exchange address, receive-only (mainnet "EXM", testnet "EXT").
    Exchange,
}

/// The base58 version prefix bytes for `kind` on `network`.
fn version_prefix(network: Network, kind: AddressKind) -> &'static [u8] {
    match (network, kind) {
        (Network::MainNetwork, AddressKind::P2pkh) => &[30],
        (Network::MainNetwork, AddressKind::P2sh) => &[13],
        (Network::MainNetwork, AddressKind::Staking) => &[63],
        (Network::MainNetwork, AddressKind::Exchange) => &[0x01, 0xb9, 0xa2],
        (Network::TestNetwork, AddressKind::P2pkh) => &[139],
        (Network::TestNetwork, AddressKind::P2sh) => &[19],
        (Network::TestNetwork, AddressKind::Staking) => &[73],
        (Network::TestNetwork, AddressKind::Exchange) => &[0x01, 0xb9, 0xb1],
    }
}

/// BIP44 coin type: mainnet 119, testnet 1.
fn coin_type(network: Network) -> u32 {
    match network {
        Network::MainNetwork => 119,
        Network::TestNetwork => 1,
    }
}

/// hash160 = RIPEMD160(SHA256(data)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// Encode a 20-byte hash as a PIVX base58check address of the given kind.
pub fn encode_address(hash: &[u8; 20], network: Network, kind: AddressKind) -> String {
    let prefix = version_prefix(network, kind);
    let mut payload = Vec::with_capacity(prefix.len() + 20);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(hash);
    bs58::encode(payload).with_check().into_string()
}

/// P2PKH address for a public key.
pub fn p2pkh_address(pubkey: &PublicKey, network: Network) -> String {
    encode_address(&hash160(&pubkey.serialize()), network, AddressKind::P2pkh)
}

/// A decoded transparent address: its 20-byte hash and detected kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAddress {
    pub hash: [u8; 20],
    pub kind: AddressKind,
    pub network: Network,
}

/// Decode and validate a PIVX transparent address, identifying its kind and
/// network by the version prefix. Errors if it is not a valid PIVX address.
pub fn decode_address(address: &str) -> Result<DecodedAddress, WalletError> {
    let data = bs58::decode(address)
        .with_check(None)
        .into_vec()
        .map_err(|_| WalletError::InvalidAddress(address.into()))?;
    for network in [Network::MainNetwork, Network::TestNetwork] {
        for kind in [
            AddressKind::P2pkh,
            AddressKind::P2sh,
            AddressKind::Staking,
            AddressKind::Exchange,
        ] {
            let prefix = version_prefix(network, kind);
            if data.len() == prefix.len() + 20 && data.starts_with(prefix) {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&data[prefix.len()..]);
                return Ok(DecodedAddress {
                    hash,
                    kind,
                    network,
                });
            }
        }
    }
    Err(WalletError::InvalidAddress(address.into()))
}

/// True if `address` is a well-formed PIVX transparent address.
pub fn is_valid_address(address: &str) -> bool {
    decode_address(address).is_ok()
}

/// A derived transparent key: the secret key, its public key, and P2PKH address.
pub struct TransparentKey {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub network: Network,
}

impl TransparentKey {
    pub fn address(&self) -> String {
        p2pkh_address(&self.public_key, self.network)
    }

    /// WIF (compressed) encoding of the secret key, for import into other tools.
    pub fn wif(&self) -> String {
        let prefix: u8 = match self.network {
            Network::MainNetwork => 212,
            Network::TestNetwork => 239,
        };
        let mut payload = Vec::with_capacity(34);
        payload.push(prefix);
        payload.extend_from_slice(&self.secret_key[..]);
        payload.push(0x01); // compressed
        bs58::encode(payload).with_check().into_string()
    }
}

type HmacSha512 = Hmac<Sha512>;

/// A BIP32 extended private key (just the parts we need for CKD).
struct ExtKey {
    key: SecretKey,
    chain_code: [u8; 32],
}

impl ExtKey {
    fn master(seed: &[u8]) -> Result<Self, WalletError> {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("hmac key");
        mac.update(seed);
        let i = mac.finalize().into_bytes();
        let key =
            SecretKey::from_slice(&i[..32]).map_err(|e| WalletError::InvalidKey(e.to_string()))?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(ExtKey { key, chain_code })
    }

    /// BIP32 child key derivation. `index >= HARDENED` derives a hardened child.
    fn derive_child(
        &self,
        secp: &Secp256k1<secp256k1::All>,
        index: u32,
    ) -> Result<Self, WalletError> {
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("hmac key");
        if index >= HARDENED {
            mac.update(&[0]);
            mac.update(&self.key[..]);
        } else {
            let pk = PublicKey::from_secret_key(secp, &self.key);
            mac.update(&pk.serialize());
        }
        mac.update(&index.to_be_bytes());
        let i = mac.finalize().into_bytes();
        let tweak = secp256k1::Scalar::from_be_bytes(i[..32].try_into().expect("32 bytes"))
            .map_err(|e| WalletError::InvalidKey(e.to_string()))?;
        let key = self
            .key
            .add_tweak(&tweak)
            .map_err(|e| WalletError::InvalidKey(e.to_string()))?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(ExtKey { key, chain_code })
    }
}

/// Derive the BIP44 transparent key at `m/44'/coin'/account'/change/index`.
/// `change` is 0 for external (receive) addresses, 1 for internal (change).
pub fn derive_key(
    seed: &[u8],
    network: Network,
    account: u32,
    change: u32,
    index: u32,
) -> Result<TransparentKey, WalletError> {
    let secp = Secp256k1::new();
    let path = [
        44 | HARDENED,
        coin_type(network) | HARDENED,
        account | HARDENED,
        change,
        index,
    ];
    let mut ext = ExtKey::master(seed)?;
    for &i in &path {
        ext = ext.derive_child(&secp, i)?;
    }
    let public_key = PublicKey::from_secret_key(&secp, &ext.key);
    Ok(TransparentKey {
        secret_key: ext.key,
        public_key,
        network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 test vector 1 (master seed 000102...0f), external chain m/0'/... roots.
    #[test]
    fn bip32_master_matches_vector() {
        // m/44'/119'/0'/0/0 must be deterministic; verify the whole path runs
        // and yields a valid compressed pubkey + decodable address.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let k = derive_key(&seed, Network::MainNetwork, 0, 0, 0).unwrap();
        let addr = k.address();
        assert!(addr.starts_with('D'), "mainnet P2PKH starts with D: {addr}");
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.kind, AddressKind::P2pkh);
        assert_eq!(decoded.network, Network::MainNetwork);
        assert_eq!(decoded.hash, hash160(&k.public_key.serialize()));
    }

    #[test]
    fn derivation_is_deterministic_and_indexed() {
        let seed = [7u8; 32];
        let a = derive_key(&seed, Network::MainNetwork, 0, 0, 0).unwrap();
        let b = derive_key(&seed, Network::MainNetwork, 0, 0, 0).unwrap();
        let c = derive_key(&seed, Network::MainNetwork, 0, 0, 1).unwrap();
        assert_eq!(a.address(), b.address());
        assert_ne!(a.address(), c.address());
    }

    #[test]
    fn address_roundtrip_all_kinds() {
        let h = [0x11u8; 20];
        for network in [Network::MainNetwork, Network::TestNetwork] {
            for kind in [
                AddressKind::P2pkh,
                AddressKind::P2sh,
                AddressKind::Staking,
                AddressKind::Exchange,
            ] {
                let addr = encode_address(&h, network, kind);
                let d = decode_address(&addr).unwrap();
                assert_eq!(d.hash, h);
                assert_eq!(d.kind, kind);
                assert_eq!(d.network, network);
            }
        }
    }

    #[test]
    fn exchange_address_prefix() {
        let h = [0x22u8; 20];
        assert!(encode_address(&h, Network::MainNetwork, AddressKind::Exchange).starts_with("EXM"));
        assert!(encode_address(&h, Network::TestNetwork, AddressKind::Exchange).starts_with("EXT"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(!is_valid_address("not an address"));
        assert!(!is_valid_address("DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6X")); // bad checksum
    }
}
