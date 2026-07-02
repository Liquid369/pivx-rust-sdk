//! Transparent wallet: HD address management, UTXO tracking (from a block
//! scan or caller-supplied), coin selection, and sending. Complements the
//! shielded [`ShieldWallet`](crate::ShieldWallet); both derive from the seed.
//!
//! PIVX has no address index, so UTXOs are discovered either by scanning
//! blocks ([`scan`](TransparentWallet::scan)) or supplied by the caller
//! ([`add_utxo`](TransparentWallet::add_utxo)).

use std::collections::HashMap;

use pivx_primitives::consensus::Network;
use secp256k1::SecretKey;

use crate::error::WalletError;
use crate::transparent::{decode_address, derive_key, hash160, AddressKind};
use crate::transparent_tx::{build_transparent_tx, TxInput, TxOutput};

/// A tracked unspent transparent output we can spend.
#[derive(Clone)]
pub struct OwnedUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    /// hash160 of the key that controls it (index into the key map).
    pub key_hash: [u8; 20],
}

/// A confirmed transparent output as seen in a scanned transaction.
pub struct ScannedOutput {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

/// A spent transparent input as seen in a scanned transaction.
pub struct ScannedInput {
    pub txid: String,
    pub vout: u32,
}

pub struct TransparentWallet {
    network: Network,
    /// hash160 → secret key, for our derived addresses (external + change).
    keys: HashMap<[u8; 20], SecretKey>,
    /// Ordered external receive addresses (for new_address / display).
    external: Vec<([u8; 20], String)>,
    next_external: usize,
    change: Vec<[u8; 20]>,
    next_change: usize,
    utxos: HashMap<(String, u32), OwnedUtxo>,
}

impl TransparentWallet {
    /// Derive `gap` external and `gap` change addresses from `seed` under
    /// account `account`. Only outputs to these addresses are recognized, so
    /// `gap` bounds how many unused addresses ahead are watched.
    pub fn new(seed: &[u8], network: Network, account: u32, gap: u32) -> Result<Self, WalletError> {
        let mut keys = HashMap::new();
        let mut external = Vec::new();
        let mut change = Vec::new();
        for i in 0..gap {
            let ext = derive_key(seed, network, account, 0, i)?;
            let eh = hash160(&ext.public_key.serialize());
            external.push((eh, ext.address()));
            keys.insert(eh, ext.secret_key);
            let ch = derive_key(seed, network, account, 1, i)?;
            let chh = hash160(&ch.public_key.serialize());
            change.push(chh);
            keys.insert(chh, ch.secret_key);
        }
        Ok(Self {
            network,
            keys,
            external,
            next_external: 0,
            change,
            next_change: 0,
            utxos: HashMap::new(),
        })
    }

    /// Next unused external receive address.
    pub fn new_address(&mut self) -> Result<String, WalletError> {
        let (_, addr) = self
            .external
            .get(self.next_external)
            .ok_or_else(|| WalletError::Other("address gap limit reached; increase gap".into()))?;
        let addr = addr.clone();
        self.next_external += 1;
        Ok(addr)
    }

    fn next_change_hash(&mut self) -> Result<[u8; 20], WalletError> {
        let h = *self
            .change
            .get(self.next_change)
            .ok_or_else(|| WalletError::Other("change gap limit reached; increase gap".into()))?;
        self.next_change += 1;
        Ok(h)
    }

    /// hash160 of a standard P2PKH scriptPubKey (76a914<20>88ac), if it is one.
    fn p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
        if script.len() == 25
            && script[0] == 0x76
            && script[1] == 0xa9
            && script[2] == 0x14
            && script[23] == 0x88
            && script[24] == 0xac
        {
            let mut h = [0u8; 20];
            h.copy_from_slice(&script[3..23]);
            Some(h)
        } else {
            None
        }
    }

    /// Add a caller-supplied UTXO if it pays one of our addresses.
    pub fn add_utxo(&mut self, txid: &str, vout: u32, amount: u64, script_pubkey: Vec<u8>) -> bool {
        match Self::p2pkh_hash(&script_pubkey) {
            Some(h) if self.keys.contains_key(&h) => {
                self.utxos.insert(
                    (txid.to_string(), vout),
                    OwnedUtxo {
                        txid: txid.to_string(),
                        vout,
                        amount,
                        script_pubkey,
                        key_hash: h,
                    },
                );
                true
            }
            _ => false,
        }
    }

    /// Apply a scanned block's transparent outputs (added if ours) and spent
    /// inputs (removed). Feed these from a decoded block (getblock verbosity 2).
    pub fn scan(&mut self, outputs: &[ScannedOutput], spent: &[ScannedInput]) {
        for o in outputs {
            self.add_utxo(&o.txid, o.vout, o.amount, o.script_pubkey.clone());
        }
        for s in spent {
            self.utxos.remove(&(s.txid.clone(), s.vout));
        }
    }

    /// Total tracked transparent balance in satoshis.
    pub fn balance(&self) -> u64 {
        self.utxos
            .values()
            .map(|u| u.amount)
            .fold(0u64, |a, v| a.saturating_add(v))
    }

    pub fn utxos(&self) -> impl Iterator<Item = &OwnedUtxo> {
        self.utxos.values()
    }

    /// Estimated size (bytes) of a P2PKH tx with the given input/output counts.
    fn est_size(n_in: usize, n_out: usize) -> u64 {
        (n_in as u64) * 148 + (n_out as u64) * 34 + 10
    }

    /// Build and sign a transparent send of `amount` sats to `to`, selecting
    /// UTXOs largest-first and returning change to a fresh change address.
    /// `fee_per_byte` defaults to 100 sats/byte if None (well above relay).
    /// Returns the raw tx hex and the txids/vouts of the inputs it spends.
    pub fn build_send(
        &mut self,
        to: &str,
        amount: u64,
        fee_per_byte: Option<u64>,
    ) -> Result<(String, Vec<(String, u32)>), WalletError> {
        if amount == 0 {
            return Err(WalletError::Other(
                "amount must be greater than zero".into(),
            ));
        }
        // Reject cold-staking / unsupported destinations early.
        if matches!(decode_address(to)?.kind, AddressKind::Staking) {
            return Err(WalletError::Other(
                "sending to a cold-staking address is not supported".into(),
            ));
        }
        let feerate = fee_per_byte.unwrap_or(100);

        let mut avail: Vec<&OwnedUtxo> = self.utxos.values().collect();
        avail.sort_by(|a, b| b.amount.cmp(&a.amount)); // largest first

        let mut selected: Vec<OwnedUtxo> = Vec::new();
        let mut total: u64 = 0;
        for u in avail {
            selected.push(u.clone());
            total = total.saturating_add(u.amount);
            let fee = feerate * Self::est_size(selected.len(), 2);
            if total >= amount.saturating_add(fee) {
                break;
            }
        }
        let fee = feerate * Self::est_size(selected.len(), 2);
        if total < amount.saturating_add(fee) {
            return Err(WalletError::InsufficientBalance);
        }
        let change_val = total - amount - fee;

        let mut outputs = vec![TxOutput {
            address: to.to_string(),
            amount,
        }];
        // Add change only if it is worth more than the extra input it would
        // later cost to spend (dust threshold ~ one input's fee).
        if change_val > feerate * 148 {
            let ch_hash = self.next_change_hash()?;
            let ch_addr =
                crate::transparent::encode_address(&ch_hash, self.network, AddressKind::P2pkh);
            outputs.push(TxOutput {
                address: ch_addr,
                amount: change_val,
            });
        }

        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                txid: u.txid.clone(),
                vout: u.vout,
                amount: u.amount,
                script_pubkey: u.script_pubkey.clone(),
                secret_key: *self
                    .keys
                    .get(&u.key_hash)
                    .expect("selected utxo has a known key"),
            })
            .collect();
        let spent: Vec<(String, u32)> = selected.iter().map(|u| (u.txid.clone(), u.vout)).collect();
        let hex = build_transparent_tx(&inputs, &outputs, 0)?;
        Ok((hex, spent))
    }

    /// Mark inputs spent after a successful broadcast.
    pub fn mark_spent(&mut self, spent: &[(String, u32)]) {
        for key in spent {
            self.utxos.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::p2pkh_address;
    use crate::transparent_tx::script_pubkey_for_address;
    use pivx_primitives::consensus::Network::MainNetwork;

    fn spk(addr: &str) -> Vec<u8> {
        script_pubkey_for_address(addr).unwrap()
    }

    #[test]
    fn tracks_and_selects_utxos() {
        let seed = [3u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 20).unwrap();
        // Our first external address' scriptPubKey.
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        let s0 = spk(&p2pkh_address(&a0.public_key, MainNetwork));
        assert!(w.add_utxo("aa".repeat(32).as_str(), 0, 200_000_000, s0.clone()));
        // A UTXO not ours is ignored.
        let other = derive_key(&[9u8; 32], MainNetwork, 0, 0, 0).unwrap();
        assert!(!w.add_utxo(
            "bb".repeat(32).as_str(),
            0,
            5,
            spk(&p2pkh_address(&other.public_key, MainNetwork))
        ));
        assert_eq!(w.balance(), 200_000_000);

        // Send half; expect a valid tx and one input selected.
        let dest = p2pkh_address(&other.public_key, MainNetwork);
        let (hex, spent) = w.build_send(&dest, 100_000_000, Some(100)).unwrap();
        assert!(hex.starts_with("01000000"));
        assert_eq!(spent.len(), 1);
        w.mark_spent(&spent);
        assert_eq!(w.balance(), 0);
    }

    #[test]
    fn insufficient_balance_errs() {
        let seed = [4u8; 32];
        let mut w = TransparentWallet::new(&seed, MainNetwork, 0, 5).unwrap();
        let a0 = derive_key(&seed, MainNetwork, 0, 0, 0).unwrap();
        w.add_utxo(
            "cc".repeat(32).as_str(),
            0,
            1000,
            spk(&p2pkh_address(&a0.public_key, MainNetwork)),
        );
        let dest = p2pkh_address(&a0.public_key, MainNetwork);
        assert!(matches!(
            w.build_send(&dest, 100_000_000, Some(100)),
            Err(WalletError::InsufficientBalance)
        ));
    }
}
