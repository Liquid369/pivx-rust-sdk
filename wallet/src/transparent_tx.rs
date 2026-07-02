//! Build and sign transparent (LEGACY, v1) PIVX transactions.
//!
//! PIVX serializes a transaction as int16 nVersion, int16 nType, vin, vout,
//! nLockTime, then (only for sapling versions) sapData — confirmed in
//! src/primitives/transaction.h. For a legacy transparent tx (nVersion=1,
//! nType=0) the leading four bytes are `01 00 00 00` and there is no sapData,
//! so the wire format is a standard Bitcoin v1 transaction. Signing is legacy
//! P2PKH SIGHASH_ALL.

use secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::error::WalletError;
use crate::transparent::{decode_address, AddressKind};

const SIGHASH_ALL: u32 = 1;

/// A transparent input to spend.
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    /// scriptPubKey of the output being spent (as from listunspent).
    pub script_pubkey: Vec<u8>,
    pub secret_key: SecretKey,
}

/// A transparent output to create.
pub struct TxOutput {
    pub address: String,
    pub amount: u64,
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let h = Sha256::digest(Sha256::digest(data));
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn write_script(out: &mut Vec<u8>, script: &[u8]) {
    write_varint(out, script.len() as u64);
    out.extend_from_slice(script);
}

/// scriptPubKey for a destination address. Supports the spendable transparent
/// output types (P2PKH, P2SH, exchange). Exchange addresses pay to the same
/// P2PKH script as a normal key hash — the address encoding differs, the
/// output script does not.
pub fn script_pubkey_for_address(address: &str) -> Result<Vec<u8>, WalletError> {
    let d = decode_address(address)?;
    Ok(match d.kind {
        AddressKind::P2pkh | AddressKind::Exchange => {
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 push20
            s.extend_from_slice(&d.hash);
            s.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
            s
        }
        AddressKind::P2sh => {
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]); // OP_HASH160 push20
            s.extend_from_slice(&d.hash);
            s.push(0x87); // OP_EQUAL
            s
        }
        AddressKind::Staking => {
            return Err(WalletError::Other(
                "sending to a cold-staking address is not supported".into(),
            ))
        }
    })
}

/// Serialize the tx. `script_sigs[i]` is the scriptSig for input i (empty when
/// building the unsigned preimage for another input).
fn serialize(
    inputs: &[TxInput],
    script_sigs: &[Vec<u8>],
    outputs: &[(Vec<u8>, u64)],
    locktime: u32,
) -> Result<Vec<u8>, WalletError> {
    let mut out = Vec::new();
    out.extend_from_slice(&1i16.to_le_bytes()); // nVersion = 1 (LEGACY)
    out.extend_from_slice(&0i16.to_le_bytes()); // nType = 0 (NORMAL)
    write_varint(&mut out, inputs.len() as u64);
    for (i, input) in inputs.iter().enumerate() {
        let mut txid = hex::decode(&input.txid).map_err(|e| WalletError::Other(e.to_string()))?;
        if txid.len() != 32 {
            return Err(WalletError::Other("txid must be 32 bytes".into()));
        }
        txid.reverse(); // prevout hash is little-endian on the wire
        out.extend_from_slice(&txid);
        out.extend_from_slice(&input.vout.to_le_bytes());
        write_script(&mut out, &script_sigs[i]);
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // nSequence
    }
    write_varint(&mut out, outputs.len() as u64);
    for (script, value) in outputs {
        out.extend_from_slice(&value.to_le_bytes());
        write_script(&mut out, script);
    }
    out.extend_from_slice(&locktime.to_le_bytes());
    Ok(out)
}

/// Build and sign a transparent transaction. Returns the raw tx hex ready for
/// `sendrawtransaction`. The caller selects inputs and includes any change as
/// an explicit output; this does no coin selection or fee computation.
pub fn build_transparent_tx(
    inputs: &[TxInput],
    outputs: &[TxOutput],
    locktime: u32,
) -> Result<String, WalletError> {
    if inputs.is_empty() {
        return Err(WalletError::Other("transaction has no inputs".into()));
    }
    let secp = Secp256k1::new();
    let out_scripts: Vec<(Vec<u8>, u64)> = outputs
        .iter()
        .map(|o| Ok((script_pubkey_for_address(&o.address)?, o.amount)))
        .collect::<Result<_, WalletError>>()?;

    let empty: Vec<Vec<u8>> = vec![Vec::new(); inputs.len()];
    let mut script_sigs = empty.clone();

    for i in 0..inputs.len() {
        // Legacy SIGHASH_ALL preimage: this input's scriptSig = its prevout
        // scriptPubKey, all others empty; append the 4-byte sighash type.
        let mut preimage_sigs = empty.clone();
        preimage_sigs[i] = inputs[i].script_pubkey.clone();
        let mut preimage = serialize(inputs, &preimage_sigs, &out_scripts, locktime)?;
        preimage.extend_from_slice(&SIGHASH_ALL.to_le_bytes());
        let digest = double_sha256(&preimage);

        let sig: Signature = secp.sign_ecdsa(&Message::from_digest(digest), &inputs[i].secret_key);
        let sig = sig.serialize_der();
        let pubkey = inputs[i].secret_key.public_key(&secp).serialize();

        // scriptSig = push(DER sig ++ sighash byte) push(compressed pubkey)
        let mut script_sig = Vec::with_capacity(sig.len() + pubkey.len() + 3);
        script_sig.push((sig.len() + 1) as u8);
        script_sig.extend_from_slice(&sig);
        script_sig.push(SIGHASH_ALL as u8);
        script_sig.push(pubkey.len() as u8);
        script_sig.extend_from_slice(&pubkey);
        script_sigs[i] = script_sig;
    }

    Ok(hex::encode(serialize(
        inputs,
        &script_sigs,
        &out_scripts,
        locktime,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent::derive_key;
    use pivx_primitives::consensus::Network::MainNetwork;

    #[test]
    fn p2pkh_script_shape() {
        let k = derive_key(&[1u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let s = script_pubkey_for_address(&k.address()).unwrap();
        assert_eq!(s.len(), 25);
        assert_eq!(&s[..3], &[0x76, 0xa9, 0x14]);
        assert_eq!(&s[23..], &[0x88, 0xac]);
    }

    #[test]
    fn builds_and_is_deterministic_in_structure() {
        let k = derive_key(&[2u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let input = TxInput {
            txid: "a".repeat(64),
            vout: 0,
            amount: 100_000_000,
            script_pubkey: script_pubkey_for_address(&k.address()).unwrap(),
            secret_key: k.secret_key,
        };
        let dest = derive_key(&[3u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let tx = build_transparent_tx(
            &[input],
            &[TxOutput {
                address: dest.address(),
                amount: 99_000_000,
            }],
            0,
        )
        .unwrap();
        assert!(tx.starts_with("01000000")); // nVersion=1, nType=0
        assert!(tx.ends_with("00000000")); // nLockTime = 0
        assert!(!tx.is_empty());
    }
}
