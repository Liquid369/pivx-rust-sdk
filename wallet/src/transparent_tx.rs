//! Build and sign transparent (SAPLING, v3) PIVX transactions.
//!
//! PIVX serializes a transaction as int16 nVersion, int16 nType, vin, vout,
//! nLockTime, then (only for sapling versions, nVersion >= 3) an
//! `Optional<SaplingTxData>` — confirmed in src/primitives/transaction.h. We
//! build nVersion=3, nType=0 (NORMAL) with an EMPTY sapData, so the tx carries
//! no shielded data (consensus-valid per sapling_validation.cpp) yet is signed
//! with SIGVERSION_SAPLING.
//!
//! The sapling sighash (interpreter.cpp `SignatureHash`, SIGVERSION_SAPLING)
//! COMMITS the spent input's amount into the signature: a value-misreporting
//! node invalidates the tx instead of silently turning the difference into
//! fee. This closes finding S1 (the legacy sighash omitted the amount). The
//! preimage is a personalized BLAKE2b-256 hash and — unlike legacy — the
//! 32-byte digest is signed DIRECTLY (no double-SHA256).

use secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};

use crate::error::WalletError;
use crate::transparent::{decode_address, AddressKind};

const SIGHASH_ALL: u32 = 1;

// 16-byte BLAKE2b personalizations (interpreter.cpp). Each is 15 ASCII chars +
// a trailing NUL, except the main one: "PIVXSigHash" (11) + NUL + a 4-byte LE
// consensus branch id, currently 0 (PIVX todo) → four more NULs.
const PERSO_PREVOUTS: &[u8; 16] = b"PIVXPrevoutHash\0";
const PERSO_SEQUENCE: &[u8; 16] = b"PIVXSequencHash\0";
const PERSO_OUTPUTS: &[u8; 16] = b"PIVXOutputsHash\0";
const PERSO_SIGHASH: &[u8; 16] = b"PIVXSigHash\0\0\0\0\0";

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

/// Personalized BLAKE2b-256 (16-byte personalization), as used by PIVX's
/// `CBLAKE2bWriter` for every sub-hash and the main sapling sighash.
fn blake2b_personal(perso: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(perso)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// nSequence for every input given the tx locktime. 0xffffffff marks the tx
/// final and makes the node IGNORE nLockTime (IsFinalTx); a non-zero locktime
/// therefore needs a non-final 0xfffffffe. Shared by the wire serializer and
/// the sighash so both commit the same sequence.
fn sequence_for(locktime: u32) -> u32 {
    if locktime != 0 {
        0xffff_fffe
    } else {
        0xffff_ffff
    }
}

/// The 32-byte prevout (COutPoint): txid in internal/LE byte order (the
/// reversed display txid) followed by the u32 LE vout.
fn prevout_bytes(txid: &str, vout: u32) -> Result<[u8; 36], WalletError> {
    let mut txid = hex::decode(txid).map_err(|e| WalletError::Other(e.to_string()))?;
    if txid.len() != 32 {
        return Err(WalletError::Other("txid must be 32 bytes".into()));
    }
    txid.reverse(); // prevout hash is little-endian on the wire
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(&txid);
    out[32..].copy_from_slice(&vout.to_le_bytes());
    Ok(out)
}

/// Sapling (SIGVERSION_SAPLING) sighash for input `in_index`, SIGHASH_ALL, no
/// ANYONECANPAY, empty sapData — interpreter.cpp `SignatureHash`. The returned
/// 32-byte BLAKE2b digest is the message signed DIRECTLY (no double-SHA256);
/// committing `amount` is what closes S1. `outputs` are (scriptPubKey, value).
fn sapling_sighash(
    inputs: &[TxInput],
    outputs: &[(Vec<u8>, u64)],
    locktime: u32,
    in_index: usize,
) -> Result<[u8; 32], WalletError> {
    let seq = sequence_for(locktime);

    // hashPrevouts = BLAKE2b(concat prevout over all inputs).
    let mut prevouts = Vec::with_capacity(inputs.len() * 36);
    for i in inputs {
        prevouts.extend_from_slice(&prevout_bytes(&i.txid, i.vout)?);
    }
    let hash_prevouts = blake2b_personal(PERSO_PREVOUTS, &prevouts);

    // hashSequence = BLAKE2b(concat nSequence LE over all inputs).
    let mut sequences = Vec::with_capacity(inputs.len() * 4);
    for _ in inputs {
        sequences.extend_from_slice(&seq.to_le_bytes());
    }
    let hash_sequence = blake2b_personal(PERSO_SEQUENCE, &sequences);

    // hashOutputs = BLAKE2b(concat CTxOut = value(i64 LE) || script over vout).
    let mut outs = Vec::new();
    for (script, value) in outputs {
        outs.extend_from_slice(&(*value as i64).to_le_bytes());
        write_script(&mut outs, script);
    }
    let hash_outputs = blake2b_personal(PERSO_OUTPUTS, &outs);

    let mut pre = Vec::new();
    pre.extend_from_slice(&3i16.to_le_bytes()); // nVersion = 3 (SAPLING)
    pre.extend_from_slice(&0i16.to_le_bytes()); // nType = 0 (NORMAL)
    pre.extend_from_slice(&hash_prevouts);
    pre.extend_from_slice(&hash_sequence);
    pre.extend_from_slice(&hash_outputs);
    // No sapData block: empty shielded data → hasSapData = false, so PIVX omits
    // hashShieldedSpends/Outputs and valueBalance here.
    // The input being signed: prevout || scriptCode || amount || nSequence.
    let input = &inputs[in_index];
    pre.extend_from_slice(&prevout_bytes(&input.txid, input.vout)?);
    write_script(&mut pre, &input.script_pubkey); // scriptCode = prevout scriptPubKey
    pre.extend_from_slice(&(input.amount as i64).to_le_bytes());
    pre.extend_from_slice(&seq.to_le_bytes());
    // No extraPayload: nType is NORMAL, not a special tx.
    pre.extend_from_slice(&locktime.to_le_bytes());
    pre.extend_from_slice(&SIGHASH_ALL.to_le_bytes()); // nHashType (int32 LE)

    Ok(blake2b_personal(PERSO_SIGHASH, &pre))
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

/// scriptPubKey for a destination address (P2PKH, P2SH, or exchange).
///
/// An exchange address is NOT a plain P2PKH: PIVX prefixes the P2PKH script
/// with OP_EXCHANGEADDR (0xe0) — see GetScriptForDestination / CScriptVisitor
/// in src/script/standard.cpp. Emitting a plain P2PKH would send to the wrong
/// script.
pub fn script_pubkey_for_address(address: &str) -> Result<Vec<u8>, WalletError> {
    let d = decode_address(address)?;
    Ok(match d.kind {
        AddressKind::P2pkh => {
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 push20
            s.extend_from_slice(&d.hash);
            s.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
            s
        }
        AddressKind::Exchange => {
            let mut s = Vec::with_capacity(26);
            s.push(0xe0); // OP_EXCHANGEADDR
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(&d.hash);
            s.extend_from_slice(&[0x88, 0xac]);
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
    out.extend_from_slice(&3i16.to_le_bytes()); // nVersion = 3 (SAPLING)
    out.extend_from_slice(&0i16.to_le_bytes()); // nType = 0 (NORMAL)
    write_varint(&mut out, inputs.len() as u64);
    let sequence = sequence_for(locktime);
    for (i, input) in inputs.iter().enumerate() {
        out.extend_from_slice(&prevout_bytes(&input.txid, input.vout)?);
        write_script(&mut out, &script_sigs[i]);
        out.extend_from_slice(&sequence.to_le_bytes());
    }
    write_varint(&mut out, outputs.len() as u64);
    for (script, value) in outputs {
        out.extend_from_slice(&value.to_le_bytes());
        write_script(&mut out, script);
    }
    out.extend_from_slice(&locktime.to_le_bytes());
    // sapData: Optional<SaplingTxData> = Some(empty) for a v3 transparent tx.
    // serialize.h Optional writes 0x01 (present) then SaplingTxData:
    // valueBalance(i64 LE = 0) || vShieldedSpend count(0x00) ||
    // vShieldedOutput count(0x00) || bindingSig(64 zero bytes). nType is NORMAL
    // so IsNormalType() is true and NO extraPayload follows.
    out.push(0x01);
    out.extend_from_slice(&0i64.to_le_bytes());
    out.push(0x00);
    out.push(0x00);
    out.extend_from_slice(&[0u8; 64]);
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

    let mut script_sigs: Vec<Vec<u8>> = vec![Vec::new(); inputs.len()];

    for i in 0..inputs.len() {
        // Sapling (SIGVERSION_SAPLING) SIGHASH_ALL: the BLAKE2b digest commits
        // this input's amount and is signed DIRECTLY (no double-SHA256).
        let digest = sapling_sighash(inputs, &out_scripts, locktime, i)?;

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

    let raw = serialize(inputs, &script_sigs, &out_scripts, locktime)?;
    // PIVX policy rejects any tx AT or above MAX_STANDARD_TX_SIZE (`sz >=
    // 100000`, src/policy/policy.cpp IsStandardTx), so never return one.
    // Callers estimate sizes before selecting inputs; this re-checks the
    // ACTUAL serialized size as insurance against estimator drift, and runs
    // before the wallet's build_send reserves anything (it reserves only
    // after this returns).
    if raw.len() >= 100_000 {
        return Err(WalletError::Other(
            "transaction would exceed the 100kB standard size (too many small inputs); consolidate UTXOs first".into(),
        ));
    }
    Ok(hex::encode(raw))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::transparent::derive_key;
    use pivx_primitives::consensus::Network::{MainNetwork, TestNetwork};

    /// Empty v3 sapData trailer (hex): Optional present (0x01) || valueBalance
    /// (8) || spend count (1) || output count (1) || bindingSig (64) — 75 bytes.
    fn sapdata_hex() -> String {
        format!("01{}", "00".repeat(74))
    }

    #[test]
    fn p2pkh_script_shape() {
        let k = derive_key(&[1u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let s = script_pubkey_for_address(&k.address()).unwrap();
        assert_eq!(s.len(), 25);
        assert_eq!(&s[..3], &[0x76, 0xa9, 0x14]);
        assert_eq!(&s[23..], &[0x88, 0xac]);
    }

    #[test]
    fn exchange_script_has_op_exchangeaddr_prefix() {
        // Exchange output = OP_EXCHANGEADDR (0xe0) + P2PKH.
        let addr =
            crate::transparent::encode_address(&[0x11; 20], MainNetwork, AddressKind::Exchange);
        let s = script_pubkey_for_address(&addr).unwrap();
        assert_eq!(s.len(), 26);
        assert_eq!(&s[..4], &[0xe0, 0x76, 0xa9, 0x14]);
        assert_eq!(&s[24..], &[0x88, 0xac]);
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
        assert!(tx.starts_with("03000000")); // nVersion=3 (SAPLING), nType=0
        assert!(tx.ends_with(&sapdata_hex())); // empty sapData trailer
                                               // nLockTime (0) sits just before the 150-hex sapData trailer.
        assert!(tx.ends_with(&format!("00000000{}", sapdata_hex())));
    }

    /// nSequence of a single-input tx, parsed from the raw hex: 4 bytes
    /// version+type, 1 varint vin count, 32 txid, 4 vout, 1 varint scriptSig
    /// length, scriptSig, then the 4 sequence bytes.
    fn first_input_sequence(tx: &str) -> String {
        let script_len = usize::from_str_radix(&tx[82..84], 16).unwrap();
        tx[84 + script_len * 2..84 + script_len * 2 + 8].to_string()
    }

    /// nLockTime hex: the 4 bytes immediately before the fixed 150-hex sapData
    /// trailer (locktime is no longer at the very end in v3).
    fn locktime_hex(tx: &str) -> String {
        let end = tx.len() - 150;
        tx[end - 8..end].to_string()
    }

    /// C11: a non-zero locktime needs a non-final nSequence (0xfffffffe) or
    /// the node ignores nLockTime entirely (IsFinalTx).
    #[test]
    fn locktime_sets_nonfinal_sequence() {
        let k = derive_key(&[2u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let dest = derive_key(&[3u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let build = |locktime: u32| {
            build_transparent_tx(
                &[TxInput {
                    txid: "ab".repeat(32),
                    vout: 0,
                    amount: 100_000_000,
                    script_pubkey: script_pubkey_for_address(&k.address()).unwrap(),
                    secret_key: k.secret_key,
                }],
                &[TxOutput {
                    address: dest.address(),
                    amount: 99_000_000,
                }],
                locktime,
            )
            .unwrap()
        };
        let with_lock = build(500_000);
        assert_eq!(locktime_hex(&with_lock), "20a10700"); // nLockTime = 500000 LE
        assert_eq!(first_input_sequence(&with_lock), "feffffff"); // non-final
        let without = build(0);
        assert_eq!(locktime_hex(&without), "00000000");
        assert_eq!(first_input_sequence(&without), "ffffffff"); // final
    }

    /// S1: the sapling sighash COMMITS the input amount — signing the same tx
    /// with a different input value yields a different signature (and a
    /// different serialized tx). The whole point of the v3 migration.
    #[test]
    fn amount_commitment_changes_signature() {
        let k = derive_key(&[2u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let dest = derive_key(&[3u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let spk = script_pubkey_for_address(&k.address()).unwrap();
        let mk = |amount: u64| TxInput {
            txid: "ab".repeat(32),
            vout: 0,
            amount,
            script_pubkey: spk.clone(),
            secret_key: k.secret_key,
        };
        let out = vec![(
            script_pubkey_for_address(&dest.address()).unwrap(),
            50_000_000u64,
        )];

        // Same everything but the committed input amount → different digest.
        let d1 = sapling_sighash(&[mk(100_000_000)], &out, 0, 0).unwrap();
        let d2 = sapling_sighash(&[mk(90_000_000)], &out, 0, 0).unwrap();
        assert_ne!(d1, d2, "sighash must commit the input amount (S1)");

        // ...and therefore a different signed tx.
        let outs = vec![TxOutput {
            address: dest.address(),
            amount: 50_000_000,
        }];
        let tx1 = build_transparent_tx(&[mk(100_000_000)], &outs, 0).unwrap();
        let tx2 = build_transparent_tx(&[mk(90_000_000)], &outs, 0).unwrap();
        assert_ne!(tx1, tx2);
    }

    /// Deterministic cross-SDK fixture: seed=[7;32], TestNetwork, account 0,
    /// first address owns a single 1 PIV input (txid aa..aa:0); send 0.9 PIV to
    /// that same first address with fee_per_byte 100, change back to change/0.
    /// The full signed tx hex and the input's sapling sighash MUST match the JS
    /// builder and a real regtest node byte-for-byte. `build_send` builds the
    /// equivalent tx (see the wallet test `cross_sdk_v3_send_fixture`); this
    /// reconstructs the same inputs/outputs to pin the sighash too.
    #[test]
    fn cross_sdk_v3_fixture() {
        let seed = [7u8; 32];
        let k0 = derive_key(&seed, TestNetwork, 0, 0, 0).unwrap();
        let change = derive_key(&seed, TestNetwork, 0, 1, 0).unwrap();
        let spk0 = script_pubkey_for_address(&k0.address()).unwrap();
        let input = TxInput {
            txid: "aa".repeat(32),
            vout: 0,
            amount: 100_000_000,
            script_pubkey: spk0.clone(),
            secret_key: k0.secret_key,
        };
        // fee = 100 * est_size(1 in, 2 P2PKH out) = 100 * 301 = 30_100.
        let change_val = 100_000_000 - 90_000_000 - 30_100;
        let outputs = vec![
            TxOutput {
                address: k0.address(),
                amount: 90_000_000,
            },
            TxOutput {
                address: change.address(),
                amount: change_val,
            },
        ];
        let out_scripts = vec![
            (spk0.clone(), 90_000_000u64),
            (
                script_pubkey_for_address(&change.address()).unwrap(),
                change_val,
            ),
        ];
        let ins = [input];
        let sighash = sapling_sighash(&ins, &out_scripts, 0, 0).unwrap();
        let tx = build_transparent_tx(&ins, &outputs, 0).unwrap();

        assert_eq!(tx, FIXTURE_TX_HEX, "v3 fixture tx hex drifted");
        assert_eq!(
            hex::encode(sighash),
            FIXTURE_SIGHASH_HEX,
            "v3 fixture sighash drifted"
        );
    }

    /// Cross-SDK fixture, shared with `transparent_wallet::tests`. Filled from
    /// the first green run (regtest- and JS-cross-checked).
    pub(crate) const FIXTURE_TX_HEX: &str = "0300000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000006a4730440220162490515f41b79479ba519e8c8fd325783dcbf138e44d8ac4f61a3b5a09065d02201e6011a5f20e9a162d6c92e036358e08950ec1f9bdd8f2d3ea7c0b48b4eeefab0121026ba36f35dfb3979ab7610e2839bd1f25c00df98bf9087f24d55488b485910f94ffffffff02804a5d05000000001976a9141d26a055949695e1753a1fd7cc747cb6218f5bd888acec209800000000001976a914b5d35b0e79d267ab599ce7917e9ff56179b6ba2688ac00000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const FIXTURE_SIGHASH_HEX: &str =
        "203158d8ab93d7730f873a0694966d43140f8f90c310d6938ba84554e1d70692";

    /// W1 belt: PIVX policy rejects any tx at or above MAX_STANDARD_TX_SIZE
    /// (`sz >= 100000`, src/policy/policy.cpp IsStandardTx), so the builder
    /// refuses to return one — insurance against wallet-estimator drift,
    /// enforced before build_send reserves anything. 700 P2PKH inputs
    /// serialize past 100kB for ANY signature sizes (even minimal 145-byte
    /// inputs give ~101.5kB).
    #[test]
    fn refuses_tx_at_or_above_100kb() {
        let k = derive_key(&[4u8; 32], MainNetwork, 0, 0, 0).unwrap();
        let spk = script_pubkey_for_address(&k.address()).unwrap();
        let inputs: Vec<TxInput> = (0..700)
            .map(|i| TxInput {
                txid: format!("{i:064x}"),
                vout: 0,
                amount: 150_000,
                script_pubkey: spk.clone(),
                secret_key: k.secret_key,
            })
            .collect();
        let err = build_transparent_tx(
            &inputs,
            &[TxOutput {
                address: k.address(),
                amount: 1_000_000,
            }],
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("100kB standard size"), "got {err}");
    }
}
