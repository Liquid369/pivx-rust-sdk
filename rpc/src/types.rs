//! Response types matching pivxd's JSON output.
//!
//! Amounts are `f64` in PIV (8 decimal places), exactly as the node emits
//! them — the same convention as every *-core RPC library.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Unspent shielded note, as returned by `listshieldunspent`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ShieldNote {
    pub txid: String,
    pub outindex: u32,
    pub confirmations: i64,
    /// True if the wallet holds the spending key (false for watch-only viewing keys).
    pub spendable: bool,
    pub address: String,
    pub amount: f64,
    /// Hex-encoded memo, trailing zero bytes trimmed.
    #[serde(default)]
    pub memo: String,
    /// Present when the wallet can determine change status.
    pub change: Option<bool>,
    pub nullifier: Option<String>,
}

/// Received note, as returned by `listreceivedbyshieldaddress`.
#[derive(Debug, Clone, Deserialize)]
pub struct ReceivedShieldNote {
    pub txid: String,
    pub amount: f64,
    #[serde(default)]
    pub memo: String,
    pub outindex: u32,
    pub confirmations: i64,
    pub blockheight: i64,
    pub blockindex: i64,
    pub blocktime: i64,
    pub change: Option<bool>,
}

/// Recipient entry for `shieldsendmany` / `rawshieldsendmany`.
#[derive(Debug, Clone, Serialize)]
pub struct ShieldRecipient {
    pub address: String,
    pub amount: f64,
    /// UTF-8 message, max 512 bytes. Only valid for shield addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

impl ShieldRecipient {
    pub fn new(address: impl Into<String>, amount: f64) -> Self {
        Self {
            address: address.into(),
            amount,
            memo: None,
        }
    }

    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }
}

/// Decrypted view of a shielded transaction (`viewshieldtransaction`).
#[derive(Debug, Clone, Deserialize)]
pub struct ShieldTxView {
    pub txid: String,
    pub fee: f64,
    pub spends: Vec<ShieldTxSpend>,
    pub outputs: Vec<ShieldTxOutput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShieldTxSpend {
    pub spend: u32,
    #[serde(rename = "txidPrev")]
    pub txid_prev: String,
    #[serde(rename = "outputPrev")]
    pub output_prev: u32,
    pub address: String,
    pub value: f64,
    #[serde(rename = "valueSat")]
    pub value_sat: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShieldTxOutput {
    pub output: u32,
    pub outgoing: bool,
    pub address: String,
    pub value: f64,
    #[serde(rename = "valueSat")]
    pub value_sat: i64,
    #[serde(default)]
    pub memo: String,
    #[serde(rename = "memoStr")]
    pub memo_str: Option<String>,
}

/// Result of `importsaplingkey` / `importsaplingviewingkey`.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportedSaplingKey {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: i64,
    pub headers: i64,
    pub bestblockhash: String,
    pub difficulty: f64,
    pub verificationprogress: f64,
    #[serde(default)]
    pub initial_block_downloading: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WalletInfo {
    pub walletname: String,
    pub walletversion: i64,
    pub balance: f64,
    #[serde(default)]
    pub delegated_balance: f64,
    #[serde(default)]
    pub cold_staking_balance: f64,
    #[serde(default)]
    pub shield_balance: f64,
    pub unconfirmed_balance: f64,
    pub immature_balance: f64,
    pub txcount: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Unspent {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub address: String,
    pub amount: f64,
    pub confirmations: i64,
    pub spendable: bool,
    #[serde(rename = "scriptPubKey", default)]
    pub script_pub_key: String,
}

/// Source for `shieldsendmany`: an address or a selector.
///
/// Selectors: [`FromAddress::AnyTransparent`], [`FromAddress::AnyShield`],
/// [`FromAddress::TransparentIncludingCold`].
#[derive(Debug, Clone)]
pub enum FromAddress {
    Address(String),
    AnyTransparent,
    AnyShield,
    TransparentIncludingCold,
}

impl FromAddress {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            FromAddress::Address(a) => a,
            FromAddress::AnyTransparent => "from_transparent",
            FromAddress::AnyShield => "from_shield",
            FromAddress::TransparentIncludingCold => "from_trans_cold",
        }
    }
}

impl<T: Into<String>> From<T> for FromAddress {
    fn from(s: T) -> Self {
        FromAddress::Address(s.into())
    }
}

// ── Typed RPC returns (v0.3) ─────────────────────────────────────────────
//
// Conditional fields are `Option`; serde already maps a missing key to `None`
// (see `ShieldNote` above), so no `#[serde(default)]` is needed on them.
// Unknown fields (e.g. sapling/special-tx blocks) are ignored for
// forward-compat. Amounts are `f64` PIV, times/heights/confirmations `i64`.

/// Verbose block header (`getblockheader`, verbose=true). For the raw
/// serialized header use `get_block` with verbosity 0.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub hash: String,
    /// -1 when the header is off the active chain.
    pub confirmations: i64,
    pub height: i64,
    pub version: i64,
    pub merkleroot: String,
    pub time: i64,
    pub mediantime: i64,
    pub nonce: i64,
    /// Compact difficulty target, 8 hex chars.
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: String,
    pub acc_checkpoint: String,
    pub shield_pool_value: ShieldPoolValue,
    /// Absent on the genesis block.
    pub previousblockhash: Option<String>,
    /// Absent on the chain tip.
    pub nextblockhash: Option<String>,
    pub chainlock: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShieldPoolValue {
    #[serde(rename = "chainValue")]
    pub chain_value: f64,
    #[serde(rename = "valueDelta")]
    pub value_delta: f64,
}

/// One entry of `getchaintips`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainTip {
    pub height: i64,
    pub hash: String,
    pub branchlen: i64,
    /// active | invalid | headers-only | valid-fork | valid-headers | unknown.
    pub status: String,
}

/// Script of a transaction output (`gettxout`, decoded-tx vout).
#[derive(Debug, Clone, Deserialize)]
pub struct ScriptPubKey {
    pub asm: String,
    pub hex: String,
    #[serde(rename = "reqSigs")]
    pub req_sigs: Option<i64>,
    #[serde(rename = "type")]
    pub script_type: String,
    pub addresses: Option<Vec<String>>,
}

/// Unspent output details (`gettxout`); the call returns `None` when spent or
/// not found.
#[derive(Debug, Clone, Deserialize)]
pub struct TxOut {
    pub bestblock: String,
    /// 0 when the output is still in the mempool.
    pub confirmations: i64,
    pub value: f64,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
    pub coinbase: bool,
}

/// Input of a decoded transaction. Coinbase inputs carry `coinbase`; every
/// other input carries `txid`/`vout`/`script_sig`.
#[derive(Debug, Clone, Deserialize)]
pub struct Vin {
    pub txid: Option<String>,
    pub vout: Option<u32>,
    #[serde(rename = "scriptSig")]
    pub script_sig: Option<ScriptSig>,
    pub coinbase: Option<String>,
    pub sequence: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptSig {
    pub asm: String,
    pub hex: String,
}

/// Output of a decoded transaction.
#[derive(Debug, Clone, Deserialize)]
pub struct Vout {
    pub value: f64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
}

/// Decoded transaction (`decoderawtransaction`, verbose `getrawtransaction`).
///
/// `blockhash`/`confirmations`/`time`/`blocktime` are present only for a
/// confirmed tx on the active chain — for a non-wallet txid that requires
/// `-txindex`, so they are `Option`. `in_active_chain` appears only when a
/// `blockhash` argument was supplied to `getrawtransaction`.
#[derive(Debug, Clone, Deserialize)]
pub struct DecodedTransaction {
    pub txid: String,
    pub version: i64,
    #[serde(rename = "type")]
    pub tx_type: i64,
    pub size: i64,
    pub locktime: i64,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    pub hex: String,
    pub chainlock: Option<bool>,
    pub in_active_chain: Option<bool>,
    pub blockhash: Option<String>,
    pub confirmations: Option<i64>,
    pub time: Option<i64>,
    pub blocktime: Option<i64>,
}

/// Input spec for `create_raw_transaction`.
#[derive(Debug, Clone, Serialize)]
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<i64>,
}

/// Previous-output spec for `sign_raw_transaction`.
#[derive(Debug, Clone, Serialize)]
pub struct PrevTx {
    pub txid: String,
    pub vout: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    #[serde(rename = "redeemScript", skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<String>,
    pub amount: f64,
}

/// Result of `sign_raw_transaction`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignRawTransactionResult {
    pub hex: String,
    pub complete: bool,
    /// Present only when signing left unresolved inputs.
    pub errors: Option<Vec<SignError>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignError {
    pub txid: String,
    pub vout: u32,
    /// Hex script signature (a string here, unlike a decoded input's object).
    #[serde(rename = "scriptSig")]
    pub script_sig: String,
    pub sequence: i64,
    pub error: String,
}

/// Element of `list_transactions` / `list_since_block` (long form: the
/// listtransactions fields plus the embedded wallet-tx fields).
#[derive(Debug, Clone, Deserialize)]
pub struct ListTransaction {
    #[serde(rename = "involvesWatchonly")]
    pub involves_watchonly: Option<bool>,
    pub address: Option<String>,
    /// send | receive | generate | immature | orphan.
    pub category: String,
    pub amount: f64,
    pub label: Option<String>,
    pub vout: u32,
    /// Present for `send` entries.
    pub fee: Option<f64>,
    pub confirmations: i64,
    /// Deprecated duplicate of `confirmations`.
    pub bcconfirmations: Option<i64>,
    /// Present for coinbase/coinstake outputs.
    pub generated: Option<bool>,
    pub blockhash: Option<String>,
    pub blockindex: Option<i64>,
    pub blocktime: Option<i64>,
    /// Present (in place of block fields) when unconfirmed.
    pub trusted: Option<bool>,
    pub txid: String,
    #[serde(default)]
    pub walletconflicts: Vec<String>,
    pub time: i64,
    pub timereceived: i64,
    pub comment: Option<String>,
    /// Any other `mapValue` keys the node attaches (e.g. `to`), so nothing is
    /// dropped vs a raw `Value` — mirrors the JS SDK's open-ended shape.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Result of `list_since_block`. PIVX omits the `removed` array.
#[derive(Debug, Clone, Deserialize)]
pub struct ListSinceBlock {
    pub transactions: Vec<ListTransaction>,
    pub lastblock: String,
}

/// Short detail element embedded in `gettransaction`.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionDetail {
    #[serde(rename = "involvesWatchonly")]
    pub involves_watchonly: Option<bool>,
    pub address: Option<String>,
    pub category: String,
    pub amount: f64,
    pub label: Option<String>,
    pub vout: u32,
    pub fee: Option<f64>,
}

/// Wallet's record of a transaction (`gettransaction`).
#[derive(Debug, Clone, Deserialize)]
pub struct Transaction {
    pub amount: f64,
    /// Present when the wallet sent the tx (`IsFromMe`).
    pub fee: Option<f64>,
    pub confirmations: i64,
    /// Deprecated duplicate of `confirmations`.
    pub bcconfirmations: Option<i64>,
    pub generated: Option<bool>,
    pub blockhash: Option<String>,
    pub blockindex: Option<i64>,
    pub blocktime: Option<i64>,
    pub trusted: Option<bool>,
    pub txid: String,
    #[serde(default)]
    pub walletconflicts: Vec<String>,
    pub time: i64,
    pub timereceived: i64,
    pub comment: Option<String>,
    pub details: Vec<TransactionDetail>,
    pub hex: String,
    /// Any other `mapValue` keys the node attaches (e.g. `to`), so nothing is
    /// dropped vs a raw `Value` — mirrors the JS SDK's open-ended shape.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Result of `validate_address`. Only `isvalid` is guaranteed; the rest depend
/// on validity and address type (transparent vs shield).
#[derive(Debug, Clone, Deserialize)]
pub struct ValidateAddress {
    pub isvalid: bool,
    pub address: Option<String>,
    /// Hex script (a string here, unlike an output's `ScriptPubKey` object).
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Option<String>,
    pub ismine: Option<bool>,
    pub isstaking: Option<bool>,
    pub iswatchonly: Option<bool>,
    pub isscript: Option<bool>,
    pub pubkey: Option<String>,
    pub iscompressed: Option<bool>,
    pub exchangepubkey: Option<String>,
    pub script: Option<String>,
    pub hex: Option<String>,
    pub addresses: Option<Vec<String>>,
    pub sigsrequired: Option<i64>,
    pub label: Option<String>,
    // Shield-address fields:
    pub diversifier: Option<String>,
    pub diversifiedtransmissionkey: Option<String>,
}
