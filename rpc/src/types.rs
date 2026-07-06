//! Response types matching pivxd's JSON output.
//!
//! Amounts are `f64` in PIV (8 decimal places), exactly as the node emits
//! them — the same convention as every *-core RPC library.

use std::collections::HashMap;

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
    /// Fee as a PIV money **string** (the node emits `FormatMoney`, e.g.
    /// `"0.00010000"`), not a JSON number. Parse it if needed; for reliable
    /// integer arithmetic prefer the per-entry `value_sat` fields.
    pub fee: String,
    pub spends: Vec<ShieldTxSpend>,
    pub outputs: Vec<ShieldTxOutput>,
}

/// `value` of a shield spend/output: a PIV amount, or the node's literal
/// string `"unknown"` when the wallet cannot recover the note amount (e.g. a
/// spend whose creating tx has no cached note data). `value_sat` is `0` in
/// the unknown case — check this enum before trusting a zero.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ShieldTxValue {
    /// Known amount in PIV.
    Piv(f64),
    /// The node reported `"unknown"`.
    Unknown,
}

impl ShieldTxValue {
    /// The PIV amount, or `None` when the node reported `"unknown"`.
    pub fn as_piv(self) -> Option<f64> {
        match self {
            ShieldTxValue::Piv(v) => Some(v),
            ShieldTxValue::Unknown => None,
        }
    }
}

impl std::fmt::Display for ShieldTxValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldTxValue::Piv(v) => write!(f, "{v}"),
            ShieldTxValue::Unknown => f.write_str("unknown"),
        }
    }
}

impl<'de> Deserialize<'de> for ShieldTxValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(f64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(ShieldTxValue::Piv(n)),
            Raw::Str(s) if s == "unknown" => Ok(ShieldTxValue::Unknown),
            Raw::Str(s) => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&s),
                &"a PIV amount or \"unknown\"",
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShieldTxSpend {
    pub spend: u32,
    #[serde(rename = "txidPrev")]
    pub txid_prev: String,
    #[serde(rename = "outputPrev")]
    pub output_prev: u32,
    /// Shield address, or the literal `"unknown"`.
    pub address: String,
    pub value: ShieldTxValue,
    #[serde(rename = "valueSat")]
    pub value_sat: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShieldTxOutput {
    pub output: u32,
    pub outgoing: bool,
    /// Shield address, or the literal `"unknown"`.
    pub address: String,
    pub value: ShieldTxValue,
    #[serde(rename = "valueSat")]
    pub value_sat: i64,
    #[serde(default)]
    pub memo: String,
    #[serde(rename = "memoStr")]
    pub memo_str: Option<String>,
}

/// Masternode counts (`getmasternodecount`). All counters are plain totals
/// from the node's masternode manager.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MasternodeCount {
    pub total: i64,
    pub stable: i64,
    pub enabled: i64,
    pub inqueue: i64,
    pub ipv4: i64,
    pub ipv6: i64,
    pub onion: i64,
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
    /// `None` when the node omits the field — distinct from a real 0 balance.
    pub delegated_balance: Option<f64>,
    /// `None` when the node omits the field — distinct from a real 0 balance.
    pub cold_staking_balance: Option<f64>,
    /// `None` when the node omits the field — distinct from a real 0 balance.
    pub shield_balance: Option<f64>,
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

// ── Typed RPC returns (v0.5) ─────────────────────────────────────────────
//
// Volatile node-status objects: every struct carries a `#[serde(flatten)]
// extra` catch-all so a node adding a field never breaks deserialization.
// Amounts are `f64` PIV; "moneystr" fields (FormatMoney) stay `String`.

/// `getnetworkinfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkInfo {
    pub version: i64,
    pub subversion: String,
    pub protocolversion: i64,
    pub localservices: Option<String>,
    pub timeoffset: i64,
    pub networkactive: Option<bool>,
    pub connections: Option<i64>,
    pub networks: Vec<NetworkEntry>,
    pub relayfee: f64,
    pub localaddresses: Vec<LocalAddress>,
    pub warnings: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkEntry {
    pub name: String,
    pub limited: bool,
    pub reachable: bool,
    pub proxy: String,
    pub proxy_randomize_credentials: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalAddress {
    pub address: String,
    pub port: i64,
    pub score: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Element of `getpeerinfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerInfo {
    pub id: i64,
    pub addr: String,
    pub addrlocal: Option<String>,
    pub mapped_as: Option<i64>,
    pub services: String,
    pub lastsend: i64,
    pub lastrecv: i64,
    pub bytessent: i64,
    pub bytesrecv: i64,
    pub conntime: i64,
    pub timeoffset: i64,
    pub pingtime: f64,
    pub pingwait: Option<f64>,
    pub version: i64,
    pub subver: String,
    pub inbound: bool,
    pub addnode: bool,
    pub masternode: bool,
    pub startingheight: i64,
    pub banscore: Option<i64>,
    pub synced_headers: Option<i64>,
    pub synced_blocks: Option<i64>,
    pub inflight: Option<Vec<i64>>,
    pub addr_processed: Option<i64>,
    pub addr_rate_limited: Option<i64>,
    pub whitelisted: bool,
    pub bytessent_per_msg: HashMap<String, i64>,
    pub bytesrecv_per_msg: HashMap<String, i64>,
    pub masternode_iqr_conn: Option<bool>,
    pub verif_mn_proreg_tx_hash: Option<String>,
    pub verif_mn_operator_pubkey_hash: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `getmempoolinfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolInfo {
    pub loaded: bool,
    pub size: i64,
    pub bytes: i64,
    pub usage: i64,
    pub mempoolminfee: f64,
    pub minrelaytxfee: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Verbose `getrawmempool` entry (value of the txid-keyed map).
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolEntry {
    pub size: i64,
    pub fee: f64,
    pub modifiedfee: f64,
    pub time: i64,
    pub height: i64,
    pub descendantcount: i64,
    pub descendantsize: i64,
    /// Raw satoshis (`GetModFeesWithDescendants`), NOT decimal PIV.
    pub descendantfees: i64,
    pub depends: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `getsupplyinfo` (PIVX-specific).
#[derive(Debug, Clone, Deserialize)]
pub struct SupplyInfo {
    pub updateheight: i64,
    pub transparentsupply: f64,
    pub shieldsupply: f64,
    pub totalsupply: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `getblockindexstats`. Note the space-keyed field names and that `ttlfee` /
/// `feeperkb` are money **strings** (`FormatMoney`), not numbers.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockIndexStats {
    #[serde(rename = "Starting block")]
    pub starting_block: i64,
    #[serde(rename = "Ending block")]
    pub ending_block: i64,
    pub txcount: i64,
    pub txcount_all: i64,
    pub txbytes: i64,
    pub ttlfee: String,
    pub feeperkb: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `getmininginfo`. In normal mode the node emits both `errors` and
/// `warnings` (with `-deprecatedrpc=getmininginfo` only `errors`), so
/// `warnings` is optional.
#[derive(Debug, Clone, Deserialize)]
pub struct MiningInfo {
    pub blocks: i64,
    pub currentblocksize: i64,
    pub currentblocktx: i64,
    pub difficulty: f64,
    pub genproclimit: i64,
    pub networkhashps: f64,
    pub pooledtx: i64,
    pub testnet: bool,
    pub chain: String,
    pub errors: String,
    pub warnings: Option<String>,
    pub generate: Option<bool>,
    pub hashespersec: Option<f64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `estimatesmartfee`.
#[derive(Debug, Clone, Deserialize)]
pub struct EstimateSmartFee {
    /// Fee-per-kB estimate in PIV; `-1.0` when the node has no estimate.
    pub feerate: f64,
    pub blocks: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Element of `getbudgetinfo`. Field names are the node's exact PascalCase keys.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetProposal {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "Hash")]
    pub hash: String,
    #[serde(rename = "FeeHash")]
    pub fee_hash: String,
    #[serde(rename = "BlockStart")]
    pub block_start: i64,
    #[serde(rename = "BlockEnd")]
    pub block_end: i64,
    #[serde(rename = "TotalPaymentCount")]
    pub total_payment_count: i64,
    #[serde(rename = "RemainingPaymentCount")]
    pub remaining_payment_count: i64,
    #[serde(rename = "PaymentAddress")]
    pub payment_address: String,
    #[serde(rename = "Ratio")]
    pub ratio: f64,
    #[serde(rename = "Yeas")]
    pub yeas: i64,
    #[serde(rename = "Nays")]
    pub nays: i64,
    #[serde(rename = "Abstains")]
    pub abstains: i64,
    #[serde(rename = "TotalPayment")]
    pub total_payment: f64,
    #[serde(rename = "MonthlyPayment")]
    pub monthly_payment: f64,
    #[serde(rename = "IsEstablished")]
    pub is_established: bool,
    #[serde(rename = "IsValid")]
    pub is_valid: bool,
    #[serde(rename = "IsInvalidReason")]
    pub is_invalid_reason: Option<String>,
    #[serde(rename = "Allotted")]
    pub allotted: f64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Element of `getbudgetprojection`: a [`BudgetProposal`] plus the running
/// `TotalBudgetAllotted`.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetProjection {
    #[serde(flatten)]
    pub proposal: BudgetProposal,
    #[serde(rename = "TotalBudgetAllotted")]
    pub total_budget_allotted: f64,
}

/// `getstakingstatus` (PIVX wallet). `lastattempt_*` are present only after a
/// staking attempt.
#[derive(Debug, Clone, Deserialize)]
pub struct StakingStatus {
    pub staking_status: bool,
    pub staking_enabled: bool,
    pub coldstaking_enabled: bool,
    pub haveconnections: bool,
    pub mnsync: bool,
    pub walletunlocked: bool,
    pub stakeablecoins: i64,
    pub stakingbalance: f64,
    pub stakesplitthreshold: f64,
    pub lastattempt_age: Option<i64>,
    pub lastattempt_depth: Option<i64>,
    pub lastattempt_hash: Option<String>,
    pub lastattempt_coins: Option<i64>,
    pub lastattempt_tries: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Element of `liststakingaddresses`.
#[derive(Debug, Clone, Deserialize)]
pub struct StakingAddress {
    pub label: String,
    pub address: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
