//! Response types matching pivxd's JSON output.
//!
//! Amounts are `f64` in PIV (8 decimal places), exactly as the node emits
//! them — the same convention as every *-core RPC library.

use serde::{Deserialize, Serialize};

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
