use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::types::*;

/// Authentication for the node's RPC interface.
#[derive(Debug, Clone)]
pub enum Auth {
    None,
    UserPass {
        user: String,
        pass: String,
    },
    /// Read `user:pass` from a pivxd `.cookie` file (regenerated each start).
    CookieFile(PathBuf),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error returned by the node's JSON-RPC layer, code intact (e.g. -13 = wallet locked).
    #[error("{method}: {message} (code {code})")]
    Rpc {
        code: i64,
        message: String,
        method: String,
    },
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("invalid response for {method}: {source}")]
    Json {
        method: String,
        source: serde_json::Error,
    },
    #[error("cannot read cookie file: {0}")]
    Cookie(#[from] std::io::Error),
    #[error("{0}")]
    InvalidCookie(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Async JSON-RPC client for a pivxd node.
///
/// Default ports: mainnet `51473`, testnet `51475`.
pub struct PivxClient {
    http: reqwest::Client,
    url: String,
    auth: Option<(String, String)>,
    id: AtomicU64,
}

impl PivxClient {
    /// `url` e.g. `"http://127.0.0.1:51473"`. For multiwallet nodes append
    /// `/wallet/<name>` to route calls to a specific wallet.
    pub fn new(url: impl Into<String>, auth: Auth) -> Result<Self> {
        let auth = match auth {
            Auth::None => None,
            Auth::UserPass { user, pass } => Some((user, pass)),
            Auth::CookieFile(path) => {
                let contents = std::fs::read_to_string(path)?;
                let (user, pass) = contents.trim().split_once(':').ok_or_else(|| {
                    Error::InvalidCookie("cookie file has no ':' separator".into())
                })?;
                Some((user.to_string(), pass.to_string()))
            }
        };
        Ok(Self {
            http: reqwest::Client::new(),
            url: url.into(),
            auth,
            id: AtomicU64::new(0),
        })
    }

    /// Raw JSON-RPC call. Trailing `Value::Null` params are trimmed so
    /// optional arguments fall back to node defaults.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        mut params: Vec<Value>,
    ) -> Result<T> {
        while params.last() == Some(&Value::Null) {
            params.pop();
        }
        let mut req = self.http.post(&self.url).json(&json!({
            "jsonrpc": "1.0",
            "id": self.id.fetch_add(1, Ordering::Relaxed),
            "method": method,
            "params": params,
        }));
        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }
        let body: Value = req.send().await?.json().await?;
        if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
            return Err(Error::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown RPC error")
                    .to_string(),
                method: method.to_string(),
            });
        }
        serde_json::from_value(body.get("result").cloned().unwrap_or(Value::Null)).map_err(
            |source| Error::Json {
                method: method.to_string(),
                source,
            },
        )
    }

    // ── Blockchain ───────────────────────────────────────────────────────

    pub async fn get_block_count(&self) -> Result<i64> {
        self.call("getblockcount", vec![]).await
    }

    pub async fn get_best_block_hash(&self) -> Result<String> {
        self.call("getbestblockhash", vec![]).await
    }

    pub async fn get_block_hash(&self, height: i64) -> Result<String> {
        self.call("getblockhash", vec![json!(height)]).await
    }

    /// `verbosity`: 0 = hex, 1 = json, 2 = json with full tx objects.
    pub async fn get_block(&self, hash: &str, verbosity: u8) -> Result<Value> {
        self.call("getblock", vec![json!(hash), json!(verbosity)])
            .await
    }

    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo> {
        self.call("getblockchaininfo", vec![]).await
    }

    pub async fn get_raw_transaction(&self, txid: &str) -> Result<String> {
        self.call("getrawtransaction", vec![json!(txid)]).await
    }

    pub async fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.call("sendrawtransaction", vec![json!(hex)]).await
    }

    // ── Transparent wallet ───────────────────────────────────────────────

    pub async fn get_balance(&self) -> Result<f64> {
        self.call("getbalance", vec![]).await
    }

    pub async fn get_new_address(&self, label: Option<&str>) -> Result<String> {
        self.call("getnewaddress", vec![json!(label)]).await
    }

    pub async fn list_unspent(&self, min_conf: i64) -> Result<Vec<Unspent>> {
        self.call("listunspent", vec![json!(min_conf)]).await
    }

    pub async fn send_to_address(&self, address: &str, amount: f64) -> Result<String> {
        self.call("sendtoaddress", vec![json!(address), json!(amount)])
            .await
    }

    pub async fn get_wallet_info(&self) -> Result<WalletInfo> {
        self.call("getwalletinfo", vec![]).await
    }

    // ── Shield (SHIELD/Sapling) ──────────────────────────────────────────

    pub async fn get_new_shield_address(&self, label: Option<&str>) -> Result<String> {
        self.call("getnewshieldaddress", vec![json!(label)]).await
    }

    pub async fn list_shield_addresses(&self, include_watch_only: bool) -> Result<Vec<String>> {
        self.call("listshieldaddresses", vec![json!(include_watch_only)])
            .await
    }

    /// Total shield balance, or one address's balance (`"*"` = all).
    pub async fn get_shield_balance(
        &self,
        address: &str,
        min_conf: i64,
        include_watch_only: bool,
    ) -> Result<f64> {
        self.call(
            "getshieldbalance",
            vec![json!(address), json!(min_conf), json!(include_watch_only)],
        )
        .await
    }

    pub async fn list_shield_unspent(
        &self,
        min_conf: i64,
        max_conf: i64,
        include_watch_only: bool,
        addresses: Option<&[String]>,
    ) -> Result<Vec<ShieldNote>> {
        self.call(
            "listshieldunspent",
            vec![
                json!(min_conf),
                json!(max_conf),
                json!(include_watch_only),
                json!(addresses),
            ],
        )
        .await
    }

    pub async fn list_received_by_shield_address(
        &self,
        address: &str,
        min_conf: i64,
    ) -> Result<Vec<ReceivedShieldNote>> {
        self.call(
            "listreceivedbyshieldaddress",
            vec![json!(address), json!(min_conf)],
        )
        .await
    }

    /// Build, prove, and broadcast a shielded transaction from the node
    /// wallet. Synchronous in PIVX: returns the txid once accepted.
    pub async fn shield_send_many(
        &self,
        from: impl Into<FromAddress>,
        recipients: &[ShieldRecipient],
    ) -> Result<String> {
        self.call(
            "shieldsendmany",
            vec![json!(from.into().as_str()), json!(recipients)],
        )
        .await
    }

    /// Like [`shield_send_many`](Self::shield_send_many) with explicit
    /// `minconf`, `fee` (None = node computes minimum), and
    /// `subtract_fee_from` addresses.
    pub async fn shield_send_many_with(
        &self,
        from: impl Into<FromAddress>,
        recipients: &[ShieldRecipient],
        min_conf: i64,
        fee: Option<f64>,
        subtract_fee_from: Option<&[String]>,
    ) -> Result<String> {
        self.call(
            "shieldsendmany",
            vec![
                json!(from.into().as_str()),
                json!(recipients),
                json!(min_conf),
                json!(fee.unwrap_or(0.0)),
                json!(subtract_fee_from),
            ],
        )
        .await
    }

    /// Build and prove a shielded transaction but do not broadcast; returns raw hex.
    pub async fn raw_shield_send_many(
        &self,
        from: impl Into<FromAddress>,
        recipients: &[ShieldRecipient],
    ) -> Result<String> {
        self.call(
            "rawshieldsendmany",
            vec![json!(from.into().as_str()), json!(recipients)],
        )
        .await
    }

    /// Decrypted view of a wallet shielded transaction (amounts, memos).
    pub async fn view_shield_transaction(&self, txid: &str) -> Result<ShieldTxView> {
        self.call("viewshieldtransaction", vec![json!(txid)]).await
    }

    pub async fn get_sapling_notes_count(&self, min_conf: i64) -> Result<i64> {
        self.call("getsaplingnotescount", vec![json!(min_conf)])
            .await
    }

    // ── Sapling keys ─────────────────────────────────────────────────────

    pub async fn export_sapling_key(&self, shield_addr: &str) -> Result<String> {
        self.call("exportsaplingkey", vec![json!(shield_addr)])
            .await
    }

    pub async fn import_sapling_key(
        &self,
        key: &str,
        rescan: Option<&str>,
        height: Option<i64>,
    ) -> Result<ImportedSaplingKey> {
        self.call(
            "importsaplingkey",
            vec![json!(key), json!(rescan), json!(height)],
        )
        .await
    }

    pub async fn export_sapling_viewing_key(&self, shield_addr: &str) -> Result<String> {
        self.call("exportsaplingviewingkey", vec![json!(shield_addr)])
            .await
    }

    /// Import an incoming viewing key for watch-only shield balance
    /// tracking. `rescan`: `"yes"` | `"no"` | `"whenkeyisnew"` (default).
    pub async fn import_sapling_viewing_key(
        &self,
        vkey: &str,
        rescan: Option<&str>,
        height: Option<i64>,
    ) -> Result<ImportedSaplingKey> {
        self.call(
            "importsaplingviewingkey",
            vec![json!(vkey), json!(rescan), json!(height)],
        )
        .await
    }
}
