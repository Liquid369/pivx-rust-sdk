use std::collections::HashMap;
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
#[non_exhaustive]
pub enum Error {
    /// Error returned by the node's JSON-RPC layer, code intact (e.g. -13 = wallet locked).
    #[error("{method}: {message} (code {code})")]
    Rpc {
        code: i64,
        message: String,
        method: String,
    },
    /// HTTP 401/403 from the node: bad rpcuser/rpcpassword, or a stale
    /// `.cookie` (pivxd regenerates it on every restart).
    #[error("authentication failed (HTTP {status}): check RPC credentials or cookie file")]
    Auth { status: u16 },
    /// Non-2xx HTTP response without a JSON-RPC error body.
    #[error("{method}: node returned HTTP {status} with no JSON-RPC error body")]
    Http { status: u16, method: String },
    /// Response body exceeded the configured cap; see
    /// [`with_max_response_size`](PivxClient::with_max_response_size).
    #[error("{method}: response body exceeds {limit}-byte cap")]
    ResponseTooLarge { method: String, limit: usize },
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

/// Build an [`Error::Rpc`] from a JSON-RPC `error` object.
fn rpc_error(err: &Value, method: &str) -> Error {
    Error::Rpc {
        code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
        message: err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown RPC error")
            .to_string(),
        method: method.to_string(),
    }
}

/// Default cap on HTTP response bodies (matches the JS client).
const DEFAULT_MAX_RESPONSE_SIZE: usize = 64 * 1024 * 1024;

/// A real pivxd `.cookie` is `__cookie__:<hex>` — well under 256 bytes. Cap the
/// read so a wrong path at a huge file can't be slurped into memory.
const MAX_COOKIE_BYTES: u64 = 4096;

fn read_cookie(path: &std::path::Path) -> Result<(String, String)> {
    use std::io::Read;
    let mut buf = String::new();
    std::fs::File::open(path)?
        .take(MAX_COOKIE_BYTES + 1)
        .read_to_string(&mut buf)?;
    if buf.len() as u64 > MAX_COOKIE_BYTES {
        return Err(Error::InvalidCookie("cookie file is too large".into()));
    }
    let (user, pass) = buf
        .trim()
        .split_once(':')
        .ok_or_else(|| Error::InvalidCookie("cookie file has no ':' separator".into()))?;
    Ok((user.to_string(), pass.to_string()))
}

/// Async JSON-RPC client for a pivxd node.
///
/// Default ports: mainnet `51473`, testnet `51475`.
///
/// Cheap to [`Clone`]: every clone shares the same reqwest connection pool,
/// request-id counter, and — crucially — the same `Arc<RwLock>` of credentials,
/// so a `.cookie` refresh triggered by a 401 on one clone is immediately
/// visible to all others.
#[derive(Clone)]
pub struct PivxClient {
    http: reqwest::Client,
    url: String,
    /// Current basic-auth credentials. Behind a shared lock so a rotated
    /// `.cookie` can be re-read on 401 without `&mut self` (client stays
    /// Send + Sync) and the refresh is shared across clones.
    auth: std::sync::Arc<std::sync::RwLock<Option<(String, String)>>>,
    /// Set only for [`Auth::CookieFile`]: where to re-read credentials from.
    cookie_path: Option<PathBuf>,
    max_response_size: usize,
    id: std::sync::Arc<AtomicU64>,
}

impl PivxClient {
    /// `url` e.g. `"http://127.0.0.1:51473"`. For multiwallet nodes append
    /// `/wallet/<name>` to route calls to a specific wallet. Uses a 30-second
    /// per-request timeout; see [`with_timeout`](Self::with_timeout) to change it.
    pub fn new(url: impl Into<String>, auth: Auth) -> Result<Self> {
        Self::with_timeout(url, auth, std::time::Duration::from_secs(30))
    }

    /// Like [`new`](Self::new) with an explicit per-request timeout. A timeout
    /// is essential in production: without one a hung or unresponsive node
    /// blocks `call`/`sync`/`send` forever.
    pub fn with_timeout(
        url: impl Into<String>,
        auth: Auth,
        timeout: std::time::Duration,
    ) -> Result<Self> {
        let (auth, cookie_path) = match auth {
            Auth::None => (None, None),
            Auth::UserPass { user, pass } => (Some((user, pass)), None),
            Auth::CookieFile(path) => (Some(read_cookie(&path)?), Some(path)),
        };
        Ok(Self {
            http: reqwest::Client::builder().timeout(timeout).build()?,
            url: url.into(),
            auth: std::sync::Arc::new(std::sync::RwLock::new(auth)),
            cookie_path,
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            id: std::sync::Arc::new(AtomicU64::new(0)),
        })
    }

    /// Cap on HTTP response body size in bytes (default 64 MiB). Responses
    /// exceeding it abort with [`Error::ResponseTooLarge`].
    /// Builder-style: `PivxClient::new(url, auth)?.with_max_response_size(n)`.
    pub fn with_max_response_size(mut self, bytes: usize) -> Self {
        self.max_response_size = bytes;
        self
    }

    /// POST `payload` with the current credentials.
    async fn post(&self, payload: &Value) -> Result<reqwest::Response> {
        let req = {
            let auth = self.auth.read().unwrap();
            let mut req = self.http.post(&self.url).json(payload);
            if let Some((user, pass)) = auth.as_ref() {
                req = req.basic_auth(user, Some(pass));
            }
            req // guard drops here, before the await
        };
        Ok(req.send().await?)
    }

    /// After a 401: re-read the cookie file. Returns true if the credentials
    /// on disk changed (and were swapped in), so the request should be
    /// retried once. False if not cookie-authed or the cookie is unchanged.
    fn refresh_cookie(&self) -> Result<bool> {
        let Some(path) = &self.cookie_path else {
            return Ok(false);
        };
        let fresh = read_cookie(path)?;
        let mut auth = self.auth.write().unwrap();
        if auth.as_ref() == Some(&fresh) {
            return Ok(false);
        }
        *auth = Some(fresh);
        Ok(true)
    }

    /// Read the body, aborting once it exceeds `max_response_size`.
    async fn read_body_capped(&self, mut resp: reqwest::Response, method: &str) -> Result<Vec<u8>> {
        let too_large = || Error::ResponseTooLarge {
            method: method.to_string(),
            limit: self.max_response_size,
        };
        if resp
            .content_length()
            .is_some_and(|len| len > self.max_response_size as u64)
        {
            return Err(too_large());
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if buf.len() + chunk.len() > self.max_response_size {
                return Err(too_large());
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }

    /// POST `payload`, applying the 401 cookie-refresh retry, HTTP-status
    /// handling, and response cap. Returns the parsed JSON body and the HTTP
    /// status. Shared by [`call`](Self::call) (single request) and
    /// [`call_batch`](Self::call_batch) (request array).
    async fn send_rpc(&self, payload: &Value, method: &str) -> Result<(Value, u16)> {
        let mut resp = self.post(payload).await?;
        // pivxd regenerates `.cookie` on every restart: on 401, re-read it and
        // retry once if the credentials actually changed. A 403 is an IP/ACL
        // denial that a cookie can't fix, so it is not retried. An unreadable
        // cookie counts as unchanged and falls through to Error::Auth (the
        // caller's actionable signal is that authentication failed).
        if resp.status().as_u16() == 401 && self.refresh_cookie().unwrap_or(false) {
            resp = self.post(payload).await?;
        }
        let status = resp.status().as_u16();
        if status == 401 || status == 403 {
            return Err(Error::Auth { status });
        }
        let is_success = resp.status().is_success();
        let bytes = self.read_body_capped(resp, method).await?;
        // pivxd (src/httprpc.cpp JSONErrorReply) reports RPC errors as
        // non-2xx *with* a JSON-RPC error body: parse the body regardless of
        // status so the caller can prefer that error.
        let body: Value = match serde_json::from_slice(&bytes) {
            Ok(body) => body,
            Err(source) if is_success => {
                return Err(Error::Json {
                    method: method.to_string(),
                    source,
                })
            }
            Err(_) => {
                return Err(Error::Http {
                    status,
                    method: method.to_string(),
                })
            }
        };
        Ok((body, status))
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
        let payload = json!({
            "jsonrpc": "1.0",
            "id": self.id.fetch_add(1, Ordering::Relaxed),
            "method": method,
            "params": params,
        });
        let (body, status) = self.send_rpc(&payload, method).await?;
        if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
            return Err(rpc_error(err, method));
        }
        if !(200..300).contains(&status) {
            return Err(Error::Http {
                status,
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

    /// Execute several JSON-RPC calls in one HTTP round-trip (batch). Returns
    /// one entry per call in request order: `Ok(result)` on success,
    /// `Err(Error::Rpc { .. })` for a per-call node error. A single bad call
    /// does not fail the batch; the outer `Err` is reserved for
    /// transport/auth/whole-request failures. Rejects an empty `calls` slice.
    ///
    /// Design: each sub-request gets a distinct id, but responses are matched
    /// to requests **by position** — the node returns the array in request
    /// order (src/httprpc.cpp) — guarded by an element-count check.
    pub async fn call_batch(
        &self,
        calls: &[(&str, Vec<Value>)],
    ) -> Result<Vec<std::result::Result<Value, Error>>> {
        if calls.is_empty() {
            return Err(Error::Rpc {
                code: -32600,
                message: "call_batch requires at least one call".to_string(),
                method: "batch".to_string(),
            });
        }
        let payload = Value::Array(
            calls
                .iter()
                .map(|(method, params)| {
                    json!({
                        "jsonrpc": "1.0",
                        "id": self.id.fetch_add(1, Ordering::Relaxed),
                        "method": method,
                        "params": params,
                    })
                })
                .collect(),
        );
        let (body, status) = self.send_rpc(&payload, "batch").await?;
        // A whole-request failure (e.g. a malformed batch) comes back as a
        // single error object, not an array — surface it as the outer Err.
        if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
            return Err(rpc_error(err, "batch"));
        }
        if !(200..300).contains(&status) {
            return Err(Error::Http {
                status,
                method: "batch".to_string(),
            });
        }
        let arr = match body {
            Value::Array(a) => a,
            other => {
                return Err(Error::Json {
                    method: "batch".to_string(),
                    source: <serde_json::Error as serde::de::Error>::custom(format!(
                        "batch response was not a JSON array: {other}"
                    )),
                })
            }
        };
        if arr.len() != calls.len() {
            return Err(Error::Json {
                method: "batch".to_string(),
                source: <serde_json::Error as serde::de::Error>::custom(format!(
                    "batch response has {} elements for {} calls",
                    arr.len(),
                    calls.len()
                )),
            });
        }
        Ok(arr
            .into_iter()
            .zip(calls.iter())
            .map(|(elem, (method, _))| {
                if let Some(err) = elem.get("error").filter(|e| !e.is_null()) {
                    Err(rpc_error(err, method))
                } else {
                    Ok(elem.get("result").cloned().unwrap_or(Value::Null))
                }
            })
            .collect())
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

    /// Verbose block header (hash, height, difficulty, chainwork, …). For the
    /// raw serialized header use [`get_block`](Self::get_block) with verbosity 0.
    pub async fn get_block_header(&self, hash: &str) -> Result<BlockHeader> {
        self.call("getblockheader", vec![json!(hash), json!(true)])
            .await
    }

    /// All known chain tips: the active tip plus any side-chain forks.
    pub async fn get_chain_tips(&self) -> Result<Vec<ChainTip>> {
        self.call("getchaintips", vec![]).await
    }

    /// Details of an unspent output, or `None` if spent / not found.
    /// `include_mempool` falls back to the node's default (`true`) when `None`.
    pub async fn get_tx_out(
        &self,
        txid: &str,
        n: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<TxOut>> {
        self.call(
            "gettxout",
            vec![json!(txid), json!(n), json!(include_mempool)],
        )
        .await
    }

    pub async fn get_raw_transaction(&self, txid: &str) -> Result<String> {
        self.call("getrawtransaction", vec![json!(txid)]).await
    }

    /// Decoded transaction with confirmation metadata (verbose
    /// `getrawtransaction`). `blockhash`/`confirmations`/`time`/`blocktime`
    /// require `-txindex` for a non-wallet txid, so they are `Option`. Pass
    /// `block_hash` to look a confirmed tx up in a specific block without
    /// `-txindex` (also sets `in_active_chain`). The hex-returning
    /// [`get_raw_transaction`](Self::get_raw_transaction) is unchanged.
    pub async fn get_raw_transaction_verbose(
        &self,
        txid: &str,
        block_hash: Option<&str>,
    ) -> Result<DecodedTransaction> {
        let mut params = vec![json!(txid), json!(true)];
        if let Some(h) = block_hash {
            params.push(json!(h));
        }
        self.call("getrawtransaction", params).await
    }

    /// Build an unsigned raw transaction (hex); not signed, not broadcast.
    /// `outputs` maps address → amount in PIV. `locktime` defaults to 0.
    pub async fn create_raw_transaction(
        &self,
        inputs: &[TxInput],
        outputs: &HashMap<String, f64>,
        locktime: Option<i64>,
    ) -> Result<String> {
        // ponytail: HashMap order is arbitrary, so vout ordering follows the
        // node's parse of the object; a caller needing a fixed vout order can
        // look up by address. Fine for an unsigned builder.
        self.call(
            "createrawtransaction",
            vec![json!(inputs), json!(outputs), json!(locktime)],
        )
        .await
    }

    /// Decode a raw transaction hex into its typed form.
    pub async fn decode_raw_transaction(&self, hex: &str) -> Result<DecodedTransaction> {
        self.call("decoderawtransaction", vec![json!(hex)]).await
    }

    /// Sign a raw transaction. PIVX's RPC is `signrawtransaction` (4 params,
    /// not the `...withkey` split). Extra args are optional; `sighash_type`
    /// falls back to the node's `"ALL"`.
    pub async fn sign_raw_transaction(
        &self,
        hex: &str,
        prev_txs: Option<&[PrevTx]>,
        priv_keys: Option<&[String]>,
        sighash_type: Option<&str>,
    ) -> Result<SignRawTransactionResult> {
        self.call(
            "signrawtransaction",
            vec![
                json!(hex),
                json!(prev_txs),
                json!(priv_keys),
                json!(sighash_type),
            ],
        )
        .await
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

    /// Wallet's record of a transaction (amounts, confirmations, fee, details).
    pub async fn get_transaction(&self, txid: &str) -> Result<Transaction> {
        self.call("gettransaction", vec![json!(txid)]).await
    }

    /// Validate an address; `isvalid` says whether it is, and the remaining
    /// fields depend on type (transparent vs shield) and wallet ownership.
    pub async fn validate_address(&self, address: &str) -> Result<ValidateAddress> {
        self.call("validateaddress", vec![json!(address)]).await
    }

    /// Wallet transactions since `block_hash` (all, if `None`) plus the last
    /// block scanned.
    /// Transactions since `block_hash` (or all wallet txs when `None`). The
    /// node reads these positionally and rejects a null `blockhash`, so when
    /// `block_hash` is `None` no params are sent (`target_confirmations` /
    /// `include_watchonly` only apply alongside a block hash).
    pub async fn list_since_block(
        &self,
        block_hash: Option<&str>,
        target_confirmations: Option<i64>,
        include_watchonly: Option<bool>,
    ) -> Result<ListSinceBlock> {
        let params = match block_hash {
            None => vec![],
            Some(h) => vec![
                json!(h),
                json!(target_confirmations.unwrap_or(1)),
                json!(include_watchonly.unwrap_or(false)),
            ],
        };
        self.call("listsinceblock", params).await
    }

    /// Recent wallet transactions. `include_delegated` and `include_cold`
    /// default to `true`. The legacy `dummy="*"` account param is supplied
    /// internally and is not exposed.
    pub async fn list_transactions(
        &self,
        count: Option<i64>,
        from: Option<i64>,
        include_watchonly: Option<bool>,
        include_delegated: Option<bool>,
        include_cold: Option<bool>,
    ) -> Result<Vec<ListTransaction>> {
        // The node reads every positional param with an unguarded getter, so
        // a null (from an omitted Option) would be rejected — substitute the
        // node's own defaults instead.
        self.call(
            "listtransactions",
            vec![
                json!("*"),
                json!(count.unwrap_or(10)),
                json!(from.unwrap_or(0)),
                json!(include_watchonly.unwrap_or(false)),
                json!(include_delegated.unwrap_or(true)),
                json!(include_cold.unwrap_or(true)),
            ],
        )
        .await
    }

    /// Send to many recipients in one transaction; returns the txid. Requires
    /// an unlocked wallet. `amounts` maps address → PIV (transparent or shield
    /// `ps1`). `include_delegated` defaults to `false`. The legacy `dummy=""`
    /// account param is supplied internally.
    pub async fn send_many(
        &self,
        amounts: &HashMap<String, f64>,
        min_conf: Option<i64>,
        comment: Option<&str>,
        include_delegated: Option<bool>,
        subtract_fee_from: Option<&[String]>,
    ) -> Result<String> {
        // min_conf (params[2]) and include_delegated (params[4]) are read with
        // unguarded getters, so send the node's defaults rather than null;
        // comment is null-tolerant and subtract_fee_from is trailing.
        let mut params = vec![
            json!(""),
            json!(amounts),
            json!(min_conf.unwrap_or(1)),
            json!(comment),
            json!(include_delegated.unwrap_or(false)),
        ];
        if let Some(s) = subtract_fee_from {
            params.push(json!(s));
        }
        self.call("sendmany", params).await
    }

    /// New transparent exchange (EXM/EXT) address.
    pub async fn get_new_exchange_address(&self, label: Option<&str>) -> Result<String> {
        self.call("getnewexchangeaddress", vec![json!(label)]).await
    }

    /// Mark an in-wallet transaction abandoned so its inputs can be respent.
    /// The node returns null; success maps to `()`.
    pub async fn abandon_transaction(&self, txid: &str) -> Result<()> {
        self.call("abandontransaction", vec![json!(txid)]).await
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
                // fee=0 is identical to omitting the param: pivxd computes the
                // minimum fee (src/wallet/rpcwallet.cpp, "If nFee=0 leave the
                // default"). A null here would be rejected by AmountFromValue.
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

    /// Import a sapling spending key. `rescan`: `"yes"` | `"no"` |
    /// `"whenkeyisnew"` (default). `height` rescans from that block.
    pub async fn import_sapling_key(
        &self,
        key: &str,
        rescan: Option<&str>,
        height: Option<i64>,
    ) -> Result<ImportedSaplingKey> {
        // params[1] (rescan) is read with get_str() and params[2] (height)
        // with get_int() — both reject a null. When height is given without
        // rescan, substitute the node default so no interior null is sent.
        let mut params = vec![json!(key)];
        if rescan.is_some() || height.is_some() {
            params.push(json!(rescan.unwrap_or("whenkeyisnew")));
        }
        if let Some(h) = height {
            params.push(json!(h));
        }
        self.call("importsaplingkey", params).await
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
        // Same null-guarding as importsaplingkey: rescan via get_str(), height
        // via get_int(); substitute the node default for rescan when only
        // height is supplied so no interior null precedes it.
        let mut params = vec![json!(vkey)];
        if rescan.is_some() || height.is_some() {
            params.push(json!(rescan.unwrap_or("whenkeyisnew")));
        }
        if let Some(h) = height {
            params.push(json!(h));
        }
        self.call("importsaplingviewingkey", params).await
    }

    // ── Masternode ───────────────────────────────────────────────────────

    pub async fn get_masternode_count(&self) -> Result<i64> {
        self.call("getmasternodecount", vec![]).await
    }

    /// Legacy masternode list; `filter` matches address/txhash/status/etc.
    /// Returns the node's raw JSON; shape varies (deterministic vs legacy) and
    /// can be a string on edge cases.
    pub async fn list_masternodes(&self, filter: Option<&str>) -> Result<Value> {
        self.call("listmasternodes", vec![json!(filter)]).await
    }

    /// This node's masternode status (errors if the node isn't a masternode).
    /// Returns the node's raw JSON; shape varies (deterministic vs legacy) and
    /// can be a string on edge cases.
    pub async fn get_masternode_status(&self) -> Result<Value> {
        self.call("getmasternodestatus", vec![]).await
    }

    /// The masternode currently scheduled to be paid.
    /// Returns the node's raw JSON; shape varies (deterministic vs legacy) and
    /// can be a string on edge cases.
    pub async fn masternode_current(&self) -> Result<Value> {
        self.call("masternodecurrent", vec![]).await
    }

    // ── Deterministic MN (evo) ───────────────────────────────────────────

    /// Deterministic masternode list. All args optional (node defaults).
    ///
    /// The wire method is `protx_list` (a flat command in PIVX's evo RPC
    /// table, `src/rpc/rpcevo.cpp`), not a `protx` command with a `list`
    /// subcommand.
    pub async fn protx_list(
        &self,
        detailed: Option<bool>,
        wallet_only: Option<bool>,
        valid_only: Option<bool>,
        height: Option<i64>,
    ) -> Result<Value> {
        // Every positional arg is read with an unguarded get_bool()/get_int(),
        // so a null (from an omitted Option before a present one) is rejected —
        // substitute the node's own defaults. height is trailing/optional.
        let mut params = vec![
            json!(detailed.unwrap_or(true)),
            json!(wallet_only.unwrap_or(false)),
            json!(valid_only.unwrap_or(false)),
        ];
        if let Some(h) = height {
            params.push(json!(h));
        }
        self.call("protx_list", params).await
    }

    // ── Budget / governance ──────────────────────────────────────────────

    /// Budget proposal(s); `name` limits the result to one proposal.
    pub async fn get_budget_info(&self, name: Option<&str>) -> Result<Vec<BudgetProposal>> {
        self.call("getbudgetinfo", vec![json!(name)]).await
    }

    pub async fn get_budget_projection(&self) -> Result<Vec<BudgetProjection>> {
        self.call("getbudgetprojection", vec![]).await
    }

    // ── Staking / cold-staking (wallet) ──────────────────────────────────

    pub async fn get_staking_status(&self) -> Result<StakingStatus> {
        self.call("getstakingstatus", vec![]).await
    }

    pub async fn list_staking_addresses(&self) -> Result<Vec<StakingAddress>> {
        self.call("liststakingaddresses", vec![]).await
    }

    pub async fn get_cold_staking_balance(&self) -> Result<f64> {
        self.call("getcoldstakingbalance", vec![]).await
    }

    // ── Network / mempool / mining / util ────────────────────────────────

    pub async fn get_peer_info(&self) -> Result<Vec<PeerInfo>> {
        self.call("getpeerinfo", vec![]).await
    }

    pub async fn get_connection_count(&self) -> Result<i64> {
        self.call("getconnectioncount", vec![]).await
    }

    pub async fn get_network_info(&self) -> Result<NetworkInfo> {
        self.call("getnetworkinfo", vec![]).await
    }

    pub async fn get_mempool_info(&self) -> Result<MempoolInfo> {
        self.call("getmempoolinfo", vec![]).await
    }

    /// Txids currently in the mempool. For per-tx metadata use the verbose
    /// variant [`get_raw_mempool_verbose`](Self::get_raw_mempool_verbose).
    pub async fn get_raw_mempool(&self) -> Result<Vec<String>> {
        self.call("getrawmempool", vec![json!(false)]).await
    }

    /// Verbose `getrawmempool`: a map keyed by txid with per-tx metadata.
    /// Polymorphic like `getrawtransaction` — the non-verbose form is
    /// [`get_raw_mempool`](Self::get_raw_mempool).
    pub async fn get_raw_mempool_verbose(&self) -> Result<HashMap<String, MempoolEntry>> {
        self.call("getrawmempool", vec![json!(true)]).await
    }

    /// Estimated fee-per-kB for confirmation within `nblocks`; -1 if unknown.
    pub async fn estimate_fee(&self, nblocks: i64) -> Result<f64> {
        self.call("estimatefee", vec![json!(nblocks)]).await
    }

    /// `{ feerate, blocks }`; `feerate` is `-1.0` if not enough data.
    pub async fn estimate_smart_fee(&self, nblocks: i64) -> Result<EstimateSmartFee> {
        self.call("estimatesmartfee", vec![json!(nblocks)]).await
    }

    pub async fn get_mining_info(&self) -> Result<MiningInfo> {
        self.call("getmininginfo", vec![]).await
    }

    /// True if `signature` is a valid signing of `message` by `address`.
    pub async fn verify_message(
        &self,
        address: &str,
        signature: &str,
        message: &str,
    ) -> Result<bool> {
        self.call(
            "verifymessage",
            vec![json!(address), json!(signature), json!(message)],
        )
        .await
    }

    /// Coin supply totals (transparent + shield). `force_update` recomputes.
    pub async fn get_supply_info(&self, force_update: Option<bool>) -> Result<SupplyInfo> {
        self.call("getsupplyinfo", vec![json!(force_update)]).await
    }

    /// Aggregate stats over `range` blocks ending at `height`.
    pub async fn get_block_index_stats(&self, height: i64, range: i64) -> Result<BlockIndexStats> {
        self.call("getblockindexstats", vec![json!(height), json!(range)])
            .await
    }
}
