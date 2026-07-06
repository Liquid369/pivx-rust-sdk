#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Watch-only wallet asked to spend: load a spending key first.
    #[error("wallet is watch-only (viewing key): load a spending key to spend")]
    NoSpendAuthority,
    #[error("sapling prover not loaded: call a load_prover_* function first")]
    ProverNotLoaded,
    #[error("not enough balance")]
    InsufficientBalance,
    /// Local scan state diverged from the node's chain (shield: commitment
    /// tree vs the block's sapling root; transparent: parent-hash mismatch).
    /// Wallet state is stale/corrupt or the node is on another chain. Recover
    /// with the keyless `reload_from_checkpoint` (shield) or `reset_scan`
    /// (transparent wallet) and resync — no keys required.
    #[error("scan diverged at height {height}: local {local}, node {node}")]
    ScanDiverged {
        height: i64,
        local: String,
        node: String,
    },
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("blocks must be strictly ascending and above the last synced height")]
    NonAscendingBlocks,
    #[error("{0}")]
    Other(String),
    #[cfg(feature = "rpc")]
    #[error(transparent)]
    Rpc(#[from] pivx_rpc::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<Box<dyn std::error::Error>> for WalletError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        WalletError::Other(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, WalletError>;
