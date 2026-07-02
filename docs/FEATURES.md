# Feature list

The PIVX SDK ships in JavaScript and Rust with matching capabilities. Each
language has two layers: `pivx-rpc` (a typed node client) and `pivx-wallet`
(a standalone, key-owning wallet). Unless noted, every feature exists in both
languages.

## pivx-rpc — node client

- Typed JSON-RPC client for `pivxd` over HTTP.
- Authentication by RPC user/password or by the datadir `.cookie` file
  (Rust: `Auth::CookieFile`; JS: pass the parsed credentials).
- Multiwallet routing via the `/wallet/<name>` URL path.
- Configurable request timeout; response-size cap to protect against a
  hostile node returning an oversized body (JS).
- Errors separate the node's own JSON-RPC error (with its numeric code)
  from transport failures, so callers can retry connection errors without
  retrying rejected requests.
- Generic `call(method, params)` escape hatch for any RPC not wrapped below.
- Typed methods:
  - Blockchain: `getBlockCount`, `getBestBlockHash`, `getBlockHash`,
    `getBlock` (verbosity 0/1/2), `getBlockchainInfo`, `getRawTransaction`,
    `sendRawTransaction`.
  - Transparent wallet: `getBalance`, `getNewAddress`, `listUnspent`,
    `sendToAddress`, `getTransaction`, `getWalletInfo`, `validateAddress`.
  - Shield: `getNewShieldAddress`, `listShieldAddresses`, `getShieldBalance`,
    `listShieldUnspent`, `listReceivedByShieldAddress`, `shieldSendMany`,
    `rawShieldSendMany`, `viewShieldTransaction`, `getSaplingNotesCount`.
  - Sapling keys: `exportSaplingKey`, `importSaplingKey`,
    `exportSaplingViewingKey`, `importSaplingViewingKey`.
- `ShieldWatcher`: poll-based monitor over the node wallet's shielded notes.
  Emits new-note, spent, and balance-change events (JS `EventEmitter`; Rust
  returns events from `poll()` so the caller drives the cadence). Does not
  crash the process when no error handler is attached (JS).
- Amounts are PIV as the node emits them (decimal `number` / `f64`).

## pivx-wallet — standalone wallet

The application holds the keys; the node is only a source of blocks and a
broadcast relay.

### Key management and capability model

- Construct from a 32-byte seed (ZIP32, PIVX coin type 119), an extended
  spending key, or an extended full viewing key.
- Capability follows the key material:
  - seed or spending key → scan, derive addresses, balance, and spend.
  - viewing key → scan, derive addresses, balance (watch-only); cannot spend.
- Watch-only wallets upgrade in place with `loadSpendingKey`, which rejects a
  key that does not match the wallet's viewing key.
- Diversified receive addresses (`getNewAddress`); all decrypt under the same
  keys, so a fresh address per deposit is free.
- Spending keys and seeds are never serialized, logged, or placed in error
  messages.

### Scanning and balances

- Block scanning with trial-decryption of shielded notes, incremental merkle
  tree maintenance, and per-note witness tracking.
- Bundled sync checkpoints (height → committed tree) so a new wallet skips
  years of history and starts near its birth height.
- Checkpoint self-validation: the starting checkpoint is confirmed against
  the node's sapling root, and the wallet rewinds to the newest checkpoint
  the node confirms if a bundled entry is stale. Self-corrects around bad
  checkpoint data.
- `sync(client)`: walks from the last synced block to the node's tip,
  fetching blocks with bounded concurrency (JS), verifying the local tree
  against each block's `finalsaplingroot`, and rolling back a batch on any
  mismatch rather than persisting partial state.
- `handleBlocks(blocks)`: feed blocks from your own source (indexer, ZMQ)
  instead of the built-in sync; heights must be strictly ascending.
- Only version-3 (sapling) transactions are fed to the scanner; other
  transactions are skipped.
- Confirmed balance and unspent-note listing, in satoshis.
- `previewTransaction(hex)` (JS only): trial-decrypt a single transaction's
  outputs without touching wallet state, for mempool hints (does not validate
  the transaction).
- Nullifier → note attribution lookup, for reconciling spends.

### Spending

- Build, prove, and broadcast shielded transactions locally.
- Shield-to-anything sends and transparent-to-shield shielding (spend
  transparent UTXOs into a shield address, with transparent change).
- Memos on shield recipients (validated to 512 bytes).
- Fee is size-based (matches the node's model). By default a send that would
  leave no room for the fee is rejected rather than silently underpaying the
  recipient; sweep semantics are opt-in (`sweep` / `subtract_fee_from_amount`).
- Amount and memo validation up front; all fee/amount arithmetic is
  overflow-checked.
- Pending-spend tracking: notes committed to a broadcast transaction are held
  until finalized or discarded, and this survives save/load so a crash cannot
  resurrect spent notes into a double-spend.
- `send(client, opts)` builds, broadcasts, and settles in one call, or use
  `createTransaction` + your own broadcast + `finalizeTransaction` /
  `discardTransaction`.
- Proving parameters load from a directory, raw bytes, or a SHA-256-pinned
  download from the PIVX Labs mirrors.
- Proving backends:
  - JavaScript: single-core WASM by default; opt-in multicore WASM with a
    configurable thread count for browsers (needs cross-origin isolation).
  - Rust: native proving (fast; the right choice for server-side throughput).

### Persistence and recovery

- `save()` / `load()`: versioned JSON wallet state (viewing key, sync
  position, commitment tree, notes, pending spends). The format is identical
  across the JS and Rust SDKs — a wallet saved by one loads in the other.
- `reloadFromCheckpoint(height)`: reset scan state to a checkpoint and drop
  tracked notes; the recovery path after a divergence error. Needs no keys.
- `sync` raises a divergence error (`ScanDivergedError` /
  `WalletError::ScanDiverged`) if the local tree stops matching the node,
  instead of corrupting witnesses.

### Concurrency

- One writer per wallet: Rust enforces this through `&mut`; JS guards sync
  and spend at runtime so overlapping calls fail fast instead of corrupting
  state.

## Runtime notes

- JS: Node 18+ and browsers, ESM, `pivx-rpc` has no runtime dependencies.
- Rust: async (`reqwest`/`tokio`); the `rpc` feature (default on) provides
  node-driven sync and broadcast and can be disabled to bring your own
  transport.
- Units: `pivx-rpc` uses PIV; `pivx-wallet` uses integer satoshis.
