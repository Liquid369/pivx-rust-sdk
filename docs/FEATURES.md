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
  - Masternodes: `getMasternodeCount`, `listMasternodes`,
    `getMasternodeStatus`, `masternodeCurrent`; deterministic (evo)
    `protxList`.
  - Budget/governance: `getBudgetInfo`, `getBudgetProjection`.
  - Staking: `getStakingStatus`, `listStakingAddresses`,
    `getColdStakingBalance`.
  - Net, mempool, mining, and util: `getPeerInfo`, `getConnectionCount`,
    `getNetworkInfo`, `getMempoolInfo`, `getRawMempool`, `estimateFee`,
    `estimateSmartFee`, `getMiningInfo`, `verifyMessage`, `getSupplyInfo`,
    `getBlockIndexStats`. Note: `getmininginfo` requires a daemon compiled
    with `--enable-mining-rpc`, which is off in standard release builds.
- Method names are camelCase in JS, snake_case in Rust
  (`getMasternodeCount` / `get_masternode_count`). Typed methods cover the
  common surface; the generic `call` still reaches any of the node's 224 RPCs.
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

## pivx-wallet — transparent wallet

A standalone HD wallet for PIVX's transparent (non-shielded, UTXO) funds —
the transparent counterpart to the shield wallet above, built from the same
kind of seed. No proving parameters are involved: transparent sends are plain
ECDSA-signed legacy transactions. Amounts are integer satoshis.

### Addressing and keys

- BIP44 HD derivation, `m/44'/119'/account'/change/index` (PIVX coin type
  119 mainnet, 1 testnet; `change` 0 = receive, 1 = internal change).
  `deriveKey(seed, network, account, change, index)` returns the key pair,
  its address, and a WIF at that path. (Rust: `derive_key`.)
- `p2pkhAddress(pubkey, network)` turns a public key into its base58 address;
  `encodeAddress(hash, network, kind)` / `decodeAddress(address)` round-trip a
  raw hash160, and `isValidAddress(address)` validates. These are independent
  of any wallet instance. (Rust: `p2pkh_address`, `encode_address`,
  `decode_address`, `is_valid_address`.)
- `decodeAddress` reports the address kind — P2PKH, P2SH, cold-staking, or
  exchange — with its network. Rust models this as the `AddressKind` enum
  (`P2pkh`, `P2sh`, `Staking`, `Exchange`).

### TransparentWallet

- `TransparentWallet.create(seed, network, account, gap)` derives `gap`
  external and `gap` change addresses over one BIP44 account; only outputs to
  those addresses are recognized. (Rust:
  `TransparentWallet::new(seed, network, account, gap)`.)
- `newAddress()` hands out the next unused external receive address, up to the
  gap limit. (Rust: `new_address`.)
- PIVX has no address index, so incoming coins are discovered two ways — both
  supported:
  - Block scan: `scanBlock(block)` credits the outputs of a decoded block
    (`getblock <hash> 2`) that pay this wallet — through a standard 25-byte
    P2PKH script or the 26-byte `OP_EXCHANGEADDR` exchange script — and drops
    UTXOs it spends; `sync(client, { fromHeight, batchSize })` walks the chain
    from a height to the tip and scans each block. In JS only one `sync` runs
    at a time; a concurrent call throws (the shield wallet's busy guard).
    (Rust: `scan_block`; `sync(client, from_height, batch_size)`.)
  - Caller-supplied: `addUtxo(txid, vout, amount, scriptPubKey)` registers a
    UTXO you already know about (e.g. from your own indexer), returning whether
    it pays this wallet. (Rust: `add_utxo`.)
- `balance()` totals tracked unspent value in satoshis, excluding outpoints
  reserved by `buildSend`; JS `getUtxos()` / Rust `utxos()` list all tracked
  outputs, reserved ones included. (Rust: `balance`.)

### Sending

- `buildSend(to, amount, feePerByte)` selects UTXOs largest-first, builds and
  ECDSA-signs a legacy (v1) transaction, and sends change to a fresh internal
  change address. It returns the raw tx hex and the list of spent outputs
  (`{ hex, spent }`; Rust: `build_send` → `(hex, spent)`). `feePerByte`
  defaults to 100 sats/byte and the fee is size-based; amounts are satoshis.
- `buildSend` reserves the UTXOs it selects: a second send cannot
  double-spend them before broadcast, and `balance()` excludes them.
  Broadcast the hex through `pivx-rpc` (`sendRawTransaction`), then call
  `markSpent(spent)` to finalize — it drops the consumed UTXOs and their
  reservation. After a definitively rejected broadcast, `release(spent)`
  makes the inputs selectable again; a transport or timeout failure is
  ambiguous (the node may have accepted the transaction), so keep the
  reservation until the txid confirms or clearly disappears — the same
  rule as the shield wallet's discard-only-on-`RpcError`. (Rust:
  `mark_spent`, `release`.)
- Coin selection rejects a send that cannot cover amount + fee rather than
  underpaying. The send path is verified against real mainnet transactions.
- `buildSend` validates the destination up front: it rejects an address from
  the wrong network (a mainnet wallet will not build a send to a testnet
  address, and vice versa), a cold-staking address, an `amount` below the
  node's dust threshold (5460 sats for a standard output), and a non-positive
  `feePerByte`. Change below the dust threshold is folded into the fee rather
  than emitted as a dust output the node would reject.
- Coinbase and coinstake outputs discovered by `scanBlock` are tracked with
  their block height and are not selected for spending until they are
  `nCoinbaseMaturity` blocks deep (100 mainnet, 15 testnet), matching the
  node's maturity rule; caller-supplied UTXOs (`addUtxo`) are assumed mature.

### Persistence and recovery

- `save()` / `load(seed, state)`: versioned JSON state (version 1, camelCase
  fields) holding the address cursors, the UTXO set (with coinbase heights),
  reservations (pending spends), and the last-scanned height and block hash.
  No key material is included; `load` re-derives keys from the seed and
  rejects a state that does not belong to it. `save()` output is
  byte-identical across the JS and Rust SDKs — a state saved by one loads in
  the other, and both test suites byte-compare a shared fixture. (Rust:
  `save` / `load(seed, state)`.)
- `scanBlock` verifies parent-hash continuity when a block claims to extend
  the last scanned one (height exactly one higher) and raises the divergence
  error (`ScanDivergedError` / `WalletError::ScanDiverged`) before mutating
  any state: the chain reorganized under the wallet. Breaking change from
  0.1: JS `scanBlock` now throws in this one case, and Rust `scan_block` now
  returns `Result`.
- `resetScan(height)` is the recovery path after a divergence: it drops
  scanned UTXOs above `height` along with their reservations, keeps
  caller-supplied ones, and resets the scan position so the wallet can
  re-sync from below the fork point. (Rust: `reset_scan`.)

### Exchange addresses

- PIVX exchange addresses (`EXM` on mainnet, `EXT` on testnet) encode the
  same hash160 as a P2PKH address behind an `OP_EXCHANGEADDR` (`0xe0`) prefix
  on an otherwise standard P2PKH script. `decodeAddress` / `isValidAddress`
  recognize and validate them (Rust: `AddressKind::Exchange`).
- Sending to an exchange address is supported: `buildSend` accepts one as a
  destination and emits the 26-byte prefixed script. (Sending to a
  cold-staking address is rejected.)
- Receiving on an exchange address is supported: the wallet recognizes
  deposits paying its keys through the 26-byte exchange script as well as
  plain P2PKH — both `scanBlock` and `addUtxo` credit them, and the UTXOs
  spend like any other. `newExchangeAddress()` hands out the next external
  index encoded as an exchange address (Rust: `new_exchange_address`); it
  shares the cursor and key with `newAddress`, so the same index's P2PKH
  form also pays the wallet. Verified on mainnet: a deposit to an exchange
  address was detected by a real block scan and the received output spent,
  accepted by the network.

## Runtime notes

- JS: Node 20.19+, ESM; browser-compatible (bundler required for WASM;
  multicore proving needs cross-origin isolation). `pivx-rpc` has no
  runtime dependencies.
- Rust: async (`reqwest`/`tokio`); the `rpc` feature (default on) provides
  node-driven sync and broadcast and can be disabled to bring your own
  transport.
- Units: `pivx-rpc` uses PIV; `pivx-wallet` uses integer satoshis.
