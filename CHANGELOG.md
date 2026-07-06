# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-07-06

Release of a full-repo audit cycle: `pivx-rpc` 0.7.0, `pivx-wallet` 0.7.0.

### Fixed

- `pivx-rpc`: `get_masternode_count` deserializes the node's real result
  object into a new `MasternodeCount` struct — the previous `Result<i64>`
  could never deserialize a live node's reply. The node's bare-string
  `"unknown"` (no chain tip) maps to a labeled `Error::Rpc`. **Breaking.**
- `pivx-rpc`: `view_shield_transaction` now works against a live node —
  `fee` is the money-formatted string pivxd emits and spend/output values
  deserialize into a `ShieldTxValue` enum (`Piv(f64)` | `Unknown`);
  `value_sat` remains the reliable integer. **Breaking** type change.
- `pivx-rpc`: `Auth`'s `Debug` implementation redacts the RPC password;
  `WalletInfo`'s conditionally-emitted balances are `Option<f64>` instead of
  silently defaulting to `0.0`; JSON-RPC response ids are verified; URLs
  carrying credentials are rejected at construction with guidance to use
  `Auth`.
- `pivx-rpc`: sapling key imports that trigger a rescan use a 10-minute
  per-request timeout, so the client no longer times out at 30 s on an
  import the node completes (and then fails retries with "Wallet is
  currently rescanning").
- `pivx-rpc`: `WatchOptions::default()` now polls with `min_conf` 1,
  matching the JS SDK's default; an explicit `0` still includes unconfirmed
  notes. **Breaking** for code relying on the old 0-conf default.
- `pivx-rpc`: `WatchOptions`'s inverted `exclude_watch_only` flag is renamed
  to `include_watch_only` (default `true`), matching the JS SDK's polarity so
  watch-only notes are polled by default; pass `include_watch_only: false` to
  exclude them. **Breaking** rename.
- `pivx-wallet` transparent: transactions are capped below PIVX's 100 kB
  standard-size limit (estimate during selection plus the actual serialized
  bytes before any reservation); fee arithmetic is overflow-checked; fee
  rates below the node's 10 sat/byte relay floor are rejected; coinstake
  detection matches the node (zero value **and** empty script).
- `pivx-wallet` transparent: everything the wallet persists it can load
  again — `add_utxo` and block scanning validate inputs with `load()`'s own
  predicates (including the cross-SDK 2^53−1 amount/height bounds),
  re-scanning a block can no longer produce a scanned-hash window `load()`
  rejects, and `reset_scan` validates its height and returns `Result`.
  **Breaking** signature change.
- `pivx-wallet` transparent: UTXO reservations survive `reset_scan`, so a
  reorg walk-back can no longer allow the same output to be selected twice
  while a broadcast is in flight.
- `pivx-wallet` shield: below Sapling activation, version-3 transactions are
  excluded from scanning (fabricated shielded data is never credited)
  without failing on consensus-legal data; `send()` keeps the pending spend
  when the node's reply means the transaction was accepted or the notes are
  contested (`already in block chain`, `bad-txns-nullifier-double-spent`,
  `bad-txns-shielded-requirements-not-met`); a failed `plan_transaction` no
  longer advances the diversifier index; and `reload_from_checkpoint` rejects
  an out-of-range height and returns `Result` instead of clamping it on the
  `i32` conversion. **Breaking** signature change.

### Added

- `pivx-wallet`: `spendable_balance()` — the maturity- and reservation-aware
  balance, alongside `balance()`.
- `pivx-rpc`: `raw_shield_send_many` accepts optional `min_conf`/`fee`
  (wire parity with the JS SDK). **Breaking** signature change.
- `pivx-wallet` transparent: `build_transparent_tx` honors a non-zero
  locktime by setting non-final input sequences.
- Test suites covering batch rollback with credited notes, checkpoint
  walk-back adoption, crash-recovery reconciliation, reorg re-credit,
  send-error branches, memo round-trips, the decrypt-time `Rseed` variant,
  and hostile-input state handling.
- CI: `cargo fmt --all -- --check` gate.

## [0.6.2] - 2026-07-05

### Fixed

- `pivx-wallet`: the tip sapling-root check now runs at exact checkpoint
  heights, not only above them, so a same-height reorg landing on a bundled
  checkpoint is caught.
- `pivx-wallet`: the tip-root and batch-scan root checks are skipped below
  Sapling activation, where the node reports a zero root against the non-zero
  empty tree (matching the checkpoint validator). The crate now uses the
  consensus V5 activation heights (mainnet 2700500, testnet 201) and fetches
  the tip root with `getblock` verbosity 1.
- `pivx-wallet` transparent wallet: `build_send` is refused while a sync is in
  progress, so a spend cannot reserve a UTXO a concurrent reorg reset is
  about to drop.
- `pivx-wallet` transparent wallet: the scanned-hash window is validated on
  load (bounded, strictly ascending, no future heights), so malformed state
  cannot misdirect the reorg walk-back.

## [0.6.1] - 2026-07-04

### Fixed

- `pivx-wallet`: same-height chain reorgs are now detected. Each sync
  revalidates the last-scanned block hash; the transparent wallet walks a
  persisted hash window to the true fork and self-heals (re-scanning), or
  returns `WalletError::ScanDiverged` when the reorg is deeper than the window
  rather than silently retaining orphaned UTXOs. The shield wallet returns
  `ScanDiverged` on a tip sapling-root mismatch (recover with
  `reload_from_checkpoint`). Require confirmations before crediting.
  (The Rust wallet uses `&mut self` for spends, so the JS SDK's concurrent
  `createTransaction` race does not apply here.)

## [0.6.0] - 2026-07-04

### Added

- `pivx-rpc`: ZMQ push notifications. `parse_zmq_frame` is a pure decoder for
  pivxd's 3-part multipart message (topics `hashblock`, `hashtx`, `rawblock`,
  `rawtx`) — bring your own socket; always compiled. `ZmqSubscriber`
  (`connect` + `recv`) is a convenience over the pure-Rust `zeromq` crate,
  behind an off-by-default `zmq` cargo feature (no system libzmq), so default
  builds pull nothing. Typed events carry the block/tx hash or raw bytes plus a
  little-endian sequence. Typical use: trigger a wallet sync on each new block.

## [0.5.0] - 2026-07-03

### Added

- `pivx-rpc`: typed return structs for 12 methods that previously returned
  `serde_json::Value` — `get_network_info`, `get_peer_info`, `get_mempool_info`,
  `get_raw_mempool` (+ new `get_raw_mempool_verbose`), `get_supply_info`,
  `get_block_index_stats`, `get_mining_info`, `estimate_smart_fee`,
  `get_budget_info`, `get_budget_projection`, `get_staking_status`,
  `list_staking_addresses`. Each struct keeps a `#[serde(flatten)]` catch-all so
  unmodeled node fields are preserved.
- `pivx-rpc`: `PivxClient` is now cheaply `Clone` — clones share the connection
  pool, request-id counter, and credential store, so a `.cookie` refresh on one
  clone is visible to all (convenient for sharing across tokio tasks).

### Changed

- `pivx-rpc`: the `Error` enum is `#[non_exhaustive]`; match it with a `_ =>`
  arm. The three masternode methods stay `serde_json::Value` on purpose — their
  shape is polymorphic and cannot be typed safely.
- `pivx-rpc`: request JSON now serializes object keys in declaration order
  (`serde_json` `preserve_order`); omitted optional params on `list_transactions`
  et al. and on `import_sapling_key`/`import_sapling_viewing_key`/`protx_list`
  are sent as the node's defaults, never a null the node would reject.

### Notes

- `pivx-rpc` is at 0.4.0 (its own semver). Return-type changes and the
  `#[non_exhaustive]` error are breaking, hence the minor bump.

## [0.4.0] - 2026-07-03

### Added

- `pivx-rpc`: batch JSON-RPC — `client.call_batch(&[(method, params), ...])`
  runs several calls in one HTTP round-trip, returning a `Vec` of per-call
  `Result` in request order; a per-call error does not fail the batch.
- `pivx-rpc`: typed methods for the exchange deposit/withdrawal workflow —
  `list_since_block` (reorg-safe deposit cursor), `list_transactions`,
  `send_many`, `get_new_exchange_address`, `abandon_transaction`, `get_tx_out`,
  `get_block_header`, `get_chain_tips`, `create_raw_transaction`,
  `decode_raw_transaction`, `sign_raw_transaction`, and
  `get_raw_transaction_verbose` (typed decoded object with confirmations for a
  non-wallet txid with `-txindex`).

### Changed

- `pivx-rpc`: `get_transaction` and `validate_address` now return typed structs
  instead of `serde_json::Value` (breaking, hence `pivx-rpc` 0.3.0).

## [0.3.0] - 2026-07-03

### Added

- `pivx-wallet`: `prune_nullifiers()` — opt-in, drops nullifier-attribution
  entries for notes that are neither tracked-unspent nor pending; call after
  reconciling. Sub-dust notes (≤ 384000 sats) are now also skipped in
  attribution and purged from tracked state, bounding growth under a dust flood
  (parity with the JS SDK).
- `pivx-rpc`: cookie-file auth now re-reads `.cookie` and retries once on HTTP
  401 when the credentials rotated (node restart); a 403 is not retried.
- `pivx-rpc`: `Error::Auth` (HTTP 401/403), `Error::Http`, and
  `Error::ResponseTooLarge` as distinct, matchable errors; response bodies are
  capped (default 64 MiB, `with_max_response_size`).

### Changed

- `pivx-wallet`: `ShieldWallet::send()` now runs Groth16 proving on
  `tokio::task::spawn_blocking`, so a send no longer stalls the async runtime.
  `create_transaction` still proves inline (CPU-blocking) for callers that
  broadcast themselves — wrap it in `spawn_blocking` on an async runtime.
- `pivx-rpc`: `ShieldWatcher` balance-change detection compares integer
  satoshis (round-then-sum), matching the JS SDK, so floating-point note
  amounts cannot fire a spurious balance event.

## [0.2.0] - 2026-07-02

### Added

- `pivx-wallet` transparent wallet: `save()`/`load(seed, state)` — versioned
  JSON state (cursors, UTXO set, reservations, scan position), byte-identical
  across the Rust and JS SDKs; no key material in the file, and load rejects
  a state that does not belong to the seed or pairs a script with the wrong
  key hash.
- `pivx-wallet` transparent wallet: exchange-address receiving — deposits
  paying the wallet through the 26-byte `OP_EXCHANGEADDR` script are
  recognized, and `new_exchange_address()` hands out the next external key
  EXM-encoded (mainnet-verified end to end).
- `pivx-wallet` transparent wallet: reorg detection — `scan_block` checks
  parent-hash continuity and returns `WalletError::ScanDiverged` before
  mutating state; `reset_scan(height)` recovers. `sync` rejects blocks
  missing `hash`/`previousblockhash`.
- `pivx-wallet` transparent wallet: UTXO reservation — `build_send` reserves
  its inputs until `mark_spent` or `release`; `balance()` excludes reserved
  outpoints.

### Changed

- **Breaking**: `scan_block` now returns `Result<(), WalletError>`.
- `WalletError::ScanDiverged` message generalized (no longer
  sapling-specific).

## [0.1.0] - 2026-07-02

### Added

- `pivx-rpc`: typed async JSON-RPC client for `pivxd` — 48 typed methods
  across blockchain, wallet, shield, masternode, staking, budget, network,
  mempool, mining, and util surfaces, plus a generic `call` for everything
  else.
- `pivx-rpc`: node errors (`Error::Rpc` with the node's code) separated from
  transport failures; poll-based `ShieldWatcher` for node-wallet monitoring.
- `pivx-wallet`: standalone shield (SHIELD/Sapling) wallet — ZIP32 key
  derivation, block scanning with note decryption, checkpointed sync
  verified against `finalsaplingroot`, natively-proved shielded spends.
- `pivx-wallet`: watch-only wallets from a viewing key (scan, receive,
  balance), upgradeable in place with a spending key.
- `pivx-wallet`: `save()`/`load()` of versioned JSON wallet state, pending
  spends included; the format is interchangeable with the JS SDK.
- `pivx-wallet`: transparent HD wallet — BIP44 derivation (coin type 119),
  block-scan or supplied-UTXO receive, ECDSA-signed legacy sends, exchange
  (`EXM`/`EXT`) address support.
