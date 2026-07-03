# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
