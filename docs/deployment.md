# Deployment guide

How to run these libraries safely in production. Read `SECURITY.md` first for
the trust model; this guide is about topology and operations.

## Which SDK for which job

The proving step (constructing the zero-knowledge proof for a shielded spend)
is the one heavy operation, and its performance decides the topology.

| Job | Use |
|---|---|
| Watch for deposits, track balances, scan the chain | `pivx-wallet` (JS or Rust). Scanning is I/O-bound and fast in both. |
| Build and prove withdrawals server-side | `pivx-wallet` **Rust**. Native proving is fast (a real shielded spend proves in seconds). |
| Build and prove in a browser | `pivx-wallet` **JS** with `proving: { multicore: true }`. Needs cross-origin isolation. |
| Query a node, node-wallet flows | `pivx-rpc` (JS or Rust). |

Do not prove shielded transactions with single-core WASM in Node for
production. It is not parallel and is far slower than native — use the Rust
SDK for server-side signing, or the multicore build in a browser.

A common exchange split: a Node service scans for deposits with `pivx-wallet`
(JS), and a separate Rust signer builds and proves withdrawals. Wallet state
is a shared JSON format, so the scanner can hand state to the signer.

## Node

- Run your own `pivxd`, or connect only to nodes you trust. The wallet does
  not validate proof-of-stake, so a hostile node can fabricate deposits
  (see `SECURITY.md`). Corroborate across independent nodes for high-value
  flows.
- Keep RPC on localhost or a private tunnel; it has no transport encryption.
- The wallet reads blocks at `getblock` verbosity 2. Default node limits (4
  RPC threads, work queue 16) are fine — the JS client bounds concurrent
  fetches; raise `rpcworkqueue`/`rpcthreads` only if you increase
  `rpcConcurrency`.

## Keys

- Hold spending keys and seeds on as few hosts as possible, encrypted at rest.
  They are never written to saved wallet state.
- Saved wallet state contains the viewing key: anyone with it can read the
  wallet's transaction history. Protect it like customer data.
- A watch-only deposit service needs only the viewing key, so keep spend
  authority off the internet-facing host entirely.

## Proving parameters

- Shielded spending needs the sapling parameters (~50 MB). Provision them
  once and load from disk (`loadProver({ path })` / `load_prover_from_path`).
- Or load from raw bytes, or let the SDK download from the PIVX Labs mirrors
  (SHA-256 pinned). Cache them; do not download per process.

## Initial sync

- A fresh wallet self-heals to the newest node-confirmed checkpoint and scans
  forward. Today that is a few hundred thousand blocks (a few minutes); it
  shortens automatically as newer valid checkpoints ship.
- Persist wallet state (`save()`) after each sync so restarts resume instead
  of rescanning.

## Confirmations and reconciliation

- Never credit a deposit from a single block or from `previewTransaction`.
  Choose a confirmation depth for your risk model (PIVX targets 60-second
  blocks).
- Reconcile against confirmed notes, not watch-only balances (an incoming
  viewing key cannot see spends and can over-report).

## Spending operationally

- One writer per wallet: never run two syncs, or a sync and a spend, on the
  same wallet instance at once.
- After a crash between broadcast and finalize, wait for the transaction to
  confirm or clearly disappear, sync, then resume — do not force a second
  send of the same notes.
- For exact payouts leave fee headroom above the amount; only use sweep mode
  when intentionally emptying a balance.
- If sync raises a divergence error, call `reloadFromCheckpoint` and re-sync.
