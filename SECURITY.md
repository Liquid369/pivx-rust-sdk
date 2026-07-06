# Security model

This SDK moves real money. Read this before integrating.

## What the standalone wallet does and does not verify

The `pivx-wallet` layer holds keys locally and uses a `pivxd` node for chain
data (blocks) and broadcast. It **decrypts and tracks** shielded notes; it
does **not** verify that the blocks it is fed belong to the real,
proof-of-stake-secured PIVX chain.

The only integrity check during sync is comparing the locally-computed
sapling commitment-tree root against the `finalsaplingroot` in the block
header returned by the node. That is a **self-consistency** check: it
confirms the local tree matches *the root the same node reported*. It is
**not authentication** — it does not prove the blocks are real, canonical,
or the most-work/most-stake chain.

### Consequence: the node is a trust anchor

A malicious or compromised node can:

- **Fabricate a deposit.** Deposit addresses are shared with payers, so an
  attacker who knows one can craft a syntactically valid shielded output
  paying that address any amount, put it in a fabricated block, and report a
  matching `finalsaplingroot`. The wallet decrypts it and counts it as
  received. If you release funds or goods on that apparent deposit, you lose
  real money.
- **Hide a real deposit** by omitting the transaction, or **stall sync** by
  reporting a low tip.

The SDK closes the *cheap* versions of these (it uses the block height it
requested rather than the node's echo, treats a missing `finalsaplingroot`
or a transaction missing its hex as hard errors, and rolls back scan state
if the root check fails), but it cannot close the fundamental one: without
PoS/header validation, a node that lies self-consistently is believed.

## Integrator requirements

1. **Use a node you control**, or corroborate across multiple independent
   nodes before crediting. Do not point a hot wallet at an arbitrary public
   RPC endpoint.
2. **Require confirmations.** Never credit a deposit from a single block or
   from `previewTransaction` (mempool preview does no validation at all —
   it only trial-decrypts, and gives no txid to dedupe on). Pick a
   confirmation depth for your risk model; PIVX targets 60-second blocks.
3. **Run the node and the RPC link on localhost or a private tunnel.** RPC
   has no transport encryption and uses HTTP Basic auth.
4. **Reconcile balances against confirmed notes**, not against watch-only
   balances (an incoming viewing key cannot see spends, so a watch-only
   balance can over-report).

## Key handling

- Spending keys and seeds are never serialized by `save()`, never logged,
  and never placed in error messages. Store the spending key separately from
  saved wallet state, encrypted, on as few hosts as possible.
- Saved wallet state (`save()` output) contains the **viewing** key. Anyone
  holding it can decrypt this wallet's entire transaction history. Protect it
  like customer data.
- **Saved-state integrity is theft-critical for a watch-only deposit
  scanner.** An attacker who can modify the state file could swap in their own
  viewing key so `getNewAddress` derives deposit addresses they control. Load
  such wallets with the expected key — `load(json, { expectedViewingKey })`
  (JS) / `load_verified(json, key)` (Rust) — and store the state with
  integrity protection.

## Spending safety

- **Fees are not silently taken from the recipient**, on either the shield
  or the transparent-input path. A send whose inputs cover the amount but not
  amount + fee returns an error unless you opt into sweep semantics
  (`subtractFeeFromAmount` in JS — the deprecated `sweep` alias still works —
  or `subtract_fee_from_amount` in Rust). For exact payouts, leave fee
  headroom (a typical shield spend costs ~0.024 PIV).
- **Dust notes are purged on scan, not spent.** A note worth no more than its
  own input fee is never selected for spending, and each scan pass drops such
  notes from tracked state, so an attacker cannot freeze withdrawals or bloat
  wallet state by flooding a deposit address with dust. One caveat: sub-dust
  notes carried in an older saved state still count toward the balance until
  the next scan purges them.
- **Pending spends are only as durable as your last save.** Notes and
  transparent UTXOs committed to a broadcast-but-unconfirmed transaction are
  held pending and survive `save()`/`load()`, so restarting cannot resurrect a
  spent input into a double-spend — *provided the restored state was saved
  after the spend was built and broadcast*. The wallet is a library: `save()`
  returns state on demand and the caller owns when it is persisted, so a crash
  between a successful broadcast and persisting the post-send state falls back
  to older state that does not know the input is spent, and a retry
  double-spends it. Persist wallet state after building and again after
  broadcasting — ideally as one atomic reserve → build → save → broadcast →
  reconcile step against your own storage and locking. On a transport or
  timeout error the SDK deliberately keeps the spend pending (it discards only
  on a definitive node rejection), so retry logic must not resurrect it: wait
  for the in-flight txid to confirm or clearly disappear, sync, then resume —
  do not force a second send of the same input.
- **Caller-supplied UTXOs are trusted as mature and spendable.** `addUtxo`
  (JS) / `add_utxo` (Rust) registers a transparent UTXO as a normal spendable
  output: it checks only that the script pays one of this wallet's keys (the
  P2PKH or exchange-script hash), and does not verify confirmations,
  coinbase/coinstake maturity, or anything more about the source. If you feed
  UTXOs from your own indexer, enforce confirmation depth and coinbase/
  coinstake maturity yourself before adding them. UTXOs discovered by the SDK's
  own block scan (`scanBlock`/`scan_block`, `sync`) are maturity-tracked and
  are the safer path.
- **One writer per wallet.** Do not run two syncs, or a sync and a spend,
  concurrently on one wallet instance. (Rust enforces this via `&mut`; JS
  guards it at runtime.)

## Recovery

If sync reports a sapling-root divergence (`ScanDivergedError` in JS,
`WalletError::ScanDiverged` in Rust) — a reorg crossed a batch boundary, the
node lied, or saved state is corrupt — call `reloadFromCheckpoint(height)`
(JS) / `reload_from_checkpoint(height)` (Rust) and re-sync. This resets scan
state to a checkpoint and rescans; it needs no keys.

Recovery drops **pending spends** along with the tracked notes. Reconcile
in-flight broadcasts first — `pendingTransactions()` (JS) /
`pending_transactions()` (Rust) lists them — and wait for each txid to
confirm or clearly disappear before recovering. Retrying a spend after
recovery while the old transaction is still unconfirmed is a double-spend
risk: the reloaded state no longer knows those notes are committed.

On each sync the transparent wallet revalidates its last-scanned block hash and
self-heals on a same-height tip reorg by re-scanning a window, whereas the
shield wallet raises the divergence above for you to recover from — but require
confirmations before crediting either way, since a same-block reorg at the tip
is only caught on the next sync.

## Cryptography provenance

The shielded cryptography is not reimplemented here. It is PIVX Labs'
`pivx-shield` engine on the `librustpivx` (librustzcash fork) crates — the
JS SDK loads its WASM build, the Rust SDK vendors the same core natively.
Sapling proving parameters are SHA-256-pinned against known digests
regardless of download source.

## Reporting

Report vulnerabilities in this SDK privately — email
[liquid369@gmail.com](mailto:liquid369@gmail.com) or open a private GitHub
security advisory on this repository — rather than a public issue.
Consensus-level or `librustpivx` issues belong upstream.
