use std::collections::HashMap;

use crate::client::{PivxClient, Result};
use crate::types::ShieldNote;

/// Change observed in the wallet's shielded note set.
#[derive(Debug, Clone, PartialEq)]
pub enum ShieldEvent {
    /// A shielded note appeared (incoming funds, or change).
    Note(ShieldNote),
    /// A previously-seen note is no longer unspent.
    ///
    /// Watch-only caveat: with only incoming viewing keys imported, the node
    /// cannot detect spends, so these only fire for addresses whose spending
    /// key is in the wallet.
    Spent(ShieldNote),
    /// Total shield balance changed.
    Balance { current: f64, previous: f64 },
}

/// Options for [`ShieldWatcher`].
#[derive(Debug, Clone, Default)]
pub struct WatchOptions {
    /// Only consider notes with at least this many confirmations (0 → node default of 1).
    pub min_conf: i64,
    /// Restrict watching to these shield addresses. Empty = all wallet addresses.
    pub addresses: Vec<String>,
    /// Exclude watch-only (viewing key) addresses. Default includes them — that's the point.
    pub exclude_watch_only: bool,
}

/// PIV → integer sats, so balance change detection is immune to f64
/// summation noise (events still carry the PIV f64 values).
fn to_sats(piv: f64) -> i64 {
    (piv * 1e8).round() as i64
}

/// Diffable note-set state: the first `apply` primes without events.
#[derive(Default)]
struct NoteDiff {
    notes: HashMap<(String, u32), ShieldNote>,
    balance: f64,
    balance_sats: i64,
    primed: bool,
}

impl NoteDiff {
    fn apply(&mut self, notes: Vec<ShieldNote>) -> Vec<ShieldEvent> {
        let current: HashMap<(String, u32), ShieldNote> = notes
            .into_iter()
            .map(|n| ((n.txid.clone(), n.outindex), n))
            .collect();
        let balance: f64 = current.values().map(|n| n.amount).sum();
        // Round each note to sats then sum (not sum-then-round): summing exact
        // per-note integers avoids f64 accumulation error, and matches the JS
        // SDK so both fire Balance on exactly the same data.
        let balance_sats: i64 = current.values().map(|n| to_sats(n.amount)).sum();

        let mut events = Vec::new();
        if self.primed {
            for (key, note) in &current {
                if !self.notes.contains_key(key) {
                    events.push(ShieldEvent::Note(note.clone()));
                }
            }
            for (key, note) in &self.notes {
                if !current.contains_key(key) {
                    events.push(ShieldEvent::Spent(note.clone()));
                }
            }
            if balance_sats != self.balance_sats {
                events.push(ShieldEvent::Balance {
                    current: balance,
                    previous: self.balance,
                });
            }
        }
        self.notes = current;
        self.balance = balance;
        self.balance_sats = balance_sats;
        self.primed = true;
        events
    }
}

/// Polls the node and reports [`ShieldEvent`]s as shielded notes appear,
/// are spent, or the balance changes.
///
/// The watcher holds no background task — call [`poll`](Self::poll) at your
/// own cadence (PIVX targets 60-second blocks). The first poll primes state
/// and returns no events.
pub struct ShieldWatcher<'a> {
    client: &'a PivxClient,
    opts: WatchOptions,
    diff: NoteDiff,
    last_hash: String,
}

impl<'a> ShieldWatcher<'a> {
    pub fn new(client: &'a PivxClient, opts: WatchOptions) -> Self {
        Self {
            client,
            opts,
            diff: NoteDiff::default(),
            last_hash: String::new(),
        }
    }

    /// One polling pass. Returns the events since the previous poll
    /// (empty if the chain tip hasn't moved).
    pub async fn poll(&mut self) -> Result<Vec<ShieldEvent>> {
        let hash = self.client.get_best_block_hash().await?;
        if hash == self.last_hash {
            return Ok(vec![]);
        }
        let min_conf = if self.opts.min_conf > 0 {
            self.opts.min_conf
        } else {
            1
        };
        let addresses = (!self.opts.addresses.is_empty()).then_some(self.opts.addresses.as_slice());
        let notes = self
            .client
            .list_shield_unspent(
                min_conf,
                9_999_999,
                !self.opts.exclude_watch_only,
                addresses,
            )
            .await?;
        let events = self.diff.apply(notes);
        self.last_hash = hash;
        Ok(events)
    }

    /// Currently-known unspent shielded notes.
    pub fn unspent(&self) -> impl Iterator<Item = &ShieldNote> {
        self.diff.notes.values()
    }

    /// Sum of currently-known unspent notes (PIV).
    pub fn balance(&self) -> f64 {
        self.diff.balance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(txid: &str, outindex: u32, amount: f64) -> ShieldNote {
        ShieldNote {
            txid: txid.into(),
            outindex,
            confirmations: 2,
            spendable: false,
            address: "ps1watch".into(),
            amount,
            memo: String::new(),
            change: None,
            nullifier: None,
        }
    }

    #[test]
    fn primes_silently_then_diffs() {
        let mut diff = NoteDiff::default();

        // prime: no events
        assert!(diff.apply(vec![note("t1", 0, 5.0)]).is_empty());
        assert_eq!(diff.balance, 5.0);

        // t1 spent, t2+t3 arrive
        let events = diff.apply(vec![note("t2", 0, 3.0), note("t3", 1, 4.0)]);
        assert_eq!(events.len(), 4);
        assert!(events
            .iter()
            .any(|e| matches!(e, ShieldEvent::Note(n) if n.txid == "t2")));
        assert!(events
            .iter()
            .any(|e| matches!(e, ShieldEvent::Note(n) if n.txid == "t3")));
        assert!(events
            .iter()
            .any(|e| matches!(e, ShieldEvent::Spent(n) if n.txid == "t1")));
        assert!(events.iter().any(
            |e| matches!(e, ShieldEvent::Balance { current, previous } if *current == 7.0 && *previous == 5.0)
        ));

        // unchanged set → no events
        assert!(diff
            .apply(vec![note("t2", 0, 3.0), note("t3", 1, 4.0)])
            .is_empty());
    }

    #[test]
    fn fp_noise_does_not_fire_balance() {
        let mut diff = NoteDiff::default();
        diff.apply(vec![note("t1", 0, 0.1), note("t2", 0, 0.2)]);

        // 0.1 + 0.2 != 0.3 in f64, but both are 30_000_000 sats: the note
        // churn fires Note/Spent events, but no Balance event.
        let events = diff.apply(vec![note("t3", 0, 0.3)]);
        assert_eq!(events.len(), 3);
        assert!(!events
            .iter()
            .any(|e| matches!(e, ShieldEvent::Balance { .. })));
    }

    #[test]
    fn balance_change_is_round_then_sum_matching_js() {
        // Round each note to sats then sum (not sum-then-round): 1.0 -> the
        // split 0.999999995 + 0.000000005 rounds to 100000000 + 1 = 100000001,
        // a genuine 1-sat change, so Balance fires — same as the JS SDK on the
        // same data. (Reachable only if a node emits sub-satoshi amounts.)
        let mut diff = NoteDiff::default();
        diff.apply(vec![note("t1", 0, 1.0)]);
        let events = diff.apply(vec![note("t2", 0, 0.999999995), note("t3", 0, 0.000000005)]);
        assert!(events
            .iter()
            .any(|e| matches!(e, ShieldEvent::Balance { .. })));
    }
}
