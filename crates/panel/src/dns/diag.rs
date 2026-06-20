//! Recent DNS resolution traces, surfaced to the panel UI at `/api/dns-diag`.
//!
//! Every query the GeoDNS resolver answers leaves a structured, step-by-step trace
//! here (a bounded ring buffer of the most recent [`MAX`] resolutions). The panel's
//! "DNS 解析诊断" view reads it to show operators exactly why a name resolved to a set
//! of IPs — or why it returned SERVFAIL — without shell access to server logs.
//!
//! The query path takes only a brief `Mutex` to append to an in-memory deque; a global
//! keeps this decoupled from the DNS runtime, the scheduler, and `AppState`.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Number of most-recent resolutions retained (newest evicts oldest).
const MAX: usize = 200;

/// One decision point in a resolution, with a severity the UI renders as a colour.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiagStep {
    /// `"ok"` | `"warn"` | `"fail"` | `"info"` — drives the UI dot colour.
    pub status: &'static str,
    /// Short step title, e.g. `"step1 域名匹配"`.
    pub label: String,
    /// The concrete values observed at this step.
    pub detail: String,
}

impl DiagStep {
    /// Build a step from a status, label and detail.
    pub fn new(status: &'static str, label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status,
            label: label.into(),
            detail: detail.into(),
        }
    }
}

/// A full trace for one resolved query.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiagEntry {
    /// Unix-millis when the query was resolved.
    pub ts_ms: u64,
    /// Normalized query name (lowercased, trailing dot stripped).
    pub query: String,
    /// Client source IP (or ECS network) the geo lookup used.
    pub client: String,
    /// Whether the query was answered with at least one IP.
    pub ok: bool,
    /// One-line outcome, e.g. `"answer: [1.2.3.4]"` or `"SERVFAIL"`.
    pub summary: String,
    /// Per-step decision trace.
    pub steps: Vec<DiagStep>,
}

/// A fixed-capacity ring of traces. Kept separate from the global so it is unit-testable.
struct Ring {
    max: usize,
    items: VecDeque<DiagEntry>,
}

impl Ring {
    fn new(max: usize) -> Self {
        Self {
            max,
            items: VecDeque::with_capacity(max),
        }
    }

    fn push(&mut self, entry: DiagEntry) {
        if self.items.len() >= self.max {
            self.items.pop_front();
        }
        self.items.push_back(entry);
    }

    /// Newest first.
    fn recent(&self) -> Vec<DiagEntry> {
        self.items.iter().rev().cloned().collect()
    }

    fn clear(&mut self) {
        self.items.clear();
    }
}

fn ring() -> &'static Mutex<Ring> {
    static BUF: OnceLock<Mutex<Ring>> = OnceLock::new();
    BUF.get_or_init(|| Mutex::new(Ring::new(MAX)))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

/// Append one resolution trace, evicting the oldest if the buffer is full.
pub fn record(query: &str, client: IpAddr, ok: bool, summary: &str, steps: Vec<DiagStep>) {
    let entry = DiagEntry {
        ts_ms: now_ms(),
        query: query.to_string(),
        client: client.to_string(),
        ok,
        summary: summary.to_string(),
        steps,
    };
    if let Ok(mut ring) = ring().lock() {
        ring.push(entry);
    }
}

/// Snapshot of recent traces, newest first.
#[must_use]
pub fn recent() -> Vec<DiagEntry> {
    ring().lock().map(|r| r.recent()).unwrap_or_default()
}

/// Drop all buffered traces.
pub fn clear() {
    if let Ok(mut ring) = ring().lock() {
        ring.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(query: &str) -> DiagEntry {
        DiagEntry {
            ts_ms: 0,
            query: query.into(),
            client: "1.1.1.1".into(),
            ok: true,
            summary: "answer".into(),
            steps: vec![DiagStep::new("ok", "step1", "x")],
        }
    }

    #[test]
    fn ring_evicts_oldest_beyond_capacity() {
        let mut ring = Ring::new(3);
        for i in 0..5 {
            ring.push(entry(&format!("q{i}")));
        }
        let got: Vec<String> = ring.recent().into_iter().map(|e| e.query).collect();
        // Only the last 3 survive; recent() is newest-first.
        assert_eq!(got, vec!["q4", "q3", "q2"]);
    }

    #[test]
    fn ring_clear_empties() {
        let mut ring = Ring::new(3);
        ring.push(entry("a"));
        ring.clear();
        assert!(ring.recent().is_empty());
    }

    #[test]
    fn diag_step_carries_status() {
        let s = DiagStep::new("fail", "step4", "no group");
        assert_eq!(s.status, "fail");
        assert_eq!(s.label, "step4");
    }
}
