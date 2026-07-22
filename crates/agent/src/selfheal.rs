//! Self-heal & backend reachability (Line B task 3).
//!
//! Two responsibilities, both feeding `StatusReport`:
//!   * Backend reachability — only the node can see the Emby backend (it sits
//!     behind the node's NAT/network), so the agent probes it directly with a
//!     bounded TCP connect. This drives `StatusReport.backend_reachable`.
//!   * Crashed-child restart — delegated to [`crate::supervisor::Supervisor`]
//!     (`heal_if_crashed`), called on the same cadence as reporting.
//!
//! Reachability is behind a [`BackendProbe`] trait so tests don't need a real
//! Emby backend; production uses [`TcpBackendProbe`] (real `tokio::net` connect).

use std::time::Duration;

use contract::protocol::{BackendEndpoint, BackendHealth};
use futures_util::stream::{self, StreamExt};

/// Max simultaneous backend connects in one concurrent probe. Order-preserving
/// (`buffered`, NOT `buffer_unordered`) so results come back in input order, and
/// bounded so a node with many rules/replicas cannot exhaust file descriptors.
const PROBE_CONCURRENCY: usize = 32;

/// Probe a set of health futures with bounded, ORDER-PRESERVING concurrency.
///
/// Uses `StreamExt::buffered` (never `buffer_unordered`): at most
/// [`PROBE_CONCURRENCY`] connects run at once and results are yielded in **input
/// order**. Input order is load-bearing — the failover engine folds these results
/// positionally into per-endpoint state and surfaces `all_health` /
/// `active_backends` in rule→endpoint order, so a reordering here would corrupt
/// backend selection. Factored out so the ordering guarantee is unit-testable with
/// deterministic per-item latency (see the `buffered_*` tests).
async fn buffered_probe<I>(probes: I) -> Vec<BackendHealth>
where
    I: IntoIterator,
    I::Item: std::future::Future<Output = BackendHealth>,
{
    stream::iter(probes)
        .buffered(PROBE_CONCURRENCY)
        .collect()
        .await
}

/// Probes whether the node's forwarding backends are reachable from this node.
///
/// The endpoints are supplied per-call from the panel's `ConfigPush.backends`, so
/// the probe always tracks the node's **real** forwarding rules — it is never tied
/// to a hardcoded or install-time address.
#[allow(async_fn_in_trait)]
pub trait BackendProbe: Send + Sync {
    /// `true` if the node is backend-up. Policy: **any-up** — at least one endpoint
    /// must accept a connection within the timeout; an empty list reports `false` (a
    /// node with no forwarding backend is not backend-up). A node with multiple
    /// backends (e.g. replicas, or several rules) must NOT be marked down just because
    /// one backend is unreachable — that would blackhole the whole node IP from DNS
    /// and take its healthy backends down with it.
    ///
    /// Default impl derives the any-up answer from [`reachable_each`](Self::reachable_each)
    /// so a probe only needs to implement per-endpoint probing.
    async fn reachable(&self, targets: &[BackendEndpoint]) -> bool {
        self.reachable_each(targets)
            .await
            .iter()
            .any(|h| h.reachable)
    }

    /// Probe **each** endpoint once and report its individual health. The failover
    /// engine uses these per-replica results to drive per-rule active-backend
    /// selection; the any-up [`reachable`](Self::reachable) is just a fold over this.
    ///
    /// Default impl probes endpoints one at a time via single-element [`reachable`]
    /// calls — enough for test doubles; real probes ([`TcpBackendProbe`]) override it
    /// to connect-test each endpoint directly.
    async fn reachable_each(&self, targets: &[BackendEndpoint]) -> Vec<BackendHealth> {
        let mut out = Vec::with_capacity(targets.len());
        for t in targets {
            let reachable = self.reachable(std::slice::from_ref(t)).await;
            out.push(BackendHealth {
                host: t.host.clone(),
                port: t.port,
                reachable,
            });
        }
        out
    }

    /// Probe each endpoint with a caller-supplied per-endpoint `timeout` (the
    /// panel's `probe_timeout`), reporting individual health. This is the method
    /// the failover engine calls so the real connect honors the panel deadline
    /// instead of a hardcoded one, and so a slow/unreachable replica cannot stall
    /// the whole probe cycle.
    ///
    /// Default impl ignores `timeout` and delegates to
    /// [`reachable_each`](Self::reachable_each) — enough for test doubles (which
    /// have no real socket to time out). The real probe ([`TcpBackendProbe`])
    /// overrides it to apply the deadline per endpoint AND to probe concurrently.
    async fn reachable_each_timed(
        &self,
        targets: &[BackendEndpoint],
        timeout: Duration,
    ) -> Vec<BackendHealth> {
        let _ = timeout;
        self.reachable_each(targets).await
    }
}

/// Real probe: a bounded TCP connect to each `host:port`. A successful connect means
/// the backend is reachable from the node's vantage point (the relay node is the only
/// place that can see a backend behind its NAT).
#[derive(Debug, Clone)]
pub struct TcpBackendProbe {
    pub timeout: Duration,
}

impl TcpBackendProbe {
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Connect-test a single endpoint within the probe's default timeout. Thin
    /// delegate over [`connects_within`](Self::connects_within) so the any-up
    /// [`reachable`] path (which has no per-call deadline) is unchanged.
    async fn connects(&self, target: &BackendEndpoint) -> bool {
        self.connects_within(target, self.timeout).await
    }

    /// Connect-test a single endpoint within a caller-supplied `timeout`. Logs WHY
    /// a probe failed (malformed address / refused / timeout) so backend-health
    /// issues are diagnosable from the agent log instead of guessable.
    async fn connects_within(&self, target: &BackendEndpoint, timeout: Duration) -> bool {
        let addr = format!("{}:{}", target.host, target.port);
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                eprintln!("backend probe: connect {addr} failed: {e}");
                false
            }
            Err(_) => {
                eprintln!("backend probe: connect {addr} timed out after {timeout:?}");
                false
            }
        }
    }
}

impl BackendProbe for TcpBackendProbe {
    async fn reachable(&self, targets: &[BackendEndpoint]) -> bool {
        if targets.is_empty() {
            return false;
        }
        // any-up: the node can still serve as long as ONE backend is reachable.
        // Short-circuit on the first live endpoint (cheaper than probing all).
        for t in targets {
            if self.connects(t).await {
                return true;
            }
        }
        false
    }

    async fn reachable_each(&self, targets: &[BackendEndpoint]) -> Vec<BackendHealth> {
        // Probe EVERY endpoint once (no short-circuit) so the failover engine sees
        // each replica's individual health, not just an any-up answer.
        let mut out = Vec::with_capacity(targets.len());
        for t in targets {
            out.push(BackendHealth {
                host: t.host.clone(),
                port: t.port,
                reachable: self.connects(t).await,
            });
        }
        out
    }

    async fn reachable_each_timed(
        &self,
        targets: &[BackendEndpoint],
        timeout: Duration,
    ) -> Vec<BackendHealth> {
        // Probe every endpoint concurrently (≤ PROBE_CONCURRENCY at once) with the
        // panel-supplied per-endpoint deadline, so a whole cycle costs ~one timeout
        // instead of Σ(unreachable replicas × timeout). Order-preserving: results
        // come back in input order (see `buffered_probe`).
        buffered_probe(targets.iter().map(|t| async move {
            BackendHealth {
                host: t.host.clone(),
                port: t.port,
                reachable: self.connects_within(t, timeout).await,
            }
        }))
        .await
    }
}

/// A probe that always reports unreachable, regardless of targets. Equivalent to a
/// [`TcpBackendProbe`] handed an empty target list; kept as an explicit double.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBackendProbe;

impl BackendProbe for NoBackendProbe {
    async fn reachable(&self, _targets: &[BackendEndpoint]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProbe(bool);
    impl BackendProbe for FixedProbe {
        async fn reachable(&self, _targets: &[BackendEndpoint]) -> bool {
            self.0
        }
    }

    fn ep(host: &str, port: u16) -> BackendEndpoint {
        BackendEndpoint {
            host: host.into(),
            port,
        }
    }

    #[tokio::test]
    async fn no_backend_is_unreachable() {
        assert!(!NoBackendProbe.reachable(&[ep("127.0.0.1", 1)]).await);
    }

    #[tokio::test]
    async fn empty_targets_report_unreachable() {
        // A node with no forwarding backend (no rules yet) is not backend-up.
        let probe = TcpBackendProbe::new(Duration::from_millis(300));
        assert!(!probe.reachable(&[]).await);
    }

    #[tokio::test]
    async fn tcp_probe_reaches_a_live_listener() {
        // Bind an ephemeral listener and probe it → reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = TcpBackendProbe::new(Duration::from_secs(1));
        assert!(probe.reachable(&[ep("127.0.0.1", addr.port())]).await);
    }

    #[tokio::test]
    async fn tcp_probe_fails_on_closed_port() {
        // Bind then drop to get a port nothing is listening on.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let probe = TcpBackendProbe::new(Duration::from_millis(300));
        assert!(!probe.reachable(&[ep("127.0.0.1", port)]).await);
    }

    #[tokio::test]
    async fn tcp_probe_reachable_if_any_target_up() {
        // One live + one dead endpoint → reachable (any-up policy: a node stays
        // backend-up as long as at least one backend accepts a connection, so one
        // dead replica/rule does not blackhole the whole node from DNS).
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = live.local_addr().unwrap().port();
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let probe = TcpBackendProbe::new(Duration::from_millis(300));
        assert!(
            probe
                .reachable(&[ep("127.0.0.1", live_port), ep("127.0.0.1", dead_port)])
                .await
        );
    }

    #[tokio::test]
    async fn tcp_probe_unreachable_if_all_targets_down() {
        // All endpoints dead → not reachable (only then is the node backend-down).
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_port = a.local_addr().unwrap().port();
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_port = b.local_addr().unwrap().port();
        drop(a);
        drop(b);
        let probe = TcpBackendProbe::new(Duration::from_millis(300));
        assert!(
            !probe
                .reachable(&[ep("127.0.0.1", a_port), ep("127.0.0.1", b_port)])
                .await
        );
    }

    #[tokio::test]
    async fn reachable_each_reports_per_endpoint_health() {
        // One live + one dead endpoint → reachable_each returns one true, one false
        // (each replica probed individually, no short-circuit).
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = live.local_addr().unwrap().port();
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let probe = TcpBackendProbe::new(Duration::from_millis(300));
        let health = probe
            .reachable_each(&[ep("127.0.0.1", live_port), ep("127.0.0.1", dead_port)])
            .await;
        assert_eq!(health.len(), 2);
        assert_eq!(health[0].port, live_port);
        assert!(health[0].reachable, "live endpoint must be reachable");
        assert_eq!(health[1].port, dead_port);
        assert!(!health[1].reachable, "dead endpoint must be unreachable");
    }

    #[tokio::test]
    async fn reachable_each_empty_is_empty_and_reachable_false() {
        let probe = TcpBackendProbe::new(Duration::from_millis(300));
        assert!(probe.reachable_each(&[]).await.is_empty());
        // any-up over an empty per-endpoint result is false (no rules → not up).
        assert!(!probe.reachable(&[]).await);
    }

    #[tokio::test]
    async fn reachable_each_default_impl_works_for_doubles() {
        // FixedProbe only implements `reachable`; the default `reachable_each`
        // must fan it out per endpoint.
        let health = FixedProbe(true)
            .reachable_each(&[ep("127.0.0.1", 1), ep("127.0.0.1", 2)])
            .await;
        assert_eq!(health.len(), 2);
        assert!(health.iter().all(|h| h.reachable));
        let health = FixedProbe(false)
            .reachable_each(&[ep("127.0.0.1", 1)])
            .await;
        assert!(health.iter().all(|h| !h.reachable));
    }

    #[tokio::test]
    async fn fixed_probe_reports_its_answer() {
        // BackendProbe uses `async fn` → not dyn-compatible by design; it is
        // consumed via static dispatch (generic `P: BackendProbe`). Verify the
        // double works through a generic helper, matching real usage.
        async fn check<P: BackendProbe>(p: &P) -> bool {
            p.reachable(&[]).await
        }
        assert!(check(&FixedProbe(true)).await);
        assert!(!check(&FixedProbe(false)).await);
    }

    #[tokio::test]
    async fn reachable_each_timed_honors_short_timeout() {
        // A dead endpoint under a 100ms deadline must resolve unreachable well
        // under a second — proving the per-endpoint deadline is the caller's
        // `timeout`, not the old hardcoded 3s. `192.0.2.1` is RFC5737 TEST-NET-1
        // (guaranteed non-routable): connect either times out at 100ms or fast-fails
        // — both are ≪ 3s.
        let probe = TcpBackendProbe::new(Duration::from_secs(3));
        let start = std::time::Instant::now();
        let health = probe
            .reachable_each_timed(&[ep("192.0.2.1", 9)], Duration::from_millis(100))
            .await;
        let elapsed = start.elapsed();
        assert_eq!(health.len(), 1);
        assert!(!health[0].reachable, "non-routable endpoint is unreachable");
        assert!(
            elapsed < Duration::from_secs(1),
            "per-endpoint deadline must be the passed timeout, not 3s (elapsed {elapsed:?})"
        );
    }

    #[tokio::test]
    async fn reachable_each_timed_probes_concurrently() {
        // Two dead endpoints must resolve in ~ONE timeout, not two: concurrent
        // probing means the wall-clock cost is bounded by a single deadline even
        // though both connects run. Serial probing would cost ~2×timeout. (If the
        // sandbox fast-fails non-routable addresses both finish near-instantly —
        // still under the bound, and the concurrency property is proven
        // deterministically by `buffered_probe_preserves_input_order`.)
        let probe = TcpBackendProbe::new(Duration::from_secs(3));
        let timeout = Duration::from_millis(400);
        let start = std::time::Instant::now();
        let health = probe
            .reachable_each_timed(&[ep("192.0.2.1", 9), ep("192.0.2.2", 9)], timeout)
            .await;
        let elapsed = start.elapsed();
        assert_eq!(health.len(), 2);
        assert!(health.iter().all(|h| !h.reachable));
        assert!(
            elapsed < timeout * 2,
            "two dead endpoints must resolve in ~one timeout (concurrent), not two \
             (elapsed {elapsed:?}, timeout {timeout:?})"
        );
    }

    /// Yield a `BackendHealth` after an optional injected delay — lets a test drive
    /// per-item completion order deterministically (no real sockets).
    async fn delayed_health(
        delay_ms: u64,
        host: &str,
        port: u16,
        reachable: bool,
    ) -> BackendHealth {
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        BackendHealth {
            host: host.into(),
            port,
            reachable,
        }
    }

    #[tokio::test]
    async fn buffered_probe_preserves_input_order() {
        // REORDER GUARD: index 0 is slow + unreachable, index 1 is fast + reachable.
        // `buffered` must yield results in INPUT order, so the collected Vec is
        // [reachable=false @ idx0, reachable=true @ idx1] BY POSITION even though
        // idx1 completes first. A `buffer_unordered` regression would flip them
        // (fast idx1 landing at position 0) — this asserts by position to catch it.
        let out = buffered_probe([
            delayed_health(200, "slow", 0, false),
            delayed_health(0, "fast", 1, true),
        ])
        .await;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].host, "slow", "slow idx0 must stay at position 0");
        assert!(
            !out[0].reachable,
            "idx0 result (unreachable) must stay at position 0"
        );
        assert_eq!(out[1].host, "fast", "fast idx1 must stay at position 1");
        assert!(
            out[1].reachable,
            "idx1 result (reachable) must stay at position 1"
        );
    }
}
