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

    /// Connect-test a single endpoint within the timeout. Logs WHY a probe failed
    /// (malformed address / refused / timeout) so backend-health issues are
    /// diagnosable from the agent log instead of guessable.
    async fn connects(&self, target: &BackendEndpoint) -> bool {
        let addr = format!("{}:{}", target.host, target.port);
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                eprintln!("backend probe: connect {addr} failed: {e}");
                false
            }
            Err(_) => {
                eprintln!(
                    "backend probe: connect {addr} timed out after {:?}",
                    self.timeout
                );
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
}
