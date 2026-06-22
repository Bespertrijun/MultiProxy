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

use contract::protocol::BackendEndpoint;

/// Probes whether the node's forwarding backends are reachable from this node.
///
/// The endpoints are supplied per-call from the panel's `ConfigPush.backends`, so
/// the probe always tracks the node's **real** forwarding rules — it is never tied
/// to a hardcoded or install-time address.
#[allow(async_fn_in_trait)]
pub trait BackendProbe: Send + Sync {
    /// `true` if the given backends are reachable. Policy: **every** endpoint must
    /// accept a connection within the timeout; an empty list reports `false` (a node
    /// with no forwarding backend is not backend-up).
    async fn reachable(&self, targets: &[BackendEndpoint]) -> bool;
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
        for t in targets {
            if !self.connects(t).await {
                return false;
            }
        }
        true
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
    async fn tcp_probe_requires_all_targets_reachable() {
        // One live + one dead endpoint → not reachable (all-must-connect policy).
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = live.local_addr().unwrap().port();
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let probe = TcpBackendProbe::new(Duration::from_millis(300));
        assert!(
            !probe
                .reachable(&[ep("127.0.0.1", live_port), ep("127.0.0.1", dead_port)])
                .await
        );
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
