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

/// Probes whether the configured Emby backend is reachable from this node.
#[allow(async_fn_in_trait)]
pub trait BackendProbe: Send + Sync {
    /// `true` if the backend currently accepts a connection within the timeout.
    async fn reachable(&self) -> bool;
}

/// Real probe: a bounded TCP connect to `host:port`. A successful connect means
/// the backend is reachable from the node's vantage point.
#[derive(Debug, Clone)]
pub struct TcpBackendProbe {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
}

impl TcpBackendProbe {
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, timeout: Duration) -> Self {
        Self {
            host: host.into(),
            port,
            timeout,
        }
    }
}

impl BackendProbe for TcpBackendProbe {
    async fn reachable(&self) -> bool {
        let addr = format!("{}:{}", self.host, self.port);
        matches!(
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr)).await,
            Ok(Ok(_))
        )
    }
}

/// A probe with no backend configured yet (before the first ConfigPush). Reports
/// unreachable so a node without forwarding config is never marked backend-up.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBackendProbe;

impl BackendProbe for NoBackendProbe {
    async fn reachable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProbe(bool);
    impl BackendProbe for FixedProbe {
        async fn reachable(&self) -> bool {
            self.0
        }
    }

    #[tokio::test]
    async fn no_backend_is_unreachable() {
        assert!(!NoBackendProbe.reachable().await);
    }

    #[tokio::test]
    async fn tcp_probe_reaches_a_live_listener() {
        // Bind an ephemeral listener and probe it → reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = TcpBackendProbe::new("127.0.0.1", addr.port(), Duration::from_secs(1));
        assert!(probe.reachable().await);
    }

    #[tokio::test]
    async fn tcp_probe_fails_on_closed_port() {
        // Bind then drop to get a port nothing is listening on.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let probe = TcpBackendProbe::new("127.0.0.1", port, Duration::from_millis(300));
        assert!(!probe.reachable().await);
    }

    #[tokio::test]
    async fn fixed_probe_reports_its_answer() {
        // BackendProbe uses `async fn` → not dyn-compatible by design; it is
        // consumed via static dispatch (generic `P: BackendProbe`). Verify the
        // double works through a generic helper, matching real usage.
        async fn check<P: BackendProbe>(p: &P) -> bool {
            p.reachable().await
        }
        assert!(check(&FixedProbe(true)).await);
        assert!(!check(&FixedProbe(false)).await);
    }
}
