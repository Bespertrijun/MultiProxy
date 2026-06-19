//! Isolated DNS runtime (Line C task 4 / MAJOR-5). The :53 server runs on its OWN
//! tokio runtime on a dedicated thread, separate from the axum management runtime, so
//! management-plane load/stalls cannot block resolution. A separate liveness flag
//! (bound + serving) is exposed distinct from the panel's HTTP readiness.
//!
//! The port is configurable so tests bind a high port without privileges.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};

use crate::dns::handler::GeoDnsHandler;

/// DNS bind configuration.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Listen address (e.g. `0.0.0.0`).
    pub bind_addr: String,
    /// Port — `53` in production, a high port in tests.
    pub port: u16,
    /// TCP per-connection idle timeout.
    pub tcp_timeout: Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            port: 53,
            tcp_timeout: Duration::from_secs(10),
        }
    }
}

/// DNS-specific liveness signal (distinct from panel HTTP readiness, MAJOR-5).
#[derive(Clone, Default)]
pub struct DnsLiveness {
    bound: Arc<AtomicBool>,
}

impl DnsLiveness {
    /// Whether the :53 sockets are bound and the server is serving.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.bound.load(Ordering::Relaxed)
    }

    fn set_live(&self, v: bool) {
        self.bound.store(v, Ordering::Relaxed);
    }
}

/// Handle to the spawned DNS runtime. Dropping it stops the runtime/thread.
pub struct DnsRuntimeHandle {
    /// The actual bound UDP port (useful when tests bind port 0).
    pub udp_port: u16,
    /// The actual bound TCP port.
    pub tcp_port: u16,
    pub liveness: DnsLiveness,
    // The runtime + server live entirely on this dedicated OS thread; the handle keeps
    // the thread joinable. Dropping the process tears it down.
    _thread: std::thread::JoinHandle<()>,
}

/// Spawn the GeoDNS server on its OWN runtime, created and driven entirely on a
/// dedicated OS thread (so it never blocks the caller's runtime — pre-mortem ③ /
/// MAJOR-5). Binds UDP + TCP on `cfg.bind_addr:cfg.port`. Returns once both sockets are
/// bound (the dedicated thread reports the real ports back over a channel).
///
/// # Errors
/// Returns the bind error string if either socket fails to bind.
pub fn spawn_dns(handler: GeoDnsHandler, cfg: DnsConfig) -> Result<DnsRuntimeHandle, String> {
    let liveness = DnsLiveness::default();
    let liveness_for_thread = liveness.clone();
    let bind = format!("{}:{}", cfg.bind_addr, cfg.port);
    let timeout = cfg.tcp_timeout;

    // The dedicated thread reports (udp_port, tcp_port) or a bind error here.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(u16, u16), String>>();

    let thread = std::thread::Builder::new()
        .name("geodns".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };

            runtime.block_on(async move {
                let udp = match UdpSocket::bind(&bind).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("udp bind {bind}: {e}")));
                        return;
                    }
                };
                let tcp = match TcpListener::bind(&bind).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("tcp bind {bind}: {e}")));
                        return;
                    }
                };
                let udp_port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
                let tcp_port = tcp.local_addr().map(|a| a.port()).unwrap_or(0);

                let mut server = Server::new(handler);
                server.register_socket(udp);
                server.register_listener(tcp, timeout, 4096);

                liveness_for_thread.set_live(true);
                let _ = ready_tx.send(Ok((udp_port, tcp_port)));

                if let Err(e) = server.block_until_done().await {
                    tracing::error!(error = %e, "geodns server stopped with error");
                }
                liveness_for_thread.set_live(false);
            });
        })
        .map_err(|e| e.to_string())?;

    // Wait for the dedicated thread to bind (or report failure).
    let (udp_port, tcp_port) = ready_rx
        .recv()
        .map_err(|_| "geodns thread exited before binding".to_string())??;

    Ok(DnsRuntimeHandle {
        udp_port,
        tcp_port,
        liveness,
        _thread: thread,
    })
}
