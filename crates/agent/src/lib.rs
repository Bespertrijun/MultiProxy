//! `agent` — Line B of the emby-nat-relay-panel system (M1).
//!
//! A thin, musl-static, dual-arch (x86_64 + aarch64) agent that runs on each
//! NAT front node. It reverse-connects to the panel over WebSocket-over-TLS
//! (rustls + the **ring** crypto provider), applies pushed gost/realm config,
//! supervises the forwarding child process, self-heals crashes, and self-reports
//! health + capacity telemetry on the server-controlled heartbeat interval.
//!
//! Modules:
//!   * [`platform`] — runtime arch/OS triple for `Hello.platform`.
//!   * [`conn`]      — wss client, handshake, reconnect-backoff, heartbeat,
//!     ConfigPush→apply→ConfigAck, session loop.
//!   * [`config`]    — write gost/realm config files + tool selection.
//!   * [`supervisor`]— process supervisor abstraction (trait + real + injectable).
//!   * [`capacity`]  — capacity telemetry (counter epoch, sliding-window bps,
//!     forward-bytes vs nic-delta source tier).
//!   * [`report`]    — StatusReport assembly.
//!   * [`selfheal`]  — backend reachability probe + crashed-child restart.
//!
//! The crate is intentionally light: it depends only on `contract` + tokio +
//! tokio-tungstenite + rustls(ring) + serde_json + small utils. It does NOT pull
//! axum/hickory/sqlx (those belong to the panel line).

pub mod capacity;
pub mod config;
pub mod conn;
pub mod platform;
pub mod report;
pub mod selfheal;
pub mod supervisor;
pub mod updater;

#[cfg(any(test, feature = "testutil"))]
pub mod testutil;

/// Install the rustls **ring** crypto provider as the process default (Line B
/// task 1 — explicitly NOT aws-lc-rs). MUST be called once at startup before any
/// TLS connection; tokio-tungstenite's TLS connector uses the process-default
/// provider. Idempotent: a second call is a no-op (returns `Ok` if already set).
///
/// We build rustls with only the `ring` feature, so this installs `ring`.
pub fn install_crypto_provider() -> Result<(), &'static str> {
    // `install_default` errors if a provider is already installed; treat that as
    // success so repeated calls (e.g. in tests) are harmless.
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => Ok(()),
        // Already installed (e.g. a prior call in the same process).
        Err(_) => Ok(()),
    }
}
