//! Agent binary entrypoint (Line B, M1).
//!
//! Wires the runtime: install the rustls **ring** crypto provider, detect the
//! platform, build the supervisor / capacity collector / backend probe, and run
//! the wss reverse-connect + reconnect-with-backoff loop until a shutdown signal.
//!
//! Configuration via CLI flags with env-var fallback:
//!   --panel-url <URL>       [env: AGENT_PANEL_URL]    (required)
//!   --node-id <ID>          [env: AGENT_NODE_ID]      (required)
//!   --token <TOKEN>         [env: AGENT_TOKEN]        (required)
//!   --config-dir <DIR>      [env: AGENT_CONFIG_DIR]   [default: /etc/multiproxy]
//!   --backend-host <HOST>   [env: AGENT_BACKEND_HOST] [default: 127.0.0.1]
//!   --backend-port <PORT>   [env: AGENT_BACKEND_PORT] [default: 8096]

use std::time::Duration;

use agent::capacity::{boot_epoch, CapacityCollector, NicCounterSource};
use agent::config::ConfigPaths;
use agent::conn::{run_reconnect_loop, AgentConfig, Backoff, SessionDeps};
use agent::selfheal::TcpBackendProbe;
use agent::supervisor::{RealSpawner, Supervisor};
use clap::Parser;

#[derive(Parser)]
#[command(name = "agent", about = "multiProxy node agent")]
struct Cli {
    /// Panel WebSocket URL (e.g. wss://panel.example.com/agent)
    #[arg(long = "panel-url", env = "AGENT_PANEL_URL")]
    panel_url: String,

    /// This node's ID
    #[arg(long = "node-id", env = "AGENT_NODE_ID")]
    node_id: String,

    /// Per-node bearer token
    #[arg(long = "token", env = "AGENT_TOKEN")]
    token: String,

    /// Config file directory
    #[arg(
        long = "config-dir",
        env = "AGENT_CONFIG_DIR",
        default_value = "/etc/multiproxy"
    )]
    config_dir: String,

    /// Emby backend host
    #[arg(
        long = "backend-host",
        env = "AGENT_BACKEND_HOST",
        default_value = "127.0.0.1"
    )]
    backend_host: String,

    /// Emby backend port
    #[arg(
        long = "backend-port",
        env = "AGENT_BACKEND_PORT",
        default_value_t = 8096
    )]
    backend_port: u16,
}

#[tokio::main]
async fn main() {
    // Task 1: install the ring crypto provider before any TLS work.
    if let Err(e) = agent::install_crypto_provider() {
        eprintln!("fatal: could not install rustls ring provider: {e}");
        std::process::exit(1);
    }

    let platform = agent::platform::detect();
    let cli = Cli::parse();

    let cfg = AgentConfig {
        panel_url: cli.panel_url,
        node_id: cli.node_id.clone(),
        token: cli.token,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: platform.clone(),
        config_paths: ConfigPaths::under(&cli.config_dir),
    };

    eprintln!(
        "agent starting — node={} platform={platform} protocol=v{} → {}",
        cli.node_id,
        contract::PROTOCOL_VERSION,
        cfg.panel_url,
    );

    // Backend reachability probe (task 3). If no backend host is configured yet,
    // a probe pointed at an unconfigured address simply fails → reported down.
    let backend = TcpBackendProbe::new(cli.backend_host, cli.backend_port, Duration::from_secs(3));

    // Capacity collector (task 3b): NIC-delta tier for M1 (forward-byte tier
    // wires gost/realm per-rule counters at M2). Window = 2 heartbeat intervals.
    let capacity = CapacityCollector::new(
        NicCounterSource,
        boot_epoch(),
        Duration::from_secs(2 * contract::protocol::DEFAULT_HEARTBEAT_INTERVAL_SECS as u64),
    );

    let deps = SessionDeps {
        supervisor: Supervisor::new(RealSpawner),
        capacity,
        backend,
        applied_gen: 0,
    };

    // Shutdown channel wired to SIGINT/SIGTERM.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        wait_for_shutdown().await;
        let _ = shutdown_tx.send(true);
    });

    run_reconnect_loop(&cfg, deps, shutdown_rx, Backoff::default()).await;
    eprintln!("agent stopped.");
}

/// Resolve when the process receives SIGINT or SIGTERM.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
