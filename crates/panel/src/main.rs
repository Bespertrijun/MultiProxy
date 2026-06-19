//! Panel binary entrypoint with CLI parameters (clap, env fallback).
//!
//! Three subcommands:
//!   `panel serve`      — the main mode (default if no subcommand given)
//!   `panel init`       — one-time admin user creation
//!   `panel fetch-geocn` — download + validate GeoCN.mmdb
//!
//! Config via CLI flags with env-var fallback (backward-compatible):
//!   --db <URL>             [env: PANEL_DB]       [default: sqlite://panel.db]
//!   --http <ADDR:PORT>     [env: PANEL_HTTP]     [default: 0.0.0.0:8080]
//!   --dns-addr <ADDR>      [env: PANEL_DNS_ADDR] [default: 0.0.0.0]
//!   --dns-port <PORT>      [env: PANEL_DNS_PORT] [default: 53]
//!   --geocn <PATH>         [env: PANEL_GEOCN]
//!   --ttl <SECS>           [env: PANEL_TTL]      [default: 60]

use std::time::Duration;

use clap::{Parser, Subcommand};
use panel::auth;
use panel::db;
use panel::dns::DnsConfig;
use panel::state::CfConfig;
use panel::{build, PanelConfig};

/// Default download URL for GeoCN.mmdb (ljxi/GeoCN latest release).
const GEOCN_DEFAULT_URL: &str = "https://github.com/ljxi/GeoCN/releases/latest/download/GeoCN.mmdb";

#[derive(Parser)]
#[command(name = "panel", about = "multiProxy management panel")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the panel (web UI/API + GeoDNS). This is the default mode.
    Serve(ServeArgs),
    /// One-time admin user creation + DB migration.
    Init(InitArgs),
    /// Download and validate a GeoCN.mmdb file.
    FetchGeocn(FetchGeocnArgs),
}

#[derive(Parser, Clone)]
struct ServeArgs {
    /// SQLite URL
    #[arg(long = "db", env = "PANEL_DB", default_value = "sqlite://panel.db")]
    database_url: String,

    /// Web UI/API bind address
    #[arg(long = "http", env = "PANEL_HTTP", default_value = "0.0.0.0:8080")]
    http_bind: String,

    /// GeoDNS bind address
    #[arg(long = "dns-addr", env = "PANEL_DNS_ADDR", default_value = "0.0.0.0")]
    dns_addr: String,

    /// GeoDNS port
    #[arg(long = "dns-port", env = "PANEL_DNS_PORT", default_value_t = 53)]
    dns_port: u16,

    /// GeoCN.mmdb path
    #[arg(long = "geocn", env = "PANEL_GEOCN")]
    geocn_path: Option<String>,

    /// Resolution A-record TTL (seconds)
    #[arg(long = "ttl", env = "PANEL_TTL", default_value_t = 60)]
    ttl_secs: u32,

    // ---- Cloudflare / ACME integration (all optional) ----
    /// Cloudflare API token
    #[arg(long = "cf-token", env = "CF_API_TOKEN")]
    cf_token: Option<String>,

    /// Cloudflare zone ID
    #[arg(long = "cf-zone", env = "CF_ZONE_ID")]
    cf_zone: Option<String>,

    /// Base domain (e.g. example.com)
    #[arg(long = "domain", env = "PANEL_DOMAIN")]
    domain: Option<String>,

    /// Resolution subdomain
    #[arg(long = "subdomain", env = "PANEL_SUBDOMAIN", default_value = "emby")]
    subdomain: String,

    /// Panel public IP (auto-detected if omitted)
    #[arg(long = "panel-ip", env = "PANEL_IP")]
    panel_ip: Option<String>,

    /// NS hostname prefix
    #[arg(long = "ns-name", default_value = "ns1")]
    ns_name: String,

    /// Use Let's Encrypt staging directory (for testing)
    #[arg(long = "acme-staging")]
    acme_staging: bool,

    /// Certificate storage directory
    #[arg(long = "cert-dir", default_value = "./certs")]
    cert_dir: String,

    /// Encryption key file path (default: panel.key next to DB)
    #[arg(long = "key-file", env = "PANEL_KEY_FILE")]
    key_file: Option<String>,

    /// Directory containing agent binaries served at /dl/
    #[arg(
        long = "agent-bin-dir",
        env = "PANEL_AGENT_BIN_DIR",
        default_value = "./dist"
    )]
    agent_bin_dir: String,
}

#[derive(Parser)]
struct InitArgs {
    /// SQLite URL
    #[arg(long = "db", env = "PANEL_DB", default_value = "sqlite://panel.db")]
    database_url: String,

    /// Encryption key file path (default: panel.key next to DB)
    #[arg(long = "key-file", env = "PANEL_KEY_FILE")]
    key_file: Option<String>,

    /// Admin username
    #[arg(long = "admin-user", default_value = "admin")]
    admin_user: String,

    /// Admin password (required -- no default)
    #[arg(long = "admin-pass")]
    admin_pass: String,
}

#[derive(Parser)]
struct FetchGeocnArgs {
    /// Where to save the downloaded GeoCN.mmdb
    #[arg(long = "output", default_value = "./GeoCN.mmdb")]
    output: String,

    /// Override download URL (for mirrors)
    #[arg(long = "url", default_value = GEOCN_DEFAULT_URL)]
    url: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init(args)) => run_init(args).await,
        Some(Command::Serve(args)) => run_serve(args).await,
        Some(Command::FetchGeocn(args)) => run_fetch_geocn(args).await,
        None => run_serve(ServeArgs::parse()).await,
    }
}

async fn run_init(args: InitArgs) {
    // 1. Connect + migrate.
    let pool = match db::connect(&args.database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("database error: {e}");
            std::process::exit(1);
        }
    };

    // 1b. Initialize encryption key file (create if missing).
    {
        let key_path = match &args.key_file {
            Some(p) => std::path::PathBuf::from(p),
            None => {
                let db_url = &args.database_url;
                let db_path = db_url
                    .strip_prefix("sqlite://")
                    .or_else(|| db_url.strip_prefix("sqlite:"))
                    .unwrap_or(db_url);
                let db_file = std::path::PathBuf::from(db_path);
                db_file
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("panel.key")
            }
        };
        if let Err(e) = panel::crypto::Vault::load_or_create_key(&key_path) {
            eprintln!("encryption key error: {e}");
            std::process::exit(1);
        }
    }

    // 2. Check if an admin already exists.
    match db::count_users(&pool).await {
        Ok(n) if n > 0 => {
            eprintln!("Admin user already exists. Use the panel UI to change the password.");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("database error: {e}");
            std::process::exit(1);
        }
        _ => {}
    }

    // 3. Hash and insert.
    let hash = match auth::hash_password(&args.admin_pass) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("password hashing failed: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = db::upsert_user(
        &pool,
        &contract::model::PanelUser {
            username: args.admin_user,
            password_hash: hash,
        },
    )
    .await
    {
        eprintln!("failed to create admin user: {e}");
        std::process::exit(1);
    }

    eprintln!("Admin user created. Run `panel serve` to start.");
}

async fn run_fetch_geocn(args: FetchGeocnArgs) {
    eprintln!("Downloading GeoCN.mmdb from {}", args.url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("failed to build HTTP client");

    let resp = match client.get(&args.url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("download failed: {e}");
            std::process::exit(1);
        }
    };

    if !resp.status().is_success() {
        eprintln!("download failed: HTTP {}", resp.status());
        std::process::exit(1);
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read response body: {e}");
            std::process::exit(1);
        }
    };

    // Write to file.
    if let Err(e) = tokio::fs::write(&args.output, &bytes).await {
        eprintln!("failed to write file: {e}");
        std::process::exit(1);
    }

    // Validate by attempting to load as GeoCN MMDB.
    if let Err(e) = geoip::DbFormat::GeoCn.load(&args.output) {
        // Invalid — remove the file.
        let _ = tokio::fs::remove_file(&args.output).await;
        eprintln!("downloaded file is not a valid MMDB: {e}");
        std::process::exit(1);
    }

    let size_mb = bytes.len() as f64 / (1024.0 * 1024.0);
    eprintln!(
        "GeoCN.mmdb saved to {} ({:.1} MB). Pass --geocn {} to `panel serve`.",
        args.output, size_mb, args.output
    );
}

/// Detect the panel's public IP via an HTTP service. Returns `None` on failure.
async fn detect_public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    // Try multiple services in order.
    for url in &[
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ] {
        if let Ok(resp) = client.get(*url).send().await {
            if let Ok(text) = resp.text().await {
                let ip = text.trim().to_string();
                if !ip.is_empty() && ip.len() < 46 {
                    return Some(ip);
                }
            }
        }
    }
    None
}

async fn run_serve(args: ServeArgs) {
    let dns = DnsConfig {
        bind_addr: args.dns_addr,
        port: args.dns_port,
        tcp_timeout: Duration::from_secs(10),
    };

    // Build optional Cloudflare config when both token and zone are provided.
    let cf = match (args.cf_token, args.cf_zone, args.domain) {
        (Some(token), Some(zone), Some(domain)) => {
            // Resolve panel IP: explicit flag, or auto-detect.
            let panel_ip = match args.panel_ip {
                Some(ip) => ip,
                None => match detect_public_ip().await {
                    Some(ip) => {
                        tracing::info!(ip = %ip, "auto-detected panel public IP");
                        ip
                    }
                    None => {
                        eprintln!("failed to auto-detect public IP; pass --panel-ip explicitly");
                        std::process::exit(1);
                    }
                },
            };
            Some(CfConfig {
                token,
                zone_id: zone,
                domain,
                subdomain: args.subdomain,
                panel_ip,
                ns_name: args.ns_name,
                acme_staging: args.acme_staging,
                cert_dir: args.cert_dir,
            })
        }
        _ => None,
    };

    let cfg = PanelConfig {
        database_url: args.database_url,
        http_bind: args.http_bind.clone(),
        dns,
        geocn_path: args.geocn_path,
        ttl_secs: args.ttl_secs,
        require_admin: true,
        cf,
        key_file: args.key_file,
        agent_bin_dir: args.agent_bin_dir,
    };

    let http_bind = cfg.http_bind.clone();
    let panel = match build(cfg).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("panel startup failed: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!(
        http = %http_bind,
        dns_udp = panel.dns_udp_port,
        dns_tcp = panel.dns_tcp_port,
        dns_live = panel.dns_liveness.is_live(),
        "panel started (DNS on isolated runtime)"
    );

    let listener = match tokio::net::TcpListener::bind(&http_bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("http bind {http_bind} failed: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, panel.router).await {
        eprintln!("http server error: {e}");
        std::process::exit(1);
    }
}
