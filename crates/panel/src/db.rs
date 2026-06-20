//! sqlx + SQLite schema, migrations, and repository functions (Line A task 1).
//!
//! Uses the BUNDLED libsqlite3 (no external `.so`). Schema covers every contract
//! model entity, including FrontNode capacity-config and the persisted capacity
//! runtime columns (`accumulated_usage_bytes`, `counter_epoch`, last-counter
//! values) required by rev3 §B / Rec#2 (persist on every report).

use std::str::FromStr;

use contract::isp::Isp;
use contract::model::{
    Agent, ConnState, DnsZone, ForwardRule, FrontNode, LineGroup, NodeStatus, PanelUser, Protocol,
    Region, SaturationState, TlsMode, Tool,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::crypto::{self, Vault};
use crate::error::{PanelError, Result};

/// The full DDL applied at startup. Idempotent (`IF NOT EXISTS`).
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS panel_user (
    username       TEXT PRIMARY KEY,
    password_hash  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS front_node (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL,
    public_ip                TEXT NOT NULL,
    division_code            INTEGER NOT NULL DEFAULT 0,
    province_code            INTEGER NOT NULL DEFAULT 0,
    isp                      TEXT NOT NULL DEFAULT 'unknown',
    status                   TEXT NOT NULL DEFAULT 'unknown',
    last_seen                INTEGER NOT NULL DEFAULT 0,
    desired_config_gen       INTEGER NOT NULL DEFAULT 0,
    applied_config_gen       INTEGER NOT NULL DEFAULT 0,
    -- capacity config (operator-set, rev3 §B)
    bandwidth_cap_mbps       INTEGER,
    traffic_quota_bytes      INTEGER,
    quota_direction          TEXT NOT NULL DEFAULT 'Both',
    quota_reset_day          INTEGER,
    soft_quota_pct           INTEGER NOT NULL DEFAULT 90,
    hard_quota_pct           INTEGER NOT NULL DEFAULT 100,
    -- capacity runtime (panel-maintained, persisted on EVERY report - rev3 §B / Rec#2)
    accumulated_usage_bytes  INTEGER NOT NULL DEFAULT 0,
    current_throughput_bps   INTEGER NOT NULL DEFAULT 0,
    saturation_state         TEXT NOT NULL DEFAULT 'normal',
    availability_state       TEXT NOT NULL DEFAULT 'available',
    -- counter-epoch reset-detection state (rev3 §A / Rec#3)
    counter_epoch            INTEGER NOT NULL DEFAULT 0,
    last_tx_bytes_total      INTEGER NOT NULL DEFAULT 0,
    last_rx_bytes_total      INTEGER NOT NULL DEFAULT 0,
    has_counter_baseline     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent (
    node_id        TEXT PRIMARY KEY,
    token_hash     TEXT NOT NULL,
    agent_version  TEXT NOT NULL DEFAULT '',
    conn_state     TEXT NOT NULL DEFAULT 'disconnected'
);

CREATE TABLE IF NOT EXISTS forward_rule (
    id            TEXT PRIMARY KEY,
    node_id       TEXT NOT NULL,
    listen_port   INTEGER NOT NULL,
    protocol      TEXT NOT NULL,
    backend_host  TEXT NOT NULL,
    backend_port  INTEGER NOT NULL,
    tool          TEXT NOT NULL,
    tls_mode      TEXT NOT NULL DEFAULT 'passthrough'
);

CREATE TABLE IF NOT EXISTS line_group (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    zone_id         TEXT,
    match_region    INTEGER,
    match_isp       TEXT,
    member_node_ids TEXT NOT NULL DEFAULT '[]',
    priority        INTEGER NOT NULL DEFAULT 0,
    fallback_group  TEXT
);

CREATE TABLE IF NOT EXISTS dns_zone (
    id           TEXT PRIMARY KEY,
    apex_domain  TEXT NOT NULL,
    soa          TEXT NOT NULL DEFAULT '',
    ns           TEXT NOT NULL DEFAULT '[]',
    default_ttl  INTEGER NOT NULL DEFAULT 60
);

CREATE TABLE IF NOT EXISTS session (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Open (creating if missing) the SQLite DB at `url` and apply the schema.
///
/// `url` examples: `sqlite::memory:` (tests), `sqlite:///abs/path/panel.db`.
///
/// # Errors
/// Returns [`PanelError::Db`] on connect/migration failure.
pub async fn connect(url: &str) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(url)
        .map_err(|e| PanelError::Db(e.to_string()))?
        .create_if_missing(true);
    // A single connection for `:memory:` so the in-memory DB is shared across the
    // pool; on-disk DBs can use the default pool size.
    let pool = if url.contains(":memory:") {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?
    } else {
        SqlitePoolOptions::new().connect_with(opts).await?
    };
    migrate(&pool).await?;
    Ok(pool)
}

/// Apply the schema DDL.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    // Strip `--` line comments first so a comment can never inject a stray `;` into
    // the statement splitter.
    let cleaned: String = SCHEMA
        .lines()
        .map(|line| match line.find("--") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    for stmt in cleaned.split(';') {
        let trimmed = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }
        sqlx::query(trimmed).execute(pool).await?;
    }

    // Column migrations for existing databases.
    let alter_stmts = &[
        "ALTER TABLE front_node ADD COLUMN quota_direction TEXT NOT NULL DEFAULT 'Both'",
        "ALTER TABLE line_group ADD COLUMN zone_id TEXT",
    ];
    for stmt in alter_stmts {
        let _ = sqlx::query(stmt).execute(pool).await;
    }

    Ok(())
}

// ---------- helpers: enum <-> text ----------

fn node_status_str(s: NodeStatus) -> &'static str {
    match s {
        NodeStatus::Online => "online",
        NodeStatus::Offline => "offline",
        NodeStatus::Unknown => "unknown",
    }
}
fn node_status_from(s: &str) -> NodeStatus {
    match s {
        "online" => NodeStatus::Online,
        "offline" => NodeStatus::Offline,
        _ => NodeStatus::Unknown,
    }
}
fn isp_str(i: Isp) -> &'static str {
    match i {
        Isp::Telecom => "telecom",
        Isp::Unicom => "unicom",
        Isp::Mobile => "mobile",
        Isp::Pengboshi => "pengboshi",
        Isp::Cernet => "cernet",
        Isp::Broadcast => "broadcast",
        Isp::Aliyun => "aliyun",
        Isp::Cstnet => "cstnet",
        Isp::Unknown => "unknown",
    }
}
fn isp_from(s: &str) -> Isp {
    match s {
        "telecom" => Isp::Telecom,
        "unicom" => Isp::Unicom,
        "mobile" => Isp::Mobile,
        "pengboshi" => Isp::Pengboshi,
        "cernet" => Isp::Cernet,
        "broadcast" => Isp::Broadcast,
        "aliyun" => Isp::Aliyun,
        "cstnet" => Isp::Cstnet,
        _ => Isp::Unknown,
    }
}
fn quota_dir_str(d: contract::model::QuotaDirection) -> &'static str {
    match d {
        contract::model::QuotaDirection::Both => "Both",
        contract::model::QuotaDirection::TxOnly => "TxOnly",
        contract::model::QuotaDirection::RxOnly => "RxOnly",
    }
}
fn quota_dir_from(s: &str) -> contract::model::QuotaDirection {
    match s {
        "TxOnly" => contract::model::QuotaDirection::TxOnly,
        "RxOnly" => contract::model::QuotaDirection::RxOnly,
        _ => contract::model::QuotaDirection::Both,
    }
}
fn sat_str(s: SaturationState) -> &'static str {
    match s {
        SaturationState::Normal => "normal",
        SaturationState::Saturated => "saturated",
    }
}
fn sat_from(s: &str) -> SaturationState {
    match s {
        "saturated" => SaturationState::Saturated,
        _ => SaturationState::Normal,
    }
}
fn avail_str(s: contract::model::AvailabilityState) -> &'static str {
    use contract::model::AvailabilityState as A;
    match s {
        A::Available => "available",
        A::SoftExcluded => "soft_excluded",
        A::HardExcluded => "hard_excluded",
    }
}
fn avail_from(s: &str) -> contract::model::AvailabilityState {
    use contract::model::AvailabilityState as A;
    match s {
        "soft_excluded" => A::SoftExcluded,
        "hard_excluded" => A::HardExcluded,
        _ => A::Available,
    }
}
fn proto_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}
fn proto_from(s: &str) -> Protocol {
    match s {
        "udp" => Protocol::Udp,
        _ => Protocol::Tcp,
    }
}
fn tool_str(t: Tool) -> &'static str {
    match t {
        Tool::Gost => "gost",
        Tool::Realm => "realm",
    }
}
fn tool_from(s: &str) -> Tool {
    match s {
        "realm" => Tool::Realm,
        _ => Tool::Gost,
    }
}
fn tls_mode_str(t: TlsMode) -> &'static str {
    match t {
        TlsMode::Passthrough => "passthrough",
        TlsMode::Terminate => "terminate",
    }
}
fn tls_mode_from(s: &str) -> TlsMode {
    match s {
        "terminate" => TlsMode::Terminate,
        _ => TlsMode::Passthrough,
    }
}

// ---------- PanelUser ----------

/// Insert or replace the admin user with an already-hashed password.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn upsert_user(pool: &SqlitePool, user: &PanelUser) -> Result<()> {
    sqlx::query(
        "INSERT INTO panel_user(username, password_hash) VALUES(?, ?)
         ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash",
    )
    .bind(&user.username)
    .bind(&user.password_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch a user by username.
///
/// # Errors
/// Returns [`PanelError::NotFound`] if absent.
pub async fn get_user(pool: &SqlitePool, username: &str) -> Result<PanelUser> {
    let row = sqlx::query("SELECT username, password_hash FROM panel_user WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| PanelError::NotFound("user".into()))?;
    Ok(PanelUser {
        username: row.get("username"),
        password_hash: row.get("password_hash"),
    })
}

/// Count users (used to decide whether to seed the default admin).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn count_users(pool: &SqlitePool) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM panel_user")
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("n"))
}

// ---------- sessions ----------

/// Persist a session token for `username`.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn create_session(
    pool: &SqlitePool,
    token: &str,
    username: &str,
    now: i64,
) -> Result<()> {
    sqlx::query("INSERT INTO session(token, username, created_at) VALUES(?, ?, ?)")
        .bind(token)
        .bind(username)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

/// Session time-to-live: sessions older than this are treated as expired and
/// rejected (security MEDIUM #2). `created_at` is stored in unix-millis at login.
pub const SESSION_TTL_MS: i64 = 604_800_000; // 7 days

/// Return the username for a session token, if the session exists AND is within the
/// [`SESSION_TTL_MS`] window. An expired session resolves to `None` (rejected) and is
/// best-effort deleted so stale rows do not accumulate.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn session_user(pool: &SqlitePool, token: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT username, created_at FROM session WHERE token = ?")
        .bind(token)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let created_at = row.get::<i64, _>("created_at");
    let now = now_ms_i64();
    if now.saturating_sub(created_at) > SESSION_TTL_MS {
        // Expired: reject and prune the stale row (best-effort).
        let _ = delete_session(pool, token).await;
        return Ok(None);
    }
    Ok(Some(row.get::<String, _>("username")))
}

/// Unix-millis as i64 (sessions are stamped/compared in this unit).
fn now_ms_i64() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Delete a session (logout).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_session(pool: &SqlitePool, token: &str) -> Result<()> {
    sqlx::query("DELETE FROM session WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update a user's password hash.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn update_user_password(pool: &SqlitePool, username: &str, new_hash: &str) -> Result<()> {
    sqlx::query("UPDATE panel_user SET password_hash = ? WHERE username = ?")
        .bind(new_hash)
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete ALL sessions for a given user (force re-login after password change).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_sessions_for_user(pool: &SqlitePool, username: &str) -> Result<()> {
    sqlx::query("DELETE FROM session WHERE username = ?")
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- FrontNode ----------

fn row_to_node(row: &sqlx::sqlite::SqliteRow) -> FrontNode {
    FrontNode {
        id: row.get("id"),
        name: row.get("name"),
        public_ip: row.get("public_ip"),
        region: Region {
            division_code: row.get::<i64, _>("division_code") as u32,
            province_code: row.get::<i64, _>("province_code") as u16,
        },
        isp: isp_from(&row.get::<String, _>("isp")),
        status: node_status_from(&row.get::<String, _>("status")),
        last_seen: row.get::<i64, _>("last_seen") as u64,
        desired_config_gen: row.get::<i64, _>("desired_config_gen") as u64,
        applied_config_gen: row.get::<i64, _>("applied_config_gen") as u64,
        bandwidth_cap_mbps: row
            .get::<Option<i64>, _>("bandwidth_cap_mbps")
            .map(|v| v as u32),
        traffic_quota_bytes: row
            .get::<Option<i64>, _>("traffic_quota_bytes")
            .map(|v| v as u64),
        quota_direction: quota_dir_from(&row.get::<String, _>("quota_direction")),
        quota_reset_day: row
            .get::<Option<i64>, _>("quota_reset_day")
            .map(|v| v as u8),
        soft_quota_pct: row.get::<i64, _>("soft_quota_pct") as u8,
        hard_quota_pct: row.get::<i64, _>("hard_quota_pct") as u8,
        accumulated_usage_bytes: row.get::<i64, _>("accumulated_usage_bytes") as u64,
        current_throughput_bps: row.get::<i64, _>("current_throughput_bps") as u64,
        saturation_state: sat_from(&row.get::<String, _>("saturation_state")),
        availability_state: avail_from(&row.get::<String, _>("availability_state")),
    }
}

/// Insert or replace a front node (config + runtime).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn upsert_node(pool: &SqlitePool, n: &FrontNode) -> Result<()> {
    sqlx::query(
        "INSERT INTO front_node(
            id, name, public_ip, division_code, province_code, isp, status, last_seen,
            desired_config_gen, applied_config_gen, bandwidth_cap_mbps, traffic_quota_bytes,
            quota_direction, quota_reset_day, soft_quota_pct, hard_quota_pct, accumulated_usage_bytes,
            current_throughput_bps, saturation_state, availability_state)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
            name=excluded.name, public_ip=excluded.public_ip,
            division_code=excluded.division_code, province_code=excluded.province_code,
            isp=excluded.isp, bandwidth_cap_mbps=excluded.bandwidth_cap_mbps,
            traffic_quota_bytes=excluded.traffic_quota_bytes, quota_direction=excluded.quota_direction,
            quota_reset_day=excluded.quota_reset_day,
            soft_quota_pct=excluded.soft_quota_pct, hard_quota_pct=excluded.hard_quota_pct",
    )
    .bind(&n.id)
    .bind(&n.name)
    .bind(&n.public_ip)
    .bind(i64::from(n.region.division_code))
    .bind(i64::from(n.region.province_code))
    .bind(isp_str(n.isp))
    .bind(node_status_str(n.status))
    .bind(n.last_seen as i64)
    .bind(n.desired_config_gen as i64)
    .bind(n.applied_config_gen as i64)
    .bind(n.bandwidth_cap_mbps.map(i64::from))
    .bind(n.traffic_quota_bytes.map(|v| v as i64))
    .bind(quota_dir_str(n.quota_direction))
    .bind(n.quota_reset_day.map(i64::from))
    .bind(i64::from(n.soft_quota_pct))
    .bind(i64::from(n.hard_quota_pct))
    .bind(n.accumulated_usage_bytes as i64)
    .bind(n.current_throughput_bps as i64)
    .bind(sat_str(n.saturation_state))
    .bind(avail_str(n.availability_state))
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch a node by id.
///
/// # Errors
/// Returns [`PanelError::NotFound`] if absent.
pub async fn get_node(pool: &SqlitePool, id: &str) -> Result<FrontNode> {
    let row = sqlx::query("SELECT * FROM front_node WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| PanelError::NotFound("front_node".into()))?;
    Ok(row_to_node(&row))
}

/// List all nodes.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn list_nodes(pool: &SqlitePool) -> Result<Vec<FrontNode>> {
    let rows = sqlx::query("SELECT * FROM front_node ORDER BY id")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_node).collect())
}

/// Delete a node.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_node(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM front_node WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Bump a node's `desired_config_gen` and return the new value.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn bump_desired_gen(pool: &SqlitePool, node_id: &str) -> Result<u64> {
    sqlx::query("UPDATE front_node SET desired_config_gen = desired_config_gen + 1 WHERE id = ?")
        .bind(node_id)
        .execute(pool)
        .await?;
    let row = sqlx::query("SELECT desired_config_gen FROM front_node WHERE id = ?")
        .bind(node_id)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("desired_config_gen") as u64)
}

/// Record an applied config generation (from a ConfigAck).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn set_applied_gen(pool: &SqlitePool, node_id: &str, gen: u64) -> Result<()> {
    sqlx::query("UPDATE front_node SET applied_config_gen = ? WHERE id = ?")
        .bind(gen as i64)
        .bind(node_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Persisted capacity-counter state used by the reset-aware accumulation engine
/// (rev3 §A / Rec#3). Mirrors the `front_node` capacity-runtime columns.
#[derive(Debug, Clone, Default)]
pub struct CapacityState {
    pub accumulated_usage_bytes: u64,
    pub counter_epoch: u64,
    pub last_tx_bytes_total: u64,
    pub last_rx_bytes_total: u64,
    pub has_counter_baseline: bool,
}

/// Read the persisted capacity-counter state for a node.
///
/// # Errors
/// Returns [`PanelError::NotFound`] if the node is absent.
pub async fn get_capacity_state(pool: &SqlitePool, node_id: &str) -> Result<CapacityState> {
    let row = sqlx::query(
        "SELECT accumulated_usage_bytes, counter_epoch, last_tx_bytes_total,
                last_rx_bytes_total, has_counter_baseline
         FROM front_node WHERE id = ?",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| PanelError::NotFound("front_node".into()))?;
    Ok(CapacityState {
        accumulated_usage_bytes: row.get::<i64, _>("accumulated_usage_bytes") as u64,
        counter_epoch: row.get::<i64, _>("counter_epoch") as u64,
        last_tx_bytes_total: row.get::<i64, _>("last_tx_bytes_total") as u64,
        last_rx_bytes_total: row.get::<i64, _>("last_rx_bytes_total") as u64,
        has_counter_baseline: row.get::<i64, _>("has_counter_baseline") != 0,
    })
}

/// Persist the capacity-counter state + derived runtime fields on EVERY accepted
/// report (rev3 §B / Rec#2 — near-zero loss window).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
#[allow(clippy::too_many_arguments)]
pub async fn persist_capacity(
    pool: &SqlitePool,
    node_id: &str,
    state: &CapacityState,
    current_throughput_bps: u64,
    saturation_state: SaturationState,
    availability_state: contract::model::AvailabilityState,
    last_seen: u64,
) -> Result<()> {
    sqlx::query(
        "UPDATE front_node SET
            accumulated_usage_bytes = ?, counter_epoch = ?, last_tx_bytes_total = ?,
            last_rx_bytes_total = ?, has_counter_baseline = ?, current_throughput_bps = ?,
            saturation_state = ?, availability_state = ?, last_seen = ?, status = 'online'
         WHERE id = ?",
    )
    .bind(state.accumulated_usage_bytes as i64)
    .bind(state.counter_epoch as i64)
    .bind(state.last_tx_bytes_total as i64)
    .bind(state.last_rx_bytes_total as i64)
    .bind(i64::from(state.has_counter_baseline))
    .bind(current_throughput_bps as i64)
    .bind(sat_str(saturation_state))
    .bind(avail_str(availability_state))
    .bind(last_seen as i64)
    .bind(node_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reset accumulated usage to 0 (quota_reset_day rollover).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn reset_usage(pool: &SqlitePool, node_id: &str) -> Result<()> {
    sqlx::query("UPDATE front_node SET accumulated_usage_bytes = 0 WHERE id = ?")
        .bind(node_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- Agent / token ----------

/// Insert or replace an agent record (token hash + version + conn state).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn upsert_agent(pool: &SqlitePool, a: &Agent) -> Result<()> {
    let conn = match a.conn_state {
        ConnState::Connected => "connected",
        ConnState::Disconnected => "disconnected",
    };
    sqlx::query(
        "INSERT INTO agent(node_id, token_hash, agent_version, conn_state) VALUES(?,?,?,?)
         ON CONFLICT(node_id) DO UPDATE SET
            token_hash=excluded.token_hash, agent_version=excluded.agent_version,
            conn_state=excluded.conn_state",
    )
    .bind(&a.node_id)
    .bind(&a.token_hash)
    .bind(&a.agent_version)
    .bind(conn)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch an agent record.
///
/// # Errors
/// Returns [`PanelError::NotFound`] if absent.
pub async fn get_agent(pool: &SqlitePool, node_id: &str) -> Result<Agent> {
    let row = sqlx::query(
        "SELECT node_id, token_hash, agent_version, conn_state FROM agent WHERE node_id = ?",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| PanelError::NotFound("agent".into()))?;
    let conn = match row.get::<String, _>("conn_state").as_str() {
        "connected" => ConnState::Connected,
        _ => ConnState::Disconnected,
    };
    Ok(Agent {
        node_id: row.get("node_id"),
        token_hash: row.get("token_hash"),
        agent_version: row.get("agent_version"),
        conn_state: conn,
    })
}

/// Mark an agent disconnected (on socket teardown).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn set_agent_conn_disconnected(pool: &SqlitePool, node_id: &str) -> Result<()> {
    sqlx::query("UPDATE agent SET conn_state = 'disconnected' WHERE node_id = ?")
        .bind(node_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set an agent's token hash (token rotation, gap 7.6).
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn set_agent_token_hash(pool: &SqlitePool, node_id: &str, hash: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO agent(node_id, token_hash) VALUES(?, ?)
         ON CONFLICT(node_id) DO UPDATE SET token_hash = excluded.token_hash",
    )
    .bind(node_id)
    .bind(hash)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------- ForwardRule ----------

/// Insert or replace a forward rule.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn upsert_rule(pool: &SqlitePool, r: &ForwardRule) -> Result<()> {
    sqlx::query(
        "INSERT INTO forward_rule(id, node_id, listen_port, protocol, backend_host, backend_port, tool, tls_mode)
         VALUES(?,?,?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
            node_id=excluded.node_id, listen_port=excluded.listen_port, protocol=excluded.protocol,
            backend_host=excluded.backend_host, backend_port=excluded.backend_port, tool=excluded.tool,
            tls_mode=excluded.tls_mode",
    )
    .bind(&r.id)
    .bind(&r.node_id)
    .bind(i64::from(r.listen_port))
    .bind(proto_str(r.protocol))
    .bind(&r.backend_host)
    .bind(i64::from(r.backend_port))
    .bind(tool_str(r.tool))
    .bind(tls_mode_str(r.tls_mode))
    .execute(pool)
    .await?;
    Ok(())
}

fn row_to_rule(row: &sqlx::sqlite::SqliteRow) -> ForwardRule {
    ForwardRule {
        id: row.get("id"),
        node_id: row.get("node_id"),
        listen_port: row.get::<i64, _>("listen_port") as u16,
        protocol: proto_from(&row.get::<String, _>("protocol")),
        backend_host: row.get("backend_host"),
        backend_port: row.get::<i64, _>("backend_port") as u16,
        tool: tool_from(&row.get::<String, _>("tool")),
        tls_mode: tls_mode_from(&row.get::<String, _>("tls_mode")),
    }
}

/// List rules for a node.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn list_rules_for_node(pool: &SqlitePool, node_id: &str) -> Result<Vec<ForwardRule>> {
    let rows = sqlx::query("SELECT * FROM forward_rule WHERE node_id = ? ORDER BY listen_port")
        .bind(node_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_rule).collect())
}

/// List all rules.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn list_rules(pool: &SqlitePool) -> Result<Vec<ForwardRule>> {
    let rows = sqlx::query("SELECT * FROM forward_rule ORDER BY id")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_rule).collect())
}

/// Delete a rule.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_rule(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM forward_rule WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- LineGroup ----------

/// Insert or replace a line group.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn upsert_line_group(pool: &SqlitePool, g: &LineGroup) -> Result<()> {
    let members = serde_json::to_string(&g.member_node_ids).unwrap_or_else(|_| "[]".into());
    sqlx::query(
        "INSERT INTO line_group(id, name, zone_id, match_region, match_isp, member_node_ids, priority, fallback_group)
         VALUES(?,?,?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
            name=excluded.name, zone_id=excluded.zone_id, match_region=excluded.match_region,
            match_isp=excluded.match_isp, member_node_ids=excluded.member_node_ids,
            priority=excluded.priority, fallback_group=excluded.fallback_group",
    )
    .bind(&g.id)
    .bind(&g.name)
    .bind(&g.zone_id)
    .bind(g.match_region.map(i64::from))
    .bind(g.match_isp.map(|i| isp_str(i).to_string()))
    .bind(members)
    .bind(i64::from(g.priority))
    .bind(&g.fallback_group)
    .execute(pool)
    .await?;
    Ok(())
}

fn row_to_group(row: &sqlx::sqlite::SqliteRow) -> LineGroup {
    let members: Vec<String> =
        serde_json::from_str(&row.get::<String, _>("member_node_ids")).unwrap_or_default();
    LineGroup {
        id: row.get("id"),
        name: row.get("name"),
        zone_id: row.get::<Option<String>, _>("zone_id"),
        match_region: row.get::<Option<i64>, _>("match_region").map(|v| v as u16),
        match_isp: row
            .get::<Option<String>, _>("match_isp")
            .map(|s| isp_from(&s)),
        member_node_ids: members,
        priority: row.get::<i64, _>("priority") as i32,
        fallback_group: row.get::<Option<String>, _>("fallback_group"),
    }
}

/// List all line groups.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn list_line_groups(pool: &SqlitePool) -> Result<Vec<LineGroup>> {
    let rows = sqlx::query("SELECT * FROM line_group ORDER BY priority, id")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_group).collect())
}

/// Delete a line group.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_line_group(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM line_group WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- DnsZone ----------

/// Insert or replace a DNS zone.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn upsert_zone(pool: &SqlitePool, z: &DnsZone) -> Result<()> {
    let ns = serde_json::to_string(&z.ns).unwrap_or_else(|_| "[]".into());
    sqlx::query(
        "INSERT INTO dns_zone(id, apex_domain, soa, ns, default_ttl) VALUES(?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
            apex_domain=excluded.apex_domain, soa=excluded.soa, ns=excluded.ns,
            default_ttl=excluded.default_ttl",
    )
    .bind(&z.id)
    .bind(&z.apex_domain)
    .bind(&z.soa)
    .bind(ns)
    .bind(i64::from(z.default_ttl))
    .execute(pool)
    .await?;
    Ok(())
}

fn row_to_zone(row: &sqlx::sqlite::SqliteRow) -> DnsZone {
    let ns: Vec<String> = serde_json::from_str(&row.get::<String, _>("ns")).unwrap_or_default();
    DnsZone {
        id: row.get("id"),
        apex_domain: row.get("apex_domain"),
        soa: row.get("soa"),
        ns,
        default_ttl: row.get::<i64, _>("default_ttl") as u32,
    }
}

/// List all DNS zones.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn list_zones(pool: &SqlitePool) -> Result<Vec<DnsZone>> {
    let rows = sqlx::query("SELECT * FROM dns_zone ORDER BY id")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_zone).collect())
}

/// Delete a DNS zone.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_zone(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM dns_zone WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- Settings (key-value) ----------

/// Read a single setting value by key, decrypting if the key is in
/// [`crypto::ENCRYPTED_KEYS`] and a vault is provided.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn get_setting(
    pool: &SqlitePool,
    key: &str,
    vault: Option<&Vault>,
) -> Result<Option<String>> {
    let row = sqlx::query("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    match row {
        Some(r) => {
            let raw: String = r.get("value");
            if crypto::is_encrypted_key(key) {
                if let Some(v) = vault {
                    let (plaintext, _) = v.decrypt_or_plaintext(&raw);
                    Ok(Some(plaintext))
                } else {
                    Ok(Some(raw))
                }
            } else {
                Ok(Some(raw))
            }
        }
        None => Ok(None),
    }
}

/// Insert or update a setting, encrypting if the key is in
/// [`crypto::ENCRYPTED_KEYS`] and a vault is provided.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn set_setting(
    pool: &SqlitePool,
    key: &str,
    value: &str,
    vault: Option<&Vault>,
) -> Result<()> {
    let store_value = if crypto::is_encrypted_key(key) {
        if let Some(v) = vault {
            v.encrypt(value)?
        } else {
            value.to_string()
        }
    } else {
        value.to_string()
    };
    sqlx::query(
        "INSERT INTO settings(key, value) VALUES(?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(&store_value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a setting by key.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_setting(pool: &SqlitePool, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM settings WHERE key = ?")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

/// Cloudflare configuration loaded from the `settings` table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CfConfigDb {
    pub cf_token: String,
    pub cf_zone_id: String,
    pub cf_domain: String,
    pub cf_subdomain: String,
    pub cf_ns_name: String,
    pub cf_panel_ip: String,
}

/// All CF-related setting keys.
pub const CF_SETTING_KEYS: &[&str] = &[
    "cf_token",
    "cf_zone_id",
    "cf_domain",
    "cf_subdomain",
    "cf_ns_name",
    "cf_panel_ip",
];

/// Load the Cloudflare config from the `settings` table, decrypting secrets via
/// the provided vault.
/// Returns `None` if the required keys (`cf_token`, `cf_zone_id`, `cf_domain`) are absent.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn get_cf_config(pool: &SqlitePool, vault: Option<&Vault>) -> Result<Option<CfConfigDb>> {
    let token = get_setting(pool, "cf_token", vault).await?;
    let zone_id = get_setting(pool, "cf_zone_id", vault).await?;
    let domain = get_setting(pool, "cf_domain", vault).await?;

    let (Some(token), Some(zone_id), Some(domain)) = (token, zone_id, domain) else {
        return Ok(None);
    };
    if token.is_empty() || zone_id.is_empty() || domain.is_empty() {
        return Ok(None);
    }

    let subdomain = get_setting(pool, "cf_subdomain", vault)
        .await?
        .unwrap_or_else(|| "emby".to_string());
    let ns_name = get_setting(pool, "cf_ns_name", vault)
        .await?
        .unwrap_or_else(|| "ns1".to_string());
    let cf_panel_ip = get_setting(pool, "cf_panel_ip", vault)
        .await?
        .unwrap_or_default();

    Ok(Some(CfConfigDb {
        cf_token: token,
        cf_zone_id: zone_id,
        cf_domain: domain,
        cf_subdomain: subdomain,
        cf_ns_name: ns_name,
        cf_panel_ip,
    }))
}

/// Delete all CF-related settings from the `settings` table.
///
/// # Errors
/// Returns [`PanelError::Db`] on failure.
pub async fn delete_cf_config(pool: &SqlitePool) -> Result<()> {
    for key in CF_SETTING_KEYS {
        delete_setting(pool, key).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem() -> SqlitePool {
        connect("sqlite::memory:").await.expect("connect")
    }

    fn now_ms() -> i64 {
        now_ms_i64()
    }

    #[tokio::test]
    async fn session_within_ttl_resolves_and_logout_invalidates() {
        let pool = mem().await;
        create_session(&pool, "tok-fresh", "admin", now_ms())
            .await
            .unwrap();
        // Fresh session resolves to the user (security MEDIUM #2: live session).
        assert_eq!(
            session_user(&pool, "tok-fresh").await.unwrap(),
            Some("admin".to_string())
        );
        // Logout (delete_session) actually invalidates it (was a no-op before).
        delete_session(&pool, "tok-fresh").await.unwrap();
        assert_eq!(session_user(&pool, "tok-fresh").await.unwrap(), None);
    }

    #[tokio::test]
    async fn expired_session_is_rejected() {
        let pool = mem().await;
        // Stamp the session just past the 7-day TTL.
        let stale = now_ms() - SESSION_TTL_MS - 1;
        create_session(&pool, "tok-stale", "admin", stale)
            .await
            .unwrap();
        // Rejected (resolves to None) even though the row exists.
        assert_eq!(session_user(&pool, "tok-stale").await.unwrap(), None);
        // And it is pruned by the rejecting read.
        let still = sqlx::query("SELECT token FROM session WHERE token = ?")
            .bind("tok-stale")
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert!(still.is_none(), "expired session row should be pruned");
    }

    fn test_vault() -> Vault {
        Vault::from_key(&[0x42u8; 32])
    }

    #[tokio::test]
    async fn encrypted_setting_roundtrip() {
        let pool = mem().await;
        let vault = test_vault();
        let token = "cf-secret-token-value-12345";

        // Write cf_token with vault — it should be encrypted in DB.
        set_setting(&pool, "cf_token", token, Some(&vault))
            .await
            .unwrap();

        // Read raw DB value (no vault) — must NOT be the plaintext.
        let raw = get_setting(&pool, "cf_token", None).await.unwrap().unwrap();
        assert_ne!(raw, token, "cf_token must be encrypted at rest");

        // Read with vault — must recover the plaintext.
        let decrypted = get_setting(&pool, "cf_token", Some(&vault))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, token);
    }

    #[tokio::test]
    async fn non_encrypted_setting_stored_plaintext() {
        let pool = mem().await;
        let vault = test_vault();

        // A key NOT in ENCRYPTED_KEYS — should be stored as plaintext.
        set_setting(&pool, "some_other_key", "hello", Some(&vault))
            .await
            .unwrap();
        let raw = get_setting(&pool, "some_other_key", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw, "hello", "non-secret keys remain plaintext");
    }

    #[tokio::test]
    async fn auto_migration_plaintext_to_encrypted() {
        let pool = mem().await;
        let vault = test_vault();
        let token = "old-plaintext-cf-token";

        // Simulate a pre-migration DB: write cf_token WITHOUT vault (plaintext).
        set_setting(&pool, "cf_token", token, None).await.unwrap();
        let raw_before = get_setting(&pool, "cf_token", None).await.unwrap().unwrap();
        assert_eq!(raw_before, token, "stored as plaintext initially");

        // Migration: read raw, detect plaintext, re-encrypt.
        let (plaintext, was_encrypted) = vault.decrypt_or_plaintext(&raw_before);
        assert!(!was_encrypted, "should detect as plaintext");
        assert_eq!(plaintext, token);

        // Re-save encrypted.
        set_setting(&pool, "cf_token", &plaintext, Some(&vault))
            .await
            .unwrap();

        // Verify: raw DB value is now encrypted.
        let raw_after = get_setting(&pool, "cf_token", None).await.unwrap().unwrap();
        assert_ne!(raw_after, token, "must be encrypted after migration");

        // Verify: reading with vault returns the original plaintext.
        let decrypted = get_setting(&pool, "cf_token", Some(&vault))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, token);
    }

    #[tokio::test]
    async fn get_cf_config_decrypts_token() {
        let pool = mem().await;
        let vault = test_vault();
        let v = Some(&vault as &Vault);

        // Seed all required CF settings.
        set_setting(&pool, "cf_token", "secret-tok", v)
            .await
            .unwrap();
        set_setting(&pool, "cf_zone_id", "z1", v).await.unwrap();
        set_setting(&pool, "cf_domain", "example.com", v)
            .await
            .unwrap();
        set_setting(&pool, "cf_subdomain", "emby", v).await.unwrap();
        set_setting(&pool, "cf_ns_name", "ns1", v).await.unwrap();
        set_setting(&pool, "cf_panel_ip", "1.2.3.4", v)
            .await
            .unwrap();

        let cf = get_cf_config(&pool, v).await.unwrap().unwrap();
        assert_eq!(cf.cf_token, "secret-tok");
        assert_eq!(cf.cf_zone_id, "z1");
        assert_eq!(cf.cf_domain, "example.com");
    }
}
