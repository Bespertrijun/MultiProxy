//! CRUD APIs + auth endpoints (Line A task 3 / AC-1, AC-2 inputs, AC-3, AC-8).
//!
//! Management routes are guarded by the session-cookie middleware ([`auth::require_session`]);
//! `/login` and the static UI are public. The :53 DNS surface is on a separate runtime
//! and not routed here (auth-exempt by construction).

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use contract::isp::Isp;
use contract::model::{
    Agent, ConnState, DnsZone, ForwardRule, FrontNode, LineGroup, NodeStatus, TlsMode,
};
use serde::{Deserialize, Serialize};

use crate::auth::{self, SESSION_COOKIE};
use crate::error::{PanelError, Result};
use crate::state::AppState;
use crate::totp;
use crate::updater;
use crate::ws_server::{now_ms, push_config_to, rebuild_and_store_snapshot};
use crate::{acme, cloudflare, db, ui, ws_server};

/// Default download URL for GeoCN.mmdb (ljxi/GeoCN latest release).
const GEOCN_DEFAULT_URL: &str = "https://github.com/ljxi/GeoCN/releases/latest/download/GeoCN.mmdb";

async fn detect_public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let ip = client
        .get("https://api.ipify.org")
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?
        .trim()
        .to_string();
    if ip.is_empty() {
        None
    } else {
        Some(ip)
    }
}

/// Maximum download size (100 MB) to prevent abuse.
const GEOCN_MAX_SIZE: u64 = 100 * 1024 * 1024;

/// Download timeout (30 seconds).
const GEOCN_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Build the management router (guarded) + public auth/UI routes.
pub fn router(state: AppState) -> Router {
    let guarded = Router::new()
        .route("/api/nodes", get(list_nodes).post(create_node))
        .route(
            "/api/nodes/{id}",
            get(get_node).put(update_node).delete(delete_node),
        )
        .route("/api/nodes/{id}/token", post(regen_token))
        .route("/api/rules", get(list_rules).post(create_rule))
        .route("/api/rules/{id}", axum::routing::delete(delete_rule))
        .route("/api/line-groups", get(list_groups).post(create_group))
        .route(
            "/api/line-groups/{id}",
            axum::routing::put(update_group).delete(delete_group),
        )
        .route("/api/zones", get(list_zones).post(create_zone))
        .route("/api/zones/{id}", axum::routing::delete(delete_zone))
        .route(
            "/api/zones/{id}/cert",
            get(zone_cert_status).post(zone_cert_issue),
        )
        .route("/api/health", get(health_view))
        .route("/api/events", get(sse_events))
        .route("/api/dns-diag", get(dns_diag_list).delete(dns_diag_clear))
        .route("/api/geocn/update", post(geocn_update))
        .route("/api/geocn/status", get(geocn_status))
        .route("/api/cf/sync", post(cf_sync))
        .route("/api/cert/status", get(cert_status))
        .route("/api/acme/renew", post(acme_renew))
        .route(
            "/api/settings/cf",
            get(get_cf_settings)
                .put(put_cf_settings)
                .delete(delete_cf_settings),
        )
        .route("/api/version", get(version_info))
        .route("/api/update/check", get(update_check))
        .route("/api/update/panel", post(update_panel))
        .route("/api/update/agents", post(update_agents))
        .route("/api/logout", post(logout))
        .route("/api/change-password", post(change_password))
        .route("/api/2fa/status", get(totp_status))
        .route("/api/2fa/setup", post(totp_setup))
        .route("/api/2fa/enable", post(totp_enable))
        .route("/api/2fa/disable", post(totp_disable))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));

    let public = Router::new()
        .route("/", get(index))
        .route("/api/login", post(login))
        .route("/ui/{*path}", get(ui::static_handler))
        .route("/agent", get(ws_server::agent_ws))
        .route("/install.sh", get(install_script))
        .route("/dl/{filename}", get(dl_agent_binary));

    // Defense-in-depth security headers on every UI/API response (security LOW #6):
    // CSP allows Tailwind CDN + Google Fonts for the embedded UI. (Cookie `Secure` + TLS are M3.)
    use axum::http::{HeaderName, HeaderValue};
    use tower_http::set_header::SetResponseHeaderLayer;
    public
        .merge(guarded)
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state)
}

// ---------- auth ----------

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
    /// TOTP code for the second factor (only needed when 2FA is enabled).
    #[serde(default)]
    code: Option<String>,
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    let user = match db::get_user(&state.db, &req.username).await {
        Ok(u) => u,
        Err(_) => return PanelError::Unauthorized.into_response(),
    };
    // Password is the first factor; a wrong password is a plain 401 and never reveals
    // whether 2FA is configured (that signal is gated behind a correct password).
    if !auth::verify_password(&req.password, &user.password_hash) {
        return PanelError::Unauthorized.into_response();
    }
    // Second factor: if enabled, a valid TOTP code is required before a session issues.
    if user.totp_enabled {
        let Some(secret) = user
            .totp_secret
            .as_deref()
            .and_then(|enc| state.vault.decrypt(enc).ok())
        else {
            return PanelError::Internal("totp secret".into()).into_response();
        };
        match req.code.as_deref() {
            None | Some("") => {
                return Json(serde_json::json!({ "ok": false, "need_2fa": true })).into_response();
            }
            Some(code) if !totp::verify(&secret, code) => {
                return Json(
                    serde_json::json!({ "ok": false, "need_2fa": true, "error": "code_invalid" }),
                )
                .into_response();
            }
            Some(_) => {}
        }
    }
    let token = auth::new_token();
    if db::create_session(&state.db, &token, &user.username, now_ms() as i64)
        .await
        .is_err()
    {
        return PanelError::Internal("session".into()).into_response();
    }
    // Max-Age bounds the cookie lifetime to the server-side session TTL (7 days,
    // security MEDIUM #2). (Secure flag is deferred to M3 with panel-side TLS.)
    let cookie =
        format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800");
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "ok": true })),
    )
        .into_response()
}

async fn logout(State(state): State<AppState>, headers: header::HeaderMap) -> Response {
    // Actually invalidate the server-side session for this request's cookie
    // (security MEDIUM #2 — logout was previously a no-op). Also expire the cookie.
    let cookie_header = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    if let Some(token) = auth::session_from_cookies(cookie_header) {
        let _ = db::delete_session(&state.db, &token).await;
    }
    let expire = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    (
        StatusCode::OK,
        [(header::SET_COOKIE, expire)],
        Json(serde_json::json!({ "ok": true })),
    )
        .into_response()
}

// ---------- change password ----------

#[derive(Deserialize)]
struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    headers: header::HeaderMap,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    // Resolve the current user from the session cookie.
    let cookie_header = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    let token = match auth::session_from_cookies(cookie_header) {
        Some(t) => t,
        None => return PanelError::Unauthorized.into_response(),
    };
    let username = match db::session_user(&state.db, &token).await {
        Ok(Some(u)) => u,
        _ => return PanelError::Unauthorized.into_response(),
    };

    // Verify current password.
    let user = match db::get_user(&state.db, &username).await {
        Ok(u) => u,
        Err(_) => return PanelError::Unauthorized.into_response(),
    };
    if !auth::verify_password(&req.current_password, &user.password_hash) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "wrong current password" })),
        )
            .into_response();
    }

    // Validate new password length.
    if req.new_password.len() < 6 {
        return PanelError::BadRequest("new password must be at least 6 characters".into())
            .into_response();
    }

    // Hash and persist.
    let new_hash = match auth::hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = db::update_user_password(&state.db, &username, &new_hash).await {
        return e.into_response();
    }

    // Invalidate ALL sessions for this user.
    let _ = db::delete_sessions_for_user(&state.db, &username).await;

    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

// ---------- two-factor auth (TOTP) ----------

/// Resolve the logged-in username from the request's session cookie.
async fn session_username(state: &AppState, headers: &header::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    let token = auth::session_from_cookies(cookie_header)?;
    db::session_user(&state.db, &token).await.ok().flatten()
}

#[derive(Deserialize)]
struct TotpCodeReq {
    code: String,
}

#[derive(Deserialize)]
struct TotpDisableReq {
    password: String,
    code: String,
}

/// Whether 2FA is currently enabled for the logged-in user.
async fn totp_status(State(state): State<AppState>, headers: header::HeaderMap) -> Response {
    let Some(username) = session_username(&state, &headers).await else {
        return PanelError::Unauthorized.into_response();
    };
    let enabled = db::get_user(&state.db, &username)
        .await
        .map(|u| u.totp_enabled)
        .unwrap_or(false);
    Json(serde_json::json!({ "enabled": enabled })).into_response()
}

/// Begin enrolment: generate a fresh secret (stored encrypted, NOT yet enabled) and
/// return the otpauth URL + QR for the authenticator app. Safe to call repeatedly
/// (each call rolls a new pending secret until `enable` confirms it).
async fn totp_setup(State(state): State<AppState>, headers: header::HeaderMap) -> Response {
    let Some(username) = session_username(&state, &headers).await else {
        return PanelError::Unauthorized.into_response();
    };
    let secret = totp::generate_secret();
    let (Ok(url), Ok(qr)) = (
        totp::provisioning_url(&secret, &username),
        totp::qr_base64(&secret, &username),
    ) else {
        return PanelError::Internal("totp provisioning".into()).into_response();
    };
    let Ok(enc) = state.vault.encrypt(&secret) else {
        return PanelError::Internal("totp encrypt".into()).into_response();
    };
    // Store the pending secret but keep 2FA disabled until `enable` verifies a code.
    if let Err(e) = db::set_user_totp(&state.db, &username, Some(&enc), false).await {
        return e.into_response();
    }
    Json(serde_json::json!({ "secret": secret, "otpauth_url": url, "qr": qr })).into_response()
}

/// Confirm enrolment: verify a code against the pending secret, then enable 2FA.
async fn totp_enable(
    State(state): State<AppState>,
    headers: header::HeaderMap,
    Json(req): Json<TotpCodeReq>,
) -> Response {
    let Some(username) = session_username(&state, &headers).await else {
        return PanelError::Unauthorized.into_response();
    };
    let Ok(user) = db::get_user(&state.db, &username).await else {
        return PanelError::Unauthorized.into_response();
    };
    let Some(secret) = user
        .totp_secret
        .as_deref()
        .and_then(|enc| state.vault.decrypt(enc).ok())
    else {
        return PanelError::BadRequest("先调用 setup 生成密钥".into()).into_response();
    };
    if !totp::verify(&secret, &req.code) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "验证码不正确" })),
        )
            .into_response();
    }
    if let Err(e) = db::set_user_totp(&state.db, &username, user.totp_secret.as_deref(), true).await
    {
        return e.into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

/// Disable 2FA: requires the current password AND a valid current code, then wipes
/// the secret.
async fn totp_disable(
    State(state): State<AppState>,
    headers: header::HeaderMap,
    Json(req): Json<TotpDisableReq>,
) -> Response {
    let Some(username) = session_username(&state, &headers).await else {
        return PanelError::Unauthorized.into_response();
    };
    let Ok(user) = db::get_user(&state.db, &username).await else {
        return PanelError::Unauthorized.into_response();
    };
    if !auth::verify_password(&req.password, &user.password_hash) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "密码不正确" })),
        )
            .into_response();
    }
    let code_ok = user
        .totp_secret
        .as_deref()
        .and_then(|enc| state.vault.decrypt(enc).ok())
        .is_some_and(|secret| totp::verify(&secret, &req.code));
    if !code_ok {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "验证码不正确" })),
        )
            .into_response();
    }
    if let Err(e) = db::set_user_totp(&state.db, &username, None, false).await {
        return e.into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

// ---------- FrontNode + token ----------

#[derive(Deserialize)]
struct CreateNodeReq {
    name: String,
    public_ip: String,
    #[serde(default)]
    division_code: u32,
    #[serde(default)]
    isp: Option<Isp>,
    #[serde(default)]
    bandwidth_cap_mbps: Option<u32>,
    #[serde(default)]
    traffic_quota_bytes: Option<u64>,
    #[serde(default)]
    quota_direction: Option<contract::model::QuotaDirection>,
    #[serde(default)]
    quota_reset_day: Option<u8>,
}

#[derive(Serialize)]
struct CreateNodeResp {
    node: FrontNode,
    /// The agent token, shown exactly ONCE (hashed at rest; AC-1).
    token: String,
}

async fn create_node(
    State(state): State<AppState>,
    Json(req): Json<CreateNodeReq>,
) -> Result<Json<CreateNodeResp>> {
    if req.name.trim().is_empty() {
        return Err(PanelError::BadRequest("name required".into()));
    }
    let id = auth::new_token();
    let region = geoip::division::decode(req.division_code);
    let node = FrontNode {
        id: id.clone(),
        name: req.name,
        public_ip: req.public_ip,
        region,
        isp: req.isp.unwrap_or(Isp::Unknown),
        status: NodeStatus::Unknown,
        last_seen: 0,
        desired_config_gen: 0,
        applied_config_gen: 0,
        bandwidth_cap_mbps: req.bandwidth_cap_mbps,
        traffic_quota_bytes: req.traffic_quota_bytes,
        quota_direction: req.quota_direction.unwrap_or_default(),
        quota_reset_day: req.quota_reset_day,
        soft_quota_pct: 90,
        hard_quota_pct: 100,
        accumulated_usage_bytes: 0,
        current_throughput_bps: 0,
        saturation_state: contract::model::SaturationState::Normal,
        availability_state: contract::model::AvailabilityState::Available,
    };
    db::upsert_node(&state.db, &node).await?;

    // Generate the agent token: shown once, hashed at rest (AC-1).
    let token = auth::new_token();
    let token_hash = auth::hash_token(&token);
    db::upsert_agent(
        &state.db,
        &Agent {
            node_id: id,
            token_hash,
            agent_version: String::new(),
            conn_state: ConnState::Disconnected,
        },
    )
    .await?;

    state.notify_change();
    Ok(Json(CreateNodeResp { node, token }))
}

async fn list_nodes(State(state): State<AppState>) -> Result<Json<Vec<FrontNode>>> {
    Ok(Json(db::list_nodes(&state.db).await?))
}

async fn get_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<FrontNode>> {
    Ok(Json(db::get_node(&state.db, &id).await?))
}

#[derive(Deserialize)]
struct UpdateNodeReq {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    public_ip: Option<String>,
    #[serde(default)]
    bandwidth_cap_mbps: Option<u32>,
    #[serde(default)]
    traffic_quota_bytes: Option<u64>,
    #[serde(default)]
    quota_direction: Option<contract::model::QuotaDirection>,
    #[serde(default)]
    quota_reset_day: Option<u8>,
}

async fn update_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateNodeReq>,
) -> Result<Json<FrontNode>> {
    let mut node = db::get_node(&state.db, &id).await?;
    if let Some(name) = req.name {
        if !name.trim().is_empty() {
            node.name = name;
        }
    }
    if let Some(ip) = req.public_ip {
        if !ip.trim().is_empty() {
            node.public_ip = ip;
        }
    }
    node.bandwidth_cap_mbps = req.bandwidth_cap_mbps.or(node.bandwidth_cap_mbps);
    node.traffic_quota_bytes = req.traffic_quota_bytes.or(node.traffic_quota_bytes);
    if let Some(dir) = req.quota_direction {
        node.quota_direction = dir;
    }
    if let Some(day) = req.quota_reset_day {
        node.quota_reset_day = Some(day);
    }
    db::upsert_node(&state.db, &node).await?;
    rebuild_and_store_snapshot(&state).await;
    Ok(Json(node))
}

async fn delete_node(State(state): State<AppState>, Path(id): Path<String>) -> Result<StatusCode> {
    db::delete_node(&state.db, &id).await?;
    rebuild_and_store_snapshot(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct TokenResp {
    token: String,
}

/// Rotate (regenerate) a node's agent token (gap 7.6). The new token is shown once;
/// the next heartbeat carrying the old token is rejected (handshake re-validates).
async fn regen_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TokenResp>> {
    db::get_node(&state.db, &id).await?; // ensure node exists
    let token = auth::new_token();
    let hash = auth::hash_token(&token);
    db::set_agent_token_hash(&state.db, &id, &hash).await?;
    Ok(Json(TokenResp { token }))
}

// ---------- ForwardRule ----------

#[derive(Deserialize)]
struct CreateRuleReq {
    node_id: String,
    listen_port: u16,
    protocol: contract::model::Protocol,
    backend_host: String,
    backend_port: u16,
    tool: contract::model::Tool,
    #[serde(default)]
    tls_mode: TlsMode,
}

/// Validate a `backend_host` against a safe charset before it is hand-written into the
/// realm TOML / gost JSON in `configgen.rs` (security LOW #9, defense-in-depth). Allows
/// ASCII alphanumeric + `.` `-` `:` (covers hostnames, IPv4, and bracketless IPv6 /
/// host:port forms), non-empty, ≤253 bytes. Rejects `"`/newline/space etc. that could
/// break the hand-built TOML.
fn validate_backend_host(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 {
        return Err(PanelError::BadRequest(
            "backend_host must be 1..=253 chars".into(),
        ));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(PanelError::BadRequest(
            "backend_host contains invalid characters (allowed: alphanumeric . - :)".into(),
        ));
    }
    Ok(())
}

async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleReq>,
) -> Result<Json<ForwardRule>> {
    db::get_node(&state.db, &req.node_id).await?; // FK check
    validate_backend_host(&req.backend_host)?;
    let rule = ForwardRule {
        id: auth::new_token(),
        node_id: req.node_id.clone(),
        listen_port: req.listen_port,
        protocol: req.protocol,
        backend_host: req.backend_host,
        backend_port: req.backend_port,
        tool: req.tool,
        tls_mode: req.tls_mode,
    };
    db::upsert_rule(&state.db, &rule).await?;
    // Bump desired config gen (D2) and push to the connected agent (Q6).
    db::bump_desired_gen(&state.db, &req.node_id).await?;
    push_config_to(&state, &req.node_id).await;
    state.notify_change();
    Ok(Json(rule))
}

async fn list_rules(State(state): State<AppState>) -> Result<Json<Vec<ForwardRule>>> {
    Ok(Json(db::list_rules(&state.db).await?))
}

async fn delete_rule(State(state): State<AppState>, Path(id): Path<String>) -> Result<StatusCode> {
    // Find the rule's node before deletion so we can re-push.
    let rules = db::list_rules(&state.db).await?;
    let node_id = rules.iter().find(|r| r.id == id).map(|r| r.node_id.clone());
    db::delete_rule(&state.db, &id).await?;
    if let Some(nid) = node_id {
        db::bump_desired_gen(&state.db, &nid).await?;
        push_config_to(&state, &nid).await;
    }
    state.notify_change();
    Ok(StatusCode::NO_CONTENT)
}

// ---------- LineGroup ----------

#[derive(Deserialize)]
struct CreateGroupReq {
    name: String,
    #[serde(default)]
    zone_id: Option<String>,
    #[serde(default)]
    match_region: Option<u16>,
    #[serde(default)]
    match_isp: Option<Isp>,
    #[serde(default)]
    member_node_ids: Vec<String>,
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    fallback_group: Option<String>,
}

async fn create_group(
    State(state): State<AppState>,
    Json(req): Json<CreateGroupReq>,
) -> Result<Json<LineGroup>> {
    let group = LineGroup {
        id: auth::new_token(),
        name: req.name,
        zone_id: req.zone_id,
        match_region: req.match_region,
        match_isp: req.match_isp,
        member_node_ids: req.member_node_ids,
        priority: req.priority,
        fallback_group: req.fallback_group,
    };
    db::upsert_line_group(&state.db, &group).await?;
    refresh_groups(&state).await?;
    Ok(Json(group))
}

async fn list_groups(State(state): State<AppState>) -> Result<Json<Vec<LineGroup>>> {
    Ok(Json(db::list_line_groups(&state.db).await?))
}

async fn update_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateGroupReq>,
) -> Result<Json<LineGroup>> {
    // PUT semantics: the group must already exist.
    if !db::list_line_groups(&state.db)
        .await?
        .iter()
        .any(|g| g.id == id)
    {
        return Err(PanelError::NotFound("line group".into()));
    }
    let group = LineGroup {
        id,
        name: req.name,
        zone_id: req.zone_id,
        match_region: req.match_region,
        match_isp: req.match_isp,
        member_node_ids: req.member_node_ids,
        priority: req.priority,
        fallback_group: req.fallback_group,
    };
    db::upsert_line_group(&state.db, &group).await?;
    refresh_groups(&state).await?;
    Ok(Json(group))
}

async fn delete_group(State(state): State<AppState>, Path(id): Path<String>) -> Result<StatusCode> {
    db::delete_line_group(&state.db, &id).await?;
    refresh_groups(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reload line groups into the shared ArcSwap (so the DNS resolver sees them) and
/// rebuild the snapshot.
async fn refresh_groups(state: &AppState) -> Result<()> {
    let groups = db::list_line_groups(&state.db).await?;
    state.groups.store(std::sync::Arc::new(groups));
    rebuild_and_store_snapshot(state).await;
    Ok(())
}

// ---------- DnsZone ----------

#[derive(Deserialize)]
struct CreateZoneReq {
    apex_domain: String,
    #[serde(default)]
    soa: String,
    #[serde(default)]
    ns: Vec<String>,
    #[serde(default = "default_ttl")]
    default_ttl: u32,
}

fn default_ttl() -> u32 {
    contract::model::DEFAULT_RESOLUTION_TTL_SECS
}

async fn create_zone(
    State(state): State<AppState>,
    Json(req): Json<CreateZoneReq>,
) -> Result<Json<DnsZone>> {
    let zone = DnsZone {
        id: auth::new_token(),
        apex_domain: req.apex_domain,
        soa: req.soa,
        ns: req.ns,
        default_ttl: req.default_ttl,
    };
    db::upsert_zone(&state.db, &zone).await?;
    refresh_zones(&state).await;

    if let Some(cf_cfg) = state.cf_config().await {
        let cf_client = cloudflare::CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);
        let ns_fqdn = format!("{}.{}", cf_cfg.ns_name, cf_cfg.domain);
        let _ = cf_client
            .upsert_record("NS", &zone.apex_domain, &ns_fqdn, false, 300)
            .await;

        // Issue the relay cert in the background (ACME takes tens of seconds; don't
        // block the create response). The UI polls per-zone cert status.
        let st = state.clone();
        let apex = zone.apex_domain.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::certs::issue_zone_cert(&st, &apex).await {
                tracing::warn!(domain = %apex, error = %e, "zone cert issuance failed");
            }
        });
    }

    Ok(Json(zone))
}

async fn list_zones(State(state): State<AppState>) -> Result<Json<Vec<DnsZone>>> {
    Ok(Json(db::list_zones(&state.db).await?))
}

async fn delete_zone(State(state): State<AppState>, Path(id): Path<String>) -> Result<StatusCode> {
    let zone = db::list_zones(&state.db)
        .await?
        .into_iter()
        .find(|z| z.id == id);
    db::delete_zone(&state.db, &id).await?;
    refresh_zones(&state).await;

    if let (Some(z), Some(cf_cfg)) = (zone, state.cf_config().await) {
        let cf_client = cloudflare::CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);
        let records = cf_client.list_records("NS", &z.apex_domain).await;
        if let Ok(recs) = records {
            for r in recs {
                let _ = cf_client.delete_record(&r.id).await;
            }
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn refresh_zones(state: &AppState) {
    if let Ok(zones) = db::list_zones(&state.db).await {
        state.zones.store(std::sync::Arc::new(zones));
    }
    // Unlike groups, zones don't rebuild the snapshot, so signal the UI directly.
    state.notify_change();
}

/// Report the relay cert status for one DNS zone (issued? loaded in memory? expiry).
async fn zone_cert_status(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let zones = db::list_zones(&state.db).await.unwrap_or_default();
    let Some(zone) = zones.into_iter().find(|z| z.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "zone not found" })),
        )
            .into_response();
    };
    let loaded = state.zone_cert(&zone.apex_domain).await.is_some();
    let status = match state.cf_config().await {
        Some(cf) => acme::read_cert_status(
            &std::path::Path::new(&cf.cert_dir).join(format!("{}.crt", zone.apex_domain)),
        ),
        None => acme::CertStatus {
            has_cert: false,
            subject: String::new(),
            expires_at: String::new(),
            days_remaining: 0,
        },
    };
    Json(serde_json::json!({
        "domain": zone.apex_domain,
        "loaded": loaded,
        "has_cert": status.has_cert,
        "subject": status.subject,
        "expires_at": status.expires_at,
        "days_remaining": status.days_remaining,
    }))
    .into_response()
}

/// Manually (re)issue the relay cert for one DNS zone via self-served DNS-01.
/// Awaits issuance so the UI gets a definitive ok/error.
async fn zone_cert_issue(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let zones = db::list_zones(&state.db).await.unwrap_or_default();
    let Some(zone) = zones.into_iter().find(|z| z.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "zone not found" })),
        )
            .into_response();
    };
    match crate::certs::issue_zone_cert(&state, &zone.apex_domain).await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

// ---------- SSE: push data-change signals to the UI (replaces 10s polling) ----------

/// Stream backend change signals to the browser via Server-Sent Events.
///
/// Each `notify_change()` on the server emits one event; the UI refetches the
/// resource lists on receipt (and diffs locally before re-rendering). On
/// `Lagged` we still emit a tick so a slow client refetches once and catches up.
/// `KeepAlive` comments keep the connection open through idle periods/proxies.
async fn sse_events(
    State(state): State<AppState>,
) -> axum::response::Sse<
    impl futures_util::Stream<
        Item = std::result::Result<axum::response::sse::Event, std::convert::Infallible>,
    >,
> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use tokio::sync::broadcast::error::RecvError;

    let rx = state.events.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(seq) => Some((Ok(Event::default().data(seq.to_string())), rx)),
            // Slow client dropped some ticks: emit one anyway so it refetches and catches up.
            Err(RecvError::Lagged(_)) => Some((Ok(Event::default().data("lagged")), rx)),
            Err(RecvError::Closed) => None,
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ---------- DNS resolution diagnostics (recent query traces for the UI) ----------

/// Return the most recent DNS resolution traces (newest first) for the diag panel.
async fn dns_diag_list() -> Json<Vec<crate::dns::diag::DiagEntry>> {
    Json(crate::dns::diag::recent())
}

/// Clear the buffered DNS resolution traces.
async fn dns_diag_clear() -> StatusCode {
    crate::dns::diag::clear();
    StatusCode::NO_CONTENT
}

// ---------- health / dashboard view (AC-5/AC-13 panel side) ----------

#[derive(Serialize)]
struct NodeHealth {
    id: String,
    name: String,
    public_ip: String,
    status: NodeStatus,
    connected: bool,
    throughput_bps: u64,
    accumulated_usage_bytes: u64,
    quota_used_ratio: Option<f64>,
    saturation_state: contract::model::SaturationState,
    availability_state: contract::model::AvailabilityState,
}

async fn health_view(State(state): State<AppState>) -> Result<Json<Vec<NodeHealth>>> {
    let nodes = db::list_nodes(&state.db).await?;
    let conns = state.conns.lock().await;
    let rts = state.runtimes.lock().await;
    let out = nodes
        .into_iter()
        .map(|n| {
            let connected = conns.contains_key(&n.id);
            let rt = rts.get(&n.id);
            let throughput = rt.map_or(n.current_throughput_bps, |r| r.throughput_bps);
            let used = rt.map_or(n.accumulated_usage_bytes, |r| {
                r.capacity.accumulated_usage_bytes
            });
            let quota_used_ratio = n
                .traffic_quota_bytes
                .filter(|q| *q > 0)
                .map(|q| used as f64 / q as f64);
            NodeHealth {
                id: n.id,
                name: n.name,
                public_ip: n.public_ip,
                status: n.status,
                connected,
                throughput_bps: throughput,
                accumulated_usage_bytes: used,
                quota_used_ratio,
                saturation_state: n.saturation_state,
                availability_state: n.availability_state,
            }
        })
        .collect();
    Ok(Json(out))
}

// ---------- GeoCN online update ----------

#[derive(Deserialize)]
struct GeocnUpdateQuery {
    url: Option<String>,
}

/// Report the active geo provider so the UI can warn when the unknown stub is in
/// effect (every lookup → province 0 / ISP Unknown, breaking region/ISP routing).
async fn geocn_status(State(state): State<AppState>) -> Response {
    let format = state.provider.current().format();
    let loaded = format != "unknown-stub";
    Json(serde_json::json!({
        "format": format,
        "loaded": loaded,
        "path": state.geocn_path,
    }))
    .into_response()
}

async fn geocn_update(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<GeocnUpdateQuery>,
) -> Response {
    let url = query.url.unwrap_or_else(|| GEOCN_DEFAULT_URL.to_string());
    let path = state.geocn_path.clone();

    let client = match reqwest::Client::builder()
        .timeout(GEOCN_DOWNLOAD_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("http client error: {e}") })),
            )
                .into_response();
        }
    };

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("download failed: {e}") })),
            )
                .into_response();
        }
    };

    if !resp.status().is_success() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "error": format!("download failed: HTTP {}", resp.status()) }),
            ),
        )
            .into_response();
    }

    // Check content-length if provided.
    if let Some(cl) = resp.content_length() {
        if cl > GEOCN_MAX_SIZE {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("file too large: {} bytes (max {})", cl, GEOCN_MAX_SIZE) })),
            )
                .into_response();
        }
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("failed to read body: {e}") })),
            )
                .into_response();
        }
    };

    if bytes.len() as u64 > GEOCN_MAX_SIZE {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "file too large" })),
        )
            .into_response();
    }

    // Write to disk.
    if let Err(e) = tokio::fs::write(&path, &bytes).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to write file: {e}") })),
        )
            .into_response();
    }

    // Validate the downloaded file.
    if let Err(e) = geoip::DbFormat::GeoCn.load(&path) {
        let _ = tokio::fs::remove_file(&path).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("invalid MMDB: {e}") })),
        )
            .into_response();
    }

    // Hot-reload the provider.
    if let Err(e) = state.provider.switch(geoip::DbFormat::GeoCn, &path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("reload failed: {e}") })),
        )
            .into_response();
    }

    let size = bytes.len() as u64;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "size_bytes": size, "path": path })),
    )
        .into_response()
}

// ---------- Cloudflare DNS sync ----------

async fn cf_sync(State(state): State<AppState>) -> Response {
    let Some(cf_cfg) = state.cf_config().await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Cloudflare not configured" })),
        )
            .into_response();
    };

    let cf = cloudflare::CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);
    match cloudflare::auto_setup_dns(
        &cf,
        &cf_cfg.domain,
        &cf_cfg.subdomain,
        &cf_cfg.panel_ip,
        &cf_cfg.ns_name,
    )
    .await
    {
        Ok(records) => {
            let names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "records": names })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ---------- Certificate status ----------

async fn cert_status(State(state): State<AppState>) -> Response {
    let Some(cf_cfg) = state.cf_config().await else {
        return Json(serde_json::json!(acme::CertStatus {
            has_cert: false,
            subject: String::new(),
            expires_at: String::new(),
            days_remaining: 0,
        }))
        .into_response();
    };

    let panel_domain = format!("panel.{}", cf_cfg.domain);
    let cert_path = std::path::Path::new(&cf_cfg.cert_dir).join(format!("{panel_domain}.crt"));
    let status = acme::read_cert_status(&cert_path);
    Json(serde_json::json!(status)).into_response()
}

// ---------- ACME cert renewal ----------

async fn acme_renew(State(state): State<AppState>) -> Response {
    let Some(cf_cfg) = state.cf_config().await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Cloudflare not configured" })),
        )
            .into_response();
    };

    let cf = cloudflare::CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);
    let panel_domain = format!("panel.{}", cf_cfg.domain);

    match acme::issue_cert(&cf, &panel_domain, &cf_cfg.cert_dir, cf_cfg.acme_staging).await {
        Ok(issued) => {
            state.set_tls_pair(issued.cert_pem, issued.key_pem).await;
            let cert_path =
                std::path::Path::new(&cf_cfg.cert_dir).join(format!("{panel_domain}.crt"));
            let status = acme::read_cert_status(&cert_path);
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "expires_at": status.expires_at })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

// ---------- CF settings CRUD ----------

/// Mask a token for display: show first 4 + last 4 chars, mask the rest.
fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        return "****".to_string();
    }
    let last = &token[token.len() - 4..];
    format!("****{last}")
}

#[derive(Serialize)]
struct CfSettingsResp {
    configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cf_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cf_zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cf_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cf_subdomain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cf_ns_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cf_panel_ip: Option<String>,
}

async fn get_cf_settings(State(state): State<AppState>) -> Response {
    let cf = match db::get_cf_config(&state.db, Some(&state.vault)).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Json(CfSettingsResp {
                configured: false,
                cf_token: None,
                cf_zone_id: None,
                cf_domain: None,
                cf_subdomain: None,
                cf_ns_name: None,
                cf_panel_ip: None,
            })
            .into_response();
        }
        Err(e) => return e.into_response(),
    };
    Json(CfSettingsResp {
        configured: true,
        cf_token: Some(mask_token(&cf.cf_token)),
        cf_zone_id: Some(cf.cf_zone_id),
        cf_domain: Some(cf.cf_domain),
        cf_subdomain: Some(cf.cf_subdomain),
        cf_ns_name: Some(cf.cf_ns_name),
        cf_panel_ip: Some(cf.cf_panel_ip),
    })
    .into_response()
}

#[derive(Deserialize)]
struct PutCfSettingsReq {
    cf_token: String,
    cf_zone_id: String,
    cf_domain: String,
    #[serde(default = "default_subdomain")]
    cf_subdomain: String,
    #[serde(default = "default_ns_name")]
    cf_ns_name: String,
    #[serde(default)]
    cf_panel_ip: String,
}
fn default_subdomain() -> String {
    "emby".to_string()
}
fn default_ns_name() -> String {
    "ns1".to_string()
}

async fn put_cf_settings(
    State(state): State<AppState>,
    Json(req): Json<PutCfSettingsReq>,
) -> Response {
    // Validate required fields.
    if req.cf_zone_id.is_empty() || req.cf_domain.is_empty() {
        return PanelError::BadRequest("cf_zone_id and cf_domain are required".into())
            .into_response();
    }

    // Resolve token: if it starts with "****", keep existing from DB.
    let vault_ref = Some(state.vault.as_ref());
    let token = if req.cf_token.starts_with("****") {
        match db::get_setting(&state.db, "cf_token", vault_ref).await {
            Ok(Some(t)) if !t.is_empty() => t,
            _ => {
                return PanelError::BadRequest(
                    "cf_token is required (no existing token found)".into(),
                )
                .into_response();
            }
        }
    } else if req.cf_token.is_empty() {
        return PanelError::BadRequest("cf_token is required".into()).into_response();
    } else {
        req.cf_token
    };

    // Save all fields to DB (cf_token is encrypted automatically by set_setting).
    if let Err(e) = db::set_setting(&state.db, "cf_token", &token, vault_ref).await {
        return e.into_response();
    }
    if let Err(e) = db::set_setting(&state.db, "cf_zone_id", &req.cf_zone_id, vault_ref).await {
        return e.into_response();
    }
    if let Err(e) = db::set_setting(&state.db, "cf_domain", &req.cf_domain, vault_ref).await {
        return e.into_response();
    }
    let subdomain = if req.cf_subdomain.is_empty() {
        "emby".to_string()
    } else {
        req.cf_subdomain
    };
    if let Err(e) = db::set_setting(&state.db, "cf_subdomain", &subdomain, vault_ref).await {
        return e.into_response();
    }
    let ns_name = if req.cf_ns_name.is_empty() {
        "ns1".to_string()
    } else {
        req.cf_ns_name
    };
    if let Err(e) = db::set_setting(&state.db, "cf_ns_name", &ns_name, vault_ref).await {
        return e.into_response();
    }
    if let Err(e) = db::set_setting(&state.db, "cf_panel_ip", &req.cf_panel_ip, vault_ref).await {
        return e.into_response();
    }

    let panel_ip = if req.cf_panel_ip.is_empty() {
        detect_public_ip().await.unwrap_or_default()
    } else {
        req.cf_panel_ip
    };

    // Build runtime CfConfig and update state.
    let cf_cfg = crate::state::CfConfig {
        token: token.clone(),
        zone_id: req.cf_zone_id,
        domain: req.cf_domain,
        subdomain,
        panel_ip,
        ns_name,
        acme_staging: state.cf_config().await.is_some_and(|c| c.acme_staging),
        cert_dir: state
            .cf_config()
            .await
            .map_or_else(|| "./certs".to_string(), |c| c.cert_dir),
    };
    state.set_cf_config(Some(cf_cfg.clone())).await;

    // Auto-create DNS Zone in panel if not exists.
    let zone_fqdn = format!("{}.{}", cf_cfg.subdomain, cf_cfg.domain);
    let ns_fqdn = format!("{}.{}", cf_cfg.ns_name, cf_cfg.domain);
    let existing_zones = db::list_zones(&state.db).await.unwrap_or_default();
    if !existing_zones.iter().any(|z| z.apex_domain == zone_fqdn) {
        let zone = DnsZone {
            id: uuid::Uuid::new_v4().to_string(),
            apex_domain: zone_fqdn,
            soa: String::new(),
            ns: vec![ns_fqdn],
            default_ttl: 60,
        };
        let _ = db::upsert_zone(&state.db, &zone).await;
    }

    // Try DNS sync (non-fatal).
    let dns_sync;
    if cf_cfg.panel_ip.is_empty() {
        dns_sync = "skipped: no panel IP configured".to_string();
    } else {
        let cf_client = cloudflare::CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);
        match cloudflare::auto_setup_dns(
            &cf_client,
            &cf_cfg.domain,
            &cf_cfg.subdomain,
            &cf_cfg.panel_ip,
            &cf_cfg.ns_name,
        )
        .await
        {
            Ok(records) => {
                dns_sync = format!("success ({} records)", records.len());
            }
            Err(e) => {
                dns_sync = format!("error: {e}");
            }
        }
    }

    // Try ACME cert check (non-fatal).
    let cert_status;
    if cf_cfg.panel_ip.is_empty() {
        cert_status = "skipped: no panel IP".to_string();
    } else {
        let panel_domain = format!("panel.{}", cf_cfg.domain);
        let cert_path = std::path::Path::new(&cf_cfg.cert_dir).join(format!("{panel_domain}.crt"));
        if acme::needs_renewal(&cert_path) {
            let cf_client = cloudflare::CfClient::new(&cf_cfg.token, &cf_cfg.zone_id);
            match acme::issue_cert(
                &cf_client,
                &panel_domain,
                &cf_cfg.cert_dir,
                cf_cfg.acme_staging,
            )
            .await
            {
                Ok(issued) => {
                    state.set_tls_pair(issued.cert_pem, issued.key_pem).await;
                    cert_status = "issued".to_string();
                }
                Err(e) => {
                    cert_status = format!("error: {e}");
                }
            }
        } else {
            cert_status = "valid".to_string();
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "dns_sync": dns_sync,
            "cert_status": cert_status,
        })),
    )
        .into_response()
}

async fn delete_cf_settings(State(state): State<AppState>) -> Response {
    if let Err(e) = db::delete_cf_config(&state.db).await {
        return e.into_response();
    }
    state.set_cf_config(None).await;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

// ---------- version + self-update ----------

async fn version_info() -> Response {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": contract::PROTOCOL_VERSION,
    }))
    .into_response()
}

async fn update_check() -> Response {
    match updater::check_update().await {
        Ok(info) => Json(serde_json::json!(info)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

async fn update_panel() -> Response {
    let info = match updater::check_update().await {
        Ok(i) => i,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("check failed: {e}") })),
            )
                .into_response();
        }
    };

    if !info.has_update {
        return Json(serde_json::json!({
            "ok": false,
            "message": "already up to date",
        }))
        .into_response();
    }

    let tag = info.latest_version.clone();
    // Respond before starting the update so the client gets the response.
    let msg = format!("updating to v{tag}, restarting...");
    tokio::spawn(async move {
        // Small delay so the HTTP response is flushed.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Err(e) = updater::self_update(&tag).await {
            tracing::error!("self-update failed: {e}");
        }
    });

    Json(serde_json::json!({
        "ok": true,
        "message": msg,
    }))
    .into_response()
}

async fn update_agents(State(state): State<AppState>) -> Response {
    let info = match updater::check_update().await {
        Ok(i) => i,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("check failed: {e}") })),
            )
                .into_response();
        }
    };

    let tag = if info.has_update {
        info.latest_version.clone()
    } else {
        info.current_version.clone()
    };

    let agent_bin_dir = std::path::Path::new(&state.agent_bin_dir);
    match updater::update_agent_binaries(&tag, agent_bin_dir).await {
        Ok(()) => Json(serde_json::json!({
            "ok": true,
            "message": format!("Agent binaries updated to v{tag}. Re-run the install script on each node or use `agent --self-update` to apply."),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

// ---------- install script + agent binary download ----------

/// Public route: returns a bash install script for one-click agent deployment.
async fn install_script() -> Response {
    let script = r##"#!/bin/bash
set -euo pipefail

# Usage: curl -sL https://panel.example.com/install.sh | bash -s -- \
#   --panel-url wss://panel.example.com/agent \
#   --node-id NODE_ID --token TOKEN

# Parse args
PANEL_URL="" NODE_ID="" TOKEN="" CONFIG_DIR="/etc/multiproxy"
while [[ $# -gt 0 ]]; do
  case $1 in
    --panel-url) PANEL_URL="$2"; shift 2;;
    --node-id) NODE_ID="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --config-dir) CONFIG_DIR="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done
[[ -z "$PANEL_URL" || -z "$NODE_ID" || -z "$TOKEN" ]] && echo "Usage: ... --panel-url URL --node-id ID --token TOKEN" && exit 1

# Detect arch
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) BINARY="agent-linux-x86_64";;
  aarch64|arm64) BINARY="agent-linux-aarch64";;
  *) echo "Unsupported arch: $ARCH"; exit 1;;
esac

# Download agent binary from panel
PANEL_BASE="${PANEL_URL%/agent}"  # strip /agent path to get base URL
PANEL_BASE="${PANEL_BASE/wss:\/\//https://}"  # wss -> https
PANEL_BASE="${PANEL_BASE/ws:\/\//http://}"    # ws -> http
echo "Downloading agent ($BINARY) from $PANEL_BASE/dl/$BINARY ..."
curl -fSL "$PANEL_BASE/dl/$BINARY" -o /usr/local/bin/agent
chmod +x /usr/local/bin/agent

# Download gost (latest release from GitHub)
echo "Downloading gost..."
GOST_ARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && GOST_ARCH="arm64"
GOST_URL="https://github.com/go-gost/gost/releases/latest/download/gost_linux_${GOST_ARCH}"
curl -fSL "$GOST_URL" -o /usr/local/bin/gost && chmod +x /usr/local/bin/gost || echo "Warning: gost download failed, install manually"

# Create config dir
mkdir -p "$CONFIG_DIR"

# Write systemd service
cat > /etc/systemd/system/multiproxy-agent.service <<EOF
[Unit]
Description=multiProxy Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agent --panel-url "$PANEL_URL" --node-id "$NODE_ID" --token "$TOKEN" --config-dir "$CONFIG_DIR"
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now multiproxy-agent

echo ""
echo "Agent installed and started!"
echo "  Binary:  /usr/local/bin/agent"
echo "  Gost:    /usr/local/bin/gost"
echo "  Config:  $CONFIG_DIR"
echo "  Service: multiproxy-agent.service"
echo "  Logs:    journalctl -u multiproxy-agent -f"
"##;

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        script,
    )
        .into_response()
}

/// Public route: serves agent binary files from the configured `agent_bin_dir`.
/// Only files matching `agent-linux-*` are served; directory traversal is rejected.
async fn dl_agent_binary(State(state): State<AppState>, Path(filename): Path<String>) -> Response {
    // Reject directory traversal and non-matching filenames.
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if !filename.starts_with("agent-linux-") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let path = std::path::Path::new(&state.agent_bin_dir).join(&filename);
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let disposition = format!("attachment; filename=\"{filename}\"");
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/octet-stream"),
                    ),
                    (
                        header::CONTENT_DISPOSITION,
                        header::HeaderValue::from_str(&disposition)
                            .unwrap_or_else(|_| header::HeaderValue::from_static("attachment")),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

// ---------- UI index ----------

async fn index() -> Html<&'static str> {
    Html(ui::INDEX_HTML)
}
