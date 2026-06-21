//! Integration: auth (AC-8) + CRUD persistence (AC-1/2/3). Boots the panel against an
//! in-memory SQLite DB, serves the axum router on an ephemeral HTTP port, and drives
//! it with a cookie-aware reqwest client.

use panel::dns::DnsConfig;
use panel::{build, PanelConfig};
use reqwest::StatusCode;

/// Boot a panel on ephemeral HTTP + DNS ports; return the base URL.
async fn boot() -> (String, reqwest::Client) {
    let cfg = PanelConfig {
        database_url: "sqlite::memory:".into(),
        http_bind: "127.0.0.1:0".into(),
        dns: DnsConfig {
            bind_addr: "127.0.0.1".into(),
            port: 0,
            ..Default::default()
        },
        geocn_path: None,
        ttl_secs: 60,
        ..Default::default()
    };
    let panel = build(cfg).await.expect("build panel");
    // Seed admin directly via the DB layer (no more seed_admin config).
    let hash = panel::auth::hash_password("secret").unwrap();
    panel::db::upsert_user(
        &panel.state.db,
        &contract::model::PanelUser {
            username: "admin".into(),
            password_hash: hash,
            totp_secret: None,
            totp_enabled: false,
        },
    )
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = panel.router.clone();
    tokio::spawn(async move {
        // Keep the panel (and its DNS runtime) alive for the server's lifetime.
        let _keep = panel;
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    (format!("http://{addr}"), client)
}

#[tokio::test]
async fn unauthenticated_is_rejected_then_login_grants_access() {
    let (base, client) = boot().await;

    // AC-8: management route without a session → 401.
    let r = client
        .get(format!("{base}/api/nodes"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // Bad password → 401.
    let r = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username":"admin","password":"wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // Correct login → 200 + cookie; subsequent management call succeeds.
    let r = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username":"admin","password":"secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let r = client
        .get(format!("{base}/api/nodes"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

async fn login(base: &str, client: &reqwest::Client) {
    client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username":"admin","password":"secret"}))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn node_crud_persists_and_token_shown_once() {
    let (base, client) = boot().await;
    login(&base, &client).await;

    // AC-1: create a node → token returned once, node persisted.
    let r = client
        .post(format!("{base}/api/nodes"))
        .json(&serde_json::json!({
            "name":"hk-1","public_ip":"1.2.3.4","division_code":440100,"isp":"telecom",
            "traffic_quota_bytes": 1000000000u64
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: serde_json::Value = r.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    assert!(!token.is_empty(), "agent token must be returned once");
    let node_id = body["node"]["id"].as_str().unwrap().to_string();
    // Province decoded from division_code 440100 → 44 (广东).
    assert_eq!(body["node"]["region"]["province_code"], 44);

    // Persisted: list shows it.
    let nodes: serde_json::Value = client
        .get(format!("{base}/api/nodes"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(nodes.as_array().unwrap().len(), 1);

    // Token is NOT re-fetchable (no endpoint returns it; only a rotate that mints a new one).
    let r = client
        .post(format!("{base}/api/nodes/{node_id}/token"))
        .send()
        .await
        .unwrap();
    let rot: serde_json::Value = r.json().await.unwrap();
    let new_token = rot["token"].as_str().unwrap();
    assert_ne!(new_token, token, "rotation mints a fresh token");
}

#[tokio::test]
async fn rule_and_group_and_zone_crud() {
    let (base, client) = boot().await;
    login(&base, &client).await;

    // Node first (rule FK).
    let node: serde_json::Value = client
        .post(format!("{base}/api/nodes"))
        .json(&serde_json::json!({"name":"n","public_ip":"9.9.9.9"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let node_id = node["node"]["id"].as_str().unwrap().to_string();

    // AC-2 input: forward rule with explicit tool selector.
    let rule: serde_json::Value = client
        .post(format!("{base}/api/rules"))
        .json(&serde_json::json!({
            "node_id": node_id, "listen_port": 8443, "protocol":"tcp",
            "backend_host":"10.0.0.5","backend_port":8096,"tool":"gost"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rule["tool"], "gost");

    // AC-3: line group with priority + region/isp match.
    let group: serde_json::Value = client
        .post(format!("{base}/api/line-groups"))
        .json(&serde_json::json!({
            "name":"gd-telecom","match_region":44,"match_isp":"telecom",
            "priority":1,"member_node_ids":[node_id]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(group["priority"], 1);

    // DnsZone.
    let zone: serde_json::Value = client
        .post(format!("{base}/api/zones"))
        .json(&serde_json::json!({"apex_domain":"emby.example.com","default_ttl":60,"ns":[]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(zone["apex_domain"], "emby.example.com");

    // All persisted.
    let rules: serde_json::Value = client
        .get(format!("{base}/api/rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rules.as_array().unwrap().len(), 1);
    let groups: serde_json::Value = client
        .get(format!("{base}/api/line-groups"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(groups.as_array().unwrap().len(), 1);
    let zones: serde_json::Value = client
        .get(format!("{base}/api/zones"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(zones.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn logout_invalidates_session() {
    // security MEDIUM #2: logout must actually invalidate the server-side session,
    // not be a no-op. After logout, the previously-valid token is rejected.
    let (base, _client) = boot().await;
    // Use a NON-cookie-store client so we control the exact cookie sent and can prove
    // the *specific* logged-out token is rejected server-side.
    let client = reqwest::Client::new();

    // Login and capture the issued session cookie.
    let login_resp = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username":"admin","password":"secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status(), StatusCode::OK);
    let set_cookie = login_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    // Max-Age binds the cookie lifetime to the session TTL (security MEDIUM #2).
    assert!(
        set_cookie.contains("Max-Age=604800"),
        "session cookie must carry Max-Age: {set_cookie}"
    );
    let cookie = set_cookie.split(';').next().unwrap().to_string(); // "panel_session=<tok>"

    // Authorized with this token before logout.
    let r = client
        .get(format!("{base}/api/nodes"))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Logout with the same token deletes the session row server-side.
    let r = client
        .post(format!("{base}/api/logout"))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // The SAME token is now rejected (the server-side session was invalidated).
    let r = client
        .get(format!("{base}/api/nodes"))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rule_rejects_unsafe_backend_host() {
    // security LOW #9: a backend_host with a quote/newline could break the hand-built
    // realm TOML in configgen.rs. The API must reject it with a 400.
    let (base, client) = boot().await;
    login(&base, &client).await;

    let node: serde_json::Value = client
        .post(format!("{base}/api/nodes"))
        .json(&serde_json::json!({"name":"n","public_ip":"9.9.9.9"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let node_id = node["node"]["id"].as_str().unwrap().to_string();

    // A quote + newline injection attempt → 400.
    let r = client
        .post(format!("{base}/api/rules"))
        .json(&serde_json::json!({
            "node_id": node_id, "listen_port": 8443, "protocol":"tcp",
            "backend_host":"evil\"\nremote = \"attacker:1","backend_port":8096,"tool":"realm"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // A normal host:port style value is still accepted.
    let r = client
        .post(format!("{base}/api/rules"))
        .json(&serde_json::json!({
            "node_id": node_id, "listen_port": 8444, "protocol":"tcp",
            "backend_host":"emby.internal.lan","backend_port":8096,"tool":"realm"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn change_password_works() {
    let (base, client) = boot().await;
    login(&base, &client).await;

    // Wrong current password → 403.
    let r = client
        .post(format!("{base}/api/change-password"))
        .json(&serde_json::json!({"current_password":"wrong","new_password":"newsecret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Too-short new password → 400.
    let r = client
        .post(format!("{base}/api/change-password"))
        .json(&serde_json::json!({"current_password":"secret","new_password":"short"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Valid change → 200 and all sessions invalidated.
    let r = client
        .post(format!("{base}/api/change-password"))
        .json(&serde_json::json!({"current_password":"secret","new_password":"newsecret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Old session is now invalid (all sessions deleted).
    let r = client
        .get(format!("{base}/api/nodes"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // Can login with the new password.
    let r = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username":"admin","password":"newsecret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Old password no longer works.
    let r = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username":"admin","password":"secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}
