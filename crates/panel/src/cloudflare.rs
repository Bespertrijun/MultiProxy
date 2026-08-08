//! Cloudflare DNS API v4 client for automated DNS record management.
//!
//! Wraps the CF REST API (`https://api.cloudflare.com/client/v4/`) to create,
//! update, and delete DNS records programmatically. Used by the panel to:
//! - Set up NS delegation for the resolution subdomain
//! - Manage `_acme-challenge` TXT records for DNS-01 certificate validation
//! - Point the panel control domain at the panel's public IP

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;

const CF_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A lightweight Cloudflare API v4 client.
#[derive(Clone)]
pub struct CfClient {
    token: String,
    zone_id: String,
    client: reqwest::Client,
    base_url: String,
}

/// A DNS record as returned by the CF API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub ttl: u32,
}

/// CF API envelope — the outer wrapper around every response.
#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    #[serde(default)]
    code: u64,
    #[serde(default)]
    message: String,
}

/// A desired record's conservative inspection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    Missing,
    Ok,
    Conflict,
}

/// The result of an inspect/create/re-read operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureRecord {
    AlreadyOk(DnsRecord),
    Created(DnsRecord),
}

impl std::fmt::Display for CfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CF error {}: {}", self.code, self.message)
    }
}

/// Result type for CF operations.
pub type CfResult<T> = Result<T, CfApiError>;

/// Error type for CF API calls.
#[derive(Debug)]
pub enum CfApiError {
    Http(reqwest::Error),
    Api(String),
    NoResult,
}

impl std::fmt::Display for CfApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CfApiError::Http(e) => write!(f, "CF HTTP error: {e}"),
            CfApiError::Api(m) => write!(f, "CF API error: {m}"),
            CfApiError::NoResult => write!(f, "CF API returned no result"),
        }
    }
}

impl std::error::Error for CfApiError {}

impl From<reqwest::Error> for CfApiError {
    fn from(e: reqwest::Error) -> Self {
        CfApiError::Http(e)
    }
}

impl CfClient {
    /// Create a new CF API client.
    pub fn new(token: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self::with_base_url(token, zone_id, CF_BASE)
    }

    /// Create a client against an injectable API base URL.
    ///
    /// The production constructor points at Cloudflare. Tests can pass a local
    /// fixture URL (normally ending in `/client/v4`) without changing provider logic.
    pub fn with_base_url(
        token: impl Into<String>,
        zone_id: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            token: token.into(),
            zone_id: zone_id.into(),
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// Alias kept explicit for callers that prefer constructor-style naming.
    pub fn new_with_base_url(
        token: impl Into<String>,
        zone_id: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self::with_base_url(token, zone_id, base_url)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn json<T: DeserializeOwned>(&self, request: reqwest::RequestBuilder) -> CfResult<T> {
        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        let parsed = serde_json::from_str::<CfResponse<T>>(&body).map_err(|e| {
            CfApiError::Api(format!(
                "CF HTTP {} returned malformed JSON: {} (body: {})",
                status,
                e,
                truncate_body(&body)
            ))
        })?;
        if !status.is_success() {
            let detail = parsed
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CfApiError::Api(format!(
                "CF HTTP {}{}",
                status,
                if detail.is_empty() {
                    format!(": {}", truncate_body(&body))
                } else {
                    format!(": {detail}")
                }
            )));
        }
        self.check_errors(&parsed)?;
        parsed.result.ok_or(CfApiError::NoResult)
    }

    /// List DNS records matching a type and name.
    pub async fn list_records(&self, record_type: &str, name: &str) -> CfResult<Vec<DnsRecord>> {
        let url = self.url(&format!("/zones/{}/dns_records", self.zone_id));
        self.json(
            self.client
                .get(&url)
                .bearer_auth(&self.token)
                .query(&[("type", record_type), ("name", name)]),
        )
        .await
    }

    /// List every record at one exact normalized name.
    pub async fn list_records_exact(&self, name: &str) -> CfResult<Vec<DnsRecord>> {
        let url = self.url(&format!("/zones/{}/dns_records", self.zone_id));
        self.json(
            self.client
                .get(&url)
                .bearer_auth(&self.token)
                .query(&[("name", name)]),
        )
        .await
    }

    /// Return the provider's canonical name for the configured zone ID.
    pub async fn zone_name(&self) -> CfResult<String> {
        let url = self.url(&format!("/zones/{}", self.zone_id));
        let zone: CfZone = self
            .json(self.client.get(&url).bearer_auth(&self.token))
            .await?;
        Ok(zone.name)
    }

    /// Validate that the configured zone ID resolves to the expected domain.
    pub async fn validate_zone_name(&self, expected_domain: &str) -> CfResult<String> {
        let actual = normalize_dns_name(&self.zone_name().await?);
        let expected = normalize_dns_name(expected_domain);
        if actual != expected {
            return Err(CfApiError::Api(format!(
                "Cloudflare Zone ID resolves to `{}`, expected `{}`",
                actual, expected
            )));
        }
        Ok(actual)
    }

    /// Create a DNS record.
    pub async fn create_record(
        &self,
        record_type: &str,
        name: &str,
        content: &str,
        proxied: bool,
        ttl: u32,
    ) -> CfResult<DnsRecord> {
        let url = self.url(&format!("/zones/{}/dns_records", self.zone_id));
        let body = serde_json::json!({
            "type": record_type,
            "name": name,
            "content": content,
            "proxied": proxied,
            "ttl": ttl,
        });
        self.json(self.client.post(&url).bearer_auth(&self.token).json(&body))
            .await
    }

    /// Update an existing DNS record by ID.
    pub async fn update_record(
        &self,
        record_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
        proxied: bool,
        ttl: u32,
    ) -> CfResult<DnsRecord> {
        let url = self.url(&format!("/zones/{}/dns_records/{record_id}", self.zone_id));
        let body = serde_json::json!({
            "type": record_type,
            "name": name,
            "content": content,
            "proxied": proxied,
            "ttl": ttl,
        });
        self.json(self.client.put(&url).bearer_auth(&self.token).json(&body))
            .await
    }

    /// Delete a DNS record by ID.
    pub async fn delete_record(&self, record_id: &str) -> CfResult<()> {
        let url = self.url(&format!("/zones/{}/dns_records/{record_id}", self.zone_id));
        self.json::<serde_json::Value>(self.client.delete(&url).bearer_auth(&self.token))
            .await
            .map(|_| ())
    }

    /// Upsert a DNS record: update if one with the same type+name exists, create otherwise.
    pub async fn upsert_record(
        &self,
        record_type: &str,
        name: &str,
        content: &str,
        proxied: bool,
        ttl: u32,
    ) -> CfResult<DnsRecord> {
        let existing = self.list_records(record_type, name).await?;
        if let Some(rec) = existing.into_iter().next() {
            self.update_record(&rec.id, record_type, name, content, proxied, ttl)
                .await
        } else {
            self.create_record(record_type, name, content, proxied, ttl)
                .await
        }
    }

    /// Inspect an exact name and classify it without changing the provider.
    pub async fn classify_record(
        &self,
        record_type: &str,
        name: &str,
        content: &str,
        proxied: bool,
    ) -> CfResult<RecordState> {
        let records = self.list_records_exact(name).await?;
        Ok(classify_records(
            &records,
            record_type,
            name,
            content,
            proxied,
        ))
    }

    /// Create only an unambiguously missing record and re-read it to verify.
    ///
    /// Existing records are never updated or deleted. A conflict, duplicate, or
    /// unverifiable create is returned as an error so callers can report attention.
    pub async fn ensure_missing_record(
        &self,
        record_type: &str,
        name: &str,
        content: &str,
        proxied: bool,
        ttl: u32,
    ) -> CfResult<EnsureRecord> {
        let before = self.list_records_exact(name).await?;
        match classify_records(&before, record_type, name, content, proxied) {
            RecordState::Ok => {
                let record = before
                    .iter()
                    .find(|r| same_record(r, record_type, name, content, proxied))
                    .cloned()
                    .ok_or(CfApiError::NoResult)?;
                Ok(EnsureRecord::AlreadyOk(record))
            }
            RecordState::Conflict => Err(CfApiError::Api(format!(
                "conflict at {} {} record; no mutation performed",
                normalize_dns_name(name),
                record_type
            ))),
            RecordState::Missing => {
                self.create_record(record_type, name, content, proxied, ttl)
                    .await?;
                let after = self.list_records_exact(name).await?;
                if classify_records(&after, record_type, name, content, proxied) != RecordState::Ok
                {
                    return Err(CfApiError::Api(format!(
                        "created {} {} but verification found a conflict or missing record",
                        record_type,
                        normalize_dns_name(name)
                    )));
                }
                let record = after
                    .iter()
                    .find(|r| same_record(r, record_type, name, content, proxied))
                    .cloned()
                    .ok_or(CfApiError::NoResult)?;
                Ok(EnsureRecord::Created(record))
            }
        }
    }

    fn check_errors<T>(&self, resp: &CfResponse<T>) -> CfResult<()> {
        if !resp.success {
            let msgs: Vec<String> = resp.errors.iter().map(|e| e.to_string()).collect();
            return Err(CfApiError::Api(msgs.join("; ")));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct CfZone {
    name: String,
}

fn truncate_body(body: &str) -> String {
    const LIMIT: usize = 300;
    let mut out = body.chars().take(LIMIT).collect::<String>();
    if body.chars().count() > LIMIT {
        out.push_str("...");
    }
    out
}

/// Normalize DNS names for comparison and API payloads.
pub fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn same_record(
    record: &DnsRecord,
    record_type: &str,
    name: &str,
    content: &str,
    proxied: bool,
) -> bool {
    record.record_type.eq_ignore_ascii_case(record_type)
        && normalize_dns_name(&record.name) == normalize_dns_name(name)
        && normalize_content(record_type, &record.content)
            == normalize_content(record_type, content)
        && record.proxied == proxied
}

fn normalize_content(record_type: &str, content: &str) -> String {
    if record_type.eq_ignore_ascii_case("A") {
        content.trim().to_string()
    } else {
        normalize_dns_name(content)
    }
}

/// Classify a complete exact-name record set using the safe mutation rules.
pub fn classify_records(
    records: &[DnsRecord],
    record_type: &str,
    name: &str,
    content: &str,
    proxied: bool,
) -> RecordState {
    if records.is_empty() {
        return RecordState::Missing;
    }

    let same_type: Vec<&DnsRecord> = records
        .iter()
        .filter(|r| r.record_type.eq_ignore_ascii_case(record_type))
        .collect();
    let has_forbidden_name_conflict = records.iter().any(|r| {
        let ty = r.record_type.to_ascii_uppercase();
        if record_type.eq_ignore_ascii_case("NS") {
            matches!(ty.as_str(), "A" | "AAAA" | "CNAME")
        } else if record_type.eq_ignore_ascii_case("A") {
            matches!(ty.as_str(), "AAAA" | "CNAME")
        } else {
            false
        }
    });
    if has_forbidden_name_conflict {
        return RecordState::Conflict;
    }
    // Other harmless record types (for example TXT) do not make the desired A/NS
    // record ambiguous. Only duplicate or mismatched records of the desired type do.
    if same_type.is_empty() {
        return RecordState::Missing;
    }
    if same_type.len() != 1 {
        return RecordState::Conflict;
    }
    if same_record(same_type[0], record_type, name, content, proxied) {
        RecordState::Ok
    } else {
        RecordState::Conflict
    }
}

/// Parse and validate an IPv4 panel target before any provider write.
pub fn parse_panel_ipv4(panel_ip: &str) -> Result<Ipv4Addr, String> {
    panel_ip
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("panel IP must be a non-empty IPv4 address: `{panel_ip}`"))
}

/// Auto-setup DNS records for the panel's resolution domain.
///
/// NS-host A and child NS records are created only when unambiguously missing; their
/// conflicts are reported and never overwritten or deleted. The `panel.{domain}` A
/// record is intentionally outside authoritative-zone integrity and keeps the legacy
/// upsert behavior so a changed public IP updates the control endpoint.
///
/// Ensures:
/// 1. A record: `{ns_name}.{domain}` -> `panel_ip` (unproxied, TTL 300)
/// 2. NS record: `{subdomain}.{domain}` -> `{ns_name}.{domain}`
/// 3. A record: `panel.{domain}` -> `panel_ip` (unproxied, TTL 300)
pub async fn auto_setup_dns(
    cf: &CfClient,
    domain: &str,
    subdomain: &str,
    panel_ip: &str,
    ns_name: &str,
) -> CfResult<Vec<DnsRecord>> {
    let mut records = Vec::new();

    cf.validate_zone_name(domain).await?;
    let panel_ip = parse_panel_ipv4(panel_ip)
        .map_err(CfApiError::Api)?
        .to_string();

    let domain = normalize_dns_name(domain);
    let ns_fqdn = format!("{}.{}", normalize_dns_name(ns_name), domain);
    let sub_fqdn = format!("{}.{}", normalize_dns_name(subdomain), domain);
    let panel_fqdn = format!("panel.{domain}");

    // 1. NS hostname A record (grey-cloud).
    tracing::info!(name = %ns_fqdn, ip = %panel_ip, "ensuring NS A record");
    let r = cf
        .ensure_missing_record("A", &ns_fqdn, &panel_ip, false, 300)
        .await?;
    records.push(match r {
        EnsureRecord::AlreadyOk(record) | EnsureRecord::Created(record) => record,
    });

    // 2. NS delegation for the resolution subdomain.
    tracing::info!(name = %sub_fqdn, target = %ns_fqdn, "ensuring NS record");
    let r = cf
        .ensure_missing_record("NS", &sub_fqdn, &ns_fqdn, false, 300)
        .await?;
    records.push(match r {
        EnsureRecord::AlreadyOk(record) | EnsureRecord::Created(record) => record,
    });

    // 3. Panel control-domain A record. This is intentionally the one legacy
    // upsert: the control endpoint must follow an operator/public-IP change, while
    // authoritative NS records above remain conservative and never overwrite.
    tracing::info!(name = %panel_fqdn, ip = %panel_ip, "upserting panel A record");
    let r = cf
        .upsert_record("A", &panel_fqdn, &panel_ip, false, 300)
        .await?;
    records.push(r);

    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::extract::{Path, Query, State};
    use axum::routing::{get, put};
    use axum::{Json, Router};
    use tokio::sync::Mutex;

    use super::*;

    #[test]
    fn constructors_keep_production_and_fixture_base_urls_explicit() {
        let production = CfClient::new("token", "zone");
        assert_eq!(production.base_url, CF_BASE);

        let fixture = CfClient::with_base_url("token", "zone", "http://fixture.test/");
        assert_eq!(fixture.base_url, "http://fixture.test");
    }

    /// Verify CF API response parsing for a successful records list.
    #[test]
    fn parse_list_response() {
        let json = r#"{
            "success": true,
            "errors": [],
            "messages": [],
            "result": [
                {
                    "id": "rec-1",
                    "type": "A",
                    "name": "ns1.example.com",
                    "content": "1.2.3.4",
                    "proxied": false,
                    "ttl": 300
                }
            ]
        }"#;
        let resp: CfResponse<Vec<DnsRecord>> = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        let records = resp.result.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "rec-1");
        assert_eq!(records[0].record_type, "A");
        assert_eq!(records[0].content, "1.2.3.4");
    }

    /// Verify CF API error response parsing.
    #[test]
    fn parse_error_response() {
        let json = r#"{
            "success": false,
            "errors": [{"code": 1003, "message": "Invalid or missing zone id."}],
            "messages": [],
            "result": null
        }"#;
        let resp: CfResponse<Vec<DnsRecord>> = serde_json::from_str(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].code, 1003);
    }

    /// Verify CF API create record response parsing.
    #[test]
    fn parse_create_response() {
        let json = r#"{
            "success": true,
            "errors": [],
            "messages": [],
            "result": {
                "id": "new-rec",
                "type": "TXT",
                "name": "_acme-challenge.panel.example.com",
                "content": "dGVzdC10b2tlbi12YWx1ZQ",
                "proxied": false,
                "ttl": 120
            }
        }"#;
        let resp: CfResponse<DnsRecord> = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        let rec = resp.result.unwrap();
        assert_eq!(rec.id, "new-rec");
        assert_eq!(rec.record_type, "TXT");
        assert!(rec.content.contains("dGVzdC10b2tlbi12YWx1ZQ"));
    }

    fn record(record_type: &str, name: &str, content: &str, proxied: bool) -> DnsRecord {
        DnsRecord {
            id: format!("{record_type}-{name}"),
            record_type: record_type.into(),
            name: name.into(),
            content: content.into(),
            proxied,
            ttl: 300,
        }
    }

    #[test]
    fn conservative_classification_rejects_conflicts_and_proxied_a() {
        assert_eq!(
            classify_records(&[], "NS", "child.example.com", "ns1.example.com", false),
            RecordState::Missing
        );
        let expected = record("NS", "child.example.com.", "ns1.example.com.", false);
        assert_eq!(
            classify_records(
                std::slice::from_ref(&expected),
                "NS",
                "CHILD.EXAMPLE.COM",
                "NS1.EXAMPLE.COM",
                false
            ),
            RecordState::Ok
        );
        assert_eq!(
            classify_records(
                &[expected.clone(), expected.clone()],
                "NS",
                "child.example.com",
                "ns1.example.com",
                false
            ),
            RecordState::Conflict
        );
        assert_eq!(
            classify_records(
                &[record("A", "ns1.example.com", "1.2.3.4", true)],
                "A",
                "ns1.example.com",
                "1.2.3.4",
                false
            ),
            RecordState::Conflict
        );
        assert_eq!(
            classify_records(
                &[record(
                    "CNAME",
                    "ns1.example.com",
                    "other.example.com",
                    false
                )],
                "A",
                "ns1.example.com",
                "1.2.3.4",
                false
            ),
            RecordState::Conflict
        );
    }

    #[derive(Clone, Default)]
    struct AutoSetupFixture {
        records: Arc<Mutex<Vec<DnsRecord>>>,
        writes: Arc<Mutex<Vec<&'static str>>>,
    }

    async fn fixture_zone(Path(_zone_id): Path<String>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": { "name": "example.com" }
        }))
    }

    async fn fixture_list(
        State(state): State<AutoSetupFixture>,
        Path(_zone_id): Path<String>,
        Query(query): Query<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let name = query.get("name").map(|value| normalize_dns_name(value));
        let records = state.records.lock().await;
        let result: Vec<DnsRecord> = records
            .iter()
            .filter(|record| {
                name.as_ref()
                    .is_none_or(|expected| normalize_dns_name(&record.name) == *expected)
            })
            .cloned()
            .collect();
        Json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": result
        }))
    }

    async fn fixture_create(
        State(state): State<AutoSetupFixture>,
        Path(_zone_id): Path<String>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let record = DnsRecord {
            id: format!("rec-{}", state.records.lock().await.len() + 1),
            record_type: body["type"].as_str().unwrap_or_default().to_string(),
            name: body["name"].as_str().unwrap_or_default().to_string(),
            content: body["content"].as_str().unwrap_or_default().to_string(),
            proxied: body["proxied"].as_bool().unwrap_or(false),
            ttl: body["ttl"].as_u64().unwrap_or_default() as u32,
        };
        state.records.lock().await.push(record.clone());
        state.writes.lock().await.push("POST");
        Json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": record
        }))
    }

    async fn fixture_update(
        State(state): State<AutoSetupFixture>,
        Path((_zone_id, id)): Path<(String, String)>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let mut records = state.records.lock().await;
        let record = records.iter_mut().find(|record| record.id == id).unwrap();
        record.content = body["content"].as_str().unwrap_or_default().to_string();
        record.proxied = body["proxied"].as_bool().unwrap_or(false);
        record.ttl = body["ttl"].as_u64().unwrap_or_default() as u32;
        let response = record.clone();
        drop(records);
        state.writes.lock().await.push("PUT");
        Json(serde_json::json!({
            "success": true,
            "errors": [],
            "result": response
        }))
    }

    #[tokio::test]
    async fn auto_setup_only_upserts_panel_a() {
        let fixture = AutoSetupFixture {
            records: Arc::new(Mutex::new(vec![record(
                "A",
                "panel.example.com",
                "1.1.1.1",
                false,
            )])),
            writes: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/zones/{zone_id}", get(fixture_zone))
            .route(
                "/zones/{zone_id}/dns_records",
                get(fixture_list).post(fixture_create),
            )
            .route("/zones/{zone_id}/dns_records/{id}", put(fixture_update))
            .with_state(fixture.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = CfClient::with_base_url("token", "zone", format!("http://{address}"));
        let records = auto_setup_dns(&client, "example.com", "child", "2.2.2.2", "ns1")
            .await
            .unwrap();
        server.abort();

        assert_eq!(records.len(), 3);
        assert_eq!(&*fixture.writes.lock().await, &["POST", "POST", "PUT"]);
        let stored = fixture.records.lock().await;
        assert_eq!(
            stored
                .iter()
                .find(|record| record.name == "panel.example.com")
                .unwrap()
                .content,
            "2.2.2.2"
        );
        assert!(stored
            .iter()
            .any(|record| record.record_type == "A" && record.name == "ns1.example.com"));
        assert!(stored
            .iter()
            .any(|record| record.record_type == "NS" && record.name == "child.example.com"));
    }
}
