//! Cloudflare DNS API v4 client for automated DNS record management.
//!
//! Wraps the CF REST API (`https://api.cloudflare.com/client/v4/`) to create,
//! update, and delete DNS records programmatically. Used by the panel to:
//! - Set up NS delegation for the resolution subdomain
//! - Manage `_acme-challenge` TXT records for DNS-01 certificate validation
//! - Point the panel control domain at the panel's public IP

use serde::{Deserialize, Serialize};

const CF_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A lightweight Cloudflare API v4 client.
#[derive(Clone)]
pub struct CfClient {
    token: String,
    zone_id: String,
    client: reqwest::Client,
}

/// A DNS record as returned by the CF API.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        Self {
            token: token.into(),
            zone_id: zone_id.into(),
            client: reqwest::Client::new(),
        }
    }


    /// List DNS records matching a type and name.
    pub async fn list_records(&self, record_type: &str, name: &str) -> CfResult<Vec<DnsRecord>> {
        let url = format!(
            "{CF_BASE}/zones/{}/dns_records?type={}&name={}",
            self.zone_id, record_type, name
        );
        let resp: CfResponse<Vec<DnsRecord>> = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .json()
            .await?;
        self.check_errors(&resp)?;
        Ok(resp.result.unwrap_or_default())
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
        let url = format!("{CF_BASE}/zones/{}/dns_records", self.zone_id);
        let body = serde_json::json!({
            "type": record_type,
            "name": name,
            "content": content,
            "proxied": proxied,
            "ttl": ttl,
        });
        let resp: CfResponse<DnsRecord> = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        self.check_errors(&resp)?;
        resp.result.ok_or(CfApiError::NoResult)
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
        let url = format!("{CF_BASE}/zones/{}/dns_records/{record_id}", self.zone_id);
        let body = serde_json::json!({
            "type": record_type,
            "name": name,
            "content": content,
            "proxied": proxied,
            "ttl": ttl,
        });
        let resp: CfResponse<DnsRecord> = self
            .client
            .put(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        self.check_errors(&resp)?;
        resp.result.ok_or(CfApiError::NoResult)
    }

    /// Delete a DNS record by ID.
    pub async fn delete_record(&self, record_id: &str) -> CfResult<()> {
        let url = format!("{CF_BASE}/zones/{}/dns_records/{record_id}", self.zone_id);
        let resp: CfResponse<serde_json::Value> = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .json()
            .await?;
        self.check_errors(&resp)?;
        Ok(())
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

    fn check_errors<T>(&self, resp: &CfResponse<T>) -> CfResult<()> {
        if !resp.success {
            let msgs: Vec<String> = resp.errors.iter().map(|e| e.to_string()).collect();
            return Err(CfApiError::Api(msgs.join("; ")));
        }
        Ok(())
    }
}

/// Auto-setup DNS records for the panel's resolution domain.
///
/// Creates/updates:
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

    let ns_fqdn = format!("{ns_name}.{domain}");
    let sub_fqdn = format!("{subdomain}.{domain}");
    let panel_fqdn = format!("panel.{domain}");

    // 1. NS hostname A record (grey-cloud).
    tracing::info!(name = %ns_fqdn, ip = %panel_ip, "upserting NS A record");
    let r = cf
        .upsert_record("A", &ns_fqdn, panel_ip, false, 300)
        .await?;
    records.push(r);

    // 2. NS delegation for the resolution subdomain.
    tracing::info!(name = %sub_fqdn, target = %ns_fqdn, "upserting NS record");
    let r = cf
        .upsert_record("NS", &sub_fqdn, &ns_fqdn, false, 300)
        .await?;
    records.push(r);

    // 3. Panel control-domain A record.
    tracing::info!(name = %panel_fqdn, ip = %panel_ip, "upserting panel A record");
    let r = cf
        .upsert_record("A", &panel_fqdn, panel_ip, false, 300)
        .await?;
    records.push(r);

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
