//! Shared rendering logic: `ForwardRule[]` → gost v3 JSON / realm TOML config strings.
//!
//! This crate is intentionally musl-thin: it depends only on `contract` + `serde`/`serde_json`.
//! Both `panel` and `agent` may depend on it without pulling in axum/hickory/sqlx.

use contract::model::{ForwardRule, Protocol, TlsMode};

/// Cert/key paths the agent writes the `ConfigPush` PEMs to, matching the agent's
/// default `--config-dir /etc/multiproxy` (`agent::config::ConfigPaths::under`). The
/// rendered gost/realm config MUST reference these exact paths so the relay process
/// finds the cert the agent just wrote to disk.
pub const PROD_TLS_CERT_PATH: &str = "/etc/multiproxy/tls.crt";
pub const PROD_TLS_KEY_PATH: &str = "/etc/multiproxy/tls.key";

/// Optional TLS config paths for injecting into rendered tool configs.
pub struct TlsPaths {
    pub cert: String,
    pub key: String,
}

impl TlsPaths {
    /// The standard prod paths (see [`PROD_TLS_CERT_PATH`]).
    #[must_use]
    pub fn prod() -> Self {
        Self {
            cert: PROD_TLS_CERT_PATH.to_string(),
            key: PROD_TLS_KEY_PATH.to_string(),
        }
    }
}

pub(crate) fn proto_token(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// Render gost v3 service config as pretty JSON.
pub fn render_gost(rules: &[&ForwardRule], tls: Option<&TlsPaths>) -> String {
    let services: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            let proto = proto_token(r.protocol);
            let mut listener = serde_json::json!({ "type": proto });
            if r.tls_mode == TlsMode::Terminate {
                if let Some(tls) = tls {
                    listener = serde_json::json!({
                        "type": "tls",
                        "tls": {
                            "certFile": tls.cert,
                            "keyFile": tls.key
                        }
                    });
                }
            }
            serde_json::json!({
                "name": format!("svc-{}-{}", proto, r.listen_port),
                "addr": format!(":{}", r.listen_port),
                "handler": { "type": proto },
                "listener": listener,
                "forwarder": {
                    "nodes": [
                        {
                            "name": "target",
                            "addr": format!("{}:{}", r.backend_host, r.backend_port)
                        }
                    ]
                }
            })
        })
        .collect();
    let doc = serde_json::json!({ "services": services });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Render realm endpoint config as TOML `[[endpoints]]` blocks.
pub fn render_realm(rules: &[&ForwardRule], tls: Option<&TlsPaths>) -> String {
    let mut out = String::new();
    out.push_str("[network]\nno_tcp = false\nuse_udp = true\n");
    for r in rules {
        out.push_str("\n[[endpoints]]\n");
        out.push_str(&format!("listen = \"0.0.0.0:{}\"\n", r.listen_port));
        out.push_str(&format!(
            "remote = \"{}:{}\"\n",
            r.backend_host, r.backend_port
        ));
        if r.protocol == Protocol::Udp {
            out.push_str("udp = true\n");
        }
        if r.tls_mode == TlsMode::Terminate {
            if let Some(tls) = tls {
                // realm terminates TLS via a Kaminari `listen_transport` string, NOT
                // standalone `tls_cert`/`tls_key` keys (which realm silently ignores,
                // leaving a plain-TCP listener → client HTTPS fails). Server-side TLS
                // is `tls;cert=<path>;key=<path>` (paths have no chars needing escape).
                out.push_str(&format!(
                    "listen_transport = \"tls;cert={};key={}\"\n",
                    tls.cert, tls.key
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::model::{TlsMode, Tool};

    fn rule(
        id: &str,
        port: u16,
        proto: Protocol,
        host: &str,
        bport: u16,
        tool: Tool,
    ) -> ForwardRule {
        ForwardRule {
            id: id.into(),
            node_id: "node-1".into(),
            listen_port: port,
            protocol: proto,
            backend_host: host.into(),
            backend_port: bport,
            tool,
            tls_mode: TlsMode::Passthrough,
            extra_backends: vec![],
        }
    }

    #[test]
    fn render_gost_single_rule_contains_expected_fragments() {
        let r = rule("r1", 8080, Protocol::Tcp, "10.0.0.5", 8096, Tool::Gost);
        let out = render_gost(&[&r], None);
        assert!(out.contains("svc-tcp-8080"), "service name missing");
        assert!(out.contains(":8080"), "listen addr missing");
        assert!(out.contains("10.0.0.5:8096"), "backend addr missing");
        assert!(out.contains("\"services\""), "top-level key missing");
    }

    #[test]
    fn render_realm_single_rule_contains_expected_fragments() {
        let r = rule("r1", 9000, Protocol::Tcp, "10.0.0.9", 8096, Tool::Realm);
        let out = render_realm(&[&r], None);
        assert!(out.contains("[[endpoints]]"), "endpoints block missing");
        assert!(out.contains("0.0.0.0:9000"), "listen addr missing");
        assert!(out.contains("10.0.0.9:8096"), "remote addr missing");
    }

    #[test]
    fn render_realm_udp_rule_includes_udp_flag() {
        let r = rule("r1", 5353, Protocol::Udp, "10.0.0.9", 53, Tool::Realm);
        let out = render_realm(&[&r], None);
        assert!(out.contains("udp = true"), "udp flag missing");
    }

    #[test]
    fn render_gost_tls_terminate_includes_cert_paths() {
        let r = ForwardRule {
            id: "r1".into(),
            node_id: "node-1".into(),
            listen_port: 443,
            protocol: Protocol::Tcp,
            backend_host: "10.0.0.5".into(),
            backend_port: 8096,
            tool: Tool::Gost,
            tls_mode: TlsMode::Terminate,
            extra_backends: vec![],
        };
        let tls = TlsPaths {
            cert: "/etc/multiproxy/tls.crt".into(),
            key: "/etc/multiproxy/tls.key".into(),
        };
        let out = render_gost(&[&r], Some(&tls));
        assert!(out.contains("/etc/multiproxy/tls.crt"), "cert path missing");
        assert!(out.contains("/etc/multiproxy/tls.key"), "key path missing");
        assert!(
            out.contains("\"type\": \"tls\""),
            "tls listener type missing"
        );
    }

    #[test]
    fn render_realm_tls_terminate_includes_listen_transport() {
        let r = ForwardRule {
            id: "r1".into(),
            node_id: "node-1".into(),
            listen_port: 443,
            protocol: Protocol::Tcp,
            backend_host: "10.0.0.5".into(),
            backend_port: 8096,
            tool: Tool::Realm,
            tls_mode: TlsMode::Terminate,
            extra_backends: vec![],
        };
        let tls = TlsPaths {
            cert: "/etc/multiproxy/tls.crt".into(),
            key: "/etc/multiproxy/tls.key".into(),
        };
        let out = render_realm(&[&r], Some(&tls));
        assert!(
            out.contains("listen_transport = \"tls;cert=/etc/multiproxy/tls.crt;key=/etc/multiproxy/tls.key\""),
            "listen_transport missing: {out}"
        );
    }

    #[test]
    fn prod_tls_paths_uses_correct_constants() {
        let p = TlsPaths::prod();
        assert_eq!(p.cert, PROD_TLS_CERT_PATH);
        assert_eq!(p.key, PROD_TLS_KEY_PATH);
    }
}
