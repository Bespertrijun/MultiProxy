//! Config renderer (Line A task 4 / AC-2): `ForwardRule[]` → gost config and/or realm
//! config per node. Deterministic output (sorted by listen port) so the golden-file
//! tests are stable. The per-rule [`Tool`] selector decides which renderer a rule
//! feeds (AC-2 gap).
//!
//! Output formats are intentionally minimal, documented, and stable:
//! - gost (v3): a JSON `{ "services": [ { name, addr, handler, forwarder } ] }`.
//! - realm: a TOML `[[endpoints]]` table list (`listen` / `remote`).
//!
//! A node may have rules for both tools; [`render_node`] returns each side only when
//! that tool has at least one rule (so `ConfigPush` carries `gost_config`/`realm_config`
//! as `Some` only when relevant).

use contract::model::{ForwardRule, Protocol, TlsMode, Tool};

/// Rendered configs for one node. Either side is `None` when that tool has no rules.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RenderedConfig {
    pub gost_config: Option<String>,
    pub realm_config: Option<String>,
}

/// Optional TLS config paths for injecting into rendered tool configs.
pub struct TlsPaths {
    pub cert: String,
    pub key: String,
}

/// Render gost + realm configs for a node's rules. Rules are partitioned by `tool`
/// and sorted by `listen_port` for deterministic output.
#[must_use]
pub fn render_node(rules: &[ForwardRule]) -> RenderedConfig {
    render_node_with_tls(rules, None)
}

/// Render gost + realm configs, optionally including TLS termination references.
#[must_use]
pub fn render_node_with_tls(rules: &[ForwardRule], tls: Option<&TlsPaths>) -> RenderedConfig {
    let mut gost_rules: Vec<&ForwardRule> = rules.iter().filter(|r| r.tool == Tool::Gost).collect();
    let mut realm_rules: Vec<&ForwardRule> =
        rules.iter().filter(|r| r.tool == Tool::Realm).collect();
    gost_rules.sort_by_key(|r| r.listen_port);
    realm_rules.sort_by_key(|r| r.listen_port);

    RenderedConfig {
        gost_config: if gost_rules.is_empty() {
            None
        } else {
            Some(render_gost(&gost_rules, tls))
        },
        realm_config: if realm_rules.is_empty() {
            None
        } else {
            Some(render_realm(&realm_rules, tls))
        },
    }
}

fn proto_token(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// Render gost v3 service config as pretty JSON.
fn render_gost(rules: &[&ForwardRule], tls: Option<&TlsPaths>) -> String {
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
fn render_realm(rules: &[&ForwardRule], tls: Option<&TlsPaths>) -> String {
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
                out.push_str(&format!("tls_cert = \"{}\"\n", tls.cert));
                out.push_str(&format!("tls_key = \"{}\"\n", tls.key));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
    }

    fn rule_tls(
        id: &str,
        port: u16,
        proto: Protocol,
        host: &str,
        bport: u16,
        tool: Tool,
        tls_mode: TlsMode,
    ) -> ForwardRule {
        ForwardRule {
            id: id.into(),
            node_id: "node-1".into(),
            listen_port: port,
            protocol: proto,
            backend_host: host.into(),
            backend_port: bport,
            tool,
            tls_mode,
        }
    }

    #[test]
    fn gost_golden() {
        let rules = vec![
            rule("r2", 8443, Protocol::Tcp, "10.0.0.5", 8096, Tool::Gost),
            rule("r1", 8080, Protocol::Tcp, "10.0.0.5", 8096, Tool::Gost),
        ];
        let out = render_node(&rules);
        let gost = out.gost_config.expect("gost rendered");
        let golden = include_str!("../tests/golden/node-gost.json");
        assert_eq!(
            gost.trim(),
            golden.trim(),
            "gost golden mismatch\n--- got ---\n{gost}"
        );
        assert!(out.realm_config.is_none());
    }

    #[test]
    fn realm_golden() {
        let rules = vec![
            rule("r1", 5353, Protocol::Udp, "10.0.0.9", 53, Tool::Realm),
            rule("r2", 9000, Protocol::Tcp, "10.0.0.9", 8096, Tool::Realm),
        ];
        let out = render_node(&rules);
        let realm = out.realm_config.expect("realm rendered");
        let golden = include_str!("../tests/golden/node-realm.toml");
        assert_eq!(
            realm.trim(),
            golden.trim(),
            "realm golden mismatch\n--- got ---\n{realm}"
        );
        assert!(out.gost_config.is_none());
    }

    #[test]
    fn mixed_tools_render_both_sides() {
        let rules = vec![
            rule("g", 8080, Protocol::Tcp, "10.0.0.5", 8096, Tool::Gost),
            rule("r", 9000, Protocol::Tcp, "10.0.0.5", 8096, Tool::Realm),
        ];
        let out = render_node(&rules);
        assert!(out.gost_config.is_some());
        assert!(out.realm_config.is_some());
        // Per-rule tool selector honored: the gost side must NOT contain the realm port.
        assert!(out.gost_config.unwrap().contains("8080"));
    }

    #[test]
    fn empty_rules_render_nothing() {
        let out = render_node(&[]);
        assert_eq!(out, RenderedConfig::default());
    }

    #[test]
    fn gost_tls_terminate_golden() {
        let rules = vec![rule_tls(
            "r1",
            443,
            Protocol::Tcp,
            "10.0.0.5",
            8096,
            Tool::Gost,
            TlsMode::Terminate,
        )];
        let tls = TlsPaths {
            cert: "/etc/multiproxy/tls.crt".into(),
            key: "/etc/multiproxy/tls.key".into(),
        };
        let out = render_node_with_tls(&rules, Some(&tls));
        let gost = out.gost_config.expect("gost rendered");
        let golden = include_str!("../tests/golden/node-gost-tls.json");
        assert_eq!(
            gost.trim(),
            golden.trim(),
            "gost TLS golden mismatch\n--- got ---\n{gost}"
        );
    }

    #[test]
    fn realm_tls_terminate_golden() {
        let rules = vec![rule_tls(
            "r1",
            443,
            Protocol::Tcp,
            "10.0.0.5",
            8096,
            Tool::Realm,
            TlsMode::Terminate,
        )];
        let tls = TlsPaths {
            cert: "/etc/multiproxy/tls.crt".into(),
            key: "/etc/multiproxy/tls.key".into(),
        };
        let out = render_node_with_tls(&rules, Some(&tls));
        let realm = out.realm_config.expect("realm rendered");
        let golden = include_str!("../tests/golden/node-realm-tls.toml");
        assert_eq!(
            realm.trim(),
            golden.trim(),
            "realm TLS golden mismatch\n--- got ---\n{realm}"
        );
    }

    #[test]
    fn tls_mode_roundtrip() {
        // Passthrough default
        assert_eq!(TlsMode::default(), TlsMode::Passthrough);
        // Serde roundtrip
        let json = serde_json::to_string(&TlsMode::Terminate).unwrap();
        assert_eq!(json, "\"terminate\"");
        let back: TlsMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TlsMode::Terminate);
        let json2 = serde_json::to_string(&TlsMode::Passthrough).unwrap();
        assert_eq!(json2, "\"passthrough\"");
        let back2: TlsMode = serde_json::from_str(&json2).unwrap();
        assert_eq!(back2, TlsMode::Passthrough);
    }

    #[test]
    fn passthrough_rules_unchanged_with_tls_paths() {
        // Passthrough rules should not include TLS config even when TlsPaths is provided.
        let rules = vec![
            rule("r1", 8080, Protocol::Tcp, "10.0.0.5", 8096, Tool::Gost),
            rule("r2", 9000, Protocol::Tcp, "10.0.0.5", 8096, Tool::Realm),
        ];
        let tls = TlsPaths {
            cert: "/etc/multiproxy/tls.crt".into(),
            key: "/etc/multiproxy/tls.key".into(),
        };
        let with = render_node_with_tls(&rules, Some(&tls));
        let without = render_node(&rules);
        assert_eq!(with.gost_config, without.gost_config);
        assert_eq!(with.realm_config, without.realm_config);
    }
}
