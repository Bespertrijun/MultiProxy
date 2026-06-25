//! Config application (Line B task 2).
//!
//! On a [`contract::protocol::ConfigPush`] the agent writes the gost and/or
//! realm config file to disk and decides which tool to (re)start. The panel
//! renders the full config text (Line A); the agent treats it as opaque bytes
//! and just persists + supervises — it does not parse the tool config itself.
//!
//! Rule: a push carries `gost_config` and/or `realm_config`. Each present config
//! is written and its tool is (re)started; a node whose rules mix tools runs BOTH
//! gost and realm at once. The caller stops any tool whose config is absent from
//! the push (e.g. all of a node's realm rules were deleted).

use std::path::{Path, PathBuf};

use contract::protocol::ConfigPush;

use crate::supervisor::Tool;

/// Where the agent writes tool config files. Configurable so tests use a tmp dir.
#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub gost: PathBuf,
    pub realm: PathBuf,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
}

impl ConfigPaths {
    /// Default layout under a base directory (e.g. `/etc/multiproxy` in prod or
    /// a tmp dir in tests).
    #[must_use]
    pub fn under(base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        Self {
            gost: base.join("gost.json"),
            realm: base.join("realm.toml"),
            tls_cert: base.join("tls.crt"),
            tls_key: base.join("tls.key"),
        }
    }
}

/// One tool's config that was written and should be (re)started against its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedConfig {
    pub tool: Tool,
    pub config_path: String,
}

/// Outcome of applying a [`ConfigPush`]: the tools whose config the push carried
/// (each must be (re)started) and the generation to ack.
///
/// `starts` holds one entry per present config — gost and/or realm, so a
/// mixed-tool node yields two. It is empty when the push carried no tool config
/// at all (the gen is still acked so the panel's drift tracking advances, and the
/// caller stops any previously-running tool).
#[derive(Debug)]
pub struct ApplyResult {
    pub starts: Vec<AppliedConfig>,
    pub applied_gen: u64,
}

/// Write the config file(s) from a push and decide the tool to run.
///
/// Returns the outcome, or an IO error if a file write failed (the caller then
/// acks with `ok=false` and the error string).
pub fn apply(push: &ConfigPush, paths: &ConfigPaths) -> std::io::Result<ApplyResult> {
    // Ensure the parent dir exists for whichever file we write.
    if let Some(text) = &push.gost_config {
        if let Some(parent) = paths.gost.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&paths.gost, text)?;
    }
    if let Some(text) = &push.realm_config {
        if let Some(parent) = paths.realm.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&paths.realm, text)?;
    }

    // Write TLS cert/key if provided (for gost/realm TLS termination).
    if let Some(cert) = &push.tls_cert_pem {
        if let Some(parent) = paths.tls_cert.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&paths.tls_cert, cert)?;
    }
    if let Some(key) = &push.tls_key_pem {
        if let Some(parent) = paths.tls_key.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&paths.tls_key, key)?;
    }

    // Start every tool the push carried — gost AND realm when a node mixes tools.
    let mut starts = Vec::new();
    if push.gost_config.is_some() {
        starts.push(AppliedConfig {
            tool: Tool::Gost,
            config_path: paths.gost.to_string_lossy().into_owned(),
        });
    }
    if push.realm_config.is_some() {
        starts.push(AppliedConfig {
            tool: Tool::Realm,
            config_path: paths.realm.to_string_lossy().into_owned(),
        });
    }
    Ok(ApplyResult {
        starts,
        applied_gen: push.desired_gen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "agent-cfg-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn writes_gost_config_and_selects_gost() {
        let dir = tmpdir();
        let paths = ConfigPaths::under(&dir);
        let push = ConfigPush {
            desired_gen: 7,
            gost_config: Some("{\"services\":[]}".into()),
            realm_config: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            backends: vec![],
            rules: vec![],
        };
        let r = apply(&push, &paths).unwrap();
        assert_eq!(r.applied_gen, 7);
        assert_eq!(r.starts.len(), 1);
        assert_eq!(r.starts[0].tool, Tool::Gost);
        let written = std::fs::read_to_string(&paths.gost).unwrap();
        assert_eq!(written, "{\"services\":[]}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writes_realm_config_and_selects_realm() {
        let dir = tmpdir();
        let paths = ConfigPaths::under(&dir);
        let push = ConfigPush {
            desired_gen: 3,
            gost_config: None,
            realm_config: Some("[network]\nno_tcp = false".into()),
            tls_cert_pem: None,
            tls_key_pem: None,
            backends: vec![],
            rules: vec![],
        };
        let r = apply(&push, &paths).unwrap();
        assert_eq!(r.applied_gen, 3);
        assert_eq!(r.starts.len(), 1);
        assert_eq!(r.starts[0].tool, Tool::Realm);
        assert!(std::fs::read_to_string(&paths.realm)
            .unwrap()
            .contains("network"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_push_acks_without_a_tool() {
        let dir = tmpdir();
        let paths = ConfigPaths::under(&dir);
        let push = ConfigPush {
            desired_gen: 9,
            gost_config: None,
            realm_config: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            backends: vec![],
            rules: vec![],
        };
        let r = apply(&push, &paths).unwrap();
        assert_eq!(r.applied_gen, 9);
        assert!(r.starts.is_empty(), "no config → no tool to start");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writes_tls_cert_and_key_when_present() {
        let dir = tmpdir();
        let paths = ConfigPaths::under(&dir);
        let push = ConfigPush {
            desired_gen: 10,
            gost_config: Some("{\"services\":[]}".into()),
            realm_config: None,
            tls_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".into(),
            ),
            tls_key_pem: Some(
                "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n".into(),
            ),
            backends: vec![],
            rules: vec![],
        };
        let r = apply(&push, &paths).unwrap();
        assert_eq!(r.applied_gen, 10);
        assert_eq!(r.starts.len(), 1);
        assert_eq!(r.starts[0].tool, Tool::Gost);
        let cert = std::fs::read_to_string(&paths.tls_cert).unwrap();
        assert!(cert.contains("CERTIFICATE"));
        let key = std::fs::read_to_string(&paths.tls_key).unwrap();
        assert!(key.contains("PRIVATE KEY"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn both_tools_start_when_both_present() {
        let dir = tmpdir();
        let paths = ConfigPaths::under(&dir);
        let push = ConfigPush {
            desired_gen: 1,
            gost_config: Some("g".into()),
            realm_config: Some("r".into()),
            tls_cert_pem: None,
            tls_key_pem: None,
            backends: vec![],
            rules: vec![],
        };
        // A mixed-tool node must (re)start BOTH gost and realm — not just one.
        let r = apply(&push, &paths).unwrap();
        let tools: Vec<Tool> = r.starts.iter().map(|s| s.tool).collect();
        assert!(tools.contains(&Tool::Gost), "gost started");
        assert!(tools.contains(&Tool::Realm), "realm started");
        assert_eq!(r.starts.len(), 2, "exactly the two present tools");
        // Both files written.
        assert_eq!(std::fs::read_to_string(&paths.gost).unwrap(), "g");
        assert_eq!(std::fs::read_to_string(&paths.realm).unwrap(), "r");
        std::fs::remove_dir_all(&dir).ok();
    }
}
