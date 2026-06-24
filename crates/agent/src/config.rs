//! Config application (Line B task 2).
//!
//! On a [`contract::protocol::ConfigPush`] the agent writes the gost and/or
//! realm config file to disk and decides which tool to (re)start. The panel
//! renders the full config text (Line A); the agent treats it as opaque bytes
//! and just persists + supervises — it does not parse the tool config itself.
//!
//! Rule: a push carries `gost_config` and/or `realm_config`. If `gost_config`
//! is present we run gost; else if `realm_config` is present we run realm. (A
//! node runs one forwarding tool at a time in M1; gost takes precedence when
//! both are somehow present.)

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

/// The decision derived from a config push: which file was written and which
/// tool to (re)start against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedConfig {
    pub tool: Tool,
    pub config_path: String,
    pub applied_gen: u64,
}

/// Outcome of applying a [`ConfigPush`].
#[derive(Debug)]
pub enum ApplyOutcome {
    /// A tool config was written; (re)start `tool` against `config_path`.
    Start(AppliedConfig),
    /// The push carried no tool config (neither gost nor realm). The gen is
    /// still acked so the panel's drift tracking advances.
    NoTool { applied_gen: u64 },
}

/// Write the config file(s) from a push and decide the tool to run.
///
/// Returns the outcome, or an IO error if a file write failed (the caller then
/// acks with `ok=false` and the error string).
pub fn apply(push: &ConfigPush, paths: &ConfigPaths) -> std::io::Result<ApplyOutcome> {
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

    // gost takes precedence if both present (M1: one tool per node).
    if push.gost_config.is_some() {
        Ok(ApplyOutcome::Start(AppliedConfig {
            tool: Tool::Gost,
            config_path: paths.gost.to_string_lossy().into_owned(),
            applied_gen: push.desired_gen,
        }))
    } else if push.realm_config.is_some() {
        Ok(ApplyOutcome::Start(AppliedConfig {
            tool: Tool::Realm,
            config_path: paths.realm.to_string_lossy().into_owned(),
            applied_gen: push.desired_gen,
        }))
    } else {
        Ok(ApplyOutcome::NoTool {
            applied_gen: push.desired_gen,
        })
    }
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
        match apply(&push, &paths).unwrap() {
            ApplyOutcome::Start(a) => {
                assert_eq!(a.tool, Tool::Gost);
                assert_eq!(a.applied_gen, 7);
                let written = std::fs::read_to_string(&paths.gost).unwrap();
                assert_eq!(written, "{\"services\":[]}");
            }
            other => panic!("expected Start, got {other:?}"),
        }
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
        match apply(&push, &paths).unwrap() {
            ApplyOutcome::Start(a) => {
                assert_eq!(a.tool, Tool::Realm);
                assert_eq!(a.applied_gen, 3);
                assert!(std::fs::read_to_string(&paths.realm)
                    .unwrap()
                    .contains("network"));
            }
            other => panic!("expected Start, got {other:?}"),
        }
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
        match apply(&push, &paths).unwrap() {
            ApplyOutcome::NoTool { applied_gen } => assert_eq!(applied_gen, 9),
            other => panic!("expected NoTool, got {other:?}"),
        }
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
        match apply(&push, &paths).unwrap() {
            ApplyOutcome::Start(a) => {
                assert_eq!(a.tool, Tool::Gost);
                assert_eq!(a.applied_gen, 10);
                let cert = std::fs::read_to_string(&paths.tls_cert).unwrap();
                assert!(cert.contains("CERTIFICATE"));
                let key = std::fs::read_to_string(&paths.tls_key).unwrap();
                assert!(key.contains("PRIVATE KEY"));
            }
            other => panic!("expected Start, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gost_takes_precedence_when_both_present() {
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
        match apply(&push, &paths).unwrap() {
            ApplyOutcome::Start(a) => assert_eq!(a.tool, Tool::Gost),
            other => panic!("expected Start(gost), got {other:?}"),
        }
        // Both files still written.
        assert_eq!(std::fs::read_to_string(&paths.gost).unwrap(), "g");
        assert_eq!(std::fs::read_to_string(&paths.realm).unwrap(), "r");
        std::fs::remove_dir_all(&dir).ok();
    }
}
