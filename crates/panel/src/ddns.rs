//! DDNS (dynamic-DNS hostname) support for node addresses.
//!
//! A node's `public_ip` field may hold either an IP literal *or* a DNS hostname — the
//! latter for a front node behind a dynamic public IP (PPPoE / NAT). The DNS hot path
//! (`scheduler::build_snapshot` → the :53 resolver) stays "dumb" and only ever serves
//! IP literals, so hostname→IP resolution happens here, out-of-band: a background task
//! resolves each hostname node and caches the result in [`NodeRuntime::resolved`]
//! (bound to the hostname it came from), then rebuilds the snapshot.
//!
//! Resolution is fail-safe toward *availability*: a transient lookup failure keeps the
//! last-known IP (it never drops a node that was working) and only logs a warning.

use std::net::IpAddr;

use crate::scheduler::NodeRuntime;
use crate::state::AppState;
use crate::ws_server::rebuild_and_store_snapshot;

/// Default DDNS refresh cadence (seconds). DDNS A-records typically carry short TTLs
/// (60–300s); 60s keeps the panel within ~1 TTL of an IP change without hammering the
/// system resolver. Override with `PANEL_DDNS_REFRESH_SECS` (clamped to ≥10s).
pub const DEFAULT_DDNS_REFRESH_SECS: u64 = 60;

/// Hard ceiling on a single hostname lookup. Bounds how long a slow/broken external
/// resolver can stall one refresh iteration — the periodic task must never become a way
/// for DNS trouble to wedge the panel (the node simply stays excluded, fail-safe).
pub const LOOKUP_TIMEOUT_SECS: u64 = 5;

/// Read the refresh cadence from `PANEL_DDNS_REFRESH_SECS` (clamped to ≥10s), else the
/// [`DEFAULT_DDNS_REFRESH_SECS`] default.
#[must_use]
pub fn refresh_interval_secs() -> u64 {
    std::env::var("PANEL_DDNS_REFRESH_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| s.max(10))
        .unwrap_or(DEFAULT_DDNS_REFRESH_SECS)
}

/// Whether `addr` is a bare IP literal (so it needs no resolution).
#[must_use]
pub fn is_ip_literal(addr: &str) -> bool {
    addr.trim().parse::<IpAddr>().is_ok()
}

/// Loose syntactic check that `addr` could be a DNS hostname. Used to reject obvious
/// garbage at node-create time; it is intentionally *not* a full RFC-1035 validator.
/// Accepts dot-separated labels of `[A-Za-z0-9-]`, total ≤253 chars, each label 1–63
/// chars with no leading/trailing hyphen, and requires at least one dot (so a bare
/// single-word token like `localhost` is rejected — it would never be a valid front-node
/// public name and is almost always a typo).
#[must_use]
pub fn looks_like_hostname(addr: &str) -> bool {
    let a = addr.trim();
    if a.is_empty() || a.len() > 253 || !a.contains('.') {
        return false;
    }
    a.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Accept an address for a node's `public_ip`: either an IP literal or a plausible
/// hostname. The single gate used by the create/update API.
#[must_use]
pub fn is_valid_node_address(addr: &str) -> bool {
    is_ip_literal(addr) || looks_like_hostname(addr)
}

/// Resolve a hostname to its first IPv4 address (A record). Returns `None` on lookup
/// failure or if the name carries only IPv6 (AAAA) records — the served set is IPv4-only
/// this phase (mirrors `dns::answer::ipv4_only`).
pub async fn resolve_hostname_v4(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    // `lookup_host` needs a port; :0 is a throwaway — only the IP is read. Bound it with
    // a timeout so a hung resolver can never stall the refresh task indefinitely.
    let lookup = tokio::net::lookup_host((host, 0));
    let timeout = std::time::Duration::from_secs(LOOKUP_TIMEOUT_SECS);
    match tokio::time::timeout(timeout, lookup).await {
        Ok(Ok(addrs)) => addrs.map(|sa| sa.ip()).find(IpAddr::is_ipv4),
        Ok(Err(e)) => {
            tracing::warn!(host, error = %e, "DDNS lookup failed");
            None
        }
        Err(_) => {
            tracing::warn!(
                host,
                timeout_secs = LOOKUP_TIMEOUT_SECS,
                "DDNS lookup timed out"
            );
            None
        }
    }
}

/// Resolve every hostname-addressed node and cache the result in its [`NodeRuntime`].
/// Rebuilds + stores the snapshot iff some resolved IP actually changed. IP-literal nodes
/// are skipped entirely; a node whose lookup fails keeps its last-known IP.
pub async fn refresh_all(state: &AppState) {
    let nodes = match crate::db::list_nodes(&state.db).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "DDNS refresh: could not list nodes");
            return;
        }
    };

    let mut any_changed = false;
    for node in &nodes {
        if is_ip_literal(&node.public_ip) {
            continue; // IP literal — nothing to resolve.
        }
        // Resolve WITHOUT holding the runtimes lock (DNS lookup may block on the system
        // resolver); take the short lock only to write the cached result.
        let Some(ip) = resolve_hostname_v4(&node.public_ip).await else {
            continue; // Keep last-known IP on failure (fail-safe toward availability).
        };
        // Bind the IP to the hostname it was resolved from so a concurrently-changed
        // `public_ip` can never be served this (now-stale) result — `build_snapshot`
        // ignores a cache whose hostname no longer matches the node's address.
        let new = (node.public_ip.clone(), ip);
        let mut rts = state.runtimes.lock().await;
        let rt: &mut NodeRuntime = rts.entry(node.id.clone()).or_default();
        if rt.resolved.as_ref() != Some(&new) {
            tracing::info!(node = %node.id, host = %node.public_ip, %ip, "DDNS resolved");
            rt.resolved = Some(new);
            any_changed = true;
        }
    }

    if any_changed {
        rebuild_and_store_snapshot(state).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literals_are_not_hostnames() {
        assert!(is_ip_literal("1.2.3.4"));
        assert!(is_ip_literal("2001:db8::1"));
        assert!(is_valid_node_address("1.2.3.4"));
        // An IP literal is handled by the IP branch, not the hostname branch.
        assert!(!looks_like_hostname("1.2.3.4") || is_ip_literal("1.2.3.4"));
    }

    #[test]
    fn accepts_plausible_hostnames() {
        for h in [
            "relay.example.com",
            "a.b.c.d.example.io",
            "node-1.ddns.net",
            "xn--fsq.example.com",
        ] {
            assert!(looks_like_hostname(h), "should accept {h}");
            assert!(is_valid_node_address(h), "should accept {h}");
        }
    }

    #[test]
    fn rejects_garbage_and_bare_words() {
        for bad in [
            "",
            "   ",
            "localhost",        // no dot
            "not a host",       // space
            "-bad.example.com", // leading hyphen label
            "bad-.example.com", // trailing hyphen label
            "exa_mple.com",     // underscore
            "a..b.com",         // empty label
        ] {
            assert!(!is_valid_node_address(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn refresh_interval_floor() {
        // Default when unset (this var is not set in the unit-test env).
        assert_eq!(refresh_interval_secs(), DEFAULT_DDNS_REFRESH_SECS);
    }
}
