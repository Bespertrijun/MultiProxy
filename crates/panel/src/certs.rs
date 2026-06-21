//! Per-zone relay TLS certificate management.
//!
//! Each DNS zone (`apex_domain`) that clients reach over HTTPS needs a cert the relay
//! node can present. Because zones are NS-delegated to the panel's own GeoDNS, the
//! ACME DNS-01 challenge is answered by that GeoDNS (self-served) rather than via
//! Cloudflare — see [`crate::acme::issue_cert_self_dns`]. Issued certs are cached in
//! [`AppState::zone_certs`] and pushed to the zone's member nodes by [`ws_server::push_config_to`].

use std::path::Path;

use crate::state::AppState;
use crate::{acme, db, ws_server};

/// Issue (or renew) the relay cert for one zone apex domain via self-served DNS-01,
/// cache it, and re-push config to every node that serves the zone.
///
/// # Errors
/// Returns a message if Cloudflare is not configured (needed for cert_dir/staging) or
/// ACME issuance fails. The previous cert (if any) stays installed on failure.
pub async fn issue_zone_cert(state: &AppState, apex_domain: &str) -> Result<(), String> {
    let cf = state
        .cf_config()
        .await
        .ok_or("Cloudflare 未配置（需要其 cert_dir / staging 设置）")?;

    tracing::info!(domain = %apex_domain, "issuing relay cert via self-served DNS-01");
    let issued = acme::issue_cert_self_dns(
        &state.acme_challenges,
        apex_domain,
        &cf.cert_dir,
        cf.acme_staging,
    )
    .await?;

    state
        .set_zone_cert(apex_domain.to_string(), issued.cert_pem, issued.key_pem)
        .await;
    repush_zone_nodes(state, apex_domain).await;
    Ok(())
}

/// Load any already-issued zone certs from disk into the cache (fast, no network).
/// Called at startup so `push_config` has certs available immediately.
pub async fn load_existing_zone_certs(state: &AppState) {
    let Some(cf) = state.cf_config().await else {
        return;
    };
    let Ok(zones) = db::list_zones(&state.db).await else {
        return;
    };
    for z in zones {
        if let Some((cert, key)) = acme::load_cert_pair(&cf.cert_dir, &z.apex_domain) {
            state.set_zone_cert(z.apex_domain, cert, key).await;
        }
    }
}

/// Issue certs for any zone whose cert is missing or expiring within 30 days.
/// Safe to call periodically (renewal) and at startup. Each zone is independent;
/// a failure on one is logged and does not stop the others.
pub async fn renew_due_zone_certs(state: &AppState) {
    let Some(cf) = state.cf_config().await else {
        return;
    };
    let Ok(zones) = db::list_zones(&state.db).await else {
        return;
    };
    for z in zones {
        let cert_path = Path::new(&cf.cert_dir).join(format!("{}.crt", z.apex_domain));
        if acme::needs_renewal(&cert_path) {
            if let Err(e) = issue_zone_cert(state, &z.apex_domain).await {
                tracing::warn!(domain = %z.apex_domain, error = %e, "zone cert issuance failed");
            }
        }
    }
}

/// Re-push config to every node that is a member of a line group bound to this zone,
/// so a freshly issued cert lands without waiting for the next CRUD/reconnect.
async fn repush_zone_nodes(state: &AppState, apex_domain: &str) {
    let zones = state.zones.load();
    let Some(zone) = zones.iter().find(|z| z.apex_domain == apex_domain) else {
        return;
    };
    let groups = state.groups.load();
    let mut node_ids: Vec<String> = groups
        .iter()
        .filter(|g| g.zone_id.as_deref() == Some(zone.id.as_str()))
        .flat_map(|g| g.member_node_ids.iter().cloned())
        .collect();
    node_ids.sort_unstable();
    node_ids.dedup();
    for nid in node_ids {
        ws_server::push_config_to(state, &nid).await;
    }
}
