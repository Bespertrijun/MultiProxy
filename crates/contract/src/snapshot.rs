//! The `AvailabilitySnapshot` — the **single** scheduler↔resolver coupling surface
//! (MAJOR-5), defined in `contract` so Line C (resolver) compiles against it before
//! Line A's scheduler exists.
//!
//! The resolver reads exactly one `ArcSwap<AvailabilitySnapshot>` and stays *dumb*:
//! it serves `LineAvailability::available` and never learns *why* an IP was excluded.
//! The two-tier fallback (Rec#1) is **baked into `available` at build time** by the
//! scheduler, so the dumb-resolver invariant holds.
//!
//! M0 freezes the *shape* (this module). M2 wires the scheduler to call
//! [`select_available`] with live health/capacity classification.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::model::LineGroupId;

/// Immutable, point-in-time availability for every line group. Atomically swapped
/// by the scheduler via `ArcSwap::store`; read lock-free by the resolver.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AvailabilitySnapshot {
    pub generation: u64,
    /// Unix-millis when this snapshot was built.
    pub built_at: u64,
    pub lines: HashMap<LineGroupId, LineAvailability>,
}

impl AvailabilitySnapshot {
    /// What the resolver serves for a line group (already two-tier-resolved).
    #[must_use]
    pub fn available_for(&self, line: &str) -> &[IpAddr] {
        self.lines
            .get(line)
            .map(|l| l.available.as_slice())
            .unwrap_or(&[])
    }

    /// The Q3 fallback group for a line, if configured.
    #[must_use]
    pub fn fallback_for(&self, line: &str) -> Option<&str> {
        self.lines
            .get(line)
            .and_then(|l| l.fallback_group.as_deref())
    }
}

/// Per-line resolver-facing availability plus observability-only classification.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LineAvailability {
    /// The served A-record set, two-tier-resolved. The resolver reads ONLY this.
    pub available: Vec<IpAddr>,
    /// Q3 fallback line group (tried by the resolver when `available` is empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_group: Option<LineGroupId>,
    /// Observability only (powers `node_availability_transition_count{reason}`).
    /// The resolver MUST ignore this — it exists for the scheduler/metrics path.
    #[serde(default)]
    pub classified: Vec<NodeClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeClassification {
    pub ip: IpAddr,
    pub class: ExclusionClass,
}

/// Unified exclusion taxonomy (Line-0 task 5).
///
/// **Hard** exclusions are NEVER promoted; **soft** exclusions MAY be promoted when
/// tier-1 would otherwise leave a healthy line empty. Soft-quota and saturation are
/// mechanically identical at the DNS layer (both = "not in the served set"); only
/// their trigger differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionClass {
    /// Healthy and within quota and not saturated → served in tier-1.
    Included,
    /// Soft exclusion: over the soft quota threshold (promotable).
    SoftQuota,
    /// Soft exclusion: bandwidth-saturated (promotable).
    Saturated,
    /// Hard exclusion: over the hard quota threshold (never promoted).
    HardQuota,
    /// Hard exclusion: failed health (never promoted).
    Unhealthy,
}

impl ExclusionClass {
    #[must_use]
    pub const fn is_included(self) -> bool {
        matches!(self, ExclusionClass::Included)
    }
    /// Soft exclusions are promotable under pressure.
    #[must_use]
    pub const fn is_soft(self) -> bool {
        matches!(self, ExclusionClass::SoftQuota | ExclusionClass::Saturated)
    }
    /// Hard exclusions are never promoted.
    #[must_use]
    pub const fn is_hard(self) -> bool {
        matches!(self, ExclusionClass::HardQuota | ExclusionClass::Unhealthy)
    }
}

/// Two-tier availability selection (Rec#1). Pure and canonical — the scheduler calls
/// this so the policy lives in one tested place.
///
/// 1. tier-1 = `Included` nodes. If non-empty → use them.
/// 2. else promote `soft`-excluded nodes (healthy-but-degraded beats a blackout).
/// 3. else empty → caller applies the Q3 path (`fallback_group` → else SERVFAIL).
///
/// Hard-excluded nodes are NEVER returned: a hard-over-quota or unhealthy node is a
/// deliberate, operator-chosen (or health-driven) removal. An all-hard-quota line
/// therefore returns empty → fallback/SERVFAIL by design.
#[must_use]
pub fn select_available(nodes: &[(IpAddr, ExclusionClass)]) -> Vec<IpAddr> {
    let tier1: Vec<IpAddr> = nodes
        .iter()
        .filter(|(_, c)| c.is_included())
        .map(|(ip, _)| *ip)
        .collect();
    if !tier1.is_empty() {
        return tier1;
    }
    // Tier-2: promote soft-excluded (degraded-but-up) over a blackout.
    nodes
        .iter()
        .filter(|(_, c)| c.is_soft())
        .map(|(ip, _)| *ip)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ExclusionClass::*;
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn tier1_used_when_any_included() {
        let nodes = [(ip(1), Included), (ip(2), Saturated), (ip(3), HardQuota)];
        assert_eq!(select_available(&nodes), vec![ip(1)]);
    }

    #[test]
    fn soft_excluded_promoted_when_tier1_empty() {
        // Scenario ⑥: a healthy-but-saturated/soft-quota node beats a blackout.
        let nodes = [(ip(1), Saturated), (ip(2), SoftQuota)];
        assert_eq!(select_available(&nodes), vec![ip(1), ip(2)]);
    }

    #[test]
    fn hard_excluded_never_promoted_even_as_last_resort() {
        // All hard-quota / unhealthy → empty → caller goes to fallback/SERVFAIL.
        let nodes = [(ip(1), HardQuota), (ip(2), Unhealthy)];
        assert!(select_available(&nodes).is_empty());
    }

    #[test]
    fn mixed_soft_and_hard_promotes_only_soft() {
        let nodes = [(ip(1), HardQuota), (ip(2), Saturated), (ip(3), Unhealthy)];
        assert_eq!(select_available(&nodes), vec![ip(2)]);
    }

    #[test]
    fn empty_input_is_empty() {
        assert!(select_available(&[]).is_empty());
    }
}
