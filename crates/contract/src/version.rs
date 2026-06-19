//! Protocol versioning and negotiation (Line-0 tasks 1 & 7.4).
//!
//! Every [`crate::protocol::Envelope`] carries `protocol_version`. The panel
//! validates it on `Hello` (gap 7.4): a version outside the accepted set is a
//! **hard reject** by default (`AuthReject{reason: ProtocolVersion}`), not a
//! silent compatibility attempt. JSON additive/optional fields (D1) cover minor
//! forward-compat within a version; this gate covers breaking changes.

/// Current wire protocol version. Bump on any breaking envelope/message change.
pub const PROTOCOL_VERSION: u32 = 1;

/// Default policy: accept only the current version (hard-reject on mismatch).
///
/// A compatibility window (e.g. also accept `PROTOCOL_VERSION - 1`) MAY be
/// enabled by panel config, but is intentionally NOT the default.
#[must_use]
pub const fn is_accepted(version: u32) -> bool {
    version == PROTOCOL_VERSION
}

/// Whether a compatibility window accepting `N-1` would admit `version`.
/// Exposed so the panel can opt in without re-deriving the rule.
#[must_use]
pub const fn is_accepted_with_back_compat(version: u32) -> bool {
    version == PROTOCOL_VERSION || version + 1 == PROTOCOL_VERSION
}
