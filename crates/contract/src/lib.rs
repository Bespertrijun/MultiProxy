//! `contract` — the frozen Line-0 shared interface: wire protocol, data model,
//! versioning, the ISP/region shapes, and the `AvailabilitySnapshot` coupling type.
//!
//! Intentionally light (serde only) so the `agent` crate can depend on it without
//! pulling hickory/axum/sqlx. All three component lines (panel, agent, geodns) fork
//! against this crate.

pub mod isp;
pub mod model;
pub mod protocol;
pub mod snapshot;
pub mod version;

pub use isp::Isp;
pub use protocol::{Envelope, Message};
pub use snapshot::{AvailabilitySnapshot, ExclusionClass};
pub use version::PROTOCOL_VERSION;
