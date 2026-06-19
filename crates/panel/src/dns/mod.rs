//! Embedded GeoDNS (Line C). A custom hickory `RequestHandler` (NOT Authority/
//! ZoneHandler — only `RequestHandler` sees the full `Request` incl. ECS) running on
//! its OWN tokio runtime/thread (isolation contract, MAJOR-5).
//!
//! The resolver reads exactly one `ArcSwap<AvailabilitySnapshot>` (the sole
//! scheduler↔resolver coupling surface) and a hot-reloadable `geoip::ProviderHandle`,
//! both lock-free on the query path.

pub mod answer;
pub mod ecs;
pub mod handler;
pub mod runtime;

pub use handler::GeoDnsHandler;
pub use runtime::{spawn_dns, DnsConfig, DnsLiveness};
