//! IP→(region, ISP) resolution behind a provider trait (D5). Default impl reads
//! GeoCN MMDB (`GeoCnProvider`). A `db.format` config selects an impl, honoring
//! AC-10's intent without pretending incompatible formats are drop-in.
//!
//! Hot-reload (AC-10): a [`ProviderHandle`] wraps `ArcSwap<Arc<dyn GeoIpProvider>>`
//! so the panel can atomically swap in a freshly-loaded DB file with zero query-path
//! locking.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use contract::isp::Isp;
use contract::model::Region;

pub mod division;
pub mod geocn;

pub use geocn::{GeoCnProvider, StaticTableProvider};

/// A geo/ISP lookup backend. Implementations: GeoCN MMDB (default, M1) and one
/// format-switch stub ([`StaticTableProvider`]) proving the `db.format` path
/// compiles (M1); ipip/纯真 adapters are deferred to M3 (MAJOR-6).
pub trait GeoIpProvider: Send + Sync {
    /// Resolve a client/recursor IP (or ECS subnet address) to region + ISP.
    /// Returns `(Region::unknown(), Isp::Unknown)` when the address is not found.
    fn lookup(&self, ip: IpAddr) -> (Region, Isp);

    /// Identifier of the loaded DB format/source, for the UI/observability.
    fn format(&self) -> &'static str;
}

/// Placeholder provider — always returns unknown. Used as the initial provider
/// before a real DB is loaded and as a safe fallback.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnknownProvider;

impl GeoIpProvider for UnknownProvider {
    fn lookup(&self, _ip: IpAddr) -> (Region, Isp) {
        (Region::unknown(), Isp::Unknown)
    }
    fn format(&self) -> &'static str {
        "unknown-stub"
    }
}

/// Supported on-disk DB formats. Selecting a format chooses a provider impl
/// (D5 — format switch is a config setting, not a recompile). `GeoCn` is the
/// real M1 default; `StaticTable` is the ONE format-switch stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbFormat {
    /// GeoCN MMDB (MaxMind binary). The M1 default.
    GeoCn,
    /// Format-switch stub: a trivial newline `cidr,division_code,isp` text table.
    /// Proves the `db.format` selection path compiles and round-trips (D5);
    /// ipip/纯真 binary adapters are the M3 follow-up.
    StaticTable,
}

impl DbFormat {
    /// Load the provider impl selected by this format from `path`.
    ///
    /// # Errors
    /// Returns the underlying loader error (bad file / parse failure).
    pub fn load(self, path: &str) -> Result<Arc<dyn GeoIpProvider>, GeoIpError> {
        match self {
            DbFormat::GeoCn => Ok(Arc::new(GeoCnProvider::open(path)?)),
            DbFormat::StaticTable => Ok(Arc::new(StaticTableProvider::open(path)?)),
        }
    }
}

/// Loader / lookup error surface for the provider impls.
#[derive(Debug)]
pub enum GeoIpError {
    /// MMDB open/parse failure (GeoCN path).
    Mmdb(String),
    /// Text-table parse failure (format-switch stub path).
    Parse(String),
    /// File I/O failure.
    Io(String),
}

impl std::fmt::Display for GeoIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoIpError::Mmdb(m) => write!(f, "mmdb error: {m}"),
            GeoIpError::Parse(m) => write!(f, "parse error: {m}"),
            GeoIpError::Io(m) => write!(f, "io error: {m}"),
        }
    }
}

impl std::error::Error for GeoIpError {}

/// Hot-reloadable provider handle (AC-10). The DNS answer-builder reads via
/// [`ProviderHandle::current`] (lock-free `ArcSwap::load`); the panel swaps in a
/// reloaded DB via [`ProviderHandle::reload`] / [`ProviderHandle::store`].
pub struct ProviderHandle {
    inner: ArcSwap<ProviderState>,
}

struct ProviderState {
    provider: Arc<dyn GeoIpProvider>,
    format: DbFormat,
    path: String,
}

impl ProviderHandle {
    /// Build a handle from an already-loaded provider (e.g. the [`UnknownProvider`]
    /// startup stub or a test provider).
    #[must_use]
    pub fn new(provider: Arc<dyn GeoIpProvider>) -> Self {
        Self {
            inner: ArcSwap::from_pointee(ProviderState {
                provider,
                format: DbFormat::StaticTable,
                path: String::new(),
            }),
        }
    }

    /// Load a provider for `format` from `path` and install it.
    ///
    /// # Errors
    /// Propagates the loader error if the DB cannot be opened/parsed.
    pub fn load(format: DbFormat, path: &str) -> Result<Self, GeoIpError> {
        let provider = format.load(path)?;
        Ok(Self {
            inner: ArcSwap::from_pointee(ProviderState {
                provider,
                format,
                path: path.to_string(),
            }),
        })
    }

    /// The current provider — lock-free read for the DNS hot path.
    #[must_use]
    pub fn current(&self) -> Arc<dyn GeoIpProvider> {
        self.inner.load().provider.clone()
    }

    /// Atomically install a new provider (used by tests and format switches).
    pub fn store(&self, format: DbFormat, path: &str, provider: Arc<dyn GeoIpProvider>) {
        self.inner.store(Arc::new(ProviderState {
            provider,
            format,
            path: path.to_string(),
        }));
    }

    /// Reload the SAME format from the SAME path (operator dropped in a new DB file).
    ///
    /// # Errors
    /// Propagates the loader error; the previous provider stays installed on failure.
    pub fn reload(&self) -> Result<(), GeoIpError> {
        let state = self.inner.load();
        let provider = state.format.load(&state.path)?;
        self.store(state.format, &state.path, provider);
        Ok(())
    }

    /// Switch to a different DB format/path at runtime (D5 format switch, no recompile).
    ///
    /// # Errors
    /// Propagates the loader error; the previous provider stays installed on failure.
    pub fn switch(&self, format: DbFormat, path: &str) -> Result<(), GeoIpError> {
        let provider = format.load(path)?;
        self.store(format, path, provider);
        Ok(())
    }

    /// The current loaded format identifier (for UI/observability).
    #[must_use]
    pub fn format(&self) -> &'static str {
        self.inner.load().provider.format()
    }
}

impl GeoIpProvider for ProviderHandle {
    fn lookup(&self, ip: IpAddr) -> (Region, Isp) {
        self.inner.load().provider.lookup(ip)
    }
    fn format(&self) -> &'static str {
        self.inner.load().provider.format()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn stub_returns_unknown() {
        let p = UnknownProvider;
        let (r, isp) = p.lookup(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(isp, Isp::Unknown);
        assert_eq!(r.division_code, 0);
    }

    #[test]
    fn handle_swaps_provider_atomically() {
        let handle = ProviderHandle::new(Arc::new(UnknownProvider));
        assert_eq!(handle.format(), "unknown-stub");

        // Build a static-table provider in memory and swap it in.
        let table =
            StaticTableProvider::from_lines("1.0.0.0/24,410105,电信\n2.0.0.0/24,310000,联通\n")
                .expect("parse table");
        handle.store(DbFormat::StaticTable, "<mem>", Arc::new(table));
        assert_eq!(handle.format(), "static-table-stub");

        let (region, isp) = handle.lookup(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 7)));
        assert_eq!(region.division_code, 410105);
        assert_eq!(region.province_code, 41);
        assert_eq!(isp, Isp::Telecom);
    }
}
