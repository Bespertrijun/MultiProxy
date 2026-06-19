//! Runtime platform detection (Line B task 5 / rev4 Q1).
//!
//! The agent reports its CPU-arch / OS triple in [`contract::protocol::Hello`]
//! so the panel renders/fetches the correct-arch gost/realm config + binary.
//! This is the locally-detected value, NOT a build-time constant baked from the
//! host that compiled the agent — though for a statically cross-compiled binary
//! the two coincide.

/// Detected `arch-os` triple, e.g. `x86_64-linux` / `aarch64-linux`.
///
/// We detect the architecture from the compiled target (`cfg!(target_arch)`),
/// which is correct for a per-arch static binary, and the OS likewise. The
/// panel treats this as the node's platform (gap: older agents omit it and the
/// contract defaults to `x86_64-linux`).
#[must_use]
pub fn detect() -> String {
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        // Any other arch we might be built for; report the raw cfg fallback.
        std::env::consts::ARCH
    };

    let os = if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    };

    format!("{arch}-{os}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_yields_arch_dash_os() {
        let p = detect();
        assert!(p.contains('-'), "platform must be arch-os, got {p}");
        // On the build/test host this is one of the two first-class triples.
        assert!(
            p == "x86_64-linux" || p == "aarch64-linux" || p.ends_with("-linux"),
            "unexpected platform triple: {p}"
        );
    }
}
