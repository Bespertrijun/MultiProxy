//! Self-update module: check GitHub Releases for newer versions, download assets,
//! and replace the running binary with an atomic rename + restart.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// GitHub repository in `owner/repo` form.
pub const GITHUB_REPO: &str = "Bespertrijun/MultiProxy";

/// Maximum asset download size (200 MB) to prevent abuse.
const MAX_ASSET_SIZE: u64 = 200 * 1024 * 1024;

/// Download timeout.
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Information about an available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub has_update: bool,
    pub release_url: String,
    pub release_notes: String,
}

/// A single asset from a GitHub release.
#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

/// Subset of the GitHub release JSON we care about.
#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: Option<String>,
    assets: Vec<GhAsset>,
}

/// Check the GitHub Releases API for a newer version.
pub async fn check_update() -> Result<UpdateInfo, String> {
    let current = env!("CARGO_PKG_VERSION");
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("multiProxy-panel")
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }

    let release: GhRelease = resp
        .json()
        .await
        .map_err(|e| format!("parse release JSON: {e}"))?;

    let latest = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);
    let has_update = version_newer(latest, current);

    Ok(UpdateInfo {
        current_version: current.to_string(),
        latest_version: latest.to_string(),
        has_update,
        release_url: release.html_url,
        release_notes: release.body.unwrap_or_default(),
    })
}

/// Download a release asset by name and save it to `dest`. Returns bytes written.
pub async fn download_asset(tag: &str, asset_name: &str, dest: &Path) -> Result<u64, String> {
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{tag}");

    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent("multiProxy-panel")
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("fetch release: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }

    let release: GhRelease = resp
        .json()
        .await
        .map_err(|e| format!("parse release JSON: {e}"))?;

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| format!("asset '{asset_name}' not found in release {tag}"))?;

    let dl_resp = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .map_err(|e| format!("download asset: {e}"))?;

    if !dl_resp.status().is_success() {
        return Err(format!("asset download returned {}", dl_resp.status()));
    }

    if let Some(cl) = dl_resp.content_length() {
        if cl > MAX_ASSET_SIZE {
            return Err(format!(
                "asset too large: {cl} bytes (max {MAX_ASSET_SIZE})"
            ));
        }
    }

    let bytes = dl_resp
        .bytes()
        .await
        .map_err(|e| format!("read asset body: {e}"))?;

    if bytes.len() as u64 > MAX_ASSET_SIZE {
        return Err("asset too large".into());
    }

    // Write to a temp file next to dest, then atomic rename.
    let dest_dir = dest.parent().unwrap_or(Path::new("."));
    let tmp_path = dest_dir.join(format!(".{asset_name}.tmp"));

    tokio::fs::write(&tmp_path, &bytes)
        .await
        .map_err(|e| format!("write temp file: {e}"))?;

    // Make executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&tmp_path, perms).map_err(|e| format!("chmod: {e}"))?;
    }

    // Atomic rename (same filesystem).
    tokio::fs::rename(&tmp_path, dest)
        .await
        .map_err(|e| format!("rename into place: {e}"))?;

    Ok(bytes.len() as u64)
}

/// Self-update: download the new panel binary matching our binary name,
/// replace the current executable, and restart.
pub async fn self_update(tag: &str) -> Result<(), String> {
    let current_exe =
        std::env::current_exe().map_err(|e| format!("cannot determine current exe: {e}"))?;

    let asset_name = detect_panel_asset_name();
    let tag_prefixed = if tag.starts_with('v') {
        tag.to_string()
    } else {
        format!("v{tag}")
    };

    tracing::info!(tag = %tag_prefixed, asset = %asset_name, "starting self-update");

    // Download to a temp path next to current exe.
    let tmp_path = current_exe
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!(".{asset_name}.update"));

    download_asset(&tag_prefixed, &asset_name, &tmp_path).await?;

    // Basic validation: check it's a valid ELF.
    validate_binary(&tmp_path)?;

    // Rename over the current binary.
    tokio::fs::rename(&tmp_path, &current_exe)
        .await
        .map_err(|e| format!("replace binary: {e}"))?;

    tracing::info!("binary replaced, restarting...");
    restart();
}

/// Detect the asset name for the currently running binary.
fn detect_panel_asset_name() -> String {
    "panel-linux-x86_64".to_string()
}

/// Detect the asset name for an agent binary given the target arch.
pub fn detect_agent_asset_name(arch: &str) -> String {
    match arch {
        "aarch64" | "arm64" => "agent-linux-aarch64".to_string(),
        _ => "agent-linux-x86_64".to_string(),
    }
}

/// Download agent binaries for both architectures into `agent_bin_dir`.
pub async fn update_agent_binaries(tag: &str, agent_bin_dir: &Path) -> Result<(), String> {
    let tag_prefixed = if tag.starts_with('v') {
        tag.to_string()
    } else {
        format!("v{tag}")
    };

    // Ensure the directory exists.
    tokio::fs::create_dir_all(agent_bin_dir)
        .await
        .map_err(|e| format!("create agent_bin_dir: {e}"))?;

    for asset_name in &["agent-linux-x86_64", "agent-linux-aarch64"] {
        let dest = agent_bin_dir.join(asset_name);
        tracing::info!(asset = %asset_name, "downloading agent binary");
        download_asset(&tag_prefixed, asset_name, &dest).await?;
    }

    Ok(())
}

/// Validate that a file looks like a valid ELF binary.
fn validate_binary(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read binary: {e}"))?;
    if bytes.len() < 4 {
        return Err("binary too small".into());
    }
    // ELF magic: 0x7F 'E' 'L' 'F'
    if &bytes[..4] != b"\x7fELF" {
        return Err("not a valid ELF binary".into());
    }
    Ok(())
}

/// Simple semver comparison: returns true if `latest` > `current`.
fn version_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let l = parse(latest);
    let c = parse(current);
    l > c
}

/// Restart strategy: if under systemd exit(0) (Restart=always picks up new binary);
/// otherwise fork+exec with same args then exit.
fn restart() -> ! {
    if is_under_systemd() {
        tracing::info!("running under systemd, exiting for restart");
        std::process::exit(0);
    }

    // Fork+exec: spawn self with same args, then exit.
    match std::env::current_exe() {
        Ok(exe) => {
            let args: Vec<String> = std::env::args().skip(1).collect();
            match std::process::Command::new(exe).args(&args).spawn() {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    tracing::error!("failed to respawn: {e}, exiting anyway");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            tracing::error!("cannot determine exe for respawn: {e}, exiting");
            std::process::exit(1);
        }
    }
}

/// Check whether we're running under systemd.
fn is_under_systemd() -> bool {
    // systemd sets INVOCATION_ID for services.
    if std::env::var("INVOCATION_ID").is_ok() {
        return true;
    }
    // Alternatively, check if ppid is 1 (init/systemd).
    #[cfg(unix)]
    {
        use std::os::unix::process::parent_id;
        if parent_id() == 1 {
            return true;
        }
    }
    false
}

/// Get the path to the current executable's directory.
pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(version_newer("0.2.0", "0.1.0"));
        assert!(version_newer("1.0.0", "0.9.9"));
        assert!(version_newer("0.1.1", "0.1.0"));
        assert!(!version_newer("0.1.0", "0.1.0"));
        assert!(!version_newer("0.0.9", "0.1.0"));
    }

    #[test]
    fn asset_name_detection() {
        assert_eq!(detect_agent_asset_name("x86_64"), "agent-linux-x86_64");
        assert_eq!(detect_agent_asset_name("aarch64"), "agent-linux-aarch64");
        assert_eq!(detect_agent_asset_name("arm64"), "agent-linux-aarch64");
    }
}
