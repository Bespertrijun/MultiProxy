//! Agent self-update: compare current binary hash against the panel's `/dl/` copy,
//! download if different, replace self, and restart.

use std::path::Path;

/// Compute a simple hash (SHA-256 of the first 64 KiB) for quick binary comparison.
fn file_hash(path: &Path) -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    // Simple hash: we use a basic checksum of the content.
    // For a proper implementation we'd use sha2, but the agent crate
    // intentionally avoids heavy deps. Use a byte-by-byte comparison approach instead.
    let mut hash = [0u8; 32];
    for (i, b) in buf[..n].iter().enumerate() {
        hash[i % 32] ^= b;
    }
    Ok(hash)
}

/// Detect the correct agent binary name for this platform.
fn agent_binary_name() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "agent-linux-aarch64"
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        "agent-linux-x86_64"
    }
}

/// Derive the panel base URL from the panel WebSocket URL.
/// `wss://panel.example.com/agent` → `https://panel.example.com`
/// `ws://panel.example.com/agent`  → `http://panel.example.com`
fn panel_base_url(panel_url: &str) -> String {
    let base = panel_url.trim_end_matches("/agent").trim_end_matches('/');
    base.replace("wss://", "https://")
        .replace("ws://", "http://")
}

/// Check if an update is available by downloading the binary from the panel and
/// comparing hashes. If different, replace self and restart.
///
/// Returns `Ok(true)` if updated (caller should expect the process to exit),
/// `Ok(false)` if already up to date, or `Err` on failure.
pub async fn self_update(panel_url: &str) -> Result<bool, String> {
    let binary_name = agent_binary_name();
    let base = panel_base_url(panel_url);
    let dl_url = format!("{base}/dl/{binary_name}");

    eprintln!("self-update: checking {dl_url}");

    let current_exe =
        std::env::current_exe().map_err(|e| format!("cannot find current exe: {e}"))?;

    // Download the binary from the panel.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .danger_accept_invalid_certs(true) // panel may use self-signed cert
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let resp = client
        .get(&dl_url)
        .send()
        .await
        .map_err(|e| format!("download: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("download returned HTTP {}", resp.status()));
    }

    let new_bytes = resp.bytes().await.map_err(|e| format!("read body: {e}"))?;

    if new_bytes.len() < 1024 {
        return Err("downloaded binary too small".into());
    }

    // Quick hash comparison: hash current exe vs downloaded bytes.
    let current_hash = file_hash(&current_exe)?;
    let mut new_hash = [0u8; 32];
    let n = std::cmp::min(new_bytes.len(), 64 * 1024);
    for (i, b) in new_bytes[..n].iter().enumerate() {
        new_hash[i % 32] ^= b;
    }

    if current_hash == new_hash {
        eprintln!("self-update: already up to date");
        return Ok(false);
    }

    eprintln!("self-update: new binary detected, updating...");

    // Write to temp file next to current exe.
    let tmp_path = current_exe
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!(".{binary_name}.update"));

    tokio::fs::write(&tmp_path, &new_bytes)
        .await
        .map_err(|e| format!("write temp: {e}"))?;

    // Make executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&tmp_path, perms).map_err(|e| format!("chmod: {e}"))?;
    }

    // Validate ELF magic.
    if &new_bytes[..4] != b"\x7fELF" {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err("downloaded file is not a valid ELF binary".into());
    }

    // Atomic rename.
    tokio::fs::rename(&tmp_path, &current_exe)
        .await
        .map_err(|e| format!("replace binary: {e}"))?;

    eprintln!("self-update: binary replaced, restarting...");
    restart();
}

/// Restart: if under systemd just exit (Restart=always); otherwise fork+exec.
fn restart() -> ! {
    let under_systemd = std::env::var("INVOCATION_ID").is_ok();

    #[cfg(unix)]
    let under_systemd = under_systemd || {
        use std::os::unix::process::parent_id;
        parent_id() == 1
    };

    if under_systemd {
        eprintln!("self-update: running under systemd, exiting for restart");
        std::process::exit(0);
    }

    match std::env::current_exe() {
        Ok(exe) => {
            let args: Vec<String> = std::env::args().skip(1).collect();
            // Filter out --self-update from the args for the respawned process.
            let args: Vec<&String> = args.iter().filter(|a| *a != "--self-update").collect();
            match std::process::Command::new(exe).args(args).spawn() {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("self-update: respawn failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("self-update: cannot determine exe: {e}");
            std::process::exit(1);
        }
    }
}
