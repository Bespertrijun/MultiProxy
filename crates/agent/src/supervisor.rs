//! Process supervisor abstraction (Line B task 2 + self-heal task 3).
//!
//! The agent (re)starts and supervises the gost or realm child process that
//! actually relays Emby traffic. The work is behind a [`ChildProcess`] trait +
//! [`ProcessSpawner`] factory so tests can inject a dummy child without a real
//! gost/realm binary present (brief: "use a process supervisor abstraction so
//! tests can inject a dummy child").
//!
//! `restart_count` and liveness are tracked so the self-heal loop (task 3) can
//! detect a crashed child and restart it, and so `StatusReport.forwarding_up`
//! reflects reality.

use std::process::Stdio;

/// Which forwarding tool a config push selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Gost,
    Realm,
}

impl Tool {
    /// Binary name to exec for this tool. The per-arch artifact selection
    /// (rev4 task 2b) resolves to a binary of this name on `PATH` / a bundled
    /// per-arch location; for M1 the name is what matters for the spawn call.
    #[must_use]
    pub fn binary(self) -> &'static str {
        match self {
            Tool::Gost => "gost",
            Tool::Realm => "realm",
        }
    }
}

/// A supervised child process. Abstracted so tests can substitute a dummy that
/// never touches the OS, while production spawns a real gost/realm process.
pub trait ChildProcess: Send {
    /// Non-blocking liveness check. `Ok(true)` = still running, `Ok(false)` =
    /// exited (crashed or clean), `Err` = the check itself failed.
    fn is_running(&mut self) -> std::io::Result<bool>;

    /// Best-effort kill; idempotent (killing an already-exited child is fine).
    fn kill(&mut self) -> std::io::Result<()>;

    /// OS process id if known (surfaced in `Metrics.gost_realm_pids`).
    fn pid(&self) -> Option<u32>;
}

/// Factory for spawning a [`ChildProcess`] from a written config file. Injected
/// so tests use [`DummySpawner`] and production uses [`RealSpawner`].
pub trait ProcessSpawner: Send + Sync {
    /// Spawn the forwarding tool against the freshly-written `config_path`.
    fn spawn(&self, tool: Tool, config_path: &str) -> std::io::Result<Box<dyn ChildProcess>>;
}

// ---------------------------------------------------------------------------
// Real implementation: spawn the actual gost/realm binary.
// ---------------------------------------------------------------------------

/// Spawns the real gost/realm binary via `std::process`.
///
/// gost takes `-C <file>` for a config file; realm takes `-c <file>`. We pass
/// the documented flag per tool. stdout/stderr are inherited so node operators
/// can see the tool's logs alongside the agent's.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealSpawner;

/// A real OS child wrapping `std::process::Child`.
pub struct RealChild {
    child: std::process::Child,
}

impl ChildProcess for RealChild {
    fn is_running(&mut self) -> std::io::Result<bool> {
        // try_wait: Ok(None) => still running, Ok(Some(_)) => exited.
        Ok(self.child.try_wait()?.is_none())
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // Send the signal (idempotent — an already-exited child returns
        // InvalidInput on some platforms; treat as success), THEN wait() to REAP
        // it. Without the wait an exited/killed child lingers as a zombie; on a
        // crash-looping or frequently-repushed node these piled up as many
        // `[realm]`/`[gost]` zombies.
        match self.child.kill() {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
            Err(e) => return Err(e),
        }
        let _ = self.child.wait();
        Ok(())
    }

    fn pid(&self) -> Option<u32> {
        Some(self.child.id())
    }
}

impl ProcessSpawner for RealSpawner {
    fn spawn(&self, tool: Tool, config_path: &str) -> std::io::Result<Box<dyn ChildProcess>> {
        let flag = match tool {
            Tool::Gost => "-C",
            Tool::Realm => "-c",
        };
        let mut cmd = std::process::Command::new(tool.binary());
        cmd.arg(flag)
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // Linux: bind the child's lifetime to ours. If the agent dies for ANY
        // reason (clean stop, SIGKILL, or crash) the kernel sends the child
        // SIGTERM, so a relay can never linger as an orphan holding its port
        // across restarts (the cause of piled-up duplicate realm processes).
        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Guard the fork→prctl race: if the parent already exited, follow it.
                if libc::getppid() == 1 {
                    libc::raise(libc::SIGTERM);
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        Ok(Box::new(RealChild { child }))
    }
}

// ---------------------------------------------------------------------------
// Supervisor: owns the current child, knows how to (re)start it, counts restarts.
// ---------------------------------------------------------------------------

/// Owns the currently-running forwarding child and the spawner that creates it.
/// Generic over the spawner so the dummy spawner is a zero-cost test seam.
pub struct Supervisor<S: ProcessSpawner> {
    spawner: S,
    current: Option<Box<dyn ChildProcess>>,
    tool: Option<Tool>,
    config_path: Option<String>,
    restart_count: u32,
}

impl<S: ProcessSpawner> Supervisor<S> {
    #[must_use]
    pub fn new(spawner: S) -> Self {
        Self {
            spawner,
            current: None,
            tool: None,
            config_path: None,
            restart_count: 0,
        }
    }

    /// (Re)start the forwarding tool against a config file. Any existing child
    /// is killed first so a config change cleanly replaces the process.
    pub fn start(&mut self, tool: Tool, config_path: impl Into<String>) -> std::io::Result<()> {
        if let Some(mut old) = self.current.take() {
            let _ = old.kill();
        }
        let config_path = config_path.into();
        let child = self.spawner.spawn(tool, &config_path)?;
        self.current = Some(child);
        self.tool = Some(tool);
        self.config_path = Some(config_path);
        Ok(())
    }

    /// Self-heal (task 3): if a child was started but is no longer running,
    /// restart it from the last config and bump `restart_count`. Returns
    /// `Ok(true)` if a restart happened.
    pub fn heal_if_crashed(&mut self) -> std::io::Result<bool> {
        let crashed = match self.current.as_mut() {
            Some(child) => !child.is_running()?,
            None => false, // nothing started yet → nothing to heal
        };
        if crashed {
            let (tool, path) = match (self.tool, self.config_path.clone()) {
                (Some(t), Some(p)) => (t, p),
                _ => return Ok(false),
            };
            let child = self.spawner.spawn(tool, &path)?;
            self.current = Some(child);
            self.restart_count += 1;
            return Ok(true);
        }
        Ok(false)
    }

    /// Whether a forwarding child is currently alive (drives `forwarding_up`).
    pub fn forwarding_up(&mut self) -> bool {
        match self.current.as_mut() {
            Some(child) => child.is_running().unwrap_or(false),
            None => false,
        }
    }

    #[must_use]
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    /// Current child pid, if any (for `Metrics.gost_realm_pids`).
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.current.as_ref().and_then(|c| c.pid())
    }

    /// Stop and drop the current child (clean shutdown).
    pub fn stop(&mut self) {
        if let Some(mut child) = self.current.take() {
            let _ = child.kill();
        }
        self.tool = None;
        self.config_path = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A dummy child whose liveness is driven by a shared flag so tests can
    /// simulate a crash deterministically.
    struct DummyChild {
        alive: Arc<std::sync::atomic::AtomicBool>,
        pid: u32,
    }

    impl ChildProcess for DummyChild {
        fn is_running(&mut self) -> std::io::Result<bool> {
            Ok(self.alive.load(Ordering::SeqCst))
        }
        fn kill(&mut self) -> std::io::Result<()> {
            self.alive.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn pid(&self) -> Option<u32> {
            Some(self.pid)
        }
    }

    /// Spawner that hands out [`DummyChild`]s and lets the test control their
    /// liveness flag + count how many spawns happened.
    struct DummySpawner {
        spawns: Arc<AtomicU32>,
        // The liveness flag handed to the most recent child.
        alive: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ProcessSpawner for DummySpawner {
        fn spawn(&self, _tool: Tool, _config_path: &str) -> std::io::Result<Box<dyn ChildProcess>> {
            let n = self.spawns.fetch_add(1, Ordering::SeqCst);
            // Each fresh spawn is born alive.
            self.alive.store(true, Ordering::SeqCst);
            Ok(Box::new(DummyChild {
                alive: self.alive.clone(),
                pid: 1000 + n,
            }))
        }
    }

    #[test]
    fn start_spawns_and_reports_up() {
        let spawns = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut sup = Supervisor::new(DummySpawner {
            spawns: spawns.clone(),
            alive: alive.clone(),
        });

        sup.start(Tool::Gost, "/tmp/gost.json").unwrap();
        assert_eq!(spawns.load(Ordering::SeqCst), 1);
        assert!(sup.forwarding_up());
        assert!(sup.pid().is_some());
    }

    #[test]
    fn heal_restarts_a_crashed_child_and_counts() {
        let spawns = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut sup = Supervisor::new(DummySpawner {
            spawns: spawns.clone(),
            alive: alive.clone(),
        });

        sup.start(Tool::Realm, "/tmp/realm.json").unwrap();
        assert_eq!(sup.restart_count(), 0);

        // Simulate crash.
        alive.store(false, Ordering::SeqCst);
        assert!(!sup.forwarding_up());

        let healed = sup.heal_if_crashed().unwrap();
        assert!(healed, "a crashed child must be restarted");
        assert_eq!(sup.restart_count(), 1);
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            2,
            "one initial + one restart"
        );
        assert!(sup.forwarding_up());
    }

    #[test]
    fn heal_is_noop_when_running() {
        let spawns = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut sup = Supervisor::new(DummySpawner {
            spawns: spawns.clone(),
            alive,
        });

        sup.start(Tool::Gost, "/tmp/gost.json").unwrap();
        let healed = sup.heal_if_crashed().unwrap();
        assert!(!healed);
        assert_eq!(sup.restart_count(), 0);
        assert_eq!(spawns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn heal_is_noop_when_nothing_started() {
        let spawns = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut sup = Supervisor::new(DummySpawner { spawns, alive });
        assert!(!sup.heal_if_crashed().unwrap());
        assert!(!sup.forwarding_up());
    }

    #[test]
    fn tool_binaries() {
        assert_eq!(Tool::Gost.binary(), "gost");
        assert_eq!(Tool::Realm.binary(), "realm");
    }
}
