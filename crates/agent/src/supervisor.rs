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
// Supervisor: owns the running forwarding child(ren), (re)starts them, counts restarts.
// ---------------------------------------------------------------------------

/// One *desired* tool: the config path it should run, plus its running child.
///
/// `child` is `None` when the most recent spawn FAILED — the tool is still
/// desired (the slot exists), so `forwarding_up` reports down and the self-heal
/// loop keeps retrying it, rather than silently forgetting the tool. (If the slot
/// were dropped on a failed spawn, a half-dead mixed node would falsely report
/// up and never recover.)
struct Slot {
    config_path: String,
    child: Option<Box<dyn ChildProcess>>,
}

/// Owns the running forwarding child(ren) and the spawner that creates them.
/// Generic over the spawner so the dummy spawner is a zero-cost test seam.
///
/// A node may run **both** gost and realm at once (when its rules mix tools), so
/// the supervisor keeps an independent [`Slot`] per tool — a gost-only push,
/// realm-only push, or mixed push each supervise exactly the tools they carry.
/// Previously a single child was kept and the second tool's config was written to
/// disk but never started, silently breaking every rule on the losing tool.
pub struct Supervisor<S: ProcessSpawner> {
    spawner: S,
    gost: Option<Slot>,
    realm: Option<Slot>,
    restart_count: u32,
}

impl<S: ProcessSpawner> Supervisor<S> {
    #[must_use]
    pub fn new(spawner: S) -> Self {
        Self {
            spawner,
            gost: None,
            realm: None,
            restart_count: 0,
        }
    }

    /// The slot for a given tool.
    fn slot_mut(&mut self, tool: Tool) -> &mut Option<Slot> {
        match tool {
            Tool::Gost => &mut self.gost,
            Tool::Realm => &mut self.realm,
        }
    }

    /// (Re)start **one tool** against a config file. Only that tool's existing
    /// child is killed first (the other tool keeps running), so a config change
    /// for one tool never bounces the other. The old child is killed (and reaped)
    /// before spawning the new one so the freshly-started process can re-bind the
    /// listen port the old one held.
    pub fn start(&mut self, tool: Tool, config_path: impl Into<String>) -> std::io::Result<()> {
        // Kill this tool's previous child first (the other tool is untouched) so
        // the new process can re-bind the listen port the old one held.
        if let Some(slot) = self.slot_mut(tool).as_mut() {
            if let Some(mut old) = slot.child.take() {
                let _ = old.kill();
            }
        }
        let config_path = config_path.into();
        // Record the desired tool + config regardless of spawn outcome: a spawn
        // failure leaves the slot present with `child = None` so the tool reports
        // down and self-heal retries it (and the error still propagates to the
        // caller for the ConfigAck).
        let (child, err) = match self.spawner.spawn(tool, &config_path) {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(e)),
        };
        *self.slot_mut(tool) = Some(Slot { config_path, child });
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Stop one tool (when a push no longer carries that tool's config, e.g. all
    /// of a node's realm rules were deleted). Idempotent if the tool isn't running.
    pub fn stop_tool(&mut self, tool: Tool) {
        if let Some(mut slot) = self.slot_mut(tool).take() {
            if let Some(mut child) = slot.child.take() {
                let _ = child.kill();
            }
        }
    }

    /// Self-heal (task 3): for every supervised (desired) tool whose child has
    /// crashed OR never spawned (a prior spawn failure), restart it from its last
    /// config and bump `restart_count`. Returns `Ok(true)` if at least one restart
    /// happened. Each tool is healed independently — a crashed gost is restarted
    /// without touching a live realm.
    pub fn heal_if_crashed(&mut self) -> std::io::Result<bool> {
        let mut healed = false;
        for tool in [Tool::Gost, Tool::Realm] {
            // Grab the config path only if this tool needs (re)spawning, dropping
            // the slot borrow before we spawn (which borrows `self.spawner`).
            let path = match self.slot_mut(tool).as_mut() {
                Some(slot) => match slot.child.as_mut() {
                    // Alive → nothing to heal; crashed or never-spawned → respawn.
                    Some(child) => {
                        if child.is_running()? {
                            None
                        } else {
                            Some(slot.config_path.clone())
                        }
                    }
                    None => Some(slot.config_path.clone()), // prior spawn failed
                },
                None => None, // tool not desired
            };
            if let Some(path) = path {
                let child = self.spawner.spawn(tool, &path)?;
                if let Some(slot) = self.slot_mut(tool).as_mut() {
                    slot.child = Some(child);
                }
                self.restart_count += 1;
                healed = true;
            }
        }
        Ok(healed)
    }

    /// Whether forwarding is fully up: at least one tool is supervised AND every
    /// supervised tool's child is alive. A node that should run both gost and
    /// realm reports down if either has crashed (drives `StatusReport.forwarding_up`).
    pub fn forwarding_up(&mut self) -> bool {
        let mut any = false;
        for tool in [Tool::Gost, Tool::Realm] {
            if let Some(slot) = self.slot_mut(tool).as_mut() {
                any = true;
                // A desired tool whose child is missing (spawn failed) or dead → down.
                let up = match slot.child.as_mut() {
                    Some(child) => child.is_running().unwrap_or(false),
                    None => false,
                };
                if !up {
                    return false;
                }
            }
        }
        any
    }

    #[must_use]
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    /// Pids of every supervised child (for `Metrics.gost_realm_pids`) — gost first,
    /// then realm when both run.
    #[must_use]
    pub fn pids(&self) -> Vec<u32> {
        [self.gost.as_ref(), self.realm.as_ref()]
            .into_iter()
            .flatten()
            .filter_map(|slot| slot.child.as_ref().and_then(|c| c.pid()))
            .collect()
    }

    /// Stop and drop every supervised child (clean shutdown).
    pub fn stop(&mut self) {
        self.stop_tool(Tool::Gost);
        self.stop_tool(Tool::Realm);
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
        assert_eq!(sup.pids().len(), 1);
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

    /// A spawner that tracks gost and realm independently (each with its own
    /// liveness flag and spawn counter) so a test can drive a mixed-tool node and
    /// crash one tool without affecting the other.
    #[derive(Clone, Default)]
    struct MultiToolSpawner {
        gost_alive: Arc<std::sync::atomic::AtomicBool>,
        realm_alive: Arc<std::sync::atomic::AtomicBool>,
        gost_spawns: Arc<AtomicU32>,
        realm_spawns: Arc<AtomicU32>,
    }

    impl ProcessSpawner for MultiToolSpawner {
        fn spawn(&self, tool: Tool, _config_path: &str) -> std::io::Result<Box<dyn ChildProcess>> {
            let (alive, spawns, base) = match tool {
                Tool::Gost => (&self.gost_alive, &self.gost_spawns, 2000),
                Tool::Realm => (&self.realm_alive, &self.realm_spawns, 3000),
            };
            let n = spawns.fetch_add(1, Ordering::SeqCst);
            alive.store(true, Ordering::SeqCst);
            Ok(Box::new(DummyChild {
                alive: alive.clone(),
                pid: base + n,
            }))
        }
    }

    #[test]
    fn supervises_gost_and_realm_concurrently() {
        // A mixed-tool node runs BOTH children at once; pids reports both and
        // forwarding_up requires every supervised tool to be alive.
        let spawner = MultiToolSpawner::default();
        let mut sup = Supervisor::new(spawner.clone());

        sup.start(Tool::Gost, "/tmp/gost.json").unwrap();
        sup.start(Tool::Realm, "/tmp/realm.toml").unwrap();

        assert_eq!(spawner.gost_spawns.load(Ordering::SeqCst), 1);
        assert_eq!(spawner.realm_spawns.load(Ordering::SeqCst), 1);
        assert_eq!(sup.pids().len(), 2, "both gost and realm pids reported");
        assert!(sup.forwarding_up(), "both children alive → forwarding up");
    }

    #[test]
    fn one_tool_crash_is_healed_without_touching_the_other() {
        let spawner = MultiToolSpawner::default();
        let mut sup = Supervisor::new(spawner.clone());
        sup.start(Tool::Gost, "/tmp/gost.json").unwrap();
        sup.start(Tool::Realm, "/tmp/realm.toml").unwrap();

        // Crash gost only.
        spawner.gost_alive.store(false, Ordering::SeqCst);
        assert!(!sup.forwarding_up(), "one crashed tool → not fully up");

        let healed = sup.heal_if_crashed().unwrap();
        assert!(healed, "crashed gost must be restarted");
        assert_eq!(sup.restart_count(), 1, "only gost restarted");
        assert_eq!(
            spawner.gost_spawns.load(Ordering::SeqCst),
            2,
            "gost respawned once"
        );
        assert_eq!(
            spawner.realm_spawns.load(Ordering::SeqCst),
            1,
            "realm untouched by gost's heal"
        );
        assert!(sup.forwarding_up());
    }

    #[test]
    fn stop_tool_stops_only_that_tool() {
        let spawner = MultiToolSpawner::default();
        let mut sup = Supervisor::new(spawner.clone());
        sup.start(Tool::Gost, "/tmp/gost.json").unwrap();
        sup.start(Tool::Realm, "/tmp/realm.toml").unwrap();

        sup.stop_tool(Tool::Realm);
        assert!(!spawner.realm_alive.load(Ordering::SeqCst), "realm killed");
        assert!(
            spawner.gost_alive.load(Ordering::SeqCst),
            "gost still alive"
        );
        assert_eq!(sup.pids(), vec![2000], "only gost remains");
        assert!(
            sup.forwarding_up(),
            "remaining gost is up → still forwarding"
        );
    }

    /// A spawner whose realm spawn can be made to fail on demand, so a test can
    /// drive the "one tool of a mixed node fails to start" path.
    #[derive(Clone, Default)]
    struct ToggleFailSpawner {
        fail_realm: Arc<std::sync::atomic::AtomicBool>,
        gost_alive: Arc<std::sync::atomic::AtomicBool>,
        realm_alive: Arc<std::sync::atomic::AtomicBool>,
        realm_spawns: Arc<AtomicU32>,
    }

    impl ProcessSpawner for ToggleFailSpawner {
        fn spawn(&self, tool: Tool, _config_path: &str) -> std::io::Result<Box<dyn ChildProcess>> {
            match tool {
                Tool::Gost => {
                    self.gost_alive.store(true, Ordering::SeqCst);
                    Ok(Box::new(DummyChild {
                        alive: self.gost_alive.clone(),
                        pid: 1,
                    }))
                }
                Tool::Realm => {
                    self.realm_spawns.fetch_add(1, Ordering::SeqCst);
                    if self.fail_realm.load(Ordering::SeqCst) {
                        Err(std::io::Error::other("realm spawn boom"))
                    } else {
                        self.realm_alive.store(true, Ordering::SeqCst);
                        Ok(Box::new(DummyChild {
                            alive: self.realm_alive.clone(),
                            pid: 2,
                        }))
                    }
                }
            }
        }
    }

    #[test]
    fn failed_spawn_keeps_tool_desired_and_down_then_self_heals() {
        // On a mixed node, if realm fails to start while gost succeeds, the node
        // must NOT report forwarding up (realm is desired but down) and self-heal
        // must keep retrying realm until it comes up.
        let spawner = ToggleFailSpawner::default();
        spawner.fail_realm.store(true, Ordering::SeqCst);
        let mut sup = Supervisor::new(spawner.clone());

        sup.start(Tool::Gost, "/tmp/gost.json").unwrap();
        let realm = sup.start(Tool::Realm, "/tmp/realm.toml");
        assert!(realm.is_err(), "realm spawn fails → error propagates");

        assert!(
            !sup.forwarding_up(),
            "a desired-but-failed tool must report forwarding down, not up"
        );
        assert_eq!(sup.pids(), vec![1], "only gost has a live pid");

        // Backend recovers; self-heal retries the previously-failed realm spawn.
        spawner.fail_realm.store(false, Ordering::SeqCst);
        let healed = sup.heal_if_crashed().unwrap();
        assert!(healed, "self-heal must retry the failed spawn");
        assert!(sup.forwarding_up(), "realm now up → forwarding fully up");
        assert_eq!(sup.pids().len(), 2, "both tools now have live pids");
        assert_eq!(
            spawner.realm_spawns.load(Ordering::SeqCst),
            2,
            "realm spawn attempted twice (initial fail + heal retry)"
        );
    }
}
