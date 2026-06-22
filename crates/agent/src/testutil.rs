//! Injectable test doubles (gated behind the `testutil` feature, off by default).
//!
//! These let integration tests — and the panel-side e2e harness — drive the
//! agent without a real gost/realm binary or a real Emby backend. They are NOT
//! compiled into the production binary.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use contract::protocol::BackendEndpoint;

use crate::selfheal::BackendProbe;
use crate::supervisor::{ChildProcess, ProcessSpawner, Tool};

/// Shared handle to control a [`DummySpawner`]'s children from a test.
#[derive(Clone, Default)]
pub struct DummyControl {
    /// Total number of spawns the spawner has performed.
    spawns: Arc<AtomicU32>,
    /// Liveness flag shared with the most recently spawned child.
    alive: Arc<AtomicBool>,
}

impl DummyControl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many children have been spawned so far.
    #[must_use]
    pub fn spawn_count(&self) -> u32 {
        self.spawns.load(Ordering::SeqCst)
    }

    /// Force the current child to look crashed (so `heal_if_crashed` restarts it).
    pub fn kill_current(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    /// Whether the current child is alive.
    #[must_use]
    pub fn current_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

/// A dummy child whose liveness is a shared flag.
pub struct DummyChild {
    alive: Arc<AtomicBool>,
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

/// Spawner that hands out [`DummyChild`]s controlled via a [`DummyControl`].
/// Every fresh spawn is born alive.
pub struct DummySpawner {
    control: DummyControl,
}

impl DummySpawner {
    #[must_use]
    pub fn new() -> (Self, DummyControl) {
        let control = DummyControl::new();
        (
            Self {
                control: control.clone(),
            },
            control,
        )
    }
}

impl ProcessSpawner for DummySpawner {
    fn spawn(&self, _tool: Tool, _config_path: &str) -> std::io::Result<Box<dyn ChildProcess>> {
        let n = self.control.spawns.fetch_add(1, Ordering::SeqCst);
        self.control.alive.store(true, Ordering::SeqCst);
        Ok(Box::new(DummyChild {
            alive: self.control.alive.clone(),
            pid: 9000 + n,
        }))
    }
}

/// A backend probe with a fixed, test-controlled reachability answer.
#[derive(Clone)]
pub struct FixedBackendProbe {
    reachable: Arc<AtomicBool>,
}

impl FixedBackendProbe {
    #[must_use]
    pub fn new(reachable: bool) -> Self {
        Self {
            reachable: Arc::new(AtomicBool::new(reachable)),
        }
    }

    pub fn set(&self, reachable: bool) {
        self.reachable.store(reachable, Ordering::SeqCst);
    }
}

impl BackendProbe for FixedBackendProbe {
    async fn reachable(&self, _targets: &[BackendEndpoint]) -> bool {
        self.reachable.load(Ordering::SeqCst)
    }
}

/// A backend probe that records the targets it was last asked about (so a test can
/// assert the agent probes the endpoints from `ConfigPush.backends`, not a fixed
/// address) and returns a fixed reachability answer.
#[derive(Clone, Default)]
pub struct RecordingBackendProbe {
    reachable: Arc<AtomicBool>,
    last_targets: Arc<Mutex<Vec<BackendEndpoint>>>,
}

impl RecordingBackendProbe {
    #[must_use]
    pub fn new(reachable: bool) -> Self {
        Self {
            reachable: Arc::new(AtomicBool::new(reachable)),
            last_targets: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The targets passed to the most recent `reachable` call.
    #[must_use]
    pub fn last_targets(&self) -> Vec<BackendEndpoint> {
        self.last_targets.lock().unwrap().clone()
    }
}

impl BackendProbe for RecordingBackendProbe {
    async fn reachable(&self, targets: &[BackendEndpoint]) -> bool {
        *self.last_targets.lock().unwrap() = targets.to_vec();
        self.reachable.load(Ordering::SeqCst)
    }
}

/// A capacity counter source driven by a fixed cumulative total that grows by
/// `step` each read — enough to produce a stable throughput in tests.
pub struct SteppingCounterSource {
    total: u64,
    step: u64,
}

impl SteppingCounterSource {
    #[must_use]
    pub fn new(step: u64) -> Self {
        Self { total: 0, step }
    }
}

impl crate::capacity::CounterSource for SteppingCounterSource {
    fn source(&self) -> contract::protocol::CapacitySource {
        contract::protocol::CapacitySource::ForwardBytes
    }
    fn read(&mut self) -> Option<crate::capacity::CounterSample> {
        self.total = self.total.saturating_add(self.step);
        Some(crate::capacity::CounterSample {
            tx_bytes_total: self.total,
            rx_bytes_total: self.total,
        })
    }
}
