//! Capacity telemetry (Line B task 3b / rev3 §A).
//!
//! The agent collects byte counters and emits a [`contract::protocol::Capacity`]
//! on every status report. Two accuracy tiers (rev3 §A / Q9):
//!   * [`CapacitySource::ForwardBytes`] — per-rule/per-port counters from the
//!     forwarding tool (gost/realm). Accurate: only relayed Emby traffic.
//!   * [`CapacitySource::NicDelta`] — NIC counter deltas read from
//!     `/proc/net/dev`. Coarse: includes all host traffic + the agent's own
//!     control channel; lower confidence.
//!
//! The agent prefers `ForwardBytes` and degrades to `NicDelta`. It computes a
//! **sliding-window** `throughput_bps` (not a raw cumulative) and stamps every
//! report with a `counter_epoch` set at boot (and bumped when the underlying
//! counter is known to have reset), so the panel can do reset-aware delta
//! accumulation by EQUALITY only — any change to the epoch re-baselines
//! (`counter_epoch != prior`), never an ordering compare (Architect Rec#3).

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use contract::protocol::{Capacity, CapacitySource};

/// A raw cumulative byte-counter sample from whatever source is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSample {
    pub tx_bytes_total: u64,
    pub rx_bytes_total: u64,
}

/// Pluggable byte-counter source. Production reads gost/realm or `/proc/net/dev`;
/// tests inject a deterministic counter.
pub trait CounterSource: Send {
    /// The attribution tier this source represents.
    fn source(&self) -> CapacitySource;

    /// Read the current cumulative tx/rx totals. `None` if unavailable right now
    /// (the collector then keeps the previous epoch and skips a delta).
    fn read(&mut self) -> Option<CounterSample>;
}

/// NIC-counter source reading aggregate bytes from `/proc/net/dev`, excluding
/// the loopback interface. Coarse tier ([`CapacitySource::NicDelta`]).
///
/// This is the fallback when per-rule forward-byte counters are not obtainable
/// from gost/realm. On non-Linux hosts `read` returns `None`.
#[derive(Debug, Default)]
pub struct NicCounterSource;

impl NicCounterSource {
    /// Parse `/proc/net/dev`-style text into summed (rx, tx) byte totals across
    /// all non-loopback interfaces. Extracted for unit testing without /proc.
    #[must_use]
    pub fn parse_proc_net_dev(text: &str) -> CounterSample {
        let mut rx_total: u64 = 0;
        let mut tx_total: u64 = 0;
        for line in text.lines() {
            // Format: "  iface: rxbytes rxpkts ... txbytes txpkts ..."
            let Some((iface, rest)) = line.split_once(':') else {
                continue;
            };
            let iface = iface.trim();
            if iface.is_empty() || iface == "lo" {
                continue;
            }
            let cols: Vec<&str> = rest.split_whitespace().collect();
            // rx bytes = column 0, tx bytes = column 8 (per /proc/net/dev layout).
            if cols.len() >= 9 {
                if let Ok(rx) = cols[0].parse::<u64>() {
                    rx_total = rx_total.saturating_add(rx);
                }
                if let Ok(tx) = cols[8].parse::<u64>() {
                    tx_total = tx_total.saturating_add(tx);
                }
            }
        }
        CounterSample {
            tx_bytes_total: tx_total,
            rx_bytes_total: rx_total,
        }
    }
}

impl CounterSource for NicCounterSource {
    fn source(&self) -> CapacitySource {
        CapacitySource::NicDelta
    }

    fn read(&mut self) -> Option<CounterSample> {
        let text = std::fs::read_to_string("/proc/net/dev").ok()?;
        Some(Self::parse_proc_net_dev(&text))
    }
}

/// One point in the sliding throughput window: a cumulative total at an instant.
#[derive(Debug, Clone, Copy)]
struct WindowPoint {
    at: Instant,
    total_bytes: u64,
}

/// Collects counters from a [`CounterSource`] and produces [`Capacity`] reports
/// with reset-aware epoch stamping and a sliding-window throughput.
pub struct CapacityCollector<C: CounterSource> {
    source: C,
    /// Boot/counter-generation id stamped on every report. Bumped on a detected
    /// reset (counter went non-monotonic) so the panel re-baselines.
    epoch: u64,
    last: Option<CounterSample>,
    /// Sliding window of (instant, cumulative tx+rx) for throughput.
    window: VecDeque<WindowPoint>,
    window_span: Duration,
}

impl<C: CounterSource> CapacityCollector<C> {
    /// `window_span` is how far back throughput is averaged (e.g. one or two
    /// heartbeat intervals). `boot_epoch` is the initial counter epoch — use a
    /// fresh value per agent boot (see [`boot_epoch`]).
    #[must_use]
    pub fn new(source: C, boot_epoch: u64, window_span: Duration) -> Self {
        Self {
            source,
            epoch: boot_epoch,
            last: None,
            window: VecDeque::new(),
            window_span,
        }
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sample the counter at `now` and return a fresh [`Capacity`], or `None` if
    /// the source has no reading this tick. Detects counter resets (a cumulative
    /// total that dropped) and bumps the epoch so the panel re-baselines.
    pub fn sample_at(&mut self, now: Instant) -> Option<Capacity> {
        let sample = self.source.read()?;
        let total = sample.tx_bytes_total.saturating_add(sample.rx_bytes_total);

        // Reset detection: a cumulative counter that went DOWN means the
        // underlying source reset (tool restarted / NIC counter wrapped). Bump
        // the epoch and clear the throughput window so we never emit a negative
        // or fabricated delta.
        if let Some(prev) = self.last {
            let prev_total = prev.tx_bytes_total.saturating_add(prev.rx_bytes_total);
            if total < prev_total {
                self.epoch = self.epoch.wrapping_add(1);
                self.window.clear();
            }
        }
        self.last = Some(sample);

        // Push the point, then evict points that are older than the window span
        // *except* keep one anchor just outside it. Keeping the most recent
        // out-of-window point means a rate is always computable from ≥2 samples
        // even when samples arrive less often than the window span (otherwise the
        // window would collapse to a single point and report 0 B/s, losing the
        // rate). The anchor is the second element while the first is stale.
        self.window.push_back(WindowPoint {
            at: now,
            total_bytes: total,
        });
        while self.window.len() > 2 {
            // front and the element after it are both older than the window →
            // the front is redundant (the next element is a closer anchor).
            let second_stale = self
                .window
                .get(1)
                .is_some_and(|p| now.duration_since(p.at) > self.window_span);
            if second_stale {
                self.window.pop_front();
            } else {
                break;
            }
        }

        let throughput_bps = self.window_throughput();

        Some(Capacity {
            counter_epoch: self.epoch,
            source: self.source.source(),
            tx_bytes_total: sample.tx_bytes_total,
            rx_bytes_total: sample.rx_bytes_total,
            throughput_bps,
        })
    }

    /// Convenience wrapper using `Instant::now()`.
    pub fn sample(&mut self) -> Option<Capacity> {
        self.sample_at(Instant::now())
    }

    /// Sliding-window bytes/sec over the retained points. Uses the oldest and
    /// newest point in the window; 0 if fewer than two points or zero span.
    fn window_throughput(&self) -> u64 {
        let (Some(front), Some(back)) = (self.window.front(), self.window.back()) else {
            return 0;
        };
        let span = back.at.duration_since(front.at);
        let secs = span.as_secs_f64();
        if secs <= 0.0 {
            return 0;
        }
        // Bytes accumulated across the window (monotonic within an epoch since a
        // reset clears the window). bytes/sec.
        let bytes = back.total_bytes.saturating_sub(front.total_bytes);
        let bps = (bytes as f64) / secs;
        bps.round() as u64
    }
}

/// A fresh counter epoch for this agent boot. Unix-millis is opaque-enough and
/// monotonic-per-boot; the contract compares epochs by EQUALITY only (any change
/// → re-baseline), never an ordering compare, so any changing value is correct.
#[must_use]
pub fn boot_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test source driven by a script of samples.
    struct ScriptSource {
        samples: std::collections::VecDeque<Option<CounterSample>>,
        tier: CapacitySource,
    }

    impl CounterSource for ScriptSource {
        fn source(&self) -> CapacitySource {
            self.tier
        }
        fn read(&mut self) -> Option<CounterSample> {
            self.samples.pop_front().flatten()
        }
    }

    fn s(tx: u64, rx: u64) -> Option<CounterSample> {
        Some(CounterSample {
            tx_bytes_total: tx,
            rx_bytes_total: rx,
        })
    }

    #[test]
    fn computes_sliding_window_throughput() {
        let src = ScriptSource {
            samples: vec![s(0, 0), s(1000, 0), s(3000, 0)].into(),
            tier: CapacitySource::ForwardBytes,
        };
        let mut col = CapacityCollector::new(src, 42, Duration::from_secs(60));
        let t0 = Instant::now();

        let c0 = col.sample_at(t0).unwrap();
        assert_eq!(c0.throughput_bps, 0, "single point → no rate yet");
        assert_eq!(c0.counter_epoch, 42);
        assert_eq!(c0.source, CapacitySource::ForwardBytes);

        // +1s, +1000 bytes total → 1000 B/s over the window.
        let c1 = col.sample_at(t0 + Duration::from_secs(1)).unwrap();
        assert_eq!(c1.throughput_bps, 1000);

        // +1s more, +2000 bytes → window now spans 2s, 3000 bytes → 1500 B/s.
        let c2 = col.sample_at(t0 + Duration::from_secs(2)).unwrap();
        assert_eq!(c2.throughput_bps, 1500);
        assert_eq!(c2.tx_bytes_total, 3000);
    }

    #[test]
    fn detects_reset_and_bumps_epoch() {
        let src = ScriptSource {
            samples: vec![s(5000, 5000), s(10, 10)].into(),
            tier: CapacitySource::NicDelta,
        };
        let mut col = CapacityCollector::new(src, 100, Duration::from_secs(60));
        let t0 = Instant::now();

        let c0 = col.sample_at(t0).unwrap();
        assert_eq!(c0.counter_epoch, 100);

        // Counter dropped sharply → treated as a reset → epoch bumped, window cleared.
        let c1 = col.sample_at(t0 + Duration::from_secs(1)).unwrap();
        assert_eq!(c1.counter_epoch, 101, "reset must bump the epoch");
        assert_eq!(
            c1.throughput_bps, 0,
            "window cleared on reset → no fabricated rate"
        );
        assert_eq!(c1.tx_bytes_total, 10);
    }

    #[test]
    fn old_points_evicted_from_window() {
        let src = ScriptSource {
            samples: vec![s(0, 0), s(1000, 0), s(2000, 0)].into(),
            tier: CapacitySource::ForwardBytes,
        };
        let mut col = CapacityCollector::new(src, 1, Duration::from_secs(1));
        let t0 = Instant::now();
        col.sample_at(t0).unwrap();
        col.sample_at(t0 + Duration::from_secs(1)).unwrap();
        // The t0 point falls out of the 1s window and is evicted; the t0+1s
        // point is kept as the anchor. Window spans [t+1s, t+3s] = 2s,
        // bytes 2000-1000 = 1000 → 500 B/s (a single point would have lost the rate).
        let c = col.sample_at(t0 + Duration::from_secs(3)).unwrap();
        assert_eq!(c.throughput_bps, 500);
    }

    #[test]
    fn missing_reading_yields_none() {
        let src = ScriptSource {
            samples: vec![None, s(1, 1)].into(),
            tier: CapacitySource::NicDelta,
        };
        let mut col = CapacityCollector::new(src, 1, Duration::from_secs(60));
        assert!(col.sample().is_none(), "no reading → no report this tick");
        assert!(col.sample().is_some());
    }

    #[test]
    fn parse_proc_net_dev_sums_non_loopback() {
        let text = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo:  123456     100    0    0    0     0          0         0   123456     100
  eth0: 1000        10    0    0    0     0          0         0   2000        20
  eth1:  500         5    0    0    0     0          0         0    700         7
";
        let c = NicCounterSource::parse_proc_net_dev(text);
        // lo excluded; rx = 1000+500, tx = 2000+700.
        assert_eq!(c.rx_bytes_total, 1500);
        assert_eq!(c.tx_bytes_total, 2700);
    }

    #[test]
    fn boot_epoch_is_nonzero() {
        assert!(boot_epoch() > 0);
    }
}
