//! Status-report assembly (Line B task 3 / 3b).
//!
//! Collects the agent's current view — forwarding liveness, backend
//! reachability, applied config generation, restart count, pids, and capacity
//! telemetry — into a [`contract::protocol::StatusReport`] that the conn loop
//! sends on the heartbeat interval.

use contract::protocol::{ActiveBackend, BackendHealth, Capacity, Metrics, StatusReport};

/// Inputs the conn loop has on hand when it's time to report.
pub struct ReportInputs {
    pub forwarding_up: bool,
    pub backend_reachable: bool,
    pub applied_config_gen: u64,
    pub restart_count: u32,
    pub pid: Option<u32>,
    pub capacity: Option<Capacity>,
    /// Per-replica probe results from the failover engine (None on the legacy
    /// no-rules path so older panels see the field omitted entirely).
    pub backend_health: Option<Vec<BackendHealth>>,
    /// Current active backend per rule from the failover engine (None on the
    /// legacy no-rules path).
    pub active_backends: Option<Vec<ActiveBackend>>,
}

/// Build the wire [`StatusReport`] from collected inputs. `metrics` is only
/// attached when there is something to report (a pid or a restart), keeping the
/// payload minimal otherwise (the field is optional/extensible per gap 7.5).
#[must_use]
pub fn build(inputs: ReportInputs) -> StatusReport {
    let metrics = if inputs.pid.is_some() || inputs.restart_count > 0 {
        Some(Metrics {
            gost_realm_pids: inputs.pid.map(|p| vec![p]),
            restart_count: Some(inputs.restart_count),
            ..Default::default()
        })
    } else {
        None
    };

    StatusReport {
        forwarding_up: inputs.forwarding_up,
        backend_reachable: inputs.backend_reachable,
        applied_config_gen: inputs.applied_config_gen,
        metrics,
        capacity: inputs.capacity,
        backend_health: inputs.backend_health,
        active_backends: inputs.active_backends,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::protocol::CapacitySource;

    #[test]
    fn builds_full_report_with_metrics_and_capacity() {
        let r = build(ReportInputs {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: 5,
            restart_count: 2,
            pid: Some(4321),
            capacity: Some(Capacity {
                counter_epoch: 99,
                source: CapacitySource::ForwardBytes,
                tx_bytes_total: 10,
                rx_bytes_total: 20,
                throughput_bps: 5,
            }),
            backend_health: None,
            active_backends: None,
        });
        assert!(r.forwarding_up);
        assert_eq!(r.applied_config_gen, 5);
        let m = r.metrics.expect("metrics present");
        assert_eq!(m.gost_realm_pids, Some(vec![4321]));
        assert_eq!(m.restart_count, Some(2));
        assert_eq!(r.capacity.unwrap().counter_epoch, 99);
    }

    #[test]
    fn omits_metrics_when_nothing_to_report() {
        let r = build(ReportInputs {
            forwarding_up: false,
            backend_reachable: false,
            applied_config_gen: 0,
            restart_count: 0,
            pid: None,
            capacity: None,
            backend_health: None,
            active_backends: None,
        });
        assert!(r.metrics.is_none());
        assert!(r.capacity.is_none());
    }

    #[test]
    fn passes_through_failover_health_fields() {
        use contract::protocol::{ActiveBackend, BackendHealth};
        let r = build(ReportInputs {
            forwarding_up: true,
            backend_reachable: true,
            applied_config_gen: 1,
            restart_count: 0,
            pid: None,
            capacity: None,
            backend_health: Some(vec![BackendHealth {
                host: "10.0.0.1".into(),
                port: 8096,
                reachable: false,
            }]),
            active_backends: Some(vec![ActiveBackend {
                rule_id: "r1".into(),
                host: "10.0.0.2".into(),
                port: 8096,
            }]),
        });
        assert_eq!(r.backend_health.as_ref().unwrap()[0].host, "10.0.0.1");
        assert!(!r.backend_health.as_ref().unwrap()[0].reachable);
        assert_eq!(r.active_backends.as_ref().unwrap()[0].host, "10.0.0.2");
    }
}
