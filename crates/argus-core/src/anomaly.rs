use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use tracing::instrument;

const BASELINE_WINDOW_MINUTES: i64 = 60;
const ANOMALY_THRESHOLD_MULTIPLIER: f64 = 3.0;

#[derive(Debug, Clone)]
pub struct TrafficSample {
    pub timestamp: DateTime<Utc>,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub connection_count: u64,
    pub unique_ports: usize,
}

#[derive(Debug, Clone)]
pub struct Baseline {
    pub mean_pps: f64,
    pub stddev_pps: f64,
    pub mean_bps: f64,
    pub stddev_bps: f64,
    pub mean_connections: f64,
    pub stddev_connections: f64,
    pub sample_count: usize,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AnomalyAlert {
    pub interface: String,
    pub metric: String,
    pub current_value: f64,
    pub expected_range: (f64, f64),
    pub deviation_multiple: f64,
    pub severity: AnomalySeverity,
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum AnomalySeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

pub struct AnomalyDetector {
    samples: Mutex<HashMap<String, VecDeque<TrafficSample>>>,
    baselines: Mutex<HashMap<String, Baseline>>,
    history: Mutex<VecDeque<AnomalyAlert>>,
    max_history: usize,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            samples: Mutex::new(HashMap::new()),
            baselines: Mutex::new(HashMap::new()),
            history: Mutex::new(VecDeque::with_capacity(1000)),
            max_history: 1000,
        }
    }

    #[instrument(skip(self))]
    pub fn record_sample(&self, interface: &str, sample: TrafficSample) {
        let mut samples = match self.samples.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        let entry = samples
            .entry(interface.to_string())
            .or_insert_with(|| VecDeque::with_capacity(3600));

        entry.push_back(sample);

        let cutoff = Utc::now() - chrono::Duration::minutes(BASELINE_WINDOW_MINUTES);
        while entry.front().is_some_and(|s| s.timestamp < cutoff) {
            entry.pop_front();
        }
    }

    #[instrument(skip(self))]
    pub fn compute_baseline(&self, interface: &str) -> Option<Baseline> {
        let samples = match self.samples.lock() {
            Ok(s) => s,
            Err(_) => return None,
        };

        let entry = samples.get(interface)?;
        if entry.len() < 10 {
            return None;
        }

        let n = entry.len() as f64;
        let sum_pps: f64 = entry.iter().map(|s| s.packets_per_second).sum();
        let sum_bps: f64 = entry.iter().map(|s| s.bytes_per_second).sum();
        let sum_conns: f64 = entry.iter().map(|s| s.connection_count as f64).sum();

        let mean_pps = sum_pps / n;
        let mean_bps = sum_bps / n;
        let mean_conns = sum_conns / n;

        let var_pps = entry
            .iter()
            .map(|s| (s.packets_per_second - mean_pps).powi(2))
            .sum::<f64>()
            / n;
        let var_bps = entry
            .iter()
            .map(|s| (s.bytes_per_second - mean_bps).powi(2))
            .sum::<f64>()
            / n;
        let var_conns = entry
            .iter()
            .map(|s| (s.connection_count as f64 - mean_conns).powi(2))
            .sum::<f64>()
            / n;

        let baseline = Baseline {
            mean_pps,
            stddev_pps: var_pps.sqrt(),
            mean_bps,
            stddev_bps: var_bps.sqrt(),
            mean_connections: mean_conns,
            stddev_connections: var_conns.sqrt(),
            sample_count: entry.len(),
            last_updated: Utc::now(),
        };

        let mut baselines = self.baselines.lock().ok()?;
        baselines.insert(interface.to_string(), baseline.clone());

        Some(baseline)
    }

    #[instrument(skip(self))]
    pub fn check_anomalies(&self, interface: &str, current: &TrafficSample) -> Vec<AnomalyAlert> {
        let baselines = match self.baselines.lock() {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let baseline = match baselines.get(interface) {
            Some(b) => b.clone(),
            None => return Vec::new(),
        };

        let mut alerts = Vec::new();

        let pps_deviation = if baseline.stddev_pps > 0.0 {
            (current.packets_per_second - baseline.mean_pps).abs() / baseline.stddev_pps
        } else {
            0.0
        };

        if pps_deviation > ANOMALY_THRESHOLD_MULTIPLIER {
            let severity = if pps_deviation > 10.0 {
                AnomalySeverity::Critical
            } else if pps_deviation > 5.0 {
                AnomalySeverity::Warning
            } else {
                AnomalySeverity::Info
            };

            alerts.push(AnomalyAlert {
                interface: interface.to_string(),
                metric: "packets_per_second".into(),
                current_value: current.packets_per_second,
                expected_range: (
                    baseline.mean_pps - baseline.stddev_pps,
                    baseline.mean_pps + baseline.stddev_pps,
                ),
                deviation_multiple: pps_deviation,
                severity,
                timestamp: Utc::now(),
                description: format!(
                    "PPS spike: {:.0} (baseline mean: {:.0}, stddev: {:.0})",
                    current.packets_per_second, baseline.mean_pps, baseline.stddev_pps,
                ),
            });
        }

        let conn_deviation = if baseline.stddev_connections > 0.0 {
            (current.connection_count as f64 - baseline.mean_connections).abs()
                / baseline.stddev_connections
        } else {
            0.0
        };

        if conn_deviation > ANOMALY_THRESHOLD_MULTIPLIER {
            alerts.push(AnomalyAlert {
                interface: interface.to_string(),
                metric: "connection_count".into(),
                current_value: current.connection_count as f64,
                expected_range: (
                    baseline.mean_connections - baseline.stddev_connections,
                    baseline.mean_connections + baseline.stddev_connections,
                ),
                deviation_multiple: conn_deviation,
                severity: AnomalySeverity::Warning,
                timestamp: Utc::now(),
                description: format!(
                    "Connection spike: {} (baseline: {:.0} ± {:.0})",
                    current.connection_count,
                    baseline.mean_connections,
                    baseline.stddev_connections,
                ),
            });
        }

        if let Ok(mut history) = self.history.lock() {
            for alert in &alerts {
                history.push_back(alert.clone());
                if history.len() > self.max_history {
                    history.pop_front();
                }
            }
        }

        alerts
    }

    pub fn get_baseline(&self, interface: &str) -> Option<Baseline> {
        self.baselines.lock().ok()?.get(interface).cloned()
    }

    pub fn get_recent_alerts(&self, limit: usize) -> Vec<AnomalyAlert> {
        self.history
            .lock()
            .map(|h| h.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    pub fn gc(&self) {
        let cutoff = Utc::now() - chrono::Duration::minutes(BASELINE_WINDOW_MINUTES * 2);
        if let Ok(mut samples) = self.samples.lock() {
            for entry in samples.values_mut() {
                while entry.front().is_some_and(|s| s.timestamp < cutoff) {
                    entry.pop_front();
                }
            }
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_computation() {
        let detector = AnomalyDetector::new();
        let now = Utc::now();

        for i in 0..30 {
            detector.record_sample(
                "eth0",
                TrafficSample {
                    timestamp: now - chrono::Duration::seconds(i * 5),
                    packets_per_second: 1000.0 + (i as f64 * 10.0),
                    bytes_per_second: 1_000_000.0,
                    connection_count: 50,
                    unique_ports: 10,
                },
            );
        }

        let baseline = detector.compute_baseline("eth0");
        assert!(baseline.is_some());
        let b = baseline.unwrap();
        assert!(b.mean_pps > 1000.0);
        assert!(b.mean_pps < 2000.0);
        assert_eq!(b.sample_count, 30);
    }

    #[test]
    fn test_anomaly_detection() {
        let detector = AnomalyDetector::new();
        let now = Utc::now();

        for i in 0..30 {
            detector.record_sample(
                "eth0",
                TrafficSample {
                    timestamp: now - chrono::Duration::seconds(i * 2),
                    packets_per_second: 1000.0 + (i as f64 - 15.0).abs() * 5.0,
                    bytes_per_second: 1_000_000.0,
                    connection_count: 50,
                    unique_ports: 10,
                },
            );
        }

        detector.compute_baseline("eth0");

        let spike = TrafficSample {
            timestamp: now,
            packets_per_second: 50000.0,
            bytes_per_second: 50_000_000.0,
            connection_count: 500,
            unique_ports: 50,
        };

        let alerts = detector.check_anomalies("eth0", &spike);
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_no_anomaly_on_normal_traffic() {
        let detector = AnomalyDetector::new();
        let now = Utc::now();

        for i in 0..30 {
            detector.record_sample(
                "eth0",
                TrafficSample {
                    timestamp: now - chrono::Duration::seconds(i * 2),
                    packets_per_second: 1000.0 + (i as f64 * 2.0),
                    bytes_per_second: 1_000_000.0,
                    connection_count: 50,
                    unique_ports: 10,
                },
            );
        }

        detector.compute_baseline("eth0");

        let normal = TrafficSample {
            timestamp: now,
            packets_per_second: 1050.0,
            bytes_per_second: 1_050_000.0,
            connection_count: 52,
            unique_ports: 11,
        };

        let alerts = detector.check_anomalies("eth0", &normal);
        assert!(alerts.is_empty());
    }
}
