use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub id: Uuid,
    pub report_type: String,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
    pub data: serde_json::Value,
    pub summary: String,
}

pub struct ComplianceEngine {
    reports: Mutex<Vec<ComplianceReport>>,
}

impl ComplianceEngine {
    pub fn new() -> Self {
        Self {
            reports: Mutex::new(Vec::new()),
        }
    }

    pub fn generate_report(
        &self,
        report_type: &str,
        generated_by: &str,
        snapshot: &serde_json::Value,
    ) -> ComplianceReport {
        let summary = generate_summary(report_type, snapshot);
        let report = ComplianceReport {
            id: Uuid::new_v4(),
            report_type: report_type.to_string(),
            generated_at: Utc::now(),
            generated_by: generated_by.to_string(),
            data: snapshot.clone(),
            summary,
        };
        if let Ok(mut reports) = self.reports.lock() {
            reports.push(report.clone());
        }
        report
    }

    pub fn list_reports(&self, limit: usize) -> Vec<ComplianceReport> {
        self.reports
            .lock()
            .map(|r| {
                let mut all: Vec<_> = r.iter().rev().cloned().collect();
                all.truncate(limit);
                all
            })
            .unwrap_or_default()
    }

    pub fn get_report(&self, id: &Uuid) -> Option<ComplianceReport> {
        self.reports
            .lock()
            .ok()
            .and_then(|r| r.iter().find(|rep| &rep.id == id).cloned())
    }
}

impl Default for ComplianceEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_summary(report_type: &str, snapshot: &serde_json::Value) -> String {
    match report_type {
        "firewall_rules_audit" => {
            let rules = snapshot["rules"].as_array().map(|a| a.len()).unwrap_or(0);
            format!("Firewall rules audit: {} rules evaluated", rules)
        }
        "connection_summary" => {
            let total = snapshot["total_connections"].as_u64().unwrap_or(0);
            let blocked = snapshot["blocked_connections"].as_u64().unwrap_or(0);
            format!("Connection summary: {} total, {} blocked", total, blocked)
        }
        "blocked_ips" => {
            let ips = snapshot["blocked_ips"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            format!("Blocked IPs report: {} IPs blocked", ips)
        }
        "alert_summary" => {
            let alerts = snapshot["alerts"].as_array().map(|a| a.len()).unwrap_or(0);
            format!("Alert summary: {} alerts generated", alerts)
        }
        _ => format!("Report type: {}", report_type),
    }
}
