use prometheus::{register_int_counter_vec, register_int_gauge_vec, IntCounterVec, IntGaugeVec};

pub struct ArgusMetrics {
    pub packets_allowed: IntCounterVec,
    pub packets_dropped: IntCounterVec,
    pub packets_rate_limited: IntCounterVec,
    pub active_connections: IntGaugeVec,
    pub blocked_ips: IntGaugeVec,
    pub rule_hit_count: IntCounterVec,
}

impl ArgusMetrics {
    pub fn new() -> Self {
        Self {
            packets_allowed: register_int_counter_vec!(
                "argus_packets_allowed_total",
                "Total packets allowed",
                &["interface", "cpu"]
            )
            .expect("packets_allowed metric"),
            packets_dropped: register_int_counter_vec!(
                "argus_packets_dropped_total",
                "Total packets dropped",
                &["interface", "reason"]
            )
            .expect("packets_dropped metric"),
            packets_rate_limited: register_int_counter_vec!(
                "argus_packets_rate_limited_total",
                "Total packets rate limited",
                &["interface"]
            )
            .expect("packets_rate_limited metric"),
            active_connections: register_int_gauge_vec!(
                "argus_active_connections",
                "Active connections",
                &["state"]
            )
            .expect("active_connections metric"),
            blocked_ips: register_int_gauge_vec!(
                "argus_blocked_ips",
                "Number of blocked IPs",
                &["reason"]
            )
            .expect("blocked_ips metric"),
            rule_hit_count: register_int_counter_vec!(
                "argus_rule_hits_total",
                "Rule hit counts",
                &["rule_id", "rule_name"]
            )
            .expect("rule_hit_count metric"),
        }
    }
}

impl Default for ArgusMetrics {
    fn default() -> Self {
        Self::new()
    }
}
