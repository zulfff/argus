use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::instrument;

pub struct TokenBucket {
    pub tokens: f64,
    pub max_tokens: f64,
    pub refill_rate: f64,
    pub last_refill: DateTime<Utc>,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    default_max_tokens: f64,
    default_refill_rate: f64,
}

impl RateLimiter {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            default_max_tokens: max_tokens,
            default_refill_rate: refill_rate,
        }
    }

    #[instrument(skip(self))]
    pub fn check_and_consume(&self, ip: IpAddr, cost: f64) -> bool {
        let now = Utc::now();
        let mut buckets = match self.buckets.lock() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let bucket = buckets.entry(ip).or_insert(TokenBucket {
            tokens: self.default_max_tokens,
            max_tokens: self.default_max_tokens,
            refill_rate: self.default_refill_rate,
            last_refill: now,
        });

        let elapsed = (now - bucket.last_refill).num_seconds() as f64;
        if elapsed > 0.0 {
            let refill = elapsed * bucket.refill_rate;
            bucket.tokens = (bucket.tokens + refill).min(bucket.max_tokens);
            bucket.last_refill = now;
        }

        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            true
        } else {
            false
        }
    }

    pub fn get_bucket_size(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }

    pub fn gc(&self) {
        let now = Utc::now();
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.retain(|_, b| {
                let idle = (now - b.last_refill).num_seconds();
                idle < 3600
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = RateLimiter::new(10.0, 1.0);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..10 {
            assert!(limiter.check_and_consume(ip, 1.0));
        }
        assert!(!limiter.check_and_consume(ip, 1.0));
    }

    #[test]
    fn test_refill() {
        let limiter = RateLimiter::new(5.0, 10.0);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(limiter.check_and_consume(ip, 5.0));
        assert!(!limiter.check_and_consume(ip, 1.0));
    }
}
