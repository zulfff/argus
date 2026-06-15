use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
struct LokiStream {
    stream: HashMap<String, String>,
    values: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
struct LokiPushRequest {
    streams: Vec<LokiStream>,
}

pub struct LokiClient {
    url: String,
    labels: HashMap<String, String>,
    client: reqwest::Client,
}

impl LokiClient {
    pub fn new(url: String, labels: HashMap<String, String>) -> Self {
        Self {
            url,
            labels,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build loki client"),
        }
    }

    pub async fn push_log(
        &self,
        level: &str,
        target: &str,
        message: &str,
        extra_labels: HashMap<String, String>,
    ) {
        let ts_ns = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_string();

        let mut stream_labels = self.labels.clone();
        stream_labels.insert("level".into(), level.to_string());
        stream_labels.insert("target".into(), target.to_string());
        for (k, v) in extra_labels {
            stream_labels.insert(k, v);
        }

        let stream = LokiStream {
            stream: stream_labels,
            values: vec![(ts_ns, message.to_string())],
        };

        let request = LokiPushRequest {
            streams: vec![stream],
        };

        let _ = self.client.post(&self.url).json(&request).send().await;
    }

    pub async fn push_event(&self, event_type: &str, data: &str) {
        let mut labels = HashMap::new();
        labels.insert("event_type".into(), event_type.to_string());
        self.push_log("info", "event", data, labels).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loki_stream_serialization() {
        let stream = LokiStream {
            stream: HashMap::from([
                ("job".into(), "argus".into()),
                ("level".into(), "info".into()),
            ]),
            values: vec![("1234567890000000".into(), "test log message".into())],
        };

        let json = serde_json::to_string(&stream).unwrap();
        assert!(json.contains("argus"));
        assert!(json.contains("test log message"));
    }

    #[test]
    fn test_loki_push_request_structure() {
        let request = LokiPushRequest {
            streams: vec![LokiStream {
                stream: HashMap::from([("job".into(), "argus".into())]),
                values: vec![("0".into(), "msg".into())],
            }],
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"streams\""));
        assert!(json.contains("\"stream\""));
    }
}
