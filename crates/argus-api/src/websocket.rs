use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::SinkExt;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct LiveEvent {
    pub event_type: String,
    pub timestamp: String,
    pub data: serde_json::Value,
}

#[derive(Clone)]
pub struct LiveEventBus {
    tx: broadcast::Sender<LiveEvent>,
}

impl LiveEventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn publish(&self, event: LiveEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LiveEvent> {
        self.tx.subscribe()
    }

    pub fn publish_stats(
        &self,
        packets_allowed: u64,
        packets_dropped: u64,
        active_connections: usize,
        blocked_ips: usize,
    ) {
        let event = LiveEvent {
            event_type: "stats".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: serde_json::json!({
                "packets_allowed": packets_allowed,
                "packets_dropped": packets_dropped,
                "active_connections": active_connections,
                "blocked_ips": blocked_ips,
            }),
        };
        self.publish(event);
    }

    pub fn publish_connection(
        &self,
        src_ip: &str,
        dst_ip: &str,
        state: &str,
    ) {
        let event = LiveEvent {
            event_type: "connection".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: serde_json::json!({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "state": state,
            }),
        };
        self.publish(event);
    }

    pub fn publish_alert(
        &self,
        alert_type: &str,
        message: &str,
        severity: &str,
    ) {
        let event = LiveEvent {
            event_type: "alert".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: serde_json::json!({
                "type": alert_type,
                "message": message,
                "severity": severity,
            }),
        };
        self.publish(event);
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let event_bus = state.event_bus.subscribe();
    ws.on_upgrade(move |socket| handle_ws(socket, event_bus))
}

async fn handle_ws(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<LiveEvent>,
) {
    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        if let Ok(json) = serde_json::to_string(&ev) {
                            if socket.send(Message::Text(json.into())).await.is_err() {
                                debug!("WebSocket client disconnected");
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("Event bus closed, closing WebSocket");
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("WebSocket client lagged by {} messages", n);
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("WebSocket client sent close");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
