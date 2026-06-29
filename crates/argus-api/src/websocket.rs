use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
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

    pub fn publish_connection(&self, src_ip: &str, dst_ip: &str, state: &str) {
        let event = LiveEvent {
            event_type: "connection".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: serde_json::json!({
                "src_ip": src_ip, "dst_ip": dst_ip, "state": state,
            }),
        };
        self.publish(event);
    }

    pub fn publish_alert(&self, alert_type: &str, message: &str, severity: &str) {
        let event = LiveEvent {
            event_type: "alert".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: serde_json::json!({
                "type": alert_type, "message": message, "severity": severity,
            }),
        };
        self.publish(event);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<WsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Validate WebSocket origin to prevent Cross-Site WebSocket Hijacking
    if let Some(origin) = headers.get(header::ORIGIN) {
        if let Ok(origin_str) = origin.to_str() {
            if let Ok(allowed) = std::env::var("ARGUS_ALLOWED_ORIGINS") {
                let allowed_origins: Vec<&str> = allowed
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !allowed_origins.is_empty() && !allowed_origins.contains(&origin_str) {
                    return Err((StatusCode::FORBIDDEN, "WebSocket origin not allowed".into()));
                }
            } else if std::env::var("ARGUS_PRODUCTION").is_ok() {
                return Err((
                    StatusCode::FORBIDDEN,
                    "WebSocket origin must be validated in production. Set ARGUS_ALLOWED_ORIGINS."
                        .into(),
                ));
            }
        }
    }

    let token = if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        let auth_str = auth_header.to_str().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid Authorization header".into(),
            )
        })?;
        if let Some(bearer_token) = auth_str.strip_prefix("Bearer ") {
            bearer_token.to_string()
        } else {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Authorization header must use Bearer scheme".into(),
            ));
        }
    } else if let Some(ws_protocol) = headers.get(header::SEC_WEBSOCKET_PROTOCOL) {
        let protocol_str = ws_protocol.to_str().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid Sec-WebSocket-Protocol header".into(),
            )
        })?;
        let parts: Vec<&str> = protocol_str.split(',').map(|s| s.trim()).collect();
        if parts.len() == 2 && parts[0] == "bearer" {
            parts[1].to_string()
        } else {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Sec-WebSocket-Protocol must be 'bearer, <token>'".into(),
            ));
        }
    } else if let Some(token) = query.token {
        warn!(
            "WebSocket using DEPRECATED query string authentication (tokens exposed in logs/history). \
             Use Sec-WebSocket-Protocol header instead. Query string auth will be removed in v2.0."
        );
        if std::env::var("ARGUS_PRODUCTION").is_ok() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Query string authentication disabled in production mode. Use Sec-WebSocket-Protocol header.".into(),
            ));
        }
        token
    } else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Missing token in Authorization or Sec-WebSocket-Protocol header".into(),
        ));
    };

    let jwt = &state.auth_config.jwt_auth;
    let _claims = jwt
        .validate_access_token(&token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e)))?;

    let event_bus = state.event_bus.subscribe();
    Ok(ws
        .protocols(["bearer"])
        .on_upgrade(move |socket| handle_ws(socket, event_bus)))
}

async fn handle_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<LiveEvent>) {
    let mut lag_count = 0u32;
    let max_lag_before_disconnect: u32 = 3;
    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        if let Ok(json) = serde_json::to_string(&ev) {
                            if socket.send(Message::Text(json)).await.is_err() {
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
                        lag_count += 1;
                        warn!("WebSocket client lagged by {} messages (strike {}/{})", n, lag_count, max_lag_before_disconnect);
                        if lag_count >= max_lag_before_disconnect {
                            warn!("WebSocket client disconnected after {} lag events", lag_count);
                            break;
                        }
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
