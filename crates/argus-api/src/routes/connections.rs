use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;
use argus_common::types::ConnectionState;

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub state: String,
}

pub async fn list_connections(State(state): State<Arc<AppState>>) -> Json<Vec<ConnectionResponse>> {
    let entries = state.connection_tracker.list_all();
    let resp: Vec<ConnectionResponse> = entries
        .into_iter()
        .map(|e| {
            let state_str = match e.state {
                ConnectionState::New => "new",
                ConnectionState::Established => "established",
                ConnectionState::Closing => "closing",
                ConnectionState::Closed => "closed",
            };
            ConnectionResponse {
                src_ip: e.src_ip.to_string(),
                dst_ip: e.dst_ip.to_string(),
                src_port: e.src_port,
                dst_port: e.dst_port,
                protocol: e.protocol,
                state: state_str.into(),
            }
        })
        .collect();
    Json(resp)
}
