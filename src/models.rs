use chrono::Local;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMeta {
    pub id: String,
    pub received_at: chrono::DateTime<Local>,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: serde_json::Map<String, serde_json::Value>,
    pub body: BodyMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyMeta {
    pub stored: bool,
    pub complete: bool,
    pub mode: String,
    pub object: Option<String>,
    pub encoding: Option<String>,
    pub original_size: u64,
    pub stored_size: u64,
    pub content_type: Option<String>,
    pub previewable: bool,
    pub limit_exceeded: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResponse {
    pub success: bool,
    pub id: String,
    pub complete: bool,
    pub body_stored: bool,
    pub total_bytes_in: u64,
    pub body_length: u64,
    pub stored_body_length: u64,
    pub header_length: u64,
    pub limit_exceeded: bool,
    pub metadata_saved: bool,
    pub error: Option<String>,
}
