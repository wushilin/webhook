use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, Request,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use named_queue::{QueueRegistry, Receiver, Sender};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio_util::io::ReaderStream;
use tracing::{info, warn};

use crate::{admin, config, models::RequestMeta, AppState};

const QUEUE_NAME: &str = "requests";
const BODY_FILE_SUFFIXES: [&str; 2] = [".body.bin", ".body.bin.gz"];

/// One captured request, serialized once and shared by every consumer.
#[derive(Clone)]
pub struct StreamEvent {
    path: Arc<str>,
    json: Arc<str>,
}

#[derive(Serialize)]
struct StreamPayload<'a> {
    #[serde(flatten)]
    meta: &'a RequestMeta,
    /// Where to fetch the stored body, or null when no body file was written.
    body_url: Option<String>,
}

/// Broadcasting queue fan-out: every websocket consumer holds its own
/// subscription, so consumers progress independently of each other.
pub struct StreamHub {
    registry: QueueRegistry,
    sender: Sender<StreamEvent>,
    admin_prefix: String,
}

impl StreamHub {
    pub fn new(config: &config::Config) -> anyhow::Result<Self> {
        let registry = QueueRegistry::new();
        registry
            .create_broadcasting::<StreamEvent>(QUEUE_NAME, config.stream.buffer)
            .map_err(|err| anyhow::anyhow!("failed to create stream queue: {err:?}"))?;
        let sender = registry
            .acquire_sender::<StreamEvent>(QUEUE_NAME)
            .map_err(|err| anyhow::anyhow!("failed to acquire stream sender: {err:?}"))?;
        Ok(Self {
            registry,
            sender,
            admin_prefix: config.server.admin_prefix.trim_end_matches('/').to_string(),
        })
    }

    /// Called once the request's body file and metadata have been written.
    /// Events carry metadata only; `body_ref` (from [`body_ref`]) points at
    /// the stored body for on-demand fetching.
    pub fn publish(&self, meta: &RequestMeta, body_ref: Option<String>) {
        let payload = StreamPayload {
            meta,
            body_url: body_ref.map(|r| format!("{}/stream/body/{r}", self.admin_prefix)),
        };
        let json = match serde_json::to_string(&payload) {
            Ok(json) => json,
            Err(err) => {
                warn!(error = ?err, "failed to serialize stream event");
                return;
            }
        };
        // Broadcast sends never block; with no consumers the event is dropped.
        let _ = self.sender.try_send(StreamEvent {
            path: meta.path.as_str().into(),
            json: json.into(),
        });
    }

    fn subscribe(&self) -> Option<Receiver<StreamEvent>> {
        self.registry.acquire_receiver(QUEUE_NAME).ok()
    }

    /// Closes the queue so open websockets end and do not hold up shutdown.
    pub fn shutdown(&self) {
        let _ = self.registry.shutdown(QUEUE_NAME);
    }
}

/// URL-safe reference to a body file: its path relative to the storage root.
pub fn body_ref(root: &Path, body_path: &Path) -> Option<String> {
    let relative = body_path.strip_prefix(root).ok()?;
    Some(URL_SAFE_NO_PAD.encode(relative.to_str()?))
}

/// Inverse of [`body_ref`]. Accepts only plain relative paths that name a
/// body file, so a reference can never reach outside the storage root.
fn decode_body_ref(encoded: &str) -> Option<PathBuf> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let relative = PathBuf::from(String::from_utf8(bytes).ok()?);
    let plain = relative.components().count() > 0
        && relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
    let file_name = relative.file_name()?.to_str()?;
    let body_file = BODY_FILE_SUFFIXES
        .iter()
        .any(|suffix| file_name.len() > suffix.len() && file_name.ends_with(suffix));
    (plain && body_file).then_some(relative)
}

/// Token check shared by the websocket and the body endpoint; with no
/// `stream.token` configured everything is allowed.
fn authorize(state: &AppState, headers: &HeaderMap, query: &[(String, String)]) -> bool {
    let Some(expected) = state.config.stream.token.as_deref() else {
        return true;
    };
    bearer_token(headers)
        .or_else(|| admin::form_value(query, "token"))
        .is_some_and(|t| admin::constant_time_eq(t.as_bytes(), expected.as_bytes()))
}

pub async fn handle(state: AppState, req: Request<Body>) -> Response {
    let query = req.uri().query().map(admin::parse_form).unwrap_or_default();
    if !authorize(&state, req.headers(), &query) {
        return (StatusCode::UNAUTHORIZED, "invalid stream token\n").into_response();
    }
    let prefix = admin::form_value(&query, "prefix").and_then(|p| normalize_prefix(&p));

    let (mut parts, _body) = req.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let Some(rx) = state.stream.subscribe() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "stream is shutting down\n").into_response();
    };
    ws.on_upgrade(move |socket| consume(socket, rx, prefix))
}

/// Streams a stored body from disk, gunzipped, optionally cut to `?limit=N`
/// bytes. Served as an inert download so a captured HTML or script body can
/// never run on the admin origin.
pub async fn body(state: AppState, req: Request<Body>, encoded: &str) -> Response {
    let query = req.uri().query().map(admin::parse_form).unwrap_or_default();
    if !authorize(&state, req.headers(), &query) {
        return (StatusCode::UNAUTHORIZED, "invalid stream token\n").into_response();
    }
    let Some(relative) = decode_body_ref(encoded) else {
        return (StatusCode::NOT_FOUND, "unknown body reference\n").into_response();
    };
    let limit = match admin::form_value(&query, "limit") {
        None => u64::MAX,
        Some(raw) => match raw.parse::<u64>() {
            Ok(limit) => limit,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid limit\n").into_response(),
        },
    };

    let path = state.storage.root().join(&relative);
    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return (StatusCode::NOT_FOUND, "body is no longer stored\n").into_response();
        }
        Err(err) => {
            warn!(error = ?err, path = %path.display(), "failed to open body file");
            return (StatusCode::INTERNAL_SERVER_ERROR, "failed to open body\n").into_response();
        }
    };
    let reader: Box<dyn AsyncRead + Send + Unpin> = if path.extension() == Some("gz".as_ref()) {
        Box::new(async_compression::tokio::bufread::GzipDecoder::new(
            BufReader::new(file),
        ))
    } else {
        Box::new(file)
    };

    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CONTENT_SECURITY_POLICY, "sandbox")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(ReaderStream::new(reader.take(limit))))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `asdf` and ` /asdf ` both mean `/asdf`; paths always start with `/`.
fn normalize_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.starts_with('/') {
        Some(trimmed.to_string())
    } else {
        Some(format!("/{trimmed}"))
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
}

async fn consume(mut socket: WebSocket, rx: Receiver<StreamEvent>, prefix: Option<String>) {
    info!(prefix = ?prefix, "stream consumer connected");
    loop {
        tokio::select! {
            event = rx.recv_async() => match event {
                Ok(event) => {
                    if prefix
                        .as_deref()
                        .is_some_and(|prefix| !event.path.starts_with(prefix))
                    {
                        continue;
                    }
                    if socket.send(Message::Text(event.json.to_string())).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            },
            // Pings are answered by axum; anything else from the client is ignored.
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
    info!("stream consumer disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_gets_leading_slash_and_blank_means_all() {
        assert_eq!(normalize_prefix("/asdf").as_deref(), Some("/asdf"));
        assert_eq!(normalize_prefix(" asdf ").as_deref(), Some("/asdf"));
        assert_eq!(normalize_prefix("  "), None);
    }

    #[test]
    fn body_ref_round_trips_and_rejects_escapes() {
        let root = Path::new("./data");
        let body = root.join("api/2026/10/12/22/00/45/45_1_host_x.body.bin.gz");
        let encoded = body_ref(root, &body).unwrap();
        assert_eq!(
            decode_body_ref(&encoded).unwrap(),
            PathBuf::from("api/2026/10/12/22/00/45/45_1_host_x.body.bin.gz")
        );

        let encode = |p: &str| URL_SAFE_NO_PAD.encode(p);
        assert!(decode_body_ref(&encode("../etc/x.body.bin")).is_none());
        assert!(decode_body_ref(&encode("/etc/x.body.bin")).is_none());
        assert!(decode_body_ref(&encode("a/b/meta.json")).is_none());
        assert!(decode_body_ref(&encode(".body.bin")).is_none());
        assert!(decode_body_ref("not base64!").is_none());
    }
}
