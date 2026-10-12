use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, Request,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use named_queue::{QueueRegistry, Receiver, Sender};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio_util::io::ReaderStream;
use tracing::{info, warn};

use crate::{admin, config, models::RequestMeta, AppState};

const QUEUE_NAME: &str = "requests";
/// An idle NDJSON stream sends a blank line this often so proxies keep it open.
const NDJSON_HEARTBEAT: Duration = Duration::from_secs(30);

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

    /// Called once the request's body file and envelope have been written.
    /// Events carry metadata only; `body_url` fetches the stored body.
    pub fn publish(&self, meta: &RequestMeta) {
        let payload = StreamPayload {
            meta,
            body_url: (meta.body.stored && meta.body.object.is_some())
                .then(|| format!("{}/stream/body/{}", self.admin_prefix, meta.id)),
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

/// Token check shared by the websocket and the body endpoint; with no
/// `stream.token` configured everything is allowed.
fn authorize(state: &AppState, headers: &HeaderMap, query: &[(String, String)]) -> bool {
    let Some(expected) = state.config.stream.token.as_deref() else {
        return true;
    };
    // X-Stream-Token first: it survives proxies that claim Authorization.
    header_token(headers)
        .or_else(|| bearer_token(headers))
        .or_else(|| admin::form_value(query, "token"))
        .is_some_and(|t| admin::constant_time_eq(t.as_bytes(), expected.as_bytes()))
}

pub async fn handle(state: AppState, req: Request<Body>) -> Response {
    let query = req.uri().query().map(admin::parse_form).unwrap_or_default();
    if !authorize(&state, req.headers(), &query) {
        return (StatusCode::UNAUTHORIZED, "invalid stream token\n").into_response();
    }
    let prefix = admin::form_value(&query, "prefix").and_then(|p| normalize_prefix(&p));
    let websocket = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    let Some(rx) = state.stream.subscribe() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "stream is shutting down\n").into_response();
    };
    if !websocket {
        return ndjson(rx, prefix);
    }
    let (mut parts, _body) = req.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    ws.on_upgrade(move |socket| consume(socket, rx, prefix))
}

/// The same events as plain HTTP for curl and friends: a never-ending
/// response with one JSON envelope per line. The subscription ends when the
/// client disconnects (the body stream is dropped) or the server shuts down.
fn ndjson(rx: Receiver<StreamEvent>, prefix: Option<String>) -> Response {
    let lines = futures_util::stream::unfold((rx, prefix), |(rx, prefix)| async move {
        loop {
            match tokio::time::timeout(NDJSON_HEARTBEAT, rx.recv_async()).await {
                Err(_) => {
                    return Some((Ok::<_, Infallible>(Bytes::from_static(b"\n")), (rx, prefix)))
                }
                Ok(Err(_)) => return None,
                Ok(Ok(event)) => {
                    if prefix
                        .as_deref()
                        .is_some_and(|p| !event.path.starts_with(p))
                    {
                        continue;
                    }
                    let mut line = event.json.as_bytes().to_vec();
                    line.push(b'\n');
                    return Some((Ok(Bytes::from(line)), (rx, prefix)));
                }
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-store")
        // Ask buffering reverse proxies (nginx) to pass lines through as they come.
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(lines))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `GET <admin_prefix>/stream/body/<id>`, authorised by the stream token.
pub async fn body(state: AppState, req: Request<Body>, id: &str) -> Response {
    let query = req.uri().query().map(admin::parse_form).unwrap_or_default();
    if !authorize(&state, req.headers(), &query) {
        return (StatusCode::UNAUTHORIZED, "invalid stream token\n").into_response();
    }
    serve_body(&state, id, &query).await
}

/// Streams a stored body from disk, gunzipped, optionally cut to `?limit=N`
/// bytes. Served as an inert download so a captured HTML or script body can
/// never run on the admin origin. Shared with the admin pages.
pub async fn serve_body(state: &AppState, id: &str, query: &[(String, String)]) -> Response {
    let limit = match admin::form_value(query, "limit") {
        None => u64::MAX,
        Some(raw) => match raw.parse::<u64>() {
            Ok(limit) => limit,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid limit\n").into_response(),
        },
    };
    let meta = match state.storage.get(id).await {
        Ok(Some(meta)) => meta,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown request\n").into_response(),
        Err(err) => {
            warn!(error = ?err, "failed to load request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to load request\n",
            )
                .into_response();
        }
    };
    let Some(path) = state.storage.blob_path(&meta) else {
        return (StatusCode::NOT_FOUND, "request has no stored body\n").into_response();
    };
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
    let reader: Box<dyn AsyncRead + Send + Unpin> = if meta.body.encoding.as_deref() == Some("gzip")
    {
        Box::new(async_compression::tokio::bufread::GzipDecoder::new(
            BufReader::new(file),
        ))
    } else {
        Box::new(file)
    };

    let mut response = Response::builder();
    if admin::form_value(query, "download").is_some() {
        // Ids are limited to URL- and filename-safe characters.
        response = response.header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}.body\"", meta.id),
        );
    }
    response
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

fn header_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-stream-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
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
}
