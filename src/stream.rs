use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
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
use base64::Engine;
use named_queue::{QueueRegistry, Receiver, Sender};
use serde::Serialize;
use tracing::{info, warn};

use crate::{admin, config, models::RequestMeta, AppState};

const QUEUE_NAME: &str = "requests";

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
    /// Base64 of the original (uncompressed) body, at most
    /// `stream.max_body_size` bytes of it; null only when nothing was captured.
    body_base64: Option<String>,
    /// Set when `body_base64` is not the whole body; `body_truncated_reason`
    /// then says why.
    body_truncated: bool,
    body_truncated_reason: Option<&'static str>,
}

/// Broadcasting queue fan-out: every websocket consumer holds its own
/// subscription, so consumers progress independently of each other.
pub struct StreamHub {
    registry: QueueRegistry,
    sender: Sender<StreamEvent>,
    consumers: Arc<AtomicUsize>,
    max_body_size: u64,
}

/// Counts a connected consumer for as long as it lives.
struct ConsumerGuard(Arc<AtomicUsize>);

impl Drop for ConsumerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl StreamHub {
    pub fn new(config: &config::StreamConfig) -> anyhow::Result<Self> {
        let registry = QueueRegistry::new();
        registry
            .create_broadcasting::<StreamEvent>(QUEUE_NAME, config.buffer)
            .map_err(|err| anyhow::anyhow!("failed to create stream queue: {err:?}"))?;
        let sender = registry
            .acquire_sender::<StreamEvent>(QUEUE_NAME)
            .map_err(|err| anyhow::anyhow!("failed to acquire stream sender: {err:?}"))?;
        Ok(Self {
            registry,
            sender,
            consumers: Arc::new(AtomicUsize::new(0)),
            max_body_size: config.max_body_size,
        })
    }

    /// Lets capture skip buffering bodies in memory when nobody is listening.
    pub fn has_consumers(&self) -> bool {
        self.consumers.load(Ordering::Relaxed) > 0
    }

    /// Called once the request's body file and metadata have been written.
    /// `body` is the in-memory copy of the first `stream.max_body_size` bytes
    /// captured while the body was persisted.
    pub fn publish(&self, meta: &RequestMeta, body: Option<&[u8]>) {
        let truncated_reason = if meta.body.limit_exceeded {
            Some("body exceeded max_body_size")
        } else if meta.body.original_size > self.max_body_size {
            Some("body too big for streaming")
        } else if !meta.body.complete {
            Some("body incomplete")
        } else if body.is_none() {
            // A consumer connected while this request's body was in flight.
            Some("body not captured")
        } else {
            None
        };
        let payload = StreamPayload {
            meta,
            body_base64: body.map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
            body_truncated: truncated_reason.is_some(),
            body_truncated_reason: truncated_reason,
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

    fn subscribe(&self) -> Option<(Receiver<StreamEvent>, ConsumerGuard)> {
        let rx = self.registry.acquire_receiver(QUEUE_NAME).ok()?;
        self.consumers.fetch_add(1, Ordering::Relaxed);
        Some((rx, ConsumerGuard(self.consumers.clone())))
    }

    /// Closes the queue so open websockets end and do not hold up shutdown.
    pub fn shutdown(&self) {
        let _ = self.registry.shutdown(QUEUE_NAME);
    }
}

pub async fn handle(state: AppState, req: Request<Body>) -> Response {
    let hub = state.stream.clone();

    let query = req.uri().query().map(admin::parse_form).unwrap_or_default();
    if let Some(expected) = state.config.stream.token.as_deref() {
        let token = bearer_token(req.headers()).or_else(|| admin::form_value(&query, "token"));
        if !token.is_some_and(|t| admin::constant_time_eq(t.as_bytes(), expected.as_bytes())) {
            return (StatusCode::UNAUTHORIZED, "invalid stream token\n").into_response();
        }
    }
    let prefix = admin::form_value(&query, "prefix").filter(|p| !p.is_empty());

    let (mut parts, _body) = req.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let Some((rx, guard)) = hub.subscribe() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "stream is shutting down\n").into_response();
    };
    ws.on_upgrade(move |socket| async move {
        consume(socket, rx, prefix).await;
        drop(guard);
    })
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
                        .is_some_and(|prefix| !config::path_matches(&event.path, prefix))
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
