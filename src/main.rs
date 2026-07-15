mod admin;
mod config;
mod models;
mod storage;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{bail, Context};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use chrono::Local;
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use models::{BodyMeta, CaptureResponse, RequestMeta};
use rand::{distributions::Alphanumeric, Rng};
use storage::{LocalStorage, StoredRequestPaths};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, env = "WEBHOOK_CONFIG", default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Prompt for a password and print its bcrypt hash for admin.password
    Genpassword,
    /// Check whether a plaintext password matches a stored (bcrypt or plaintext) password
    Verifypassword,
}

#[derive(Clone)]
pub struct AppState {
    config: Arc<config::Config>,
    storage: Arc<LocalStorage>,
    hostname: Arc<String>,
    sessions: Arc<admin::Sessions>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();
    match args.command {
        Some(Command::Genpassword) => return genpassword(),
        Some(Command::Verifypassword) => return verifypassword(),
        None => {}
    }

    let config = Arc::new(config::Config::load_or_default(&args.config)?);
    config.validate()?;

    match config.admin.password.as_deref() {
        None => warn!("admin.password is not configured; the admin UI requires no login"),
        Some(password) if !password.starts_with("$2") => {
            warn!("admin.password is plaintext; generate a bcrypt hash with the genpassword subcommand")
        }
        Some(_) => {}
    }

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());

    let storage = Arc::new(LocalStorage::new(config.storage.root.clone()));
    storage.ensure_root().await?;

    let state = AppState {
        config: config.clone(),
        storage: storage.clone(),
        hostname: Arc::new(sanitize_token(&hostname)),
        sessions: Arc::new(admin::Sessions::new()),
    };

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        retention_worker(cleanup_state).await;
    });

    let app = build_app(state);

    let addr: SocketAddr = config.server.bind.parse().context("invalid server.bind")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "webhook listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/", any(capture_request))
        .route("/*path", any(capture_request))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl-c");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to listen for terminate")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn retention_worker(state: AppState) {
    let mut interval = tokio::time::interval(state.config.retention.cleanup_interval);
    loop {
        interval.tick().await;
        if let Err(err) = state.storage.cleanup_expired(&state.config).await {
            warn!(error = ?err, "retention cleanup failed");
        }
    }
}

async fn capture_request(State(state): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    let admin_prefix = state.config.server.admin_prefix.trim_end_matches('/');
    let path = req.uri().path();
    if path == admin_prefix || path.starts_with(&format!("{admin_prefix}/")) {
        return admin::handle_admin(state, req).await.into_response();
    }

    match capture_request_inner(state, req).await {
        Ok(response) => response,
        Err(err) => {
            error!(error = ?err, "request capture failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist request metadata\n".to_string(),
            )
                .into_response()
        }
    }
}

async fn capture_request_inner(state: AppState, req: Request<Body>) -> anyhow::Result<Response> {
    let received_at = Local::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let content_length = parse_content_length(&headers);
    let header_length = approximate_header_length(method.as_str(), &uri, &headers);
    let path = uri.path().to_string();
    let rule = state.config.rule_for_path(&path);

    if let Some(len) = content_length {
        if len > rule.max_body_size {
            let id = request_id(received_at, &state.hostname);
            let paths = state
                .storage
                .paths_for(&path, received_at, &id, rule.body_mode);
            let meta = build_meta(
                &id,
                received_at,
                method.as_str(),
                &uri,
                &headers,
                BodyMeta {
                    stored: false,
                    complete: false,
                    mode: rule.body_mode.to_string(),
                    object: None,
                    encoding: None,
                    original_size: 0,
                    stored_size: 0,
                    content_type: content_type(&headers),
                    previewable: false,
                    limit_exceeded: true,
                    error: Some(format!(
                        "content-length {} exceeds configured max_body_size {}",
                        len, rule.max_body_size
                    )),
                },
            );
            state
                .storage
                .write_meta_with_expiry(&paths, &meta, expires_at(received_at, rule.ttl))
                .await?;
            let capture_response = CaptureResponse {
                success: false,
                id,
                complete: false,
                body_stored: false,
                total_bytes_in: header_length,
                body_length: 0,
                stored_body_length: 0,
                header_length,
                limit_exceeded: true,
                metadata_saved: true,
                error: meta.body.error.clone(),
            };
            return Ok(metadata_json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &capture_response,
            ));
        }
    }

    let id = request_id(received_at, &state.hostname);
    let paths = state
        .storage
        .paths_for(&path, received_at, &id, rule.body_mode);
    let body_meta = stream_body(&state.storage, req.into_body(), &paths, &headers, &rule).await;

    let status = if body_meta.limit_exceeded {
        StatusCode::PAYLOAD_TOO_LARGE
    } else if body_meta.complete {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    let capture_response = CaptureResponse {
        success: body_meta.complete && !body_meta.limit_exceeded,
        id: id.clone(),
        complete: body_meta.complete,
        body_stored: body_meta.stored,
        total_bytes_in: header_length.saturating_add(body_meta.original_size),
        body_length: body_meta.original_size,
        stored_body_length: body_meta.stored_size,
        header_length,
        limit_exceeded: body_meta.limit_exceeded,
        metadata_saved: true,
        error: body_meta.error.clone(),
    };

    let meta = build_meta(&id, received_at, method.as_str(), &uri, &headers, body_meta);
    state
        .storage
        .write_meta_with_expiry(&paths, &meta, expires_at(received_at, rule.ttl))
        .await?;

    if capture_response.success {
        let responder = state.config.responder_for_path(&path);
        Ok(build_capture_response(responder, &capture_response))
    } else {
        Ok(metadata_json_response(status, &capture_response))
    }
}

fn build_capture_response(
    responder: config::ResolvedResponder,
    capture_response: &CaptureResponse,
) -> Response {
    let status = StatusCode::from_u16(responder.status).unwrap_or(StatusCode::OK);
    let (mut response, default_content_type): (Response, Option<&str>) = match responder.body {
        config::ResponderBody::StaticText(body) => {
            (body.into_response(), Some("text/plain; charset=utf-8"))
        }
        config::ResponderBody::StaticJson(body) => (
            serde_json::to_string(&body)
                .unwrap_or_else(|_| "{}".to_string())
                .into_response(),
            Some("application/json; charset=utf-8"),
        ),
        config::ResponderBody::MetadataJson => (
            serde_json::to_string(capture_response)
                .unwrap_or_else(|_| r#"{"success":false}"#.to_string())
                .into_response(),
            Some("application/json; charset=utf-8"),
        ),
    };
    *response.status_mut() = status;

    if let Some(content_type) = default_content_type {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    for (name, value) in responder.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn metadata_json_response(status: StatusCode, capture_response: &CaptureResponse) -> Response {
    let responder = config::ResolvedResponder {
        status: status.as_u16(),
        headers: config::ResponderConfig::default().headers,
        body: config::ResponderBody::MetadataJson,
    };
    build_capture_response(responder, capture_response)
}

async fn stream_body(
    storage: &LocalStorage,
    body: Body,
    paths: &StoredRequestPaths,
    headers: &HeaderMap,
    rule: &config::ResolvedPathRule,
) -> BodyMeta {
    if matches!(rule.body_mode, config::BodyMode::MetadataOnly) {
        let mut stream = body.into_data_stream();
        let mut original_size = 0u64;
        let mut complete = true;
        let mut limit_exceeded = false;
        let mut error = None;

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    original_size = original_size.saturating_add(bytes.len() as u64);
                    if original_size > rule.max_body_size {
                        complete = false;
                        limit_exceeded = true;
                        error = Some(format!(
                            "streamed body exceeded configured max_body_size {}",
                            rule.max_body_size
                        ));
                        break;
                    }
                }
                Err(err) => {
                    complete = false;
                    error = Some(format!("request body stream failed: {err}"));
                    break;
                }
            }
        }

        return BodyMeta {
            stored: false,
            complete,
            mode: rule.body_mode.to_string(),
            object: None,
            encoding: None,
            original_size,
            stored_size: 0,
            content_type: content_type(headers),
            previewable: false,
            limit_exceeded,
            error,
        };
    }

    let file = match storage.create_body_file(paths).await {
        Ok(file) => file,
        Err(err) => {
            return BodyMeta {
                stored: false,
                complete: false,
                mode: rule.body_mode.to_string(),
                object: paths.body_file_name(),
                encoding: rule.body_mode.encoding().map(ToString::to_string),
                original_size: 0,
                stored_size: 0,
                content_type: content_type(headers),
                previewable: false,
                limit_exceeded: false,
                error: Some(format!("failed to create body file: {err}")),
            };
        }
    };

    let mut writer: Box<dyn AsyncWrite + Unpin + Send> = match rule.body_mode {
        config::BodyMode::Compressed => {
            Box::new(async_compression::tokio::write::GzipEncoder::new(file))
        }
        config::BodyMode::Raw => Box::new(file),
        config::BodyMode::MetadataOnly => unreachable!(),
    };

    let mut stream = body.into_data_stream();
    let mut original_size = 0u64;
    let mut complete = true;
    let mut limit_exceeded = false;
    let mut error = None;

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                original_size = original_size.saturating_add(bytes.len() as u64);
                if original_size > rule.max_body_size {
                    complete = false;
                    limit_exceeded = true;
                    error = Some(format!(
                        "streamed body exceeded configured max_body_size {}",
                        rule.max_body_size
                    ));
                    break;
                }
                if let Err(err) = writer.write_all(&bytes).await {
                    complete = false;
                    error = Some(format!("body write failed: {err}"));
                    break;
                }
            }
            Err(err) => {
                complete = false;
                error = Some(format!("request body stream failed: {err}"));
                break;
            }
        }
    }

    if let Err(err) = writer.shutdown().await {
        complete = false;
        error.get_or_insert_with(|| format!("body close failed: {err}"));
    }

    let stored_size = paths.body_size().await.unwrap_or(0);
    BodyMeta {
        stored: true,
        complete,
        mode: rule.body_mode.to_string(),
        object: paths.body_file_name(),
        encoding: rule.body_mode.encoding().map(ToString::to_string),
        original_size,
        stored_size,
        content_type: content_type(headers),
        previewable: complete && original_size <= rule.preview_limit,
        limit_exceeded,
        error,
    }
}

fn build_meta(
    id: &str,
    received_at: chrono::DateTime<Local>,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: BodyMeta,
) -> RequestMeta {
    RequestMeta {
        id: id.to_string(),
        received_at,
        method: method.to_string(),
        path: uri.path().to_string(),
        query: uri.query().map(ToString::to_string),
        headers: headers_to_json(headers),
        body,
    }
}

fn expires_at(
    received_at: chrono::DateTime<Local>,
    ttl: std::time::Duration,
) -> std::time::SystemTime {
    let received_at: std::time::SystemTime = received_at.into();
    received_at + ttl
}

fn parse_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
}

fn approximate_header_length(method: &str, uri: &Uri, headers: &HeaderMap) -> u64 {
    let mut length = method.len() + 1 + uri.to_string().len() + " HTTP/1.1\r\n".len();
    for (name, value) in headers {
        length += name.as_str().len() + ": ".len() + value.as_bytes().len() + "\r\n".len();
    }
    length += "\r\n".len();
    length as u64
}

fn content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

fn headers_to_json(headers: &HeaderMap) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for (name, value) in headers {
        let value = value
            .to_str()
            .map(ToString::to_string)
            .unwrap_or_else(|_| "<non-utf8>".to_string());
        map.entry(name.as_str().to_string())
            .and_modify(|existing| match existing {
                serde_json::Value::Array(values) => {
                    values.push(serde_json::Value::String(value.clone()))
                }
                other => {
                    let previous = other.take();
                    *other = serde_json::Value::Array(vec![
                        previous,
                        serde_json::Value::String(value.clone()),
                    ]);
                }
            })
            .or_insert_with(|| serde_json::Value::String(value));
    }
    map
}

fn request_id(received_at: chrono::DateTime<Local>, hostname: &str) -> String {
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    format!(
        "{:02}_{:09}_{}_{}",
        received_at.second(),
        received_at.timestamp_subsec_nanos(),
        hostname,
        random
    )
}

fn genpassword() -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        bail!("passwords do not match");
    }
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;
    println!("{hash}");
    println!("\nPut this in config.toml:\n\n[admin]\nusername = \"admin\"\npassword = \"{hash}\"");
    Ok(())
}

fn verifypassword() -> anyhow::Result<()> {
    use std::io::Write;
    print!("Stored password (bcrypt hash or plaintext): ");
    std::io::stdout().flush()?;
    let mut stored = String::new();
    std::io::stdin().read_line(&mut stored)?;
    let plain = rpassword::prompt_password("Plaintext password to check: ")?;
    if admin::password_matches(stored.trim(), &plain) {
        println!("SAME: the plaintext password matches the stored password");
        Ok(())
    } else {
        println!("NOT SAME: the plaintext password does not match the stored password");
        std::process::exit(1);
    }
}

fn sanitize_token(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

trait SecondExt {
    fn second(&self) -> u32;
}

impl SecondExt for chrono::DateTime<Local> {
    fn second(&self) -> u32 {
        chrono::Timelike::second(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::{collections::BTreeMap, io::Read, net::SocketAddr, time::Duration};
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    struct TestServer {
        addr: SocketAddr,
        state: AppState,
        _tmp: TempDir,
        task: JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_test_server(max_body_size: u64) -> TestServer {
        spawn_test_server_with_config(max_body_size, |_| {}).await
    }

    async fn spawn_test_server_with_config(
        max_body_size: u64,
        configure: impl FnOnce(&mut config::Config),
    ) -> TestServer {
        let tmp = TempDir::new().expect("tempdir");
        let mut config = config::Config::default();
        config.storage.root = tmp.path().join("data");
        config.body.max_body_size = max_body_size;
        config.body.preview_limit = max_body_size;
        configure(&mut config);

        let config = Arc::new(config);
        let storage = Arc::new(LocalStorage::new(config.storage.root.clone()));
        storage.ensure_root().await.expect("storage root");
        let state = AppState {
            config,
            storage,
            hostname: Arc::new("test-host".to_string()),
            sessions: Arc::new(admin::Sessions::new()),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let app = build_app(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        TestServer {
            addr,
            state,
            _tmp: tmp,
            task,
        }
    }

    async fn raw_http(addr: SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(request).await.expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        String::from_utf8_lossy(&response).into_owned()
    }

    fn response_body(response: &str) -> &str {
        response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("response body")
    }

    fn response_json(response: &str) -> serde_json::Value {
        serde_json::from_str(response_body(response)).expect("json response")
    }

    fn header_value<'a>(response: &'a str, name: &str) -> Option<&'a str> {
        let name = name.to_ascii_lowercase();
        response.lines().find_map(|line| {
            let (header, value) = line.split_once(':')?;
            (header.to_ascii_lowercase() == name).then(|| value.trim())
        })
    }

    async fn wait_for_records(server: &TestServer, expected: usize) -> Vec<storage::RequestRecord> {
        for _ in 0..40 {
            let records = server.state.storage.recent(20, None).await.expect("recent");
            if records.len() >= expected {
                return records;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        server.state.storage.recent(20, None).await.expect("recent")
    }

    #[tokio::test]
    async fn complete_garbage_body_with_query_returns_success_json() {
        let server = spawn_test_server(1024).await;
        let body = [0_u8, 159, 146, 150, 255];
        let mut request = format!(
            "POST /garbage/path?alpha=1&encoded=%7Bz%7D HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);

        let response = raw_http(server.addr, &request).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        let json = response_json(&response);
        assert_eq!(json["success"], true);
        assert_eq!(json["body_length"], body.len() as u64);
        assert_eq!(json["metadata_saved"], true);

        let records = wait_for_records(&server, 1).await;
        let record = &records[0];
        assert_eq!(
            record.meta.query.as_deref(),
            Some("alpha=1&encoded=%7Bz%7D")
        );
        assert!(record.meta.body.complete);
        assert_eq!(record.meta.body.original_size, body.len() as u64);

        let compressed = tokio::fs::read(record.body_path.as_ref().expect("body path"))
            .await
            .expect("read body");
        let mut decoder = GzDecoder::new(compressed.as_slice());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).expect("decompress");
        assert_eq!(decoded, body);
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected_upfront_and_metadata_is_written() {
        let server = spawn_test_server(8).await;
        let request = b"POST /too-large HTTP/1.1\r\nhost: localhost\r\ncontent-length: 9\r\nconnection: close\r\n\r\n";

        let response = raw_http(server.addr, request).await;
        assert!(
            response.starts_with("HTTP/1.1 413 Payload Too Large"),
            "{response}"
        );
        let json = response_json(&response);
        assert_eq!(json["success"], false);
        assert_eq!(json["limit_exceeded"], true);
        assert_eq!(json["body_stored"], false);

        let records = wait_for_records(&server, 1).await;
        let meta = &records[0].meta;
        assert_eq!(meta.path, "/too-large");
        assert!(meta.body.limit_exceeded);
        assert!(!meta.body.stored);
        assert_eq!(meta.body.original_size, 0);
    }

    #[tokio::test]
    async fn funny_url_path_is_encoded_for_storage_and_query_is_preserved() {
        let server = spawn_test_server(1024).await;
        let request = b"GET /funny/a%20b/%E2%98%83/..%2Fescape?x=1&y=%7Bz%7D HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

        let response = raw_http(server.addr, request).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        let records = wait_for_records(&server, 1).await;
        let record = &records[0];
        assert_eq!(record.meta.path, "/funny/a%20b/%E2%98%83/..%2Fescape");
        assert_eq!(record.meta.query.as_deref(), Some("x=1&y=%7Bz%7D"));

        let meta_path = record.meta_path.to_string_lossy();
        assert!(
            meta_path.contains("/funny/a b/☃/..%2Fescape/"),
            "{meta_path}"
        );
    }

    #[tokio::test]
    async fn half_broken_connection_marks_body_incomplete_when_handler_receives_it() {
        let server = spawn_test_server(1024).await;
        let mut stream = TcpStream::connect(server.addr).await.expect("connect");
        stream
            .write_all(
                b"POST /broken HTTP/1.1\r\nhost: localhost\r\ncontent-length: 20\r\nconnection: close\r\n\r\nhello",
            )
            .await
            .expect("write partial request");
        drop(stream);

        let records = wait_for_records(&server, 1).await;
        assert_eq!(records.len(), 1);
        let meta = &records[0].meta;
        assert_eq!(meta.path, "/broken");
        assert!(!meta.body.complete);
        assert_eq!(meta.body.original_size, 5);
        assert!(meta.body.error.is_some());
    }

    #[test]
    fn password_matches_supports_bcrypt_and_plaintext() {
        let hash = bcrypt::hash("hello", 4).expect("hash");
        assert!(admin::password_matches(&hash, "hello"));
        assert!(!admin::password_matches(&hash, "hellO"));
        assert!(admin::password_matches("plain", "plain"));
        assert!(!admin::password_matches("plain", "plain2"));
    }

    #[tokio::test]
    async fn admin_ui_requires_login_and_webform_auth_works() {
        let server = spawn_test_server_with_config(1024, |config| {
            config.admin.password = Some("s3cret pass".to_string());
        })
        .await;

        let dashboard = raw_http(
            server.addr,
            b"GET /_wh_admin/ HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
        )
        .await;
        assert!(dashboard.starts_with("HTTP/1.1 303"), "{dashboard}");
        assert_eq!(
            header_value(&dashboard, "location"),
            Some("/_wh_admin/login")
        );

        let login = raw_http(
            server.addr,
            b"GET /_wh_admin/login HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
        )
        .await;
        assert!(login.starts_with("HTTP/1.1 200"), "{login}");
        assert!(login.contains("Sign in"), "{login}");

        let bad_form = "username=admin&password=wrong";
        let bad = raw_http(
            server.addr,
            format!(
                "POST /_wh_admin/login HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                bad_form.len(),
                bad_form
            )
            .as_bytes(),
        )
        .await;
        assert!(bad.starts_with("HTTP/1.1 401"), "{bad}");

        // `+` must decode to a space in the form body.
        let good_form = "username=admin&password=s3cret+pass";
        let good = raw_http(
            server.addr,
            format!(
                "POST /_wh_admin/login HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                good_form.len(),
                good_form
            )
            .as_bytes(),
        )
        .await;
        assert!(good.starts_with("HTTP/1.1 303"), "{good}");
        let cookie = header_value(&good, "set-cookie")
            .and_then(|value| value.split(';').next())
            .expect("session cookie")
            .to_string();
        assert!(cookie.starts_with("wh_admin_session="), "{cookie}");

        let authed = raw_http(
            server.addr,
            format!(
                "GET /_wh_admin/ HTTP/1.1\r\nhost: localhost\r\ncookie: {cookie}\r\nconnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        assert!(authed.starts_with("HTTP/1.1 200"), "{authed}");
        assert!(authed.contains("Dashboard"), "{authed}");

        // The admin prefix must not swallow lookalike capture paths.
        let lookalike = raw_http(
            server.addr,
            b"POST /_wh_adminfoo HTTP/1.1\r\nhost: localhost\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi",
        )
        .await;
        assert!(lookalike.starts_with("HTTP/1.1 200"), "{lookalike}");
        assert_eq!(response_json(&lookalike)["success"], true);
    }

    #[tokio::test]
    async fn custom_responders_apply_by_path_prefix_in_order() {
        let server = spawn_test_server_with_config(1024, |config| {
            config.responder.headers = BTreeMap::from([(
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            )]);
            config.responders = vec![
                config::ResponderRule {
                    path_match: "/api1".to_string(),
                    status: Some(200),
                    headers: BTreeMap::from([("x-webhook-debug".to_string(), "api1".to_string())]),
                    body: Some(config::ResponderBody::StaticJson(serde_json::json!({
                        "success": true,
                        "source": "api1"
                    }))),
                },
                config::ResponderRule {
                    path_match: "/api1/test2".to_string(),
                    status: Some(202),
                    headers: BTreeMap::from([
                        (
                            "content-type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        ),
                        ("x-webhook-debug".to_string(), "api1-test2".to_string()),
                    ]),
                    body: Some(config::ResponderBody::StaticText("accepted".to_string())),
                },
            ];
        })
        .await;

        let api1 = raw_http(
            server.addr,
            b"POST /api1/anything HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
        assert!(api1.starts_with("HTTP/1.1 200 OK"), "{api1}");
        assert_eq!(response_json(&api1)["source"], "api1");
        assert_eq!(header_value(&api1, "x-webhook-debug"), Some("api1"));

        let api1_test2 = raw_http(
            server.addr,
            b"POST /api1/test2/deeper HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
        assert!(
            api1_test2.starts_with("HTTP/1.1 202 Accepted"),
            "{api1_test2}"
        );
        assert_eq!(response_body(&api1_test2), "accepted");
        assert_eq!(
            header_value(&api1_test2, "content-type"),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(
            header_value(&api1_test2, "x-webhook-debug"),
            Some("api1-test2")
        );
    }
}
