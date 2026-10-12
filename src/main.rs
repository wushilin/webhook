mod admin;
mod config;
mod models;
mod storage;
mod stream;

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
use clap::{Args as ClapArgs, Parser, Subcommand};
use futures_util::StreamExt;
use models::{BodyMeta, CaptureResponse, RequestMeta};
use rand::{distributions::Alphanumeric, Rng};
use storage::{BlobLocation, Storage};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, env = "WEBHOOK_CONFIG", hide = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the webhook capture server
    Run(RunArgs),
    /// Print a default TOML config to stdout
    Genconfig,
    /// Prompt for a password and print its bcrypt hash for admin.password
    Genpassword,
    /// Check whether a plaintext password matches a stored (bcrypt or plaintext) password
    Verifypassword,
}

#[derive(ClapArgs, Debug)]
struct RunArgs {
    #[arg(short, long, env = "WEBHOOK_CONFIG", default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Clone)]
pub struct AppState {
    config: Arc<config::Config>,
    storage: Arc<Storage>,
    hostname: Arc<String>,
    sessions: Arc<admin::Sessions>,
    stream: Arc<stream::StreamHub>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();
    let config_path = match args.command {
        Some(Command::Run(run_args)) => run_args.config,
        Some(Command::Genconfig) => return genconfig(),
        Some(Command::Genpassword) => return genpassword(),
        Some(Command::Verifypassword) => return verifypassword(),
        None => args.config.unwrap_or_else(|| PathBuf::from("config.toml")),
    };

    let config = Arc::new(config::Config::load_or_default(&config_path)?);
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

    let storage = Arc::new(
        Storage::open_async(config.storage.db.clone(), config.storage.blobs.clone()).await?,
    );

    if config.stream.token.is_none() {
        warn!("stream.token is not configured; anyone can open the request stream");
    }
    let stream = Arc::new(stream::StreamHub::new(&config)?);

    let state = AppState {
        config: config.clone(),
        storage: storage.clone(),
        hostname: Arc::new(sanitize_token(&hostname)),
        sessions: Arc::new(admin::Sessions::new()),
        stream: stream.clone(),
    };

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        retention_worker(cleanup_state).await;
    });
    let sweep_state = state.clone();
    tokio::spawn(async move {
        orphan_sweeper(sweep_state).await;
    });
    let flush_storage = storage.clone();
    tokio::spawn(async move {
        stats_flusher(flush_storage).await;
    });

    let app = build_app(state);

    let addr: SocketAddr = config.server.bind.parse().context("invalid server.bind")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "webhook listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            stream.shutdown();
        })
        .await?;

    if let Err(err) = storage.flush_stats().await {
        warn!(error = ?err, "final stats flush failed");
    }
    Ok(())
}

fn genconfig() -> anyhow::Result<()> {
    print!("{}", config::default_config_toml());
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

/// Writes buffered dashboard counts to the database every few seconds.
async fn stats_flusher(storage: Arc<Storage>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        if let Err(err) = storage.flush_stats().await {
            warn!(error = ?err, "stats flush failed");
        }
    }
}

async fn retention_worker(state: AppState) {
    let interval_period = state
        .config
        .retention
        .cleanup_interval
        .max(std::time::Duration::from_secs(1));
    let mut interval = tokio::time::interval(interval_period);
    loop {
        interval.tick().await;
        if let Err(err) = state.storage.cleanup().await {
            warn!(error = ?err, "retention cleanup failed");
        }
    }
}

/// Sweeps the blob folders for orphans and empty folders. Rare by design: the
/// first run waits 10 minutes so frequent restarts don't each trigger one.
async fn orphan_sweeper(state: AppState) {
    let period = state
        .config
        .retention
        .orphan_sweep_interval
        .max(std::time::Duration::from_secs(60));
    let first = tokio::time::Instant::now() + period.min(std::time::Duration::from_secs(600));
    let mut interval = tokio::time::interval_at(first, period);
    loop {
        interval.tick().await;
        let started = std::time::Instant::now();
        let report = state
            .storage
            .sweep_blobs(state.config.retention.prune_grace)
            .await;
        info!(
            folders = report.folders,
            files = report.files,
            orphans_removed = report.orphans_removed,
            folders_removed = report.folders_removed,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "blob sweep finished"
        );
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
                .put(&meta, expires_at(received_at, rule.ttl))
                .await?;
            state.stream.publish(&meta);
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
    let location = state.storage.blob_location(&id, rule.body_mode);
    let body_meta = stream_body(
        &state.storage,
        req.into_body(),
        location.as_ref(),
        &headers,
        &rule,
    )
    .await;

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
        .put(&meta, expires_at(received_at, rule.ttl))
        .await?;
    state.stream.publish(&meta);

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
    storage: &Storage,
    body: Body,
    location: Option<&BlobLocation>,
    headers: &HeaderMap,
    rule: &config::ResolvedPathRule,
) -> BodyMeta {
    let Some(location) = location else {
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
    };

    let file = match storage.create_body_file(location).await {
        Ok(file) => file,
        Err(err) => {
            return BodyMeta {
                stored: false,
                complete: false,
                mode: rule.body_mode.to_string(),
                object: Some(location.object.clone()),
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

    let stored_size = tokio::fs::metadata(&location.path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    BodyMeta {
        stored: true,
        complete,
        mode: rule.body_mode.to_string(),
        object: Some(location.object.clone()),
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

/// `20261012T142016.557051647Z_<host>_<random>`: sorts by capture time (UTC),
/// and is safe in URLs and file names.
fn request_id(received_at: chrono::DateTime<Local>, hostname: &str) -> String {
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();
    format!(
        "{}_{}_{}",
        received_at
            .with_timezone(&chrono::Utc)
            .format("%Y%m%dT%H%M%S%.9fZ"),
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
        config.storage.db = tmp.path().join("db");
        config.storage.blobs = tmp.path().join("blobs");
        config.body.max_body_size = max_body_size;
        config.body.preview_limit = max_body_size;
        configure(&mut config);

        let config = Arc::new(config);
        let stream = Arc::new(stream::StreamHub::new(&config).expect("stream"));
        let storage =
            Arc::new(Storage::open(&config.storage.db, &config.storage.blobs).expect("storage"));
        let state = AppState {
            config,
            storage,
            hostname: Arc::new("test-host".to_string()),
            sessions: Arc::new(admin::Sessions::new()),
            stream,
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

    async fn recent(server: &TestServer) -> Vec<RequestMeta> {
        let query = storage::SearchQuery {
            prefix: None,
            from: None,
            to: None,
            before: None,
            limit: 20,
            scan_budget: 10_000,
        };
        server
            .state
            .storage
            .search(query)
            .await
            .expect("search")
            .records
    }

    async fn wait_for_records(server: &TestServer, expected: usize) -> Vec<RequestMeta> {
        for _ in 0..40 {
            let records = recent(server).await;
            if records.len() >= expected {
                return records;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        recent(server).await
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
        let meta = &records[0];
        assert_eq!(meta.query.as_deref(), Some("alpha=1&encoded=%7Bz%7D"));
        assert!(meta.body.complete);
        assert_eq!(meta.body.original_size, body.len() as u64);

        // Blobs live in the hashed fan-out, named after the request id.
        let blob = server.state.storage.blob_path(meta).expect("blob path");
        assert!(blob.ends_with(format!("{}.body.bin.gz", meta.id)));
        let compressed = tokio::fs::read(&blob).await.expect("read body");
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
        let meta = &records[0];
        assert_eq!(meta.path, "/too-large");
        assert!(meta.body.limit_exceeded);
        assert!(!meta.body.stored);
        assert_eq!(meta.body.original_size, 0);
    }

    #[tokio::test]
    async fn funny_url_path_and_query_are_preserved() {
        let server = spawn_test_server(1024).await;
        let request = b"GET /funny/a%20b/%E2%98%83/..%2Fescape?x=1&y=%7Bz%7D HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

        let response = raw_http(server.addr, request).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

        let records = wait_for_records(&server, 1).await;
        assert_eq!(records[0].path, "/funny/a%20b/%E2%98%83/..%2Fescape");
        assert_eq!(records[0].query.as_deref(), Some("x=1&y=%7Bz%7D"));
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
        let meta = &records[0];
        assert_eq!(meta.path, "/broken");
        assert!(!meta.body.complete);
        assert_eq!(meta.body.original_size, 5);
        assert!(meta.body.error.is_some());
    }

    #[test]
    fn cli_accepts_explicit_run_config_path() {
        let args = Args::try_parse_from(["webhook", "run", "-c", "custom.toml"]).unwrap();
        match args.command {
            Some(Command::Run(run_args)) => {
                assert_eq!(run_args.config, PathBuf::from("custom.toml"))
            }
            other => panic!("expected run command, got {other:?}"),
        }
    }

    #[test]
    fn cli_keeps_no_subcommand_as_run_default() {
        let args = Args::try_parse_from(["webhook"]).unwrap();
        assert!(args.command.is_none());
    }

    #[test]
    fn cli_keeps_legacy_top_level_config_for_default_run() {
        let args = Args::try_parse_from(["webhook", "-c", "legacy.toml"]).unwrap();
        assert_eq!(args.config, Some(PathBuf::from("legacy.toml")));
        assert!(args.command.is_none());
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
        assert!(authed.contains("Overview"), "{authed}");

        // Search, detail and the session-protected body endpoint.
        raw_http(
            server.addr,
            b"POST /hooks/github?x=1 HTTP/1.1\r\nhost: localhost\r\ncontent-length: 9\r\nconnection: close\r\n\r\nbody-text",
        )
        .await;
        let id = wait_for_records(&server, 1).await[0].id.clone();
        let get = |path: String, cookie: Option<String>| {
            let cookie = cookie
                .map(|c| format!("cookie: {c}\r\n"))
                .unwrap_or_default();
            let addr = server.addr;
            async move {
                raw_http(
                    addr,
                    format!("GET {path} HTTP/1.0\r\nhost: localhost\r\n{cookie}\r\n").as_bytes(),
                )
                .await
            }
        };
        let list = get(
            "/_wh_admin/requests?path=/hooks".to_string(),
            Some(cookie.clone()),
        )
        .await;
        assert!(list.contains("/hooks/github"), "{list}");
        assert!(list.contains(&id), "{list}");
        let none = get(
            "/_wh_admin/requests?path=/nothing".to_string(),
            Some(cookie.clone()),
        )
        .await;
        assert!(none.contains("No requests match"), "{none}");
        let detail = get(format!("/_wh_admin/requests/{id}"), Some(cookie.clone())).await;
        assert!(
            detail.starts_with("HTTP/1.1 200") || detail.starts_with("HTTP/1.0 200"),
            "{detail}"
        );
        assert!(detail.contains("Copy as cURL"), "{detail}");
        let body = get(
            format!("/_wh_admin/requests/{id}/body"),
            Some(cookie.clone()),
        )
        .await;
        assert_eq!(response_body(&body), "body-text");
        let anonymous = get(format!("/_wh_admin/requests/{id}/body"), None).await;
        assert!(anonymous.contains(" 303 "), "{anonymous}");
        let missing = get("/_wh_admin/requests/nope".to_string(), Some(cookie.clone())).await;
        assert!(missing.contains(" 404 "), "{missing}");

        // The admin prefix must not swallow lookalike capture paths.
        let lookalike = raw_http(
            server.addr,
            b"POST /_wh_adminfoo HTTP/1.1\r\nhost: localhost\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi",
        )
        .await;
        assert!(lookalike.starts_with("HTTP/1.1 200"), "{lookalike}");
        assert_eq!(response_json(&lookalike)["success"], true);
    }

    async fn next_stream_event(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    ) -> serde_json::Value {
        use futures_util::StreamExt;
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("stream event timeout")
                .expect("stream open")
                .expect("stream message");
            if let tokio_tungstenite::tungstenite::Message::Text(text) = message {
                return serde_json::from_str(&text).expect("event json");
            }
        }
    }

    /// HTTP/1.0 so the response body is close-delimited rather than chunked.
    async fn get_body(server: &TestServer, url: &str, auth: Option<&str>) -> String {
        let auth = auth
            .map(|token| format!("authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        raw_http(
            server.addr,
            format!("GET {url} HTTP/1.0\r\nhost: localhost\r\n{auth}\r\n").as_bytes(),
        )
        .await
    }

    #[tokio::test]
    async fn stream_requires_token_and_fans_out_to_independent_consumers() {
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

        let server = spawn_test_server_with_config(1024, |config| {
            config.stream.token = Some("tok".to_string());
            config.paths = vec![config::PathRule {
                path_match: "/meta".to_string(),
                ttl: None,
                body_mode: Some(config::BodyMode::MetadataOnly),
                preview_limit: None,
                max_body_size: None,
            }];
        })
        .await;
        let url = format!("ws://{}/_wh_admin/stream", server.addr);

        let err = connect_async(url.as_str()).await.expect_err("no token");
        assert!(err.to_string().contains("401"), "{err}");
        let err = connect_async(format!("{url}?token=wrong"))
            .await
            .expect_err("wrong token");
        assert!(err.to_string().contains("401"), "{err}");

        let mut request = url.as_str().into_client_request().unwrap();
        request
            .headers_mut()
            .insert("authorization", "Bearer tok".parse().unwrap());
        let (mut all_a, _) = connect_async(request).await.expect("bearer token");
        let (mut all_b, _) = connect_async(format!("{url}?token=tok"))
            .await
            .expect("query token");
        let (mut only_api, _) = connect_async(format!("{url}?token=tok&prefix=/api/v1"))
            .await
            .expect("prefix consumer");

        raw_http(
            server.addr,
            b"POST /other?x=1 HTTP/1.1\r\nhost: localhost\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
        )
        .await;
        raw_http(
            server.addr,
            b"POST /api/v1/hook HTTP/1.1\r\nhost: localhost\r\ncontent-length: 10\r\nconnection: close\r\n\r\n0123456789",
        )
        .await;
        // The prefix is a plain string prefix, not a path segment.
        raw_http(
            server.addr,
            b"POST /api/v1x HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
        raw_http(
            server.addr,
            b"POST /meta HTTP/1.1\r\nhost: localhost\r\ncontent-length: 3\r\nconnection: close\r\n\r\nabc",
        )
        .await;

        let mut hook_url = String::new();
        for ws in [&mut all_a, &mut all_b] {
            // Envelopes carry metadata and a body_url, never the body itself.
            let first = next_stream_event(ws).await;
            assert_eq!(first["path"], "/other");
            assert_eq!(first["query"], "x=1");
            assert_eq!(first["body"]["original_size"], 5);
            assert!(first.get("body_base64").is_none());
            let other_url = first["body_url"].as_str().expect("body_url").to_string();
            assert!(other_url.starts_with("/_wh_admin/stream/body/"));
            assert_eq!(
                response_body(&get_body(&server, &other_url, Some("tok")).await),
                "hello"
            );

            let second = next_stream_event(ws).await;
            assert_eq!(second["path"], "/api/v1/hook");
            hook_url = second["body_url"].as_str().expect("body_url").to_string();

            assert_eq!(next_stream_event(ws).await["path"], "/api/v1x");

            // metadata_only stores no body, so there is nothing to fetch.
            let meta_only = next_stream_event(ws).await;
            assert_eq!(meta_only["path"], "/meta");
            assert!(meta_only["body_url"].is_null());
        }

        let filtered = next_stream_event(&mut only_api).await;
        assert_eq!(filtered["path"], "/api/v1/hook");
        assert_eq!(next_stream_event(&mut only_api).await["path"], "/api/v1x");

        // Body endpoint: token rules, gunzip, limit, inert content type.
        let full = get_body(&server, &hook_url, Some("tok")).await;
        assert!(
            full.starts_with("HTTP/1.0 200") || full.starts_with("HTTP/1.1 200"),
            "{full}"
        );
        assert_eq!(response_body(&full), "0123456789");
        assert_eq!(
            header_value(&full, "content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(
            header_value(&full, "x-content-type-options"),
            Some("nosniff")
        );
        let head = get_body(&server, &format!("{hook_url}?limit=4"), Some("tok")).await;
        assert_eq!(response_body(&head), "0123");
        let by_query = get_body(&server, &format!("{hook_url}?token=tok&limit=2"), None).await;
        assert_eq!(response_body(&by_query), "01");
        let denied = get_body(&server, &hook_url, None).await;
        assert!(denied.contains(" 401 "), "{denied}");
        let unknown = get_body(&server, "/_wh_admin/stream/body/..%2F..%2Fetc", Some("tok")).await;
        assert!(unknown.contains(" 404 "), "{unknown}");
    }

    #[tokio::test]
    async fn stream_view_page_is_served_with_admin_prefix() {
        let server = spawn_test_server_with_config(1024, |config| {
            config.admin.password = Some("secret".to_string());
            config.stream.token = Some("tok".to_string());
        })
        .await;
        // Not logged in: the page sends you to the login form.
        let anonymous = raw_http(
            server.addr,
            b"GET /_wh_admin/streamview HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
        )
        .await;
        assert!(anonymous.starts_with("HTTP/1.1 303"), "{anonymous}");

        let form = "username=admin&password=secret";
        let login = raw_http(
            server.addr,
            format!(
                "POST /_wh_admin/login HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{form}",
                form.len()
            )
            .as_bytes(),
        )
        .await;
        let cookie = header_value(&login, "set-cookie")
            .and_then(|value| value.split(';').next())
            .expect("session cookie")
            .to_string();
        let page = raw_http(
            server.addr,
            format!(
                "GET /_wh_admin/streamview HTTP/1.1\r\nhost: localhost\r\ncookie: {cookie}\r\nconnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        // Logged in: the stream token is pre-filled.
        assert!(page.contains(r#"const STREAM_TOKEN = "tok";"#), "{page}");
        assert!(
            page.contains(r#"const ADMIN_PREFIX = "/_wh_admin";"#),
            "{page}"
        );
        assert!(page.contains("const TOKEN_REQUIRED = true;"), "{page}");
        assert!(!page.contains("__ADMIN_PREFIX__"));
    }

    #[tokio::test]
    async fn stream_is_open_without_token() {
        let server = spawn_test_server(1024).await;
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{}/_wh_admin/stream", server.addr))
                .await
                .expect("open stream");
        raw_http(
            server.addr,
            b"GET /ping HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(next_stream_event(&mut ws).await["path"], "/ping");
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
