use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Response},
};
use flate2::read::GzDecoder;
use rand::{distributions::Alphanumeric, Rng};
use std::{
    collections::HashMap,
    io::Read,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use crate::{models::RequestMeta, storage::RequestRecord, AppState};

const SESSION_COOKIE: &str = "wh_admin_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const LOGIN_FORM_LIMIT: usize = 16 * 1024;

#[derive(Debug, Default)]
pub struct Sessions {
    tokens: Mutex<HashMap<String, SystemTime>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    fn create(&self) -> String {
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let now = SystemTime::now();
        let mut tokens = self.tokens.lock().expect("sessions lock");
        tokens.retain(|_, expires| *expires > now);
        tokens.insert(token.clone(), now + SESSION_TTL);
        token
    }

    fn is_valid(&self, token: &str) -> bool {
        let now = SystemTime::now();
        let mut tokens = self.tokens.lock().expect("sessions lock");
        tokens.retain(|_, expires| *expires > now);
        tokens.contains_key(token)
    }

    fn remove(&self, token: &str) {
        self.tokens.lock().expect("sessions lock").remove(token);
    }
}

/// Shared by the server login and the `verifypassword` CLI: a stored value
/// starting with `$2` is treated as a bcrypt hash, anything else as plaintext.
pub fn password_matches(stored: &str, given: &str) -> bool {
    let stored = stored.trim();
    if stored.starts_with("$2") {
        bcrypt::verify(given, stored).unwrap_or(false)
    } else {
        constant_time_eq(stored.as_bytes(), given.as_bytes())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn handle_admin(state: AppState, req: Request<Body>) -> Response {
    let prefix = state
        .config
        .server
        .admin_prefix
        .trim_end_matches('/')
        .to_string();
    let subpath = req
        .uri()
        .path()
        .strip_prefix(&prefix)
        .unwrap_or("")
        .to_string();
    let method = req.method().clone();

    match subpath.as_str() {
        "/style.css" => css(),
        "/login" if method == Method::GET => {
            if is_authorized(&state, req.headers()) {
                redirect(&format!("{prefix}/"))
            } else {
                login_page(&state, None, StatusCode::OK)
            }
        }
        "/login" if method == Method::POST => login_submit(state, req).await,
        "/logout" => logout(&state, req.headers()),
        _ if !is_authorized(&state, req.headers()) => redirect(&format!("{prefix}/login")),
        "" | "/" => dashboard(state).await,
        "/requests" => requests(state, req.uri().query()).await,
        p if p.starts_with("/requests/") => {
            request_detail(state, p.trim_start_matches("/requests/")).await
        }
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn is_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    if state.config.admin.password.is_none() {
        return true;
    }
    session_cookie(headers)
        .map(|token| state.sessions.is_valid(&token))
        .unwrap_or(false)
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            if let Some(token) = pair.trim().strip_prefix(&format!("{SESSION_COOKIE}=")) {
                return Some(token.to_string());
            }
        }
    }
    None
}

async fn login_submit(state: AppState, req: Request<Body>) -> Response {
    let prefix = state
        .config
        .server
        .admin_prefix
        .trim_end_matches('/')
        .to_string();
    let Some(expected_password) = state.config.admin.password.clone() else {
        return redirect(&format!("{prefix}/"));
    };

    let body = match axum::body::to_bytes(req.into_body(), LOGIN_FORM_LIMIT).await {
        Ok(body) => body,
        Err(_) => {
            return login_page(
                &state,
                Some("Could not read the login form."),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let form = parse_form(&String::from_utf8_lossy(&body));
    let username = form_value(&form, "username").unwrap_or_default();
    let password = form_value(&form, "password").unwrap_or_default();
    let expected_username = state.config.admin.username.clone();

    // bcrypt verification is CPU-bound (~100ms), keep it off the runtime.
    let ok = tokio::task::spawn_blocking(move || {
        let user_ok = constant_time_eq(username.as_bytes(), expected_username.as_bytes());
        let pass_ok = password_matches(&expected_password, &password);
        user_ok && pass_ok
    })
    .await
    .unwrap_or(false);

    if !ok {
        return login_page(
            &state,
            Some("Invalid username or password."),
            StatusCode::UNAUTHORIZED,
        );
    }

    let token = state.sessions.create();
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path={prefix}; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, format!("{prefix}/"))
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .unwrap_or_else(|_| redirect(&format!("{prefix}/")))
}

fn logout(state: &AppState, headers: &HeaderMap) -> Response {
    if let Some(token) = session_cookie(headers) {
        state.sessions.remove(&token);
    }
    let prefix = state.config.server.admin_prefix.trim_end_matches('/');
    let cookie = format!("{SESSION_COOKIE}=; Path={prefix}; HttpOnly; SameSite=Lax; Max-Age=0");
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, format!("{prefix}/login"))
        .header(header::SET_COOKIE, cookie)
        .body(Body::empty())
        .unwrap_or_else(|_| redirect(&format!("{prefix}/login")))
}

fn redirect(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::SEE_OTHER.into_response())
}

fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((decode_component(key), decode_component(value)))
        })
        .collect()
}

fn form_value(form: &[(String, String)], name: &str) -> Option<String> {
    form.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

fn decode_component(raw: &str) -> String {
    let plus_decoded = raw.replace('+', " ");
    urlencoding::decode(&plus_decoded)
        .map(|v| v.into_owned())
        .unwrap_or(plus_decoded)
}

async fn dashboard(state: AppState) -> Response {
    match state.storage.dashboard().await {
        Ok(stats) => {
            let path_rows = if stats.top_paths.is_empty() {
                r#"<tr><td colspan="2" class="empty">No requests captured yet.</td></tr>"#
                    .to_string()
            } else {
                stats
                    .top_paths
                    .iter()
                    .map(|(path, count)| {
                        format!(
                            "<tr><td><a href=\"{}/requests?path={}\">{}</a></td><td class=\"num\">{}</td></tr>",
                            state.config.server.admin_prefix,
                            urlencoding::encode(path),
                            escape(path),
                            count
                        )
                    })
                    .collect::<String>()
            };
            let method_rows = if stats.top_methods.is_empty() {
                r#"<tr><td colspan="2" class="empty">No requests captured yet.</td></tr>"#
                    .to_string()
            } else {
                stats
                    .top_methods
                    .iter()
                    .map(|(method, count)| {
                        format!(
                            "<tr><td>{}</td><td class=\"num\">{}</td></tr>",
                            method_chip(method),
                            count
                        )
                    })
                    .collect::<String>()
            };

            page(
                &state,
                "Dashboard",
                "dashboard",
                &format!(
                    r#"
<section class="metrics">
  <div class="tile"><span>Requests since restart</span><b>{}</b></div>
  <div class="tile"><span>Complete</span><b>{}</b></div>
  <div class="tile"><span>Incomplete</span><b>{}</b></div>
  <div class="tile"><span>Stored body</span><b>{}</b></div>
</section>
<section class="grid">
  <div class="card">
    <h2>Top paths</h2>
    <table><thead><tr><th>Path</th><th class="num">Requests</th></tr></thead><tbody>{}</tbody></table>
  </div>
  <div class="card">
    <h2>Methods</h2>
    <table><thead><tr><th>Method</th><th class="num">Requests</th></tr></thead><tbody>{}</tbody></table>
  </div>
</section>
"#,
                    stats.total_requests,
                    stats.complete_requests,
                    stats.incomplete_requests,
                    human_bytes(stats.stored_body_bytes),
                    path_rows,
                    method_rows
                ),
            )
        }
        Err(err) => error_response(err),
    }
}

async fn requests(state: AppState, query: Option<&str>) -> Response {
    let path_filter = query
        .map(parse_form)
        .and_then(|form| form_value(&form, "path"))
        .filter(|value| !value.is_empty());

    match state.storage.recent(200, path_filter.as_deref()).await {
        Ok(records) => {
            let rows = if records.is_empty() {
                r#"<tr><td colspan="5" class="empty">No requests matched.</td></tr>"#.to_string()
            } else {
                records
                    .iter()
                    .map(|record| request_row(&state, record))
                    .collect::<String>()
            };
            let title = path_filter
                .as_ref()
                .map(|p| format!("Requests for {p}"))
                .unwrap_or_else(|| "Recent requests".to_string());
            page(
                &state,
                &title,
                "requests",
                &format!(
                    r#"<div class="toolbar"><form method="get"><input name="path" placeholder="Filter by path, e.g. /api1" value="{}"><button>Filter</button></form></div>
<div class="card"><table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th class="num">Body</th><th>Status</th></tr></thead><tbody>{}</tbody></table></div>"#,
                    escape(path_filter.as_deref().unwrap_or("")),
                    rows
                ),
            )
        }
        Err(err) => error_response(err),
    }
}

async fn request_detail(state: AppState, id: &str) -> Response {
    match state.storage.find_by_id(id).await {
        Ok(Some(record)) => {
            let meta_json =
                serde_json::to_string_pretty(&record.meta).unwrap_or_else(|_| "{}".to_string());
            let preview = body_preview(&record).await;
            page(
                &state,
                &format!("Request {}", escape(&record.meta.id)),
                "requests",
                &format!(
                    r#"<p class="backlink"><a href="{}/requests">&larr; All requests</a></p>
<section class="detail card">
<div class="summary">
  <div><span>Method</span><b>{}</b></div>
  <div><span>Path</span><b>{}</b></div>
  <div><span>Received</span><b>{}</b></div>
  <div><span>Body</span><b>{}</b></div>
  <div><span>Metadata file</span><b>{}</b></div>
</div>
<h2>Body preview</h2>
{}
<h2>Metadata</h2>
<pre>{}</pre>
</section>"#,
                    state.config.server.admin_prefix,
                    method_chip(&record.meta.method),
                    escape(&record.meta.path),
                    escape(&record.meta.received_at.to_rfc3339()),
                    body_status(&record.meta),
                    escape(&record.meta_path.display().to_string()),
                    preview,
                    escape(&meta_json)
                ),
            )
        }
        Ok(None) => (StatusCode::NOT_FOUND, "request not found").into_response(),
        Err(err) => error_response(err),
    }
}

async fn body_preview(record: &RequestRecord) -> String {
    if !record.meta.body.previewable {
        return "<p class=\"muted\">Body preview is unavailable for this request.</p>".to_string();
    }
    let Some(path) = &record.body_path else {
        return "<p class=\"muted\">No body object was stored.</p>".to_string();
    };
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let decoded = if record.meta.body.encoding.as_deref() == Some("gzip") {
                let original_size = record.meta.body.original_size as usize;
                let inflated = tokio::task::spawn_blocking(move || {
                    let mut decoder = GzDecoder::new(bytes.as_slice());
                    let mut out = Vec::with_capacity(original_size);
                    decoder.read_to_end(&mut out).map(|_| out)
                })
                .await;
                match inflated {
                    Ok(Ok(out)) => out,
                    Ok(Err(err)) => {
                        return format!(
                            "<p class=\"error\">Failed to decompress body: {}</p>",
                            escape(&err.to_string())
                        );
                    }
                    Err(err) => {
                        return format!(
                            "<p class=\"error\">Failed to decompress body: {}</p>",
                            escape(&err.to_string())
                        );
                    }
                }
            } else {
                bytes
            };
            let text = String::from_utf8_lossy(&decoded);
            format!("<pre>{}</pre>", escape(&text))
        }
        Err(err) => format!(
            "<p class=\"error\">Failed to read body: {}</p>",
            escape(&err.to_string())
        ),
    }
}

fn request_row(state: &AppState, record: &RequestRecord) -> String {
    format!(
        r#"<tr>
<td class="mono"><a href="{}/requests/{}">{}</a></td>
<td>{}</td>
<td class="path">{}{}</td>
<td class="num">{}</td>
<td>{}</td>
</tr>"#,
        state.config.server.admin_prefix,
        urlencoding::encode(&record.meta.id),
        escape(
            &record
                .meta
                .received_at
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        ),
        method_chip(&record.meta.method),
        escape(&record.meta.path),
        record
            .meta
            .query
            .as_ref()
            .map(|q| format!("<span class=\"query\">?{}</span>", escape(q)))
            .unwrap_or_default(),
        human_bytes(record.meta.body.original_size),
        body_status(&record.meta)
    )
}

fn method_chip(method: &str) -> String {
    let class = match method {
        "GET" => "get",
        "POST" => "post",
        "PUT" | "PATCH" => "put",
        "DELETE" => "delete",
        _ => "other",
    };
    format!("<span class=\"method {}\">{}</span>", class, escape(method))
}

fn body_status(meta: &RequestMeta) -> String {
    if meta.body.limit_exceeded {
        "<span class=\"pill warn\">&#9888; limit exceeded</span>".to_string()
    } else if meta.body.complete {
        "<span class=\"pill ok\">&#10003; complete</span>".to_string()
    } else {
        "<span class=\"pill bad\">&#10007; incomplete</span>".to_string()
    }
}

fn login_page(state: &AppState, error: Option<&str>, status: StatusCode) -> Response {
    let prefix = state.config.server.admin_prefix.trim_end_matches('/');
    let error_html = error
        .map(|message| format!("<p class=\"form-error\">{}</p>", escape(message)))
        .unwrap_or_default();
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in &middot; Webhook Debug</title>
  <link rel="stylesheet" href="{prefix}/style.css">
</head>
<body class="login-body">
  <main class="login-card">
    <div class="brand"><span class="brand-mark">&#9889;</span><span class="brand-name">Webhook Debug</span></div>
    <h1>Sign in</h1>
    <p class="muted">Enter your admin credentials to view captured requests.</p>
    {error_html}
    <form method="post" action="{prefix}/login">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" autofocus required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>"#
    );
    (status, Html(html)).into_response()
}

fn page(state: &AppState, title: &str, active: &str, body: &str) -> Response {
    let prefix = state.config.server.admin_prefix.trim_end_matches('/');
    let nav_class = |name: &str| {
        if name == active {
            " class=\"active\""
        } else {
            ""
        }
    };
    let logout = if state.config.admin.password.is_some() {
        format!("<a class=\"logout\" href=\"{prefix}/logout\">Sign out</a>")
    } else {
        String::new()
    };
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title_escaped} &middot; Webhook Debug</title>
  <link rel="stylesheet" href="{prefix}/style.css">
</head>
<body>
  <aside>
    <div class="brand"><span class="brand-mark">&#9889;</span><span class="brand-name">Webhook Debug</span></div>
    <nav>
      <a href="{prefix}/"{dash_active}>Dashboard</a>
      <a href="{prefix}/requests"{req_active}>Requests</a>
    </nav>
    <div class="side-footer">
      <small>{root}</small>
      {logout}
    </div>
  </aside>
  <main>
    <header><h1>{title_escaped}</h1></header>
    {body}
  </main>
</body>
</html>"#,
        title_escaped = escape(title),
        prefix = prefix,
        dash_active = nav_class("dashboard"),
        req_active = nav_class("requests"),
        root = escape(&state.storage.root().display().to_string()),
        logout = logout,
        body = body
    );
    Html(html).into_response()
}

fn css() -> Response {
    let css = r#"
:root {
  color-scheme: light;
  --plane: #f9f9f7;
  --surface: #fcfcfb;
  --ink: #0b0b0b;
  --ink-2: #52514e;
  --muted: #898781;
  --hairline: #e1e0d9;
  --ring: rgba(11, 11, 11, 0.10);
  --accent: #2a78d6;
  --accent-strong: #256abf;
  --accent-deep: #1c5cab;
  --side-bg: #1a1a19;
  --side-ink: #ffffff;
  --side-ink-2: #c3c2b7;
  --side-ring: rgba(255, 255, 255, 0.10);
  --good-bg: #e3f6e3; --good-ink: #006300;
  --warn-bg: #fdf0d1; --warn-ink: #7a5200;
  --bad-bg: #fbe3e3;  --bad-ink: #a32222;
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--plane);
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; grid-template-columns: 248px 1fr; }

aside {
  background: var(--side-bg); color: var(--side-ink);
  padding: 22px 18px; display: flex; flex-direction: column; gap: 26px;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand-mark {
  display: inline-flex; align-items: center; justify-content: center;
  width: 32px; height: 32px; border-radius: 9px; font-size: 17px;
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent-deep) 100%);
}
.brand-name { font-size: 16px; font-weight: 650; letter-spacing: 0.01em; }
aside nav { display: grid; gap: 4px; }
aside nav a {
  color: var(--side-ink-2); text-decoration: none; font-size: 14px; font-weight: 500;
  padding: 9px 12px; border-radius: 8px; transition: background 120ms, color 120ms;
}
aside nav a:hover { background: rgba(255, 255, 255, 0.07); color: var(--side-ink); }
aside nav a.active {
  background: rgba(57, 135, 229, 0.22); color: var(--side-ink); font-weight: 600;
}
.side-footer { margin-top: auto; display: grid; gap: 12px; }
.side-footer small { color: var(--muted); overflow-wrap: anywhere; line-height: 1.4; }
.logout {
  color: var(--side-ink-2); text-decoration: none; font-size: 13px; font-weight: 600;
  padding: 8px 12px; border: 1px solid var(--side-ring); border-radius: 8px; text-align: center;
  transition: background 120ms, color 120ms;
}
.logout:hover { background: rgba(255, 255, 255, 0.07); color: var(--side-ink); }

main { padding: 30px 36px; overflow-x: auto; }
header { margin-bottom: 22px; }
header h1 { margin: 0; font-size: 26px; font-weight: 650; letter-spacing: -0.01em; }
h2 { margin: 0 0 12px; font-size: 15px; font-weight: 650; color: var(--ink-2); }

.metrics { display: grid; grid-template-columns: repeat(4, minmax(130px, 1fr)); gap: 14px; margin-bottom: 22px; }
.tile {
  background: var(--surface); border: 1px solid var(--ring); border-radius: 12px;
  padding: 16px 18px; box-shadow: 0 1px 2px rgba(11, 11, 11, 0.04);
}
.tile span { display: block; font-size: 13px; color: var(--ink-2); margin-bottom: 6px; }
.tile b { font-size: 30px; font-weight: 600; line-height: 1.1; }

.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
.card {
  background: var(--surface); border: 1px solid var(--ring); border-radius: 12px;
  padding: 16px 18px; box-shadow: 0 1px 2px rgba(11, 11, 11, 0.04); overflow-x: auto;
}
.card table { border: 0; box-shadow: none; }

table { width: 100%; border-collapse: collapse; background: var(--surface); }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--hairline); vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); font-weight: 650; }
tr:last-child td { border-bottom: 0; }
tbody tr { transition: background 100ms; }
tbody tr:hover { background: rgba(42, 120, 214, 0.045); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.mono { font-variant-numeric: tabular-nums; white-space: nowrap; }
td.path { overflow-wrap: anywhere; }
td.empty { color: var(--muted); text-align: center; padding: 28px 12px; }

a { color: var(--accent-strong); text-decoration: none; }
a:hover { text-decoration: underline; }
.backlink { margin: -8px 0 14px; font-size: 13px; }
.query { color: var(--muted); overflow-wrap: anywhere; }
.muted { color: var(--muted); }

.method {
  display: inline-block; min-width: 52px; text-align: center;
  font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; font-weight: 700;
  padding: 3px 8px; border-radius: 6px; background: #f0efec; color: var(--ink-2);
}
.method.get { background: #e7f0fb; color: var(--accent-deep); }
.method.post { background: var(--good-bg); color: var(--good-ink); }
.method.put { background: var(--warn-bg); color: var(--warn-ink); }
.method.delete { background: var(--bad-bg); color: var(--bad-ink); }

.pill {
  display: inline-flex; align-items: center; gap: 5px; white-space: nowrap;
  padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 650;
}
.pill.ok { color: var(--good-ink); background: var(--good-bg); }
.pill.warn { color: var(--warn-ink); background: var(--warn-bg); }
.pill.bad { color: var(--bad-ink); background: var(--bad-bg); }

.toolbar { margin-bottom: 16px; }
form { display: flex; gap: 8px; }
input {
  min-width: 320px; padding: 9px 12px; font: inherit; color: var(--ink);
  background: var(--surface); border: 1px solid var(--hairline); border-radius: 8px;
  transition: border-color 120ms, box-shadow 120ms;
}
input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(42, 120, 214, 0.18); }
button {
  padding: 9px 16px; border: 0; border-radius: 8px; font: inherit; font-weight: 650;
  background: var(--accent); color: #fff; cursor: pointer; transition: background 120ms;
}
button:hover { background: var(--accent-strong); }
button:focus-visible { outline: 2px solid var(--accent-deep); outline-offset: 2px; }

.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; align-items: start; }
.summary div { border: 1px solid var(--hairline); border-radius: 10px; padding: 12px 14px; }
.summary b { font-size: 14px; }
.summary span { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
.summary b { font-weight: 600; overflow-wrap: anywhere; }

pre {
  background: var(--side-bg); color: #e8e7e0; border-radius: 10px; padding: 14px 16px;
  overflow: auto; line-height: 1.5; font-size: 13px;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
}
.error { color: var(--bad-ink); }

.login-body {
  display: flex; align-items: center; justify-content: center;
  min-height: 100vh; padding: 24px; grid-template-columns: none;
}
.login-card {
  width: 100%; max-width: 380px; background: var(--surface);
  border: 1px solid var(--ring); border-radius: 16px; padding: 32px;
  box-shadow: 0 12px 32px rgba(11, 11, 11, 0.08);
}
.login-card .brand { color: var(--ink); margin-bottom: 22px; }
.login-card .brand-mark { color: #fff; }
.login-card h1 { margin: 0 0 6px; font-size: 22px; font-weight: 650; }
.login-card p { margin: 0 0 18px; font-size: 14px; line-height: 1.5; }
.login-card form { display: block; }
.login-card label { display: block; font-size: 13px; font-weight: 600; color: var(--ink-2); margin: 14px 0 6px; }
.login-card input { display: block; width: 100%; min-width: 0; }
.login-card button { width: 100%; margin-top: 20px; padding: 11px 16px; }
.form-error {
  background: var(--bad-bg); color: var(--bad-ink); border-radius: 8px;
  padding: 10px 12px; font-size: 13px; font-weight: 600;
}

@media (max-width: 900px) {
  body { grid-template-columns: 1fr; }
  aside { flex-direction: row; align-items: center; gap: 14px; padding: 14px 16px; }
  aside nav { display: flex; gap: 4px; }
  .side-footer { margin: 0 0 0 auto; }
  .side-footer small { display: none; }
  .metrics, .grid { grid-template-columns: 1fr 1fr; }
  main { padding: 20px; }
  input { min-width: 0; width: 100%; }
}
@media (max-width: 560px) {
  .metrics, .grid { grid-template-columns: 1fr; }
}
"#;
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        css.to_string(),
    )
        .into_response()
}

fn error_response(err: anyhow::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("admin error: {err}\n"),
    )
        .into_response()
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
