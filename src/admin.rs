use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Local, NaiveDateTime, TimeZone};
use rand::{distributions::Alphanumeric, Rng};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use crate::{
    models::RequestMeta,
    storage::{Counts, Granularity, SearchPage, SearchQuery, METHODS},
    AppState,
};

const SESSION_COOKIE: &str = "wh_admin_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const LOGIN_FORM_LIMIT: usize = 16 * 1024;
const PAGE_SIZE: usize = 100;
/// Index keys examined per results page; keys are small, so this is fast.
const SCAN_BUDGET: usize = 200_000;
const STYLE_CSS: &str = include_str!("ui/style.css");
const APP_JS: &str = include_str!("ui/app.js");
const STREAM_VIEW: &str = include_str!("ui/streamview.html");
/// Quick time ranges on the requests page.
const RANGES: [(&str, &str, u64); 5] = [
    ("15m", "15 min", 15 * 60),
    ("1h", "1 hour", 60 * 60),
    ("24h", "24 hours", 24 * 60 * 60),
    ("7d", "7 days", 7 * 24 * 60 * 60),
    ("all", "All", 0),
];

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

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
        "/style.css" => asset("text/css; charset=utf-8", STYLE_CSS),
        "/app.js" => asset("text/javascript; charset=utf-8", APP_JS),
        "/login" if method == Method::GET => {
            if is_authorized(&state, req.headers()) {
                redirect(&format!("{prefix}/"))
            } else {
                login_page(&state, None, StatusCode::OK)
            }
        }
        "/login" if method == Method::POST => login_submit(state, req).await,
        "/logout" => logout(&state, req.headers()),
        // Authenticated by stream.token rather than the admin session.
        "/stream" => crate::stream::handle(state, req).await,
        p if p.starts_with("/stream/body/") => {
            let id = decode_component(p.trim_start_matches("/stream/body/"));
            crate::stream::body(state, req, &id).await
        }
        // A static shell: every event it shows comes through the token-gated stream.
        "/streamview" => stream_view(&state),
        _ if !is_authorized(&state, req.headers()) => redirect(&format!("{prefix}/login")),
        "" | "/" => overview(state, req.uri().query()).await,
        "/requests" => requests(state, req.uri().query()).await,
        p if p.starts_with("/requests/") && p.ends_with("/body") => {
            let id = decode_component(p.trim_start_matches("/requests/").trim_end_matches("/body"));
            let query = req.uri().query().map(parse_form).unwrap_or_default();
            crate::stream::serve_body(&state, &id, &query).await
        }
        p if p.starts_with("/requests/") => {
            request_detail(state, &decode_component(p.trim_start_matches("/requests/"))).await
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

pub(crate) fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((decode_component(key), decode_component(value)))
        })
        .collect()
}

pub(crate) fn form_value(form: &[(String, String)], name: &str) -> Option<String> {
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

// ---------- overview ----------

/// Dashboard range: total span, bucket granularity read from the database,
/// and the display bin width (a whole number of buckets).
struct OverviewRange {
    key: &'static str,
    label: &'static str,
    bins: u64,
    bin_secs: u64,
    granularity: Granularity,
    bin_label: &'static str,
}

const OVERVIEW_RANGES: [OverviewRange; 4] = [
    OverviewRange {
        key: "1h",
        label: "1 hour",
        bins: 60,
        bin_secs: 60,
        granularity: Granularity::Minute,
        bin_label: "minute",
    },
    OverviewRange {
        key: "24h",
        label: "24 hours",
        bins: 48,
        bin_secs: 30 * 60,
        granularity: Granularity::Minute,
        bin_label: "30 minutes",
    },
    OverviewRange {
        key: "7d",
        label: "7 days",
        bins: 56,
        bin_secs: 3 * 3600,
        granularity: Granularity::Hour,
        bin_label: "3 hours",
    },
    OverviewRange {
        key: "30d",
        label: "30 days",
        bins: 30,
        bin_secs: 86_400,
        granularity: Granularity::Hour,
        bin_label: "day",
    },
];

async fn overview(state: AppState, query: Option<&str>) -> Response {
    let prefix = admin_prefix(&state);
    let form = query.map(parse_form).unwrap_or_default();
    let selected = form_value(&form, "range").unwrap_or_default();
    let range = OVERVIEW_RANGES
        .iter()
        .find(|r| r.key == selected)
        .unwrap_or(&OVERVIEW_RANGES[1]);

    // Bins end at the next bin boundary in local time, so the last bin is
    // the current, partial one.
    let offset = i64::from(Local::now().offset().local_minus_utc());
    let now = crate::storage::epoch_secs(SystemTime::now()) as i64;
    let width = range.bin_secs as i64;
    let end = ((now + offset) / width + 1) * width - offset;
    let start = end - width * range.bins as i64;
    let to_time = |secs: i64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64);

    let (buckets, totals) = match tokio::try_join!(
        state
            .storage
            .counts(to_time(start), to_time(end), range.granularity),
        state.storage.totals()
    ) {
        Ok(result) => result,
        Err(err) => return error_response(err),
    };
    let mut bins = vec![Counts::default(); range.bins as usize];
    let mut total = Counts::default();
    for (bucket, counts) in &buckets {
        let index = (*bucket as i64 - start).div_euclid(width);
        if let Some(bin) = usize::try_from(index).ok().and_then(|i| bins.get_mut(i)) {
            *bin += *counts;
            total += *counts;
        }
    }

    let range_links: String = OVERVIEW_RANGES
        .iter()
        .map(|r| {
            format!(
                r#"<a href="{prefix}/?range={}" class="{}">{}</a>"#,
                r.key,
                if r.key == range.key { "active" } else { "" },
                r.label
            )
        })
        .collect();
    let head = format!(
        r#"<div class="page-head">
  <div><h1>Overview</h1><p>Captured requests over the last {label}.</p></div>
  <div class="actions"><span class="ranges">{range_links}</span></div>
</div>"#,
        label = range.label
    );

    let tile = |label: &str, value: String, note: &str| {
        format!(
            r#"<div class="tile"><span>{label}</span><b>{value}</b>{}</div>"#,
            if note.is_empty() {
                String::new()
            } else {
                format!("<small>{note}</small>")
            }
        )
    };
    let tiles = [
        tile("Requests", compact(total.requests), ""),
        tile("Complete", compact(total.complete), ""),
        tile(
            "Incomplete",
            compact(total.incomplete),
            "client disconnected mid-body",
        ),
        tile(
            "Limit exceeded",
            compact(total.limit_exceeded),
            "rejected with 413",
        ),
        tile("Body data received", human_bytes(total.body_bytes), ""),
    ]
    .join("");

    let chart = column_chart(range, start, width, &bins);
    let methods = method_bars(&total);
    let stored = format!(
        r#"<div class="card">
  <div class="card-head"><h2>Stored now</h2><a href="{prefix}/requests">Search requests &rarr;</a></div>
  <div class="stored">
    <div><span>Requests kept</span><b>{kept}</b><small>approximate</small></div>
    <div><span>Database on disk</span><b>{db}</b><small>metadata, indexes and journal</small></div>
    <div><span>Retention</span><b>{ttl}</b><small>default; per-path rules may differ</small></div>
  </div>
</div>"#,
        kept = compact(totals.stored_requests as u64),
        db = human_bytes(totals.db_disk_bytes),
        ttl = short_duration(state.config.retention.default_ttl),
    );

    let body = format!(
        r#"<section class="metrics">{tiles}</section>
{chart}
<section class="grid">{methods}{stored}</section>"#
    );
    page(&state, "Overview", None, "overview", &head, &body)
}

/// Requests per bin as columns: hover or focus a column for its numbers; the
/// same numbers are in the table under "Show as table".
fn column_chart(range: &OverviewRange, start: i64, width: i64, bins: &[Counts]) -> String {
    let max = bins.iter().map(|b| b.requests).max().unwrap_or(0);
    let top = nice_ceiling(max);
    let bin_start = |i: usize| {
        chrono::DateTime::<Local>::from(
            SystemTime::UNIX_EPOCH + Duration::from_secs((start + width * i as i64).max(0) as u64),
        )
    };
    let time_label = |i: usize| {
        let t = bin_start(i);
        if width >= 86_400 {
            t.format("%b %-d").to_string()
        } else if width >= 3_600 {
            t.format("%b %-d %H:%M").to_string()
        } else {
            t.format("%H:%M").to_string()
        }
    };
    let span_label = |i: usize| format!("{} – {}", time_label(i), time_label(i + 1));

    let columns: String = bins
        .iter()
        .enumerate()
        .map(|(i, bin)| {
            let pct = if top == 0 { 0.0 } else { bin.requests as f64 * 100.0 / top as f64 };
            let detail = if bin.incomplete + bin.limit_exceeded > 0 {
                format!(
                    "{} incomplete · {} over limit",
                    bin.incomplete, bin.limit_exceeded
                )
            } else {
                String::new()
            };
            let value = format!(
                "{} request{}",
                bin.requests,
                if bin.requests == 1 { "" } else { "s" }
            );
            format!(
                r#"<div class="col" tabindex="0" data-value="{value}" data-title="{title}" data-detail="{detail}"><span class="col-bar{empty}" style="height:{pct:.2}%"></span></div>"#,
                title = escape(&span_label(i)),
                detail = escape(&detail),
                empty = if bin.requests == 0 { " zero" } else { "" },
            )
        })
        .collect();
    let ticks: String = [(top, 100), (top / 2, 50), (0, 0)]
        .iter()
        .map(|(value, at)| {
            format!(
                r#"<span class="tick" style="bottom:{at}%"><i>{}</i></span>"#,
                compact(*value)
            )
        })
        .collect();
    let last = bins.len().saturating_sub(1);
    let x_labels = format!(
        r#"<span>{}</span><span>{}</span><span>{}</span>"#,
        escape(&time_label(0)),
        escape(&time_label(bins.len() / 2)),
        escape(&time_label(last)),
    );
    let table_rows: String = bins
        .iter()
        .enumerate()
        .rev()
        .map(|(i, bin)| {
            format!(
                r#"<tr><td>{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td><td class="num">{}</td></tr>"#,
                escape(&span_label(i)),
                bin.requests,
                bin.complete,
                bin.incomplete,
                bin.limit_exceeded
            )
        })
        .collect();

    format!(
        r#"<div class="card chart-card">
  <div class="card-head"><h2>Requests per {bin_label}</h2><span class="muted">peak {peak}</span></div>
  <div class="chart" role="img" aria-label="Requests per {bin_label} over the last {label}; peak {peak}.">
    <div class="chart-plot">{ticks}<div class="cols">{columns}</div></div>
    <div class="chart-x">{x_labels}</div>
  </div>
  <details class="chart-table"><summary>Show as table</summary>
    <table><thead><tr><th>Time</th><th class="num">Requests</th><th class="num">Complete</th><th class="num">Incomplete</th><th class="num">Over limit</th></tr></thead><tbody>{table_rows}</tbody></table>
  </details>
</div>"#,
        bin_label = range.bin_label,
        label = range.label,
        peak = compact(max),
    )
}

fn method_bars(total: &Counts) -> String {
    let max = total.methods.iter().copied().max().unwrap_or(0).max(1);
    let rows: String = METHODS
        .iter()
        .zip(total.methods)
        .filter(|(_, count)| *count > 0)
        .map(|(method, count)| {
            format!(
                r#"<div class="hbar"><span class="hbar-label">{chip}</span><span class="hbar-track"><span class="hbar-fill" style="width:{pct:.2}%"></span></span><span class="hbar-value">{value}</span></div>"#,
                chip = method_chip(method),
                pct = count as f64 * 100.0 / max as f64,
                value = compact(count),
            )
        })
        .collect();
    format!(
        r#"<div class="card"><div class="card-head"><h2>Methods</h2></div>{}</div>"#,
        if rows.is_empty() {
            r#"<p class="muted">No requests in this range.</p>"#.to_string()
        } else {
            rows
        }
    )
}

/// Smallest 1, 2 or 5 × 10^k at or above `value`, for a clean axis top.
fn nice_ceiling(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let mut magnitude = 1u64;
    while magnitude.saturating_mul(10) <= value {
        magnitude *= 10;
    }
    [1, 2, 5, 10]
        .iter()
        .map(|step| step * magnitude)
        .find(|candidate| *candidate >= value)
        .unwrap_or(value)
}

/// 1,284 → "1,284"; 12,900 → "12.9K"; 4,200,000 → "4.2M".
fn compact(value: u64) -> String {
    match value {
        0..=9_999 => {
            let digits = value.to_string();
            let mut out = String::new();
            for (i, ch) in digits.chars().enumerate() {
                if i > 0 && (digits.len() - i).is_multiple_of(3) {
                    out.push(',');
                }
                out.push(ch);
            }
            out
        }
        10_000..=999_999 => format!("{:.1}K", value as f64 / 1_000.0),
        _ => format!("{:.1}M", value as f64 / 1_000_000.0),
    }
}

// ---------- requests explorer ----------

/// Parsed `/requests` query string, re-encodable for links.
#[derive(Default, Clone)]
struct Filters {
    path: String,
    range: String,
    from: String,
    to: String,
}

impl Filters {
    fn parse(query: Option<&str>) -> (Self, Option<String>) {
        let form = query.map(parse_form).unwrap_or_default();
        let get = |name| {
            form_value(&form, name)
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        let mut filters = Self {
            path: get("path"),
            range: get("range"),
            from: get("from"),
            to: get("to"),
        };
        if !filters.path.is_empty() && !filters.path.starts_with('/') {
            filters.path.insert(0, '/');
        }
        let custom = !filters.from.is_empty() || !filters.to.is_empty();
        if custom {
            filters.range = "custom".to_string();
        } else if !RANGES.iter().any(|(key, _, _)| *key == filters.range) {
            filters.range = "all".to_string();
        }
        (
            filters,
            form_value(&form, "before").filter(|b| !b.is_empty()),
        )
    }

    fn url(&self, prefix: &str, overrides: &[(&str, &str)]) -> String {
        let mut pairs: Vec<(&str, &str)> = vec![
            ("path", &self.path),
            ("range", &self.range),
            ("from", &self.from),
            ("to", &self.to),
        ];
        for (key, value) in overrides {
            match pairs.iter_mut().find(|(k, _)| k == key) {
                Some(pair) => pair.1 = value,
                None => pairs.push((key, value)),
            }
        }
        let query: Vec<String> = pairs
            .iter()
            .filter(|(k, v)| !v.is_empty() && !(*k == "range" && (*v == "all" || *v == "custom")))
            .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
            .collect();
        if query.is_empty() {
            format!("{prefix}/requests")
        } else {
            format!("{prefix}/requests?{}", query.join("&"))
        }
    }

    fn window(&self) -> (Option<SystemTime>, Option<SystemTime>) {
        if self.range == "custom" {
            return (parse_local_time(&self.from), parse_local_time(&self.to));
        }
        let secs = RANGES
            .iter()
            .find(|(key, _, _)| *key == self.range)
            .map_or(0, |(_, _, secs)| *secs);
        let from = (secs > 0).then(|| SystemTime::now() - Duration::from_secs(secs));
        (from, None)
    }
}

/// `datetime-local` input values, in the server's time zone.
fn parse_local_time(value: &str) -> Option<SystemTime> {
    let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M"))
        .ok()?;
    Local
        .from_local_datetime(&naive)
        .earliest()
        .map(SystemTime::from)
}

async fn requests(state: AppState, query: Option<&str>) -> Response {
    let prefix = admin_prefix(&state);
    let (filters, before) = Filters::parse(query);
    let (from, to) = filters.window();
    let cursor = before
        .as_deref()
        .and_then(|b| URL_SAFE_NO_PAD.decode(b).ok());
    let search = SearchQuery {
        prefix: (!filters.path.is_empty()).then(|| filters.path.clone()),
        from,
        to,
        before: cursor.clone(),
        limit: PAGE_SIZE,
        scan_budget: SCAN_BUDGET,
    };
    let page_data = match state.storage.search(search).await {
        Ok(page) => page,
        Err(err) => return error_response(err),
    };

    let range_links: String = RANGES
        .iter()
        .map(|(key, label, _)| {
            format!(
                r#"<a href="{}" class="{}">{label}</a>"#,
                escape(&filters.url(&prefix, &[("range", key), ("from", ""), ("to", "")])),
                if filters.range == *key { "active" } else { "" },
            )
        })
        .collect();
    let custom = filters.range == "custom";

    let filter_bar = format!(
        r#"<form class="filters" method="get" action="{prefix}/requests">
  <label class="grow">Path prefix
    <input name="path" value="{path}" placeholder="All paths, or e.g. /api/v1" spellcheck="false" autocomplete="off">
  </label>
  <input type="hidden" name="range" value="{range}">
  <label>Time range <span class="ranges">{range_links}</span></label>
  <label>From <input type="datetime-local" name="from" value="{from}" step="1"></label>
  <label>To <input type="datetime-local" name="to" value="{to}" step="1"></label>
  <button type="submit">Search</button>
  {reset}
</form>"#,
        path = escape(&filters.path),
        range = if custom { "" } else { filters.range.as_str() },
        from = escape(&filters.from),
        to = escape(&filters.to),
        reset = if filters.path.is_empty() && filters.range == "all" {
            String::new()
        } else {
            format!(r#"<a class="button secondary" href="{prefix}/requests">Reset</a>"#)
        },
    );

    let notice = if page_data.budget_exhausted {
        format!(
            r#"<div class="notice">Searched back to {} without filling the page. <a class="button secondary small" href="{}">Keep searching</a></div>"#,
            page_data
                .scanned_back_to
                .map(format_system_time)
                .unwrap_or_else(|| "the start".to_string()),
            escape(&next_url(&filters, &prefix, &page_data)),
        )
    } else {
        String::new()
    };

    let rows = if page_data.records.is_empty() {
        format!(
            r#"<tr><td colspan="6" class="empty">{}</td></tr>"#,
            if page_data.budget_exhausted {
                "No matches yet in the part searched so far."
            } else {
                "No requests match these filters."
            }
        )
    } else {
        page_data
            .records
            .iter()
            .map(|meta| request_row(&prefix, meta))
            .collect()
    };

    let mut pager_links = Vec::new();
    if cursor.is_some() {
        pager_links.push(format!(
            r#"<a class="button secondary small" href="{}">&larr; Newest</a>"#,
            escape(&filters.url(&prefix, &[]))
        ));
    }
    if page_data.next.is_some() && !page_data.budget_exhausted {
        pager_links.push(format!(
            r#"<a class="button secondary small" href="{}">Older &rarr;</a>"#,
            escape(&next_url(&filters, &prefix, &page_data))
        ));
    }
    let pager = format!(
        r#"<div class="pager"><span>{} shown, newest first{}</span><span style="display:flex;gap:8px">{}</span></div>"#,
        page_data.records.len(),
        if cursor.is_some() {
            " · older page"
        } else {
            ""
        },
        pager_links.join("")
    );

    let body = format!(
        r#"{filter_bar}{notice}
<div class="card flush">
<table class="results"><thead><tr><th>Time</th><th>Method</th><th>Path</th><th class="num">Body</th><th class="ctype">Content type</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>
{pager}
</div>"#
    );
    let subtitle = if filters.path.is_empty() {
        "Every captured request, newest first.".to_string()
    } else {
        format!("Paths starting with {}", filters.path)
    };
    page(&state, "Requests", Some(&subtitle), "requests", "", &body)
}

fn next_url(filters: &Filters, prefix: &str, page: &SearchPage) -> String {
    let before = page
        .next
        .as_deref()
        .map(|key| URL_SAFE_NO_PAD.encode(key))
        .unwrap_or_default();
    filters.url(prefix, &[("before", &before)])
}

fn request_row(prefix: &str, meta: &RequestMeta) -> String {
    let href = format!("{prefix}/requests/{}", urlencoding::encode(&meta.id));
    format!(
        r#"<tr data-href="{href}">
<td class="time">{time}<small>{date}</small></td>
<td>{method}</td>
<td class="path"><a href="{href}">{path}</a>{query}</td>
<td class="num">{size}</td>
<td class="ctype">{ctype}</td>
<td>{status}</td>
</tr>"#,
        href = escape(&href),
        time = meta.received_at.format("%H:%M:%S%.3f"),
        date = meta.received_at.format("%Y-%m-%d"),
        method = method_chip(&meta.method),
        path = escape(&meta.path),
        query = meta
            .query
            .as_ref()
            .map(|q| format!(r#"<span class="query">?{}</span>"#, escape(q)))
            .unwrap_or_default(),
        size = human_bytes(meta.body.original_size),
        ctype = escape(meta.body.content_type.as_deref().unwrap_or("")),
        status = body_status(meta),
    )
}

// ---------- request detail ----------

async fn request_detail(state: AppState, id: &str) -> Response {
    let prefix = admin_prefix(&state);
    let meta = match state.storage.get(id).await {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            let body = format!(
                r#"<p class="crumbs"><a href="{prefix}/requests">&larr; Requests</a></p>
<div class="card"><p>No request with id <span class="mono">{}</span>. It may have expired and been removed by retention.</p></div>"#,
                escape(id)
            );
            let mut response = page(&state, "Request not found", None, "requests", "", &body);
            *response.status_mut() = StatusCode::NOT_FOUND;
            return response;
        }
        Err(err) => return error_response(err),
    };

    let body_url = state
        .storage
        .blob_path(&meta)
        .map(|_| format!("{prefix}/requests/{}/body", urlencoding::encode(&meta.id)));
    let data = serde_json::json!({ "meta": &meta, "bodyUrl": body_url });
    // JSON inside <script>: escape `<` so the data can never close the tag.
    let data = data.to_string().replace('<', "\\u003c");

    let header_count = meta
        .headers
        .values()
        .map(|v| v.as_array().map_or(1, Vec::len))
        .sum::<usize>();
    let header_rows: String = {
        let mut names: Vec<_> = meta.headers.keys().collect();
        names.sort();
        names
            .into_iter()
            .flat_map(|name| {
                let values = match &meta.headers[name] {
                    serde_json::Value::Array(values) => values.clone(),
                    other => vec![other.clone()],
                };
                values.into_iter().map(move |value| {
                    format!(
                        "<tr><td>{}</td><td>{}</td></tr>",
                        escape(name),
                        escape(value.as_str().unwrap_or(&value.to_string()))
                    )
                })
            })
            .collect()
    };
    let query_params = meta.query.as_deref().map(parse_form).unwrap_or_default();
    let query_rows: String = if query_params.is_empty() {
        r#"<tr><td colspan="2" class="empty">No query string.</td></tr>"#.to_string()
    } else {
        query_params
            .iter()
            .map(|(k, v)| format!("<tr><td>{}</td><td>{}</td></tr>", escape(k), escape(v)))
            .collect()
    };
    let raw = serde_json::to_string_pretty(&meta).unwrap_or_default();

    let size = if meta.body.stored {
        format!(
            "{} <span class=\"muted\">({} stored{})</span>",
            human_bytes(meta.body.original_size),
            human_bytes(meta.body.stored_size),
            meta.body
                .encoding
                .as_deref()
                .map(|e| format!(", {e}"))
                .unwrap_or_default()
        )
    } else {
        human_bytes(meta.body.original_size)
    };
    let error = meta
        .body
        .error
        .as_deref()
        .map(|e| {
            format!(
                r#"<div><span>Error</span><b class="error">{}</b></div>"#,
                escape(e)
            )
        })
        .unwrap_or_default();

    let head = format!(
        r#"<p class="crumbs"><a href="{prefix}/requests">&larr; Requests</a></p>
<div class="page-head">
  <div style="min-width:0">
    <div class="req-title">{method}<h1>{path}</h1></div>
    <p>{received} &middot; <span class="mono">{id}</span></p>
  </div>
  <div class="actions"><button id="copy-curl" type="button" class="secondary">Copy as cURL</button></div>
</div>"#,
        method = method_chip(&meta.method),
        path = escape(&format!(
            "{}{}",
            meta.path,
            meta.query
                .as_deref()
                .map(|q| format!("?{q}"))
                .unwrap_or_default()
        )),
        received = escape(
            &meta
                .received_at
                .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                .to_string()
        ),
        id = escape(&meta.id),
    );
    let body = format!(
        r#"<section class="summary">
  <div><span>Status</span><b>{status}</b></div>
  <div><span>Body</span><b>{size}</b></div>
  <div><span>Content type</span><b>{ctype}</b></div>
  <div><span>Body mode</span><b>{mode}</b></div>
  {error}
</section>
<div class="card">
  <div class="tabs" role="tablist">
    <button type="button" data-tab="body">Body</button>
    <button type="button" data-tab="headers">Headers<small>{header_count}</small></button>
    <button type="button" data-tab="query">Query<small>{query_count}</small></button>
    <button type="button" data-tab="raw">Raw</button>
  </div>
  <div id="tab-body"><p class="muted">Loading&hellip;</p></div>
  <div id="tab-headers" hidden><table class="kv"><tbody>{header_rows}</tbody></table></div>
  <div id="tab-query" hidden><table class="kv"><tbody>{query_rows}</tbody></table></div>
  <div id="tab-raw" hidden><pre>{raw}</pre></div>
</div>
<script type="application/json" id="req-data">{data}</script>"#,
        status = body_status(&meta),
        ctype = escape(meta.body.content_type.as_deref().unwrap_or("—")),
        mode = escape(&meta.body.mode),
        query_count = query_params.len(),
        raw = escape(&raw),
    );
    page(&state, &meta.path, None, "requests", &head, &body)
}

// ---------- live stream ----------

fn stream_view(state: &AppState) -> Response {
    let prefix = admin_prefix(state);
    // JSON string literal, with `<` escaped so it cannot close the script tag.
    let prefix_js = serde_json::to_string(&prefix)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('<', "\\u003c");
    let token_required = if state.config.stream.token.is_some() {
        "true"
    } else {
        "false"
    };
    let body = STREAM_VIEW
        .replace("__ADMIN_PREFIX__", &prefix_js)
        .replace("__TOKEN_REQUIRED__", token_required);
    page(
        state,
        "Live stream",
        Some("Requests as they arrive. Expand a card to load its body."),
        "stream",
        "",
        &body,
    )
}

// ---------- shared rendering ----------

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

fn admin_prefix(state: &AppState) -> String {
    state
        .config
        .server
        .admin_prefix
        .trim_end_matches('/')
        .to_string()
}

/// `30 days`, `2 hours`, `45 min`: coarse, for display only.
fn short_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let (value, unit) = if secs >= 86_400 && secs.is_multiple_of(86_400) {
        (secs / 86_400, "day")
    } else if secs >= 3_600 && secs.is_multiple_of(3_600) {
        (secs / 3_600, "hour")
    } else if secs >= 60 {
        (secs / 60, "min")
    } else {
        (secs, "sec")
    };
    let plural = if value == 1 || unit == "min" || unit == "sec" {
        ""
    } else {
        "s"
    };
    format!("{value} {unit}{plural}")
}

fn format_system_time(time: SystemTime) -> String {
    chrono::DateTime::<Local>::from(time)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

fn login_page(state: &AppState, error: Option<&str>, status: StatusCode) -> Response {
    let prefix = admin_prefix(state);
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

const ICON_OVERVIEW: &str = r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1.2"/><rect x="9" y="1.5" width="5.5" height="5.5" rx="1.2"/><rect x="1.5" y="9" width="5.5" height="5.5" rx="1.2"/><rect x="9" y="9" width="5.5" height="5.5" rx="1.2"/></svg>"#;
const ICON_REQUESTS: &str = r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M2 3.5h12M2 8h12M2 12.5h8"/></svg>"#;
const ICON_STREAM: &str = r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><circle cx="8" cy="8" r="1.6"/><path d="M4.8 4.8a4.5 4.5 0 0 0 0 6.4M11.2 4.8a4.5 4.5 0 0 1 0 6.4M2.6 2.6a7.6 7.6 0 0 0 0 10.8M13.4 2.6a7.6 7.6 0 0 1 0 10.8"/></svg>"#;

/// Shared layout. `head` replaces the default title block when non-empty.
fn page(
    state: &AppState,
    title: &str,
    subtitle: Option<&str>,
    active: &str,
    head: &str,
    body: &str,
) -> Response {
    let prefix = admin_prefix(state);
    let nav = [
        ("overview", "/", "Overview", ICON_OVERVIEW),
        ("requests", "/requests", "Requests", ICON_REQUESTS),
        ("stream", "/streamview", "Live stream", ICON_STREAM),
    ]
    .iter()
    .map(|(key, href, label, icon)| {
        format!(
            r#"<a href="{prefix}{href}"{}>{icon}<span>{label}</span></a>"#,
            if *key == active {
                r#" class="active""#
            } else {
                ""
            }
        )
    })
    .collect::<String>();
    let logout = if state.config.admin.password.is_some() {
        format!("<a class=\"logout\" href=\"{prefix}/logout\">Sign out</a>")
    } else {
        String::new()
    };
    let head = if head.is_empty() {
        format!(
            r#"<div class="page-head"><div><h1>{}</h1>{}</div></div>"#,
            escape(title),
            subtitle
                .map(|s| format!("<p>{}</p>", escape(s)))
                .unwrap_or_default()
        )
    } else {
        head.to_string()
    };
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} &middot; Webhook Debug</title>
  <link rel="stylesheet" href="{prefix}/style.css">
  <script src="{prefix}/app.js"></script>
</head>
<body>
  <aside>
    <div class="brand"><span class="brand-mark">&#9889;</span><span class="brand-name">Webhook Debug</span></div>
    <nav>{nav}</nav>
    <div class="side-footer">
      <small><b>Database</b>{db}</small>
      <small><b>Blobs</b>{blobs}</small>
      {logout}
    </div>
  </aside>
  <main>
    {head}
    {body}
  </main>
</body>
</html>"#,
        title = escape(title),
        db = escape(&state.config.storage.db.display().to_string()),
        blobs = escape(&state.config.storage.blobs.display().to_string()),
    );
    Html(html).into_response()
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
