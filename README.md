# webhook

A webhook capture and debugging server written in Rust. It accepts HTTP requests on **any** method and path, persists the full request (metadata + streamed body) to disk, replies with a configurable response, and ships a built-in admin UI for browsing captured requests.

Useful for debugging third-party webhook integrations, inspecting what a client actually sends, or acting as a configurable stub endpoint during development.

## Features

- **Catch-all capture** — every method (`GET`, `POST`, `PUT`, ...) on every non-admin path is recorded.
- **Streamed body persistence** — bodies are written to disk as they arrive (never buffered whole in memory), optionally gzip-compressed, with configurable size limits.
- **JSON metadata sidecar** — method, path, query, headers, timing, and body stats stored as JSON next to each body file.
- **Path/time-partitioned storage layout** — records are laid out by request path and timestamp for easy `find`/`grep`.
- **TTL-based retention** — captures write folder-level expiry markers; a background worker deletes expired folders, orphaned files, and empty folders on a schedule.
- **Configurable responses** — global and per-path-prefix response status, headers, and body (capture metadata JSON, static text, or static JSON).
- **Admin UI** — dashboard, bounded recent-request list with path filtering, and request detail pages with body preview, protected by an optional login (bcrypt password, in-memory sessions).
- **Safe filesystem mapping** — URL path segments are reversibly percent-encoded for filesystem use; the original path is always preserved verbatim in metadata.

## Quick start

```sh
# build
cargo build --release

# generate a default config
./target/release/webhook genconfig > config.toml

# run with a config file
./target/release/webhook run -c config.toml

# or via cargo
cargo run -- genconfig > config.toml
cargo run -- run -c config.toml
```

Send it anything:

```sh
curl -X POST http://127.0.0.1:8080/orders/created?source=stripe \
  -H 'content-type: application/json' \
  -d '{"id": 42, "status": "paid"}'
```

Response:

```json
{
  "success": true,
  "id": "31_922460000_myhost_AbCdEf1234567890",
  "complete": true,
  "body_stored": true,
  "total_bytes_in": 456,
  "body_length": 28,
  "stored_body_length": 47,
  "header_length": 428,
  "limit_exceeded": false,
  "metadata_saved": true,
  "error": null
}
```

Then browse captured requests in the admin UI at `http://127.0.0.1:8080/_wh_admin/`.

## Command line

```text
webhook [COMMAND]

Subcommands:
  run             Run the webhook capture server
  genconfig       Print a default TOML config to stdout
  genpassword     Prompt for a password and print its bcrypt hash for admin.password
  verifypassword  Check whether a plaintext password matches a stored (bcrypt or plaintext) value

Run options:
  -c, --config <FILE>   Config file path [env: WEBHOOK_CONFIG] [default: config.toml]
```

Logging is JSON via `tracing`, controlled with `RUST_LOG` (e.g. `RUST_LOG=info`).

## Releases

Tagged versions are built for Linux (GNU and musl), macOS, Windows, and FreeBSD
on x86_64 and ARM64. Download the archive matching your platform from the
[GitHub Releases page](https://github.com/wushilin/webhook/releases). Archives
are named `webhook-<version>-<target>.tar.gz` and include the executable, this
README, the example config, and the license.

## Configuration

Configuration is TOML. Every section and key is optional — missing keys use the defaults shown below. Generate a default file with `webhook genconfig > config.toml`, or see [`config.example.toml`](config.example.toml) for a complete working example with sample path rules.

### Full example

```toml
[server]
bind = "127.0.0.1:8080"        # listen address
admin_prefix = "/_wh_admin"    # URL prefix for the admin UI (must start with /_, at least 7 chars, end with admin)

[admin]
username = "admin"
# bcrypt hash (recommended; generate with `webhook genpassword`)
# or a plaintext password. Comment out to disable the admin login entirely.
password = "$2b$12$..."

[storage]
backend = "local"              # only "local" is implemented
root = "./data"                # storage root directory

[retention]
default_ttl = "30d"            # how long records are kept
min_ttl = "2h"                 # shorter per-path TTLs are raised to this floor
cleanup_interval = "1h"        # how often the cleanup worker runs
prune_grace = "1h"             # empty folders / orphaned files are only removed
                               # once untouched this long

[body]
mode = "compressed"            # compressed | raw | metadata_only
preview_limit = "5MiB"         # max original body size shown in the admin UI preview
max_body_size = "100MiB"       # requests with a larger body are rejected with 413

[stream]
token = "change-me"            # required by the websocket stream; unset = open stream
buffer = 1024                  # events buffered per consumer before its oldest are dropped

# Default response for successful captures
[responder]
status = 200
body = "metadata_json"         # metadata_json | { static_text = "..." } | { static_json = {...} }
headers = { content-type = "application/json; charset=utf-8" }

# Per-path-prefix response overrides (applied in order; later, more specific
# rules override earlier ones)
[[responders]]
match = "/api1"
status = 200
body = { static_json = { success = true } }
headers = { x-webhook-debug = "api1" }

[[responders]]
match = "/api1/test2"
status = 202
body = { static_text = "accepted" }
headers = { content-type = "text/plain; charset=utf-8", x-webhook-debug = "api1-test2" }

# Per-path-prefix capture overrides
[[paths]]
match = "/large-events"
ttl = "7d"
body_mode = "metadata_only"    # count the bytes, don't store the body

[[paths]]
match = "/debug"
ttl = "30d"
body_mode = "compressed"
preview_limit = "5MiB"
max_body_size = "100MiB"
```

Durations use [humantime](https://docs.rs/humantime) syntax (`30d`, `1h`, `15m`, `90s`). Sizes accept `B`, `KB`/`KiB`, `MB`/`MiB`, `GB`/`GiB` (both spellings are 1024-based).

### `[server]`

| Key | Default | Description |
|---|---|---|
| `bind` | `127.0.0.1:8080` | Socket address to listen on |
| `admin_prefix` | `/_wh_admin` | Path prefix reserved for the admin UI; trailing slashes are trimmed, and the value must start with `/_`, be at least 7 characters long, and end with `admin` |

### `[admin]`

| Key | Default | Description |
|---|---|---|
| `username` | `admin` | Admin login username |
| `password` | *(unset)* | bcrypt hash (recommended) or plaintext. When unset, the admin UI is **open** and a warning is logged at startup |

### `[stream]`

| Key | Default | Description |
|---|---|---|
| `token` | *(unset)* | Token required to open the request stream. When unset, the stream is **open** to anyone and a warning is logged at startup |
| `buffer` | `1024` | Events buffered per consumer. A consumer that falls further behind loses its oldest events |

Sessions and the recent-request browser are kept in memory — restarting the server signs everyone out and starts a new recent-request view.

Generate a password hash:

```sh
$ webhook genpassword
Password:
Confirm password:
$2b$12$...

# verify a plaintext password against a stored value
$ webhook verifypassword
```

### `[storage]`

| Key | Default | Description |
|---|---|---|
| `backend` | `local` | Storage backend (only `local` is implemented) |
| `root` | `./data` | Directory where captures are stored |

### `[retention]`

| Key | Default | Description |
|---|---|---|
| `default_ttl` | `30d` | Records older than this are deleted (overridable per `[[paths]]` rule) |
| `min_ttl` | `2h` | Minimum effective TTL; shorter configured TTLs are coalesced to this value |
| `cleanup_interval` | `1h` | How often the cleanup worker runs |
| `prune_grace` | `1h` | Orphaned files and empty folders are only removed once untouched this long |

### `[body]`

| Key | Default | Description |
|---|---|---|
| `mode` | `compressed` | `compressed` (gzip), `raw` (as received), or `metadata_only` (body counted but not stored) |
| `preview_limit` | `5MiB` | Bodies up to this original size are previewable in the admin UI (must be ≤ `max_body_size`) |
| `max_body_size` | `100MiB` | Larger bodies are rejected with `413 Payload Too Large` |

### `[responder]` and `[[responders]]`

Control what a **successful** capture returns to the client. `[responder]` sets the global default; each `[[responders]]` rule overrides it for a path prefix (exact match or `prefix/`). Rules are applied in config order, so put more specific prefixes later — the last matching rule wins for each field.

Body variants:

- `body = "metadata_json"` — the capture summary JSON shown above (default)
- `body = { static_text = "ok" }` — fixed plaintext
- `body = { static_json = { success = true } }` — fixed JSON

Failed captures ignore responder rules and always return capture-health statuses (`413`, `400`, `500`) with metadata JSON.

### `[[paths]]`

Per-path-prefix capture behavior. Each rule may override `ttl`, `body_mode`, `preview_limit`, and `max_body_size`; unset keys inherit the globals. Matching is by exact path or path-prefix, applied in config order (last match wins per field).

## Storage layout

For `POST /test1/test2/test3?aaafe=afafw` received at 16:20:31, local storage writes:

```text
data/test1/test2/test3/2026/07/15/16/20/31/
  .expires_at                                           # Unix epoch seconds for folder expiry
  31_922460000_myhost_AbCdEf1234567890.json          # metadata
  31_922460000_myhost_AbCdEf1234567890.body.bin.gz   # body (".body.bin" in raw mode)
```

The metadata JSON looks like:

```json
{
  "id": "31_922460000_myhost_AbCdEf1234567890",
  "received_at": "2026-07-15T16:20:31.922460+08:00",
  "method": "POST",
  "path": "/test1/test2/test3",
  "query": "aaafe=afafw",
  "headers": { "host": "127.0.0.1:8080", "content-type": "application/json" },
  "body": {
    "stored": true,
    "complete": true,
    "mode": "compressed",
    "object": "31_922460000_myhost_AbCdEf1234567890.body.bin.gz",
    "encoding": "gzip",
    "original_size": 28,
    "stored_size": 47,
    "content_type": "application/json",
    "previewable": true,
    "limit_exceeded": false,
    "error": null
  }
}
```

Path segments are URL-decoded and then reversibly percent-encoded for filesystem safety. Ordinary readable characters, including Unicode, are kept. Literal `%`, path separators inside encoded segments, control characters, Windows-forbidden characters, `.` / `..`, trailing dot/space, and Windows device names are escaped. The original request path is always preserved verbatim in the metadata.

The body file is written as a stream. If a client disconnects mid-body or an unknown-length body crosses `max_body_size`, the metadata records `complete = false` (and `limit_exceeded = true` in the latter case).

## Large bodies

- If `Content-Length` exceeds `max_body_size`, the request is rejected upfront with `413 Payload Too Large` (metadata is still written).
- If `Content-Length` is missing, the server streams until the limit is crossed, closes the body file, records `limit_exceeded = true`, and returns `413`.

## Retention and cleanup

At capture time, the server resolves the path rule, applies `max(rule_ttl, min_ttl)`, and writes a `.expires_at` marker into the second-level capture folder. Every `cleanup_interval`, cleanup streams through the storage tree, deletes folders whose marker is expired without opening each metadata JSON, and prunes empty parent folders after their children are gone. It separately sweeps garbage such as stale `*.json.tmp`, stale `.expires_at.*.tmp`, and body files whose metadata was never written; that garbage sweep only touches files and folders untouched for `prune_grace`.

## Admin UI

Served under `server.admin_prefix` (default `/_wh_admin`):

| Route | Description |
|---|---|
| `/_wh_admin/` | Dashboard with in-memory counters since process start and top 20 active paths; per-path counts evict after 7 days without a hit or when the 5k active-path cap is exceeded, then restart from 1 when seen again |
| `/_wh_admin/requests` | Last 5000 requests since process start, filterable by path |
| `/_wh_admin/requests/<id>` | Request detail with headers and body preview for requests still in the recent-request buffer |
| `/_wh_admin/login`, `/logout` | Session login/logout (only when `admin.password` is set) |
| `/_wh_admin/stream` | WebSocket stream of captured requests (see below) |
| `/_wh_admin/streamview` | Live browser view of the stream (see below) |

Paths that merely resemble the admin prefix (e.g. `/_wh_adminfoo`) are still captured as webhooks.

## Request stream

`/_wh_admin/stream` is a WebSocket that pushes one JSON text message for each request captured after you connect. It uses `stream.token` rather than the admin login, sent as `Authorization: Bearer <token>` or `?token=<token>`. If `stream.token` is unset, the stream needs no token.

Every connection is an independent consumer that receives its own copy of every event. A slow consumer never holds up the others or the capture path. If a consumer falls more than `stream.buffer` events behind, it loses its oldest events. Events from before you connect are not replayed.

Add `?prefix=/api/v1` to receive only requests whose path starts with `/api/v1`. This is a plain string match, so `/api/v1` also matches `/api/v1x`; use `/api/v1/` to match only paths under `/api/v1/`. A leading `/` is added if you leave it out.

```sh
websocat -H 'Authorization: Bearer change-me' 'ws://127.0.0.1:8080/_wh_admin/stream?prefix=/api/v1'
```

### Live view

`/_wh_admin/streamview` shows the stream in the browser. Enter the stream token and an optional path prefix, and new requests appear on top as cards. Click a card to expand it and see:

- **Summary:** size, content type and request id.
- **Body:** fetched from the body endpoint only when you expand the card, first 256KiB, with a **Load all** button for the rest. It's shown as pretty-printed JSON, a form field list, plain text, or a hex dump for binary bodies, with buttons to copy or download it.
- **Headers and raw event:** every header, plus the raw JSON event.

**Pause** only freezes the page. The WebSocket stays connected, and new requests wait in a banner until you resume. The page keeps the latest 500 cards and drops the oldest. It reconnects automatically if the connection drops.

The page itself is served without the admin login, because it holds no data; everything it shows comes through the token-protected stream. You can prefill the form with `/_wh_admin/streamview?token=…&prefix=…`. The token is then removed from the address bar, and the page remembers the token and prefix in the browser's local storage.

### Message format

- **One request, one message.** Each captured request is sent as exactly one WebSocket **text** message containing one UTF-8 JSON object: an envelope with the request metadata. **Bodies are never sent over the stream.** Fetch them from `body_url` when you need them, so a burst of large requests costs the stream almost nothing.
- **Ordering.** Messages arrive in the order the requests finished being captured. A message is sent only after that request's body file and metadata JSON have been written, so `body_url` is ready to fetch as soon as the message arrives.
- **Client to server.** Anything the client sends is ignored, apart from Close. Pings are answered automatically.
- **Shutdown.** When the server shuts down, it sends a Close frame.

Message fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Capture id, the same one used in the admin UI and in the capture response |
| `received_at` | string | RFC 3339 timestamp with the server's local offset |
| `method` | string | HTTP method |
| `path` | string | Request path, still percent-encoded as received |
| `query` | string \| null | Raw query string without the `?` |
| `headers` | object | Header name (lowercase) → string, or an array of strings when the header repeats |
| `body` | object | Stored body metadata, the same as in the metadata JSON on disk: `stored`, `complete`, `mode`, `object`, `encoding`, `original_size` (bytes received), `stored_size` (bytes on disk), `content_type`, `previewable`, `limit_exceeded`, `error` |
| `body_url` | string \| null | Path of the body endpoint for this request. `null` when no body file was written, for example in `metadata_only` mode or when the request was rejected up front by `Content-Length` |

Example (formatted here for readability; on the wire it is a single line):

```json
{
  "id": "07_123456789_myhost_AbCdEfGhIjKlMnOp",
  "received_at": "2026-10-12T09:15:07.123456789+08:00",
  "method": "POST",
  "path": "/api/v1/hook",
  "query": "source=github",
  "headers": { "content-type": "application/json", "content-length": "11" },
  "body": {
    "stored": true, "complete": true, "mode": "compressed",
    "object": "07_123456789_myhost_AbCdEfGhIjKlMnOp.body.bin.gz",
    "encoding": "gzip", "original_size": 11, "stored_size": 31,
    "content_type": "application/json", "previewable": true,
    "limit_exceeded": false, "error": null
  },
  "body_url": "/_wh_admin/stream/body/YXBpL3YxL2hvb2svMjAyNi8xMC8xMi8wOS8xNS8wNy8wN18xMjM0NTY3ODlfbXlob3N0X0FiQ2RFZkdoSWpLbE1uT3AuYm9keS5iaW4uZ3o"
}
```

### Fetching a body

`GET <body_url>` returns the original, uncompressed body as stored on disk. It uses the same token rules as the stream (`Authorization: Bearer <token>` or `?token=`).

- **Reference:** the last part of `body_url` is the body file's location under `storage.root`, base64url-encoded. It works for as long as the request is retained (`retention.default_ttl`), not only while it's in the live stream. The server rejects any reference that would point outside the storage root.
- **`?limit=N`:** returns only the first N bytes of the body. Without it you get the whole body, streamed from disk and gunzipped on the fly, so even large bodies aren't buffered in memory.
- **Response:** always `application/octet-stream` with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, so a captured HTML or script body can never run on the admin origin. Use `body.content_type` from the envelope for the original type.
- **Errors:** 401 for a missing or wrong token, 404 when the reference is invalid or the body has expired.
- **Partial bodies:** for incomplete or limit-exceeded requests you get exactly what was stored, which can be shorter than `body.original_size`.

```sh
curl -H 'Authorization: Bearer change-me' "http://127.0.0.1:8080$BODY_URL?limit=1024"
```

## Development

```sh
cargo test    # integration tests drive a real TCP listener
cargo build --release
```

## License

[Apache-2.0](LICENSE)
