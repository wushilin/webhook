# webhook

A webhook capture and debugging server written in Rust. It accepts HTTP requests on **any** method and path, persists the full request (metadata + streamed body) to disk, replies with a configurable response, and ships a built-in admin UI for browsing captured requests.

Useful for debugging third-party webhook integrations, inspecting what a client actually sends, or acting as a configurable stub endpoint during development.

## Features

- **Catch-all capture** — every method (`GET`, `POST`, `PUT`, ...) on every non-admin path is recorded.
- **Streamed body persistence** — bodies are written to disk as they arrive (never buffered whole in memory), optionally gzip-compressed, with configurable size limits.
- **JSON metadata sidecar** — method, path, query, headers, timing, and body stats stored as JSON next to each body file.
- **Path/time-partitioned storage layout** — records are laid out by request path and timestamp for easy `find`/`grep`.
- **TTL-based retention** — a background worker deletes expired records, orphaned files, and empty folders on a schedule, with per-path TTL overrides.
- **Configurable responses** — global and per-path-prefix response status, headers, and body (capture metadata JSON, static text, or static JSON).
- **Admin UI** — dashboard, request list with path filtering, and request detail pages with body preview, protected by an optional login (bcrypt password, in-memory sessions).
- **Safe filesystem mapping** — URL paths are sanitized (traversal-safe, hidden files and Windows-reserved names neutralized) before being used as directories; the original path is always preserved verbatim in metadata.

## Quick start

```sh
# build
cargo build --release

# run with a config file (defaults to ./config.toml; falls back to
# built-in defaults if the file does not exist)
./target/release/webhook --config config.example.toml

# or via cargo
cargo run -- --config config.example.toml
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
webhook [--config <FILE>] [SUBCOMMAND]

Options:
  -c, --config <FILE>   Config file path [env: WEBHOOK_CONFIG] [default: config.toml]

Subcommands:
  genpassword     Prompt for a password and print its bcrypt hash for admin.password
  verifypassword  Check whether a plaintext password matches a stored (bcrypt or plaintext) value
```

Logging is JSON via `tracing`, controlled with `RUST_LOG` (e.g. `RUST_LOG=info`).

## Configuration

Configuration is TOML. Every section and key is optional — missing keys use the defaults shown below. See [`config.example.toml`](config.example.toml) for a complete working example.

### Full example

```toml
[server]
bind = "127.0.0.1:8080"        # listen address
admin_prefix = "/_wh_admin"    # URL prefix for the admin UI (must start with /)

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
cleanup_interval = "1h"        # how often the cleanup worker runs
prune_grace = "1h"             # empty folders / orphaned files are only removed
                               # once untouched this long

[body]
mode = "compressed"            # compressed | raw | metadata_only
preview_limit = "5MiB"         # max original body size shown in the admin UI preview
max_body_size = "100MiB"       # requests with a larger body are rejected with 413

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
| `admin_prefix` | `/_wh_admin` | Path prefix reserved for the admin UI; everything else is captured |

### `[admin]`

| Key | Default | Description |
|---|---|---|
| `username` | `admin` | Admin login username |
| `password` | *(unset)* | bcrypt hash (recommended) or plaintext. When unset, the admin UI is **open** and a warning is logged at startup |

Sessions last 24 hours and are kept in memory — restarting the server signs everyone out.

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
data/test1/test2/test3/2026/07/15/16/20/
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

Path segments are sanitized for the filesystem (URL-decoded, traversal-safe, hidden files and Windows-reserved names neutralized, capped at 64 characters per segment and 10 segments deep). The original request path is always preserved verbatim in the metadata.

The body file is written as a stream. If a client disconnects mid-body or an unknown-length body crosses `max_body_size`, the metadata records `complete = false` (and `limit_exceeded = true` in the latter case).

## Large bodies

- If `Content-Length` exceeds `max_body_size`, the request is rejected upfront with `413 Payload Too Large` (metadata is still written).
- If `Content-Length` is missing, the server streams until the limit is crossed, closes the body file, records `limit_exceeded = true`, and returns `413`.

## Retention and cleanup

Every `cleanup_interval`, the server deletes records older than their TTL and then sweeps the storage tree for garbage: stale `*.json.tmp` files, body files whose metadata was never written (e.g. the client never completed the request), and empty folders — including path folders that no longer receive traffic. The sweep only touches files and folders untouched for `prune_grace`, and folder deletion is serialized against request writers with an in-process lock, so an in-flight capture can never lose its directory.

## Admin UI

Served under `server.admin_prefix` (default `/_wh_admin`):

| Route | Description |
|---|---|
| `/_wh_admin/` | Dashboard |
| `/_wh_admin/requests` | Recent requests, filterable by path |
| `/_wh_admin/requests/<id>` | Request detail with headers and body preview |
| `/_wh_admin/login`, `/logout` | Session login/logout (only when `admin.password` is set) |

Paths that merely resemble the admin prefix (e.g. `/_wh_adminfoo`) are still captured as webhooks.

## Development

```sh
cargo test    # integration tests drive a real TCP listener
cargo build --release
```

## License

[Apache-2.0](LICENSE)
