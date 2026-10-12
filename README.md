# webhook

A webhook capture and debugging server written in Rust. It accepts HTTP requests on **any** method and path, persists the full request (metadata + streamed body) to disk, replies with a configurable response, and ships a built-in admin UI for browsing captured requests.

Useful for debugging third-party webhook integrations, inspecting what a client actually sends, or acting as a configurable stub endpoint during development.

## Features

- **Catch-all capture** — every method (`GET`, `POST`, `PUT`, ...) on every non-admin path is recorded.
- **Streamed body persistence** — bodies are written to disk as they arrive (never buffered whole in memory), optionally gzip-compressed, with configurable size limits.
- **JSON metadata sidecar** — method, path, query, headers, timing, and body stats stored as JSON next to each body file.
- **Path/time-partitioned storage layout** — records are laid out by request path and timestamp for easy `find`/`grep`.
- **Indexed storage** — request metadata lives in an embedded [fjall](https://github.com/fjall-rs/fjall) database indexed by time and path; bodies are files in a fixed hashed fan-out of folders. Search, detail lookups and retention never walk a directory tree.
- **TTL-based retention** — an expiry index lets cleanup delete exactly the requests that have expired, however many paths you capture.
- **Configurable responses** — global and per-path-prefix response status, headers, and body (capture metadata JSON, static text, or static JSON).
- **Admin UI** — overview, a request explorer that searches everything retained by path prefix and time range, request detail pages with a formatted body viewer and *Copy as cURL*, and a live stream view. Protected by an optional login (bcrypt password, in-memory sessions). Light and dark themes.
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
db = "./data/db"               # request database; keep it on a local disk, not NFS
blobs = "./data/blobs"         # body files; may be on NFS

[retention]
default_ttl = "30d"            # how long records are kept
min_ttl = "2h"                 # shorter per-path TTLs are raised to this floor
cleanup_interval = "1h"        # how often the cleanup worker runs
prune_grace = "1h"             # orphaned body files are only removed once
                               # untouched this long

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
| `db` | `./data/db` | Request database (metadata and indexes). Put it on a **local disk**: embedded databases rely on file locking and fsync behaviour that NFS doesn't provide |
| `blobs` | `./data/blobs` | Body files. Can live on NFS. Created on startup if missing |

`storage.root` from older versions is no longer accepted; startup fails with a message pointing at `db` and `blobs`.

### `[retention]`

| Key | Default | Description |
|---|---|---|
| `default_ttl` | `30d` | Records older than this are deleted (overridable per `[[paths]]` rule) |
| `min_ttl` | `2h` | Minimum effective TTL; shorter configured TTLs are coalesced to this value |
| `cleanup_interval` | `1h` | How often the cleanup worker runs |
| `prune_grace` | `1h` | A body file with no matching request (left by a crash mid-capture) is only removed once untouched this long |

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

Request metadata goes into a fjall database at `storage.db`. Every read is a point lookup by id or a range over ordered keys with a fixed bound; nothing scans a whole keyspace. fjall is synchronous, so every call runs on Tokio's blocking thread pool, off the request-handling threads.

| Keyspace | Key | Value | Used for |
|---|---|---|---|
| `envelopes` | request id | metadata JSON | detail pages, body lookups |
| `by_time` | received time (ns) + path + id | — | newest-first search by time range and path prefix, reading keys only |
| `expiry` | expiry time (s) + id | — | retention |
| `stats_min` | minute start (s) | counts | overview ranges up to 24 hours (kept 2 days) |
| `stats_hour` | hour start (s) | counts | overview ranges of 7 and 30 days (kept 90 days) |

Each counts bucket holds requests, complete, incomplete, limit exceeded, body bytes and a per-method breakdown. Captures add to an in-memory buffer that is written into the buckets every 5 seconds and at shutdown; the overview adds the unwritten part on top, so it is always current. A crash can lose at most the last few seconds of counts, never any requests.

Bodies are written to `storage.blobs` as one file per request, named after the request id, in one level of 65,536 folders named by 4 hex characters of a hash of the id:

```text
data/blobs/20d2/20261012T082031.922460000Z_myhost_AbCdEf123456.body.bin.gz   # ".body.bin" in raw mode
```

Request ids start with the UTC capture time (`20261012T082031.922460000Z_<host>_<random>`), so they sort by time and are safe in URLs and file names. The metadata looks like:

```json
{
  "id": "20261012T082031.922460000Z_myhost_AbCdEf123456",
  "received_at": "2026-10-12T16:20:31.922460+08:00",
  "method": "POST",
  "path": "/test1/test2/test3",
  "query": "aaafe=afafw",
  "headers": { "host": "127.0.0.1:8080", "content-type": "application/json" },
  "body": {
    "stored": true,
    "complete": true,
    "mode": "compressed",
    "object": "20d2/20261012T082031.922460000Z_myhost_AbCdEf123456.body.bin.gz",
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

Creating a body file is retried as a whole: create the folder, touch it (update its modification time), create the file; if any step fails, for example because cleanup removed the folder in between, all three are repeated, up to 5 times. The body is then written as a stream and the metadata is committed once it is complete. If a client disconnects mid-body or an unknown-length body crosses `max_body_size`, the metadata records `complete = false` (and `limit_exceeded = true` in the latter case).

## Large bodies

- If `Content-Length` exceeds `max_body_size`, the request is rejected upfront with `413 Payload Too Large` (metadata is still written).
- If `Content-Length` is missing, the server streams until the limit is crossed, closes the body file, records `limit_exceeded = true`, and returns `413`.

## Retention and cleanup

At capture time the server resolves the path rule and records an expiry of `received_at + max(rule_ttl, min_ttl)` in the `expiry` index. Every `cleanup_interval`, cleanup reads that index from the start up to now and, for each expired request, deletes its body file and its database entries. The cost is proportional to the number of expired requests, not to how much is stored or how many distinct paths there are.

Each pass also sweeps 4,096 of the 65,536 blob folders, so a full round takes 16 passes. In each folder it:

- removes **orphan** body files: no matching metadata, and untouched for `prune_grace`. Orphans only come from a crash between writing a body and committing its metadata.
- removes the folder itself if it is **empty and untouched for 30 minutes**. Deleting a body file updates its folder's modification time, and writers touch the folder before creating a file, so a folder in use never qualifies; a writer that loses the race anyway retries (see above).

Old overview counts are dropped too: minute buckets after 2 days, hour buckets after 90 days.

## Admin UI

Served under `server.admin_prefix` (default `/_wh_admin`):

| Route | Description |
|---|---|
| `/_wh_admin/` | Overview for the last 1 hour, 24 hours, 7 days or 30 days: requests, complete, incomplete, limit exceeded and body bytes, a requests-over-time chart (hover a column for its numbers, or *Show as table*), the method breakdown, and stored totals. Built from the counts buckets: at most 1,440 minute or 720 hour keys per view, and the counts survive restarts |
| `/_wh_admin/requests` | Request explorer. Searches **everything retained**, newest first, by path prefix (`?path=`, a plain string prefix) and time range (quick ranges or a custom from/to in the server's time zone), 100 per page with an *Older* link. If a rare prefix doesn't fill a page within the scan budget, the page says how far back it searched and offers to keep going |
| `/_wh_admin/requests/<id>` | Request detail: status, sizes, and Body / Headers / Query / Raw tabs. The body loads on demand (first 256KiB, then *Load all*) and is shown as formatted JSON, form fields, text or a hex dump. *Copy as cURL* rebuilds the request |
| `/_wh_admin/requests/<id>/body` | The stored body, behind the admin login (same responses as the stream body endpoint below) |
| `/_wh_admin/login`, `/logout` | Session login/logout (only when `admin.password` is set) |
| `/_wh_admin/stream` | WebSocket stream of captured requests (see below) |
| `/_wh_admin/streamview` | Live browser view of the stream (see below) |

Paths that merely resemble the admin prefix (e.g. `/_wh_adminfoo`) are still captured as webhooks.

### Live view

`/_wh_admin/streamview` shows the stream in the browser. Enter the stream token and an optional path prefix, and new requests appear on top as cards. Click a card to expand it and see:

- **Summary:** size and receive time, with a link to the full request page.
- **Body:** fetched from the body endpoint only when you expand the card, first 256KiB, with a **Load all** button for the rest. It's shown as pretty-printed JSON, a form field list, plain text, or a hex dump for binary bodies, with buttons to copy or download it.
- **Headers:** every header.

**Pause** only freezes the page. The WebSocket stays connected, and new requests wait in a banner until you resume. The page keeps the latest 500 cards and drops the oldest. It reconnects automatically if the connection drops.

The page itself is served without the admin login, because it holds no data; everything it shows comes through the token-protected stream. You can prefill the form with `/_wh_admin/streamview?token=…&prefix=…`. The token is then removed from the address bar, and the page remembers the token and prefix in the browser's local storage.

### Message format

- **One request, one message.** Each captured request is sent as exactly one WebSocket **text** message containing one UTF-8 JSON object: an envelope with the request metadata. **Bodies are never sent over the stream.** Fetch them from `body_url` when you need them, so a burst of large requests costs the stream almost nothing.
- **Ordering.** Messages arrive in the order the requests finished being captured. A message is sent only after that request's body file and metadata have been written, so `body_url` is ready to fetch as soon as the message arrives.
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
  "id": "20261012T011507.123456789Z_myhost_AbCdEfGhIjKl",
  "received_at": "2026-10-12T09:15:07.123456789+08:00",
  "method": "POST",
  "path": "/api/v1/hook",
  "query": "source=github",
  "headers": { "content-type": "application/json", "content-length": "11" },
  "body": {
    "stored": true, "complete": true, "mode": "compressed",
    "object": "430e/20261012T011507.123456789Z_myhost_AbCdEfGhIjKl.body.bin.gz",
    "encoding": "gzip", "original_size": 11, "stored_size": 31,
    "content_type": "application/json", "previewable": true,
    "limit_exceeded": false, "error": null
  },
  "body_url": "/_wh_admin/stream/body/20261012T011507.123456789Z_myhost_AbCdEfGhIjKl"
}
```

### Fetching a body

`GET <body_url>` returns the original, uncompressed body as stored on disk. It uses the same token rules as the stream (`Authorization: Bearer <token>` or `?token=`).

- **Lookup:** the last part of `body_url` is the request id. It works for as long as the request is retained (`retention.default_ttl`), not only while it's in the live stream.
- **`?limit=N`:** returns only the first N bytes of the body. Without it you get the whole body, streamed from disk and gunzipped on the fly, so even large bodies aren't buffered in memory.
- **Response:** always `application/octet-stream` with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, so a captured HTML or script body can never run on the admin origin. Use `body.content_type` from the envelope for the original type.
- **Errors:** 401 for a missing or wrong token, 404 for an unknown id, a request without a stored body, or an expired one.
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
