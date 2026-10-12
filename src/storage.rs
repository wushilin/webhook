//! Request storage: envelopes (request metadata) in a fjall database, bodies
//! as blob files in a fixed hashed fan-out.
//!
//! Keyspaces:
//! - `envelopes`: `id` → `RequestMeta` JSON.
//! - `by_time`: `received_at nanos (u64 BE) ++ path ++ 0x00 ++ id` → empty.
//!   Time-ordered with the path in the key, so path-prefix searches over a
//!   time window are key-only scans.
//! - `expiry`: `expires_at secs (u64 BE) ++ id` → empty. Retention reads it
//!   from the start up to now, so cleanup costs O(expired requests) and never
//!   walks a directory tree.
//!
//! Blobs live at `<blobs>/<h1>/<h2>/<id>.body.bin[.gz]`, where `h1/h2` come
//! from a hash of the id. The id in the file name is the envelope key, so an
//! orphan blob (no envelope) is recognisable from its name alone.

use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use tokio::{fs, sync::RwLock};
use tracing::{info, warn};

use crate::{config, models::RequestMeta};

const PATH_STATS_IDLE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const PATH_STATS_LIMIT: usize = 5_000;
const PATH_STATS_PRUNE_TARGET: usize = PATH_STATS_LIMIT * 9 / 10;
/// Longer paths are cut in the `by_time` key (fjall keys are at most 64KiB);
/// the full path is still in the envelope.
const MAX_KEY_PATH_BYTES: usize = 4096;
const CLEANUP_BATCH: usize = 1_000;
/// The orphan sweep covers this many of the 256 top-level fan-out folders per
/// cleanup pass, so a full sweep takes 256 / 16 = 16 passes.
const SWEEP_DIRS_PER_PASS: usize = 16;
const BODY_SUFFIXES: [&str; 2] = [".body.bin.gz", ".body.bin"];

pub struct Storage {
    db: Database,
    envelopes: Keyspace,
    by_time: Keyspace,
    expiry: Keyspace,
    blobs: PathBuf,
    stats: RwLock<StatsAccumulator>,
    sweep_cursor: AtomicUsize,
}

/// Where a request's body goes: the absolute file path plus the path relative
/// to the blob root, which the envelope records as `body.object`.
#[derive(Debug, Clone)]
pub struct BlobLocation {
    pub path: PathBuf,
    pub object: String,
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// Plain string prefix on the request path.
    pub prefix: Option<String>,
    /// Oldest `received_at` to include.
    pub from: Option<SystemTime>,
    /// Newest `received_at` to include.
    pub to: Option<SystemTime>,
    /// Continue below this `by_time` key (from a previous page).
    pub before: Option<Vec<u8>>,
    pub limit: usize,
    /// Maximum index keys examined for one page.
    pub scan_budget: usize,
}

#[derive(Debug, Default)]
pub struct SearchPage {
    pub records: Vec<RequestMeta>,
    /// Pass back as `before` to continue; `None` when the window is exhausted.
    pub next: Option<Vec<u8>>,
    /// True when the page stopped because `scan_budget` ran out rather than
    /// because it filled up; `next` then continues the scan.
    pub budget_exhausted: bool,
    /// `received_at` of the last index key examined.
    pub scanned_back_to: Option<SystemTime>,
}

#[derive(Debug, Default, Clone)]
pub struct DashboardStats {
    pub total_requests: usize,
    pub complete_requests: usize,
    pub incomplete_requests: usize,
    pub stored_body_bytes: u64,
    pub top_paths: Vec<(String, usize)>,
    pub top_methods: Vec<(String, usize)>,
    pub stored_requests: usize,
    pub db_disk_bytes: u64,
}

#[derive(Debug, Default)]
struct StatsAccumulator {
    total_requests: usize,
    complete_requests: usize,
    incomplete_requests: usize,
    stored_body_bytes: u64,
    paths: BTreeMap<String, PathStats>,
    methods: BTreeMap<String, usize>,
}

#[derive(Debug, Clone)]
struct PathStats {
    count: usize,
    last_seen: SystemTime,
}

impl Storage {
    pub fn open(db_path: &Path, blobs: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_path)
            .with_context(|| format!("failed to create {}", db_path.display()))?;
        std::fs::create_dir_all(blobs)
            .with_context(|| format!("failed to create {}", blobs.display()))?;
        let db = Database::builder(db_path)
            .open()
            .with_context(|| format!("failed to open database at {}", db_path.display()))?;
        let envelopes = db.keyspace("envelopes", KeyspaceCreateOptions::default)?;
        let by_time = db.keyspace("by_time", KeyspaceCreateOptions::default)?;
        let expiry = db.keyspace("expiry", KeyspaceCreateOptions::default)?;
        Ok(Self {
            db,
            envelopes,
            by_time,
            expiry,
            blobs: blobs.to_path_buf(),
            stats: RwLock::new(StatsAccumulator::default()),
            sweep_cursor: AtomicUsize::new(0),
        })
    }

    pub fn blob_location(&self, id: &str, mode: config::BodyMode) -> Option<BlobLocation> {
        let ext = mode.extension()?;
        let object = format!("{}/{id}.{ext}", fan_out(id));
        Some(BlobLocation {
            path: self.blobs.join(&object),
            object,
        })
    }

    /// The stored body file for an envelope, if it has one.
    pub fn blob_path(&self, meta: &RequestMeta) -> Option<PathBuf> {
        let object = meta.body.object.as_deref().filter(|_| meta.body.stored)?;
        let relative = Path::new(object);
        relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
            .then(|| self.blobs.join(relative))
    }

    pub async fn create_body_file(&self, location: &BlobLocation) -> anyhow::Result<fs::File> {
        if let Some(parent) = location.path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&location.path)
            .await
            .with_context(|| format!("failed to create {}", location.path.display()))
    }

    /// Records the envelope and its index entries in one atomic batch. Called
    /// after the body file is complete, so a crash in between leaves at worst
    /// an orphan blob for the sweep.
    pub async fn put(&self, meta: &RequestMeta, expires_at: SystemTime) -> anyhow::Result<()> {
        let json = serde_json::to_vec(meta)?;
        let time_key = time_key(meta);
        let expiry_key = expiry_key(expires_at, &meta.id);
        let id = meta.id.clone();
        let (db, envelopes, by_time, expiry) = self.handles();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut batch = db.batch();
            batch.insert(&envelopes, id.as_bytes(), json);
            batch.insert(&by_time, time_key, []);
            batch.insert(&expiry, expiry_key, []);
            batch.commit()?;
            Ok(())
        })
        .await??;
        self.record_stats(meta).await;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> anyhow::Result<Option<RequestMeta>> {
        let envelopes = self.envelopes.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<RequestMeta>> {
            match envelopes.get(id.as_bytes())? {
                Some(value) => Ok(Some(serde_json::from_slice(&value)?)),
                None => Ok(None),
            }
        })
        .await?
    }

    /// Newest-first page of requests in a time window, filtered by path
    /// prefix on the index keys before any envelope is read.
    pub async fn search(&self, query: SearchQuery) -> anyhow::Result<SearchPage> {
        let by_time = self.by_time.clone();
        let envelopes = self.envelopes.clone();
        tokio::task::spawn_blocking(move || search_blocking(&by_time, &envelopes, &query)).await?
    }

    pub async fn dashboard(&self) -> anyhow::Result<DashboardStats> {
        let mut stats = self.stats.write().await;
        stats.prune_paths(SystemTime::now());
        Ok(DashboardStats {
            total_requests: stats.total_requests,
            complete_requests: stats.complete_requests,
            incomplete_requests: stats.incomplete_requests,
            stored_body_bytes: stats.stored_body_bytes,
            top_paths: sorted_counts(
                stats
                    .paths
                    .iter()
                    .map(|(path, path_stats)| (path.clone(), path_stats.count))
                    .collect(),
                20,
            ),
            top_methods: sorted_counts(stats.methods.clone(), 8),
            stored_requests: self.envelopes.approximate_len(),
            db_disk_bytes: self.db.disk_space().unwrap_or(0),
        })
    }

    /// Deletes every request whose expiry has passed, then sweeps a slice of
    /// the blob fan-out for orphans untouched for `prune_grace`.
    pub async fn cleanup(&self, config: &config::Config) -> anyhow::Result<()> {
        let now = SystemTime::now();
        let mut removed = 0usize;
        loop {
            let expired = self.expired_batch(now).await?;
            if expired.is_empty() {
                break;
            }
            let mut progressed = false;
            for (expiry_key, id) in expired {
                if self.remove_request(expiry_key, &id).await? {
                    removed += 1;
                    progressed = true;
                }
            }
            // Every blob in this batch failed to delete; retry next pass.
            if !progressed {
                break;
            }
        }
        if removed > 0 {
            info!(removed, "retention removed expired requests");
        }
        self.sweep_orphans(config.retention.prune_grace).await;
        Ok(())
    }

    async fn expired_batch(&self, now: SystemTime) -> anyhow::Result<Vec<(Vec<u8>, String)>> {
        let expiry = self.expiry.clone();
        let upper = epoch_secs(now).saturating_add(1).to_be_bytes();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(Vec<u8>, String)>> {
            let mut out = Vec::new();
            for guard in expiry.range(..upper.as_slice()).take(CLEANUP_BATCH) {
                let key = guard.key()?;
                let id = String::from_utf8_lossy(key.get(8..).unwrap_or_default()).into_owned();
                out.push((key.to_vec(), id));
            }
            Ok(out)
        })
        .await?
    }

    /// Returns false when the blob could not be deleted; the envelope is then
    /// kept so a later pass retries.
    async fn remove_request(&self, expiry_key: Vec<u8>, id: &str) -> anyhow::Result<bool> {
        let meta = self.get(id).await?;
        if let Some(blob) = meta.as_ref().and_then(|meta| self.blob_path(meta)) {
            match fs::remove_file(&blob).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    warn!(error = ?err, path = %blob.display(), "failed to delete blob");
                    return Ok(false);
                }
            }
        }
        let time_key = meta.as_ref().map(time_key);
        let id = id.to_string();
        let (db, envelopes, by_time, expiry) = self.handles();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut batch = db.batch();
            batch.remove(&envelopes, id.as_bytes());
            if let Some(time_key) = time_key {
                batch.remove(&by_time, time_key);
            }
            batch.remove(&expiry, expiry_key);
            batch.commit()?;
            Ok(())
        })
        .await??;
        Ok(true)
    }

    async fn sweep_orphans(&self, grace: Duration) {
        let start = self
            .sweep_cursor
            .fetch_add(SWEEP_DIRS_PER_PASS, Ordering::Relaxed);
        for offset in 0..SWEEP_DIRS_PER_PASS {
            let top = self.blobs.join(format!("{:02x}", (start + offset) % 256));
            let Ok(mut subdirs) = fs::read_dir(&top).await else {
                continue;
            };
            while let Ok(Some(subdir)) = subdirs.next_entry().await {
                let Ok(mut files) = fs::read_dir(subdir.path()).await else {
                    continue;
                };
                while let Ok(Some(file)) = files.next_entry().await {
                    self.remove_if_orphan(&file.path(), grace).await;
                }
            }
        }
    }

    async fn remove_if_orphan(&self, file: &Path, grace: Duration) {
        let Some(id) = file
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|name| BODY_SUFFIXES.iter().find_map(|s| name.strip_suffix(s)))
        else {
            return;
        };
        // A blob still being written keeps a fresh mtime.
        if !is_older_than(file, grace).await {
            return;
        }
        let envelopes = self.envelopes.clone();
        let key = id.as_bytes().to_vec();
        let known = tokio::task::spawn_blocking(move || envelopes.contains_key(key))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(true);
        if !known {
            let _ = fs::remove_file(file).await;
        }
    }

    fn handles(&self) -> (Database, Keyspace, Keyspace, Keyspace) {
        (
            self.db.clone(),
            self.envelopes.clone(),
            self.by_time.clone(),
            self.expiry.clone(),
        )
    }

    async fn record_stats(&self, meta: &RequestMeta) {
        let mut stats = self.stats.write().await;
        let received_at = meta.received_at.into();
        stats.prune_paths(received_at);

        stats.total_requests += 1;
        if meta.body.complete {
            stats.complete_requests += 1;
        } else {
            stats.incomplete_requests += 1;
        }
        stats.stored_body_bytes = stats
            .stored_body_bytes
            .saturating_add(meta.body.stored_size);
        let path_stats = stats.paths.entry(meta.path.clone()).or_insert(PathStats {
            count: 0,
            last_seen: received_at,
        });
        path_stats.count += 1;
        path_stats.last_seen = received_at;
        *stats.methods.entry(meta.method.clone()).or_default() += 1;
    }
}

fn search_blocking(
    by_time: &Keyspace,
    envelopes: &Keyspace,
    query: &SearchQuery,
) -> anyhow::Result<SearchPage> {
    let lower = query
        .from
        .map(epoch_nanos)
        .unwrap_or(0)
        .to_be_bytes()
        .to_vec();
    // Exclusive upper bound: the continuation key, else just past `to`.
    let upper = match (&query.before, query.to) {
        (Some(before), _) => before.clone(),
        (None, Some(to)) => epoch_nanos(to).saturating_add(1).to_be_bytes().to_vec(),
        (None, None) => u64::MAX.to_be_bytes().to_vec(),
    };
    let prefix = query.prefix.as_deref().map(str::as_bytes);

    let mut page = SearchPage::default();
    let mut scanned = 0usize;
    for guard in by_time.range(lower.as_slice()..upper.as_slice()).rev() {
        let key = guard.key()?;
        scanned += 1;
        let Some((nanos, path, id)) = split_time_key(&key) else {
            continue;
        };
        page.scanned_back_to = Some(UNIX_EPOCH + Duration::from_nanos(nanos));
        if prefix.is_none_or(|p| path.starts_with(p)) {
            if let Some(value) = envelopes.get(id)? {
                page.records.push(serde_json::from_slice(&value)?);
            }
        }
        if page.records.len() >= query.limit || scanned >= query.scan_budget {
            page.budget_exhausted = page.records.len() < query.limit;
            page.next = Some(key.to_vec());
            return Ok(page);
        }
    }
    Ok(page)
}

fn time_key(meta: &RequestMeta) -> Vec<u8> {
    let received: SystemTime = meta.received_at.into();
    let path = meta.path.as_bytes();
    let path = path.get(..MAX_KEY_PATH_BYTES).unwrap_or(path);
    let mut key = Vec::with_capacity(8 + path.len() + 1 + meta.id.len());
    key.extend_from_slice(&epoch_nanos(received).to_be_bytes());
    key.extend_from_slice(path);
    key.push(0);
    key.extend_from_slice(meta.id.as_bytes());
    key
}

/// `(nanos, path, id)` from a `by_time` key. Request paths never contain a
/// raw NUL (it would have to be percent-encoded), so the first NUL ends it.
fn split_time_key(key: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let nanos = u64::from_be_bytes(key.get(..8)?.try_into().ok()?);
    let rest = key.get(8..)?;
    let nul = rest.iter().position(|b| *b == 0)?;
    Some((nanos, rest.get(..nul)?, rest.get(nul + 1..)?))
}

fn expiry_key(expires_at: SystemTime, id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + id.len());
    key.extend_from_slice(&epoch_secs(expires_at).to_be_bytes());
    key.extend_from_slice(id.as_bytes());
    key
}

/// `h1/h2` fan-out folders from an FNV-1a hash of the id: 65,536 leaf
/// folders in total, however many distinct paths are captured.
fn fan_out(id: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:02x}/{:02x}", (hash >> 8) & 0xff, hash & 0xff)
}

fn epoch_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn epoch_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn is_older_than(path: &Path, grace: Duration) -> bool {
    match fs::metadata(path).await.and_then(|m| m.modified()) {
        Ok(mtime) => SystemTime::now()
            .duration_since(mtime)
            .map(|age| age >= grace)
            .unwrap_or(false),
        Err(_) => false,
    }
}

impl StatsAccumulator {
    fn prune_paths(&mut self, now: SystemTime) {
        self.paths.retain(|_, stats| {
            now.duration_since(stats.last_seen)
                .map(|age| age < PATH_STATS_IDLE_TTL)
                .unwrap_or(true)
        });
        if self.paths.len() <= PATH_STATS_LIMIT {
            return;
        }

        let mut oldest: Vec<_> = self
            .paths
            .iter()
            .map(|(path, stats)| (path.clone(), stats.last_seen))
            .collect();
        oldest.sort_by_key(|(_, last_seen)| *last_seen);
        for (path, _) in oldest
            .into_iter()
            .take(self.paths.len().saturating_sub(PATH_STATS_PRUNE_TARGET))
        {
            self.paths.remove(&path);
        }
    }
}

fn sorted_counts(map: BTreeMap<String, usize>, limit: usize) -> Vec<(String, usize)> {
    let mut values: Vec<_> = map.into_iter().collect();
    values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    values.truncate(limit);
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::BodyMeta;
    use chrono::Local;
    use tempfile::TempDir;

    fn open(tmp: &TempDir) -> Storage {
        Storage::open(&tmp.path().join("db"), &tmp.path().join("blobs")).unwrap()
    }

    fn test_meta(id: &str, path: &str, received_at: chrono::DateTime<Local>) -> RequestMeta {
        RequestMeta {
            id: id.to_string(),
            received_at,
            method: "POST".to_string(),
            path: path.to_string(),
            query: None,
            headers: serde_json::Map::new(),
            body: BodyMeta {
                stored: false,
                complete: true,
                mode: "metadata_only".to_string(),
                object: None,
                encoding: None,
                original_size: 0,
                stored_size: 0,
                content_type: None,
                previewable: false,
                limit_exceeded: false,
                error: None,
            },
        }
    }

    fn query(limit: usize) -> SearchQuery {
        SearchQuery {
            prefix: None,
            from: None,
            to: None,
            before: None,
            limit,
            scan_budget: 10_000,
        }
    }

    fn ids(page: &SearchPage) -> Vec<&str> {
        page.records.iter().map(|m| m.id.as_str()).collect()
    }

    fn later() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3600)
    }

    #[tokio::test]
    async fn search_is_newest_first_with_prefix_window_and_pages() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);
        let start = Local::now() - chrono::Duration::seconds(100);
        for i in 0..6i64 {
            let path = if i % 2 == 0 { "/a/x" } else { "/b" };
            let meta = test_meta(
                &format!("id{i}"),
                path,
                start + chrono::Duration::seconds(i),
            );
            storage.put(&meta, later()).await.unwrap();
        }

        let page = storage.search(query(3)).await.unwrap();
        assert_eq!(ids(&page), vec!["id5", "id4", "id3"]);
        let next = storage
            .search(SearchQuery {
                before: page.next.clone(),
                ..query(3)
            })
            .await
            .unwrap();
        assert_eq!(ids(&next), vec!["id2", "id1", "id0"]);

        // Plain string prefix: "/a" matches "/a/x".
        let page = storage
            .search(SearchQuery {
                prefix: Some("/a".to_string()),
                ..query(10)
            })
            .await
            .unwrap();
        assert_eq!(ids(&page), vec!["id4", "id2", "id0"]);
        assert!(page.next.is_none());

        let page = storage
            .search(SearchQuery {
                from: Some((start + chrono::Duration::seconds(1)).into()),
                to: Some((start + chrono::Duration::seconds(3)).into()),
                ..query(10)
            })
            .await
            .unwrap();
        assert_eq!(ids(&page), vec!["id3", "id2", "id1"]);
    }

    #[tokio::test]
    async fn search_reports_an_exhausted_scan_budget() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);
        let start = Local::now();
        for i in 0..5i64 {
            let meta = test_meta(
                &format!("id{i}"),
                "/busy",
                start + chrono::Duration::seconds(i),
            );
            storage.put(&meta, later()).await.unwrap();
        }
        let page = storage
            .search(SearchQuery {
                prefix: Some("/rare".to_string()),
                scan_budget: 2,
                ..query(10)
            })
            .await
            .unwrap();
        assert!(page.records.is_empty());
        assert!(page.budget_exhausted);
        assert!(page.next.is_some());
    }

    #[tokio::test]
    async fn cleanup_removes_expired_envelopes_index_entries_and_blobs() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);

        let mut expired = test_meta("gone", "/old", Local::now());
        let location = storage
            .blob_location("gone", config::BodyMode::Raw)
            .unwrap();
        drop(storage.create_body_file(&location).await.unwrap());
        expired.body.stored = true;
        expired.body.object = Some(location.object.clone());
        storage
            .put(&expired, SystemTime::now() - Duration::from_secs(1))
            .await
            .unwrap();
        storage
            .put(&test_meta("kept", "/new", Local::now()), later())
            .await
            .unwrap();

        storage.cleanup(&config::Config::default()).await.unwrap();

        assert!(storage.get("gone").await.unwrap().is_none());
        assert!(!location.path.exists());
        assert!(storage.get("kept").await.unwrap().is_some());
        assert_eq!(ids(&storage.search(query(10)).await.unwrap()), vec!["kept"]);
    }

    #[tokio::test]
    async fn sweep_removes_only_old_blobs_without_an_envelope() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);
        let mut config = config::Config::default();
        config.retention.prune_grace = Duration::ZERO;

        let orphan = storage
            .blob_location("orphan", config::BodyMode::Compressed)
            .unwrap();
        drop(storage.create_body_file(&orphan).await.unwrap());
        let live = storage
            .blob_location("live", config::BodyMode::Compressed)
            .unwrap();
        drop(storage.create_body_file(&live).await.unwrap());
        let mut meta = test_meta("live", "/x", Local::now());
        meta.body.stored = true;
        meta.body.object = Some(live.object.clone());
        storage.put(&meta, later()).await.unwrap();

        // 16 passes cover all 256 top-level fan-out folders.
        for _ in 0..16 {
            storage.cleanup(&config).await.unwrap();
        }
        assert!(!orphan.path.exists());
        assert!(live.path.exists());
    }

    #[test]
    fn blob_locations_fan_out_by_id_and_reject_escapes() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);
        let location = storage
            .blob_location("abc", config::BodyMode::Compressed)
            .unwrap();
        let parts: Vec<_> = location.object.split('/').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], "abc.body.bin.gz");
        assert!(storage
            .blob_location("abc", config::BodyMode::MetadataOnly)
            .is_none());

        let mut meta = test_meta("abc", "/", Local::now());
        meta.body.stored = true;
        meta.body.object = Some("../../etc/passwd".to_string());
        assert!(storage.blob_path(&meta).is_none());
    }

    #[test]
    fn time_keys_split_back_into_parts() {
        let meta = test_meta("id1", "/p/q", Local::now());
        let key = time_key(&meta);
        let (_, path, id) = split_time_key(&key).unwrap();
        assert_eq!(path, b"/p/q");
        assert_eq!(id, b"id1");
    }

    #[tokio::test]
    async fn path_counts_evict_after_seven_idle_days_and_restart() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);

        let old = Local::now() - chrono::Duration::from_std(PATH_STATS_IDLE_TTL).unwrap();
        for i in 0..3 {
            let meta = test_meta(&format!("old{i}"), "/old-id-path", old);
            storage.put(&meta, later()).await.unwrap();
        }
        storage
            .put(&test_meta("new1", "/new-path", Local::now()), later())
            .await
            .unwrap();
        let stats = storage.dashboard().await.unwrap();
        assert_eq!(stats.top_paths, vec![("/new-path".to_string(), 1)]);

        storage
            .put(
                &test_meta("old-returned", "/old-id-path", Local::now()),
                later(),
            )
            .await
            .unwrap();
        let stats = storage.dashboard().await.unwrap();
        assert!(stats
            .top_paths
            .iter()
            .any(|(path, count)| path == "/old-id-path" && *count == 1));
    }

    #[test]
    fn path_stats_cap_prunes_least_recent_paths() {
        let mut stats = StatsAccumulator::default();
        let start = SystemTime::now();
        for i in 0..=PATH_STATS_LIMIT {
            stats.paths.insert(
                format!("/path/{i}"),
                PathStats {
                    count: 1,
                    last_seen: start + Duration::from_secs(i as u64),
                },
            );
        }

        stats.prune_paths(start + Duration::from_secs(PATH_STATS_LIMIT as u64));

        assert_eq!(stats.paths.len(), PATH_STATS_PRUNE_TARGET);
        assert!(!stats.paths.contains_key("/path/0"));
        assert!(stats
            .paths
            .contains_key(&format!("/path/{PATH_STATS_LIMIT}")));
    }
}
