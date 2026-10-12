//! Request storage: envelopes (request metadata) in a fjall database, bodies
//! as blob files in a fixed hashed fan-out.
//!
//! Every database read is a point lookup or a bounded range over ordered
//! keys; nothing scans a whole keyspace. fjall is synchronous, so every call
//! runs on the blocking thread pool.
//!
//! Keyspaces:
//! - `envelopes`: `id` → `RequestMeta` JSON.
//! - `by_time`: `received_at nanos (u64 BE) ++ path ++ 0x00 ++ id` → empty.
//!   Time-ordered with the path in the key, so path-prefix searches over a
//!   time window read keys only.
//! - `expiry`: `expires_at secs (u64 BE) ++ id` → empty. Retention reads it
//!   from the start up to now: cost is O(expired requests).
//! - `stats_min` / `stats_hour`: `bucket start secs (u64 BE)` → [`Counts`].
//!   Dashboard totals read at most a day of minutes or a month of hours.
//!
//! Blobs live at `<blobs>/<hhhh>/<id>.body.bin[.gz]`: one level of 65,536
//! folders named by 4 hex characters of a hash of the id. The id in the file
//! name is the envelope key, so an orphan blob is recognisable from its name.

use std::{
    collections::BTreeMap,
    ops::AddAssign,
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use tokio::fs;
use tracing::{info, warn};

use crate::{config, models::RequestMeta};

/// Longer paths are cut in the `by_time` key (fjall keys are at most 64KiB);
/// the full path is still in the envelope.
const MAX_KEY_PATH_BYTES: usize = 4096;
const CLEANUP_BATCH: usize = 1_000;
/// An empty fan-out folder is removed only once untouched this long. Deleting
/// a blob updates its folder's mtime, and writers touch the folder before
/// creating a blob, so a folder in use is never older than this.
const EMPTY_DIR_GRACE: Duration = Duration::from_secs(30 * 60);
/// Attempts at "create folder, touch it, create file" before giving up.
const CREATE_ATTEMPTS: u32 = 5;
const BODY_SUFFIXES: [&str; 2] = [".body.bin.gz", ".body.bin"];
const MINUTE: u64 = 60;
const HOUR: u64 = 60 * 60;
/// Minute buckets serve ranges up to a day; hour buckets everything longer.
const STATS_MINUTE_KEEP: Duration = Duration::from_secs(2 * 24 * 60 * 60);
const STATS_HOUR_KEEP: Duration = Duration::from_secs(90 * 24 * 60 * 60);

pub struct Storage {
    db: Database,
    envelopes: Keyspace,
    by_time: Keyspace,
    expiry: Keyspace,
    stats_min: Keyspace,
    stats_hour: Keyspace,
    blobs: PathBuf,
    /// Counts not yet written to the stats keyspaces, by minute.
    pending: Mutex<BTreeMap<u64, Counts>>,
    /// Serializes stats flushes, which read-modify-write buckets.
    flush_lock: tokio::sync::Mutex<()>,
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

/// Method slots in [`Counts::methods`].
pub const METHODS: [&str; 6] = ["GET", "POST", "PUT", "PATCH", "DELETE", "Other"];

/// Request counts for one time bucket.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub requests: u64,
    pub complete: u64,
    pub incomplete: u64,
    pub limit_exceeded: u64,
    pub body_bytes: u64,
    pub methods: [u64; 6],
}

impl Counts {
    fn of(meta: &RequestMeta) -> Self {
        let mut counts = Self {
            requests: 1,
            body_bytes: meta.body.original_size,
            ..Self::default()
        };
        if meta.body.limit_exceeded {
            counts.limit_exceeded = 1;
        } else if meta.body.complete {
            counts.complete = 1;
        } else {
            counts.incomplete = 1;
        }
        let slot = METHODS
            .iter()
            .position(|m| *m == meta.method)
            .unwrap_or(METHODS.len() - 1);
        counts.methods[slot] = 1;
        counts
    }

    fn encode(&self) -> Vec<u8> {
        [
            self.requests,
            self.complete,
            self.incomplete,
            self.limit_exceeded,
            self.body_bytes,
        ]
        .iter()
        .chain(self.methods.iter())
        .flat_map(|v| v.to_le_bytes())
        .collect()
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut values = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c));
        let mut next = || values.next().unwrap_or(0);
        let mut counts = Self {
            requests: next(),
            complete: next(),
            incomplete: next(),
            limit_exceeded: next(),
            body_bytes: next(),
            methods: [0; 6],
        };
        for slot in &mut counts.methods {
            *slot = next();
        }
        counts
    }
}

impl AddAssign for Counts {
    fn add_assign(&mut self, other: Self) {
        self.requests += other.requests;
        self.complete += other.complete;
        self.incomplete += other.incomplete;
        self.limit_exceeded += other.limit_exceeded;
        self.body_bytes += other.body_bytes;
        for (slot, value) in self.methods.iter_mut().zip(other.methods) {
            *slot += value;
        }
    }
}

/// Bucket width for [`Storage::counts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Minute,
    Hour,
}

impl Granularity {
    pub fn seconds(self) -> u64 {
        match self {
            Self::Minute => MINUTE,
            Self::Hour => HOUR,
        }
    }
}

/// What one blob sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    pub folders: usize,
    pub files: usize,
    pub orphans_removed: usize,
    pub folders_removed: usize,
}

enum BlobCheck {
    Kept,
    Removed,
    /// Already deleted by someone else.
    Gone,
}

#[derive(Debug, Default, Clone)]
pub struct StoreTotals {
    pub stored_requests: usize,
    pub db_disk_bytes: u64,
}

impl Storage {
    /// Opens (creating if needed) the database and blob root. Blocking; call
    /// through [`Storage::open_async`] from async code.
    pub fn open(db_path: &Path, blobs: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_path)
            .with_context(|| format!("failed to create {}", db_path.display()))?;
        std::fs::create_dir_all(blobs)
            .with_context(|| format!("failed to create {}", blobs.display()))?;
        let db = Database::builder(db_path)
            .open()
            .with_context(|| format!("failed to open database at {}", db_path.display()))?;
        let keyspace = |name| db.keyspace(name, KeyspaceCreateOptions::default);
        Ok(Self {
            envelopes: keyspace("envelopes")?,
            by_time: keyspace("by_time")?,
            expiry: keyspace("expiry")?,
            stats_min: keyspace("stats_min")?,
            stats_hour: keyspace("stats_hour")?,
            db,
            blobs: blobs.to_path_buf(),
            pending: Mutex::new(BTreeMap::new()),
            flush_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub async fn open_async(db_path: PathBuf, blobs: PathBuf) -> anyhow::Result<Self> {
        tokio::task::spawn_blocking(move || Self::open(&db_path, &blobs)).await?
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

    /// Creates a blob file: create the folder, touch it, create the file,
    /// and on any failure repeat all three. The sweep may remove an empty
    /// folder between two steps; the touch keeps it fresh for the retry.
    pub async fn create_body_file(&self, location: &BlobLocation) -> anyhow::Result<fs::File> {
        let dir = location
            .path
            .parent()
            .context("blob path has no parent folder")?;
        let mut last_error = None;
        for attempt in 0..CREATE_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(10 * u64::from(attempt))).await;
            }
            if let Err(err) = fs::create_dir_all(dir).await {
                last_error = Some(err);
                continue;
            }
            touch_dir(dir).await;
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&location.path)
                .await
            {
                Ok(file) => return Ok(file),
                Err(err) => last_error = Some(err),
            }
        }
        Err(anyhow::anyhow!(
            "failed to create {} after {CREATE_ATTEMPTS} attempts: {}",
            location.path.display(),
            last_error.map_or_else(|| "unknown error".to_string(), |e| e.to_string())
        ))
    }

    /// Records the envelope and its index entries in one atomic batch. Called
    /// after the body file is complete, so a crash in between leaves at worst
    /// an orphan blob for the sweep.
    pub async fn put(&self, meta: &RequestMeta, expires_at: SystemTime) -> anyhow::Result<()> {
        let json = serde_json::to_vec(meta)?;
        let time_key = time_key(meta);
        let expiry_key = expiry_key(expires_at, &meta.id);
        let id = meta.id.clone();
        let (db, envelopes, by_time, expiry) = (
            self.db.clone(),
            self.envelopes.clone(),
            self.by_time.clone(),
            self.expiry.clone(),
        );
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut batch = db.batch();
            batch.insert(&envelopes, id.as_bytes(), json);
            batch.insert(&by_time, time_key, []);
            batch.insert(&expiry, expiry_key, []);
            batch.commit()?;
            Ok(())
        })
        .await??;
        self.count(meta);
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

    // ---------- counters ----------

    fn count(&self, meta: &RequestMeta) {
        let received: SystemTime = meta.received_at.into();
        let minute = floor_to(epoch_secs(received), MINUTE);
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        *pending.entry(minute).or_default() += Counts::of(meta);
    }

    /// Adds pending counts into the minute and hour buckets. Runs from a timer
    /// and at shutdown; the lock keeps read-modify-write single-writer.
    pub async fn flush_stats(&self) -> anyhow::Result<()> {
        let _flush = self.flush_lock.lock().await;
        let pending = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        if pending.is_empty() {
            return Ok(());
        }
        let mut hours: BTreeMap<u64, Counts> = BTreeMap::new();
        for (minute, counts) in &pending {
            *hours.entry(floor_to(*minute, HOUR)).or_default() += *counts;
        }
        let (db, stats_min, stats_hour) = (
            self.db.clone(),
            self.stats_min.clone(),
            self.stats_hour.clone(),
        );
        let result = tokio::task::spawn_blocking({
            let pending = pending.clone();
            move || -> anyhow::Result<()> {
                let mut batch = db.batch();
                for (keyspace, buckets) in [(&stats_min, &pending), (&stats_hour, &hours)] {
                    for (start, counts) in buckets {
                        let key = start.to_be_bytes();
                        let mut total = keyspace
                            .get(key)?
                            .map(|v| Counts::decode(&v))
                            .unwrap_or_default();
                        total += *counts;
                        batch.insert(keyspace, key, total.encode());
                    }
                }
                batch.commit()?;
                Ok(())
            }
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r);
        if result.is_err() {
            // Put the counts back so the next flush retries them.
            let mut current = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            for (minute, counts) in pending {
                *current.entry(minute).or_default() += counts;
            }
        }
        result
    }

    /// Per-bucket counts for `[from, to)`, including counts not yet flushed.
    /// Reads at most `(to - from) / granularity` keys.
    pub async fn counts(
        &self,
        from: SystemTime,
        to: SystemTime,
        granularity: Granularity,
    ) -> anyhow::Result<BTreeMap<u64, Counts>> {
        let width = granularity.seconds();
        let lower = floor_to(epoch_secs(from), width);
        let upper = epoch_secs(to);
        let keyspace = match granularity {
            Granularity::Minute => self.stats_min.clone(),
            Granularity::Hour => self.stats_hour.clone(),
        };
        let mut buckets =
            tokio::task::spawn_blocking(move || -> anyhow::Result<BTreeMap<u64, Counts>> {
                let mut out = BTreeMap::new();
                let range = lower.to_be_bytes()..upper.to_be_bytes();
                for guard in keyspace.range(range) {
                    let (key, value) = guard.into_inner()?;
                    if let Ok(bytes) = <[u8; 8]>::try_from(key.as_ref()) {
                        out.insert(u64::from_be_bytes(bytes), Counts::decode(&value));
                    }
                }
                Ok(out)
            })
            .await??;
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        for (minute, counts) in pending.range(lower..upper) {
            *buckets.entry(floor_to(*minute, width)).or_default() += *counts;
        }
        Ok(buckets)
    }

    /// Approximate stored request count and database size, from metadata.
    pub async fn totals(&self) -> anyhow::Result<StoreTotals> {
        let (db, envelopes) = (self.db.clone(), self.envelopes.clone());
        tokio::task::spawn_blocking(move || StoreTotals {
            stored_requests: envelopes.approximate_len(),
            db_disk_bytes: db.disk_space().unwrap_or(0),
        })
        .await
        .map_err(Into::into)
    }

    // ---------- retention ----------

    /// Deletes every request whose expiry has passed and stats buckets past
    /// their keep window. Orphan blobs are left to [`Storage::sweep_blobs`].
    pub async fn cleanup(&self) -> anyhow::Result<()> {
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
        self.prune_stats(now).await?;
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
        let (db, envelopes, by_time, expiry) = (
            self.db.clone(),
            self.envelopes.clone(),
            self.by_time.clone(),
            self.expiry.clone(),
        );
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

    async fn prune_stats(&self, now: SystemTime) -> anyhow::Result<()> {
        let (db, stats_min, stats_hour) = (
            self.db.clone(),
            self.stats_min.clone(),
            self.stats_hour.clone(),
        );
        let cutoffs = [
            epoch_secs(now.checked_sub(STATS_MINUTE_KEEP).unwrap_or(UNIX_EPOCH)),
            epoch_secs(now.checked_sub(STATS_HOUR_KEEP).unwrap_or(UNIX_EPOCH)),
        ];
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut batch = db.batch();
            for (keyspace, cutoff) in [(&stats_min, cutoffs[0]), (&stats_hour, cutoffs[1])] {
                let upper = cutoff.to_be_bytes();
                for guard in keyspace.range(..upper.as_slice()).take(CLEANUP_BATCH) {
                    batch.remove(keyspace, guard.key()?);
                }
            }
            batch.commit()?;
            Ok(())
        })
        .await?
    }

    /// One full pass over the blob fan-out: removes orphan blobs (no
    /// envelope, untouched for `orphan_grace`) and folders that are empty and
    /// untouched for [`EMPTY_DIR_GRACE`]. Runs rarely, yields to the runtime
    /// after every entry, and treats anything that vanishes underneath it
    /// (deleted by retention or by hand) as already handled.
    pub async fn sweep_blobs(&self, orphan_grace: Duration) -> SweepReport {
        let mut report = SweepReport::default();
        let mut dirs = match fs::read_dir(&self.blobs).await {
            Ok(dirs) => dirs,
            Err(err) => {
                warn!(error = ?err, path = %self.blobs.display(), "blob sweep could not list the blob root");
                return report;
            }
        };
        loop {
            let dir = match dirs.next_entry().await {
                Ok(Some(dir)) => dir,
                Ok(None) => break,
                Err(err) => {
                    warn!(error = ?err, "blob sweep stopped listing the blob root");
                    break;
                }
            };
            tokio::task::yield_now().await;
            let is_fan_out = dir
                .file_name()
                .to_str()
                .is_some_and(|n| n.len() == 4 && n.bytes().all(|b| b.is_ascii_hexdigit()));
            if !is_fan_out {
                continue;
            }
            report.folders += 1;
            let path = dir.path();
            // A folder removed since the listing is simply skipped.
            let Ok(mut files) = fs::read_dir(&path).await else {
                continue;
            };
            let mut remaining = 0usize;
            let mut complete = true;
            loop {
                let file = match files.next_entry().await {
                    Ok(Some(file)) => file,
                    Ok(None) => break,
                    Err(_) => {
                        complete = false;
                        break;
                    }
                };
                report.files += 1;
                match self.remove_if_orphan(&file.path(), orphan_grace).await {
                    BlobCheck::Kept => remaining += 1,
                    BlobCheck::Removed => report.orphans_removed += 1,
                    BlobCheck::Gone => {}
                }
                tokio::task::yield_now().await;
            }
            // remove_dir refuses a folder a writer has filled since; a
            // folder already removed is fine too.
            if complete && remaining == 0 && is_older_than(&path, EMPTY_DIR_GRACE).await {
                match fs::remove_dir(&path).await {
                    Ok(()) => report.folders_removed += 1,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {}
                }
            }
        }
        report
    }

    async fn remove_if_orphan(&self, file: &Path, grace: Duration) -> BlobCheck {
        let Some(id) = file
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|name| BODY_SUFFIXES.iter().find_map(|s| name.strip_suffix(s)))
        else {
            return BlobCheck::Kept;
        };
        // A point lookup by id (bloom-filtered, usually at most one disk
        // read) comes first, so live blobs cost no stat on the blob store.
        // On any lookup failure, assume the blob is wanted.
        let envelopes = self.envelopes.clone();
        let key = id.as_bytes().to_vec();
        let known = tokio::task::spawn_blocking(move || envelopes.contains_key(key))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(true);
        if known {
            return BlobCheck::Kept;
        }
        // An unknown blob may still be mid-write: its mtime is then fresh.
        let mtime = match fs::metadata(file).await.and_then(|m| m.modified()) {
            Ok(mtime) => mtime,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return BlobCheck::Gone,
            Err(_) => return BlobCheck::Kept,
        };
        if SystemTime::now()
            .duration_since(mtime)
            .map_or(true, |age| age < grace)
        {
            return BlobCheck::Kept;
        }
        match fs::remove_file(file).await {
            Ok(()) => BlobCheck::Removed,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => BlobCheck::Gone,
            Err(_) => BlobCheck::Kept,
        }
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

/// Best-effort mtime bump so the sweep sees the folder as in use.
#[cfg(unix)]
async fn touch_dir(dir: &Path) {
    let dir = dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || {
        std::fs::File::open(&dir).and_then(|f| f.set_modified(SystemTime::now()))
    })
    .await;
}

#[cfg(not(unix))]
async fn touch_dir(_dir: &Path) {}

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

/// 4 hex characters from an FNV-1a hash of the id: 65,536 folders in one
/// level, however many distinct paths are captured.
fn fan_out(id: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:04x}", hash & 0xffff)
}

fn floor_to(secs: u64, width: u64) -> u64 {
    secs - secs % width
}

fn epoch_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub fn epoch_secs(time: SystemTime) -> u64 {
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

    /// Sets a path's mtime into the past, as if untouched for `age`.
    fn age(path: &Path, age: Duration) {
        std::fs::File::open(path)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
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
    async fn counts_are_bucketed_and_include_unflushed_requests() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);
        let now = Local::now();
        let mut get = test_meta("g", "/x", now);
        get.method = "GET".to_string();
        let mut broken = test_meta("b", "/x", now);
        broken.body.complete = false;
        broken.body.original_size = 7;
        let earlier = test_meta("e", "/x", now - chrono::Duration::hours(3));
        for meta in [&get, &broken, &earlier] {
            storage.put(meta, later()).await.unwrap();
        }
        let window = |hours| {
            (
                SystemTime::now() - Duration::from_secs(hours * HOUR),
                SystemTime::now() + Duration::from_secs(60),
            )
        };

        // Before a flush, counts come from memory.
        let (from, to) = window(1);
        let total = sum(&storage.counts(from, to, Granularity::Minute).await.unwrap());
        assert_eq!(total.requests, 2);

        storage.flush_stats().await.unwrap();
        let total = sum(&storage.counts(from, to, Granularity::Minute).await.unwrap());
        assert_eq!(total.requests, 2);
        assert_eq!(total.complete, 1);
        assert_eq!(total.incomplete, 1);
        assert_eq!(total.body_bytes, 7);
        assert_eq!(total.methods[0], 1); // GET
        assert_eq!(total.methods[1], 1); // POST

        // A second flush adds to the stored buckets.
        storage
            .put(&test_meta("again", "/x", Local::now()), later())
            .await
            .unwrap();
        storage.flush_stats().await.unwrap();
        let (from, to) = window(4);
        let hours = storage.counts(from, to, Granularity::Hour).await.unwrap();
        assert_eq!(sum(&hours).requests, 4);
        assert!(hours.keys().all(|start| start % HOUR == 0));
    }

    fn sum(buckets: &BTreeMap<u64, Counts>) -> Counts {
        let mut total = Counts::default();
        for counts in buckets.values() {
            total += *counts;
        }
        total
    }

    #[test]
    fn counts_round_trip_through_bytes() {
        let counts = Counts {
            requests: 9,
            complete: 5,
            incomplete: 3,
            limit_exceeded: 1,
            body_bytes: 1 << 40,
            methods: [1, 2, 3, 4, 5, 6],
        };
        assert_eq!(Counts::decode(&counts.encode()), counts);
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

        storage.cleanup().await.unwrap();

        assert!(storage.get("gone").await.unwrap().is_none());
        assert!(!location.path.exists());
        assert!(storage.get("kept").await.unwrap().is_some());
        assert_eq!(ids(&storage.search(query(10)).await.unwrap()), vec!["kept"]);
    }

    #[tokio::test]
    async fn sweep_removes_orphans_and_only_stale_empty_folders() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);

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

        // A stale empty folder goes; a freshly touched one stays.
        let stale = tmp.path().join("blobs/abcd");
        let fresh = tmp.path().join("blobs/abce");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        age(&stale, EMPTY_DIR_GRACE + Duration::from_secs(60));

        // A non-blob file is never touched.
        let note = live.path.with_file_name("README.txt");
        std::fs::write(&note, "keep").unwrap();

        let report = storage.sweep_blobs(Duration::ZERO).await;
        assert_eq!(report.orphans_removed, 1);
        assert_eq!(report.folders_removed, 1);
        assert!(note.exists());
        assert!(!orphan.path.exists());
        assert!(live.path.exists());
        assert!(!stale.exists());
        assert!(fresh.exists());
        // The orphan's folder was just modified by the delete, so it stays.
        assert!(orphan.path.parent().unwrap().exists());
    }

    #[tokio::test]
    async fn sweep_treats_vanished_files_and_folders_as_handled() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);

        // A blob deleted by someone else between listing and checking.
        let gone = tmp.path().join("blobs/0000/gone.body.bin");
        assert!(matches!(
            storage.remove_if_orphan(&gone, Duration::ZERO).await,
            BlobCheck::Gone
        ));

        // The whole blob root removed by hand: the sweep reports nothing.
        std::fs::remove_dir_all(tmp.path().join("blobs")).unwrap();
        assert_eq!(
            storage.sweep_blobs(Duration::ZERO).await,
            SweepReport::default()
        );
    }

    #[tokio::test]
    async fn create_body_file_recreates_a_folder_removed_underneath_it() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);
        let location = storage.blob_location("id1", config::BodyMode::Raw).unwrap();
        // The folder does not exist yet; creation makes it and the file.
        drop(storage.create_body_file(&location).await.unwrap());
        assert!(location.path.exists());

        let second = storage.blob_location("id2", config::BodyMode::Raw).unwrap();
        std::fs::remove_dir_all(second.path.parent().unwrap()).ok();
        drop(storage.create_body_file(&second).await.unwrap());
        assert!(second.path.exists());
    }

    #[test]
    fn blob_locations_fan_out_one_level_and_reject_escapes() {
        let tmp = TempDir::new().unwrap();
        let storage = open(&tmp);
        let location = storage
            .blob_location("abc", config::BodyMode::Compressed)
            .unwrap();
        let parts: Vec<_> = location.object.split('/').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 4);
        assert!(parts[0].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(parts[1], "abc.body.bin.gz");
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
}
