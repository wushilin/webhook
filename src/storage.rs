use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use chrono::{Datelike, Local, Timelike};
use tokio::{fs, io::AsyncWriteExt, sync::RwLock};

use crate::{config, models::RequestMeta};

const EXPIRES_AT_FILE: &str = ".expires_at";

#[derive(Debug)]
pub struct LocalStorage {
    root: PathBuf,
    stats: RwLock<StatsAccumulator>,
    /// Serializes directory deletion against file/directory creation.
    /// Writers take it shared around `create_dir_all` + file create; the
    /// retention pruner takes it exclusive while it re-checks that a
    /// directory is empty and removes it. A per-path lock would not be
    /// enough: pruning an empty parent races a writer creating a child.
    dir_lock: RwLock<()>,
}

#[derive(Debug, Clone)]
pub struct StoredRequestPaths {
    meta_path: PathBuf,
    body_path: Option<PathBuf>,
    body_file_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub meta: RequestMeta,
    pub meta_path: PathBuf,
    pub body_path: Option<PathBuf>,
}

#[derive(Debug, Default, Clone)]
pub struct DashboardStats {
    pub total_requests: usize,
    pub complete_requests: usize,
    pub incomplete_requests: usize,
    pub stored_body_bytes: u64,
    pub top_paths: Vec<(String, usize)>,
    pub top_methods: Vec<(String, usize)>,
}

#[derive(Debug, Default)]
struct StatsAccumulator {
    total_requests: usize,
    complete_requests: usize,
    incomplete_requests: usize,
    stored_body_bytes: u64,
    paths: std::collections::BTreeMap<String, usize>,
    methods: std::collections::BTreeMap<String, usize>,
}

impl LocalStorage {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            stats: RwLock::new(StatsAccumulator::default()),
            dir_lock: RwLock::new(()),
        }
    }

    pub async fn ensure_root(&self) -> anyhow::Result<()> {
        fs::create_dir_all(&self.root).await?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn paths_for(
        &self,
        request_path: &str,
        received_at: chrono::DateTime<Local>,
        id: &str,
        body_mode: config::BodyMode,
    ) -> StoredRequestPaths {
        let mut base = self.root.clone();
        for segment in request_path_segments(request_path) {
            base.push(segment);
        }
        base.push(format!("{:04}", received_at.year()));
        base.push(format!("{:02}", received_at.month()));
        base.push(format!("{:02}", received_at.day()));
        base.push(format!("{:02}", received_at.hour()));
        base.push(format!("{:02}", received_at.minute()));
        base.push(format!("{:02}", received_at.second()));

        let meta_path = base.join(format!("{id}.json"));
        let (body_path, body_file_name) = body_mode
            .extension()
            .map(|ext| {
                let file = format!("{id}.{ext}");
                (Some(base.join(&file)), Some(file))
            })
            .unwrap_or((None, None));

        StoredRequestPaths {
            meta_path,
            body_path,
            body_file_name,
        }
    }

    pub async fn write_meta_with_expiry(
        &self,
        paths: &StoredRequestPaths,
        meta: &RequestMeta,
        expires_at: SystemTime,
    ) -> anyhow::Result<()> {
        self.write_meta_inner(paths, meta, Some(expires_at)).await
    }

    async fn write_meta_inner(
        &self,
        paths: &StoredRequestPaths,
        meta: &RequestMeta,
        expires_at: Option<SystemTime>,
    ) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(meta)?;
        let tmp = paths.meta_path.with_extension("json.tmp");
        let mut file = {
            let _guard = self.dir_lock.read().await;
            if let Some(parent) = paths.meta_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            fs::File::create(&tmp).await?
        };
        file.write_all(&json).await?;
        file.write_all(b"\n").await?;
        file.shutdown().await?;
        fs::rename(&tmp, &paths.meta_path).await?;
        if let Some(expires_at) = expires_at {
            self.write_expires_at(paths, meta, expires_at).await?;
        }
        self.record_stats(meta).await;
        Ok(())
    }

    pub async fn create_body_file(&self, paths: &StoredRequestPaths) -> anyhow::Result<fs::File> {
        let body_path = paths
            .body_path
            .as_ref()
            .context("no body path for metadata-only mode")?;
        let _guard = self.dir_lock.read().await;
        if let Some(parent) = body_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(body_path)
            .await
            .with_context(|| format!("failed to create {}", body_path.display()))
    }

    pub async fn recent(
        &self,
        limit: usize,
        path_filter: Option<&str>,
    ) -> anyhow::Result<Vec<RequestRecord>> {
        let mut files = Vec::new();
        collect_json_files(&self.root, &mut files).await?;

        let mut records = Vec::new();
        for file in files {
            let Ok(meta) = read_meta(&file).await else {
                continue;
            };
            if let Some(filter) = path_filter {
                if meta.path != filter
                    && !meta
                        .path
                        .starts_with(&format!("{}/", filter.trim_end_matches('/')))
                {
                    continue;
                }
            }
            let body_path = meta
                .body
                .object
                .as_ref()
                .and_then(|name| file.parent().map(|parent| parent.join(name)));
            records.push(RequestRecord {
                meta,
                meta_path: file,
                body_path,
            });
        }
        records.sort_by(|a, b| {
            b.meta
                .received_at
                .cmp(&a.meta.received_at)
                .then_with(|| b.meta.id.cmp(&a.meta.id))
        });
        records.truncate(limit);
        Ok(records)
    }

    pub async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<RequestRecord>> {
        let mut files = Vec::new();
        collect_json_files(&self.root, &mut files).await?;
        for file in files {
            if file.file_stem().and_then(|s| s.to_str()) != Some(id) {
                continue;
            }
            let Ok(meta) = read_meta(&file).await else {
                continue;
            };
            let body_path = meta
                .body
                .object
                .as_ref()
                .and_then(|name| file.parent().map(|parent| parent.join(name)));
            return Ok(Some(RequestRecord {
                meta,
                meta_path: file,
                body_path,
            }));
        }
        Ok(None)
    }

    pub async fn dashboard(&self) -> anyhow::Result<DashboardStats> {
        Ok(self.stats.read().await.snapshot())
    }

    pub async fn cleanup_expired(&self, config: &config::Config) -> anyhow::Result<()> {
        let now = SystemTime::now();
        let grace = config.retention.prune_grace;

        let mut files = Vec::new();
        let mut dirs = Vec::new();
        collect_entries(&self.root, &mut files, &mut dirs).await?;

        let (expires_at_files, other_files): (Vec<_>, Vec<_>) = files
            .into_iter()
            .partition(|path| path.file_name().and_then(|n| n.to_str()) == Some(EXPIRES_AT_FILE));
        let expires_at_dirs: std::collections::HashSet<PathBuf> = expires_at_files
            .iter()
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect();

        // Pass 1: delete expired leaf folders using the folder-level expiry
        // marker written at capture time. This avoids opening every metadata
        // JSON during routine cleanup.
        for file in &expires_at_files {
            let Ok(expires_at) = read_expires_at(file).await else {
                continue;
            };
            if expires_at > now {
                continue;
            }
            let Some(folder) = file.parent() else {
                continue;
            };
            if folder == self.root {
                continue;
            }
            let _guard = self.dir_lock.write().await;
            let _ = fs::remove_dir_all(folder).await;
            drop(_guard);
            self.prune_dir_chain(folder.parent()).await;
        }

        // Pass 2: migrate cleanup behavior for legacy markerless records.
        // New folders have `.expires_at`, so routine cleanup does not open
        // each metadata JSON.
        for file in other_files.iter().filter(|path| {
            path.extension().and_then(|e| e.to_str()) == Some("json")
                && path
                    .parent()
                    .map(|parent| !expires_at_dirs.contains(parent))
                    .unwrap_or(false)
        }) {
            let Ok(meta) = read_meta(file).await else {
                continue;
            };
            let ttl = config.rule_for_path(&meta.path).ttl;
            let age = now
                .duration_since(meta.received_at.into())
                .unwrap_or(Duration::ZERO);
            if age < ttl {
                continue;
            }

            if let Some(body) = &meta.body.object {
                if let Some(parent) = file.parent() {
                    let _ = fs::remove_file(parent.join(body)).await;
                }
            }
            let _ = fs::remove_file(file).await;
            self.prune_dir_chain(file.parent()).await;
        }

        // Pass 3: delete orphans — stale meta tmp files (crash between create
        // and rename) and body files whose meta was never written. The grace
        // period keeps in-flight writes safe: an active body stream refreshes
        // its file mtime on every chunk.
        for file in &other_files {
            if !is_older_than(file, grace).await {
                continue;
            }
            let Some(name) = file.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let orphan = if name.ends_with(".json.tmp")
                || (name.starts_with(".expires_at.") && name.ends_with(".tmp"))
            {
                true
            } else if let Some(id) = name
                .strip_suffix(".body.bin.gz")
                .or_else(|| name.strip_suffix(".body.bin"))
            {
                let meta = file.with_file_name(format!("{id}.json"));
                // Keep the body file if the meta check itself fails.
                !fs::try_exists(&meta).await.unwrap_or(true)
            } else {
                false
            };
            if orphan {
                let _ = fs::remove_file(file).await;
            }
        }

        // Pass 4: sweep empty folders, deepest first. Only folders whose
        // mtime is past the grace period are considered — writers only ever
        // create entries in the folder for the current time window, so an
        // old-mtime empty folder cannot be an active write target. The
        // exclusive lock closes the remaining window against a writer that is
        // mid-create.
        dirs.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
        for dir in dirs {
            if dir == self.root || !is_older_than(&dir, grace).await {
                continue;
            }
            let _guard = self.dir_lock.write().await;
            if dir_is_empty(&dir).await {
                let _ = fs::remove_dir(&dir).await;
            }
        }
        Ok(())
    }

    /// Removes `start` and its ancestors (up to, excluding, the root) while
    /// they are empty. Holds the directory lock exclusively so no writer can
    /// be mid-create inside a folder we are checking.
    async fn prune_dir_chain(&self, start: Option<&Path>) {
        let Some(mut current) = start.map(Path::to_path_buf) else {
            return;
        };
        let _guard = self.dir_lock.write().await;
        while current.starts_with(&self.root) && current != self.root {
            if !dir_is_empty(&current).await || fs::remove_dir(&current).await.is_err() {
                break;
            }
            match current.parent() {
                Some(parent) => current = parent.to_path_buf(),
                None => break,
            }
        }
    }

    async fn record_stats(&self, meta: &RequestMeta) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        if meta.body.complete {
            stats.complete_requests += 1;
        } else {
            stats.incomplete_requests += 1;
        }
        stats.stored_body_bytes = stats
            .stored_body_bytes
            .saturating_add(meta.body.stored_size);
        *stats.paths.entry(meta.path.clone()).or_default() += 1;
        *stats.methods.entry(meta.method.clone()).or_default() += 1;
    }

    async fn write_expires_at(
        &self,
        paths: &StoredRequestPaths,
        meta: &RequestMeta,
        expires_at: SystemTime,
    ) -> anyhow::Result<()> {
        let Some(parent) = paths.meta_path.parent() else {
            return Ok(());
        };
        let path = parent.join(EXPIRES_AT_FILE);
        let existing = read_expires_at(&path).await.ok();
        let expires_at = existing
            .map(|old| old.max(expires_at))
            .unwrap_or(expires_at);
        let value = epoch_seconds(expires_at).to_string();
        let tmp = parent.join(format!(".expires_at.{}.tmp", meta.id));

        let _guard = self.dir_lock.read().await;
        fs::write(&tmp, value).await?;
        fs::rename(&tmp, &path).await?;
        Ok(())
    }
}

impl StatsAccumulator {
    fn snapshot(&self) -> DashboardStats {
        DashboardStats {
            total_requests: self.total_requests,
            complete_requests: self.complete_requests,
            incomplete_requests: self.incomplete_requests,
            stored_body_bytes: self.stored_body_bytes,
            top_paths: sorted_counts(self.paths.clone(), 8),
            top_methods: sorted_counts(self.methods.clone(), 8),
        }
    }
}

impl StoredRequestPaths {
    pub fn body_file_name(&self) -> Option<String> {
        self.body_file_name.clone()
    }

    pub async fn body_size(&self) -> anyhow::Result<u64> {
        let Some(body_path) = &self.body_path else {
            return Ok(0);
        };
        Ok(fs::metadata(body_path).await?.len())
    }
}

async fn read_meta(path: &Path) -> anyhow::Result<RequestMeta> {
    let text = fs::read_to_string(path).await?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

async fn read_expires_at(path: &Path) -> anyhow::Result<SystemTime> {
    let text = fs::read_to_string(path).await?;
    let seconds = text
        .trim()
        .parse::<u64>()
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

async fn collect_json_files(root: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    collect_entries(root, &mut files, &mut dirs).await?;
    out.extend(
        files
            .into_iter()
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json")),
    );
    Ok(())
}

async fn collect_entries(
    root: &Path,
    files: &mut Vec<PathBuf>,
    dirs: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(mut entries) = fs::read_dir(&dir).await else {
            continue;
        };
        // Entries can vanish mid-scan (retention races a request burst), so
        // tolerate per-entry errors instead of aborting the walk.
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            match entry.file_type().await {
                Ok(file_type) if file_type.is_dir() => {
                    dirs.push(path.clone());
                    stack.push(path);
                }
                Ok(_) => files.push(path),
                Err(_) => continue,
            }
        }
    }
    Ok(())
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

async fn dir_is_empty(dir: &Path) -> bool {
    match fs::read_dir(dir).await {
        Ok(mut entries) => matches!(entries.next_entry().await, Ok(None)),
        Err(_) => false,
    }
}

fn request_path_segments(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    for raw in path.split('/').filter(|raw| !raw.is_empty()) {
        let decoded = urlencoding::decode(raw).unwrap_or_else(|_| raw.into());
        segments.push(encode_path_segment(&decoded));
    }
    if segments.is_empty() {
        segments.push("_root".to_string());
    }
    segments
}

fn encode_path_segment(segment: &str) -> String {
    if segment == "." {
        return "%2E".to_string();
    }
    if segment == ".." {
        return "%2E%2E".to_string();
    }

    let mut encoded = String::new();
    let chars: Vec<(usize, char)> = segment.char_indices().collect();
    let last_char_start = chars.last().map(|(idx, _)| *idx);
    for (idx, c) in chars {
        let is_trailing_bad = Some(idx) == last_char_start && matches!(c, '.' | ' ');
        if is_trailing_bad || should_escape_char(c) {
            push_percent_encoded(&mut encoded, c);
        } else {
            encoded.push(c);
        }
    }

    if is_reserved_windows_name(segment) {
        encode_first_char(segment)
    } else {
        encoded
    }
}

fn should_escape_char(c: char) -> bool {
    c == '%' || c.is_control() || matches!(c, '/' | '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
}

fn push_percent_encoded(out: &mut String, c: char) {
    let mut buf = [0u8; 4];
    for byte in c.encode_utf8(&mut buf).as_bytes() {
        out.push('%');
        out.push_str(&format!("{byte:02X}"));
    }
}

fn encode_first_char(segment: &str) -> String {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut encoded = String::new();
    push_percent_encoded(&mut encoded, first);
    encoded.push_str(chars.as_str());
    encoded
}

fn is_reserved_windows_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit())
}

fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn sorted_counts(
    map: std::collections::BTreeMap<String, usize>,
    limit: usize,
) -> Vec<(String, usize)> {
    let mut values: Vec<_> = map.into_iter().collect();
    values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    values.truncate(limit);
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BodyMeta, RequestMeta};
    use tempfile::TempDir;

    fn test_meta(id: &str, path: &str, object: Option<String>) -> RequestMeta {
        RequestMeta {
            id: id.to_string(),
            received_at: Local::now(),
            method: "POST".to_string(),
            path: path.to_string(),
            query: None,
            headers: serde_json::Map::new(),
            body: BodyMeta {
                stored: object.is_some(),
                complete: true,
                mode: "raw".to_string(),
                object,
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

    fn zero_grace_config(ttl: Duration) -> config::Config {
        let mut config = config::Config::default();
        config.retention.default_ttl = ttl;
        config.retention.prune_grace = Duration::ZERO;
        config
    }

    #[test]
    fn segments_are_reversible_and_filesystem_safe() {
        assert_eq!(request_path_segments("/a/./b"), vec!["a", "%2E", "b"]);
        assert_eq!(request_path_segments("/.."), vec!["%2E%2E"]);
        assert_eq!(request_path_segments("/.hidden"), vec![".hidden"]);
        assert_eq!(request_path_segments("/nul"), vec!["%6Eul"]);
        assert_eq!(request_path_segments("/COM1.txt"), vec!["%43OM1.txt"]);
        assert_eq!(request_path_segments("/trailing."), vec!["trailing%2E"]);
        assert_eq!(request_path_segments("/a%2Fb"), vec!["a%2Fb"]);
        assert_eq!(request_path_segments("/100%25"), vec!["100%25"]);
        assert_eq!(request_path_segments("/snow/%E2%98%83"), vec!["snow", "☃"]);
        assert_eq!(request_path_segments("/"), vec!["_root"]);
    }

    #[tokio::test]
    async fn cleanup_deletes_expired_records_and_their_folders() {
        let tmp = TempDir::new().unwrap();
        let storage = LocalStorage::new(tmp.path().join("data"));
        storage.ensure_root().await.unwrap();

        let paths = storage.paths_for("/svc/hook", Local::now(), "id1", config::BodyMode::Raw);
        let mut file = storage.create_body_file(&paths).await.unwrap();
        file.write_all(b"payload").await.unwrap();
        file.shutdown().await.unwrap();
        storage
            .write_meta_with_expiry(
                &paths,
                &test_meta("id1", "/svc/hook", paths.body_file_name()),
                SystemTime::now() - Duration::from_secs(1),
            )
            .await
            .unwrap();

        storage
            .cleanup_expired(&zero_grace_config(Duration::ZERO))
            .await
            .unwrap();

        let mut entries = fs::read_dir(storage.root()).await.unwrap();
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "expired record folders should be pruned to the storage root"
        );
    }

    #[tokio::test]
    async fn cleanup_deletes_orphans_and_empty_folders_but_keeps_live_records() {
        let tmp = TempDir::new().unwrap();
        let storage = LocalStorage::new(tmp.path().join("data"));
        storage.ensure_root().await.unwrap();

        let paths = storage.paths_for("/live", Local::now(), "live1", config::BodyMode::Raw);
        let mut file = storage.create_body_file(&paths).await.unwrap();
        file.write_all(b"data").await.unwrap();
        file.shutdown().await.unwrap();
        storage
            .write_meta_with_expiry(
                &paths,
                &test_meta("live1", "/live", paths.body_file_name()),
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let stats = storage.dashboard().await.unwrap();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.top_paths, vec![("/live".to_string(), 1)]);

        let stale_dir = storage.root().join("gone").join("2026").join("01");
        fs::create_dir_all(&stale_dir).await.unwrap();
        fs::write(stale_dir.join("x.json.tmp"), b"{").await.unwrap();
        fs::write(stale_dir.join("orphan.body.bin.gz"), b"junk")
            .await
            .unwrap();
        fs::create_dir_all(storage.root().join("empty").join("nested"))
            .await
            .unwrap();

        storage
            .cleanup_expired(&zero_grace_config(Duration::from_secs(3600)))
            .await
            .unwrap();

        assert!(!fs::try_exists(storage.root().join("gone")).await.unwrap());
        assert!(!fs::try_exists(storage.root().join("empty")).await.unwrap());
        assert!(fs::try_exists(&paths.meta_path).await.unwrap());
        assert!(fs::try_exists(paths.body_path.as_ref().unwrap())
            .await
            .unwrap());
    }
}
