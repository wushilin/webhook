use std::{collections::BTreeMap, path::Path, path::PathBuf, time::Duration};

use anyhow::{bail, Context};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub body: BodyConfig,
    #[serde(default)]
    pub responder: ResponderConfig,
    #[serde(default)]
    pub responders: Vec<ResponderRule>,
    #[serde(default)]
    pub paths: Vec<PathRule>,
    #[serde(default)]
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    #[serde(default = "default_admin_username")]
    pub username: String,
    /// bcrypt hash (recommended, generate with `webhook genpassword`)
    /// or a plaintext password. When absent, the admin UI requires no login.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_admin_prefix")]
    pub admin_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    #[serde(default = "default_storage_root")]
    pub root: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_ttl", with = "humantime_serde")]
    pub default_ttl: Duration,
    #[serde(default = "default_cleanup_interval", with = "humantime_serde")]
    pub cleanup_interval: Duration,
    #[serde(default = "default_prune_grace", with = "humantime_serde")]
    pub prune_grace: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BodyConfig {
    #[serde(default)]
    pub mode: BodyMode,
    #[serde(
        default = "default_preview_limit",
        deserialize_with = "deserialize_size"
    )]
    pub preview_limit: u64,
    #[serde(
        default = "default_max_body_size",
        deserialize_with = "deserialize_size"
    )]
    pub max_body_size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponderConfig {
    #[serde(default = "default_response_status")]
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: ResponderBody,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponderRule {
    #[serde(rename = "match")]
    pub path_match: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<ResponderBody>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponderBody {
    StaticText(String),
    StaticJson(serde_json::Value),
    #[default]
    MetadataJson,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathRule {
    #[serde(rename = "match")]
    pub path_match: String,
    #[serde(default, with = "humantime_serde")]
    pub ttl: Option<Duration>,
    #[serde(default)]
    pub body_mode: Option<BodyMode>,
    #[serde(default, deserialize_with = "deserialize_optional_size")]
    pub preview_limit: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_size")]
    pub max_body_size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ResolvedPathRule {
    pub ttl: Duration,
    pub body_mode: BodyMode,
    pub preview_limit: u64,
    pub max_body_size: u64,
}

#[derive(Debug, Clone)]
pub struct ResolvedResponder {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: ResponderBody,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BodyMode {
    #[default]
    Compressed,
    Raw,
    MetadataOnly,
}

impl BodyMode {
    pub fn extension(self) -> Option<&'static str> {
        match self {
            BodyMode::Compressed => Some("body.bin.gz"),
            BodyMode::Raw => Some("body.bin"),
            BodyMode::MetadataOnly => None,
        }
    }

    pub fn encoding(self) -> Option<&'static str> {
        match self {
            BodyMode::Compressed => Some("gzip"),
            BodyMode::Raw | BodyMode::MetadataOnly => None,
        }
    }
}

impl std::fmt::Display for BodyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyMode::Compressed => write!(f, "compressed"),
            BodyMode::Raw => write!(f, "raw"),
            BodyMode::MetadataOnly => write!(f, "metadata_only"),
        }
    }
}

impl Config {
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
        } else {
            Ok(Self::default())
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.storage.backend != "local" {
            bail!(
                "storage.backend={} is not implemented yet; use backend=\"local\"",
                self.storage.backend
            );
        }
        if !self.server.admin_prefix.starts_with('/') {
            bail!("server.admin_prefix must start with /");
        }
        if self.body.preview_limit > self.body.max_body_size {
            bail!("body.preview_limit cannot be greater than body.max_body_size");
        }
        for rule in &self.paths {
            if !rule.path_match.starts_with('/') {
                bail!("path rule match must start with /: {}", rule.path_match);
            }
        }
        validate_status(self.responder.status)?;
        for name in self.responder.headers.keys() {
            validate_header_name(name)?;
        }
        for rule in &self.responders {
            if !rule.path_match.starts_with('/') {
                bail!("responder match must start with /: {}", rule.path_match);
            }
            if let Some(status) = rule.status {
                validate_status(status)?;
            }
            for name in rule.headers.keys() {
                validate_header_name(name)?;
            }
        }
        Ok(())
    }

    pub fn rule_for_path(&self, path: &str) -> ResolvedPathRule {
        let mut resolved = ResolvedPathRule {
            ttl: self.retention.default_ttl,
            body_mode: self.body.mode,
            preview_limit: self.body.preview_limit,
            max_body_size: self.body.max_body_size,
        };

        for rule in self.paths.iter().filter(|rule| {
            path == rule.path_match
                || path.starts_with(&format!("{}/", rule.path_match.trim_end_matches('/')))
        }) {
            if let Some(ttl) = rule.ttl {
                resolved.ttl = ttl;
            }
            if let Some(mode) = rule.body_mode {
                resolved.body_mode = mode;
            }
            if let Some(limit) = rule.preview_limit {
                resolved.preview_limit = limit;
            }
            if let Some(limit) = rule.max_body_size {
                resolved.max_body_size = limit;
            }
        }

        resolved
    }

    pub fn responder_for_path(&self, path: &str) -> ResolvedResponder {
        let mut resolved = ResolvedResponder {
            status: self.responder.status,
            headers: self.responder.headers.clone(),
            body: self.responder.body.clone(),
        };

        for rule in self
            .responders
            .iter()
            .filter(|rule| path_matches(path, &rule.path_match))
        {
            if let Some(status) = rule.status {
                resolved.status = status;
            }
            resolved.headers.extend(rule.headers.clone());
            if let Some(body) = &rule.body {
                resolved.body = body.clone();
            }
        }

        resolved
    }
}


impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            username: default_admin_username(),
            password: None,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            admin_prefix: default_admin_prefix(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            root: default_storage_root(),
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            default_ttl: default_ttl(),
            cleanup_interval: default_cleanup_interval(),
            prune_grace: default_prune_grace(),
        }
    }
}

impl Default for BodyConfig {
    fn default() -> Self {
        Self {
            mode: BodyMode::Compressed,
            preview_limit: default_preview_limit(),
            max_body_size: default_max_body_size(),
        }
    }
}

impl Default for ResponderConfig {
    fn default() -> Self {
        let mut headers = BTreeMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        );
        Self {
            status: default_response_status(),
            headers,
            body: ResponderBody::MetadataJson,
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_admin_prefix() -> String {
    "/_wh_admin".to_string()
}

fn default_admin_username() -> String {
    "admin".to_string()
}

fn default_storage_backend() -> String {
    "local".to_string()
}

fn default_storage_root() -> PathBuf {
    PathBuf::from("./data")
}

fn default_ttl() -> Duration {
    Duration::from_secs(30 * 24 * 60 * 60)
}

fn default_cleanup_interval() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_prune_grace() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_preview_limit() -> u64 {
    5 * 1024 * 1024
}

fn default_max_body_size() -> u64 {
    100 * 1024 * 1024
}

fn default_response_status() -> u16 {
    200
}

fn validate_status(status: u16) -> anyhow::Result<()> {
    if !(100..=599).contains(&status) {
        bail!("invalid responder status: {}", status);
    }
    Ok(())
}

fn validate_header_name(name: &str) -> anyhow::Result<()> {
    axum::http::header::HeaderName::from_bytes(name.as_bytes())
        .with_context(|| format!("invalid responder header name: {name}"))?;
    Ok(())
}

fn path_matches(path: &str, rule: &str) -> bool {
    path == rule || path.starts_with(&format!("{}/", rule.trim_end_matches('/')))
}

fn deserialize_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_size(&value).map_err(serde::de::Error::custom)
}

fn deserialize_optional_size<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .as_deref()
        .map(parse_size)
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn parse_size(value: &str) -> anyhow::Result<u64> {
    let trimmed = value.trim();
    let split_at = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let number = trimmed[..split_at]
        .parse::<u64>()
        .with_context(|| format!("invalid size number: {value}"))?;
    let unit = trimmed[split_at..].trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        other => bail!("invalid size unit: {other}"),
    };
    Ok(number.saturating_mul(multiplier))
}
