use serde::Serialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Config,
    ProjectMetadata,
    Sessions,
    History,
    Logs,
    Cache,
    Temporary,
    Credentials,
    Workspace,
    State,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentEntry {
    pub path: PathBuf,
    pub kind: EntryKind,
    pub size: u64,
    pub protected: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentReport {
    pub name: String,
    pub detected: bool,
    pub roots: Vec<PathBuf>,
    pub entries: Vec<AgentEntry>,
    pub notes: Vec<String>,
}

pub fn detect_agents() -> Vec<AgentReport> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_default();
    let config = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let cache = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cache"));
    let data = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));
    let state = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/state"));
    let hermes = env::var_os("HERMES_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".hermes"));
    let claude_config = env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".claude"));
    let codex_home = env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"));
    detect_agents_from_with_overrides(
        &home,
        &config,
        &cache,
        &data,
        &state,
        &hermes,
        &claude_config,
        &codex_home,
    )
}

pub fn detect_agents_from(
    home: &Path,
    config: &Path,
    cache: &Path,
    data: &Path,
    state: &Path,
    hermes: &Path,
) -> Vec<AgentReport> {
    detect_agents_from_with_overrides(
        home,
        config,
        cache,
        data,
        state,
        hermes,
        &home.join(".claude"),
        &home.join(".codex"),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn detect_agents_from_with_overrides(
    home: &Path,
    config: &Path,
    cache: &Path,
    data: &Path,
    state: &Path,
    hermes: &Path,
    claude_config: &Path,
    codex_home: &Path,
) -> Vec<AgentReport> {
    vec![
        detect_one(
            "claude",
            vec![
                claude_config.to_path_buf(),
                home.join(".claude.json"),
                config.join("claude"),
                cache.join("claude"),
                data.join("claude"),
                state.join("claude"),
            ],
            false,
        ),
        detect_one(
            "codex",
            vec![
                codex_home.to_path_buf(),
                config.join("codex"),
                cache.join("codex"),
                data.join("codex"),
                state.join("codex"),
            ],
            false,
        ),
        detect_one(
            "hermes",
            vec![
                hermes.to_path_buf(),
                config.join("hermes"),
                cache.join("hermes"),
                data.join("hermes"),
                state.join("hermes"),
            ],
            true,
        ),
    ]
}

fn detect_one(name: &str, roots: Vec<PathBuf>, hermes: bool) -> AgentReport {
    let detected = roots.iter().any(|root| root.is_dir() || root.is_file());
    let mut entries = Vec::new();
    for root in &roots {
        if !root.is_dir() && !root.is_file() {
            continue;
        }
        for item in WalkDir::new(root)
            .follow_links(false)
            .max_depth(4)
            .into_iter()
            .filter_map(Result::ok)
            .take(5000)
        {
            let path = item.path();
            if item.file_type().is_symlink() || !item.file_type().is_file() {
                continue;
            }
            let metadata = match fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let kind = classify(path.strip_prefix(root).unwrap_or(path));
            let protected = matches!(
                kind,
                EntryKind::Credentials
                    | EntryKind::Config
                    | EntryKind::Workspace
                    | EntryKind::State
            ) || hermes && matches!(kind, EntryKind::Sessions | EntryKind::History);
            let reason = if protected {
                "May contain credentials, configuration, or user work; AgentClean will not remove it by default."
            } else {
                "Observed agent-owned data; classification is informational until an explicit rule permits cleanup."
            };
            entries.push(AgentEntry {
                path: path.to_path_buf(),
                kind,
                size: metadata.len(),
                protected,
                reason: reason.into(),
            });
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    AgentReport {
        name: name.into(),
        detected,
        roots,
        entries,
        notes: vec!["Detection is bounded, symlink-safe, and read-only.".into()],
    }
}

fn classify(path: &Path) -> EntryKind {
    let components: Vec<String> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(str::to_ascii_lowercase)
        .collect();
    let name = components.last().map(String::as_str).unwrap_or_default();
    let has_dir = |names: &[&str]| {
        components[..components.len().saturating_sub(1)]
            .iter()
            .any(|component| names.contains(&component.as_str()))
    };

    if [
        ".env",
        "auth",
        "auth.json",
        "auth.toml",
        "credentials",
        "credentials.json",
        "credentials.toml",
        "secrets",
        "token",
        "tokens",
        "api_keys",
        "apikeys",
    ]
    .contains(&name)
    {
        EntryKind::Credentials
    } else if [
        ".claude.json",
        "config",
        "config.json",
        "config.toml",
        "settings.json",
        "settings.local.json",
        "settings.toml",
        "providers.json",
        "managed-settings.json",
    ]
    .contains(&name)
        || has_dir(&["config", "providers", "gateway"])
    {
        EntryKind::Config
    } else if ["session.jsonl", "conversation.jsonl"].contains(&name)
        || has_dir(&["sessions", "projects", "conversations"])
    {
        EntryKind::Sessions
    } else if ["history", "history.jsonl", "checkpoint", "snapshot"].contains(&name)
        || has_dir(&["file-history", "checkpoints"])
    {
        EntryKind::History
    } else if ["log", "logs", "debug"].contains(&name)
        || name.ends_with(".log")
        || has_dir(&["logs", "debug"])
    {
        EntryKind::Logs
    } else if has_dir(&["tmp", "temp", "temporary"]) {
        EntryKind::Temporary
    } else if [
        "state",
        "state.db",
        "state.db-wal",
        "state.db-shm",
        "kanban.db",
        "gateway_state.json",
        "pid",
        "lock",
        "sock",
    ]
    .contains(&name)
        || has_dir(&["state", "runtime"])
    {
        EntryKind::State
    } else if [
        "cache",
        "caches",
        "paste-cache",
        "image-cache",
        "audio_cache",
        "scratch",
    ]
    .contains(&name)
        || has_dir(&["cache", "caches", "scratch"])
    {
        EntryKind::Cache
    } else if ["project", "metadata"].contains(&name) {
        EntryKind::ProjectMetadata
    } else if ["workspace", "workspaces", "skills", "memories"].contains(&name)
        || has_dir(&["workspace", "workspaces", "skills", "memories"])
        || ["soul.md", "claude.md", "agents.md"].contains(&name)
    {
        EntryKind::Workspace
    } else {
        EntryKind::Unknown
    }
}
