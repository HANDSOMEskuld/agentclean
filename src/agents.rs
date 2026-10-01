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
    detect_agents_from(&home, &config, &cache, &data, &state, &hermes)
}

pub fn detect_agents_from(
    home: &Path,
    config: &Path,
    cache: &Path,
    data: &Path,
    state: &Path,
    hermes: &Path,
) -> Vec<AgentReport> {
    vec![
        detect_one(
            "claude",
            vec![
                home.join(".claude"),
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
                home.join(".codex"),
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
    let detected = roots.iter().any(|root| root.is_dir());
    let mut entries = Vec::new();
    for root in &roots {
        if !root.is_dir() {
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
            let kind = classify(path);
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
    let text = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if [
        "credentials",
        "credential",
        "auth",
        "token",
        "tokens",
        "secrets",
        "api_keys",
        "apikeys",
    ]
    .iter()
    .any(|x| name.contains(x))
    {
        EntryKind::Credentials
    } else if ["config", "settings", "providers", "gateway"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        EntryKind::Config
    } else if ["session", "sessions", "conversation", "conversations"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        EntryKind::Sessions
    } else if ["history", "checkpoint", "snapshot"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        EntryKind::History
    } else if ["log", "logs", "debug"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        EntryKind::Logs
    } else if ["cache", "caches", "tmp", "temp", "temporary"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        if name.contains("tmp") || name.contains("temp") {
            EntryKind::Temporary
        } else {
            EntryKind::Cache
        }
    } else if ["project", "metadata"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        EntryKind::ProjectMetadata
    } else if ["workspace", "workspaces"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        EntryKind::Workspace
    } else if ["state", "data"]
        .iter()
        .any(|x| name.contains(x) || text.contains(&format!("/{x}/")))
    {
        EntryKind::State
    } else {
        EntryKind::Unknown
    }
}
