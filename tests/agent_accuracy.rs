use agentclean::agents::{detect_agents_from, detect_agents_from_with_overrides, EntryKind};
use std::fs;
use tempfile::tempdir;

fn kinds_for(name: &str) -> Vec<(String, EntryKind, bool)> {
    let d = tempdir().unwrap();
    let root = d.path().join(name);
    fs::create_dir_all(&root).unwrap();
    for (path, body) in [
        ("settings.json", "{}"),
        (".env", "secret"),
        ("auth.json", "secret"),
        ("history.jsonl", "prompt"),
        ("projects/-work/session.jsonl", "transcript"),
        ("cache/changelog.md", "cache"),
        ("debug/run.log", "log"),
        ("tmp/image.bin", "tmp"),
        ("state.db", "db"),
        ("skills/my-skill/SKILL.md", "skill"),
        ("workspace/README.md", "user"),
        ("misc.bin", "unknown"),
    ] {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, body).unwrap();
    }
    let reports = detect_agents_from(
        d.path(),
        &d.path().join("config"),
        &d.path().join("cache"),
        &d.path().join("data"),
        &d.path().join("state"),
        &root,
    );
    reports
        .into_iter()
        .find(|r| r.name == "hermes")
        .unwrap()
        .entries
        .into_iter()
        .map(|e| {
            (
                e.path.strip_prefix(&root).unwrap().display().to_string(),
                e.kind,
                e.protected,
            )
        })
        .collect()
}

#[test]
fn real_agent_layouts_use_specific_categories_and_protection() {
    let entries = kinds_for(".hermes");
    let get = |path: &str| entries.iter().find(|(p, _, _)| p == path).unwrap();
    assert_eq!(get("settings.json").1, EntryKind::Config);
    assert_eq!(get(".env").1, EntryKind::Credentials);
    assert_eq!(get("auth.json").1, EntryKind::Credentials);
    assert_eq!(get("history.jsonl").1, EntryKind::History);
    assert_eq!(get("projects/-work/session.jsonl").1, EntryKind::Sessions);
    assert_eq!(get("cache/changelog.md").1, EntryKind::Cache);
    assert_eq!(get("debug/run.log").1, EntryKind::Logs);
    assert_eq!(get("tmp/image.bin").1, EntryKind::Temporary);
    assert_eq!(get("state.db").1, EntryKind::State);
    assert_eq!(get("skills/my-skill/SKILL.md").1, EntryKind::Workspace);
    assert_eq!(get("workspace/README.md").1, EntryKind::Workspace);
    assert_eq!(get("misc.bin").1, EntryKind::Unknown);
    assert!(get("projects/-work/session.jsonl").2);
    assert!(get("skills/my-skill/SKILL.md").2);
}

#[test]
fn detector_honors_claude_and_codex_overrides_without_scanning_nested_workspaces() {
    let d = tempdir().unwrap();
    let claude = d.path().join("claude-home");
    let codex = d.path().join("codex-home");
    fs::create_dir_all(claude.join("projects/-repo")).unwrap();
    fs::create_dir_all(codex.join("sessions")).unwrap();
    fs::write(claude.join("projects/-repo/a.jsonl"), "transcript").unwrap();
    fs::write(codex.join("config.toml"), "model = 'x'").unwrap();
    let reports = detect_agents_from_with_overrides(
        d.path(),
        &d.path().join("config"),
        &d.path().join("cache"),
        &d.path().join("data"),
        &d.path().join("state"),
        &d.path().join("hermes"),
        &claude,
        &codex,
    );
    assert!(
        reports
            .iter()
            .find(|r| r.name == "claude")
            .unwrap()
            .detected
    );
    assert!(reports.iter().find(|r| r.name == "codex").unwrap().detected);
}

#[test]
fn classification_uses_component_boundaries_and_protects_user_history() {
    let d = tempdir().unwrap();
    let root = d.path().join(".claude");
    for path in [
        "author.md",
        "configuration.txt",
        "sessionary.txt",
        "my-sessions/data.bin",
        "projects/-repo/transcript.jsonl",
        "history.jsonl",
        "settings.json",
        "auth.json",
        "state.db",
        "skills/example/SKILL.md",
    ] {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, "fixture").unwrap();
    }
    let reports = detect_agents_from(
        d.path(),
        &d.path().join("config"),
        &d.path().join("cache"),
        &d.path().join("data"),
        &d.path().join("state"),
        &root,
    );
    let entries = reports
        .into_iter()
        .find(|r| r.name == "hermes")
        .unwrap()
        .entries;
    let get = |path: &str| {
        entries
            .iter()
            .find(|entry| entry.path.strip_prefix(&root).unwrap().to_str() == Some(path))
            .unwrap()
    };
    assert_eq!(get("author.md").kind, EntryKind::Unknown);
    assert_eq!(get("configuration.txt").kind, EntryKind::Unknown);
    assert_eq!(get("sessionary.txt").kind, EntryKind::Unknown);
    assert_eq!(get("my-sessions/data.bin").kind, EntryKind::Unknown);
    assert_eq!(
        get("projects/-repo/transcript.jsonl").kind,
        EntryKind::Sessions
    );
    assert!(get("projects/-repo/transcript.jsonl").protected);
    assert_eq!(get("history.jsonl").kind, EntryKind::History);
    assert!(get("history.jsonl").protected);
}
