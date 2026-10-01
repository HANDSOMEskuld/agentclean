use agentclean::agents::{detect_agents, EntryKind};
use std::fs;
use tempfile::tempdir;

#[test]
fn detectors_honor_hermes_home_and_protect_credentials() {
    let home = tempdir().unwrap();
    let hermes = home.path().join("custom-hermes");
    fs::create_dir_all(hermes.join("sessions")).unwrap();
    fs::write(hermes.join("credentials.json"), "secret").unwrap();
    fs::write(hermes.join("sessions/session.jsonl"), "event").unwrap();
    let old_home = std::env::var_os("HOME");
    let old_hermes = std::env::var_os("HERMES_HOME");
    std::env::set_var("HOME", home.path());
    std::env::set_var("HERMES_HOME", &hermes);
    let result = detect_agents();
    if let Some(v) = old_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }
    if let Some(v) = old_hermes {
        std::env::set_var("HERMES_HOME", v);
    } else {
        std::env::remove_var("HERMES_HOME");
    }
    let hermes = result.into_iter().find(|a| a.name == "hermes").unwrap();
    assert!(hermes.detected);
    assert!(hermes
        .entries
        .iter()
        .any(|e| e.kind == EntryKind::Credentials && e.protected));
    assert!(hermes.entries.iter().any(|e| e.kind == EntryKind::Sessions));
}

#[test]
fn detectors_use_xdg_roots_without_recursive_unbounded_scan() {
    let home = tempdir().unwrap();
    let config = home.path().join("config");
    fs::create_dir_all(config.join("claude/projects")).unwrap();
    fs::write(config.join("claude/config.json"), "{}").unwrap();
    let old_home = std::env::var_os("HOME");
    let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
    std::env::set_var("HOME", home.path());
    std::env::set_var("XDG_CONFIG_HOME", &config);
    let result = detect_agents();
    if let Some(v) = old_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }
    if let Some(v) = old_xdg {
        std::env::set_var("XDG_CONFIG_HOME", v);
    } else {
        std::env::remove_var("XDG_CONFIG_HOME");
    }
    let claude = result.into_iter().find(|a| a.name == "claude").unwrap();
    assert!(claude.detected);
    assert!(claude
        .entries
        .iter()
        .any(|e| e.path.ends_with("config.json")));
}
