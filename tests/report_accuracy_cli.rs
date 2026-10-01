use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn scan_reports_completeness_and_separate_space_totals() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("user.txt"), b"user content").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["report", "--path", dir.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["status"], "COMPLETE");
    assert_eq!(v["space"]["apparent_bytes"], 12);
    assert_eq!(v["space"]["quarantine_freed_bytes"], 0);
    assert_eq!(v["space"]["by_risk"]["unknown"]["apparent_bytes"], 12);
}

#[test]
fn agents_report_observed_totals_and_category_breakdown() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".codex")).unwrap();
    fs::write(dir.path().join(".codex/auth.json"), b"fixture").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["agents", "--json"])
        .env("HOME", dir.path())
        .env("HERMES_HOME", dir.path().join("hermes"))
        .env("CODEX_HOME", dir.path().join(".codex"))
        .env("CLAUDE_CONFIG_DIR", dir.path().join(".claude"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let codex = v["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "codex")
        .unwrap();
    assert_eq!(codex["observed_apparent_bytes"], 7);
    assert_eq!(codex["by_category"]["credentials"]["apparent_bytes"], 7);
    assert_eq!(codex["by_category"]["credentials"]["files"], 1);
}
