use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn analyze_json_is_stable_and_reports_fixture() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("old.cache"), b"abc").unwrap();
    let out = run(&["analyze", "--path", dir.path().to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["command"], "analyze");
    assert_eq!(value["scanned_files"], 1);
    assert!(value.get("scanned_bytes").is_some());
}

#[test]
fn inspect_json_contains_directory_summary() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested").join("x"), b"1234").unwrap();
    let out = run(&["inspect", "--path", dir.path().to_str().unwrap(), "--json"]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["command"], "inspect");
    assert_eq!(value["directories"][0]["files"], 1);
    assert_eq!(value["directories"][0]["bytes"], 4);
}

#[test]
fn dry_run_renders_plan_without_mutation() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("x.cache"), b"data").unwrap();
    let out = run(&["clean", "--path", dir.path().to_str().unwrap(), "--dry-run"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Dry run"));
    assert!(text.contains("No files were changed"));
    assert!(dir.path().join("x.cache").exists());
}

#[test]
fn agents_json_uses_environment_roots_and_stable_shape() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join(".claude")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["agents", "--json"])
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("xdg-config"))
        .env("XDG_CACHE_HOME", dir.path().join("xdg-cache"))
        .env("HERMES_HOME", dir.path().join("hermes"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["command"], "agents");
    assert!(value["agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["name"] == "claude" && a["detected"] == true));
    for agent in value["agents"].as_array().unwrap() {
        assert!(agent.get("paths").is_some());
        assert!(agent.get("entries").is_some());
    }
}

#[test]
fn doctor_json_has_checks_and_nonzero_when_path_missing() {
    let out = run(&["doctor", "--path", "/definitely/not/a/real/path", "--json"]);
    assert!(!out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["command"], "doctor");
    assert!(value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["status"] == "fail"));
}

#[test]
fn config_json_is_read_only_and_has_defaults() {
    let dir = tempdir().unwrap();
    let out = run(&[
        "config",
        "--path",
        dir.path().join("missing.yml").to_str().unwrap(),
        "--json",
    ]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["command"], "config");
    assert!(value["config"]["protected"].as_array().unwrap().len() >= 2);
}
