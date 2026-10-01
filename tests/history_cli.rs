use std::{
    path::Path,
    process::{Command, Output},
};

fn run(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(args)
        .arg("--state-dir")
        .arg(state)
        .output()
        .unwrap()
}

#[test]
fn history_and_restore_commands_are_real_and_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("missing-state");
    let history = run(&state, &["history", "--json"]);
    assert!(
        history.status.success(),
        "{}",
        String::from_utf8_lossy(&history.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(value["command"], "history");
    assert_eq!(value["entries"], serde_json::json!([]));
    assert!(!state.exists(), "history must be read-only");

    let restore = run(&state, &["restore", "not-a-journal-id", "--json"]);
    assert!(!restore.status.success());
    assert!(!state.exists());
}
