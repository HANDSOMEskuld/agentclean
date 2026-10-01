use std::process::Command;

#[test]
fn docker_command_returns_structured_read_only_inventory() {
    let out = Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["docker", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["command"], "docker");
    assert!(value.get("daemon_available").is_some());
    assert!(value.get("unsupported").is_some());
    assert!(value.get("errors").is_some());
}
