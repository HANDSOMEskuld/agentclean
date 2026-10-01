#![cfg(unix)]

use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn fixture(body: &str) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    std::fs::write(
        &docker,
        format!("#!/usr/bin/python3\nimport sys, time, json\na = sys.argv[1:]\n{body}\n"),
    )
    .unwrap();
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["docker", "--json"])
        .env("DOCKER_BINARY", docker)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn drains_large_stdout_and_stderr_without_pipe_deadlock() {
    let report = fixture(
        r#"
if a[0] == 'info': print('26.1.5')
elif a[:2] == ['image', 'ls']:
    sys.stderr.write('diagnostic ' * 20000)
    for i in range(4000):
        print(json.dumps({'ID':str(i),'Repository':'fixture','Tag':'latest','Size':'1MB'}))
"#,
    );
    assert_eq!(report["images"].as_array().unwrap().len(), 4000, "{report}");
    assert_eq!(report["unsupported"], serde_json::json!([]));
}
