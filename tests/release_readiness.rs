use agentclean::{
    history,
    model::Risk,
    planner::CleanupPlan,
    rules::RuleSet,
    scan::{scan_path, ScanOptions},
};
use std::fs;
use std::time::{Duration, SystemTime};

#[test]
fn safe_fixture_runs_scan_plan_quarantine_history_restore_verify() {
    let fixture = tempfile::tempdir_in("/var/tmp").unwrap();
    let cache = fixture.path().join("cache");
    fs::create_dir_all(&cache).unwrap();
    let file = cache.join("stale.cache");
    fs::write(&file, b"rebuildable fixture data").unwrap();
    let rules = RuleSet::from_yaml(&format!(
        "version: 1\nrules:\n  - id: fixture-cache\n    pattern: '{}'\n    risk: safe\n    cleanup_strategy: quarantine\n    rebuildable: true\n    min_age_days: 0\n",
        file.display()
    ))
    .unwrap();
    let report = scan_path(
        &cache,
        &ScanOptions {
            rules,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.files[0].risk, Risk::Safe);
    let plan = CleanupPlan::from_report(&report, false);
    assert_eq!(plan.items.len(), 1);
    assert_eq!(
        plan.total_reclaimable,
        b"rebuildable fixture data".len() as u64
    );
    let state = fixture.path().join("state");
    let ids = plan.execute(state.clone()).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(!file.exists());
    let entries = history::read(&state).unwrap();
    assert!(entries
        .iter()
        .any(|e| e.id == ids[0] && e.result == "moved"));
    // Older journals have no reason field; history and restore must still read them.
    let journal_path = state.join("journal");
    let journal = fs::read_to_string(&journal_path).unwrap();
    let legacy = journal
        .lines()
        .map(|line| {
            let (body, _) = line.rsplit_once('|').unwrap();
            let mut fields = body.split('|').collect::<Vec<_>>();
            fields.remove(5);
            *fields.last_mut().unwrap() = "v1";
            let body = fields.join("|");
            let checksum = body.bytes().fold(1469598103934665603u64, |h, b| {
                (h ^ b as u64).wrapping_mul(1099511628211)
            });
            format!("{body}|{checksum:016x}\n")
        })
        .collect::<String>();
    fs::write(journal_path, legacy).unwrap();
    let entries = history::read(&state).unwrap();
    assert!(entries.iter().all(|entry| entry.reason.is_empty()));
    let engine = agentclean::core::cleanup::CleanupEngine::new(&state).unwrap();
    let restored = engine.restore(&ids[0]).unwrap();
    assert_eq!(restored.id, ids[0]);
    assert_eq!(fs::read(&file).unwrap(), b"rebuildable fixture data");
    assert!(state.join("journal").is_file());
    let _ = SystemTime::now().checked_add(Duration::from_secs(0));
}

#[test]
fn controlled_fixture_covers_all_risks_and_cleanup_plan_boundaries() {
    let fixture = tempfile::tempdir_in("/var/tmp").unwrap();
    let safe = fixture.path().join("safe/cache/safe.bin");
    let caution = fixture.path().join("caution/cache/caution.bin");
    let dangerous = fixture.path().join("dangerous/cache/dangerous.bin");
    let protected = fixture.path().join("protected/credentials/protected.bin");
    let unknown = fixture.path().join("unknown/cache/unknown.bin");
    for path in [&safe, &caution, &dangerous, &protected, &unknown] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
    }
    fs::write(&safe, b"safe!").unwrap();
    fs::write(&caution, b"caution").unwrap();
    fs::write(&dangerous, b"dangerous!!").unwrap();
    fs::write(&protected, b"protected!!!!").unwrap();
    fs::write(&unknown, b"unknown..........").unwrap();

    let rules = RuleSet::from_yaml(&format!(
        "version: 1\nrules:\n  - id: safe\n    pattern: '{}'\n    risk: safe\n    cleanup_strategy: quarantine\n    rebuildable: true\n    min_age_days: 0\n  - id: caution\n    pattern: '{}'\n    risk: caution\n    cleanup_strategy: never\n  - id: dangerous\n    pattern: '{}'\n    risk: dangerous\n    cleanup_strategy: never\n  - id: protected\n    pattern: '{}'\n    risk: protected\n    cleanup_strategy: never\n",
        safe.display(), caution.display(), dangerous.display(), protected.display()
    ))
    .unwrap();
    let report = scan_path(
        fixture.path(),
        &ScanOptions {
            rules,
            ..Default::default()
        },
    )
    .unwrap();

    for (risk, expected_count, expected_bytes) in [
        (Risk::Safe, 1, 5),
        (Risk::Caution, 1, 7),
        (Risk::Dangerous, 1, 11),
        (Risk::Protected, 1, 13),
        (Risk::Unknown, 1, 17),
    ] {
        assert_eq!(
            report.files.iter().filter(|f| f.risk == risk).count(),
            expected_count,
            "count for {risk:?}"
        );
        assert_eq!(report.by_risk(risk), expected_bytes, "bytes for {risk:?}");
    }

    let plan = CleanupPlan::from_report(&report, false);
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.total_reclaimable, 5);
    assert_eq!(plan.blocked.len(), 4);
    let mut blocked_risks = plan
        .blocked
        .iter()
        .map(|item| item.risk)
        .collect::<Vec<_>>();
    blocked_risks.sort();
    assert_eq!(
        blocked_risks,
        vec![
            Risk::Caution,
            Risk::Dangerous,
            Risk::Protected,
            Risk::Unknown
        ]
    );
    assert!(plan.blocked.iter().all(|item| item.operation == "blocked"));
    assert_eq!(
        plan.blocked
            .iter()
            .map(|item| item.expected_size)
            .sum::<u64>(),
        48
    );
}

#[test]
fn cli_clean_restore_and_undo_mutate_only_isolated_fixture() {
    let fixture = tempfile::tempdir_in("/var/tmp").unwrap();
    let home = fixture.path().join("home");
    let cache = fixture.path().join("cache");
    let state = fixture.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&cache).unwrap();
    let safe = cache.join("safe.cache");
    let protected = cache.join("credentials.txt");
    fs::write(&safe, b"safe fixture").unwrap();
    fs::write(&protected, b"must remain").unwrap();
    let rules = fixture.path().join("rules.yml");
    fs::write(
        &rules,
        format!(
            "version: 1\nrules:\n  - id: isolated-safe\n    pattern: '{}'\n    risk: safe\n    cleanup_strategy: quarantine\n    rebuildable: true\n    min_age_days: 0\n",
            safe.display()
        ),
    )
    .unwrap();

    let clean = std::process::Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args([
            "clean",
            "--path",
            cache.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--execute",
            "--yes",
            "--json",
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(!safe.exists());
    assert_eq!(fs::read(&protected).unwrap(), b"must remain");
    assert!(state.join("quarantine/manifest.jsonl").is_file());

    let history_output = std::process::Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["history", "--state-dir", state.to_str().unwrap(), "--json"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(history_output.status.success());
    let history_json: serde_json::Value = serde_json::from_slice(&history_output.stdout).unwrap();
    let moved = history_json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["result"] == "moved")
        .unwrap();
    let id = moved["id"].as_str().unwrap();
    assert_eq!(moved["original_path"], safe.to_string_lossy().as_ref());
    assert_eq!(moved["size"], 12);
    assert!(!moved["reason"].as_str().unwrap_or_default().is_empty());
    let manifest = fs::read_to_string(state.join("quarantine/manifest.jsonl")).unwrap();
    let manifest_entry: serde_json::Value = serde_json::from_str(manifest.trim()).unwrap();
    assert_eq!(manifest_entry["reason"], moved["reason"]);
    assert!(moved["quarantine_path"]
        .as_str()
        .unwrap()
        .starts_with(state.to_str().unwrap()));

    let restore = std::process::Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args([
            "restore",
            id,
            "--state-dir",
            state.to_str().unwrap(),
            "--json",
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        restore.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    assert_eq!(fs::read(&safe).unwrap(), b"safe fixture");

    fs::remove_file(&safe).unwrap();
    fs::write(&safe, b"safe fixture").unwrap();
    let clean_again = std::process::Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args([
            "clean",
            "--path",
            cache.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--execute",
            "--yes",
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(clean_again.status.success());
    let undo = std::process::Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["undo", "--state-dir", state.to_str().unwrap(), "--json"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        undo.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&undo.stderr)
    );
    assert!(safe.exists());
}

#[test]
fn isolated_home_detects_claude_codex_hermes_and_developer_cache() {
    let fixture = tempfile::tempdir_in("/var/tmp").unwrap();
    let home = fixture.path().join("home");
    let config = home.join(".config");
    let cache = home.join(".cache");
    let hermes = home.join("hermes-data");
    for directory in [
        home.join(".claude"),
        home.join(".codex"),
        config.join("claude"),
        config.join("codex"),
        cache.join("claude"),
        cache.join("codex"),
        hermes.join("sessions"),
        cache.join("npm"),
    ] {
        fs::create_dir_all(&directory).unwrap();
    }
    fs::write(home.join(".claude/history.jsonl"), b"claude history").unwrap();
    fs::write(home.join(".codex/credentials.json"), b"[REDACTED]").unwrap();
    fs::write(hermes.join("sessions/session.json"), b"hermes session").unwrap();
    fs::write(cache.join("npm/package.tgz"), b"rebuildable npm cache").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args(["agents", "--json"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", &cache)
        .env("HERMES_HOME", &hermes)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for name in ["claude", "codex", "hermes"] {
        let agent = value["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["name"] == name)
            .unwrap();
        assert_eq!(agent["detected"], true, "{name} was not detected");
        assert!(!agent["entries"].as_array().unwrap().is_empty());
    }
    let codex_entry = value["agents"][1]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"].as_str().unwrap().contains("credentials"))
        .unwrap();
    assert_eq!(codex_entry["protected"], true);

    let rules = RuleSet::from_yaml(&format!(
        "version: 1\nrules:\n  - id: npm-cache\n    pattern: '{}'\n    risk: safe\n    cleanup_strategy: quarantine\n    rebuildable: true\n    min_age_days: 0\n",
        cache.join("npm/package.tgz").display()
    ))
    .unwrap();
    let report = scan_path(
        &cache.join("npm"),
        &ScanOptions {
            rules,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.files[0].risk, Risk::Safe);
}

#[test]
fn cli_analyze_loads_explicit_rules_and_reports_risk() {
    let fixture = tempfile::tempdir_in("/var/tmp").unwrap();
    let file = fixture.path().join("cache.bin");
    let rules = fixture.path().join("rules.yml");
    fs::write(&file, b"safe").unwrap();
    fs::write(
        &rules,
        format!(
            "version: 1\nrules:\n  - id: explicit-safe\n    pattern: '{}'\n    risk: safe\n    cleanup_strategy: quarantine\n    rebuildable: true\n    min_age_days: 0\n",
            file.display()
        ),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agentclean"))
        .args([
            "analyze",
            "--path",
            fixture.path().to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["findings"][0]["risk"], "safe");
}
