#[path = "../src/core/cleanup.rs"]
mod cleanup;

use cleanup::{CandidateResult, CleanupEngine, OperationResult, Risk};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from("/var/tmp").join(format!("agentclean-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}
fn old() -> SystemTime {
    SystemTime::now() + Duration::from_secs(1)
}

#[test]
fn quarantine_move_is_journaled_and_restore_returns_original() {
    let root = fixture("roundtrip");
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    let file = cache.join("stale.tmp");
    fs::write(&file, b"secret").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = engine
        .plan(&cache, "known-cache", old(), Risk::Low)
        .unwrap();
    assert_eq!(plan.freed_bytes, 0);
    let moved = engine.execute(&plan).unwrap();
    assert_eq!(moved.len(), 1);
    assert!(!file.exists());
    assert!(matches!(moved[0].result, OperationResult::Moved));
    assert_eq!(
        engine.restore(&moved[0].id).unwrap().result,
        OperationResult::Restored
    );
    assert_eq!(fs::read(&file).unwrap(), b"secret");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn protected_and_unknown_paths_are_refused() {
    let root = fixture("guards");
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    for name in [
        "Documents",
        "Desktop",
        "Pictures",
        "Videos",
        ".ssh",
        ".gnupg",
        "config",
        "credentials",
        "source",
    ] {
        let p = root.join(name).join("cache");
        fs::create_dir_all(&p).unwrap();
        assert!(engine.plan(&p, "r", old(), Risk::Low).is_err(), "{name}");
    }
    let unknown = root.join("project").join("data");
    fs::create_dir_all(&unknown).unwrap();
    assert!(engine.plan(unknown, "r", old(), Risk::Low).is_err());
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn symlink_source_is_never_traversed() {
    use std::os::unix::fs::symlink;
    let root = fixture("symlink");
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    let target = root.join("outside");
    fs::write(&target, b"must stay").unwrap();
    symlink(&target, cache.join("link")).unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    assert!(engine.plan(&cache, "r", old(), Risk::Low).is_err());
    assert!(target.exists());
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn symlinked_source_ancestor_is_refused() {
    use std::os::unix::fs::symlink;

    let root = fixture("symlink-ancestor");
    let real = root.join("real");
    let cache = real.join("cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("x"), b"must stay").unwrap();
    symlink(&real, root.join("linked")).unwrap();

    let engine = CleanupEngine::new(root.join("state")).unwrap();
    assert!(engine
        .plan(root.join("linked/cache"), "r", old(), Risk::Low)
        .is_err());
    assert!(cache.join("x").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cleanup_state_inside_source_is_refused() {
    let root = fixture("state-overlap");
    let cache = root.join("cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("x"), b"must stay").unwrap();
    let engine = CleanupEngine::new(cache.join("state")).unwrap();
    assert!(engine.plan(&cache, "r", old(), Risk::Low).is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn restore_refuses_overwrite() {
    let root = fixture("overwrite");
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    let file = cache.join("x");
    fs::write(&file, b"one").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = engine.plan(&cache, "r", old(), Risk::Low).unwrap();
    let moved = engine.execute(&plan).unwrap().remove(0);
    fs::write(&file, b"replacement").unwrap();
    assert!(engine.restore(&moved.id).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"replacement");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn changed_candidate_is_revalidated_before_move() {
    let root = fixture("race");
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    let file = cache.join("x");
    fs::write(&file, b"one").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = engine.plan(&cache, "r", old(), Risk::Low).unwrap();
    fs::write(&file, b"changed").unwrap();
    assert!(engine.execute(&plan).is_err());
    assert!(file.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn concurrent_state_lock_fails_closed() {
    let root = fixture("lock");
    let e1 = CleanupEngine::new(root.join("state")).unwrap();
    let _guard = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(e1.state_dir.join(".lock"))
        .unwrap();
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    fs::write(cache.join("x"), b"x").unwrap();
    let plan = e1.plan(&cache, "r", old(), Risk::Low).unwrap();
    assert!(e1.execute(&plan).is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn malformed_rule_and_journal_fail_closed() {
    let root = fixture("tamper");
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    fs::write(cache.join("x"), b"x").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    assert!(engine.plan(&cache, "../delete", old(), Risk::Low).is_err());
    fs::write(engine.state_dir.join("journal"), b"tampered\n").unwrap();
    assert!(engine.restore("q-1").is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn refused_candidates_cannot_be_executed() {
    let root = fixture("refused");
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = cleanup::Plan {
        candidates: vec![cleanup::Candidate {
            source: root.join("cache"),
            size: 0,
            modified: SystemTime::now(),
            result: CandidateResult::Refused("no".into()),
        }],
        rule_id: "r".into(),
        risk: Risk::High,
        freed_bytes: 0,
    };
    assert!(engine.execute(&plan).is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn caution_and_high_risk_plans_refuse_before_move_or_state_mutation() {
    for risk in [Risk::Caution, Risk::High] {
        let root = fixture(&format!("risk-{risk:?}"));
        let cache = root.join("cache");
        fs::create_dir(&cache).unwrap();
        let file = cache.join("x");
        fs::write(&file, b"must stay").unwrap();
        let engine = CleanupEngine::new(root.join("state")).unwrap();
        let plan = engine.plan(&cache, "r", old(), risk).unwrap();

        assert!(engine.execute(&plan).is_err());
        assert!(file.exists());
        assert!(!root.join("state/journal").exists());
        assert!(fs::read_dir(root.join("state/quarantine"))
            .unwrap()
            .next()
            .is_none());
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn direct_engine_refuses_candidates_inside_dirty_git_repository() {
    let root = fixture("dirty-git");
    fs::create_dir(root.join(".git")).unwrap();
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    let file = cache.join("untracked.cache");
    fs::write(&file, b"must stay").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();

    assert!(engine.plan(&cache, "r", old(), Risk::Low).is_err());

    let metadata = fs::metadata(&file).unwrap();
    let plan = cleanup::Plan {
        candidates: vec![cleanup::Candidate {
            source: file.clone(),
            size: metadata.len(),
            modified: metadata.modified().unwrap(),
            result: CandidateResult::Eligible,
        }],
        rule_id: "r".into(),
        risk: Risk::Low,
        freed_bytes: 0,
    };
    assert!(engine.execute(&plan).is_err());
    assert!(file.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn successful_quarantine_move_writes_manifest_record() {
    let root = fixture("manifest");
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    let file = cache.join("stale.tmp");
    fs::write(&file, b"manifest me").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = engine
        .plan(&cache, "known-cache", old(), Risk::Low)
        .unwrap();

    let moved = engine.execute(&plan).unwrap().remove(0);
    let manifest = fs::read_to_string(engine.state_dir.join("quarantine/manifest.jsonl")).unwrap();
    let record: serde_json::Value = serde_json::from_str(manifest.trim()).unwrap();

    assert_eq!(record["original_path"], file.to_string_lossy().as_ref());
    assert_eq!(
        record["quarantine_path"],
        moved.quarantine_path.to_string_lossy().as_ref()
    );
    assert_eq!(record["size"], 11);
    assert!(record["timestamp"].as_u64().is_some());
    assert_eq!(record["rule"], "known-cache");
    assert_eq!(record["risk"], "low");
    assert_eq!(record["operation"], "moved");
    assert!(engine.state_dir.join("journal").is_file());
    assert!(!file.exists());
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn state_quarantine_symlink_is_refused() {
    use std::os::unix::fs::symlink;

    let root = fixture("quarantine-symlink");
    let state = root.join("state");
    let outside = root.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir(&state).unwrap();
    symlink(&outside, state.join("quarantine")).unwrap();

    assert!(CleanupEngine::new(&state).is_err());
    assert!(outside.read_dir().unwrap().next().is_none());
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn restore_refuses_symlinked_original_parent() {
    use std::os::unix::fs::symlink;

    let root = fixture("restore-parent-symlink");
    let cache = root.join("cache");
    let outside = root.join("outside");
    fs::create_dir(&cache).unwrap();
    fs::create_dir(&outside).unwrap();
    let file = cache.join("x");
    fs::write(&file, b"protected").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = engine.plan(&cache, "r", old(), Risk::Low).unwrap();
    let moved = engine.execute(&plan).unwrap().remove(0);

    fs::remove_dir(&cache).unwrap();
    symlink(&outside, &cache).unwrap();
    assert!(engine.restore(&moved.id).is_err());
    assert!(!outside.join("x").exists());
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn restore_refuses_quarantine_symlink_even_if_target_is_inside_quarantine() {
    use std::os::unix::fs::symlink;

    let root = fixture("restore-quarantine-symlink");
    let cache = root.join("cache");
    fs::create_dir(&cache).unwrap();
    let file = cache.join("x");
    fs::write(&file, b"protected").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = engine.plan(&cache, "r", old(), Risk::Low).unwrap();
    let moved = engine.execute(&plan).unwrap().remove(0);
    let target = moved.quarantine_path.with_extension("target");
    fs::rename(&moved.quarantine_path, &target).unwrap();
    symlink(&target, &moved.quarantine_path).unwrap();

    assert!(engine.restore(&moved.id).is_err());
    assert!(!file.exists());
    let _ = fs::remove_dir_all(root);
}
