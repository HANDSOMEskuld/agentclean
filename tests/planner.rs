use agentclean::{
    model::{Finding, FindingExplanation, Risk, ScanReport, ScanStatus},
    planner::CleanupPlan,
};
use std::path::PathBuf;

fn report() -> ScanReport {
    ScanReport {
        root: PathBuf::from("/tmp/fixture"),
        files: vec![
            Finding {
                path: PathBuf::from("/tmp/fixture/cache/a.bin"),
                bytes: 10,
                apparent_bytes: 10,
                allocated_bytes: 10,
                reclaimable_allocated_bytes: 10,
                modified_secs: 1,
                age_secs: Some(100),
                risk: Risk::Safe,
                rule_id: Some("cache".into()),
                kind: "file".into(),
                explanation: FindingExplanation {
                    summary: "old cache".into(),
                    ..Default::default()
                },
            },
            Finding {
                path: PathBuf::from("/tmp/fixture/cache/b.bin"),
                bytes: 20,
                apparent_bytes: 20,
                allocated_bytes: 20,
                reclaimable_allocated_bytes: 20,
                modified_secs: 1,
                age_secs: Some(100),
                risk: Risk::Safe,
                rule_id: Some("cache".into()),
                kind: "file".into(),
                explanation: FindingExplanation {
                    summary: "old cache".into(),
                    ..Default::default()
                },
            },
            Finding {
                path: PathBuf::from("/tmp/fixture/config/token"),
                bytes: 3,
                apparent_bytes: 3,
                allocated_bytes: 3,
                reclaimable_allocated_bytes: 3,
                modified_secs: 1,
                age_secs: Some(100),
                risk: Risk::Dangerous,
                rule_id: Some("credentials".into()),
                kind: "file".into(),
                explanation: FindingExplanation {
                    summary: "credential".into(),
                    ..Default::default()
                },
            },
        ],
        status: ScanStatus::Complete,
        ..Default::default()
    }
}

#[test]
fn planner_preserves_file_granularity_and_blocks_non_safe() {
    let plan = CleanupPlan::from_report(&report(), true);
    assert_eq!(plan.items.len(), 2);
    assert!(plan.items.iter().all(|item| item.path.is_file()
        || item.path.ends_with("a.bin")
        || item.path.ends_with("b.bin")));
    assert_eq!(plan.total_reclaimable, 30);
    assert_eq!(plan.blocked.len(), 1);
    assert_eq!(plan.blocked[0].operation, "blocked");
}

#[test]
fn dry_run_execute_never_creates_state_or_moves_files() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("not-created");
    let plan = CleanupPlan::from_report(&report(), true);
    assert!(plan.execute(state.clone()).is_ok());
    assert!(!state.exists());
}

#[test]
fn partial_report_has_no_executable_items() {
    let mut r = report();
    r.status = ScanStatus::Partial;
    let plan = CleanupPlan::from_report(&r, false);
    assert!(plan.items.is_empty());
    assert_eq!(plan.blocked.len(), 3);
}

#[test]
fn execution_rejects_tampered_protected_item_before_state_creation() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let mut plan = CleanupPlan::from_report(&report(), false);
    plan.items[0].risk = Risk::Protected;
    assert!(plan.execute(state.clone()).is_err());
    assert!(!state.exists());
}

#[test]
fn execution_rejects_scan_to_plan_size_change_before_state_creation() {
    let scratch = tempfile::tempdir().unwrap();
    let cache = scratch.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    let file = cache.join("a.bin");
    std::fs::write(&file, b"changed data").unwrap();
    let state = scratch.path().join("state");
    let mut r = report();
    r.files.truncate(1);
    r.files[0].path = file.clone();
    let plan = CleanupPlan::from_report(&r, false);
    assert!(plan.execute(state.clone()).is_err());
    assert!(!state.exists());
    assert_eq!(std::fs::read(file).unwrap(), b"changed data");
}

#[test]
fn dirty_git_candidates_are_blocked_before_execution() {
    let dir = tempfile::tempdir().unwrap();
    std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    let cache = dir.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    let file = cache.join("old.cache");
    std::fs::write(&file, b"cache").unwrap();
    let mut r = report();
    r.files.truncate(1);
    r.root = dir.path().to_path_buf();
    r.files[0].path = file;
    let plan = CleanupPlan::from_report(&r, false);
    assert!(plan.items.is_empty());
    assert_eq!(plan.blocked.len(), 1);
}
