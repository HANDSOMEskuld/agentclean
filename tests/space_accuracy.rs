use agentclean::{
    planner::CleanupPlan,
    rules::RuleSet,
    scan::{scan_path, ScanOptions},
};
use std::fs;

fn fixture() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}
fn safe_options() -> ScanOptions {
    ScanOptions { rules: RuleSet::from_yaml("version: 1\nrules:\n  - id: fixture\n    pattern: '*'\n    risk: safe\n    cleanup_strategy: quarantine\n    rebuildable: true\n    min_age_days: 0\n").unwrap(), ..Default::default() }
}
#[test]
#[cfg(unix)]
fn sparse_potential_is_allocated_not_apparent_and_quarantine_frees_zero() {
    use std::os::unix::fs::MetadataExt;
    let dir = fixture();
    let path = dir.path().join("sparse.cache");
    fs::File::create(&path)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    let report = scan_path(dir.path(), &safe_options()).unwrap();
    let plan = CleanupPlan::from_report(&report, true);
    let json = serde_json::to_value(plan).unwrap();
    assert_eq!(
        json["potential_reclaimable_allocated_bytes"],
        fs::metadata(path).unwrap().blocks() * 512
    );
    assert_eq!(json["immediate_freed_bytes"], 0);
    assert_eq!(json["quarantine_apparent_bytes"], 64 * 1024 * 1024);
}

#[test]
#[cfg(unix)]
fn hardlinks_report_physical_allocation_but_zero_reclaimable_shared_space() {
    let dir = fixture();
    let first = dir.path().join("first.cache");
    let second = dir.path().join("second.cache");
    fs::write(&first, b"shared inode").unwrap();
    fs::hard_link(&first, &second).unwrap();
    let report = scan_path(dir.path(), &safe_options()).unwrap();
    assert_eq!(report.files.len(), 1, "one inode should be counted once");
    assert!(report.files[0].allocated_bytes > 0);
    let plan = CleanupPlan::from_report(&report, true);
    assert_eq!(plan.potential_reclaimable_allocated_bytes, 0);
}
