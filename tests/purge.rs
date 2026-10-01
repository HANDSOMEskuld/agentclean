use agentclean::core::cleanup;
use agentclean::core::cleanup::{CleanupEngine, PurgeOptions, Risk, MIN_RETENTION};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime},
};

fn fixture(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("agentclean-purge-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}
fn moved(name: &str) -> (PathBuf, CleanupEngine, cleanup::JournalEntry) {
    let root = fixture(name);
    fs::create_dir(root.join("cache")).unwrap();
    fs::write(root.join("cache/x"), b"rebuildable bytes").unwrap();
    let engine = CleanupEngine::new(root.join("state")).unwrap();
    let plan = engine
        .plan(
            root.join("cache"),
            "known-cache",
            SystemTime::now() + Duration::from_secs(1),
            Risk::Low,
        )
        .unwrap();
    let entry = engine.execute(&plan).unwrap().remove(0);
    (root, engine, entry)
}
#[test]
fn purge_defaults_to_read_only_dry_run() {
    let (root, engine, entry) = moved("dry-run");
    let journal = fs::read(engine.state_dir.join("journal")).unwrap();
    let plan = engine
        .plan_purge_at(
            std::slice::from_ref(&entry.id),
            MIN_RETENTION,
            SystemTime::now() + MIN_RETENTION + Duration::from_secs(1),
        )
        .unwrap();
    let report = engine.purge(&plan, PurgeOptions::default()).unwrap();
    assert!(report.dry_run);
    assert_eq!(report.logical_bytes, entry.size);
    assert!(report.allocated_bytes >= report.logical_bytes);
    assert_eq!(report.unlinked_bytes, 0);
    assert_eq!(report.observed_free_bytes, None);
    assert!(plan.allocated_bytes >= plan.logical_bytes);
    assert!(entry.quarantine_path.exists());
    assert_eq!(fs::read(engine.state_dir.join("journal")).unwrap(), journal);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn confirmed_purge_unlinks_quarantine_and_observes_filesystem_space() {
    let (root, engine, entry) = moved("confirmed");
    let plan = engine
        .plan_purge_at(
            std::slice::from_ref(&entry.id),
            MIN_RETENTION,
            SystemTime::now() + MIN_RETENTION + Duration::from_secs(1),
        )
        .unwrap();
    let report = engine
        .purge(&plan, PurgeOptions { confirmed: true })
        .unwrap();
    assert!(!report.dry_run);
    assert_eq!(report.purged_ids, vec![entry.id.clone()]);
    assert_eq!(report.unlinked_bytes, entry.size);
    assert!(!entry.quarantine_path.exists());
    assert!(report.observed_free_bytes.is_some());
    assert!(report.free_bytes_before.is_some());
    assert!(report.free_bytes_after.is_some());
    let journal = fs::read_to_string(engine.state_dir.join("journal")).unwrap();
    assert!(journal.lines().any(|line| line.contains("707572676564")));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn minimum_retention_is_enforced_even_for_explicit_purge() {
    let (root, engine, entry) = moved("retention");
    let too_soon = SystemTime::now() + Duration::from_secs(1);
    let plan = engine
        .plan_purge_at(&[entry.id], MIN_RETENTION, too_soon)
        .unwrap();
    assert!(plan.entries.is_empty());
    assert_eq!(plan.blocked.len(), 1);
    assert!(plan.blocked[0].reason.contains("retention"));
    assert!(entry.quarantine_path.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn purge_revalidates_all_entries_before_unlinking_any() {
    let (root, engine, first) = moved("atomic-validation-first");
    let (root2, engine2, second) = moved("atomic-validation-second");
    let now = SystemTime::now() + MIN_RETENTION + Duration::from_secs(1);
    let mut plan = engine
        .plan_purge_at(&[first.id], MIN_RETENTION, now)
        .unwrap();
    let other = engine2
        .plan_purge_at(&[second.id], MIN_RETENTION, now)
        .unwrap();
    plan.entries.extend(other.entries);
    plan.logical_bytes += second.size;
    plan.allocated_bytes += second.size;
    fs::remove_file(&second.quarantine_path).unwrap();
    assert!(engine.execute_purge(&plan, true).is_err());
    assert!(first.quarantine_path.exists());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(root2).unwrap();
}
