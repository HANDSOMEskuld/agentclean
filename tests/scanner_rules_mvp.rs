use agentclean::model::{Risk, ScanStatus};
use agentclean::rules::RuleSet;
use agentclean::scan::{scan_path, ScanOptions};
use std::fs;
use tempfile::tempdir;

#[test]
fn scanner_reports_age_explanation_and_apparent_allocated_bytes() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("cache.bin"), b"hello").unwrap();
    let report = scan_path(d.path(), &ScanOptions::default()).unwrap();
    let finding = &report.files[0];
    assert_eq!(report.status(), ScanStatus::Complete);
    assert_eq!(finding.apparent_bytes(), 5);
    assert!(finding.allocated_bytes() >= 5);
    assert!(finding.age_secs().is_some());
    assert!(!finding.explanation().summary.is_empty());
}
#[cfg(unix)]
#[test]
fn scanner_deduplicates_hardlinks_and_avoids_symlinks() {
    use std::os::unix::fs::symlink;
    let d = tempdir().unwrap();
    fs::write(d.path().join("one"), b"same").unwrap();
    fs::hard_link(d.path().join("one"), d.path().join("two")).unwrap();
    symlink(d.path().join("one"), d.path().join("link")).unwrap();
    let report = scan_path(d.path(), &ScanOptions::default()).unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.scanned_files, 1);
}
#[test]
fn scanner_limits_files_and_reports_partial() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("one"), b"1").unwrap();
    fs::write(d.path().join("two"), b"2").unwrap();
    let report = scan_path(
        d.path(),
        &ScanOptions {
            max_files: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(report.status(), ScanStatus::Partial);
    assert_eq!(report.scanned_files, 1);
}

#[cfg(unix)]
#[test]
fn scanner_rejects_symlink_root() {
    use std::os::unix::fs::symlink;
    let d = tempdir().unwrap();
    let target = tempdir().unwrap();
    symlink(target.path(), d.path().join("root")).unwrap();
    assert!(scan_path(&d.path().join("root"), &ScanOptions::default()).is_err());
}

#[test]
fn scanner_limits_depth_files_duration_and_exclusions() {
    let d = tempdir().unwrap();
    fs::create_dir(d.path().join("nested")).unwrap();
    fs::write(d.path().join("root"), b"1").unwrap();
    fs::write(d.path().join("nested/file"), b"2").unwrap();
    let options = ScanOptions {
        max_depth: Some(0),
        excluded_paths: vec![d.path().join("root")],
        ..Default::default()
    };
    let report = scan_path(d.path(), &options).unwrap();
    assert!(report.files.is_empty());
}
#[test]
fn missing_root_is_an_error() {
    let d = tempdir().unwrap();
    assert!(scan_path(&d.path().join("missing"), &ScanOptions::default()).is_err());
}

#[test]
fn rules_validate_version_and_cleanup_strategy() {
    let rules=RuleSet::from_yaml("version: 1\nrules:\n  - id: cache\n    pattern: '**/*.cache'\n    risk: safe\n    cleanup_strategy: quarantine\n").unwrap();
    assert_eq!(rules.version, 1);
    assert_eq!(rules.rules[0].risk, Risk::Safe);
    assert!(RuleSet::from_yaml("version: 99\nrules: []\n").is_err());
    assert!(RuleSet::from_yaml("version: 1\nrules:\n  - id: x\n    pattern: '*'\n    risk: safe\n    cleanup_strategy: nope\n").is_err());
}
