use agentclean::{
    model::Risk,
    scan::{scan_path, ScanOptions},
};
use std::fs;
use tempfile::tempdir;

#[test]
fn scan_reports_files_without_following_links() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("a.cache"), b"hello").unwrap();
    let report = scan_path(d.path(), &ScanOptions::default()).unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.files[0].bytes, 5);
    assert!(matches!(
        report.files[0].risk,
        Risk::Unknown | Risk::Safe | Risk::Caution
    ));
}

#[test]
fn rules_parse_and_classify_cache() {
    let yaml = "rules:\n  - id: npm\n    pattern: '**/node_modules/.cache/**'\n    risk: safe\n";
    let rules = agentclean::rules::RuleSet::from_yaml(yaml).unwrap();
    assert_eq!(rules.rules.len(), 1);
}
