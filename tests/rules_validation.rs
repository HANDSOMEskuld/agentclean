use agentclean::rules::RuleSet;

#[test]
fn rules_reject_unknown_fields_and_duplicate_ids() {
    assert!(RuleSet::from_yaml(
        "version: 1\nrules:\n  - id: x\n    pattern: '*'\n    risk: safe\n    unknown: true\n"
    )
    .is_err());
    assert!(RuleSet::from_yaml("version: 1\nrules:\n  - id: x\n    pattern: '*'\n    risk: safe\n  - id: x\n    pattern: '**'\n    risk: safe\n").is_err());
}

#[test]
fn rules_reject_invalid_glob_and_missing_required_environment() {
    assert!(RuleSet::from_yaml(
        "version: 1\nrules:\n  - id: x\n    pattern: '[abc'\n    risk: safe\n"
    )
    .is_err());
    assert!(RuleSet::from_yaml("version: 1\nrules:\n  - id: x\n    pattern: '*'\n    risk: safe\n    paths: ['${AGENTCLEAN_MISSING_TEST_ENV}']\n").is_err());
}
