use agentclean::model::Risk;
use agentclean::rules::RuleSet;

#[test]
fn protected_risk_is_explicit_and_never_classified_as_cleanable() {
    let rules = RuleSet::from_yaml(
        "version: 1\nrules:\n  - id: credentials\n    pattern: '**/credentials.json'\n    risk: protected\n    cleanup_strategy: never\n",
    )
    .unwrap();
    assert_eq!(rules.classify("/tmp/credentials.json").0, Risk::Protected);
    assert!(RuleSet::from_yaml(
        "version: 1\nrules:\n  - id: bad\n    pattern: '*'\n    risk: protected\n    cleanup_strategy: quarantine\n"
    )
    .is_err());
}
