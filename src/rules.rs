use crate::model::Risk;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub pattern: String,
    pub risk: Risk,
    #[serde(default)]
    pub cleanup_strategy: CleanupStrategy,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rebuildable: bool,
    #[serde(default)]
    pub min_age_days: u64,
    #[serde(default)]
    pub exclusions: Vec<String>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStrategy {
    Never,
    #[default]
    AnalysisOnly,
    Quarantine,
    ToolAwareOnly,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    #[serde(default = "default_version")]
    pub version: u32,
    pub rules: Vec<Rule>,
}
fn default_version() -> u32 {
    1
}
impl Default for RuleSet {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
        }
    }
}

impl RuleSet {
    pub fn from_yaml(s: &str) -> Result<Self> {
        let rules: Self = serde_yaml::from_str(s)?;
        rules.validate()?;
        Ok(rules)
    }
    pub fn load(path: &std::path::Path) -> Result<Self> {
        Self::from_yaml(&std::fs::read_to_string(path)?)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported rule schema version {}", self.version);
        }
        let mut ids = HashSet::new();
        for r in &self.rules {
            if r.id.trim().is_empty() || r.pattern.trim().is_empty() {
                bail!("rule id and pattern are required");
            }
            if !ids.insert(&r.id) {
                bail!("duplicate rule id {}", r.id);
            }
            validate_glob(&r.pattern)?;
            for p in &r.paths {
                validate_env(p)?;
            }
            for p in &r.exclusions {
                validate_env(p)?;
            }
            if matches!(r.risk, Risk::Unknown | Risk::Protected)
                && !matches!(
                    r.cleanup_strategy,
                    CleanupStrategy::Never | CleanupStrategy::AnalysisOnly
                )
            {
                bail!(
                    "protected or unknown-risk rule {} must not be cleanable",
                    r.id
                );
            }
        }
        Ok(())
    }
    pub fn classify(&self, path: &str) -> (Risk, Option<String>) {
        self.matching_rule(path)
            .map(|r| (r.risk, Some(r.id.clone())))
            .unwrap_or((Risk::Unknown, None))
    }
    pub(crate) fn matching_rule(&self, path: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| glob_match(&r.pattern, path))
    }
}

fn validate_env(s: &str) -> Result<()> {
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        let tail = &rest[start + 2..];
        let end = tail
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unterminated environment variable in {}", s))?;
        let expr = &tail[..end];
        let name = expr.split_once(":-").map_or(expr, |(n, _)| n);
        if name.is_empty() {
            bail!("empty environment variable in {}", s);
        }
        if !expr.contains(":-") && std::env::var(name).is_err() {
            bail!("missing environment variable {}", name);
        }
        rest = &tail[end + 1..];
    }
    Ok(())
}
fn validate_glob(p: &str) -> Result<()> {
    let mut bracket = false;
    let mut escaped = false;
    for c in p.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '[' {
            if bracket {
                bail!("invalid glob pattern {}", p);
            }
            bracket = true;
        }
        if c == ']' {
            if !bracket {
                bail!("invalid glob pattern {}", p);
            }
            bracket = false;
        }
    }
    if bracket || escaped {
        bail!("invalid glob pattern {}", p);
    }
    Ok(())
}
fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    fn go(p: &[char], v: &[char]) -> bool {
        if p.is_empty() {
            return v.is_empty();
        }
        match p[0] {
            '*' => (0..=v.len()).any(|n| go(&p[1..], &v[n..])),
            '?' => !v.is_empty() && go(&p[1..], &v[1..]),
            '[' => {
                if let Some(end) = p.iter().position(|&c| c == ']') {
                    !v.is_empty() && p[1..end].contains(&v[0]) && go(&p[end + 1..], &v[1..])
                } else {
                    false
                }
            }
            c => !v.is_empty() && c == v[0] && go(&p[1..], &v[1..]),
        }
    }
    go(&p, &v)
}
