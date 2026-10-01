use crate::{
    core::cleanup::{CleanupEngine, Risk as CleanupRisk},
    model::{Risk, ScanReport},
};
use anyhow::Result;
use serde::Serialize;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Strategy {
    Quarantine,
    DeleteRebuildable,
    ExternalCommand,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupItem {
    pub path: PathBuf,
    pub expected_size: u64,
    pub risk: Risk,
    pub reason: String,
    pub strategy: Strategy,
    pub plugin: Option<String>,
    pub rule: Option<String>,
    pub operation: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CleanupPlan {
    pub root: PathBuf,
    pub items: Vec<CleanupItem>,
    pub blocked: Vec<CleanupItem>,
    pub total_reclaimable: u64,
    pub files: u64,
    pub directories: u64,
    pub dry_run: bool,
}

fn is_protected_path(path: &std::path::Path) -> bool {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect();
    parts.iter().any(|part| {
        matches!(
            part.as_str(),
            ".ssh"
                | ".gnupg"
                | "credentials"
                | "credential"
                | "auth"
                | "tokens"
                | "secrets"
                | ".git"
        )
    }) || parts
        .windows(2)
        .any(|pair| pair[0] == ".git" || (pair[0] == "git" && pair[1] == "worktrees"))
}

fn is_dirty_git_path(path: &std::path::Path) -> bool {
    let mut current = path.parent();
    while let Some(dir) = current {
        let dotgit = dir.join(".git");
        if dotgit.is_dir() || dotgit.is_file() {
            let status = std::process::Command::new("git")
                .args([
                    "-C",
                    &dir.to_string_lossy(),
                    "status",
                    "--porcelain",
                    "--untracked-files=all",
                ])
                .output();
            return status
                .map(|output| !output.status.success() || !output.stdout.is_empty())
                .unwrap_or(true);
        }
        current = dir.parent();
    }
    false
}

impl CleanupPlan {
    pub fn from_report(report: &ScanReport, dry_run: bool) -> Self {
        let mut items = Vec::new();
        let mut blocked = Vec::new();
        for f in &report.files {
            let safe = f.risk == Risk::Safe
                && report.status == crate::model::ScanStatus::Complete
                && !is_protected_path(&f.path)
                && !is_dirty_git_path(&f.path);
            let item = CleanupItem {
                path: f.path.clone(),
                expected_size: f.apparent_bytes,
                risk: f.risk,
                reason: f.explanation.summary.clone(),
                strategy: if safe {
                    Strategy::Quarantine
                } else {
                    Strategy::None
                },
                plugin: None,
                rule: f.rule_id.clone(),
                operation: if safe {
                    "quarantine".into()
                } else {
                    "blocked".into()
                },
            };
            if safe {
                items.push(item);
            } else {
                blocked.push(item);
            }
        }
        let total_reclaimable = items.iter().map(|i| i.expected_size).sum();
        Self {
            root: report.root.clone(),
            files: items.len() as u64,
            directories: 0,
            total_reclaimable,
            items,
            blocked,
            dry_run,
        }
    }

    pub fn execute(&self, state_dir: PathBuf) -> Result<Vec<String>> {
        if self.dry_run {
            return Ok(Vec::new());
        }
        for item in &self.items {
            if item.risk != Risk::Safe || item.strategy != Strategy::Quarantine {
                anyhow::bail!("plan contains a protected or unsupported operation");
            }
            if item
                .path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                anyhow::bail!("path traversal refused");
            }
            let metadata = std::fs::symlink_metadata(&item.path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() != item.expected_size
            {
                anyhow::bail!("candidate changed since scan: {}", item.path.display());
            }
        }
        if self.items.is_empty() {
            return Ok(Vec::new());
        }
        let engine = CleanupEngine::new(state_dir)?;
        let mut ids = Vec::new();
        for i in &self.items {
            let p = engine.plan(
                &i.path,
                i.rule.clone().unwrap_or_else(|| "cli-plan".into()),
                SystemTime::now() + Duration::from_secs(1),
                CleanupRisk::Low,
            )?;
            for entry in engine.execute(&p)? {
                ids.push(entry.id);
            }
        }
        Ok(ids)
    }
}
