use crate::{
    model::{Finding, Risk, ScanReport, ScanStatus},
    rules::{CleanupStrategy, RuleSet},
};
use anyhow::{bail, Result};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub rules: RuleSet,
    pub max_files: Option<usize>,
    pub max_depth: Option<usize>,
    pub max_duration: Option<Duration>,
    pub excluded_paths: Vec<PathBuf>,
}

pub fn scan_path(root: &Path, options: &ScanOptions) -> Result<ScanReport> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() {
        bail!("scan root is not a directory: {}", root.display());
    }
    if meta.file_type().is_symlink() {
        bail!("scan root may not be a symlink: {}", root.display());
    }
    let started = Instant::now();
    let mut out = ScanReport {
        root: root.to_path_buf(),
        ..Default::default()
    };
    let excluded: Vec<PathBuf> = options
        .excluded_paths
        .iter()
        .map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();
    let mut identities = HashSet::new();
    let mut it = WalkDir::new(root).follow_links(false).into_iter();
    while let Some(item) = it.next() {
        if options.max_duration.is_some_and(|d| started.elapsed() >= d)
            || options
                .max_files
                .is_some_and(|m| out.scanned_files as usize >= m)
        {
            out.status = ScanStatus::Partial;
            break;
        }
        let entry = match item {
            Ok(e) => e,
            Err(e) => {
                out.errors.push(e.to_string());
                out.status = ScanStatus::Partial;
                continue;
            }
        };
        if options
            .max_depth
            .is_some_and(|d| entry.depth() >= d && entry.file_type().is_dir())
        {
            it.skip_current_dir();
            continue;
        }
        if options.max_depth.is_some_and(|d| entry.depth() > d) {
            continue;
        }
        let path = entry.path();
        let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if excluded
            .iter()
            .any(|x| canonical == *x || canonical.starts_with(x))
        {
            if entry.file_type().is_dir() {
                it.skip_current_dir();
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let md = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                out.errors.push(format!("{}: {}", path.display(), e));
                out.status = ScanStatus::Partial;
                continue;
            }
        };
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            (md.dev(), md.ino())
        };
        #[cfg(not(unix))]
        let identity = (canonical.clone(), md.len(), md.modified().ok());
        if !identities.insert(identity) {
            continue;
        }
        let bytes = md.len();
        let modified = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let path_text = path.to_string_lossy();
        let rule = options.rules.matching_rule(&path_text);
        let (mut risk, id) = rule
            .map(|r| (r.risk, Some(r.id.clone())))
            .unwrap_or((Risk::Unknown, None));
        if path.components().any(|c| matches!(c, std::path::Component::Normal(n) if [".ssh", ".gnupg", "credentials", "config", "auth"].iter().any(|x| n == *x))) { risk = Risk::Protected; }
        if let Some(r) = rule {
            let age = md
                .modified()
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map_or(0, |d| d.as_secs());
            if risk == Risk::Safe
                && (age < r.min_age_days.saturating_mul(86400)
                    || !r.rebuildable
                    || matches!(
                        r.cleanup_strategy,
                        CleanupStrategy::Never | CleanupStrategy::AnalysisOnly
                    ))
            {
                risk = Risk::Caution;
            }
        }
        out.scanned_files += 1;
        out.scanned_bytes = out.scanned_bytes.saturating_add(bytes);
        let allocated = allocated_bytes(&md);
        out.files.push(Finding {
            path: path.to_path_buf(),
            bytes,
            apparent_bytes: bytes,
            allocated_bytes: allocated,
            modified_secs: modified,
            age_secs: md
                .modified()
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|d| d.as_secs()),
            risk,
            rule_id: id.clone(),
            kind: "file".into(),
            explanation: crate::model::FindingExplanation {
                summary: format!("{:?} filesystem file", risk),
                rule: id,
                details: vec![format!("apparent={} allocated={}", bytes, allocated)],
            },
        });
    }
    if !out.errors.is_empty() {
        out.status = ScanStatus::Partial;
    }
    out.duration_ms = started.elapsed().as_millis();
    Ok(out)
}
#[cfg(unix)]
fn allocated_bytes(md: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    md.blocks().saturating_mul(512)
}
#[cfg(not(unix))]
fn allocated_bytes(md: &fs::Metadata) -> u64 {
    md.len()
}
pub fn scan_home() -> Result<ScanReport> {
    scan_path(
        &dirs::home_dir().unwrap_or_else(|| Path::new(".").to_path_buf()),
        &ScanOptions::default(),
    )
}
