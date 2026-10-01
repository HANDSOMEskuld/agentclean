//! Fail-closed, quarantine-only cleanup engine.
//!
//! This module intentionally uses only the standard library so the safety boundary is
//! easy to audit and can be integrated into the core crate without a dependency policy.

use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    Low,
    Caution,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateResult {
    Eligible,
    Refused(String),
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub source: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
    pub result: CandidateResult,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub candidates: Vec<Candidate>,
    pub rule_id: String,
    pub risk: Risk,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationResult {
    Prepared,
    Moved,
    Restored,
    Refused(String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub timestamp: u128,
    pub size: u64,
    pub rule: String,
    pub reason: String,
    pub risk: Risk,
    pub platform: String,
    pub host: String,
    pub result: OperationResult,
    pub quarantine_path: PathBuf,
}

#[derive(Debug)]
pub struct CleanupError(pub String);
impl std::fmt::Display for CleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CleanupError {}
impl From<io::Error> for CleanupError {
    fn from(e: io::Error) -> Self {
        Self(e.to_string())
    }
}
type Result<T> = std::result::Result<T, CleanupError>;

#[derive(Debug, Clone)]
pub struct CleanupEngine {
    pub state_dir: PathBuf,
}

impl CleanupEngine {
    pub fn new(state_dir: impl Into<PathBuf>) -> Result<Self> {
        let state_dir = state_dir.into();
        if state_dir.as_os_str().is_empty() || state_dir.parent().is_none() {
            return Err(CleanupError("invalid state directory".into()));
        }
        reject_symlink_ancestors(&state_dir)?;
        if state_dir.exists() && fs::symlink_metadata(&state_dir)?.file_type().is_symlink() {
            return Err(CleanupError("state directory is a symlink".into()));
        }
        let quarantine_dir = state_dir.join("quarantine");
        if quarantine_dir.exists() {
            let quarantine_meta = fs::symlink_metadata(&quarantine_dir)?;
            if quarantine_meta.file_type().is_symlink() || !quarantine_meta.is_dir() {
                return Err(CleanupError(
                    "quarantine directory is not a real directory".into(),
                ));
            }
        }
        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&quarantine_dir)?;
        #[cfg(unix)]
        {
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&quarantine_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { state_dir })
    }

    /// Read-only analysis. A single unsafe member refuses the complete plan.
    pub fn plan(
        &self,
        path: impl AsRef<Path>,
        rule_id: impl Into<String>,
        older_than: SystemTime,
        risk: Risk,
    ) -> Result<Plan> {
        let path = path.as_ref();
        let rule_id = rule_id.into();
        if rule_id.is_empty()
            || rule_id.contains('/')
            || rule_id.contains('\\')
            || rule_id.contains("..")
        {
            return Err(CleanupError("malformed rule id".into()));
        }
        let mut candidates = Vec::new();
        let root = self.validate_source_root(path)?;
        self.refuse_git_repository(&root)?;
        let mut stack = vec![root];
        while let Some(p) = stack.pop() {
            let sm = fs::symlink_metadata(&p)?;
            if sm.file_type().is_symlink() {
                return Err(CleanupError(format!("symlink refused: {}", p.display())));
            }
            if sm.is_dir() {
                self.validate_dir(&p)?;
                for e in fs::read_dir(&p)? {
                    stack.push(e?.path());
                }
            } else if sm.is_file() {
                let modified = sm.modified()?;
                if modified <= older_than {
                    candidates.push(Candidate {
                        source: p,
                        size: sm.len(),
                        modified,
                        result: CandidateResult::Eligible,
                    });
                }
            } else {
                return Err(CleanupError("special file refused".into()));
            }
        }
        Ok(Plan {
            freed_bytes: 0,
            candidates,
            rule_id,
            risk,
        })
    }

    /// Move eligible entries into same-filesystem quarantine. Never permanently deletes.
    pub fn execute(&self, plan: &Plan) -> Result<Vec<JournalEntry>> {
        if plan.risk != Risk::Low {
            return Err(CleanupError(
                "caution and high-risk cleanup requires explicit higher-level authorization".into(),
            ));
        }
        if plan
            .candidates
            .iter()
            .any(|c| !matches!(c.result, CandidateResult::Eligible))
        {
            return Err(CleanupError("plan contains refused candidate".into()));
        }
        if plan.candidates.is_empty() {
            return Ok(Vec::new());
        }
        let _lock = Lock::acquire(&self.state_dir)?;
        let mut out = Vec::new();
        for c in &plan.candidates {
            let sm = match fs::symlink_metadata(&c.source) {
                Ok(m) => m,
                Err(e) => {
                    self.write_entry(&JournalEntry::failed(c, plan, format!("revalidation: {e}")))?;
                    return Err(CleanupError(format!("revalidation failed: {e}")));
                }
            };
            if !sm.is_file()
                || sm.file_type().is_symlink()
                || sm.len() != c.size
                || sm.modified().ok() != Some(c.modified)
            {
                return Err(CleanupError(format!(
                    "candidate changed: {}",
                    c.source.display()
                )));
            }
            self.validate_source_root(&c.source)?;
            self.refuse_git_repository(&c.source)?;
            let id = new_id();
            let q = self.state_dir.join("quarantine").join(&id);
            let prepared = JournalEntry {
                id: id.clone(),
                original_path: c.source.clone(),
                timestamp: now(),
                size: c.size,
                rule: plan.rule_id.clone(),
                reason: format!("cleanup rule: {}", plan.rule_id),
                risk: plan.risk,
                platform: env::consts::OS.into(),
                host: env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()),
                result: OperationResult::Prepared,
                quarantine_path: q.clone(),
            };
            self.write_entry(&prepared)?;
            if let Err(e) = fs::rename(&c.source, &q) {
                let failed = JournalEntry {
                    result: OperationResult::Failed(e.to_string()),
                    ..prepared
                };
                self.write_entry(&failed)?;
                return Err(CleanupError(format!("quarantine move failed: {e}")));
            }
            let moved = JournalEntry {
                result: OperationResult::Moved,
                ..prepared
            };
            self.write_entry(&moved)?;
            self.write_manifest_entry(&moved)?;
            out.push(moved);
        }
        Ok(out)
    }

    pub fn restore(&self, id: &str) -> Result<JournalEntry> {
        if !valid_id(id) {
            return Err(CleanupError("invalid journal id".into()));
        }
        let _lock = Lock::acquire(&self.state_dir)?;
        let entries = self.read_entries()?;
        let moved = entries
            .into_iter()
            .rev()
            .find(|e| e.id == id && matches!(e.result, OperationResult::Moved))
            .ok_or_else(|| CleanupError("no movable journal entry".into()))?;
        let raw_q_meta = fs::symlink_metadata(&moved.quarantine_path)
            .map_err(|_| CleanupError("quarantine entry missing or tampered".into()))?;
        if raw_q_meta.file_type().is_symlink() || !raw_q_meta.is_file() {
            return Err(CleanupError(
                "quarantine entry is not a regular file".into(),
            ));
        }
        let qroot = fs::canonicalize(self.state_dir.join("quarantine"))?;
        let q = fs::canonicalize(&moved.quarantine_path)
            .map_err(|_| CleanupError("quarantine entry missing or tampered".into()))?;
        if !q.starts_with(&qroot) || q == qroot {
            return Err(CleanupError("quarantine confinement failed".into()));
        }
        let qm = fs::symlink_metadata(&q)?;
        if qm.file_type().is_symlink() || !qm.is_file() || qm.len() != moved.size {
            return Err(CleanupError("quarantine entry tampered".into()));
        }
        if moved.original_path.exists() {
            return Err(CleanupError("restore refuses overwrite".into()));
        }
        self.validate_source_parent(&moved.original_path)?;
        fs::rename(&q, &moved.original_path)?;
        let restored = JournalEntry {
            result: OperationResult::Restored,
            ..moved
        };
        self.write_entry(&restored)?;
        Ok(restored)
    }

    fn validate_source_root(&self, p: &Path) -> Result<PathBuf> {
        if p.as_os_str().is_empty() || !p.is_absolute() {
            return Err(CleanupError("absolute path required".into()));
        }
        let mut current = Some(p);
        while let Some(path) = current {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() {
                return Err(CleanupError(format!(
                    "source path ancestor is a symlink: {}",
                    path.display()
                )));
            }
            current = path.parent();
        }
        let sm = fs::symlink_metadata(p)?;
        if sm.file_type().is_symlink() {
            return Err(CleanupError("source symlink refused".into()));
        }
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|h| fs::canonicalize(h).ok());
        let canon = fs::canonicalize(p)?;
        let state = fs::canonicalize(&self.state_dir)?;
        if canon == state || canon.starts_with(&state) || state.starts_with(&canon) {
            return Err(CleanupError(
                "source and cleanup state paths overlap".into(),
            ));
        }
        if canon == Path::new("/")
            || home.as_ref().is_some_and(|h| {
                canon == *h
                    || canon.starts_with(h)
                    || h.parent().is_some_and(|parent| canon == parent)
            })
        {
            return Err(CleanupError(
                "root, home, or home parent/descendant refused".into(),
            ));
        }
        self.validate_dir(&canon)?;
        if !known_cache_path(&canon) {
            return Err(CleanupError(
                "path is not an explicitly known cache leaf".into(),
            ));
        }
        Ok(canon)
    }
    fn validate_dir(&self, p: &Path) -> Result<()> {
        let protected: HashSet<&str> = [
            "Documents",
            "Desktop",
            "Pictures",
            "Videos",
            ".ssh",
            ".gnupg",
            ".git",
            "credentials",
            "config",
            "source",
            "src",
        ]
        .into_iter()
        .collect();
        for c in p.components() {
            if let Component::Normal(n) = c {
                if protected.contains(n.to_string_lossy().as_ref()) {
                    return Err(CleanupError(format!("protected path: {}", p.display())));
                }
            }
        }
        Ok(())
    }
    fn validate_source_parent(&self, p: &Path) -> Result<()> {
        let parent = p.parent().ok_or_else(|| CleanupError("no parent".into()))?;
        let parent_meta = fs::symlink_metadata(parent)?;
        if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
            return Err(CleanupError(
                "restore parent is not a real directory".into(),
            ));
        }
        let canonical_parent = fs::canonicalize(parent)?;
        if canonical_parent != parent {
            return Err(CleanupError("restore parent path changed".into()));
        }
        self.validate_dir(parent)
    }
    fn refuse_git_repository(&self, p: &Path) -> Result<()> {
        let mut current = Some(p);
        while let Some(dir) = current {
            let dotgit = dir.join(".git");
            if fs::metadata(&dotgit).is_ok() {
                return Err(CleanupError(format!(
                    "Git repository path refused: {}",
                    p.display()
                )));
            }
            current = dir.parent();
        }
        Ok(())
    }
    fn write_entry(&self, e: &JournalEntry) -> Result<()> {
        let journal = self.state_dir.join("journal");
        reject_existing_state_file(&journal)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal)?;
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        let line = encode(e);
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_data()?;
        Ok(())
    }
    fn write_manifest_entry(&self, e: &JournalEntry) -> Result<()> {
        let manifest = self.state_dir.join("quarantine/manifest.jsonl");
        reject_existing_state_file(&manifest)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&manifest)?;
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        let record = format!(
            "{{\"original_path\":{},\"quarantine_path\":{},\"size\":{},\"timestamp\":{},\"rule\":{},\"reason\":{},\"risk\":{},\"operation\":{}}}",
            json_string(&e.original_path.to_string_lossy()),
            json_string(&e.quarantine_path.to_string_lossy()),
            e.size,
            e.timestamp,
            json_string(&e.rule),
            json_string(&e.reason),
            json_string(risk(e.risk)),
            json_string(&result(&e.result)),
        );
        f.write_all(record.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_data()?;
        Ok(())
    }
    fn read_entries(&self) -> Result<Vec<JournalEntry>> {
        let p = self.state_dir.join("journal");
        if !p.exists() {
            return Ok(Vec::new());
        }
        reject_existing_state_file(&p)?;
        let mut s = String::new();
        File::open(p)?.read_to_string(&mut s)?;
        s.lines().map(decode).collect()
    }
}

impl JournalEntry {
    fn failed(c: &Candidate, p: &Plan, msg: String) -> Self {
        Self {
            id: new_id(),
            original_path: c.source.clone(),
            timestamp: now(),
            size: c.size,
            rule: p.rule_id.clone(),
            reason: format!("cleanup rule: {}", p.rule_id),
            risk: p.risk,
            platform: env::consts::OS.into(),
            host: env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()),
            result: OperationResult::Failed(msg),
            quarantine_path: PathBuf::new(),
        }
    }
}

fn reject_symlink_ancestors(path: &Path) -> Result<()> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if candidate.exists() {
            let metadata = fs::symlink_metadata(candidate)?;
            if metadata.file_type().is_symlink() {
                return Err(CleanupError(format!(
                    "state path ancestor is a symlink: {}",
                    candidate.display()
                )));
            }
        }
        current = candidate.parent();
    }
    Ok(())
}

fn reject_existing_state_file(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CleanupError(format!(
                "state file is not a regular file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

struct Lock {
    path: PathBuf,
}
impl Lock {
    fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join(".lock");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| CleanupError("cleanup state is locked".into()))?;
        Ok(Self { path })
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn known_cache_path(p: &Path) -> bool {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .any(|n| {
            matches!(
                n.as_str(),
                "cache" | "caches" | "_cacache" | "registry" | "pip" | "npm" | "uv"
            )
        })
}
fn now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
fn new_id() -> String {
    format!("q-{}-{}", now(), NEXT_ID.fetch_add(1, Ordering::Relaxed))
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.starts_with("q-")
        && s.len() < 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn risk(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Caution => "caution",
        Risk::High => "high",
    }
}
fn parse_risk(s: &str) -> Result<Risk> {
    match s {
        "low" => Ok(Risk::Low),
        "caution" => Ok(Risk::Caution),
        "high" => Ok(Risk::High),
        _ => Err(CleanupError("bad risk".into())),
    }
}
fn result(r: &OperationResult) -> String {
    match r {
        OperationResult::Prepared => "prepared".into(),
        OperationResult::Moved => "moved".into(),
        OperationResult::Restored => "restored".into(),
        OperationResult::Refused(s) => format!("refused:{s}"),
        OperationResult::Failed(s) => format!("failed:{s}"),
    }
}
fn parse_result(s: &str) -> OperationResult {
    if s == "prepared" {
        OperationResult::Prepared
    } else if s == "moved" {
        OperationResult::Moved
    } else if s == "restored" {
        OperationResult::Restored
    } else if let Some(x) = s.strip_prefix("failed:") {
        OperationResult::Failed(x.into())
    } else {
        OperationResult::Refused(s.into())
    }
}
fn enc(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}
fn dec(s: &str) -> Result<String> {
    if !s.len().is_multiple_of(2) {
        return Err(CleanupError("bad journal encoding".into()));
    };
    let b = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| CleanupError("bad journal encoding".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    String::from_utf8(b).map_err(|_| CleanupError("bad journal utf8".into()))
}
fn checksum(s: &str) -> u64 {
    s.bytes().fold(1469598103934665603u64, |h, b| {
        (h ^ (b as u64)).wrapping_mul(1099511628211)
    })
}
fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn encode(e: &JournalEntry) -> String {
    let body = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        enc(&e.id),
        enc(&e.original_path.to_string_lossy()),
        e.timestamp,
        e.size,
        enc(&e.rule),
        enc(&e.reason),
        risk(e.risk),
        enc(&e.platform),
        enc(&e.host),
        enc(&result(&e.result)),
        enc(&e.quarantine_path.to_string_lossy()),
        "v2"
    );
    format!("{}|{:016x}", body, checksum(&body))
}
fn decode(line: &str) -> Result<JournalEntry> {
    let mut x = line.rsplitn(2, '|');
    let sum = x.next().ok_or_else(|| CleanupError("bad journal".into()))?;
    let body = x.next().ok_or_else(|| CleanupError("bad journal".into()))?;
    if checksum(body)
        != u64::from_str_radix(sum, 16).map_err(|_| CleanupError("bad journal checksum".into()))?
    {
        return Err(CleanupError("journal tampered".into()));
    };
    let f: Vec<_> = body.split('|').collect();
    if !((f.len() == 11 && f[10] == "v1") || (f.len() == 12 && f[11] == "v2")) {
        return Err(CleanupError("bad journal fields".into()));
    };
    Ok(JournalEntry {
        id: dec(f[0])?,
        original_path: PathBuf::from(dec(f[1])?),
        timestamp: f[2]
            .parse()
            .map_err(|_| CleanupError("bad timestamp".into()))?,
        size: f[3].parse().map_err(|_| CleanupError("bad size".into()))?,
        rule: dec(f[4])?,
        reason: if f.len() == 12 {
            dec(f[5])?
        } else {
            String::new()
        },
        risk: parse_risk(f[if f.len() == 12 { 6 } else { 5 }])?,
        platform: dec(f[if f.len() == 12 { 7 } else { 6 }])?,
        host: dec(f[if f.len() == 12 { 8 } else { 7 }])?,
        result: parse_result(&dec(f[if f.len() == 12 { 9 } else { 8 }])?),
        quarantine_path: PathBuf::from(dec(f[if f.len() == 12 { 10 } else { 9 }])?),
    })
}
