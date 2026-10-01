use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Safe,
    Caution,
    Dangerous,
    Protected,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingExplanation {
    pub summary: String,
    pub rule: Option<String>,
    pub details: Vec<String>,
}
impl Default for FindingExplanation {
    fn default() -> Self {
        Self {
            summary: "Observed filesystem entry".into(),
            rule: None,
            details: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: PathBuf,
    pub bytes: u64,
    pub apparent_bytes: u64,
    pub allocated_bytes: u64,
    #[serde(default)]
    pub reclaimable_allocated_bytes: u64,
    pub modified_secs: u64,
    pub age_secs: Option<u64>,
    pub risk: Risk,
    pub rule_id: Option<String>,
    pub kind: String,
    pub explanation: FindingExplanation,
}
impl Finding {
    pub fn apparent_bytes(&self) -> u64 {
        self.apparent_bytes
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }
    pub fn reclaimable_allocated_bytes(&self) -> u64 {
        self.reclaimable_allocated_bytes
    }
    pub fn age_secs(&self) -> Option<u64> {
        self.age_secs
    }
    pub fn explanation(&self) -> FindingExplanation {
        self.explanation.clone()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    #[default]
    Complete,
    Partial,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub root: PathBuf,
    pub files: Vec<Finding>,
    pub errors: Vec<String>,
    pub scanned_bytes: u64,
    pub scanned_files: u64,
    pub status: ScanStatus,
    pub duration_ms: u128,
    #[serde(default)]
    pub scanned_apparent_bytes: u64,
    #[serde(default)]
    pub scanned_allocated_bytes: u64,
}
impl ScanReport {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.bytes).sum()
    }
    pub fn total_apparent_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.apparent_bytes).sum()
    }
    pub fn total_allocated_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.allocated_bytes).sum()
    }
    pub fn total_reclaimable_allocated_bytes(&self) -> u64 {
        self.files
            .iter()
            .filter(|f| f.risk == Risk::Safe)
            .map(|f| f.reclaimable_allocated_bytes)
            .sum()
    }
    pub fn by_risk(&self, risk: Risk) -> u64 {
        self.files
            .iter()
            .filter(|f| f.risk == risk)
            .map(|f| f.bytes)
            .sum()
    }
    pub fn status(&self) -> ScanStatus {
        self.status
    }
    pub fn duration_ms(&self) -> u128 {
        self.duration_ms
    }
}
