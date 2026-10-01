use anyhow::{anyhow, Result};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub original_path: PathBuf,
    pub timestamp: u128,
    pub size: u64,
    pub rule: String,
    pub reason: String,
    pub risk: String,
    pub platform: String,
    pub host: String,
    pub result: String,
    pub quarantine_path: PathBuf,
}

/// Read and validate the cleanup journal without creating the state directory.
pub fn read(state: &Path) -> Result<Vec<Entry>> {
    let path = state.join("journal");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    text.lines().map(decode).collect()
}

pub fn latest_undoable(entries: &[Entry]) -> Option<&Entry> {
    let restored: std::collections::HashSet<&str> = entries
        .iter()
        .filter(|e| e.result == "restored")
        .map(|e| e.id.as_str())
        .collect();
    entries
        .iter()
        .rev()
        .find(|e| e.result == "moved" && !restored.contains(e.id.as_str()))
}

fn decode(line: &str) -> Result<Entry> {
    let (body, sum) = line
        .rsplit_once('|')
        .ok_or_else(|| anyhow!("malformed journal"))?;
    let expected =
        u64::from_str_radix(sum, 16).map_err(|_| anyhow!("malformed journal checksum"))?;
    if checksum(body) != expected {
        return Err(anyhow!("journal tampered"));
    }
    let fields: Vec<&str> = body.split('|').collect();
    if !((fields.len() == 11 && fields[10] == "v1") || (fields.len() == 12 && fields[11] == "v2")) {
        return Err(anyhow!("malformed journal fields"));
    }
    let risk = fields[if fields.len() == 12 { 6 } else { 5 }];
    if !matches!(risk, "low" | "caution" | "high") {
        return Err(anyhow!("malformed journal risk"));
    }
    Ok(Entry {
        id: dec(fields[0])?,
        original_path: PathBuf::from(dec(fields[1])?),
        timestamp: fields[2]
            .parse()
            .map_err(|_| anyhow!("malformed journal timestamp"))?,
        size: fields[3]
            .parse()
            .map_err(|_| anyhow!("malformed journal size"))?,
        rule: dec(fields[4])?,
        reason: if fields.len() == 12 {
            dec(fields[5])?
        } else {
            String::new()
        },
        risk: fields[if fields.len() == 12 { 6 } else { 5 }].into(),
        platform: dec(fields[if fields.len() == 12 { 7 } else { 6 }])?,
        host: dec(fields[if fields.len() == 12 { 8 } else { 7 }])?,
        result: dec(fields[if fields.len() == 12 { 9 } else { 8 }])?,
        quarantine_path: PathBuf::from(dec(fields[if fields.len() == 12 { 10 } else { 9 }])?),
    })
}

fn dec(s: &str) -> Result<String> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("malformed journal encoding"));
    }
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| anyhow!("malformed journal encoding"))
        })
        .collect::<Result<Vec<_>>>()?;
    String::from_utf8(bytes).map_err(|_| anyhow!("malformed journal utf8"))
}

fn checksum(s: &str) -> u64 {
    s.bytes().fold(1469598103934665603u64, |h, b| {
        (h ^ b as u64).wrapping_mul(1099511628211)
    })
}
