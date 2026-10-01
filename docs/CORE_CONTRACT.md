# Core contract: scanner ↔ cleanup

This document is the integration boundary for `src/core/cleanup.rs`. Scanner and rule code must produce observations; cleanup independently revalidates every operation.

## Candidate

```rust
pub struct CleanupCandidate {
    pub path: std::path::PathBuf,
    pub risk: Risk,
    pub bytes: u64,
    pub modified_secs: u64,
    pub rule_id: String,
    pub fingerprint: Fingerprint,
}

pub struct Fingerprint {
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub size: u64,
    pub modified_secs: u64,
    pub digest: Option<[u8; 32]>,
}
```

`Risk` is ordered conservatively: `Safe`, `Caution`, `Dangerous`, `Unknown`. Unknown is never executable. Paths are absolute where possible and are never followed through symlinks/junctions.

## Manager contract

`CleanupManager` owns `home`, `state_dir`, and a verified rule set. It accepts candidates but must re-stat and re-check: protected roots (credentials, config, source, databases, active sessions, repositories), mount/network boundaries, file identity/fingerprint, allowlisted leaf-cache semantics, and activity. A rule never grants blanket recursive deletion. Candidate mismatch means abstain and report.

Operations are dry-run by default. Permanent removal requires `--execute --yes`; caution additionally requires an explicit acknowledgement. Dangerous and unknown candidates are blocked. Quarantine is recoverable but does **not** count as freed disk; `freed_bytes` remains zero until a separate explicit safe purge.

Journal records are durable and include operation id, candidate identity, pre/post state, and recovery state (`planned`, `quarantined`, `removed`, `restored`, `failed`). Restore never overwrites an existing destination. Undo reads the journal and only reverses verified quarantine operations.

## Reports and errors

Cleanup reports must distinguish planned, skipped, blocked, quarantined, removed, restored and freed bytes. Permission errors, races, unsupported metadata and active files are normal diagnostic outcomes, not reasons to guess. The CLI must expose dry-run behavior and never claim unsupported Docker or platform capabilities.

The cleanup owner may add fields and methods, but must preserve these safety invariants and keep this document synchronized with public types.
