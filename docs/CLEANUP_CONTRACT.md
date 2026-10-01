# Cleanup and quarantine contract

This document is the standalone contract for `src/core/cleanup.rs`. The core agent may wrap these types, but must not weaken their safety decisions.

## Defaults and safety boundary

- Planning is read-only. `CleanupEngine::plan` never renames or removes anything.
- Execution is quarantine-only: it moves eligible entries into a same-filesystem quarantine directory. This v0.1 engine has no permanent purge operation and never reports quarantined bytes as freed space.
- The cleanup guard is independent of rule risk. Unknown/custom paths, protected roots, links, source trees, Git trees, nested mounts, sensitive names, and unreadable/uninspectable trees are refused.
- A rule is not permission. Only known cache leaves explicitly listed by the engine are eligible, and an age cutoff is rechecked immediately before the move.
- Real HOME, `/`, drive roots, parents of HOME, and protected user directories (`Documents`, `Desktop`, `Pictures`, `Videos`, `.ssh`, `.gnupg`, configuration and credential locations) are never eligible. Tests must use temporary fixture directories.
- The engine refuses execution when platform guarantees needed by its checks are unavailable. Quarantine and source must be on the same filesystem; no copy/delete fallback is allowed.

## API

`CleanupEngine::new(state_dir)` creates a state directory lazily. State consists of a quarantine directory, append-only journal, and exclusive lock. `plan(path, rule_id, older_than)` returns a `Plan` containing only validated candidates. `execute(&plan)` acquires the state lock, revalidates each candidate, writes a durable `PREPARED` journal record before each rename, renames it into quarantine, then writes a durable `MOVED` record. A failed move leaves a recoverable PREPARED record and never claims success.

`restore(id)` acquires the same lock, validates the journal and quarantine confinement, refuses an existing destination, refuses tampered/missing entries, and atomically renames the quarantined entry back. It writes durable restore records. Journal IDs are opaque safe identifiers and are never interpreted as paths.

A journal record contains: ID, original path, timestamp, byte size, rule, risk, platform/host, operation result, quarantine path, and a record checksum. Malformed or inconsistent records fail closed. Journal and lock files are private where the platform supports permissions.

## Platform limits

The implementation uses `std::fs::rename` after conservative path and metadata checks. It does not claim to defeat a privileged concurrent attacker between checks and rename. On Unix, symlinks are rejected and directory device changes are treated as nested mounts. On platforms without equivalent conservative checks, planning/execution must refuse rather than silently degrade.

## Integration obligations

Callers must show the plan and require explicit consent for execution. CAUTION/high-risk rules require an additional explicit consent signal at the integration layer. Callers must present `freed_bytes = 0` for quarantine moves. Never expose a permanent-delete button as an alias for quarantine or infer eligibility from a scan result without calling `plan`/`execute` revalidation.
