# Cleanup and quarantine contract

This document is the standalone contract for `src/core/cleanup.rs`. The core agent
may wrap these types, but must not weaken their safety decisions. The purge API is
an unreleased v0.2.0 candidate while package metadata remains v0.1.0.

## Defaults and safety boundary

- Planning is read-only. `CleanupEngine::plan` never renames or removes anything.
- Normal cleanup execution is quarantine-only: it moves eligible entries into a
  same-filesystem quarantine directory. Purge is a separate operation and is never
  implied by cleanup. Quarantine never reports bytes as freed space.
- The cleanup guard is independent of rule risk. Unknown/custom paths, protected roots, links, source trees, Git trees, nested mounts, sensitive names, and unreadable/uninspectable trees are refused.
- A rule is not permission. Only known cache leaves explicitly listed by the engine are eligible, and an age cutoff is rechecked immediately before the move.
- Real HOME, `/`, drive roots, parents of HOME, and protected user directories (`Documents`, `Desktop`, `Pictures`, `Videos`, `.ssh`, `.gnupg`, configuration and credential locations) are never eligible. Tests must use temporary fixture directories.
- The engine refuses execution when platform guarantees needed by its checks are unavailable. Quarantine and source must be on the same filesystem; no copy/delete fallback is allowed.

## API

`CleanupEngine::new(state_dir)` creates a state directory lazily. State consists of a quarantine directory, append-only journal, and exclusive lock. `plan(path, rule_id, older_than)` returns a `Plan` containing only validated candidates. `execute(&plan)` acquires the state lock, revalidates each candidate, writes a durable `PREPARED` journal record before each rename, renames it into quarantine, then writes a durable `MOVED` record. A failed move leaves a recoverable PREPARED record and never claims success.

`restore(id)` acquires the same lock, validates the journal and quarantine confinement,
refuses an existing destination, refuses tampered/missing entries, and recreates the
original file without overwriting the destination. It writes durable restore records.
Journal IDs are opaque safe identifiers and are never interpreted as paths.

- A journal record contains: ID, original path, timestamp, byte size, rule, risk,
  platform/host, operation result, quarantine path, and a record checksum.
  Malformed or inconsistent records fail closed. Journal and lock files are private
  where the platform supports permissions. The journal is the audit and recovery
  source for restore, undo, and purge eligibility; it is not permission to purge.

## Purge and retention

Purge operates only on verified `MOVED` journal entries whose retention age has
elapsed. The minimum retention is seven days and cannot be lowered by a caller.
Purge planning is read-only; the default execution mode is also read-only. The
irreversible unlink path requires explicit `--execute --yes`, revalidates every
entry before unlinking any entry, and aborts if identity, confinement, metadata, or
platform checks fail.

The accounting fields are deliberately separate:

- `logical_bytes` is the apparent file-size total;
- `allocated_bytes` is the observed allocation total and is not a promise of
  reclaimable free space;
- `unlinked_bytes` counts bytes for completed unlink operations;
- **Observed free bytes**: a measured before/after filesystem free-space delta when
  supported; otherwise `None`, never an estimate. The raw before/after values are
  retained so a measured zero delta is distinguishable from an unsupported reading.

Moving an entry to quarantine changes location, not necessarily filesystem free
space. Shared blocks, sparse files, open handles, snapshots, compression, and
filesystem-specific behavior mean none of these fields should be presented as an
exact universal free-space delta.

## Platform limits

The implementation uses `std::fs::rename` after conservative path and metadata checks. It does not claim to defeat a privileged concurrent attacker between checks and rename. On Unix, symlinks are rejected and directory device changes are treated as nested mounts. On platforms without equivalent conservative checks, planning/execution must refuse rather than silently degrade.

## Integration obligations

Callers must show the plan and require explicit consent for execution. CAUTION/high-risk rules require an additional explicit consent signal at the integration layer. Callers must present `freed_bytes = 0` for quarantine moves. Never expose a permanent-delete button as an alias for quarantine or infer eligibility from a scan result without calling `plan`/`execute` revalidation. Unsupported platforms and incomplete observations must remain blocked or explicitly diagnostic; portability is fail-closed, not best-effort deletion.
