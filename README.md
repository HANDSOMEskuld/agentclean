# AgentClean

AgentClean is a conservative, analysis-first disk cleaner for agent workspaces and developer caches. It treats scanning as observation, allows only explicit SAFE findings into a cleanup plan, and moves approved files into an isolated quarantine instead of permanently deleting them.

## Current release status

The repository metadata and current binary still identify as **v0.1.0**. The purge,
retention, and space-accounting work is documented as an **unreleased v0.2.0
candidate**, not as a published release. Do not call it v0.2.0 until the package
version, release tag, and cross-platform validation are updated together.

CI runs locked formatting, Clippy, tests, and release builds on Linux, macOS, and
Windows. Version tags (`vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-*`) use the
release workflow to produce platform archives and a checked `SHA256SUMS` file;
RC tags are published as prereleases. No release is created from a branch or by
the CI workflow.

### Recovery after interruption

`recover` is read-only by default and inspects incomplete `Prepared` and `PurgePending` journal states:

```bash
agentclean recover --state-dir ~/.agentclean --json
```

Only unambiguous states may be repaired, and repair requires both `--execute --yes`. If any ambiguous entry exists, the command refuses the entire repair batch. Recovery never deletes user data; it either closes an uncommitted preparation record or returns a verified pending purge to `Moved`, leaving it restorable. Missing, tampered, symlinked, or otherwise ambiguous paths remain blocked for manual investigation.


- `SAFE` means a rule explicitly identifies a rebuildable file and permits quarantine. A directory name such as `cache`, `tmp`, or `logs` is not sufficient.
- `CAUTION`, `DANGEROUS`, `PROTECTED`, and `UNKNOWN` findings are blocked from automatic cleanup.
- Credentials, configuration, source/workspace data, active sessions, Git repositories, system paths, HOME, symlinks, and Docker data are protected or blocked.
- Dry-run and execution use the same plan; `purge` is dry-run by default.
- Execution revalidates file type, symlink state, size, modification time, path confinement, and safety boundaries before moving anything.
- Cleanup is quarantine-first. `clean --execute --yes` moves eligible files into
  quarantine; `purge --execute --yes` is the separate, irreversible unlink step.
- Purge enforces a seven-day minimum retention window. A shorter requested window
  is rejected, and entries younger than the window are blocked.
- Every successful move is recorded in the journal and `quarantine/manifest.jsonl`.
- Restore never overwrites an existing destination. `undo` restores the latest still-movable journal entry.
- Quarantine state must be placed in an explicitly selected state directory; tests use temporary state directories and never the real user state.

## Lifecycle

AgentClean follows one conservative lifecycle:

1. **Scan** observes paths, metadata, risk, and scan completeness without changing data.
2. **Classify** applies evidence-based rules; names alone do not authorize cleanup.
3. **Plan** independently revalidates safety boundaries and produces the candidates,
   blocked items, and byte accounting used by both preview and execution.
4. **Quarantine** revalidates immediately before moving an eligible entry to the
   selected state directory. The move is recoverable.
5. **Restore** or `undo` uses the journal to return quarantined entries without
   overwriting an existing destination.
6. **Purge** is optional and separate. It is read-only unless both `--execute` and
   `--yes` are supplied, and only entries older than the minimum retention period
   can be unlinked.

The append-only audit journal records operation identity, original and quarantine
paths, timestamps, size, rule, risk, platform/host, result, and a checksum. A
malformed, inconsistent, stale, or unsupported record fails closed.

## Commands

```sh
agentclean scan --path . --json
agentclean analyze --path . --json
agentclean inspect --path . --json
agentclean doctor --path . --json
agentclean agents --json
agentclean docker --json
agentclean clean --path . --dry-run --json
agentclean clean --path /sandbox/cache --rules /sandbox/rules.yml --state-dir /sandbox/state --execute --yes --json
agentclean history --state-dir /sandbox/state --json
agentclean restore q-<journal-id> --state-dir /sandbox/state --json
agentclean undo --state-dir /sandbox/state --json
agentclean purge --state-dir /sandbox/state --retention-days 7 --json
agentclean purge --state-dir /sandbox/state --retention-days 7 --execute --yes --json
agentclean tui --path .
```

`clean --execute` and `purge --execute` require `--yes`; review the default dry-run
first. They never bypass protected or unknown findings. Purge is intentionally not
an alias for quarantine.

## Space accounting

Reports use distinct terms:

- **Logical/apparent bytes**: the file sizes represented by eligible entries.
- **Allocated bytes**: filesystem blocks observed for those entries; sparse files,
  hard links, shared extents, compression, and filesystem accounting can make this
  differ from logical bytes.
- **Quarantine bytes**: bytes moved out of the source path but still present in the
  quarantine filesystem; quarantine is recoverable and does **not** mean disk space
  was freed.
- **Unlinked/freed bytes**: bytes whose purge unlink completed. Even then, open
  handles, snapshots, shared storage, and filesystem behavior can delay actual
  free-space change.
- **Observed free bytes**: the measured before/after free-space delta when the platform
  supports it; otherwise it is reported as unavailable rather than fabricated.
  The JSON report also exposes the raw `free_bytes_before` and `free_bytes_after`
  observations so a zero delta is distinguishable from an unsupported measurement.

Incomplete scans, unsupported metadata, permission errors, races, and platform
limitations fail closed or remain diagnostic; they must not be converted into
optimistic reclaim estimates.

## Evidence and scope

The release-readiness fixture covers all five risk classes with exact file counts and byte totals, creates a real SAFE cleanup item, executes a real filesystem quarantine move, verifies the journal and manifest, restores the file, and exercises restore conflict and undo. Additional tests cover dirty Git, symlink refusal, path traversal, TOCTOU revalidation, malformed journals, locking, and partial scans.

The Claude, Codex, and Hermes detectors are bounded and read-only. They report observations and do not grant cleanup permission. Docker support is read-only inventory; no Docker prune, remove, or volume deletion is executed.

## Known limitations

- Codex is reported as not detected when no Codex data exists on the machine; no synthetic findings are produced.
- Agent detector classifications are informational until an explicit cleanup rule permits an operation.
- The current v0.2 candidate adds explicit purge accounting, but it does not invoke
  tool-specific cache commands or clean Docker objects. Permanent unlink is never
  implicit.
- A privileged concurrent process or unusual network filesystem can defeat ordinary user-space race defenses.
- The TUI is read-only. There is no interactive cleanup editor or rule editor.
- Release binaries should be tested on each target OS; this validation is Linux-focused.

## Development verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --release --locked
```

The evidence currently supports **v0.1.0 as the latest release-candidate version**
and **v0.2.0 as an unreleased candidate**: the purge tests and isolated
release-readiness tests pass, while the package metadata remains 0.1.0. The
cross-platform CI matrix is the release gate; no real HOME, agent data, Docker
volume, or development workspace is used for destructive validation.
