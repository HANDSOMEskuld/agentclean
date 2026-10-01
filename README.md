# AgentClean

AgentClean is a conservative, analysis-first disk cleaner for agent workspaces and developer caches. It treats scanning as observation, allows only explicit SAFE findings into a cleanup plan, and moves approved files into an isolated quarantine instead of permanently deleting them.

## v0.1 safety model

- `SAFE` means a rule explicitly identifies a rebuildable file and permits quarantine. A directory name such as `cache`, `tmp`, or `logs` is not sufficient.
- `CAUTION`, `DANGEROUS`, `PROTECTED`, and `UNKNOWN` findings are blocked from automatic cleanup.
- Credentials, configuration, source/workspace data, active sessions, Git repositories, system paths, HOME, symlinks, and Docker data are protected or blocked.
- Dry-run and execution use the same `CleanupPlan`.
- Execution revalidates file type, symlink state, size, modification time, path confinement, and safety boundaries before moving anything.
- Cleanup is quarantine-first. No permanent deletion is performed by the v0.1 execution path.
- Every successful move is recorded in the journal and `quarantine/manifest.jsonl`.
- Restore never overwrites an existing destination. `undo` restores the latest still-movable journal entry.
- Quarantine state must be placed in an explicitly selected state directory; tests use temporary state directories and never the real user state.

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
agentclean tui --path .
```

`clean --execute` requires both `--yes` and a user-supplied isolated state directory in normal operation. It never bypasses protected or unknown findings.

## Evidence and scope

The release-readiness fixture covers all five risk classes with exact file counts and byte totals, creates a real SAFE cleanup item, executes a real filesystem quarantine move, verifies the journal and manifest, restores the file, and exercises restore conflict and undo. Additional tests cover dirty Git, symlink refusal, path traversal, TOCTOU revalidation, malformed journals, locking, and partial scans.

The Claude, Codex, and Hermes detectors are bounded and read-only. They report observations and do not grant cleanup permission. Docker support is read-only inventory; no Docker prune, remove, or volume deletion is executed.

## Known limitations

- Codex is reported as not detected when no Codex data exists on the machine; no synthetic findings are produced.
- Agent detector classifications are informational until an explicit cleanup rule permits an operation.
- The v0.1 cleaner does not permanently delete files, invoke tool-specific cache commands, or clean Docker objects.
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

AgentClean v0.1.0 is intended as a release candidate only when all four commands and the isolated fixture acceptance test pass. No real HOME, agent data, Docker volume, or development workspace is used for destructive validation.
