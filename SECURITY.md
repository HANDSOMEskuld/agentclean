# Security policy

AgentClean operates on valuable local data. Treat all scan paths, rules, plugin metadata, filesystem contents and journal records as untrusted input.

## Reporting

Do not publish proof-of-concept destructive commands or user credentials in a public issue. Until a maintainer has configured GitHub private vulnerability reporting, report privately to the repository owner via their published contact channel. No private reporting address is invented here.

## Invariants

- Analysis and dry run are defaults. A scan never deletes or renames user data.
- Unknown storage, credentials, configuration, source code, active sessions, databases and volumes are not cache merely because a directory name suggests it.
- Rule risk is advisory; the cleanup guard independently decides whether an operation is allowed.
- Filesystem links are not traversed for cleanup. Protected roots and descendants cannot be overridden by a community rule.
- Scan results are observations, not deletion capabilities. Cleanup revalidates eligibility and identity.
- Quarantine moves do not release filesystem capacity. Reports must not label moved bytes as freed bytes.
- Restore does not overwrite an existing destination.
- Docker analysis never grants permission to delete a volume.
- No test may destructively operate on real HOME or system directories.

## Threat model

Malicious or malformed rules, hostile filenames, symlinks/junctions, scan-to-clean races, tampered journals, nested repositories, credentials within apparent caches, permissions, shared disks, hardlinks and concurrent invocations matter. File metadata and process/lock checks alone cannot prove a directory is unused. Abstention is preferable to an unsafe guess.

An unprivileged tool cannot defend against a hostile privileged process altering its state or filesystem. Windows/macOS/Linux behavior must be disclosed separately. Network filesystems and unusual mount semantics are not assumed safe. Do not run cleanup as root merely to bypass an access denial.

## Release requirements

Before publishing, run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, a fresh `cargo test`, and `cargo build --release`. The release-readiness integration fixture must execute real filesystem mutation only inside `/var/tmp` isolation, verify quarantine manifest and journal records, restore and undo the file, and cover dirty Git, symlink/path traversal, restore conflict, and TOCTOU rejection. Review the actual cleanup implementation and platform limitations in `docs/` rather than interpreting this policy as a claim that every defense is implemented. No guarantee of recovering data after permanent removal can be made.
