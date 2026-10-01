# Changelog

All notable changes to AgentClean are documented here.

## [Unreleased] — v0.2.0-rc1

- Added read-only `recover` inspection and explicit `recover --execute --yes` repair for unambiguous interrupted journal states; ambiguous states remain fail-closed.
- Added cross-platform CI build/test matrix and tag-verified release artifacts with SHA256 checksums.

This is release messaging for work present in the repository, not a published
version. The current candidate is **0.2.0-rc1**; no tag or GitHub Release is
created until the release workflow completes its target-platform builds.

- Added a separate `purge` lifecycle after quarantine. It is dry-run by default;
  permanent unlink requires both `--execute` and `--yes`.
- Added a seven-day minimum retention floor. Entries younger than the requested
  retention are blocked, and a retention request below the floor is rejected.
- Added purge planning and reporting that separates logical/apparent bytes,
  allocated bytes, unlinked bytes, and observed free bytes.
- Kept quarantine moves at zero freed bytes: moving into quarantine is recoverable
  and does not prove that disk space was returned to the filesystem.
- Kept unsupported free-space measurement unavailable rather than estimating or
  fabricating a value.
- Documented the scan → classify → plan → quarantine → restore/undo → purge
  lifecycle, durable journal, fail-closed behavior, and platform limits.

Evidence for the candidate includes isolated purge tests for dry-run behavior,
retention enforcement, and all-entry revalidation, plus release-readiness tests
covering quarantine, journal, restore, and undo. No real user, agent, Docker, or
development data was purged.

The CI/release workflow is prepared for locked Linux/macOS/Windows validation,
platform archives, and SHA256 checksums. This candidate remains unreleased until
its version metadata and release tag are intentionally advanced together.

## [0.1.0] - Release Candidate

- Added bounded filesystem scanning with symlink avoidance, hardlink deduplication, limits, exclusions, and scan status.
- Added explicit SAFE, CAUTION, DANGEROUS, PROTECTED, and UNKNOWN risk handling.
- Added unified CleanupPlan shared by dry-run and execution.
- Added quarantine-first cleanup with pre-move revalidation, journal, JSONL quarantine manifest, restore, restore conflict protection, undo, and locking.
- Added bounded read-only Claude, Codex, and Hermes data detection.
- Added read-only Docker inventory and conservative volume classification.
- Added JSON/text CLI output and read-only TUI.
- Added release-readiness fixtures for real isolated filesystem mutation and recovery.

This release candidate has not performed destructive cleanup on real user data, agent data, Docker volumes, or development workspaces.
