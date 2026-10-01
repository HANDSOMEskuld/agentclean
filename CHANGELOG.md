# Changelog

All notable changes to AgentClean are documented here.

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
