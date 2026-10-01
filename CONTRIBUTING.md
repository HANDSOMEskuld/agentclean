# Contributing

## Development

1. Install stable Rust with rustup.
2. Clone the repository and run `cargo test`.
3. Run `cargo fmt -- --check` and `cargo clippy --all-targets --all-features -- -D warnings`.
4. Add fixture-based tests for behavior and safety boundaries. Never use a real home directory or destructive command in tests.
5. Keep rules explainable and conservative. A rule must not bypass the cleanup guard.

## Changes

Use focused commits and describe platform assumptions. New scanner support should include detection, path semantics, risk rationale, age policy, exclusions, report coverage and tests. Do not inspect or commit credentials, session transcripts, generated reports containing personal paths, or machine-specific data.

## Pull requests

Include test output, supported platforms, security impact, migration notes and known limitations. Run the full verification commands locally. For security vulnerabilities follow `SECURITY.md` rather than opening a public exploit report.
