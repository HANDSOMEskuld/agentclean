# AgentClean implementation and acceptance plan

Scope: production-minded Rust v0.1, analysis-first; no destructive actions on real user data during development.

1. Research actual machine and upstream directory semantics; cite evidence and uncertainty.
2. Rust engine: models, external YAML rules, plugins, single-pass bounded scans, physical/logical size distinction, cancellation, conservative active/Git classification.
3. Safety: independently guarded cleanup, dry-run default, explicit confirmations, quarantine, durable journal, restore, race/path/protected data tests. Never claim quarantine frees disk.
4. CLI/TUI: scan analyze report inspect doctor agents rules config clean history undo/restore; explain risks and age policy.
5. Docker read-only inventory, risk classification; volumes never cleaned automatically.
6. Integration fixtures, Linux verification; Windows compilation and macOS CI.
7. README, MIT LICENSE, CONTRIBUTING, SECURITY, architecture/rules docs, CI/release preparation.
8. Independent security review and remediation; fmt/clippy/test/release; actual doctor/scan/analyze/clean dry-run captured.

Repository inspection: /root is not a git repository; no existing agentclean project. Initialized /root/agentclean without modifying other projects. Rust was absent; installed stable toolchain with rustup.
Observed roots: /root/.claude (cache, sessions, projects, history, settings, plugins, backups); /root/.hermes (active SQLite WAL, sessions, logs, caches, auth/config, source, skills, sandboxes); npm, pip, uv caches. Codex/Cursor/Gemini/OpenCode/Cline not found at common roots. Do not read credentials or conversation contents.

Acceptance requires real tool outputs. Mark unsupported/untested capabilities honestly, not placeholders disguised as implementations. No publishing/account login without user authorization.
