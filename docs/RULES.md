# Rule notes and evidence boundary

These external rules are intentionally conservative and are not authorization to delete. The scanner may use them to identify paths for analysis, but cleanup must independently apply `docs/CORE_CONTRACT.md` and `docs/CLEANUP_CONTRACT.md`.

## Schema

Each rule has:

- `id`: stable rule identifier;
- `sources`: upstream URLs supporting the path and meaning;
- `paths`: platform-aware roots or documented leaf paths, with environment overrides where upstream supports them;
- `description`: verified semantics and important mixed-state caveats;
- `risk`: `safe`, `caution`, `dangerous`, or `unknown`;
- `rebuildable`: whether upstream documents recreation/redownload, not whether deletion is safe now;
- `min_age_days`: conservative age floor; age alone never overrides protected/activity checks;
- `cleanup_policy`: `never`, `analysis_only`, or `tool_aware_only`;
- `exclusions`: protected names or subtrees.

## Policy

Agent homes are `never` cleanup candidates because they contain conversations, sessions, credentials, configuration, databases, memories, checkpoints, or installed extensions. Cursor is `unknown` because no authoritative local-layout source was found. Docker is inventory-only and volumes are always dangerous. Developer cache rules are candidates for future tool-aware operations only; no rule authorizes raw recursive deletion.

## Platform resolution

Rules use `$HOME`, `${XDG_CACHE_HOME}`, `${APPDATA}`, `${LocalAppData}`, and product-specific overrides (`HERMES_HOME`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, `CLINE_DATA_DIR`, `CLINE_SANDBOX_DATA_DIR`, `OPENCODE_CONFIG_DIR`, `CARGO_HOME`, `GOMODCACHE`, `GOPATH`, `MAVEN_REPO_LOCAL`, `GRADLE_USER_HOME`, `NPM_CONFIG_CACHE`, `PIP_CACHE_DIR`, `DOCKER_DATA_ROOT`). The engine must resolve these per platform and never treat an empty/unset expansion as filesystem root.
