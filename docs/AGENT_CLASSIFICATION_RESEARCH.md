# Agent classification research

## Scope and safety

This audit covers the detector and rule metadata for Claude Code, OpenAI Codex CLI,
and Hermes Agent. The live directories `/root/.claude`, `/root/.codex`, and
`/root/.hermes` were inspected **read-only**, using directory names and file
names only. File contents, credentials, prompts, transcripts, databases, and
history were not opened. No real user data was changed.

## Evidence

- Claude Code's official directory reference says `~/.claude` is personal
  configuration and documents `CLAUDE.md`, settings, plugins, transcripts,
  prompt history, paste cache, file history, uploads, backups, plans, logs,
  shell snapshots, and other application data. It explicitly warns not to
  delete `~/.claude.json`, settings, or plugins because they hold auth,
  preferences, and installed plugins. [1]
- The current Claude installation's names matched this evidence: `settings.json`,
  `history.jsonl`, `projects/`, `backups/`, `plugins/`, and `cache/`.
- OpenAI's Codex configuration source identifies `config.toml` and links the
  basic, advanced, and reference configuration documentation. [2] The Codex
  documentation/search evidence also identifies `CODEX_HOME` as the home for
  local session history, including `history.jsonl` and session data. [3]
  `/root/.codex` was absent at audit time, so no Codex live layout was inferred.
- Hermes' authoritative session-storage documentation identifies
  `$HERMES_HOME/state.db` as the SQLite store for session metadata and full
  message history, with companion `state.db-wal` and `state.db-shm` files.
  It also documents profile isolation under `profiles/<name>/`, where profiles
  contain configuration, `.env`, `SOUL.md`, memories, sessions, skills, cron,
  and state. [4]
- Hermes' profile documentation says profiles contain their own config, API
  keys, memory, sessions, skills, and gateway state, and explicitly describes
  `config.yaml`, `.env`, `SOUL.md`, `profile.yaml`, `auth.json`, and `state.db`
  as profile identity files. [5]
- The current Hermes names included those protected categories plus gateway
  sockets/PIDs, runtime locks, logs, cache, scratch, memories, skills,
  sandboxes, cron, pairing, and shared auth names. These names were recorded
  without reading contents.

## Classification policy

Classification is evidence-based and conservative:

1. Exact basenames and exact directory components are used instead of broad
   path-substring matching. For example, `configuration.txt`, `author.md`,
   `sessionary.txt`, and `my-sessions/` do not become config, credentials, or
   sessions merely because they contain a keyword.
2. Credentials, configuration, sessions, history, workspace, and runtime state
   remain protected. This reduces `UNKNOWN` only where the on-disk name is
   supported by product documentation; it does not convert uncertain data into
   `SAFE` or a cleanup candidate.
3. Agent roots are detected from documented environment overrides (`CLAUDE_CONFIG_DIR`,
   `CODEX_HOME`, and `HERMES_HOME`) and standard locations. A root may be a
   documented file as well as a directory, while traversal remains bounded,
   read-only, and non-following for symlinks.
4. `projects/`, `sessions/`, `history.jsonl`, Claude file-history/cache names,
   Codex session/config names, and Hermes state/profile names are treated as
   user history or application state, not disposable cache.
5. Unknown remains the fail-closed result for names without enough evidence.

## Regression coverage

`tests/agent_accuracy.rs` now covers:

- Claude and Codex override roots;
- project/session layout classification;
- credentials and history protection;
- exact-component boundary behavior that rejects substring false positives;
- representative config, cache, log, temporary, state, and workspace names.

The existing `tests/agents.rs` coverage continues to verify Hermes-home and XDG
root handling, credential protection, and bounded scanning.

## Rule metadata

The agent and developer-cache rule files use `cleanup_strategy` consistently.
Agent rules remain dangerous, non-rebuildable, and analysis-only/never-cleaned;
agent state, credentials, project data, transcripts, and configuration are not
classified as safe cache. Developer cache rules retain caution/tool-aware
handling and explicit credential/config exclusions.

## Sources

[1]: https://code.claude.com/docs/en/claude-directory
[2]: https://github.com/openai/codex/blob/main/docs/config.md
[3]: https://learn.chatgpt.com/docs/config-file/config-advanced
[4]: https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/session-storage.md
[5]: https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/profiles.md
