# Slash commands

### What are slash commands?

Slash commands are special commands you can type that start with `/`.

---

### Built-in slash commands

Control Codex’s behavior during an interactive session with slash commands.

| Command         | Purpose                                                                    |
| --------------- | -------------------------------------------------------------------------- |
| `/model`        | choose what model and reasoning effort to use                              |
| `/approvals`    | choose what Codex can do without approval                                  |
| `/review`       | review my current changes and find issues                                  |
| `/new`          | start a new chat during a conversation                                     |
| `/resume`       | resume an old chat                                                         |
| `/init`         | create an AGENTS.md file with instructions for Codex                       |
| `/compact`      | summarize conversation to prevent hitting the context limit                |
| `/autocompact`  | toggle automatic conversation compaction (supports `on|off|toggle|status`) |
| `/thoughts`     | toggle showing agent thoughts/reasoning (supports `on|off|toggle|status`)  |
| `/hooks`        | show automation hooks quickstart + paths                                   |
| `/ps`           | list running background terminals and hooks                                |
| `/ps-kill`      | terminate background terminals                                             |
| `/diff`         | show git diff (including untracked files)                                  |
| `/mention`      | mention a file                                                             |
| `/help`         | show help for a topic (e.g. `/help xcodex`)                                |
| `/status`       | open the status/settings menu (bottom pane)                                |
| `/settings`     | open the status/settings menu (bottom pane)                                |
| `/worktree`     | switch this session to a different git worktree (see also: `/worktree shared`) |
| `/mcp`          | list configured MCP tools                                                  |
| `/experimental` | open the experimental menu to enable features from our beta program        |
| `/skills`       | browse and insert skills (experimental; see [docs/skills.md](./skills.md)) |
| `/logout`       | log out of Codex                                                           |
| `/quit`         | exit Codex                                                                 |
| `/exit`         | exit Codex                                                                 |
| `/feedback`     | save a local report for troubleshooting                                    |

---

### xcodex additions

If you're using `xcodex`, run:

- `/help xcodex` — quick index of xcodex-only features available in your current UI.
- `/ps` and `/ps-kill` — background terminals (availability may depend on UI frontend); see `docs/xcodex/background-terminals.md`.

More xcodex docs:

- `docs/xcodex/README.md`
- `docs/xcodex/settings.md`
- `docs/xcodex/worktrees.md`

Worktree helpers (xcodex):

- `/worktree shared add|rm|list` — edit `worktrees.shared_dirs` from inside the TUI (no manual `config.toml` edit).
