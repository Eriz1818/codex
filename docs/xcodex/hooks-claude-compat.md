# Claude Code hooks compatibility (observer-only)

xcodex can run many “Claude Code style” command hooks by configuring Claude-style events/matchers in `~/.codex/config.toml` under `hooks.command`.

This is **observer-only**: hook failures and outputs never block or modify xcodex execution.

Claude hooks reference: https://code.claude.com/docs/en/hooks

## Enable (TOML-first)

Configure in `~/.codex/config.toml`:

```toml
[hooks.command]
default_timeout_sec = 30

[[hooks.command.PostToolUse]]
matcher = "Write|Edit"
  [[hooks.command.PostToolUse.hooks]]
  argv = ["python3", "/absolute/path/to/hook.py"]
```

Notes:

- xcodex accepts canonical event keys and Claude/OpenCode aliases for xcodex-emitted events (for example `PostToolUse` and `"tool.execute.after"`).
- `hook_event_name` in the emitted payload is the exact config key that triggered this hook (canonical or alias).

## Supported hooks

- Hook type: `type: "command"` only.
- Hook outputs are ignored (no allow/deny/ask, no input modification).

## Events

xcodex accepts all Claude hook event names in the Claude config, and attempts to map them onto xcodex lifecycle signals.

Notes:

- Some events are approximations (for example, Claude `Stop` is mapped to xcodex’s “agent turn complete”).
- xcodex also has its own hooks system with additional events; Claude compat does not replace those.

### OpenCode event aliases (1:1 only)

xcodex accepts a small subset of OpenCode event names as aliases in `hooks.command` (quoted keys in TOML when they contain `.`), but only when they correspond directly to events xcodex actually emits.

- `session.start` → `session-start`
- `session.end` → `session-end`
- `tool.execute.before` → `tool-call-started`
- `tool.execute.after` → `tool-call-finished`

## Tool names and matchers

Claude configs/scripts commonly match on tool names like `Write|Edit|Bash`.

In `hooks.command`, xcodex matcher evaluation accepts either:

- xcodex tool ids (recommended): `write_file`, `edit_block`, `exec_command`, ...
- Claude tool-name aliases (supported): `Write`, `Edit`, `Bash`, ...

Common mappings:

- `write_file` → `Write`
- `edit_block`, `apply_patch` → `Edit`
- `read_file`, `read_multiple_files` → `Read`
- `exec_command`, `start_process`, `interact_with_process` → `Bash`

Matcher semantics follow Claude’s documented behavior:

- `*` matches all tool names.
- A string without regex metacharacters matches exact tool name.
- A regex (for example `Write|Edit`) matches tool name.

## Payload shape (best-effort)

Hook commands receive a Claude-first superset payload on stdin with snake_case keys.

For tool-related events, xcodex translates some tool input shapes to Claude-like `tool_input` objects for compatibility:

- `Write`: maps `path` → `file_path` and includes `content` when present.
- `Read`: maps `path` → `file_path` and passes through `offset`/`length` when present.
- `Edit`: tries to provide `file_path` (from `file_path`/`path`, or extracted from an `apply_patch` header).
- `Bash`: maps `cmd` → `command` when present.

## Notifications (best-effort)

For Claude `Notification` hooks, xcodex provides:

- `notification_type` (always)
- `message` (best-effort)
- `title` (best-effort)

In particular, xcodex emits Notification hooks for certain permission/elicitation prompts, even though Claude’s full decision-control pipeline is out of scope for this mode.

## Unsupported (by design)

- Decision-control semantics (allow/deny/ask, `updatedInput`) for `PreToolUse`, `PermissionRequest`, `Stop`, `SubagentStop`.
- Prompt hooks (`type: "prompt"`).
- Claude environment variable emulation (`CLAUDE_*`).
- Plugin hooks merging (`${CLAUDE_PLUGIN_ROOT}`).
