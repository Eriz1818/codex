# xcodex hooks (automation)

xcodex includes a basic “automation hooks” system: Codex can spawn external programs on a small set of lifecycle events and pass a JSON payload to them.

This is intended for **notifications and integrations** (fire-and-forget). Hooks do not block the run if they fail.

This document is an overview; the authoritative reference is `docs/config.md#hooks`.

## What you need to use hooks

No additional commands are required.

1. Ensure you have a `~/.codex/config.toml`
2. Add a `[hooks]` section (examples below)

If you want to disable all external hooks for a single run, pass `--no-hooks`:

```sh
codex --no-hooks
codex exec --no-hooks "…"
```

In the interactive TUI, quitting while hooks are still running prompts for confirmation by default. Toggle with `tui.confirm_exit_with_running_hooks`.

## Supported events

- `agent_turn_complete`: runs after each completed turn
- `approval_requested`: runs when Codex asks for approval (exec / apply-patch / MCP elicitation)
- `session_start`: runs when a session starts (after `SessionConfigured`)
- `session_end`: runs when a session ends (best-effort during shutdown)
- `model_request_started`: runs immediately before issuing a model request
- `model_response_completed`: runs after a model response completes
- `tool_call_started`: runs when a tool call begins execution
- `tool_call_finished`: runs when a tool call finishes (success/failure/aborted)

Note: `tool_call_started` is emitted when the tool call is dispatched; `duration-ms` in `tool_call_finished` includes any time spent queued behind non-parallel tool calls.

Each hook command receives event JSON on **stdin**.

The payload always includes (at minimum):

- `schema-version`: currently `1`
- `type`: kebab-case event type (for example `agent-turn-complete`, `model-request-started`, `tool-call-finished`)
- `event-id`: unique id for the event
- `timestamp`: RFC3339 timestamp

## Configuration

Hooks are configured as argv arrays:

```toml
[hooks]
agent_turn_complete = [
  ["python3", "/path/to/.codex/hooks/turn_complete.py"],
]

approval_requested = [
  ["python3", "/path/to/.codex/hooks/approval.py"],
]
```

### Payload delivery (stdin + file fallback)

For small payloads, Codex writes the full JSON payload to stdin.

For large payloads, Codex writes the full payload JSON to a file under CODEX_HOME and writes a small JSON envelope to stdin containing `payload-path`. Hook scripts should handle both cases.

Payload/log files are kept under CODEX_HOME and pruned with a global keep-last-N policy.
While the TUI is running, hook stdout/stderr are redirected to log files under CODEX_HOME so hooks do not corrupt the terminal UI.

Config knobs:

```toml
[hooks]
# Defaults shown.
max_stdin_payload_bytes = 16384
keep_last_n_payloads = 50
```

## Example: log turn summaries to a file

Create `~/.codex/hooks/turn_complete.py`:

```python
#!/usr/bin/env python3
import json
import pathlib
import sys

stdin_payload = sys.stdin.read()
payload = json.loads(stdin_payload)
payload_path = payload.get("payload-path")
if payload_path:
    payload = json.loads(pathlib.Path(payload_path).read_text())
out = pathlib.Path.home() / ".codex" / "hooks.log"
out.parent.mkdir(parents=True, exist_ok=True)

line = f"{payload.get('type')} cwd={payload.get('cwd')} last={payload.get('last-assistant-message')!r}\n"
out.write_text(out.read_text() + line if out.exists() else line)
```

Then wire it up in `~/.codex/config.toml` as shown above.

## Example: approval notifications

When an approval is requested, the payload includes:

- `kind`: `exec`, `apply-patch`, or `elicitation`
- `command` (for exec approvals)
- `paths` / `grant-root` (for apply_patch approvals)
- `server-name` / `request-id` / `message` (for MCP elicitation)

Use this to route alerts (macOS notification, Slack webhook, etc.).

## Making hooks easier to adopt (ideas)

To get users using hooks with minimal effort, we could add:

- A `xcodex hooks init` command that writes:
  - `~/.codex/hooks/` example scripts
  - a commented-out `[hooks]` section in `~/.codex/config.toml`
- A `just hooks-install` recipe that installs the examples into `~/.codex/hooks/`
- A small “marketplace” of prebuilt hook scripts in-repo (loggers, notifiers, memory capture)
- An option to pass payload via stdin (better for large payloads and compatibility with other hook ecosystems)

## Avoiding recursion

If a hook script runs `codex exec` (for example to do background processing after a turn completes), use `codex exec --no-hooks ...` so the child run does not re-trigger hooks.

## Related docs

- `docs/config.md#hooks` (authoritative config reference)

## `notify` (deprecated)

The legacy `notify` config is deprecated; use `hooks.agent_turn_complete` instead.
