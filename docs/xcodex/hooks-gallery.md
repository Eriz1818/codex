# Hooks gallery

This page is a curated set of hook recipes you can copy/paste.

For configuration details and the full list of events, see:

- `docs/xcodex/hooks.md` (overview + quickstart)
- `docs/config.md#hooks` (authoritative reference)

For ready-to-use scripts, see `examples/hooks/`.

## Common patterns

### 1) Log every payload (JSONL)

Use: debugging and auditing.

Script: `examples/hooks/log_all_jsonl.py`

Config:

```toml
[hooks]
session_start = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
session_end = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
model_request_started = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
model_response_completed = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
tool_call_started = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
tool_call_finished = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
agent_turn_complete = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
approval_requested = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
```

Output: appends JSON to `$CODEX_HOME/hooks.jsonl`.

### 2) Log compact tool call summaries

Use: get a quick “timeline” of what Codex did without storing full payloads.

Script: `examples/hooks/tool_call_summary.py`

Config:

```toml
[hooks]
tool_call_finished = [["python3", "/absolute/path/to/tool_call_summary.py"]]
```

Output: appends to `$CODEX_HOME/hooks-tool-calls.log`.

### 3) Notify on approval requests (macOS)

Use: get a desktop notification when Codex needs a decision.

Script: `examples/hooks/approval_notify_macos_terminal_notifier.py`

Dependencies:

- `terminal-notifier` (if missing, the hook exits 0 and does nothing)

Config:

```toml
[hooks]
approval_requested = [["python3", "/absolute/path/to/approval_notify_macos_terminal_notifier.py"]]
```

### 4) Notify on approval requests (Linux)

Use: desktop notifications on Linux.

Script: `examples/hooks/notify_linux_notify_send.py`

Dependencies:

- `notify-send` (if missing, the hook exits 0 and does nothing)

Config:

```toml
[hooks]
approval_requested = [["python3", "/absolute/path/to/notify_linux_notify_send.py"]]
```

## Notes

- Treat hook payloads/logs as potentially sensitive.
- Hooks run “fire-and-forget”; failures are logged and do not block the session.
- Hook commands are argv arrays (no shell expansion), so use absolute paths.

