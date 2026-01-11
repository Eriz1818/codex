# Hooks examples

This directory contains copy/pasteable hook scripts for `xcodex` (and upstream `codex`) hooks.

Hooks are configured as argv arrays in `$CODEX_HOME/config.toml` under `[hooks]`. Codex writes event JSON to the hook program’s stdin. For large payloads, stdin contains a small JSON envelope with `payload_path`, which points to the full payload JSON.

## Quickstart

1. Install the Python hook helper into your Codex home:

```sh
xcodex hooks install sdks python
```

2. Copy one or more scripts into your Codex home:

```sh
mkdir -p "${CODEX_HOME:-$HOME/.xcodex}/hooks"
cp examples/hooks/log_all_jsonl.py "${CODEX_HOME:-$HOME/.xcodex}/hooks/"
```

3. Edit `$CODEX_HOME/config.toml` and add:

```toml
[hooks]
agent_turn_complete = [["python3", "/absolute/path/to/log_all_jsonl.py"]]
```

4. Test your configured hooks without running a full session:

```sh
xcodex hooks test --configured-only
```

5. Inspect the output file(s) created under `$CODEX_HOME`.

## Examples

- `log_all_jsonl.py`: append every event payload to a JSONL file.
- `tool_call_summary.py`: append a compact one-line summary for `tool-call-finished` events.
- `tool_call_summary_model.py`: same as above, but uses the dataclass model parser (`read_payload_model()`).
- `approval_notify_macos_terminal_notifier.py`: macOS notifications for approvals via `terminal-notifier` (if installed).
- `notify_linux_notify_send.py`: Linux desktop notifications via `notify-send` (if installed).
