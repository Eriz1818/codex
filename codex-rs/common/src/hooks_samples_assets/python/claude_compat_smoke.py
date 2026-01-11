#!/usr/bin/env python3
"""
Sample external hook: log the Claude-compat (hooks.command) payload basics.

This is useful when validating Claude-style hooks against xcodex:
- `hook_event_name` is the exact key that matched in your config (alias or canonical)
- `xcodex_event_type` is the canonical xcodex event type string
"""

import json
import os
import pathlib

import xcodex_hooks


def main() -> int:
    payload = xcodex_hooks.read_payload()

    record = {
        "hook_event_name": payload.get("hook_event_name") or payload.get("hook-event-name"),
        "xcodex_event_type": payload.get("xcodex_event_type") or payload.get("xcodex-event-type"),
        "tool_name": payload.get("tool_name") or payload.get("tool-name"),
        "cwd": payload.get("cwd"),
        "session_id": payload.get("session_id") or payload.get("session-id"),
        "turn_id": payload.get("turn_id") or payload.get("turn-id"),
    }

    codex_home = pathlib.Path(
        os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".xcodex"))
    )
    out = codex_home / "hooks-claude-compat-smoke.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
