#!/usr/bin/env python3
"""
Example hook: append every hook payload to CODEX_HOME/hooks.jsonl (one JSON object per line).

This is useful for auditing/debugging, but treat payloads as sensitive.
"""
import json
import os
import pathlib

import xcodex_hooks


def main() -> int:
    payload = xcodex_hooks.read_payload()
    # Add your logic here. For example, filter by event type:
    # if payload.get("type") != "tool-call-finished": return 0
    codex_home = pathlib.Path(os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".xcodex")))
    out = codex_home / "hooks.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
