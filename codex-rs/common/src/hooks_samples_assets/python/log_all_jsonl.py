#!/usr/bin/env python3
"""
Sample external hook: log every hook payload as one JSON object per line.

Customize by editing `main()` below. This hook is fire-and-forget: failures
won't stop Codex, but payloads/logs may contain sensitive data.
"""

import json
import os
import pathlib

import xcodex_hooks


def main() -> int:
    payload = xcodex_hooks.read_payload()
    codex_home = pathlib.Path(
        os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".xcodex"))
    )
    out = codex_home / "hooks.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

