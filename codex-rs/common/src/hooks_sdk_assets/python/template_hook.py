#!/usr/bin/env python3
from __future__ import annotations

"""
xCodex hooks kit: Python template hook.

This file is installed under `$CODEX_HOME/hooks/templates/python/` and is meant
as a starting point you copy and edit.

It imports the shared helper from `$CODEX_HOME/hooks/xcodex_hooks.py`.
That helper is installed by:

    xcodex hooks install sdks python

or automatically by:

    xcodex hooks init
"""

import json
import os
import pathlib
import sys

# Ensure `$CODEX_HOME/hooks/` (which contains `xcodex_hooks.py`) is importable
# when this template is executed from `$CODEX_HOME/hooks/templates/python/`.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
import xcodex_hooks  # noqa: E402


def main() -> int:
    # Parse the event payload (handles stdin vs payload_path envelopes).
    payload = xcodex_hooks.read_payload()

    codex_home = pathlib.Path(os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".xcodex")))
    out = codex_home / "hooks.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        # Add your logic here. This template just logs the full payload.
        f.write(json.dumps(payload) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
