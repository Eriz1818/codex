from __future__ import annotations

"""
Example hook module for the Python hook host.

This module is intended to be used with:

  python3 -u "$CODEX_HOME/hooks/host/python/host.py" "$CODEX_HOME/hooks/host/python/example_hook.py"

It appends compact summaries for `tool-call-finished` events to:
  $CODEX_HOME/hooks-host-tool-calls.log
"""

import os
from typing import Any, Dict


def on_event(event: Dict[str, Any]) -> None:
    if event.get("xcodex_event_type") != "tool-call-finished":
        return

    codex_home = os.environ.get("CODEX_HOME")
    if not codex_home:
        return

    tool = event.get("tool_name", "?")
    status = event.get("status", "?")
    success = event.get("success", False)
    duration_ms = event.get("duration_ms", 0)
    output_bytes = event.get("output_bytes", 0)
    cwd = event.get("cwd", "")

    line = (
        f"type=tool-call-finished tool={tool} status={status} success={success} "
        f"duration_ms={duration_ms} output_bytes={output_bytes} cwd={cwd}\n"
    )

    out_path = os.path.join(codex_home, "hooks-host-tool-calls.log")
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(line)
