#!/usr/bin/env python3
"""
Example PyO3 in-process hook (observer-only).

This file is meant to be copied under $CODEX_HOME/hooks/ and referenced from:

  [hooks]
  enable_unsafe_inproc = true
  inproc = ["pyo3"]

  [hooks.pyo3]
  script_path = "hooks/pyo3_hook.py"
  callable = "on_event"
"""

import json
import pathlib
from datetime import datetime

# `xcodex` will append both:
# - the directory containing this script, and
# - $CODEX_HOME/hooks
# to sys.path before importing/calling it, so installed helpers are importable.
try:
    import xcodex_hooks_runtime
except Exception:  # pragma: no cover
    xcodex_hooks_runtime = None


def on_event(event: dict) -> None:
    """
    Called for every hook event.

    The event dict uses the same schema as external hooks.
    """

    # Example: write a JSONL file with all events.
    # Store it next to the user's CODEX_HOME hooks directory.
    hooks_dir = pathlib.Path(__file__).resolve().parent
    out_path = hooks_dir.parent / "hooks-pyo3.jsonl"

    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "type": event.get("type"),
        "event_id": event.get("event-id"),
        # Keep the raw event for debugging.
        "event": event,
    }

    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # Optional: for tool-call-finished events, also append a compact summary line.
    if event.get("type") == "tool-call-finished":
        summary_path = hooks_dir.parent / "hooks-tool-calls-pyo3.log"
        duration_ms = event.get("duration-ms")
        output_bytes = event.get("output-bytes")

        line = f"type=tool-call-finished tool={event.get('tool-name')} status={event.get('status')} success={event.get('success')} duration_ms={duration_ms} output_bytes={output_bytes} cwd={event.get('cwd')}\n"
        with summary_path.open("a", encoding="utf-8") as f:
            f.write(line)
