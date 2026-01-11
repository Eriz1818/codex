#!/usr/bin/env python3
"""
Sample PyO3 in-process hook (observer-only).

This file is installed under $CODEX_HOME/hooks/ and referenced from:

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

try:
    import xcodex_hooks_runtime
except Exception:  # pragma: no cover
    xcodex_hooks_runtime = None


def on_event(event: dict) -> None:
    hooks_dir = pathlib.Path(__file__).resolve().parent
    out_path = hooks_dir.parent / "hooks-pyo3.jsonl"

    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "type": event.get("type"),
        "event_id": event.get("event-id"),
        "event": event,
    }

    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    if event.get("type") == "tool-call-finished":
        summary_path = hooks_dir.parent / "hooks-tool-calls-pyo3.log"
        duration_ms = event.get("duration-ms")
        output_bytes = event.get("output-bytes")

        line = (
            f"type=tool-call-finished tool={event.get('tool-name')} status={event.get('status')} "
            f"success={event.get('success')} duration_ms={duration_ms} output_bytes={output_bytes} "
            f"cwd={event.get('cwd')}\n"
        )
        with summary_path.open("a", encoding="utf-8") as f:
            f.write(line)

