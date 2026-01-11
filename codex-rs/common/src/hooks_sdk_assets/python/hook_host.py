from __future__ import annotations

"""
xCodex hook host (Python reference implementation).

This is a long-lived process that reads hook events as JSONL on stdin and
dispatches them to a user hook module.

Installed into `$CODEX_HOME/hooks/` by:

  xcodex hooks install sdks python

Usage (example):

  python3 -u "$CODEX_HOME/hooks/host/python/host.py" "$CODEX_HOME/hooks/host/python/example_hook.py"

Protocol (v1):

  One JSON object per line. For hook events:
    {"schema_version":1,"type":"hook-event","seq":123,"event":{...hook payload...}}

The `event` payload uses the same schema as external hooks (see `docs/xcodex/hooks.md`).
"""

import importlib.util
import json
import pathlib
import sys
import traceback
from types import ModuleType
from typing import Any, Dict


def _load_module_from_path(path: str) -> ModuleType:
    module_path = pathlib.Path(path)
    spec = importlib.util.spec_from_file_location("xcodex_user_hook", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resolve_event_payload(event_or_envelope: Any) -> Dict[str, Any]:
    if isinstance(event_or_envelope, dict) and (
        "payload_path" in event_or_envelope or "payload-path" in event_or_envelope
    ):
        payload_path = event_or_envelope.get("payload_path") or event_or_envelope.get("payload-path")
        if isinstance(payload_path, str) and payload_path:
            return json.loads(pathlib.Path(payload_path).read_text(encoding="utf-8"))
    if isinstance(event_or_envelope, dict):
        return event_or_envelope
    return {}


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write(
            "usage: host.py /absolute/path/to/user_hook.py\n"
            "expected user_hook to define: on_event(event: dict) -> None\n"
        )
        return 2

    module_path = sys.argv[1]
    module = _load_module_from_path(module_path)
    on_event = getattr(module, "on_event", None)
    if not callable(on_event):
        sys.stderr.write(f"{module_path} must define a callable on_event(event: dict)\n")
        return 2

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        try:
            msg = json.loads(raw_line)
        except Exception:
            sys.stderr.write("hook host: failed to parse JSON line\n")
            sys.stderr.write(raw_line + "\n")
            continue

        if msg.get("type") != "hook-event":
            continue

        event = _resolve_event_payload(msg.get("event"))
        try:
            on_event(event)
        except Exception:
            sys.stderr.write("hook host: user hook raised\n")
            traceback.print_exc(file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
