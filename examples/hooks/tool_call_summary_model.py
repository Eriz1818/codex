#!/usr/bin/env python3
"""
Example hook: append a compact summary for tool-call-finished events (model-based).

This version uses `xcodex_hooks.read_payload_model()`, which parses the JSON payload into a
dataclass model and performs light type coercions (e.g., ints/bools) while preserving unknown
fields in `.extras` / `.raw`.
"""

import os
import pathlib

import xcodex_hooks
import xcodex_hooks_models


def main() -> int:
    event = xcodex_hooks.read_payload_model()
    if not isinstance(event, xcodex_hooks_models.ToolCallFinishedHookEvent):
        return 0

    tool_name = event.tool_name or "unknown"
    status = event.status or "unknown"
    duration_ms = event.duration_ms or 0
    success = event.success
    output_bytes = event.output_bytes or 0
    cwd = event.cwd or ""

    codex_home = pathlib.Path(os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".xcodex")))
    out = codex_home / "hooks-tool-calls.log"
    out.parent.mkdir(parents=True, exist_ok=True)

    line = (
        f"type=tool-call-finished tool={tool_name} status={status} "
        f"success={success} duration_ms={duration_ms} output_bytes={output_bytes} cwd={cwd}\n"
    )
    with out.open("a", encoding="utf-8") as f:
        f.write(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

