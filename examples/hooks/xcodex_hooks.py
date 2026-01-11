#!/usr/bin/env python3
from __future__ import annotations

"""
xCodex hooks kit (repo example copy).

This file is a copy of the helper that `xcodex hooks install sdks python` installs
into `$CODEX_HOME/hooks/xcodex_hooks.py`.

We keep a copy under `examples/hooks/` so the example scripts can be executed
directly from the repo (and so the code is easy to read/audit).

Docs:
- Hooks overview: docs/xcodex/hooks.md
- Hook SDK installers: docs/xcodex/hooks-sdks.md
- Authoritative config reference: docs/config.md#hooks
"""

import json
import pathlib
import sys
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    import xcodex_hooks_models


def read_payload(raw: Optional[str] = None) -> Dict[str, Any]:
    """
    Read a hook payload as a dict.

    Input:
    - If `raw` is provided, it is treated as the full stdin string.
    - Otherwise, the function reads stdin (`sys.stdin.read()`).

    Output:
    - Returns the full payload dict for the event.

    Behavior:
    - For small payloads, stdin is the full JSON payload.
    - For large payloads, stdin is a small JSON envelope containing `payload_path`,
      which points to the full JSON payload written under CODEX_HOME.

    Typical usage in a hook script:

        payload = read_payload()
        if payload.get("hook_event_name") != "PostToolUse":
            return 0
        # ... your logic ...
    """
    if raw is None:
        raw = sys.stdin.read()

    raw = raw or "{}"
    payload = json.loads(raw)
    payload_path = payload.get("payload_path") or payload.get("payload-path")
    if payload_path:
        payload = json.loads(pathlib.Path(payload_path).read_text(encoding="utf-8"))
    return payload


def read_payload_model(raw: Optional[str] = None) -> "xcodex_hooks_models.HookPayload":
    """
    Read a hook payload and parse it into a dataclass model.

    This is optional sugar over:
    - `payload = read_payload()`
    - `event = xcodex_hooks_models.parse_hook_payload(payload)`

    The parser is tolerant by design: unknown fields are preserved in `.extras` / `.raw`.
    """
    payload = read_payload(raw)
    import xcodex_hooks_models

    return xcodex_hooks_models.parse_hook_payload(payload)
