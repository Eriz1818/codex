from __future__ import annotations

"""
xCodex hooks kit: Python runtime helpers for external hooks.

This file is installed into `$CODEX_HOME/hooks/` by:

  xcodex hooks install sdks python

It provides small "runtime parsing" helpers that keep your hook scripts:
- tolerant / forward-compatible (unknown fields/types do not break)
- readable (you can branch on hook_event_name / xcodex_event_type)

Typing:
- TypedDict event types live in `xcodex_hooks_types.py`.
"""

from typing import Any, Mapping, Optional

try:
    from typing import TypeGuard
except ImportError:  # pragma: no cover
    class TypeGuard:  # type: ignore
        def __class_getitem__(cls, item):
            return bool

from xcodex_hooks_types import HookPayload


def _has_keys(payload: Mapping[str, Any], keys: tuple[str, ...]) -> bool:
    return all(k in payload for k in keys)


def as_hook_payload(payload: Mapping[str, Any]) -> Optional[HookPayload]:
    if not _has_keys(
        payload,
        (
            "schema_version",
            "event_id",
            "timestamp",
            "session_id",
            "cwd",
            "permission_mode",
            "transcript_path",
            "hook_event_name",
            "xcodex_event_type",
        ),
    ):
        return None
    return payload  # type: ignore[return-value]
