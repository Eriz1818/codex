//! Generate Python dataclass models for xcodex external hook payloads.
//!
//! Usage:
//!   cd codex-rs
//!   cargo run -p codex-core --bin hooks_python_models --features hooks-schema --quiet \
//!     > common/src/hooks_sdk_assets/python/xcodex_hooks_models.py

#[cfg(feature = "hooks-schema")]
use std::collections::BTreeSet;
#[cfg(feature = "hooks-schema")]
use std::fmt::Write;

#[cfg(feature = "hooks-schema")]
use codex_core::hooks::HookPayload;
#[cfg(feature = "hooks-schema")]
use schemars::schema_for;
#[cfg(feature = "hooks-schema")]
use serde_json::Value;

#[cfg(not(feature = "hooks-schema"))]
fn main() {
    eprintln!("error: build with `--features hooks-schema` to enable schema/type generation");
    std::process::exit(2);
}

#[cfg(feature = "hooks-schema")]
fn main() {
    let schema = schema_for!(HookPayload);
    let schema_json = match serde_json::to_value(&schema) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("error: failed to serialize schema: {err}");
            std::process::exit(1);
        }
    };

    match generate_python_models(&schema_json) {
        Ok(out) => print!("{out}"),
        Err(err) => {
            eprintln!("error: failed to generate Python models: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "hooks-schema")]
fn generate_python_models(schema: &Value) -> Result<String, String> {
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or("expected top-level properties object")?;

    let required: BTreeSet<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut keys: Vec<&String> = properties.keys().collect();
    keys.sort_by(|a, b| a.as_str().cmp(b.as_str()));

    let mut required_keys = Vec::new();
    let mut optional_keys = Vec::new();
    for key in &keys {
        if required.contains(key.as_str()) {
            required_keys.push(key);
        } else {
            optional_keys.push(key);
        }
    }

    let mut out = String::new();
    out.push_str(
        r#"from __future__ import annotations

"""
xCodex hooks kit: Python runtime models for external hooks.

This file is generated from the Rust hook payload schema (source-of-truth).
It is installed into `$CODEX_HOME/hooks/` by:
  - `xcodex hooks install sdks python`

Re-generate from the repo:
  cd codex-rs
  cargo run -p codex-core --bin hooks_python_models --features hooks-schema --quiet \
    > common/src/hooks_sdk_assets/python/xcodex_hooks_models.py

This module is intentionally dependency-free (no pydantic). It aims to provide:
- ergonomic attribute access (dataclasses)
- forward compatibility (unknown fields are preserved in `.extras` / `.raw`)

Docs:
- Hooks overview: docs/xcodex/hooks.md
- Machine-readable schema: docs/xcodex/hooks.schema.json
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return None


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 10)
        except Exception:
            return None
    return None


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y", "on"):
            return True
        if v in ("false", "0", "no", "n", "off"):
            return False
    return None


def _as_str_list(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            s = _as_str(item)
            if s is not None:
                out.append(s)
        return out
    return None


@dataclass
class HookPayload:
"#,
    );

    for key in required_keys {
        let ty = py_hint_for_schema(
            properties
                .get(*key)
                .ok_or("property disappeared while iterating")?,
            false,
        );
        writeln!(&mut out, "    {key}: {ty}").map_err(|_| "formatting failed".to_string())?;
    }
    for key in optional_keys {
        let ty = py_hint_for_schema(
            properties
                .get(*key)
                .ok_or("property disappeared while iterating")?,
            true,
        );
        writeln!(&mut out, "    {key}: {ty} = None")
            .map_err(|_| "formatting failed".to_string())?;
    }

    out.push_str(
        r#"

    raw: Dict[str, Any] = None  # type: ignore[assignment]
    extras: Dict[str, Any] = None  # type: ignore[assignment]


def parse_hook_payload(payload: Mapping[str, Any]) -> HookPayload:
    raw = dict(payload)
    known = {
"#,
    );
    for key in &keys {
        writeln!(&mut out, "        {key:?},").map_err(|_| "formatting failed".to_string())?;
    }
    out.push_str(
        r#"    }
    extras = {k: v for (k, v) in raw.items() if k not in known}

    return HookPayload(
"#,
    );

    for key in &keys {
        let extractor = py_extractor_for_schema(
            properties
                .get(*key)
                .ok_or("property disappeared while iterating")?,
        );
        writeln!(&mut out, "        {key}={extractor}(raw.get({key:?})),")
            .map_err(|_| "formatting failed".to_string())?;
    }
    out.push_str(
        r#"        raw=raw,
        extras=extras,
    )
"#,
    );

    Ok(out)
}

#[cfg(feature = "hooks-schema")]
fn py_hint_for_schema(schema: &Value, optional: bool) -> String {
    let base = if schema.get("$ref").is_some() {
        "Any".to_string()
    } else if let Some(ty) = schema.get("type").and_then(Value::as_str) {
        match ty {
            "string" => "str".to_string(),
            "integer" | "number" => "int".to_string(),
            "boolean" => "bool".to_string(),
            "array" => {
                if let Some(items) = schema.get("items")
                    && items.get("type").and_then(Value::as_str) == Some("string")
                {
                    "List[str]".to_string()
                } else {
                    "List[Any]".to_string()
                }
            }
            "object" => "Dict[str, Any]".to_string(),
            _ => "Any".to_string(),
        }
    } else {
        "Any".to_string()
    };

    if optional {
        format!("Optional[{base}]")
    } else {
        base
    }
}

#[cfg(feature = "hooks-schema")]
fn py_extractor_for_schema(schema: &Value) -> &'static str {
    if schema.get("$ref").is_some() {
        return "lambda x: x";
    }

    match schema.get("type").and_then(Value::as_str) {
        Some("string") => "_as_str",
        Some("integer") | Some("number") => "_as_int",
        Some("boolean") => "_as_bool",
        Some("array") => {
            if let Some(items) = schema.get("items")
                && items.get("type").and_then(Value::as_str) == Some("string")
            {
                "_as_str_list"
            } else {
                "lambda x: x if isinstance(x, list) else None"
            }
        }
        _ => "lambda x: x",
    }
}
