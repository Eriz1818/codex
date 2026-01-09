//! Generate Python dataclass models for xcodex external hook payloads.
//!
//! Usage:
//!   cd codex-rs
//!   cargo run -p codex-core --bin hooks_python_models --features hooks-schema --quiet \
//!     > common/src/hooks_sdk_assets/python/xcodex_hooks_models.py

#[cfg(feature = "hooks-schema")]
use std::collections::BTreeMap;
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
    let one_of = schema
        .get("oneOf")
        .and_then(Value::as_array)
        .ok_or("expected top-level oneOf array")?;

    let _root_required: BTreeSet<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut variants: BTreeMap<String, Value> = BTreeMap::new();
    for variant in one_of {
        let properties = variant
            .get("properties")
            .and_then(Value::as_object)
            .ok_or("variant missing properties object")?;
        let ty = properties
            .get("type")
            .and_then(|v| v.get("enum"))
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(Value::as_str)
            .ok_or("variant type property missing enum string")?;
        variants.insert(ty.to_string(), variant.clone());
    }

    let mut out = String::new();
    out.push_str(
        r#"from __future__ import annotations

"""
xCodex hooks kit: Python runtime models for external hooks.

This file is generated from the Rust hook payload schema (source-of-truth).
It is installed into `$CODEX_HOME/hooks/` by:
  - `xcodex hooks install python`

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
- Compatibility policy: docs/xcodex/hooks.md (Compatibility policy)
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Union, Literal


@dataclass
class HookEventBase:
    schema_version: int
    event_id: str
    timestamp: str
    event_type: str

    raw: Dict[str, Any]
    extras: Dict[str, Any]


@dataclass
class UnknownHookEvent(HookEventBase):
    pass


HookEvent = Union[
    UnknownHookEvent,
"#,
    );

    for event_type in variants.keys() {
        writeln!(&mut out, "    \"{}HookEvent\",", pascal_case(event_type))
            .map_err(|_| "formatting failed".to_string())?;
    }
    out.push_str("]\n\n");

    out.push_str(
        r#"
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


def _as_any_list(value: Any) -> Optional[List[Any]]:
    if value is None:
        return None
    if isinstance(value, list):
        return value
    return None

"#,
    );

    for (event_type, variant) in &variants {
        let name = format!("{}HookEvent", pascal_case(event_type));
        let properties = variant
            .get("properties")
            .and_then(Value::as_object)
            .ok_or("variant missing properties object")?;

        writeln!(&mut out, "@dataclass").map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "class {name}(HookEventBase):")
            .map_err(|_| "formatting failed".to_string())?;

        writeln!(&mut out, "    event_type: Literal[{event_type:?}]")
            .map_err(|_| "formatting failed".to_string())?;

        // Deterministic key order.
        let mut keys: Vec<(&String, &Value)> = properties.iter().collect();
        keys.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

        for (key, key_schema) in &keys {
            let key = key.as_str();
            if key == "type" || key == "schema-version" || key == "event-id" || key == "timestamp" {
                continue;
            }
            let field_name = snake_case(key);
            let ty = py_type_for_schema(key_schema);
            writeln!(&mut out, "    {field_name}: Optional[{ty}] = None")
                .map_err(|_| "formatting failed".to_string())?;
        }

        if keys.is_empty() {
            writeln!(&mut out, "    pass").map_err(|_| "formatting failed".to_string())?;
        }

        out.push('\n');
    }

    out.push_str(
        r#"def parse_hook_event(payload: Mapping[str, Any]) -> HookEvent:
    """
    Parse a raw hook payload dict into a dataclass model.

    This is tolerant by design:
    - unknown event types return UnknownHookEvent
    - unknown fields are preserved under `.extras` and `.raw`
    """
    schema_version = int(payload.get("schema-version") or 0)
    event_id = str(payload.get("event-id") or "")
    timestamp = str(payload.get("timestamp") or "")
    event_type = str(payload.get("type") or "")

    raw = dict(payload)
    base_known = {"schema-version", "event-id", "timestamp", "type"}

    def extras_for(known: set[str]) -> Dict[str, Any]:
        return {k: v for k, v in raw.items() if k not in known}

"#,
    );

    out.push_str("    if event_type == \"\":\n");
    out.push_str("        return UnknownHookEvent(schema_version, event_id, timestamp, event_type, raw, extras_for(base_known))\n\n");

    for (event_type, variant) in &variants {
        let class_name = format!("{}HookEvent", pascal_case(event_type));
        let properties = variant
            .get("properties")
            .and_then(Value::as_object)
            .ok_or("variant missing properties object")?;

        let mut known_keys: BTreeSet<String> = BTreeSet::new();
        for k in ["schema-version", "event-id", "timestamp", "type"] {
            known_keys.insert(k.to_string());
        }
        for k in properties.keys() {
            known_keys.insert(k.clone());
        }

        writeln!(&mut out, "    if event_type == {event_type:?}:")
            .map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "        return {class_name}(")
            .map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "            schema_version=schema_version,")
            .map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "            event_id=event_id,")
            .map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "            timestamp=timestamp,")
            .map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "            event_type={event_type:?},")
            .map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "            raw=raw,").map_err(|_| "formatting failed".to_string())?;
        writeln!(
            &mut out,
            "            extras=extras_for({{{}}}),",
            known_keys
                .iter()
                .map(|k| format!("{k:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .map_err(|_| "formatting failed".to_string())?;

        // Event fields
        let mut keys: Vec<&String> = properties.keys().collect();
        keys.sort();
        for key in keys {
            let key = key.as_str();
            if key == "type" || key == "schema-version" || key == "event-id" || key == "timestamp" {
                continue;
            }
            let field_name = snake_case(key);
            let expr = py_coerce_expr(key, properties.get(key).unwrap_or(&Value::Null));
            writeln!(&mut out, "            {field_name}={expr},")
                .map_err(|_| "formatting failed".to_string())?;
        }

        writeln!(&mut out, "        )\n").map_err(|_| "formatting failed".to_string())?;
    }

    out.push_str(
        r#"    return UnknownHookEvent(schema_version, event_id, timestamp, event_type, raw, extras_for(base_known | {"type"}))
"#,
    );

    Ok(out)
}

#[cfg(feature = "hooks-schema")]
fn py_type_for_schema(schema: &Value) -> String {
    // Keep this intentionally shallow; complex nested objects become Any.
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str)
        && (reference.ends_with("/ApprovalKind") || reference.ends_with("/ToolCallStatus"))
    {
        return "str".to_string();
    }

    if let Some(ty) = schema.get("type") {
        match ty {
            Value::String(s) if s == "string" => return "str".to_string(),
            Value::String(s) if s == "integer" || s == "number" => return "int".to_string(),
            Value::String(s) if s == "boolean" => return "bool".to_string(),
            Value::String(s) if s == "array" => {
                let items = schema.get("items").unwrap_or(&Value::Null);
                let item_ty = py_type_for_schema(items);
                return format!("List[{item_ty}]");
            }
            Value::String(s) if s == "object" => return "Dict[str, Any]".to_string(),
            Value::String(s) if s == "null" => return "Any".to_string(),
            Value::Array(arr) => {
                if arr.iter().any(|v| v.as_str() == Some("string")) {
                    return "str".to_string();
                }
                if arr.iter().any(|v| v.as_str() == Some("array")) {
                    let items = schema.get("items").unwrap_or(&Value::Null);
                    let item_ty = py_type_for_schema(items);
                    return format!("List[{item_ty}]");
                }
                return "Any".to_string();
            }
            _ => {}
        }
    }

    if schema.get("anyOf").is_some() || schema.get("oneOf").is_some() {
        // Often "T | null" or complex unions; represent as Any.
        return "Any".to_string();
    }

    "Any".to_string()
}

#[cfg(feature = "hooks-schema")]
fn py_coerce_expr(key: &str, schema: &Value) -> String {
    let getter = format!("payload.get({key:?})");

    if schema.get("$ref").and_then(Value::as_str).is_some() {
        return format!("_as_str({getter})");
    }

    match schema.get("type") {
        Some(Value::String(s)) if s == "string" => format!("_as_str({getter})"),
        Some(Value::String(s)) if s == "integer" || s == "number" => format!("_as_int({getter})"),
        Some(Value::String(s)) if s == "boolean" => format!("_as_bool({getter})"),
        Some(Value::String(s)) if s == "array" => {
            let items = schema.get("items").unwrap_or(&Value::Null);
            if items.get("type").and_then(Value::as_str) == Some("string") {
                format!("_as_str_list({getter})")
            } else {
                format!("_as_any_list({getter})")
            }
        }
        Some(Value::Array(arr)) => {
            let has_string = arr.iter().any(|v| v.as_str() == Some("string"));
            let has_int = arr
                .iter()
                .any(|v| v.as_str() == Some("integer") || v.as_str() == Some("number"));
            let has_bool = arr.iter().any(|v| v.as_str() == Some("boolean"));
            let has_array = arr.iter().any(|v| v.as_str() == Some("array"));

            if has_string {
                return format!("_as_str({getter})");
            }
            if has_int {
                return format!("_as_int({getter})");
            }
            if has_bool {
                return format!("_as_bool({getter})");
            }
            if has_array {
                let items = schema.get("items").unwrap_or(&Value::Null);
                if items.get("type").and_then(Value::as_str) == Some("string") {
                    return format!("_as_str_list({getter})");
                }
                return format!("_as_any_list({getter})");
            }

            getter
        }
        _ => getter,
    }
}

#[cfg(feature = "hooks-schema")]
fn snake_case(input: &str) -> String {
    input.replace('-', "_")
}

#[cfg(feature = "hooks-schema")]
fn pascal_case(s: &str) -> String {
    let mut out = String::new();
    let mut upper_next = true;
    for ch in s.chars() {
        if ch == '-' || ch == '_' || ch == ' ' {
            upper_next = true;
            continue;
        }
        if upper_next {
            for up in ch.to_uppercase() {
                out.push(up);
            }
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}
