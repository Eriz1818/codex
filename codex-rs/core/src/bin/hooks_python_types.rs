//! Generate Python TypedDict types and runtime helpers for xcodex external hooks.
//!
//! Usage:
//!   cd codex-rs
//!   cargo run -p codex-core --bin hooks_python_types --features hooks-schema --quiet \
//!     > common/src/hooks_sdk_assets/python/xcodex_hooks_types.py

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

    match generate_python_types(&schema_json) {
        Ok(out) => print!("{out}"),
        Err(err) => {
            eprintln!("error: failed to generate Python types: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "hooks-schema")]
fn generate_python_types(schema: &Value) -> Result<String, String> {
    let definitions = schema
        .get("definitions")
        .and_then(Value::as_object)
        .ok_or("expected definitions object")?;

    let one_of = schema
        .get("oneOf")
        .and_then(Value::as_array)
        .ok_or("expected top-level oneOf array")?;

    let root_required: BTreeSet<String> = schema
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
    writeln!(
        &mut out,
        "from __future__ import annotations\n\n\
\"\"\"\n\
xCodex hooks kit: Python typed helpers for external hooks.\n\n\
This file is generated from the Rust hook payload schema (source-of-truth).\n\
It is installed into `$CODEX_HOME/hooks/` by:\n\
  - `xcodex hooks install python`\n\n\
Re-generate from the repo:\n\
  cd codex-rs\n\
  cargo run -p codex-core --bin hooks_python_types --features hooks-schema --quiet \\\n\
    > common/src/hooks_sdk_assets/python/xcodex_hooks_types.py\n\n\
Docs:\n\
- Hooks overview: docs/xcodex/hooks.md\n\
- Machine-readable schema: docs/xcodex/hooks.schema.json\n\
- Hook SDK installers: docs/xcodex/hooks-sdks.md\n\
\"\"\"\n"
    )
    .map_err(|_| "formatting failed".to_string())?;

    out.push_str(
        r#"
from typing import Any, Dict, List, Literal, Optional, TypedDict, Union
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import NotRequired, Required
else:
    class _Req:
        def __class_getitem__(cls, item):  # noqa: D401
            return item

    Required = NotRequired = _Req  # type: ignore
"#,
    );

    if let Some(approval_kind) = definitions.get("ApprovalKind").and_then(py_string_union) {
        writeln!(&mut out, "\nApprovalKind = {approval_kind}")
            .map_err(|_| "formatting failed".to_string())?;
    } else {
        writeln!(&mut out, "\nApprovalKind = str").map_err(|_| "formatting failed".to_string())?;
    }

    if let Some(tool_call_status) = definitions.get("ToolCallStatus").and_then(py_string_union) {
        writeln!(&mut out, "\nToolCallStatus = {tool_call_status}")
            .map_err(|_| "formatting failed".to_string())?;
    } else {
        writeln!(&mut out, "\nToolCallStatus = str")
            .map_err(|_| "formatting failed".to_string())?;
    }

    writeln!(
        &mut out,
        "\nHookPayloadBase = TypedDict(\n\
    \"HookPayloadBase\",\n\
    {{\n\
        \"schema-version\": Required[int],\n\
        \"event-id\": Required[str],\n\
        \"timestamp\": Required[str],\n\
    }},\n\
    total=False,\n\
)\n"
    )
    .map_err(|_| "formatting failed".to_string())?;

    let mut variant_names = Vec::new();
    for (event_type, variant) in &variants {
        let name = format!("{}Payload", pascal_case(event_type));
        variant_names.push(name.clone());

        let properties = variant
            .get("properties")
            .and_then(Value::as_object)
            .ok_or("variant missing properties object")?;

        let mut required: BTreeSet<String> = root_required.clone();
        if let Some(arr) = variant.get("required").and_then(Value::as_array) {
            for key in arr.iter().filter_map(Value::as_str) {
                required.insert(key.to_string());
            }
        }

        writeln!(&mut out, "{name} = TypedDict(").map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "    \"{name}\",").map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "    {{").map_err(|_| "formatting failed".to_string())?;

        writeln!(
            &mut out,
            "        \"type\": Required[Literal[\"{event_type}\"]],"
        )
        .map_err(|_| "formatting failed".to_string())?;

        let mut keys: Vec<(&String, &Value)> = properties.iter().collect();
        keys.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

        for (key, key_schema) in keys {
            if key == "type" || key == "schema-version" || key == "event-id" || key == "timestamp" {
                continue;
            }
            let annotation = if required.contains(key.as_str()) {
                "Required"
            } else {
                "NotRequired"
            };
            let py_ty = py_type_for_schema(key_schema, definitions);
            writeln!(&mut out, "        \"{key}\": {annotation}[{py_ty}],")
                .map_err(|_| "formatting failed".to_string())?;
        }

        writeln!(&mut out, "    }},\n    total=False,\n)\n")
            .map_err(|_| "formatting failed".to_string())?;
    }

    writeln!(&mut out, "HookPayload = Union[").map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, "    HookPayloadBase,").map_err(|_| "formatting failed".to_string())?;
    for name in &variant_names {
        writeln!(&mut out, "    {name},").map_err(|_| "formatting failed".to_string())?;
    }
    writeln!(&mut out, "    Dict[str, Any],").map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, "]\n").map_err(|_| "formatting failed".to_string())?;

    Ok(out)
}

#[cfg(feature = "hooks-schema")]
fn py_string_union(schema: &Value) -> Option<String> {
    let literals = py_string_literals(schema)?;
    let mut parts: Vec<String> = literals
        .into_iter()
        .map(|s| format!("Literal[{s:?}]"))
        .collect();
    parts.sort();
    parts.dedup();

    match parts.len() {
        0 => None,
        1 => Some(parts[0].clone()),
        _ => Some(format!("Union[{}]", parts.join(", "))),
    }
}

#[cfg(feature = "hooks-schema")]
fn py_string_literals(schema: &Value) -> Option<Vec<String>> {
    if let Some(arr) = schema.get("enum").and_then(Value::as_array) {
        let mut out = Vec::new();
        for v in arr {
            out.push(v.as_str()?.to_string());
        }
        return Some(out);
    }

    let one_of = schema.get("oneOf")?.as_array()?;
    let mut out = Vec::new();
    for v in one_of {
        out.extend(py_string_literals(v)?);
    }
    Some(out)
}

#[cfg(feature = "hooks-schema")]
fn py_type_for_schema(schema: &Value, definitions: &serde_json::Map<String, Value>) -> String {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if let Some((_, name)) = reference.rsplit_once('/') {
            match name {
                "ApprovalKind" => return "ApprovalKind".to_string(),
                "ToolCallStatus" => return "ToolCallStatus".to_string(),
                _ => {}
            }
            if let Some(def) = definitions.get(name)
                && let Some(union) = py_string_union(def)
            {
                return union;
            }
        }
        return "Any".to_string();
    }

    if let Some(union) = py_string_union(schema) {
        return union;
    }

    if let Some(ty) = schema.get("type") {
        match ty {
            Value::String(s) if s == "string" => return "str".to_string(),
            Value::String(s) if s == "integer" || s == "number" => return "int".to_string(),
            Value::String(s) if s == "boolean" => return "bool".to_string(),
            Value::String(s) if s == "null" => return "None".to_string(),
            Value::String(s) if s == "object" => return "Dict[str, Any]".to_string(),
            Value::String(s) if s == "array" => {
                let items = schema.get("items").unwrap_or(&Value::Null);
                let item_ty = py_type_for_schema(items, definitions);
                return format!("List[{item_ty}]");
            }
            Value::Array(arr) => {
                let mut parts = BTreeSet::new();
                for v in arr.iter().filter_map(Value::as_str) {
                    let part = match v {
                        "string" => "str".to_string(),
                        "integer" | "number" => "int".to_string(),
                        "boolean" => "bool".to_string(),
                        "null" => "None".to_string(),
                        "object" => "Dict[str, Any]".to_string(),
                        "array" => {
                            let items = schema.get("items").unwrap_or(&Value::Null);
                            let item_ty = py_type_for_schema(items, definitions);
                            format!("List[{item_ty}]")
                        }
                        _ => "Any".to_string(),
                    };
                    parts.insert(part);
                }
                return if parts.len() == 1 {
                    match parts.into_iter().next() {
                        Some(value) => value,
                        None => "Any".to_string(),
                    }
                } else {
                    format!(
                        "Union[{}]",
                        parts.into_iter().collect::<Vec<_>>().join(", ")
                    )
                };
            }
            _ => {}
        }
    }

    for key in ["anyOf", "oneOf"] {
        if let Some(arr) = schema.get(key).and_then(Value::as_array) {
            let mut parts = BTreeSet::new();
            for v in arr {
                parts.insert(py_type_for_schema(v, definitions));
            }
            if !parts.is_empty() {
                return if parts.len() == 1 {
                    match parts.into_iter().next() {
                        Some(value) => value,
                        None => "Any".to_string(),
                    }
                } else {
                    format!(
                        "Union[{}]",
                        parts.into_iter().collect::<Vec<_>>().join(", ")
                    )
                };
            }
        }
    }

    "Any".to_string()
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
