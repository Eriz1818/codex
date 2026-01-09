//! Generate TypeScript `.d.ts` types for xcodex external hook payloads.
//!
//! Usage:
//!   cd codex-rs
//!   cargo run -p codex-core --bin hooks_typescript --features hooks-schema --quiet \
//!     > common/src/hooks_sdk_assets/js/xcodex_hooks.d.ts

#[cfg(feature = "hooks-schema")]
use std::collections::BTreeMap;
#[cfg(feature = "hooks-schema")]
use std::collections::BTreeSet;
#[cfg(feature = "hooks-schema")]
use std::fmt::Write;

#[cfg(feature = "hooks-schema")]
use serde_json::Value;

#[cfg(feature = "hooks-schema")]
use codex_core::hooks::HookPayload;
#[cfg(feature = "hooks-schema")]
use schemars::schema_for;

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

    match generate_typescript_dts(&schema_json) {
        Ok(out) => print!("{out}"),
        Err(err) => {
            eprintln!("error: failed to generate TypeScript types: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "hooks-schema")]
fn generate_typescript_dts(schema: &Value) -> Result<String, String> {
    let definitions = schema
        .get("definitions")
        .and_then(Value::as_object)
        .ok_or("expected definitions object")?;
    let mut out = String::new();
    writeln!(&mut out, r#"/**"#,).map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#" * xCodex hooks kit: TypeScript type definitions for external hooks."#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" *"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" * Installed into `$CODEX_HOME/hooks/` by:"#,)
        .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" * - `xcodex hooks install javascript`"#)
        .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" * - `xcodex hooks install typescript`"#)
        .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" *"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#" * These types model the JSON payload shape emitted by Codex hooks."#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" *"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" * Docs:"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" * - Hooks overview: docs/xcodex/hooks.md"#)
        .map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#" * - Hook SDK installers: docs/xcodex/hooks-sdks.md"#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#" * - Machine-readable schema: docs/xcodex/hooks.schema.json"#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#" * - Authoritative config reference: docs/config.md#hooks"#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" */"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out).map_err(|_| "formatting failed".to_string())?;

    if let Some(approval_kind) = definitions
        .get("ApprovalKind")
        .and_then(ts_schema_string_union)
    {
        writeln!(&mut out, "export type ApprovalKind = {approval_kind};")
            .map_err(|_| "formatting failed".to_string())?;
    }
    if let Some(tool_call_status) = definitions
        .get("ToolCallStatus")
        .and_then(ts_schema_string_union)
    {
        writeln!(&mut out, "export type ToolCallStatus = {tool_call_status};")
            .map_err(|_| "formatting failed".to_string())?;
    }
    writeln!(&mut out).map_err(|_| "formatting failed".to_string())?;

    writeln!(&mut out, r#"export type HookPayloadBase = {{"#)
        .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#"  "schema-version": number;"#)
        .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#"  "event-id": string;"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#"  timestamp: string;"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#"}};"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out).map_err(|_| "formatting failed".to_string())?;

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
        let type_prop = properties
            .get("type")
            .ok_or("variant missing type property")?;
        let ty = type_prop
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(Value::as_str)
            .ok_or("variant type property missing enum string")?;

        variants.insert(ty.to_string(), variant.clone());
    }

    for (event_type, variant) in &variants {
        let name = format!("{}Payload", pascal_case(event_type));
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

        writeln!(&mut out, "export type {name} = HookPayloadBase & {{")
            .map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out, "  type: \"{event_type}\";")
            .map_err(|_| "formatting failed".to_string())?;

        let mut keys: Vec<(&String, &Value)> = properties.iter().collect();
        keys.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

        for (key, schema) in keys {
            if key == "type" || key == "schema-version" || key == "event-id" || key == "timestamp" {
                continue;
            }

            let optional = if required.contains(key) { "" } else { "?" };
            let ts_type = ts_type_for_schema(schema, definitions);
            let ts_key = ts_key(key);
            writeln!(&mut out, "  {ts_key}{optional}: {ts_type};")
                .map_err(|_| "formatting failed".to_string())?;
        }

        writeln!(&mut out, "}};").map_err(|_| "formatting failed".to_string())?;
        writeln!(&mut out).map_err(|_| "formatting failed".to_string())?;
    }

    writeln!(&mut out, "export type HookPayload =").map_err(|_| "formatting failed".to_string())?;
    for event_type in variants.keys() {
        let name = format!("{}Payload", pascal_case(event_type));
        writeln!(&mut out, "  | {name}").map_err(|_| "formatting failed".to_string())?;
    }
    writeln!(
        &mut out,
        r#"  | (HookPayloadBase & {{ type: string; [k: string]: unknown }});"#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out).map_err(|_| "formatting failed".to_string())?;

    writeln!(&mut out, r#"/**"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#" * Read a hook payload (handles stdin vs payload-path envelopes)."#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" *"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#" * @param raw Optional stdin string; if omitted, reads from fd 0."#
    )
    .map_err(|_| "formatting failed".to_string())?;
    writeln!(&mut out, r#" */"#).map_err(|_| "formatting failed".to_string())?;
    writeln!(
        &mut out,
        r#"export function readPayload(raw?: string): HookPayload;"#
    )
    .map_err(|_| "formatting failed".to_string())?;

    Ok(out)
}

#[cfg(feature = "hooks-schema")]
fn ts_string_enum_union(def: &Value) -> Option<String> {
    let values = def.get("enum")?.as_array()?;
    let mut parts = Vec::new();
    for v in values {
        let s = v.as_str()?;
        parts.push(format!("\"{s}\""));
    }
    Some(parts.join(" | "))
}

#[cfg(feature = "hooks-schema")]
fn ts_schema_string_union(schema: &Value) -> Option<String> {
    if let Some(union) = ts_string_enum_union(schema) {
        return Some(union);
    }
    let one_of = schema.get("oneOf")?.as_array()?;
    let mut parts = Vec::new();
    for v in one_of {
        if let Some(union) = ts_string_enum_union(v) {
            parts.push(union);
        } else {
            return None;
        }
    }
    Some(parts.join(" | "))
}

#[cfg(feature = "hooks-schema")]
fn ts_type_for_schema(schema: &Value, definitions: &serde_json::Map<String, Value>) -> String {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if let Some((_, name)) = reference.rsplit_once('/') {
            match name {
                "ApprovalKind" => return "ApprovalKind".to_string(),
                "ToolCallStatus" => return "ToolCallStatus".to_string(),
                _ => {}
            }

            if let Some(def) = definitions.get(name)
                && let Some(union) = ts_schema_string_union(def)
            {
                return union;
            }
        }
        return "unknown".to_string();
    }

    if let Some(union) = ts_schema_string_union(schema) {
        return union;
    }

    if let Some(ty) = schema.get("type") {
        match ty {
            Value::String(s) if s == "string" => return "string".to_string(),
            Value::String(s) if s == "integer" || s == "number" => return "number".to_string(),
            Value::String(s) if s == "boolean" => return "boolean".to_string(),
            Value::String(s) if s == "null" => return "null".to_string(),
            Value::String(s) if s == "object" => return "Record<string, unknown>".to_string(),
            Value::String(s) if s == "array" => {
                let items = schema.get("items").unwrap_or(&Value::Null);
                let item_ty = ts_type_for_schema(items, definitions);
                return format!("{item_ty}[]");
            }
            Value::Array(arr) => {
                let mut parts = BTreeSet::new();
                let mut has_array = false;
                for v in arr.iter().filter_map(Value::as_str) {
                    match v {
                        "array" => has_array = true,
                        "string" => {
                            parts.insert("string".to_string());
                        }
                        "integer" | "number" => {
                            parts.insert("number".to_string());
                        }
                        "boolean" => {
                            parts.insert("boolean".to_string());
                        }
                        "null" => {
                            parts.insert("null".to_string());
                        }
                        "object" => {
                            parts.insert("Record<string, unknown>".to_string());
                        }
                        _ => {
                            parts.insert("unknown".to_string());
                        }
                    }
                }

                if has_array {
                    let items = schema.get("items").unwrap_or(&Value::Null);
                    let item_ty = ts_type_for_schema(items, definitions);
                    parts.insert(format!("{item_ty}[]"));
                }
                return parts.into_iter().collect::<Vec<_>>().join(" | ");
            }
            _ => {}
        }
    }

    for key in ["anyOf", "oneOf"] {
        if let Some(arr) = schema.get(key).and_then(Value::as_array) {
            let mut parts = BTreeSet::new();
            for v in arr {
                parts.insert(ts_type_for_schema(v, definitions));
            }
            if !parts.is_empty() {
                return parts.into_iter().collect::<Vec<_>>().join(" | ");
            }
        }
    }

    if schema.get("nullable").and_then(Value::as_bool) == Some(true) {
        return "unknown | null".to_string();
    }

    "unknown".to_string()
}

#[cfg(feature = "hooks-schema")]
fn ts_key(key: &str) -> String {
    let is_ident = key.chars().enumerate().all(|(i, ch)| {
        if i == 0 {
            ch == '_' || ch.is_ascii_alphabetic()
        } else {
            ch == '_' || ch.is_ascii_alphanumeric()
        }
    });
    if is_ident {
        key.to_string()
    } else {
        format!("\"{key}\"")
    }
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
