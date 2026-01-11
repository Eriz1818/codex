//! Generate the JSON Schema for xcodex external hook payloads.
//!
//! Usage:
//!   cargo run -p codex-core --bin hooks_schema --features hooks-schema > docs/xcodex/hooks.schema.json

#[cfg(not(feature = "hooks-schema"))]
fn main() {
    eprintln!("error: build with `--features hooks-schema` to enable JSON Schema generation");
    std::process::exit(2);
}

#[cfg(feature = "hooks-schema")]
use codex_core::hooks::HookPayload;
#[cfg(feature = "hooks-schema")]
use codex_core::hooks::HookStdinEnvelope;
#[cfg(feature = "hooks-schema")]
use schemars::schema_for;
#[cfg(feature = "hooks-schema")]
use serde::Serialize;

#[cfg(feature = "hooks-schema")]
#[derive(Debug, Serialize)]
struct HookSchemaBundle {
    hook_payload: schemars::schema::RootSchema,
    stdin_envelope: schemars::schema::RootSchema,
}

#[cfg(feature = "hooks-schema")]
fn main() {
    let bundle = HookSchemaBundle {
        hook_payload: schema_for!(HookPayload),
        stdin_envelope: schema_for!(HookStdinEnvelope),
    };

    match serde_json::to_string_pretty(&bundle) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("error: failed to serialize schema bundle: {err}");
            std::process::exit(1);
        }
    }
}
