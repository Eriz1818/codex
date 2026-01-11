mod generated;

pub use generated::*;

use std::io;
use std::io::Read;
use std::path::Path;

use serde_json::Value;

#[derive(Debug)]
pub enum HookReadError {
    Io(io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for HookReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookReadError::Io(err) => write!(f, "I/O error reading hook payload: {err}"),
            HookReadError::Json(err) => write!(f, "invalid JSON hook payload: {err}"),
        }
    }
}

impl std::error::Error for HookReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HookReadError::Io(err) => Some(err),
            HookReadError::Json(err) => Some(err),
        }
    }
}

impl From<io::Error> for HookReadError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for HookReadError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

pub fn read_payload_from_stdin() -> Result<HookPayload, HookReadError> {
    read_payload_from_reader(io::stdin())
}

pub fn read_payload_from_reader<R: Read>(reader: R) -> Result<HookPayload, HookReadError> {
    let json = read_payload_json_from_reader(reader)?;
    Ok(serde_json::from_value(json)?)
}

pub fn read_payload_json_from_stdin() -> Result<Value, HookReadError> {
    read_payload_json_from_reader(io::stdin())
}

pub fn read_payload_json_from_reader<R: Read>(mut reader: R) -> Result<Value, HookReadError> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let payload = if buf.is_empty() || buf.iter().all(u8::is_ascii_whitespace) {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_slice(&buf)?
    };

    resolve_payload_path_envelope(payload)
}

fn resolve_payload_path_envelope(payload: Value) -> Result<Value, HookReadError> {
    let payload_path = payload
        .as_object()
        .and_then(|obj| obj.get("payload_path").or_else(|| obj.get("payload-path")))
        .and_then(Value::as_str);

    if let Some(payload_path) = payload_path {
        let contents = std::fs::read_to_string(Path::new(payload_path))?;
        Ok(serde_json::from_str(&contents)?)
    } else {
        Ok(payload)
    }
}
