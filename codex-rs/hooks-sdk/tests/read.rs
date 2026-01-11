use codex_hooks_sdk::read_payload_from_reader;
use pretty_assertions::assert_eq;
use tempfile::TempDir;

fn tool_call_finished_payload(marker_key: &str, marker_value: &str) -> String {
    format!(
        "{{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"PostToolUse\",\"xcodex_event_type\":\"tool-call-finished\",\"turn_id\":\"tu\",\"cwd\":\"/tmp\",\"tool_name\":\"Write\",\"tool_use_id\":\"c\",\"tool_response\":null,\"status\":\"completed\",\"duration_ms\":1,\"success\":true,\"output_bytes\":0,\"{marker_key}\":\"{marker_value}\"}}"
    )
}

#[test]
fn reads_inline_payload_and_preserves_unknown_fields() {
    let marker_key = "__extra__";
    let marker_value = "hello";

    let payload = tool_call_finished_payload(marker_key, marker_value);
    let payload = read_payload_from_reader(payload.as_bytes()).expect("read");

    assert_eq!(payload.tool_name.as_deref(), Some("Write"));
    assert_eq!(
        payload.extra.get(marker_key).and_then(|v| v.as_str()),
        Some(marker_value)
    );
}

#[test]
fn resolves_payload_path_envelope() {
    let dir = TempDir::new().expect("tmp");

    let marker_key = "__marker__";
    let marker_value = "ok";

    let payload_path = dir.path().join("payload.json");
    std::fs::write(
        &payload_path,
        tool_call_finished_payload(marker_key, marker_value),
    )
    .expect("write");

    let envelope = format!("{{\"payload_path\":\"{}\"}}", payload_path.display());
    let payload = read_payload_from_reader(envelope.as_bytes()).expect("read");

    assert_eq!(
        payload.extra.get(marker_key).and_then(|v| v.as_str()),
        Some(marker_value)
    );
}

#[test]
fn preserves_unknown_fields() {
    let payload = r#"{
  "schema_version": 1,
  "event_id": "e",
  "timestamp": "t",
  "session_id": "th",
  "transcript_path": "",
  "permission_mode": "default",
  "hook_event_name": "SessionStart",
  "xcodex_event_type": "session-start",
  "cwd": "/tmp",
  "answer": 42
}"#;

    let payload = read_payload_from_reader(payload.as_bytes()).expect("read");
    assert_eq!(
        payload
            .extra
            .get("answer")
            .and_then(serde_json::Value::as_i64),
        Some(42)
    );
}
