#![cfg(not(target_os = "windows"))]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use codex_core::config::Constrained;
use codex_core::protocol::AskForApproval;
use codex_core::protocol::EventMsg;
use codex_core::protocol::HookProcessBeginEvent;
use codex_core::protocol::HookProcessEndEvent;
use codex_core::protocol::Op;
use codex_protocol::protocol::ReviewDecision;
use codex_protocol::user_input::UserInput;
use core_test_support::fs_wait;
use core_test_support::responses;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use tempfile::TempDir;

use responses::ev_assistant_message;
use responses::ev_completed;
use responses::ev_function_call;
use responses::ev_response_created;
use responses::mount_sse_sequence;
use responses::sse;
use responses::start_mock_server;

fn write_hook_script(dir: &TempDir, filename: &str, output_name: &str) -> Result<String> {
    let script = dir.path().join(filename);
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/bash
set -euo pipefail
out_dir="$(dirname "$0")"
tmp="$out_dir/{output_name}.tmp.$$"
stdin_payload="$(cat)"
python3 - "$stdin_payload" "$tmp" <<'PY'
import json
import pathlib
import sys

payload = json.loads(sys.argv[1])
payload_path = payload.get("payload_path") or payload.get("payload-path")
if payload_path:
    payload = json.loads(pathlib.Path(payload_path).read_text())

pathlib.Path(sys.argv[2]).write_text(json.dumps(payload))
PY
mv "$tmp" "$out_dir/{output_name}""#
        ),
    )?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
    Ok(script
        .to_str()
        .ok_or_else(|| anyhow!("hook script path is not valid utf-8"))?
        .to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_agent_turn_complete_invoked() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    responses::mount_sse_once(
        &server,
        sse(vec![ev_assistant_message("m1", "Done"), ev_completed("r1")]),
    )
    .await;

    let hook_dir = TempDir::new()?;
    let hook_script = write_hook_script(&hook_dir, "hook.sh", "turn.json")?;
    let hook_file = hook_dir.path().join("turn.json");

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.agent_turn_complete = vec![vec![hook_script]];
        })
        .build(&server)
        .await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello world".into(),
            }],
            final_output_json_schema: None,
        })
        .await?;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    fs_wait::wait_for_path_exists(&hook_file, Duration::from_secs(5)).await?;
    let hook_payload_raw = tokio::fs::read_to_string(&hook_file).await?;
    let payload: Value = serde_json::from_str(&hook_payload_raw)?;

    assert_eq!(payload["schema_version"], json!(1));
    assert_eq!(payload["hook_event_name"], json!("Stop"));
    assert_eq!(payload["xcodex_event_type"], json!("agent-turn-complete"));
    assert_eq!(payload["input_messages"], json!(["hello world"]));
    assert_eq!(payload["last_assistant_message"], json!("Done"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_approval_requested_invoked_for_exec() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let call_id = "hooks-approval-requested";
    let args = json!({
        "command": ["/bin/sh", "-c", "echo hook-test"],
        "timeout_ms": 1_000,
    });

    let responses = vec![
        sse(vec![
            ev_response_created("resp-1"),
            ev_function_call(call_id, "shell", &serde_json::to_string(&args)?),
            ev_completed("resp-1"),
        ]),
        sse(vec![
            ev_assistant_message("m1", "Done"),
            ev_completed("resp-2"),
        ]),
    ];
    mount_sse_sequence(&server, responses).await;

    let hook_dir = TempDir::new()?;
    let hook_script = write_hook_script(&hook_dir, "hook.sh", "approval.json")?;
    let hook_file = hook_dir.path().join("approval.json");

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.approval_requested = vec![vec![hook_script]];
            cfg.approval_policy = Constrained::allow_any(AskForApproval::UnlessTrusted);
        })
        .build(&server)
        .await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "run a shell command".into(),
            }],
            final_output_json_schema: None,
        })
        .await?;

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::ExecApprovalRequest(_))).await;
    fs_wait::wait_for_path_exists(&hook_file, Duration::from_secs(5)).await?;

    let hook_payload_raw = tokio::fs::read_to_string(&hook_file).await?;
    let payload: Value = serde_json::from_str(&hook_payload_raw)?;
    assert_eq!(payload["schema_version"], json!(1));
    assert_eq!(payload["hook_event_name"], json!("PermissionRequest"));
    assert_eq!(payload["xcodex_event_type"], json!("approval-requested"));
    assert_eq!(payload["kind"], json!("exec"));
    assert_eq!(payload["call_id"], json!(call_id));
    assert_eq!(payload["command"], args["command"]);

    codex
        .submit(Op::ExecApproval {
            id: "0".into(),
            decision: ReviewDecision::Approved,
        })
        .await?;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_session_start_invoked() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let hook_dir = TempDir::new()?;
    let hook_script = write_hook_script(&hook_dir, "hook.sh", "session_start.json")?;
    let hook_file = hook_dir.path().join("session_start.json");

    let _codex = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.session_start = vec![vec![hook_script]];
        })
        .build(&server)
        .await?;

    fs_wait::wait_for_path_exists(&hook_file, Duration::from_secs(5)).await?;
    let hook_payload_raw = tokio::fs::read_to_string(&hook_file).await?;
    let payload: Value = serde_json::from_str(&hook_payload_raw)?;

    assert_eq!(payload["schema_version"], json!(1));
    assert_eq!(payload["hook_event_name"], json!("SessionStart"));
    assert_eq!(payload["xcodex_event_type"], json!("session-start"));
    assert_eq!(payload["session_source"], json!("exec"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_model_request_started_invoked() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    responses::mount_sse_once(
        &server,
        sse(vec![ev_assistant_message("m1", "Done"), ev_completed("r1")]),
    )
    .await;

    let hook_dir = TempDir::new()?;
    let hook_script = write_hook_script(&hook_dir, "hook.sh", "model_request.json")?;
    let hook_file = hook_dir.path().join("model_request.json");

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.model_request_started = vec![vec![hook_script]];
        })
        .build(&server)
        .await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello world".into(),
            }],
            final_output_json_schema: None,
        })
        .await?;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    fs_wait::wait_for_path_exists(&hook_file, Duration::from_secs(5)).await?;
    let hook_payload_raw = tokio::fs::read_to_string(&hook_file).await?;
    let payload: Value = serde_json::from_str(&hook_payload_raw)?;

    assert_eq!(payload["schema_version"], json!(1));
    assert_eq!(payload["hook_event_name"], json!("model-request-started"));
    assert_eq!(payload["xcodex_event_type"], json!("model-request-started"));
    assert_eq!(payload["attempt"], json!(1));
    assert!(payload["model_request_id"].is_string());
    assert!(payload["input_item_count"].as_i64().unwrap_or(0) > 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_model_response_completed_invoked() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    responses::mount_sse_once(
        &server,
        sse(vec![ev_assistant_message("m1", "Done"), ev_completed("r1")]),
    )
    .await;

    let hook_dir = TempDir::new()?;
    let hook_script = write_hook_script(&hook_dir, "hook.sh", "model_response.json")?;
    let hook_file = hook_dir.path().join("model_response.json");

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.model_response_completed = vec![vec![hook_script]];
        })
        .build(&server)
        .await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello world".into(),
            }],
            final_output_json_schema: None,
        })
        .await?;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    fs_wait::wait_for_path_exists(&hook_file, Duration::from_secs(5)).await?;
    let hook_payload_raw = tokio::fs::read_to_string(&hook_file).await?;
    let payload: Value = serde_json::from_str(&hook_payload_raw)?;

    assert_eq!(payload["schema_version"], json!(1));
    assert_eq!(
        payload["hook_event_name"],
        json!("model-response-completed")
    );
    assert_eq!(
        payload["xcodex_event_type"],
        json!("model-response-completed")
    );
    assert_eq!(payload["attempt"], json!(1));
    assert!(payload["model_request_id"].is_string());
    assert_eq!(payload["response_id"], json!("r1"));
    assert_eq!(payload["needs_follow_up"], json!(false));
    assert_eq!(payload["token_usage"]["total_tokens"], json!(0));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_tool_call_started_and_finished_invoked() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let call_id = "hooks-tool-call";
    let args = json!({
        "command": ["/bin/sh", "-c", "echo hook-test"],
        "timeout_ms": 1_000,
    });

    let responses = vec![
        sse(vec![
            ev_response_created("resp-1"),
            ev_function_call(call_id, "shell", &serde_json::to_string(&args)?),
            ev_completed("resp-1"),
        ]),
        sse(vec![
            ev_assistant_message("m1", "Done"),
            ev_completed("resp-2"),
        ]),
    ];
    mount_sse_sequence(&server, responses).await;

    let hook_dir = TempDir::new()?;
    let started_hook_script = write_hook_script(&hook_dir, "hook_started.sh", "tool_started.json")?;
    let finished_hook_script =
        write_hook_script(&hook_dir, "hook_finished.sh", "tool_finished.json")?;
    let started_file = hook_dir.path().join("tool_started.json");
    let finished_file = hook_dir.path().join("tool_finished.json");

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.tool_call_started = vec![vec![started_hook_script]];
            cfg.hooks.tool_call_finished = vec![vec![finished_hook_script]];
            cfg.approval_policy = Constrained::allow_any(AskForApproval::Never);
        })
        .build(&server)
        .await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "run a shell command".into(),
            }],
            final_output_json_schema: None,
        })
        .await?;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    fs_wait::wait_for_path_exists(&started_file, Duration::from_secs(5)).await?;
    fs_wait::wait_for_path_exists(&finished_file, Duration::from_secs(5)).await?;

    let started_raw = tokio::fs::read_to_string(&started_file).await?;
    let started_payload: Value = serde_json::from_str(&started_raw)?;
    assert_eq!(started_payload["schema_version"], json!(1));
    assert_eq!(started_payload["hook_event_name"], json!("PreToolUse"));
    assert_eq!(
        started_payload["xcodex_event_type"],
        json!("tool-call-started")
    );
    assert_eq!(started_payload["tool_use_id"], json!(call_id));

    let finished_raw = tokio::fs::read_to_string(&finished_file).await?;
    let finished_payload: Value = serde_json::from_str(&finished_raw)?;
    assert_eq!(finished_payload["schema_version"], json!(1));
    assert_eq!(finished_payload["hook_event_name"], json!("PostToolUse"));
    assert_eq!(
        finished_payload["xcodex_event_type"],
        json!("tool-call-finished")
    );
    assert_eq!(finished_payload["tool_use_id"], json!(call_id));
    assert_eq!(finished_payload["tool_name"], json!("Bash"));
    assert_eq!(finished_payload["status"], json!("completed"));
    assert!(finished_payload["duration_ms"].as_u64().is_some());
    assert!(finished_payload["success"].is_boolean());
    assert!(finished_payload["output_bytes"].as_u64().is_some());
    assert!(finished_payload["output_preview"].is_string());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_session_end_invoked() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let hook_dir = TempDir::new()?;
    let hook_script = write_hook_script(&hook_dir, "hook.sh", "session_end.json")?;
    let hook_file = hook_dir.path().join("session_end.json");

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.session_end = vec![vec![hook_script]];
        })
        .build(&server)
        .await?;

    codex.submit(Op::Shutdown).await?;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::ShutdownComplete)).await;

    fs_wait::wait_for_path_exists(&hook_file, Duration::from_secs(5)).await?;
    let hook_payload_raw = tokio::fs::read_to_string(&hook_file).await?;
    let payload: Value = serde_json::from_str(&hook_payload_raw)?;

    assert_eq!(payload["schema_version"], json!(1));
    assert_eq!(payload["hook_event_name"], json!("SessionEnd"));
    assert_eq!(payload["xcodex_event_type"], json!("session-end"));
    assert_eq!(payload["session_source"], json!("exec"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hooks_tool_call_finished_emits_hook_process_events() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let call_id = "hooks-tool-call-hook-process";
    let args = json!({
        "command": ["/bin/sh", "-c", "echo hook-test"],
        "timeout_ms": 1_000,
    });

    let responses = vec![
        sse(vec![
            ev_response_created("resp-1"),
            ev_function_call(call_id, "shell", &serde_json::to_string(&args)?),
            ev_completed("resp-1"),
        ]),
        sse(vec![
            ev_assistant_message("m1", "Done"),
            ev_completed("resp-2"),
        ]),
    ];
    mount_sse_sequence(&server, responses).await;

    let hook_dir = TempDir::new()?;
    let hook_script = write_hook_script(&hook_dir, "hook.sh", "tool_finished.json")?;
    let hook_script_for_assert = hook_script.clone();
    let hook_file = hook_dir.path().join("tool_finished.json");

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |cfg| {
            cfg.hooks.tool_call_finished = vec![vec![hook_script]];
            cfg.approval_policy = Constrained::allow_any(AskForApproval::Never);
        })
        .build(&server)
        .await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "run a shell command".into(),
            }],
            final_output_json_schema: None,
        })
        .await?;

    let EventMsg::HookProcessBegin(HookProcessBeginEvent {
        hook_id,
        event_type,
        command,
        ..
    }) = wait_for_event(&codex, |ev| matches!(ev, EventMsg::HookProcessBegin(_))).await
    else {
        unreachable!("wait_for_event filters for HookProcessBegin")
    };

    assert_eq!(event_type, "tool-call-finished");
    assert_eq!(command, vec![hook_script_for_assert]);

    let EventMsg::HookProcessEnd(HookProcessEndEvent {
        hook_id: finished_id,
        exit_code,
    }) = wait_for_event(&codex, |ev| matches!(ev, EventMsg::HookProcessEnd(_))).await
    else {
        unreachable!("wait_for_event filters for HookProcessEnd")
    };

    assert_eq!(finished_id, hook_id);
    assert_eq!(exit_code, Some(0));

    fs_wait::wait_for_path_exists(&hook_file, Duration::from_secs(5)).await?;
    Ok(())
}
