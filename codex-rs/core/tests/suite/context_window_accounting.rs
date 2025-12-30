use anyhow::Result;
use codex_core::protocol::CodexErrorInfo;
use codex_core::protocol::EventMsg;
use codex_core::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::mount_sse_once_match;
use core_test_support::responses::sse_failed;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use wiremock::matchers::body_string_contains;

#[cfg(not(target_os = "windows"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupt_recomputes_prompt_estimate_after_history_grows() -> Result<()> {
    use codex_protocol::protocol::TokenUsageInfo;
    use core_test_support::responses::ev_completed_with_tokens;
    use core_test_support::responses::ev_function_call;
    use core_test_support::responses::ev_response_created;
    use core_test_support::responses::mount_sse_once;
    use core_test_support::responses::sse;
    use std::time::Duration;
    use tokio::time::timeout;

    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let call_id = "call-long";
    let args = serde_json::json!({
        "command": "sleep 60",
        "timeout_ms": 60_000
    })
    .to_string();
    let body = sse(vec![
        ev_response_created("resp-1"),
        ev_function_call(call_id, "shell_command", &args),
        ev_completed_with_tokens("resp-1", 50),
    ]);
    mount_sse_once(&server, body).await;

    let TestCodex { codex, .. } = test_codex().with_model("gpt-5.1").build(&server).await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "x".repeat(5_000),
            }],
        })
        .await?;

    // Wait until the exec begins to avoid a race, then interrupt.
    core_test_support::wait_for_event(&codex, |ev| matches!(ev, EventMsg::ExecCommandBegin(_)))
        .await;
    codex.submit(Op::Interrupt).await?;

    let (mut saw_aborted, mut info_after_abort) = (false, None::<TokenUsageInfo>);
    while !(saw_aborted && info_after_abort.is_some()) {
        let event = timeout(Duration::from_secs(10), codex.next_event())
            .await
            .expect("timeout waiting for abort + token estimate")
            .expect("event stream ended unexpectedly")
            .msg;

        match event {
            EventMsg::TurnAborted(_) => saw_aborted = true,
            EventMsg::TokenCount(payload) => {
                let Some(info) = payload.info else {
                    continue;
                };
                if info.total_token_usage.total_tokens == 50
                    && info.last_token_usage.input_tokens == 0
                    && info.last_token_usage.total_tokens > info.total_token_usage.total_tokens
                {
                    info_after_abort = Some(info);
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_compact_disabled_does_not_locally_block_on_context_window() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let response_mock = mount_sse_once_match(
        &server,
        body_string_contains("trigger context overflow"),
        sse_failed(
            "resp-overflow",
            "context_length_exceeded",
            "Your input exceeds the context window of this model. Please adjust your input and try again.",
        ),
    )
    .await;

    let TestCodex { codex, .. } = test_codex()
        .with_config(|config| {
            config.model = Some("gpt-5.1".to_string());
            config.model_context_window = Some(100);
            config.model_auto_compact_token_limit = None;
        })
        .build(&server)
        .await?;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "trigger context overflow".into(),
            }],
        })
        .await?;

    let error_event =
        core_test_support::wait_for_event(&codex, |ev| matches!(ev, EventMsg::Error(_))).await;
    assert!(
        matches!(
            error_event,
            EventMsg::Error(ref err)
                if err.codex_error_info == Some(CodexErrorInfo::ContextWindowExceeded)
                    && err.message.contains("provider rejected")
                    && err.message.contains("context_length_exceeded")
        ),
        "expected provider context window rejection; got {error_event:?}"
    );

    core_test_support::wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    assert_eq!(
        response_mock.requests().len(),
        1,
        "auto-compact disabled should attempt the request and let the provider reject"
    );

    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_emits_prompt_estimate_consistent_with_aborted_history() -> Result<()> {
    use core_test_support::responses::ev_completed_with_tokens;
    use core_test_support::responses::ev_function_call;
    use core_test_support::responses::ev_response_created;
    use core_test_support::responses::mount_sse_once;
    use core_test_support::responses::sse;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let call_id = "call-resume";
    let args = serde_json::json!({
        "command": "sleep 60",
        "timeout_ms": 60_000
    })
    .to_string();
    let body = sse(vec![
        ev_response_created("resp-1"),
        ev_function_call(call_id, "shell_command", &args),
        ev_completed_with_tokens("resp-1", 50),
    ]);
    mount_sse_once(&server, body).await;

    let mut builder = test_codex().with_model("gpt-5.1");
    let initial = builder.build(&server).await?;
    let codex = Arc::clone(&initial.codex);
    let home = Arc::clone(&initial.home);
    let rollout_path = initial.session_configured.rollout_path.clone();

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "x".repeat(5_000),
            }],
        })
        .await?;
    core_test_support::wait_for_event(&codex, |ev| matches!(ev, EventMsg::ExecCommandBegin(_)))
        .await;
    codex.submit(Op::Interrupt).await?;

    let (mut saw_aborted, mut abort_estimate) = (false, None::<i64>);
    while !(saw_aborted && abort_estimate.is_some()) {
        let event = timeout(Duration::from_secs(10), codex.next_event())
            .await
            .expect("timeout waiting for abort + token estimate")
            .expect("event stream ended unexpectedly")
            .msg;

        match event {
            EventMsg::TurnAborted(_) => saw_aborted = true,
            EventMsg::TokenCount(payload) => {
                let Some(info) = payload.info else {
                    continue;
                };
                if info.total_token_usage.total_tokens == 50
                    && info.last_token_usage.input_tokens == 0
                {
                    abort_estimate = Some(info.last_token_usage.total_tokens);
                }
            }
            _ => {}
        }
    }

    let abort_estimate = abort_estimate.expect("abort token estimate captured");

    let mut resume_builder = test_codex().with_model("gpt-5.1");
    let resumed = resume_builder.resume(&server, home, rollout_path).await?;
    let resumed_token_event = core_test_support::wait_for_event(&resumed.codex, |ev| {
        matches!(ev, EventMsg::TokenCount(payload) if payload.info.as_ref().is_some_and(|info| {
            info.total_token_usage.total_tokens == 50 && info.last_token_usage.input_tokens == 0
        }))
    })
    .await;
    let EventMsg::TokenCount(resumed_payload) = resumed_token_event else {
        unreachable!("wait_for_event returned unexpected event");
    };
    let resumed_info = resumed_payload
        .info
        .expect("token usage info present after resume recompute");

    assert_eq!(
        resumed_info.last_token_usage.total_tokens, abort_estimate,
        "expected resume recompute to match last in-session estimate"
    );

    Ok(())
}
