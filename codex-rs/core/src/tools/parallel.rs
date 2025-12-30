use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;
use tokio_util::either::Either;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;
use tracing::instrument;
use tracing::trace_span;
use uuid::Uuid;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::error::CodexErr;
use crate::function_tool::FunctionCallError;
use crate::tools::context::SharedTurnDiffTracker;
use crate::tools::context::ToolPayload;
use crate::tools::router::ToolCall;
use crate::tools::router::ToolRouter;
use crate::user_notification::ToolCallStatus;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::ResponseInputItem;

#[derive(Clone)]
pub(crate) struct ToolCallRuntime {
    router: Arc<ToolRouter>,
    session: Arc<Session>,
    turn_context: Arc<TurnContext>,
    tracker: SharedTurnDiffTracker,
    parallel_execution: Arc<RwLock<()>>,
    thread_id: String,
    model_request_id: Uuid,
    attempt: u32,
}

impl ToolCallRuntime {
    pub(crate) fn new(
        router: Arc<ToolRouter>,
        session: Arc<Session>,
        turn_context: Arc<TurnContext>,
        tracker: SharedTurnDiffTracker,
        thread_id: String,
        model_request_id: Uuid,
        attempt: u32,
    ) -> Self {
        Self {
            router,
            session,
            turn_context,
            tracker,
            parallel_execution: Arc::new(RwLock::new(())),
            thread_id,
            model_request_id,
            attempt,
        }
    }

    #[instrument(level = "trace", skip_all, fields(call = ?call))]
    pub(crate) fn handle_tool_call(
        self,
        call: ToolCall,
        cancellation_token: CancellationToken,
    ) -> impl std::future::Future<Output = Result<ResponseInputItem, CodexErr>> {
        let supports_parallel = self.router.tool_supports_parallel(&call.tool_name);
        let tool_name = call.tool_name.clone();
        let call_id = call.call_id.clone();
        let call_for_task = call.clone();

        let router = Arc::clone(&self.router);
        let session = Arc::clone(&self.session);
        let hook_session = Arc::clone(&self.session);
        let turn = Arc::clone(&self.turn_context);
        let turn_for_task = Arc::clone(&turn);
        let tracker = Arc::clone(&self.tracker);
        let lock = Arc::clone(&self.parallel_execution);
        let started = Instant::now();
        let thread_id = self.thread_id.clone();
        let model_request_id = self.model_request_id;
        let attempt = self.attempt;

        hook_session.user_hooks().tool_call_started(
            thread_id.clone(),
            turn.sub_id.clone(),
            turn.cwd.display().to_string(),
            model_request_id,
            attempt,
            tool_name.clone(),
            call_id.clone(),
        );

        let dispatch_span = trace_span!(
            "dispatch_tool_call",
            otel.name = call.tool_name.as_str(),
            tool_name = call.tool_name.as_str(),
            call_id = call.call_id.as_str(),
            aborted = false,
        );

        let handle: AbortOnDropHandle<
            Result<(ToolCallStatus, ResponseInputItem), FunctionCallError>,
        > = AbortOnDropHandle::new(tokio::spawn(async move {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    let secs = started.elapsed().as_secs_f32().max(0.1);
                    dispatch_span.record("aborted", true);
                    Ok((ToolCallStatus::Aborted, Self::aborted_response(&call_for_task, secs)))
                },
                res = async {
                    let _guard = if supports_parallel {
                        Either::Left(lock.read().await)
                    } else {
                        Either::Right(lock.write().await)
                    };

                    router
                        .dispatch_tool_call(session, turn_for_task, tracker, call_for_task.clone())
                        .instrument(dispatch_span.clone())
                        .await
                } => res.map(|response| (ToolCallStatus::Completed, response)),
            }
        }));

        async move {
            let result = match handle.await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(FunctionCallError::Fatal(message))) => Err(CodexErr::Fatal(message)),
                Ok(Err(other)) => Err(CodexErr::Fatal(other.to_string())),
                Err(err) => Err(CodexErr::Fatal(format!(
                    "tool task failed to receive: {err:?}"
                ))),
            };

            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match &result {
                Ok((status, response)) => {
                    let (mut success, output_bytes, output_preview) =
                        summarize_tool_output(response, TOOL_OUTPUT_PREVIEW_BYTES);
                    if matches!(status, ToolCallStatus::Aborted) {
                        success = false;
                    }
                    hook_session.user_hooks().tool_call_finished(
                        thread_id,
                        turn.sub_id.clone(),
                        turn.cwd.display().to_string(),
                        model_request_id,
                        attempt,
                        tool_name.clone(),
                        call_id.clone(),
                        *status,
                        duration_ms,
                        success,
                        output_bytes,
                        output_preview,
                    );
                }
                Err(message) => {
                    let message = message.to_string();
                    hook_session.user_hooks().tool_call_finished(
                        thread_id,
                        turn.sub_id.clone(),
                        turn.cwd.display().to_string(),
                        model_request_id,
                        attempt,
                        tool_name,
                        call_id,
                        ToolCallStatus::Completed,
                        duration_ms,
                        false,
                        message.len(),
                        Some(truncate_preview(&message, TOOL_OUTPUT_PREVIEW_BYTES)),
                    );
                }
            }

            match result {
                Ok((_, response)) => Ok(response),
                Err(err) => Err(err),
            }
        }
        .in_current_span()
    }
}

const TOOL_OUTPUT_PREVIEW_BYTES: usize = 512;

fn truncate_preview(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }

    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
        if end == 0 {
            return String::new();
        }
    }

    text[..end].to_string()
}

fn append_truncated(preview: &mut String, text: &str, max_bytes: usize) {
    if preview.len() >= max_bytes || text.is_empty() {
        return;
    }

    let remaining = max_bytes - preview.len();
    if text.len() <= remaining {
        preview.push_str(text);
        return;
    }

    let mut end = remaining;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
        if end == 0 {
            return;
        }
    }

    preview.push_str(&text[..end]);
}

fn summarize_mcp_tool_output(
    result: &mcp_types::CallToolResult,
    max_preview_bytes: usize,
) -> (bool, usize, Option<String>) {
    let mut combined_len = 0usize;
    let mut preview = String::new();
    let mut has_any_content = false;

    for block in &result.content {
        let mcp_types::ContentBlock::TextContent(text) = block else {
            continue;
        };

        if has_any_content {
            combined_len = combined_len.saturating_add(1);
            if preview.len() < max_preview_bytes {
                preview.push('\n');
            }
        }

        combined_len = combined_len.saturating_add(text.text.len());
        append_truncated(&mut preview, &text.text, max_preview_bytes);

        if combined_len > 0 {
            has_any_content = true;
        }
    }

    let is_error = result.is_error.unwrap_or(false);
    let preview = if combined_len == 0 {
        None
    } else {
        Some(preview)
    };
    (!is_error, combined_len, preview)
}

fn summarize_tool_output(
    response: &ResponseInputItem,
    max_preview_bytes: usize,
) -> (bool, usize, Option<String>) {
    match response {
        ResponseInputItem::FunctionCallOutput { output, .. } => {
            let content = &output.content;
            let preview = truncate_preview(content, max_preview_bytes);
            (output.success.unwrap_or(true), content.len(), Some(preview))
        }
        ResponseInputItem::CustomToolCallOutput { output, .. } => {
            let preview = truncate_preview(output, max_preview_bytes);
            (true, output.len(), Some(preview))
        }
        ResponseInputItem::McpToolCallOutput { result, .. } => match result {
            Ok(call_result) => summarize_mcp_tool_output(call_result, max_preview_bytes),
            Err(message) => {
                let preview = truncate_preview(message, max_preview_bytes);
                (false, message.len(), Some(preview))
            }
        },
        ResponseInputItem::Message { .. } => (true, 0, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn summarize_mcp_tool_output_matches_combined_string_behavior() {
        let result = mcp_types::CallToolResult {
            content: vec![
                mcp_types::ContentBlock::TextContent(mcp_types::TextContent {
                    text: "hello".to_string(),
                    annotations: None,
                    r#type: "text".to_string(),
                }),
                mcp_types::ContentBlock::TextContent(mcp_types::TextContent {
                    text: "".to_string(),
                    annotations: None,
                    r#type: "text".to_string(),
                }),
                mcp_types::ContentBlock::TextContent(mcp_types::TextContent {
                    text: "world".to_string(),
                    annotations: None,
                    r#type: "text".to_string(),
                }),
            ],
            is_error: Some(false),
            structured_content: None,
        };

        let (success, output_bytes, preview) = summarize_mcp_tool_output(&result, 512);

        assert!(success);
        assert_eq!(output_bytes, "hello\n\nworld".len());
        assert_eq!(preview.as_deref(), Some("hello\n\nworld"));
    }

    #[test]
    fn summarize_mcp_tool_output_truncates_preview_without_allocating_full_string() {
        let result = mcp_types::CallToolResult {
            content: vec![mcp_types::ContentBlock::TextContent(
                mcp_types::TextContent {
                    text: "x".repeat(10_000),
                    annotations: None,
                    r#type: "text".to_string(),
                },
            )],
            is_error: Some(false),
            structured_content: None,
        };

        let (_success, output_bytes, preview) = summarize_mcp_tool_output(&result, 512);

        assert_eq!(output_bytes, 10_000);
        assert_eq!(preview.as_ref().map(String::len), Some(512));
    }
}

impl ToolCallRuntime {
    fn aborted_response(call: &ToolCall, secs: f32) -> ResponseInputItem {
        match &call.payload {
            ToolPayload::Custom { .. } => ResponseInputItem::CustomToolCallOutput {
                call_id: call.call_id.clone(),
                output: Self::abort_message(call, secs),
            },
            ToolPayload::Mcp { .. } => ResponseInputItem::McpToolCallOutput {
                call_id: call.call_id.clone(),
                result: Err(Self::abort_message(call, secs)),
            },
            _ => ResponseInputItem::FunctionCallOutput {
                call_id: call.call_id.clone(),
                output: FunctionCallOutputPayload {
                    content: Self::abort_message(call, secs),
                    ..Default::default()
                },
            },
        }
    }

    fn abort_message(call: &ToolCall, secs: f32) -> String {
        match call.tool_name.as_str() {
            "shell" | "container.exec" | "local_shell" | "shell_command" | "unified_exec" => {
                format!("Wall time: {secs:.1} seconds\naborted by user")
            }
            _ => format!("aborted by user after {secs:.1}s"),
        }
    }
}
