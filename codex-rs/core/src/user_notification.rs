use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use async_channel::Sender;
use chrono::DateTime;
use chrono::Utc;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tracing::error;
use tracing::warn;
use uuid::Uuid;

use crate::config::HooksConfig;
use crate::protocol::Event;
use crate::protocol::EventMsg;
use crate::protocol::HookProcessBeginEvent;
use crate::protocol::HookProcessEndEvent;
use crate::protocol::TokenUsage;

const MAX_CONCURRENT_HOOKS: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct UserHooks {
    hooks: HooksConfig,
    codex_home: PathBuf,
    tx_event: Option<Sender<Event>>,
    semaphore: std::sync::Arc<Semaphore>,
}

impl UserHooks {
    pub(crate) fn new(
        codex_home: PathBuf,
        hooks: HooksConfig,
        tx_event: Option<Sender<Event>>,
    ) -> Self {
        Self {
            hooks,
            codex_home,
            tx_event,
            semaphore: std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_HOOKS)),
        }
    }

    pub(crate) fn agent_turn_complete(
        &self,
        thread_id: String,
        turn_id: String,
        cwd: String,
        input_messages: Vec<String>,
        last_assistant_message: Option<String>,
    ) {
        self.invoke_hook_commands(
            &self.hooks.agent_turn_complete,
            HookNotification::AgentTurnComplete {
                thread_id,
                turn_id,
                cwd,
                input_messages,
                last_assistant_message,
            },
        );
    }

    pub(crate) fn approval_requested_exec(
        &self,
        thread_id: String,
        turn_id: String,
        call_id: String,
        cwd: String,
        command: Vec<String>,
        reason: Option<String>,
    ) {
        self.invoke_hook_commands(
            &self.hooks.approval_requested,
            HookNotification::ApprovalRequested {
                thread_id,
                turn_id: Some(turn_id),
                cwd: Some(cwd),
                kind: ApprovalKind::Exec,
                call_id: Some(call_id),
                reason,
                command: Some(command),
                paths: None,
                grant_root: None,
                server_name: None,
                request_id: None,
                message: None,
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn approval_requested_apply_patch(
        &self,
        thread_id: String,
        turn_id: String,
        call_id: String,
        cwd: String,
        paths: Vec<String>,
        reason: Option<String>,
        grant_root: Option<String>,
    ) {
        self.invoke_hook_commands(
            &self.hooks.approval_requested,
            HookNotification::ApprovalRequested {
                thread_id,
                turn_id: Some(turn_id),
                cwd: Some(cwd),
                kind: ApprovalKind::ApplyPatch,
                call_id: Some(call_id),
                reason,
                command: None,
                paths: Some(paths),
                grant_root,
                server_name: None,
                request_id: None,
                message: None,
            },
        );
    }

    pub(crate) fn approval_requested_elicitation(
        &self,
        thread_id: String,
        cwd: String,
        server_name: String,
        request_id: String,
        message: String,
    ) {
        self.invoke_hook_commands(
            &self.hooks.approval_requested,
            HookNotification::ApprovalRequested {
                thread_id,
                turn_id: None,
                cwd: Some(cwd),
                kind: ApprovalKind::Elicitation,
                call_id: None,
                reason: None,
                command: None,
                paths: None,
                grant_root: None,
                server_name: Some(server_name),
                request_id: Some(request_id),
                message: Some(message),
            },
        );
    }

    pub(crate) fn session_start(&self, thread_id: String, cwd: String, session_source: String) {
        self.invoke_hook_commands(
            &self.hooks.session_start,
            HookNotification::SessionStart {
                thread_id,
                cwd,
                session_source,
            },
        );
    }

    pub(crate) fn session_end(&self, thread_id: String, cwd: String, session_source: String) {
        self.invoke_hook_commands_detached(
            &self.hooks.session_end,
            HookNotification::SessionEnd {
                thread_id,
                cwd,
                session_source,
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn model_request_started(
        &self,
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        model: String,
        provider: String,
        input_item_count: usize,
        tool_count: usize,
        parallel_tool_calls: bool,
        has_output_schema: bool,
    ) {
        self.invoke_hook_commands(
            &self.hooks.model_request_started,
            HookNotification::ModelRequestStarted {
                thread_id,
                turn_id,
                cwd,
                model_request_id,
                attempt,
                model,
                provider,
                input_item_count,
                tool_count,
                parallel_tool_calls,
                has_output_schema,
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn model_response_completed(
        &self,
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        response_id: String,
        token_usage: Option<TokenUsage>,
        needs_follow_up: bool,
    ) {
        self.invoke_hook_commands(
            &self.hooks.model_response_completed,
            HookNotification::ModelResponseCompleted {
                thread_id,
                turn_id,
                cwd,
                model_request_id,
                attempt,
                response_id,
                token_usage,
                needs_follow_up,
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn tool_call_started(
        &self,
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        tool_name: String,
        call_id: String,
    ) {
        self.invoke_hook_commands(
            &self.hooks.tool_call_started,
            HookNotification::ToolCallStarted {
                thread_id,
                turn_id,
                cwd,
                model_request_id,
                attempt,
                tool_name,
                call_id,
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn tool_call_finished(
        &self,
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        tool_name: String,
        call_id: String,
        status: ToolCallStatus,
        duration_ms: u64,
        success: bool,
        output_bytes: usize,
        output_preview: Option<String>,
    ) {
        self.invoke_hook_commands(
            &self.hooks.tool_call_finished,
            HookNotification::ToolCallFinished {
                thread_id,
                turn_id,
                cwd,
                model_request_id,
                attempt,
                tool_name,
                call_id,
                status,
                duration_ms,
                success,
                output_bytes,
                output_preview,
            },
        );
    }

    fn invoke_hook_commands(&self, commands: &[Vec<String>], notification: HookNotification) {
        if commands.is_empty() {
            return;
        }

        let payload = HookPayload::new(notification);
        let Ok(payload_json) = serde_json::to_vec(&payload) else {
            error!("failed to serialise hook payload");
            return;
        };

        let commands: Vec<Vec<String>> = commands
            .iter()
            .cloned()
            .filter(|command| !command.is_empty())
            .collect();
        if commands.is_empty() {
            return;
        }

        let ctx = HookCommandContext {
            max_stdin_payload_bytes: self.hooks.max_stdin_payload_bytes,
            keep_last_n_payloads: self.hooks.keep_last_n_payloads,
            codex_home: self.codex_home.clone(),
            tx_event: self.tx_event.clone(),
            semaphore: self.semaphore.clone(),
        };

        tokio::spawn(async move {
            let stdin_payload = prepare_hook_stdin_payload(
                &payload,
                &payload_json,
                ctx.max_stdin_payload_bytes,
                ctx.keep_last_n_payloads,
                &ctx.codex_home,
            );

            for command in commands {
                let ctx = ctx.clone();
                let payload = payload.clone();
                let stdin_payload = stdin_payload.clone();
                tokio::spawn(async move {
                    run_hook_command(command, payload, stdin_payload, ctx).await;
                });
            }
        });
    }

    fn invoke_hook_commands_detached(
        &self,
        commands: &[Vec<String>],
        notification: HookNotification,
    ) {
        if commands.is_empty() {
            return;
        }

        let payload = HookPayload::new(notification);
        let Ok(payload_json) = serde_json::to_vec(&payload) else {
            error!("failed to serialise hook payload");
            return;
        };

        let stdin_payload = prepare_hook_stdin_payload(
            &payload,
            &payload_json,
            self.hooks.max_stdin_payload_bytes,
            self.hooks.keep_last_n_payloads,
            &self.codex_home,
        );

        for command in commands.iter().cloned() {
            if command.is_empty() {
                continue;
            }

            spawn_hook_command_detached(
                command,
                self.hooks.keep_last_n_payloads,
                &self.codex_home,
                &stdin_payload,
            );
        }
    }
}

#[derive(Clone)]
struct HookCommandContext {
    max_stdin_payload_bytes: usize,
    keep_last_n_payloads: usize,
    codex_home: PathBuf,
    tx_event: Option<Sender<Event>>,
    semaphore: std::sync::Arc<Semaphore>,
}

async fn run_hook_command(
    command: Vec<String>,
    payload: HookPayload,
    stdin_payload: Vec<u8>,
    ctx: HookCommandContext,
) {
    let HookCommandContext {
        keep_last_n_payloads,
        codex_home,
        tx_event,
        semaphore,
        ..
    } = ctx;

    let _permit = semaphore.acquire().await;
    let hook_id = Uuid::new_v4();
    let event_type = payload.event_type().to_string();

    let (stdout, stderr) = open_hook_log_files(&codex_home, hook_id, keep_last_n_payloads);

    let child = {
        let mut cmd = tokio::process::Command::new(&command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(stdout);
        cmd.stderr(stderr);
        cmd.spawn()
    };

    let mut child = match child {
        Ok(child) => child,
        Err(e) => {
            #[allow(clippy::indexing_slicing)]
            let program = &command[0];
            warn!("failed to spawn hook '{program}': {e}");
            return;
        }
    };

    if let Some(tx_event) = &tx_event {
        let _ = tx_event
            .send(Event {
                id: "hook_process".to_string(),
                msg: EventMsg::HookProcessBegin(HookProcessBeginEvent {
                    hook_id,
                    payload_event_id: payload.event_id,
                    event_type: event_type.clone(),
                    command: command.clone(),
                }),
            })
            .await;
    }

    if let Some(mut stdin) = child.stdin.take()
        && let Err(e) = stdin.write_all(&stdin_payload).await
    {
        warn!("failed to write hook payload to stdin: {e}");
    }

    let exit_code = match child.wait().await {
        Ok(status) => status.code(),
        Err(e) => {
            warn!("failed waiting for hook process to exit: {e}");
            None
        }
    };
    if let Some(code) = exit_code
        && code != 0
    {
        warn!("hook exited with non-zero status {code}: {event_type}");
    }

    if let Some(tx_event) = &tx_event {
        let _ = tx_event
            .send(Event {
                id: "hook_process".to_string(),
                msg: EventMsg::HookProcessEnd(HookProcessEndEvent { hook_id, exit_code }),
            })
            .await;
    }
}

fn spawn_hook_command_detached(
    command: Vec<String>,
    keep_last_n_payloads: usize,
    codex_home: &Path,
    stdin_payload: &[u8],
) {
    let (stdout, stderr) = open_hook_log_files(codex_home, Uuid::new_v4(), keep_last_n_payloads);

    let child = {
        let mut cmd = std::process::Command::new(&command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(stdout);
        cmd.stderr(stderr);
        cmd.spawn()
    };

    let mut child = match child {
        Ok(child) => child,
        Err(e) => {
            #[allow(clippy::indexing_slicing)]
            let program = &command[0];
            warn!("failed to spawn hook '{program}': {e}");
            return;
        }
    };

    if let Some(mut stdin) = child.stdin.take()
        && let Err(e) = stdin.write_all(stdin_payload)
    {
        warn!("failed to write hook payload to stdin: {e}");
    }
}

fn open_hook_log_files(codex_home: &Path, hook_id: Uuid, keep_last_n: usize) -> (Stdio, Stdio) {
    let logs_dir = codex_home.join("tmp").join("hooks").join("logs");
    if let Err(e) = ensure_dir(&logs_dir) {
        warn!("failed to create hooks log dir: {e}");
        return (Stdio::null(), Stdio::null());
    }

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let log_path = logs_dir.join(format!("{timestamp_ms}-{hook_id}.log"));
    let file = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
    {
        Ok(file) => file,
        Err(e) => {
            warn!("failed to open hook log file: {e}");
            return (Stdio::null(), Stdio::null());
        }
    };

    if let Err(e) = set_file_permissions(&log_path, &file) {
        warn!("failed to set hook log file permissions: {e}");
    }

    if let Err(e) = prune_old_files(&logs_dir, keep_last_n) {
        warn!("failed to prune hook log files: {e}");
    }

    let stderr = match file.try_clone() {
        Ok(clone) => clone,
        Err(e) => {
            warn!("failed to clone hook log file handle: {e}");
            return (Stdio::from(file), Stdio::null());
        }
    };

    (Stdio::from(file), Stdio::from(stderr))
}

fn prepare_hook_stdin_payload(
    payload: &HookPayload,
    payload_json: &[u8],
    max_stdin_payload_bytes: usize,
    keep_last_n_payloads: usize,
    codex_home: &Path,
) -> Vec<u8> {
    if payload_json.len() <= max_stdin_payload_bytes {
        return payload_json.to_vec();
    }

    let payload_path =
        match write_payload_file(codex_home, payload, payload_json, keep_last_n_payloads) {
            Ok(path) => path,
            Err(e) => {
                warn!("failed to write hook payload file: {e}");
                return payload_json.to_vec();
            }
        };

    let envelope = HookStdinEnvelope::from_payload(payload, payload_path);
    match serde_json::to_vec(&envelope) {
        Ok(envelope_json) => envelope_json,
        Err(e) => {
            warn!("failed to serialise hook stdin envelope: {e}");
            payload_json.to_vec()
        }
    }
}

fn write_payload_file(
    codex_home: &Path,
    payload: &HookPayload,
    payload_json: &[u8],
    keep_last_n: usize,
) -> anyhow::Result<PathBuf> {
    let payload_dir = codex_home.join("tmp").join("hooks").join("payloads");
    ensure_dir(&payload_dir)?;

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let event_id = payload.event_id;
    let filename = format!("{timestamp_ms}-{event_id}.json");
    let payload_path = payload_dir.join(filename);

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&payload_path)?;
    file.write_all(payload_json)?;

    set_file_permissions(&payload_path, &file)?;
    prune_old_files(&payload_dir, keep_last_n)?;

    Ok(payload_path)
}

fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    set_dir_permissions(path)?;
    Ok(())
}

fn prune_old_files(dir: &Path, keep_last_n: usize) -> anyhow::Result<()> {
    if keep_last_n == 0 {
        return Ok(());
    }

    let mut entries = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .collect::<Vec<_>>();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    if entries.len() <= keep_last_n {
        return Ok(());
    }

    let to_delete = entries.len().saturating_sub(keep_last_n);
    for entry in entries.into_iter().take(to_delete) {
        let _ = std::fs::remove_file(entry.path());
    }

    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn set_file_permissions(path: &Path, _file: &File) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct HookPayload {
    schema_version: u32,
    event_id: Uuid,
    timestamp: DateTime<Utc>,
    #[serde(flatten)]
    notification: HookNotification,
}

impl HookPayload {
    fn new(notification: HookNotification) -> Self {
        Self {
            schema_version: 1,
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            notification,
        }
    }

    fn event_type(&self) -> &'static str {
        self.notification.event_type()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct HookStdinEnvelope {
    schema_version: u32,
    event_id: Uuid,
    timestamp: DateTime<Utc>,
    #[serde(rename = "type")]
    event_type: &'static str,
    payload_path: String,
}

impl HookStdinEnvelope {
    fn from_payload(payload: &HookPayload, payload_path: PathBuf) -> Self {
        Self {
            schema_version: payload.schema_version,
            event_id: payload.event_id,
            timestamp: payload.timestamp,
            event_type: payload.event_type(),
            payload_path: payload_path.display().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ApprovalKind {
    Exec,
    ApplyPatch,
    Elicitation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ToolCallStatus {
    Completed,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum HookNotification {
    #[serde(rename_all = "kebab-case")]
    AgentTurnComplete {
        thread_id: String,
        turn_id: String,
        cwd: String,

        input_messages: Vec<String>,
        last_assistant_message: Option<String>,
    },

    #[serde(rename_all = "kebab-case")]
    ApprovalRequested {
        thread_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,

        kind: ApprovalKind,

        #[serde(skip_serializing_if = "Option::is_none")]
        call_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        command: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        paths: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        grant_root: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        server_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    #[serde(rename_all = "kebab-case")]
    SessionStart {
        thread_id: String,
        cwd: String,
        session_source: String,
    },

    #[serde(rename_all = "kebab-case")]
    SessionEnd {
        thread_id: String,
        cwd: String,
        session_source: String,
    },

    #[serde(rename_all = "kebab-case")]
    ModelRequestStarted {
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        model: String,
        provider: String,
        #[serde(rename = "prompt-input-item-count")]
        input_item_count: usize,
        tool_count: usize,
        parallel_tool_calls: bool,
        has_output_schema: bool,
    },

    #[serde(rename_all = "kebab-case")]
    ModelResponseCompleted {
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        response_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        token_usage: Option<TokenUsage>,
        needs_follow_up: bool,
    },

    #[serde(rename_all = "kebab-case")]
    ToolCallStarted {
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        tool_name: String,
        call_id: String,
    },

    #[serde(rename_all = "kebab-case")]
    ToolCallFinished {
        thread_id: String,
        turn_id: String,
        cwd: String,
        model_request_id: Uuid,
        attempt: u32,
        tool_name: String,
        call_id: String,
        status: ToolCallStatus,
        duration_ms: u64,
        success: bool,
        output_bytes: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        output_preview: Option<String>,
    },
}

impl HookNotification {
    fn event_type(&self) -> &'static str {
        match self {
            Self::AgentTurnComplete { .. } => "agent-turn-complete",
            Self::ApprovalRequested { .. } => "approval-requested",
            Self::SessionStart { .. } => "session-start",
            Self::SessionEnd { .. } => "session-end",
            Self::ModelRequestStarted { .. } => "model-request-started",
            Self::ModelResponseCompleted { .. } => "model-response-completed",
            Self::ToolCallStarted { .. } => "tool-call-started",
            Self::ToolCallFinished { .. } => "tool-call-finished",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_hook_payload_includes_version_and_ids() -> Result<()> {
        let payload = HookPayload::new(HookNotification::ApprovalRequested {
            thread_id: "thread-1".to_string(),
            turn_id: None,
            cwd: Some("/tmp".to_string()),
            kind: ApprovalKind::Exec,
            call_id: Some("call-1".to_string()),
            reason: None,
            command: Some(vec!["echo".to_string(), "hi".to_string()]),
            paths: None,
            grant_root: None,
            server_name: None,
            request_id: None,
            message: None,
        });
        let serialized = serde_json::to_string(&payload)?;
        assert!(
            serialized.contains(r#""schema-version":1"#),
            "payload must include schema-version: {serialized}"
        );
        assert!(
            serialized.contains(r#""event-id":"#),
            "payload must include event-id: {serialized}"
        );
        assert!(
            serialized.contains(r#""timestamp":"#),
            "payload must include timestamp: {serialized}"
        );
        Ok(())
    }

    #[test]
    fn test_hook_stdin_envelope_has_payload_path() -> Result<()> {
        let payload = HookPayload::new(HookNotification::AgentTurnComplete {
            thread_id: "t".to_string(),
            turn_id: "turn".to_string(),
            cwd: "/tmp".to_string(),
            input_messages: Vec::new(),
            last_assistant_message: None,
        });
        let envelope =
            HookStdinEnvelope::from_payload(&payload, PathBuf::from("/tmp/payload.json"));
        let serialized = serde_json::to_string(&envelope)?;
        assert!(
            serialized.contains(r#""payload-path":"/tmp/payload.json""#),
            "envelope must include payload-path: {serialized}"
        );
        Ok(())
    }
}
