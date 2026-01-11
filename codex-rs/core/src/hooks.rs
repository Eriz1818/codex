//! Hook dispatch and payload types.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use async_channel::Sender;
use chrono::DateTime;
use chrono::Utc;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tracing::error;
use tracing::warn;
use uuid::Uuid;

#[cfg(feature = "pyo3-hooks")]
use pyo3::IntoPy;
#[cfg(feature = "pyo3-hooks")]
use pyo3::types::PyAnyMethods;
#[cfg(feature = "pyo3-hooks")]
use pyo3::types::PyDict;
#[cfg(feature = "pyo3-hooks")]
use pyo3::types::PyDictMethods;
#[cfg(feature = "pyo3-hooks")]
use pyo3::types::PyList;
#[cfg(feature = "pyo3-hooks")]
use pyo3::types::PyListMethods;
#[cfg(feature = "pyo3-hooks")]
use serde_json::Value as JsonValue;
#[cfg(feature = "pyo3-hooks")]
use std::num::NonZeroUsize;

use crate::config::HooksConfig;
use crate::protocol::AskForApproval;
use crate::protocol::Event;
use crate::protocol::EventMsg;
use crate::protocol::ExecPolicyAmendment;
use crate::protocol::HookProcessBeginEvent;
use crate::protocol::HookProcessEndEvent;
use crate::protocol::SandboxPolicy;
use crate::protocol::TokenUsage;
use crate::protocol_config_types::SandboxMode;

mod claude_compat;

const MAX_CONCURRENT_HOOKS: usize = 8;
const TOOL_CALL_SUMMARY_LOG_FILENAME: &str = "hooks-tool-calls.log";
const HOOK_EVENT_LOG_JSONL_FILENAME: &str = "hooks.jsonl";
const INPROC_TOOL_CALL_SUMMARY_HOOK_NAME: &str = "tool_call_summary";
const INPROC_EVENT_LOG_JSONL_HOOK_NAME: &str = "event_log_jsonl";
const INPROC_PYO3_HOOK_NAME: &str = "pyo3";
const INPROC_HOOK_QUEUE_CAPACITY: usize = 256;
const INPROC_HOOK_TIMEOUT: Duration = Duration::from_secs(1);
const INPROC_HOOK_FAILURE_THRESHOLD: u32 = 3;
const INPROC_HOOK_CIRCUIT_BREAKER_OPEN_DURATION: Duration = Duration::from_secs(30);
const HOOK_HOST_QUEUE_CAPACITY: usize = 1024;
const HOOK_HOST_FAILURE_THRESHOLD: u32 = 3;
const HOOK_HOST_CIRCUIT_BREAKER_OPEN_DURATION: Duration = Duration::from_secs(30);

pub type HookResult = anyhow::Result<()>;

#[derive(Debug, Clone)]
pub struct HookContext {
    codex_home: PathBuf,
}

impl HookContext {
    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }
}

trait HookHandler: Send + Sync {
    fn on_event(&self, ctx: &HookContext, event: &HookEvent) -> HookResult;
}

trait HookProvider: Send + Sync {
    fn on_event(&self, event: &HookEvent);

    fn on_event_detached(&self, event: &HookEvent) {
        self.on_event(event);
    }
}

#[derive(Clone)]
struct HookBus {
    providers: Vec<std::sync::Arc<dyn HookProvider>>,
}

impl HookBus {
    fn emit(&self, notification: HookNotification) {
        if self.providers.is_empty() {
            return;
        }

        let event = HookEvent::new(notification);
        for provider in &self.providers {
            provider.on_event(&event);
        }
    }

    fn emit_detached(&self, notification: HookNotification) {
        if self.providers.is_empty() {
            return;
        }

        let event = HookEvent::new(notification);
        for provider in &self.providers {
            provider.on_event_detached(&event);
        }
    }
}

#[derive(Clone)]
pub(crate) struct UserHooks {
    bus: HookBus,
}

#[derive(Clone)]
struct InprocHookPolicy {
    queue_capacity: usize,
    timeout: Duration,
    failure_threshold: u32,
    circuit_breaker_open_duration: Duration,
}

impl Default for InprocHookPolicy {
    fn default() -> Self {
        Self {
            queue_capacity: INPROC_HOOK_QUEUE_CAPACITY,
            timeout: INPROC_HOOK_TIMEOUT,
            failure_threshold: INPROC_HOOK_FAILURE_THRESHOLD,
            circuit_breaker_open_duration: INPROC_HOOK_CIRCUIT_BREAKER_OPEN_DURATION,
        }
    }
}

#[derive(Clone)]
struct InprocHookEntry {
    name: String,
    hook: std::sync::Arc<dyn HookHandler>,
    timeout: Option<Duration>,
}

#[derive(Clone)]
struct InprocHookWorker {
    name: String,
    tx_payload: mpsc::Sender<std::sync::Arc<HookEvent>>,
}

#[derive(Clone, Default)]
struct InprocHookCircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl InprocHookCircuitBreaker {
    fn is_open(&self) -> bool {
        self.open_until
            .is_some_and(|open_until| Instant::now() < open_until)
    }

    fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    fn on_failure(&mut self, policy: &InprocHookPolicy) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= policy.failure_threshold {
            self.open_until = Some(Instant::now() + policy.circuit_breaker_open_duration);
        }
    }

    fn on_timeout(&mut self, policy: &InprocHookPolicy) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.open_until = Some(Instant::now() + policy.circuit_breaker_open_duration);
    }
}

struct InprocHooksProvider {
    hooks: Vec<InprocHookWorker>,
}

impl InprocHooksProvider {
    fn new(codex_home: PathBuf, hooks: Vec<InprocHookEntry>) -> Self {
        Self::new_with_policy(codex_home, hooks, InprocHookPolicy::default())
    }

    fn new_with_policy(
        codex_home: PathBuf,
        hooks: Vec<InprocHookEntry>,
        policy: InprocHookPolicy,
    ) -> Self {
        let ctx = HookContext { codex_home };
        let mut workers = Vec::with_capacity(hooks.len());

        for hook in hooks {
            let (tx_payload, mut rx_payload) = mpsc::channel(policy.queue_capacity);
            let entry_name = hook.name.clone();
            let handler = std::sync::Arc::clone(&hook.hook);
            let ctx = ctx.clone();
            let policy = policy.clone();
            let timeout = hook.timeout.unwrap_or(policy.timeout);

            tokio::spawn(async move {
                let mut breaker = InprocHookCircuitBreaker::default();
                while let Some(event) = rx_payload.recv().await {
                    if breaker.is_open() {
                        warn!("skipping in-process hook due to open circuit breaker: {entry_name}");
                        continue;
                    }

                    let event = std::sync::Arc::clone(&event);
                    let ctx = ctx.clone();
                    let entry_name = entry_name.clone();
                    let handler = std::sync::Arc::clone(&handler);
                    let started_at = Instant::now();

                    let handle = tokio::task::spawn_blocking(move || {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            handler.on_event(&ctx, &event)
                        }))
                    });

                    match tokio::time::timeout(timeout, handle).await {
                        Ok(Ok(Ok(Ok(())))) => {
                            breaker.on_success();
                        }
                        Ok(Ok(Ok(Err(err)))) => {
                            error!("in-process hook failed: {entry_name}: {err}");
                            breaker.on_failure(&policy);
                        }
                        Ok(Ok(Err(_panic))) => {
                            error!("in-process hook panicked: {entry_name}");
                            breaker.on_failure(&policy);
                        }
                        Ok(Err(join_err)) => {
                            error!("in-process hook join error: {entry_name}: {join_err}");
                            breaker.on_failure(&policy);
                        }
                        Err(_timeout) => {
                            let timeout_ms = timeout.as_millis();
                            error!("in-process hook timed out after {timeout_ms}ms: {entry_name}");
                            breaker.on_timeout(&policy);
                        }
                    }

                    let elapsed = started_at.elapsed();
                    if elapsed > timeout {
                        let timeout_ms = timeout.as_millis();
                        let elapsed_ms = elapsed.as_millis();
                        warn!(
                            "in-process hook exceeded timeout budget ({timeout_ms}ms): {entry_name} ({elapsed_ms}ms)"
                        );
                    }
                }
            });

            workers.push(InprocHookWorker {
                name: hook.name,
                tx_payload,
            });
        }

        Self { hooks: workers }
    }
}

impl HookProvider for InprocHooksProvider {
    fn on_event(&self, event: &HookEvent) {
        let event = std::sync::Arc::new(event.clone());
        for hook in &self.hooks {
            if hook
                .tx_payload
                .try_send(std::sync::Arc::clone(&event))
                .is_err()
            {
                warn!(
                    "dropping in-process hook event due to full queue: {}",
                    hook.name
                );
            }
        }
    }
}

struct ToolCallSummaryHook;

impl HookHandler for ToolCallSummaryHook {
    fn on_event(&self, ctx: &HookContext, event: &HookEvent) -> HookResult {
        let HookNotification::ToolCallFinished {
            tool_name,
            status,
            success,
            duration_ms,
            output_bytes,
            cwd,
            ..
        } = &event.notification
        else {
            return Ok(());
        };

        let out_path = ctx.codex_home.join(TOOL_CALL_SUMMARY_LOG_FILENAME);
        let line = format!(
            "type=tool-call-finished tool={tool_name} status={} success={success} duration_ms={duration_ms} output_bytes={output_bytes} cwd={cwd}\n",
            tool_call_status_string(*status)
        );
        append_tool_call_summary_line(&out_path, &line)?;
        Ok(())
    }
}

struct EventLogJsonlHook;

impl HookHandler for EventLogJsonlHook {
    fn on_event(&self, ctx: &HookContext, event: &HookEvent) -> HookResult {
        let out_path = ctx.codex_home.join(HOOK_EVENT_LOG_JSONL_FILENAME);
        append_hook_payload_jsonl_line(&out_path, event)?;
        Ok(())
    }
}

#[cfg(feature = "pyo3-hooks")]
struct Pyo3Hook {
    script_path: String,
    callable: String,
    batch_size: Option<NonZeroUsize>,
    state: std::sync::Mutex<Option<Pyo3HookState>>,
}

#[cfg(feature = "pyo3-hooks")]
struct Pyo3HookState {
    on_event: pyo3::Py<pyo3::PyAny>,
    on_events: Option<pyo3::Py<pyo3::PyAny>>,
    pending: Vec<JsonValue>,
}

#[cfg(feature = "pyo3-hooks")]
impl Pyo3Hook {
    fn new(script_path: String, callable: String, batch_size: Option<NonZeroUsize>) -> Self {
        Self {
            script_path,
            callable,
            batch_size,
            state: std::sync::Mutex::new(None),
        }
    }

    fn script_path(&self, ctx: &HookContext) -> PathBuf {
        let path = PathBuf::from(&self.script_path);
        if path.is_absolute() {
            return path;
        }
        ctx.codex_home().join(path)
    }

    fn should_flush_batch(event: &HookEvent) -> bool {
        matches!(
            event.notification(),
            HookNotification::AgentTurnComplete { .. } | HookNotification::SessionEnd { .. }
        )
    }

    fn json_value_to_py(
        py: pyo3::Python<'_>,
        value: &JsonValue,
    ) -> pyo3::PyResult<pyo3::Py<pyo3::PyAny>> {
        match value {
            JsonValue::Null => Ok(().into_py(py)),
            JsonValue::Bool(value) => Ok((*value).into_py(py)),
            JsonValue::Number(value) => {
                if let Some(value) = value.as_i64() {
                    Ok(value.into_py(py))
                } else if let Some(value) = value.as_u64() {
                    Ok(value.into_py(py))
                } else if let Some(value) = value.as_f64() {
                    Ok(value.into_py(py))
                } else {
                    Err(pyo3::exceptions::PyValueError::new_err(
                        "unsupported JSON number",
                    ))
                }
            }
            JsonValue::String(value) => Ok(value.as_str().into_py(py)),
            JsonValue::Array(values) => {
                let list = PyList::empty_bound(py);
                for value in values {
                    list.append(Self::json_value_to_py(py, value)?)?;
                }
                Ok(list.into_py(py))
            }
            JsonValue::Object(values) => {
                let dict = PyDict::new_bound(py);
                for (key, value) in values {
                    dict.set_item(key.as_str(), Self::json_value_to_py(py, value)?)?;
                }
                Ok(dict.into_py(py))
            }
        }
    }
}

#[cfg(feature = "pyo3-hooks")]
impl HookHandler for Pyo3Hook {
    fn on_event(&self, ctx: &HookContext, event: &HookEvent) -> HookResult {
        static PY_INIT: std::sync::Once = std::sync::Once::new();
        PY_INIT.call_once(pyo3::prepare_freethreaded_python);

        let hook_event_name = default_hook_event_name(event);
        let payload = HookPayload::from_event(event, &hook_event_name);
        let payload_json = serde_json::to_value(&payload)?;
        let script_path = self.script_path(ctx);
        let flush_batch = Self::should_flush_batch(event);

        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("pyo3 hook mutex is poisoned"))?;

        if guard.is_none() {
            pyo3::Python::with_gil(|py| -> HookResult {
                let sys = py.import_bound("sys")?;
                let sys_path = sys.getattr("path")?;

                fn append_sys_path(
                    sys_path: &pyo3::Bound<'_, pyo3::PyAny>,
                    path: &std::path::Path,
                ) -> pyo3::PyResult<()> {
                    let path = path.to_string_lossy();
                    if path.is_empty() {
                        return Ok(());
                    }

                    let contains = sys_path.call_method1("__contains__", (path.as_ref(),))?;
                    if contains.extract::<bool>()? {
                        return Ok(());
                    }

                    sys_path.call_method1("append", (path.as_ref(),))?;
                    Ok(())
                }

                let hooks_dir = ctx.codex_home().join("hooks");
                if let Some(script_dir) = script_path.parent() {
                    append_sys_path(&sys_path, script_dir)?;
                }
                append_sys_path(&sys_path, &hooks_dir)?;

                let code = std::fs::read_to_string(&script_path)?;
                let filename = script_path.to_string_lossy();
                let module = pyo3::types::PyModule::from_code_bound(
                    py,
                    &code,
                    filename.as_ref(),
                    "xcodex_user_hook",
                )?;

                let on_event = module.getattr(self.callable.as_str())?;
                if !on_event.is_callable() {
                    anyhow::bail!(
                        "pyo3 hook callable is not callable: {} in {}",
                        self.callable,
                        script_path.display()
                    );
                }

                let on_events = module.getattr("on_events").ok().and_then(|candidate| {
                    if candidate.is_callable() {
                        Some(candidate.into_py(py))
                    } else {
                        None
                    }
                });

                if self.batch_size.is_some() && on_events.is_none() {
                    warn!(
                        "hooks.pyo3.batch_size is set, but the hook script does not define on_events; falling back to per-event calls"
                    );
                }

                guard.replace(Pyo3HookState {
                    on_event: on_event.into_py(py),
                    on_events,
                    pending: Vec::new(),
                });
                Ok(())
            })?;
        }

        #[expect(clippy::expect_used)]
        let state = guard.as_mut().expect("initialized above");

        if let (Some(batch_size), Some(on_events)) = (self.batch_size, state.on_events.as_ref()) {
            state.pending.push(payload_json);
            if state.pending.len() < batch_size.get() && !flush_batch {
                return Ok(());
            }

            let pending = std::mem::take(&mut state.pending);
            pyo3::Python::with_gil(|py| -> HookResult {
                let events = PyList::empty_bound(py);
                for payload in &pending {
                    events.append(Self::json_value_to_py(py, payload)?)?;
                }
                on_events.call1(py, (events,))?;
                Ok(())
            })?;
            return Ok(());
        }

        pyo3::Python::with_gil(|py| -> HookResult {
            let event_obj = Self::json_value_to_py(py, &payload_json)?;
            state.on_event.call1(py, (event_obj,))?;
            Ok(())
        })
    }
}

struct ExternalCommandHooksProvider {
    hooks: HooksConfig,
    command_hooks: CompiledCommandHooksConfig,
    codex_home: PathBuf,
    tx_event: Option<Sender<Event>>,
    semaphore: std::sync::Arc<Semaphore>,
}

impl ExternalCommandHooksProvider {
    fn new(codex_home: PathBuf, hooks: HooksConfig, tx_event: Option<Sender<Event>>) -> Self {
        let command_hooks = CompiledCommandHooksConfig::compile(&hooks.command);
        Self {
            hooks,
            command_hooks,
            codex_home,
            tx_event,
            semaphore: std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_HOOKS)),
        }
    }

    fn commands_for_event(&self, event: &HookEvent) -> &[Vec<String>] {
        match event.notification() {
            HookNotification::AgentTurnComplete { .. } => &self.hooks.agent_turn_complete,
            HookNotification::ApprovalRequested { .. } => &self.hooks.approval_requested,
            HookNotification::SessionStart { .. } => &self.hooks.session_start,
            HookNotification::SessionEnd { .. } => &self.hooks.session_end,
            HookNotification::UserPromptSubmit { .. } => &self.hooks.user_prompt_submit,
            HookNotification::PreCompact { .. } => &self.hooks.pre_compact,
            HookNotification::Notification { .. } => &self.hooks.notification,
            HookNotification::SubagentStop { .. } => &self.hooks.subagent_stop,
            HookNotification::ModelRequestStarted { .. } => &self.hooks.model_request_started,
            HookNotification::ModelResponseCompleted { .. } => &self.hooks.model_response_completed,
            HookNotification::ToolCallStarted { .. } => &self.hooks.tool_call_started,
            HookNotification::ToolCallFinished { .. } => &self.hooks.tool_call_finished,
        }
    }

    fn command_hooks_for_event(&self, event: &HookEvent) -> Vec<CommandHookSpec> {
        let key = HookEventKey::from_notification(event.notification());
        let Some(entries) = self.command_hooks.by_event.get(&key) else {
            return Vec::new();
        };

        let candidates = build_match_candidates(event.notification());
        let mut hooks = Vec::new();
        for entry in entries {
            if candidates.matches(&entry.matcher) {
                hooks.extend(entry.hooks.iter().cloned());
            }
        }

        hooks
    }

    fn invoke_hook_commands(&self, commands: &[Vec<String>], event: HookEvent) {
        if commands.is_empty() {
            return;
        }

        let hook_event_name = default_hook_event_name(&event);
        let payload = HookPayload::from_event(&event, &hook_event_name);
        let Ok(payload_json) = serde_json::to_vec(&payload) else {
            error!("failed to serialise hook payload to JSON");
            return;
        };

        let commands: Vec<Vec<String>> = commands
            .iter()
            .filter(|&command| !command.is_empty())
            .cloned()
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

    fn invoke_hook_commands_detached(&self, commands: &[Vec<String>], event: HookEvent) {
        if commands.is_empty() {
            return;
        }

        let hook_event_name = default_hook_event_name(&event);
        let payload = HookPayload::from_event(&event, &hook_event_name);
        let Ok(payload_json) = serde_json::to_vec(&payload) else {
            error!("failed to serialise hook payload to JSON");
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

    fn invoke_command_hooks(&self, hooks: Vec<CommandHookSpec>, event: HookEvent) {
        if hooks.is_empty() {
            return;
        }

        let hooks: Vec<CommandHookSpec> = hooks
            .into_iter()
            .filter(|hook| !hook.argv.is_empty())
            .collect();
        if hooks.is_empty() {
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
            for hook in hooks {
                let ctx = ctx.clone();
                let payload = HookPayload::from_event(&event, hook.hook_event_name.as_str());
                let stdin_payload = serde_json::to_vec(&payload)
                    .ok()
                    .map(|payload_json| {
                        prepare_hook_stdin_payload(
                            &payload,
                            &payload_json,
                            ctx.max_stdin_payload_bytes,
                            ctx.keep_last_n_payloads,
                            &ctx.codex_home,
                        )
                    })
                    .unwrap_or_default();
                tokio::spawn(async move {
                    run_hook_command_with_timeout(
                        hook.argv,
                        payload,
                        stdin_payload,
                        ctx,
                        hook.timeout,
                    )
                    .await;
                });
            }
        });
    }

    fn invoke_command_hooks_detached(&self, hooks: Vec<CommandHookSpec>, event: HookEvent) {
        if hooks.is_empty() {
            return;
        }

        let hooks: Vec<CommandHookSpec> = hooks
            .into_iter()
            .filter(|hook| !hook.argv.is_empty())
            .collect();
        if hooks.is_empty() {
            return;
        }

        tokio::spawn({
            let codex_home = self.codex_home.clone();
            let max_stdin_payload_bytes = self.hooks.max_stdin_payload_bytes;
            let keep_last_n_payloads = self.hooks.keep_last_n_payloads;
            async move {
                for hook in hooks {
                    let payload = HookPayload::from_event(&event, hook.hook_event_name.as_str());
                    let stdin_payload = serde_json::to_vec(&payload)
                        .ok()
                        .map(|payload_json| {
                            prepare_hook_stdin_payload(
                                &payload,
                                &payload_json,
                                max_stdin_payload_bytes,
                                keep_last_n_payloads,
                                &codex_home,
                            )
                        })
                        .unwrap_or_default();

                    spawn_hook_command_detached(
                        hook.argv,
                        keep_last_n_payloads,
                        &codex_home,
                        &stdin_payload,
                    );
                }
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HookEventKey {
    AgentTurnComplete,
    ApprovalRequested,
    SessionStart,
    SessionEnd,
    UserPromptSubmit,
    PreCompact,
    Notification,
    SubagentStop,
    ModelRequestStarted,
    ModelResponseCompleted,
    ToolCallStarted,
    ToolCallFinished,
}

impl HookEventKey {
    fn from_notification(notification: &HookNotification) -> Self {
        match notification {
            HookNotification::AgentTurnComplete { .. } => Self::AgentTurnComplete,
            HookNotification::ApprovalRequested { .. } => Self::ApprovalRequested,
            HookNotification::SessionStart { .. } => Self::SessionStart,
            HookNotification::SessionEnd { .. } => Self::SessionEnd,
            HookNotification::UserPromptSubmit { .. } => Self::UserPromptSubmit,
            HookNotification::PreCompact { .. } => Self::PreCompact,
            HookNotification::Notification { .. } => Self::Notification,
            HookNotification::SubagentStop { .. } => Self::SubagentStop,
            HookNotification::ModelRequestStarted { .. } => Self::ModelRequestStarted,
            HookNotification::ModelResponseCompleted { .. } => Self::ModelResponseCompleted,
            HookNotification::ToolCallStarted { .. } => Self::ToolCallStarted,
            HookNotification::ToolCallFinished { .. } => Self::ToolCallFinished,
        }
    }

    fn is_tool_scoped(self) -> bool {
        matches!(
            self,
            Self::ApprovalRequested | Self::ToolCallStarted | Self::ToolCallFinished
        )
    }
}

fn canonical_event_key(name: &str) -> Option<HookEventKey> {
    match name.trim() {
        // Canonical TOML keys (snake_case)
        "agent_turn_complete" => Some(HookEventKey::AgentTurnComplete),
        "approval_requested" => Some(HookEventKey::ApprovalRequested),
        "session_start" => Some(HookEventKey::SessionStart),
        "session_end" => Some(HookEventKey::SessionEnd),
        "user_prompt_submit" => Some(HookEventKey::UserPromptSubmit),
        "pre_compact" => Some(HookEventKey::PreCompact),
        "notification" => Some(HookEventKey::Notification),
        "subagent_stop" => Some(HookEventKey::SubagentStop),
        "model_request_started" => Some(HookEventKey::ModelRequestStarted),
        "model_response_completed" => Some(HookEventKey::ModelResponseCompleted),
        "tool_call_started" => Some(HookEventKey::ToolCallStarted),
        "tool_call_finished" => Some(HookEventKey::ToolCallFinished),

        // Canonical event type strings (kebab-case)
        "agent-turn-complete" => Some(HookEventKey::AgentTurnComplete),
        "approval-requested" => Some(HookEventKey::ApprovalRequested),
        "session-start" => Some(HookEventKey::SessionStart),
        "session-end" => Some(HookEventKey::SessionEnd),
        "user-prompt-submit" => Some(HookEventKey::UserPromptSubmit),
        "pre-compact" => Some(HookEventKey::PreCompact),
        "model-request-started" => Some(HookEventKey::ModelRequestStarted),
        "model-response-completed" => Some(HookEventKey::ModelResponseCompleted),
        "tool-call-started" => Some(HookEventKey::ToolCallStarted),
        "tool-call-finished" => Some(HookEventKey::ToolCallFinished),

        // Claude aliases
        "SessionStart" => Some(HookEventKey::SessionStart),
        "SessionEnd" => Some(HookEventKey::SessionEnd),
        "UserPromptSubmit" => Some(HookEventKey::UserPromptSubmit),
        "PreCompact" => Some(HookEventKey::PreCompact),
        "Notification" => Some(HookEventKey::Notification),
        "Stop" => Some(HookEventKey::AgentTurnComplete),
        "SubagentStop" => Some(HookEventKey::SubagentStop),
        "PermissionRequest" => Some(HookEventKey::ApprovalRequested),
        "PreToolUse" => Some(HookEventKey::ToolCallStarted),
        "PostToolUse" => Some(HookEventKey::ToolCallFinished),

        // OpenCode aliases (quoted keys in TOML). Only keep 1:1 aliases for xcodex-emitted events.
        "session.start" => Some(HookEventKey::SessionStart),
        "session.end" => Some(HookEventKey::SessionEnd),
        "tool.execute.before" => Some(HookEventKey::ToolCallStarted),
        "tool.execute.after" => Some(HookEventKey::ToolCallFinished),

        _ => None,
    }
}

#[derive(Clone, Debug)]
enum CommandMatcher {
    Any,
    Exact(String),
    Regex(Regex),
}

impl CommandMatcher {
    fn matches(&self, text: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => expected == text,
            Self::Regex(re) => re.is_match(text),
        }
    }
}

fn compile_matcher(matcher: Option<&str>) -> Option<CommandMatcher> {
    let matcher = matcher.unwrap_or_default();
    if matcher.is_empty() || matcher == "*" {
        return Some(CommandMatcher::Any);
    }

    let is_regex = matcher.chars().any(|c| {
        matches!(
            c,
            '.' | '|' | '(' | ')' | '[' | ']' | '+' | '?' | '^' | '$' | '{' | '}' | '\\'
        )
    });

    if is_regex {
        Regex::new(matcher).ok().map(CommandMatcher::Regex)
    } else {
        Some(CommandMatcher::Exact(matcher.to_string()))
    }
}

#[derive(Clone, Debug)]
struct CommandHookSpec {
    argv: Vec<String>,
    timeout: Duration,
    hook_event_name: String,
}

#[derive(Clone, Debug)]
struct CommandMatcherEntry {
    matcher: CommandMatcher,
    hooks: Vec<CommandHookSpec>,
}

#[derive(Clone, Debug)]
struct CompiledCommandHooksConfig {
    by_event: HashMap<HookEventKey, Vec<CommandMatcherEntry>>,
}

impl CompiledCommandHooksConfig {
    fn compile(cfg: &crate::config::HooksCommandConfig) -> Self {
        let default_timeout = Duration::from_secs(cfg.default_timeout_sec);
        let mut by_event: HashMap<HookEventKey, Vec<CommandMatcherEntry>> = HashMap::new();

        for (event_name, entries) in &cfg.events {
            let Some(event) = canonical_event_key(event_name) else {
                warn!("unknown command hook event: {event_name}");
                continue;
            };

            let mut compiled_entries = Vec::new();
            for entry in entries {
                let Some(mut matcher) = compile_matcher(entry.matcher.as_deref()) else {
                    let Some(matcher) = entry.matcher.as_deref() else {
                        continue;
                    };
                    warn!("invalid matcher regex for event {event_name}: {matcher}");
                    continue;
                };

                if !event.is_tool_scoped() && !matches!(matcher, CommandMatcher::Any) {
                    warn!("matcher is ignored for non-tool event {event_name}");
                    matcher = CommandMatcher::Any;
                }

                let hooks = compile_command_hook_specs(event_name, &entry.hooks, default_timeout);
                if hooks.is_empty() {
                    continue;
                }

                compiled_entries.push(CommandMatcherEntry { matcher, hooks });
            }

            if compiled_entries.is_empty() {
                continue;
            }

            by_event.insert(event, compiled_entries);
        }

        Self { by_event }
    }
}

#[derive(Clone, Debug, Default)]
struct CompiledEventFilters {
    by_event: HashMap<HookEventKey, Vec<CommandMatcher>>,
}

impl CompiledEventFilters {
    fn compile(cfg: &crate::config::HookEventFiltersConfig) -> Self {
        let mut by_event: HashMap<HookEventKey, Vec<CommandMatcher>> = HashMap::new();

        for (event_name, entries) in &cfg.events {
            let Some(event) = canonical_event_key(event_name) else {
                warn!("unknown hook filter event: {event_name}");
                continue;
            };

            let mut compiled = Vec::new();
            for entry in entries {
                let Some(mut matcher) = compile_matcher(entry.matcher.as_deref()) else {
                    let Some(matcher) = entry.matcher.as_deref() else {
                        continue;
                    };
                    warn!("invalid matcher regex for filter event {event_name}: {matcher}");
                    continue;
                };

                if !event.is_tool_scoped() && !matches!(matcher, CommandMatcher::Any) {
                    warn!("matcher is ignored for non-tool filter event {event_name}");
                    matcher = CommandMatcher::Any;
                }

                compiled.push(matcher);
            }

            if compiled.is_empty() {
                continue;
            }

            by_event.insert(event, compiled);
        }

        Self { by_event }
    }

    fn allows(&self, event: HookEventKey, candidates: &HookMatchCandidates<'_>) -> bool {
        if self.by_event.is_empty() {
            return true;
        }

        let Some(matchers) = self.by_event.get(&event) else {
            return false;
        };

        matchers.iter().any(|matcher| candidates.matches(matcher))
    }
}

fn compile_command_hook_specs(
    event_name: &str,
    hooks: &[crate::config::HooksCommandHookConfig],
    default_timeout: Duration,
) -> Vec<CommandHookSpec> {
    let mut compiled = Vec::new();

    for hook in hooks {
        let timeout = hook
            .timeout_sec
            .map(Duration::from_secs)
            .unwrap_or(default_timeout);

        match (&hook.argv, &hook.command) {
            (Some(argv), None) => {
                if argv.is_empty() {
                    warn!("hooks.command hook argv is empty for event {event_name}");
                    continue;
                }

                compiled.push(CommandHookSpec {
                    argv: argv.clone(),
                    timeout,
                    hook_event_name: event_name.to_string(),
                });
            }
            (None, Some(command)) => {
                if command.trim().is_empty() {
                    warn!("hooks.command hook command is empty for event {event_name}");
                    continue;
                }

                compiled.push(CommandHookSpec {
                    argv: wrap_shell_command(command),
                    timeout,
                    hook_event_name: event_name.to_string(),
                });
            }
            (Some(_), Some(_)) => {
                warn!(
                    "hooks.command hook must set exactly one of argv/command for event {event_name}"
                );
            }
            (None, None) => {
                warn!("hooks.command hook must set argv or command for event {event_name}");
            }
        }
    }

    compiled
}

fn wrap_shell_command(command: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd.exe".to_string(), "/C".to_string(), command.to_string()]
    } else {
        vec!["bash".to_string(), "-lc".to_string(), command.to_string()]
    }
}

#[derive(Clone, Debug)]
struct HookMatchCandidates<'a> {
    xcodex: Option<&'a str>,
    claude: Option<String>,
}

impl<'a> HookMatchCandidates<'a> {
    fn matches(&self, matcher: &CommandMatcher) -> bool {
        if matches!(matcher, CommandMatcher::Any) {
            return true;
        }

        if let Some(xcodex) = self.xcodex
            && matcher.matches(xcodex)
        {
            return true;
        }

        if let Some(claude) = self.claude.as_deref()
            && matcher.matches(claude)
        {
            return true;
        }

        false
    }
}

fn build_match_candidates(notification: &HookNotification) -> HookMatchCandidates<'_> {
    match notification {
        HookNotification::ToolCallStarted { tool_name, .. }
        | HookNotification::ToolCallFinished { tool_name, .. } => HookMatchCandidates {
            xcodex: Some(tool_name.as_str()),
            claude: claude_compat::map_tool_name(tool_name),
        },
        HookNotification::ApprovalRequested { kind, .. } => {
            let (xcodex, claude) = match kind {
                ApprovalKind::Exec => ("exec", "Bash"),
                ApprovalKind::ApplyPatch => ("apply-patch", "Edit"),
                ApprovalKind::Elicitation => ("elicitation", "MCP"),
            };
            HookMatchCandidates {
                xcodex: Some(xcodex),
                claude: Some(claude.to_string()),
            }
        }
        _ => HookMatchCandidates {
            xcodex: None,
            claude: None,
        },
    }
}

fn default_hook_event_name(event: &HookEvent) -> String {
    claude_compat::default_hook_event_name(event.notification())
        .unwrap_or_else(|| event.xcodex_event_type())
        .to_string()
}

#[cfg(feature = "pyo3-hooks")]
#[derive(Clone)]
struct FilteredHookHandler {
    filters: CompiledEventFilters,
    inner: std::sync::Arc<dyn HookHandler>,
}

#[cfg(feature = "pyo3-hooks")]
impl HookHandler for FilteredHookHandler {
    fn on_event(&self, ctx: &HookContext, event: &HookEvent) -> HookResult {
        let key = HookEventKey::from_notification(event.notification());
        let candidates = build_match_candidates(event.notification());
        if !self.filters.allows(key, &candidates) {
            return Ok(());
        }

        self.inner.on_event(ctx, event)
    }
}

impl HookProvider for ExternalCommandHooksProvider {
    fn on_event(&self, event: &HookEvent) {
        let command_hooks = self.command_hooks_for_event(event);
        if !command_hooks.is_empty() {
            self.invoke_command_hooks(command_hooks, event.clone());
        }

        let commands = self.commands_for_event(event);
        if !commands.is_empty() {
            self.invoke_hook_commands(commands, event.clone());
        }
    }

    fn on_event_detached(&self, event: &HookEvent) {
        let command_hooks = self.command_hooks_for_event(event);
        if !command_hooks.is_empty() {
            self.invoke_command_hooks_detached(command_hooks, event.clone());
        }

        let commands = self.commands_for_event(event);
        if !commands.is_empty() {
            self.invoke_hook_commands_detached(commands, event.clone());
        }
    }
}

#[derive(Clone)]
struct HookHostPolicy {
    queue_capacity: usize,
    failure_threshold: u32,
    circuit_breaker_open_duration: Duration,
}

impl Default for HookHostPolicy {
    fn default() -> Self {
        Self {
            queue_capacity: HOOK_HOST_QUEUE_CAPACITY,
            failure_threshold: HOOK_HOST_FAILURE_THRESHOLD,
            circuit_breaker_open_duration: HOOK_HOST_CIRCUIT_BREAKER_OPEN_DURATION,
        }
    }
}

#[derive(Default)]
struct HookHostCircuitBreaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl HookHostCircuitBreaker {
    fn is_open(&self) -> bool {
        self.open_until
            .is_some_and(|open_until| Instant::now() < open_until)
    }

    fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    fn on_failure(&mut self, policy: &HookHostPolicy) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= policy.failure_threshold {
            self.open_until = Some(Instant::now() + policy.circuit_breaker_open_duration);
        }
    }
}

enum HookHostMessage {
    Payload(std::sync::Arc<HookPayload>),
}

struct HookHostProvider {
    tx_line: mpsc::Sender<HookHostMessage>,
    filters: CompiledEventFilters,
}

#[derive(Clone)]
struct HookHostSpawnConfig {
    command: Vec<String>,
    codex_home: PathBuf,
    sandbox_policy: SandboxPolicy,
    codex_linux_sandbox_exe: Option<PathBuf>,
    keep_last_n_payloads: usize,
    write_timeout: Option<Duration>,
}

impl HookHostProvider {
    fn new(
        hooks: &HooksConfig,
        codex_home: PathBuf,
        session_sandbox_policy: SandboxPolicy,
        codex_linux_sandbox_exe: Option<PathBuf>,
    ) -> Option<Self> {
        if !hooks.host.enabled {
            return None;
        }

        if hooks.host.command.is_empty() {
            warn!("hooks.host.enabled=true but hooks.host.command is empty; hook host is disabled");
            return None;
        }

        let sandbox_policy =
            resolve_hook_host_sandbox_policy(&codex_home, &session_sandbox_policy, hooks);

        let filters = CompiledEventFilters::compile(&hooks.host.filters);
        let write_timeout = hooks.host.timeout_sec.map(Duration::from_secs);

        let spawn_cfg = HookHostSpawnConfig {
            command: hooks.host.command.clone(),
            codex_home,
            sandbox_policy,
            codex_linux_sandbox_exe,
            keep_last_n_payloads: hooks.keep_last_n_payloads,
            write_timeout,
        };

        let policy = HookHostPolicy::default();
        let (tx_line, rx_line) = mpsc::channel(policy.queue_capacity);
        tokio::spawn(run_hook_host_manager(rx_line, spawn_cfg, policy));

        Some(Self { tx_line, filters })
    }
}

impl HookProvider for HookHostProvider {
    fn on_event(&self, event: &HookEvent) {
        let key = HookEventKey::from_notification(event.notification());
        let candidates = build_match_candidates(event.notification());
        if !self.filters.allows(key, &candidates) {
            return;
        }

        let hook_event_name = default_hook_event_name(event);
        let payload = HookPayload::from_event(event, &hook_event_name);
        let payload = std::sync::Arc::new(payload);
        if self
            .tx_line
            .try_send(HookHostMessage::Payload(payload))
            .is_err()
        {
            warn!("hook host queue full; dropping hook event");
        }
    }
}

fn resolve_hook_host_sandbox_policy(
    _codex_home: &Path,
    session_sandbox_policy: &SandboxPolicy,
    hooks: &HooksConfig,
) -> SandboxPolicy {
    let Some(override_mode) = hooks.host.sandbox_mode else {
        return session_sandbox_policy.clone();
    };

    match override_mode {
        SandboxMode::ReadOnly => SandboxPolicy::new_read_only_policy(),
        SandboxMode::WorkspaceWrite => SandboxPolicy::new_workspace_write_policy(),
        SandboxMode::DangerFullAccess => SandboxPolicy::DangerFullAccess,
    }
}

#[derive(Serialize)]
struct HookHostLine<'a> {
    schema_version: u32,
    #[serde(rename = "type")]
    ty: &'static str,
    seq: u64,
    event: &'a HookPayload,
}

async fn run_hook_host_manager(
    mut rx_line: mpsc::Receiver<HookHostMessage>,
    spawn_cfg: HookHostSpawnConfig,
    policy: HookHostPolicy,
) {
    let mut breaker = HookHostCircuitBreaker::default();
    let mut child: Option<tokio::process::Child> = None;
    let mut stdin: Option<tokio::process::ChildStdin> = None;
    let mut sequence: u64 = 0;

    while let Some(msg) = rx_line.recv().await {
        if breaker.is_open() {
            warn!("skipping hook host due to open circuit breaker");
            continue;
        }

        if child.is_none() || stdin.is_none() {
            match spawn_hook_host_process(&spawn_cfg).await {
                Ok((next_child, next_stdin)) => {
                    child = Some(next_child);
                    stdin = Some(next_stdin);
                }
                Err(e) => {
                    warn!("failed to spawn hook host: {e}");
                    breaker.on_failure(&policy);
                    continue;
                }
            }
        }

        let Some(stdin_handle) = stdin.as_mut() else {
            continue;
        };

        let HookHostMessage::Payload(payload) = msg;
        sequence = sequence.wrapping_add(1);

        let line = HookHostLine {
            schema_version: payload.schema_version(),
            ty: "hook-event",
            seq: sequence,
            event: &payload,
        };

        let Ok(mut line) = serde_json::to_vec(&line) else {
            error!("failed to serialise hook host payload");
            breaker.on_failure(&policy);
            continue;
        };

        line.push(b'\n');
        let write_result = match spawn_cfg.write_timeout {
            Some(timeout) => {
                match tokio::time::timeout(timeout, stdin_handle.write_all(&line)).await {
                    Ok(result) => result.map_err(Some),
                    Err(_timeout) => Err(None),
                }
            }
            None => stdin_handle.write_all(&line).await.map_err(Some),
        };

        match write_result {
            Ok(()) => {
                breaker.on_success();
            }
            Err(Some(err)) => {
                warn!("failed to write hook event to host stdin: {err}");
                stdin = None;
                if let Some(mut child) = child.take() {
                    let _ = child.start_kill();
                }
                breaker.on_failure(&policy);
            }
            Err(None) => {
                let Some(timeout) = spawn_cfg.write_timeout else {
                    continue;
                };
                let timeout_ms = timeout.as_millis();
                warn!("timeout writing hook event to host stdin after {timeout_ms}ms");
                stdin = None;
                if let Some(mut child) = child.take() {
                    let _ = child.start_kill();
                }
                breaker.on_failure(&policy);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HookHostSpawnInvocation {
    program: String,
    args: Vec<String>,
    arg0_override: Option<String>,
}

fn build_hook_host_spawn_invocation(
    program: String,
    args: Vec<String>,
    sandbox: crate::exec::SandboxType,
    sandbox_policy: &SandboxPolicy,
    sandbox_policy_cwd: &Path,
    codex_linux_sandbox_exe: &Option<PathBuf>,
) -> HookHostSpawnInvocation {
    match sandbox {
        crate::exec::SandboxType::None => HookHostSpawnInvocation {
            program,
            args,
            arg0_override: None,
        },
        #[cfg(target_os = "macos")]
        crate::exec::SandboxType::MacosSeatbelt => {
            let wrapped = vec![program].into_iter().chain(args).collect::<Vec<_>>();
            let args = crate::seatbelt::create_seatbelt_command_args(
                wrapped,
                sandbox_policy,
                sandbox_policy_cwd,
            );
            HookHostSpawnInvocation {
                program: crate::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE.to_string(),
                args,
                arg0_override: None,
            }
        }
        #[cfg(not(target_os = "macos"))]
        crate::exec::SandboxType::MacosSeatbelt => HookHostSpawnInvocation {
            program,
            args,
            arg0_override: None,
        },
        crate::exec::SandboxType::LinuxSeccomp => {
            let exe = codex_linux_sandbox_exe
                .clone()
                .unwrap_or_else(|| PathBuf::from("codex-linux-sandbox"));
            let wrapped = vec![program].into_iter().chain(args).collect::<Vec<_>>();
            let args = crate::landlock::create_linux_sandbox_command_args(
                wrapped,
                sandbox_policy,
                sandbox_policy_cwd,
            );
            HookHostSpawnInvocation {
                program: exe.to_string_lossy().to_string(),
                args,
                arg0_override: Some("codex-linux-sandbox".to_string()),
            }
        }
        crate::exec::SandboxType::WindowsRestrictedToken => HookHostSpawnInvocation {
            program,
            args,
            arg0_override: None,
        },
    }
}

fn downgrade_hook_host_sandbox_if_unavailable(
    sandbox: crate::exec::SandboxType,
    codex_linux_sandbox_exe: &Option<PathBuf>,
) -> crate::exec::SandboxType {
    if sandbox == crate::exec::SandboxType::LinuxSeccomp && codex_linux_sandbox_exe.is_none() {
        crate::exec::SandboxType::None
    } else {
        sandbox
    }
}

async fn spawn_hook_host_process(
    cfg: &HookHostSpawnConfig,
) -> io::Result<(tokio::process::Child, tokio::process::ChildStdin)> {
    #[allow(clippy::indexing_slicing)]
    let program = cfg.command[0].clone();
    #[allow(clippy::indexing_slicing)]
    let args: Vec<String> = cfg.command[1..].to_vec();

    let (stdout, stderr) = open_hook_host_log_files(&cfg.codex_home, cfg.keep_last_n_payloads);
    let command_cwd = cfg.codex_home.clone();
    let sandbox_policy_cwd = cfg.codex_home.clone();

    let mut sandbox = match &cfg.sandbox_policy {
        SandboxPolicy::DangerFullAccess | SandboxPolicy::ExternalSandbox { .. } => {
            crate::exec::SandboxType::None
        }
        _ => crate::safety::get_platform_sandbox().unwrap_or(crate::exec::SandboxType::None),
    };

    let downgraded =
        downgrade_hook_host_sandbox_if_unavailable(sandbox, &cfg.codex_linux_sandbox_exe);
    if sandbox == crate::exec::SandboxType::LinuxSeccomp
        && downgraded == crate::exec::SandboxType::None
    {
        warn!(
            "linux sandbox requested for hook host, but codex_linux_sandbox_exe is not configured; spawning unsandboxed"
        );
    }
    sandbox = downgraded;

    if sandbox == crate::exec::SandboxType::WindowsRestrictedToken {
        warn!("hook host sandboxing is not supported on Windows yet; spawning unsandboxed");
    }

    let invocation = build_hook_host_spawn_invocation(
        program,
        args,
        sandbox,
        &cfg.sandbox_policy,
        &sandbox_policy_cwd,
        &cfg.codex_linux_sandbox_exe,
    );

    let mut cmd = tokio::process::Command::new(&invocation.program);
    if let Some(arg0) = invocation.arg0_override {
        cmd.arg0(arg0);
    }
    cmd.args(invocation.args);
    cmd.current_dir(command_cwd);
    cmd.env("CODEX_HOME", cfg.codex_home.as_os_str());
    cmd.stdin(Stdio::piped());
    cmd.stdout(stdout);
    cmd.stderr(stderr);
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("hook host stdin pipe not available"))?;

    Ok((child, stdin))
}

fn open_hook_host_log_files(codex_home: &Path, keep_last_n: usize) -> (Stdio, Stdio) {
    let logs_dir = codex_home
        .join("tmp")
        .join("hooks")
        .join("host")
        .join("logs");
    if let Err(e) = ensure_dir(&logs_dir) {
        warn!("failed to create hook host log dir: {e}");
        return (Stdio::null(), Stdio::null());
    }

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let log_id = Uuid::new_v4();
    let log_path = logs_dir.join(format!("{timestamp_ms}-{log_id}.log"));
    let file = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
    {
        Ok(file) => file,
        Err(e) => {
            warn!("failed to open hook host log file: {e}");
            return (Stdio::null(), Stdio::null());
        }
    };

    if let Err(e) = set_file_permissions(&log_path, &file) {
        warn!("failed to set hook host log file permissions: {e}");
    }

    if let Err(e) = prune_old_files(&logs_dir, keep_last_n) {
        warn!("failed to prune hook host log files: {e}");
    }

    let stderr = match file.try_clone() {
        Ok(clone) => clone,
        Err(e) => {
            warn!("failed to clone hook host log file handle: {e}");
            return (Stdio::from(file), Stdio::null());
        }
    };

    (Stdio::from(file), Stdio::from(stderr))
}

fn resolve_inproc_hooks(hooks: &HooksConfig) -> Vec<InprocHookEntry> {
    let mut hook_names = hooks.inproc.clone();
    if hooks.inproc_tool_call_summary {
        hook_names.push(INPROC_TOOL_CALL_SUMMARY_HOOK_NAME.to_string());
    }

    let mut deduped = BTreeSet::new();
    let mut resolved = Vec::new();
    for hook_name in hook_names {
        if !deduped.insert(hook_name.clone()) {
            continue;
        }

        match hook_name.as_str() {
            INPROC_TOOL_CALL_SUMMARY_HOOK_NAME => {
                resolved.push(InprocHookEntry {
                    name: hook_name,
                    hook: std::sync::Arc::new(ToolCallSummaryHook),
                    timeout: None,
                });
            }
            INPROC_EVENT_LOG_JSONL_HOOK_NAME => {
                resolved.push(InprocHookEntry {
                    name: hook_name,
                    hook: std::sync::Arc::new(EventLogJsonlHook),
                    timeout: None,
                });
            }
            INPROC_PYO3_HOOK_NAME => {
                #[cfg(feature = "pyo3-hooks")]
                {
                    if !hooks.enable_unsafe_inproc {
                        warn!(
                            "hooks.enable_unsafe_inproc=false; refusing to enable PyO3 in-process hook",
                        );
                        continue;
                    }

                    let Some(script_path) = hooks
                        .pyo3
                        .script_path
                        .clone()
                        .filter(|path| !path.is_empty())
                    else {
                        warn!(
                            "hooks.inproc includes {INPROC_PYO3_HOOK_NAME}, but hooks.pyo3.script_path is empty; skipping",
                        );
                        continue;
                    };

                    let callable = hooks
                        .pyo3
                        .callable
                        .clone()
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| "on_event".to_string());

                    let batch_size = hooks
                        .pyo3
                        .batch_size
                        .and_then(NonZeroUsize::new)
                        .filter(|batch_size| batch_size.get() > 1);

                    let timeout = hooks.pyo3.timeout_sec.map(Duration::from_secs);
                    let filters = CompiledEventFilters::compile(&hooks.pyo3.filters);

                    let handler =
                        std::sync::Arc::new(Pyo3Hook::new(script_path, callable, batch_size));
                    let handler: std::sync::Arc<dyn HookHandler> = if filters.by_event.is_empty() {
                        handler
                    } else {
                        std::sync::Arc::new(FilteredHookHandler {
                            filters,
                            inner: handler,
                        })
                    };

                    resolved.push(InprocHookEntry {
                        name: hook_name,
                        hook: handler,
                        timeout,
                    });
                }
                #[cfg(not(feature = "pyo3-hooks"))]
                {
                    warn!(
                        "hooks.inproc includes {INPROC_PYO3_HOOK_NAME}, but codex-core is built without the pyo3-hooks feature",
                    );
                }
            }
            _ => {
                warn!("unknown in-process hook: {hook_name}");
            }
        }
    }

    resolved
}

impl UserHooks {
    pub(crate) fn new(
        codex_home: PathBuf,
        hooks: HooksConfig,
        tx_event: Option<Sender<Event>>,
        session_sandbox_policy: SandboxPolicy,
        codex_linux_sandbox_exe: Option<PathBuf>,
    ) -> Self {
        let mut providers: Vec<std::sync::Arc<dyn HookProvider>> = Vec::new();

        let inproc_hooks = resolve_inproc_hooks(&hooks);
        if !inproc_hooks.is_empty() {
            providers.push(std::sync::Arc::new(InprocHooksProvider::new(
                codex_home.clone(),
                inproc_hooks,
            )));
        }

        if let Some(host_provider) = HookHostProvider::new(
            &hooks,
            codex_home.clone(),
            session_sandbox_policy,
            codex_linux_sandbox_exe,
        ) {
            providers.push(std::sync::Arc::new(host_provider));
        }

        providers.push(std::sync::Arc::new(ExternalCommandHooksProvider::new(
            codex_home, hooks, tx_event,
        )));

        Self {
            bus: HookBus { providers },
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
        self.bus.emit(HookNotification::AgentTurnComplete {
            thread_id,
            turn_id,
            cwd,
            input_messages,
            last_assistant_message,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn approval_requested_exec(
        &self,
        thread_id: String,
        turn_id: String,
        call_id: String,
        cwd: String,
        approval_policy: AskForApproval,
        sandbox_policy: SandboxPolicy,
        command: Vec<String>,
        reason: Option<String>,
        proposed_execpolicy_amendment: Option<ExecPolicyAmendment>,
    ) {
        let notification_message = command.join(" ");
        self.bus.emit(HookNotification::ApprovalRequested {
            thread_id: thread_id.clone(),
            turn_id: Some(turn_id),
            cwd: Some(cwd.clone()),
            kind: ApprovalKind::Exec,
            call_id: Some(call_id),
            reason,
            approval_policy: Some(approval_policy),
            sandbox_policy: Some(sandbox_policy),
            proposed_execpolicy_amendment,
            command: Some(command),
            paths: None,
            grant_root: None,
            server_name: None,
            request_id: None,
            message: None,
        });

        // Best-effort mapping for Claude-compatible notification hooks.
        self.notification(
            thread_id,
            cwd,
            "permission_prompt".to_string(),
            Some(notification_message),
            Some("Permission requested".to_string()),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn approval_requested_apply_patch(
        &self,
        thread_id: String,
        turn_id: String,
        call_id: String,
        cwd: String,
        approval_policy: AskForApproval,
        sandbox_policy: SandboxPolicy,
        paths: Vec<String>,
        reason: Option<String>,
        grant_root: Option<String>,
    ) {
        let notification_message = paths.join(", ");
        self.bus.emit(HookNotification::ApprovalRequested {
            thread_id: thread_id.clone(),
            turn_id: Some(turn_id),
            cwd: Some(cwd.clone()),
            kind: ApprovalKind::ApplyPatch,
            call_id: Some(call_id),
            reason,
            approval_policy: Some(approval_policy),
            sandbox_policy: Some(sandbox_policy),
            proposed_execpolicy_amendment: None,
            command: None,
            paths: Some(paths),
            grant_root,
            server_name: None,
            request_id: None,
            message: None,
        });

        // Best-effort mapping for Claude-compatible notification hooks.
        self.notification(
            thread_id,
            cwd,
            "permission_prompt".to_string(),
            Some(notification_message),
            Some("Permission requested".to_string()),
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
        let notification_message = message.clone();
        self.bus.emit(HookNotification::ApprovalRequested {
            thread_id: thread_id.clone(),
            turn_id: None,
            cwd: Some(cwd.clone()),
            kind: ApprovalKind::Elicitation,
            call_id: None,
            reason: None,
            approval_policy: None,
            sandbox_policy: None,
            proposed_execpolicy_amendment: None,
            command: None,
            paths: None,
            grant_root: None,
            server_name: Some(server_name),
            request_id: Some(request_id),
            message: Some(message),
        });

        // Best-effort mapping for Claude-compatible notification hooks.
        self.notification(
            thread_id,
            cwd,
            "elicitation_dialog".to_string(),
            Some(notification_message),
            Some("Elicitation".to_string()),
        );
    }

    pub(crate) fn session_start(&self, thread_id: String, cwd: String, session_source: String) {
        self.bus.emit(HookNotification::SessionStart {
            thread_id,
            cwd,
            session_source,
        });
    }

    pub(crate) fn session_end(&self, thread_id: String, cwd: String, session_source: String) {
        self.bus.emit_detached(HookNotification::SessionEnd {
            thread_id,
            cwd,
            session_source,
        });
    }

    pub(crate) fn user_prompt_submit(&self, thread_id: String, cwd: String, prompt: String) {
        self.bus.emit(HookNotification::UserPromptSubmit {
            thread_id,
            cwd,
            prompt,
        });
    }

    pub(crate) fn pre_compact(&self, thread_id: String, cwd: String, trigger: String) {
        self.bus.emit(HookNotification::PreCompact {
            thread_id,
            cwd,
            trigger,
        });
    }

    pub(crate) fn notification(
        &self,
        thread_id: String,
        cwd: String,
        notification_type: String,
        message: Option<String>,
        title: Option<String>,
    ) {
        self.bus.emit(HookNotification::Notification {
            thread_id,
            cwd,
            notification_type,
            message,
            title,
        });
    }

    pub(crate) fn subagent_stop(
        &self,
        thread_id: String,
        cwd: String,
        subagent: String,
        status: String,
    ) {
        self.bus.emit(HookNotification::SubagentStop {
            thread_id,
            cwd,
            subagent,
            status,
        });
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
        self.bus.emit(HookNotification::ModelRequestStarted {
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
        });
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
        self.bus.emit(HookNotification::ModelResponseCompleted {
            thread_id,
            turn_id,
            cwd,
            model_request_id,
            attempt,
            response_id,
            token_usage,
            needs_follow_up,
        });
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
        tool_input: Option<Value>,
    ) {
        self.bus.emit(HookNotification::ToolCallStarted {
            thread_id,
            turn_id,
            cwd,
            model_request_id,
            attempt,
            tool_name,
            call_id,
            tool_input,
        });
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
        tool_input: Option<Value>,
        tool_response: Option<Value>,
    ) {
        self.bus.emit(HookNotification::ToolCallFinished {
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
            tool_input,
            tool_response,
        });
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
    let event_type = payload.xcodex_event_type().to_string();

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
                    payload_event_id: payload.event_id(),
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

async fn run_hook_command_with_timeout(
    command: Vec<String>,
    payload: HookPayload,
    stdin_payload: Vec<u8>,
    ctx: HookCommandContext,
    timeout: Duration,
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
    let event_type = payload.xcodex_event_type().to_string();

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
                    payload_event_id: payload.event_id(),
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

    let mut exit_code = None;
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            exit_code = status.code();
        }
        Ok(Err(e)) => {
            warn!("failed waiting for hook process to exit: {e}");
        }
        Err(_timeout) => {
            let timeout_sec = timeout.as_secs();
            warn!("hook timed out after {timeout_sec}s: {event_type}");
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
        }
    }

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

#[derive(Debug, Clone, PartialEq)]
struct HookEvent {
    schema_version: u32,
    event_id: Uuid,
    timestamp: DateTime<Utc>,
    notification: HookNotification,
}

impl HookEvent {
    pub fn new(notification: HookNotification) -> Self {
        Self {
            schema_version: 1,
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            notification,
        }
    }

    pub fn notification(&self) -> &HookNotification {
        &self.notification
    }

    pub fn xcodex_event_type(&self) -> &'static str {
        self.notification.event_type()
    }
}

#[cfg_attr(feature = "hooks-schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HookPayload {
    session_id: String,
    transcript_path: String,
    permission_mode: String,

    hook_event_name: String,

    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    event_id: Uuid,
    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    turn_id: Option<String>,
    cwd: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_use_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_input: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_response: Option<Value>,

    schema_version: u32,
    xcodex_event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_preview: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    notification_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    input_messages: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_assistant_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_source: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    subagent: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_policy: Option<AskForApproval>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_policy: Option<SandboxPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposed_execpolicy_amendment: Option<ExecPolicyAmendment>,
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
    model_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_item_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_output_schema: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_usage: Option<TokenUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    needs_follow_up: Option<bool>,
}

impl HookPayload {
    pub fn new(notification: HookNotification, hook_event_name: impl Into<String>) -> Self {
        let event = HookEvent::new(notification);
        let hook_event_name = hook_event_name.into();
        Self::from_event(&event, &hook_event_name)
    }

    fn from_event(event: &HookEvent, hook_event_name: &str) -> Self {
        let notification = event.notification();
        let (session_id, turn_id, cwd) = match notification {
            HookNotification::AgentTurnComplete {
                thread_id,
                turn_id,
                cwd,
                ..
            } => (thread_id.clone(), Some(turn_id.clone()), cwd.clone()),
            HookNotification::ApprovalRequested {
                thread_id,
                turn_id,
                cwd,
                ..
            } => (
                thread_id.clone(),
                turn_id.clone(),
                cwd.clone().unwrap_or_default(),
            ),
            HookNotification::SessionStart { thread_id, cwd, .. }
            | HookNotification::SessionEnd { thread_id, cwd, .. }
            | HookNotification::UserPromptSubmit { thread_id, cwd, .. }
            | HookNotification::PreCompact { thread_id, cwd, .. }
            | HookNotification::Notification { thread_id, cwd, .. }
            | HookNotification::SubagentStop { thread_id, cwd, .. } => {
                (thread_id.clone(), None, cwd.clone())
            }
            HookNotification::ModelRequestStarted {
                thread_id,
                turn_id,
                cwd,
                ..
            }
            | HookNotification::ModelResponseCompleted {
                thread_id,
                turn_id,
                cwd,
                ..
            }
            | HookNotification::ToolCallStarted {
                thread_id,
                turn_id,
                cwd,
                ..
            }
            | HookNotification::ToolCallFinished {
                thread_id,
                turn_id,
                cwd,
                ..
            } => (thread_id.clone(), Some(turn_id.clone()), cwd.clone()),
        };

        let mut out = Self {
            session_id,
            transcript_path: String::new(),
            permission_mode: "default".to_string(),
            hook_event_name: hook_event_name.to_string(),
            event_id: event.event_id,
            timestamp: event.timestamp,
            turn_id,
            cwd,
            tool_name: None,
            tool_use_id: None,
            tool_input: None,
            tool_response: None,
            schema_version: event.schema_version,
            xcodex_event_type: event.xcodex_event_type().to_string(),
            duration_ms: None,
            success: None,
            status: None,
            output_bytes: None,
            output_preview: None,
            notification_type: None,
            message: None,
            title: None,
            input_messages: None,
            last_assistant_message: None,
            prompt: None,
            trigger: None,
            session_source: None,
            subagent: None,
            kind: None,
            call_id: None,
            reason: None,
            approval_policy: None,
            sandbox_policy: None,
            proposed_execpolicy_amendment: None,
            command: None,
            paths: None,
            grant_root: None,
            server_name: None,
            request_id: None,
            model_request_id: None,
            attempt: None,
            model: None,
            provider: None,
            input_item_count: None,
            tool_count: None,
            parallel_tool_calls: None,
            has_output_schema: None,
            response_id: None,
            token_usage: None,
            needs_follow_up: None,
        };

        match notification {
            HookNotification::AgentTurnComplete {
                input_messages,
                last_assistant_message,
                ..
            } => {
                out.input_messages = Some(input_messages.clone());
                out.last_assistant_message = last_assistant_message.clone();
            }
            HookNotification::ApprovalRequested {
                kind,
                call_id,
                reason,
                approval_policy,
                sandbox_policy,
                proposed_execpolicy_amendment,
                command,
                paths,
                grant_root,
                server_name,
                request_id,
                message,
                ..
            } => {
                let (kind_str, tool_name) = match kind {
                    ApprovalKind::Exec => ("exec", "Bash"),
                    ApprovalKind::ApplyPatch => ("apply-patch", "Edit"),
                    ApprovalKind::Elicitation => ("elicitation", "MCP"),
                };
                out.kind = Some(kind_str.to_string());
                out.call_id = call_id.clone();
                out.reason = reason.clone();
                out.approval_policy = *approval_policy;
                out.sandbox_policy = sandbox_policy.clone();
                out.proposed_execpolicy_amendment = proposed_execpolicy_amendment.clone();
                out.command = command.clone();
                out.paths = paths.clone();
                out.grant_root = grant_root.clone();
                out.server_name = server_name.clone();
                out.request_id = request_id.clone();
                out.message = message.clone();

                out.tool_name = Some(tool_name.to_string());
                out.tool_use_id = call_id.clone();
                out.tool_input = match kind {
                    ApprovalKind::Exec => command
                        .as_ref()
                        .map(|cmd| serde_json::json!({ "command": cmd })),
                    ApprovalKind::ApplyPatch => paths
                        .as_ref()
                        .map(|paths| serde_json::json!({ "paths": paths })),
                    ApprovalKind::Elicitation => None,
                };
                out.tool_response = Some(Value::Null);
            }
            HookNotification::SessionStart { session_source, .. }
            | HookNotification::SessionEnd { session_source, .. } => {
                out.session_source = Some(session_source.clone());
            }
            HookNotification::UserPromptSubmit { prompt, .. } => {
                out.prompt = Some(prompt.clone());
            }
            HookNotification::PreCompact { trigger, .. } => {
                out.trigger = Some(trigger.clone());
            }
            HookNotification::Notification {
                notification_type,
                message,
                title,
                ..
            } => {
                out.notification_type = Some(notification_type.clone());
                out.message = message.clone();
                out.title = title.clone();
            }
            HookNotification::SubagentStop {
                subagent, status, ..
            } => {
                out.tool_name = Some("Task".to_string());
                out.subagent = Some(subagent.clone());
                out.status = Some(status.clone());
            }
            HookNotification::ModelRequestStarted {
                model_request_id,
                attempt,
                model,
                provider,
                input_item_count,
                tool_count,
                parallel_tool_calls,
                has_output_schema,
                ..
            } => {
                out.model_request_id = Some(model_request_id.to_string());
                out.attempt = Some(*attempt);
                out.model = Some(model.clone());
                out.provider = Some(provider.clone());
                out.input_item_count = Some(*input_item_count);
                out.tool_count = Some(*tool_count);
                out.parallel_tool_calls = Some(*parallel_tool_calls);
                out.has_output_schema = Some(*has_output_schema);
            }
            HookNotification::ModelResponseCompleted {
                model_request_id,
                attempt,
                response_id,
                token_usage,
                needs_follow_up,
                ..
            } => {
                out.model_request_id = Some(model_request_id.to_string());
                out.attempt = Some(*attempt);
                out.response_id = Some(response_id.clone());
                out.token_usage = token_usage.clone();
                out.needs_follow_up = Some(*needs_follow_up);
            }
            HookNotification::ToolCallStarted {
                model_request_id,
                attempt,
                tool_name,
                call_id,
                tool_input,
                ..
            } => {
                let tool_name =
                    claude_compat::map_tool_name(tool_name).unwrap_or_else(|| tool_name.clone());
                let translated_input = claude_compat::translate_tool_input(
                    Some(tool_name.as_str()),
                    tool_input.as_ref(),
                );

                out.tool_name = Some(tool_name);
                out.tool_use_id = Some(call_id.clone());
                out.tool_input = translated_input;
                out.tool_response = Some(Value::Null);
                out.model_request_id = Some(model_request_id.to_string());
                out.attempt = Some(*attempt);
            }
            HookNotification::ToolCallFinished {
                model_request_id,
                attempt,
                tool_name,
                call_id,
                status,
                duration_ms,
                success,
                output_bytes,
                output_preview,
                tool_input,
                tool_response,
                ..
            } => {
                let tool_name =
                    claude_compat::map_tool_name(tool_name).unwrap_or_else(|| tool_name.clone());
                let translated_input = claude_compat::translate_tool_input(
                    Some(tool_name.as_str()),
                    tool_input.as_ref(),
                );
                let translated_response = claude_compat::translate_tool_response(
                    Some(tool_name.as_str()),
                    tool_response.as_ref(),
                );

                out.tool_name = Some(tool_name);
                out.tool_use_id = Some(call_id.clone());
                out.tool_input = translated_input;
                out.tool_response = Some(translated_response.unwrap_or(Value::Null));
                out.status = Some(tool_call_status_string(*status).to_string());
                out.duration_ms = Some(*duration_ms);
                out.success = Some(*success);
                out.output_bytes = Some(*output_bytes);
                out.output_preview = output_preview.clone();
                out.model_request_id = Some(model_request_id.to_string());
                out.attempt = Some(*attempt);
            }
        }

        out
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn event_id(&self) -> Uuid {
        self.event_id
    }

    pub fn timestamp(&self) -> &DateTime<Utc> {
        &self.timestamp
    }

    pub fn xcodex_event_type(&self) -> &str {
        self.xcodex_event_type.as_str()
    }
}

#[cfg_attr(feature = "hooks-schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HookStdinEnvelope {
    schema_version: u32,
    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    event_id: Uuid,
    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    timestamp: DateTime<Utc>,
    hook_event_name: String,
    xcodex_event_type: String,
    payload_path: String,
}

impl HookStdinEnvelope {
    pub fn from_payload(payload: &HookPayload, payload_path: PathBuf) -> Self {
        Self {
            schema_version: payload.schema_version,
            event_id: payload.event_id,
            timestamp: payload.timestamp,
            hook_event_name: payload.hook_event_name.clone(),
            xcodex_event_type: payload.xcodex_event_type.clone(),
            payload_path: payload_path.display().to_string(),
        }
    }
}

#[cfg_attr(feature = "hooks-schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalKind {
    Exec,
    ApplyPatch,
    Elicitation,
}

#[cfg_attr(feature = "hooks-schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolCallStatus {
    Completed,
    Aborted,
}

fn tool_call_status_string(status: ToolCallStatus) -> &'static str {
    match status {
        ToolCallStatus::Completed => "completed",
        ToolCallStatus::Aborted => "aborted",
    }
}

fn append_tool_call_summary_line(path: &Path, line: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

fn append_hook_payload_jsonl_line(path: &Path, event: &HookEvent) -> HookResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let hook_event_name = default_hook_event_name(event);
    let payload = HookPayload::from_event(event, &hook_event_name);
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    set_file_permissions(path, &file)?;
    serde_json::to_writer(&mut file, &payload)?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg_attr(feature = "hooks-schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HookNotification {
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
        approval_policy: Option<AskForApproval>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sandbox_policy: Option<SandboxPolicy>,
        #[serde(skip_serializing_if = "Option::is_none")]
        proposed_execpolicy_amendment: Option<ExecPolicyAmendment>,

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
    UserPromptSubmit {
        thread_id: String,
        cwd: String,
        prompt: String,
    },

    #[serde(rename_all = "kebab-case")]
    PreCompact {
        thread_id: String,
        cwd: String,
        trigger: String,
    },

    #[serde(rename_all = "kebab-case")]
    Notification {
        thread_id: String,
        cwd: String,
        notification_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },

    #[serde(rename_all = "kebab-case")]
    SubagentStop {
        thread_id: String,
        cwd: String,
        subagent: String,
        status: String,
    },

    #[serde(rename_all = "kebab-case")]
    ModelRequestStarted {
        thread_id: String,
        turn_id: String,
        cwd: String,
        #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
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
        #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
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
        #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
        model_request_id: Uuid,
        attempt: u32,
        tool_name: String,
        call_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_input: Option<Value>,
    },

    #[serde(rename_all = "kebab-case")]
    ToolCallFinished {
        thread_id: String,
        turn_id: String,
        cwd: String,
        #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_input: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_response: Option<Value>,
    },
}

impl HookNotification {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::AgentTurnComplete { .. } => "agent-turn-complete",
            Self::ApprovalRequested { .. } => "approval-requested",
            Self::SessionStart { .. } => "session-start",
            Self::SessionEnd { .. } => "session-end",
            Self::UserPromptSubmit { .. } => "user-prompt-submit",
            Self::PreCompact { .. } => "pre-compact",
            Self::Notification { .. } => "notification",
            Self::SubagentStop { .. } => "subagent-stop",
            Self::ModelRequestStarted { .. } => "model-request-started",
            Self::ModelResponseCompleted { .. } => "model-response-completed",
            Self::ToolCallStarted { .. } => "tool-call-started",
            Self::ToolCallFinished { .. } => "tool-call-finished",
        }
    }
}

pub(crate) mod hooks_test {
    use super::*;
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HooksTestTarget {
        Configured,
        All,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HooksTestEvent {
        AgentTurnComplete,
        ApprovalRequestedExec,
        ApprovalRequestedApplyPatch,
        ApprovalRequestedElicitation,
        SessionStart,
        SessionEnd,
        UserPromptSubmit,
        PreCompact,
        Notification,
        SubagentStop,
        ModelRequestStarted,
        ModelResponseCompleted,
        ToolCallStarted,
        ToolCallFinished,
    }

    #[derive(Debug, Clone)]
    pub struct HooksTestReport {
        pub invocations: Vec<HooksTestInvocation>,
        pub codex_home: PathBuf,
        pub logs_dir: PathBuf,
        pub payloads_dir: PathBuf,
    }

    #[derive(Debug, Clone)]
    pub struct HooksTestInvocation {
        pub event_type: &'static str,
        pub command: Vec<String>,
        pub exit_code: Option<i32>,
    }

    #[derive(Debug, Clone)]
    struct HooksTestCommand {
        command: Vec<String>,
        hook_event_name: String,
    }

    pub async fn run_hooks_test(
        codex_home: PathBuf,
        hooks: HooksConfig,
        target: HooksTestTarget,
        requested_events: Vec<HooksTestEvent>,
        timeout: Duration,
    ) -> anyhow::Result<HooksTestReport> {
        let logs_dir = codex_home.join("tmp").join("hooks").join("logs");
        let payloads_dir = codex_home.join("tmp").join("hooks").join("payloads");

        let command_hooks = CompiledCommandHooksConfig::compile(&hooks.command);

        let events = resolve_events(target, requested_events);
        let mut invocations = Vec::new();

        for event in events {
            let notification = build_notification_for_test(event);
            let commands = commands_for_event(&hooks, &command_hooks, event, target, &notification);
            if commands.is_empty() {
                continue;
            }

            let event = HookEvent::new(notification);

            for command in commands {
                let payload = HookPayload::from_event(&event, &command.hook_event_name);
                let payload_json = serde_json::to_vec(&payload)?;
                let stdin_payload = prepare_hook_stdin_payload(
                    &payload,
                    &payload_json,
                    hooks.max_stdin_payload_bytes,
                    hooks.keep_last_n_payloads,
                    &codex_home,
                );

                let exit_code = tokio::time::timeout(
                    timeout,
                    run_hook_command_for_test(
                        command.command.clone(),
                        hooks.keep_last_n_payloads,
                        &codex_home,
                        &stdin_payload,
                    ),
                )
                .await
                .ok()
                .and_then(std::result::Result::ok)
                .flatten();

                invocations.push(HooksTestInvocation {
                    event_type: event.xcodex_event_type(),
                    command: command.command,
                    exit_code,
                });
            }
        }

        Ok(HooksTestReport {
            invocations,
            codex_home,
            logs_dir,
            payloads_dir,
        })
    }

    fn resolve_events(
        target: HooksTestTarget,
        requested: Vec<HooksTestEvent>,
    ) -> Vec<HooksTestEvent> {
        if !requested.is_empty() {
            return requested;
        }
        match target {
            HooksTestTarget::All | HooksTestTarget::Configured => vec![
                HooksTestEvent::SessionStart,
                HooksTestEvent::SessionEnd,
                HooksTestEvent::UserPromptSubmit,
                HooksTestEvent::PreCompact,
                HooksTestEvent::Notification,
                HooksTestEvent::SubagentStop,
                HooksTestEvent::ModelRequestStarted,
                HooksTestEvent::ModelResponseCompleted,
                HooksTestEvent::ToolCallStarted,
                HooksTestEvent::ToolCallFinished,
                HooksTestEvent::AgentTurnComplete,
                HooksTestEvent::ApprovalRequestedExec,
                HooksTestEvent::ApprovalRequestedApplyPatch,
                HooksTestEvent::ApprovalRequestedElicitation,
            ],
        }
    }

    fn commands_for_event(
        hooks: &HooksConfig,
        command_hooks: &CompiledCommandHooksConfig,
        event: HooksTestEvent,
        target: HooksTestTarget,
        notification: &HookNotification,
    ) -> Vec<HooksTestCommand> {
        let hook_event_name = claude_compat::default_hook_event_name(notification)
            .unwrap_or_else(|| notification.event_type())
            .to_string();

        let mut configured: Vec<HooksTestCommand> = match event {
            HooksTestEvent::AgentTurnComplete => hooks
                .agent_turn_complete
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::ApprovalRequestedExec
            | HooksTestEvent::ApprovalRequestedApplyPatch
            | HooksTestEvent::ApprovalRequestedElicitation => hooks
                .approval_requested
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::SessionStart => hooks
                .session_start
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::SessionEnd => hooks
                .session_end
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::UserPromptSubmit => hooks
                .user_prompt_submit
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::PreCompact => hooks
                .pre_compact
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::Notification => hooks
                .notification
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::SubagentStop => hooks
                .subagent_stop
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::ModelRequestStarted => hooks
                .model_request_started
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::ModelResponseCompleted => hooks
                .model_response_completed
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::ToolCallStarted => hooks
                .tool_call_started
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
            HooksTestEvent::ToolCallFinished => hooks
                .tool_call_finished
                .iter()
                .cloned()
                .map(|command| HooksTestCommand {
                    command,
                    hook_event_name: hook_event_name.clone(),
                })
                .collect(),
        };

        let event = HookEventKey::from_notification(notification);
        let candidates = build_match_candidates(notification);
        if let Some(entries) = command_hooks.by_event.get(&event) {
            for entry in entries {
                if candidates.matches(&entry.matcher) {
                    for hook in &entry.hooks {
                        configured.push(HooksTestCommand {
                            command: hook.argv.clone(),
                            hook_event_name: hook.hook_event_name.clone(),
                        });
                    }
                }
            }
        }

        match target {
            HooksTestTarget::Configured => configured,
            HooksTestTarget::All => configured,
        }
    }

    pub(crate) fn build_notification_for_test(event: HooksTestEvent) -> HookNotification {
        let thread_id = format!("hooks-test-{}", Uuid::new_v4());
        let turn_id = format!("turn-{}", Uuid::new_v4());
        let cwd = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .display()
            .to_string();

        match event {
            HooksTestEvent::AgentTurnComplete => HookNotification::AgentTurnComplete {
                thread_id,
                turn_id,
                cwd,
                input_messages: vec!["hooks test".to_string()],
                last_assistant_message: Some("hooks test".to_string()),
            },
            HooksTestEvent::ApprovalRequestedExec => HookNotification::ApprovalRequested {
                thread_id,
                turn_id: Some(turn_id),
                cwd: Some(cwd),
                kind: ApprovalKind::Exec,
                call_id: Some(format!("call-{}", Uuid::new_v4())),
                reason: Some("hooks test".to_string()),
                approval_policy: None,
                sandbox_policy: None,
                proposed_execpolicy_amendment: None,
                command: Some(vec!["echo".to_string(), "hooks-test".to_string()]),
                paths: None,
                grant_root: None,
                server_name: None,
                request_id: None,
                message: None,
            },
            HooksTestEvent::ApprovalRequestedApplyPatch => HookNotification::ApprovalRequested {
                thread_id,
                turn_id: Some(turn_id),
                cwd: Some(cwd),
                kind: ApprovalKind::ApplyPatch,
                call_id: Some(format!("call-{}", Uuid::new_v4())),
                reason: Some("hooks test".to_string()),
                approval_policy: None,
                sandbox_policy: None,
                proposed_execpolicy_amendment: None,
                command: None,
                paths: Some(vec!["/tmp/hooks-test.txt".to_string()]),
                grant_root: Some("/tmp".to_string()),
                server_name: None,
                request_id: None,
                message: None,
            },
            HooksTestEvent::ApprovalRequestedElicitation => HookNotification::ApprovalRequested {
                thread_id,
                turn_id: None,
                cwd: Some(cwd),
                kind: ApprovalKind::Elicitation,
                call_id: None,
                reason: None,
                approval_policy: None,
                sandbox_policy: None,
                proposed_execpolicy_amendment: None,
                command: None,
                paths: None,
                grant_root: None,
                server_name: Some("hooks-test".to_string()),
                request_id: Some("hooks-test".to_string()),
                message: Some("hooks test".to_string()),
            },
            HooksTestEvent::SessionStart => HookNotification::SessionStart {
                thread_id,
                cwd,
                session_source: "hooks-test".to_string(),
            },
            HooksTestEvent::SessionEnd => HookNotification::SessionEnd {
                thread_id,
                cwd,
                session_source: "hooks-test".to_string(),
            },
            HooksTestEvent::UserPromptSubmit => HookNotification::UserPromptSubmit {
                thread_id,
                cwd,
                prompt: "hooks test".to_string(),
            },
            HooksTestEvent::PreCompact => HookNotification::PreCompact {
                thread_id,
                cwd,
                trigger: "hooks-test".to_string(),
            },
            HooksTestEvent::Notification => HookNotification::Notification {
                thread_id,
                cwd,
                notification_type: "hooks-test".to_string(),
                message: Some("hooks test".to_string()),
                title: Some("hooks-test".to_string()),
            },
            HooksTestEvent::SubagentStop => HookNotification::SubagentStop {
                thread_id,
                cwd,
                subagent: "hooks-test".to_string(),
                status: "completed".to_string(),
            },
            HooksTestEvent::ModelRequestStarted => HookNotification::ModelRequestStarted {
                thread_id,
                turn_id,
                cwd,
                model_request_id: Uuid::new_v4(),
                attempt: 1,
                model: "hooks-test".to_string(),
                provider: "hooks-test".to_string(),
                input_item_count: 1,
                tool_count: 0,
                parallel_tool_calls: false,
                has_output_schema: false,
            },
            HooksTestEvent::ModelResponseCompleted => HookNotification::ModelResponseCompleted {
                thread_id,
                turn_id,
                cwd,
                model_request_id: Uuid::new_v4(),
                attempt: 1,
                response_id: "hooks-test".to_string(),
                token_usage: None,
                needs_follow_up: false,
            },
            HooksTestEvent::ToolCallStarted => HookNotification::ToolCallStarted {
                thread_id,
                turn_id,
                cwd,
                model_request_id: Uuid::new_v4(),
                attempt: 1,
                tool_name: "hooks-test".to_string(),
                call_id: format!("call-{}", Uuid::new_v4()),
                tool_input: None,
            },
            HooksTestEvent::ToolCallFinished => HookNotification::ToolCallFinished {
                thread_id,
                turn_id,
                cwd,
                model_request_id: Uuid::new_v4(),
                attempt: 1,
                tool_name: "hooks-test".to_string(),
                call_id: format!("call-{}", Uuid::new_v4()),
                status: ToolCallStatus::Completed,
                duration_ms: 0,
                success: true,
                output_bytes: 0,
                output_preview: None,
                tool_input: None,
                tool_response: None,
            },
        }
    }

    async fn run_hook_command_for_test(
        command: Vec<String>,
        keep_last_n_payloads: usize,
        codex_home: &Path,
        stdin_payload: &[u8],
    ) -> anyhow::Result<Option<i32>> {
        if command.is_empty() {
            return Ok(None);
        }

        let (stdout, stderr) =
            open_hook_log_files(codex_home, Uuid::new_v4(), keep_last_n_payloads);

        let mut cmd = tokio::process::Command::new(&command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(stdout);
        cmd.stderr(stderr);

        let mut child = cmd.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_payload).await?;
        }

        Ok(child.wait().await?.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use pretty_assertions::assert_eq;
    use serde_json::Value;
    use std::time::Duration;
    use tempfile::TempDir;

    async fn read_to_string_eventually(path: &Path) -> Result<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    if !contents.is_empty() {
                        return Ok(contents);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "timeout waiting for file: {}",
                    path.display()
                ));
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn test_hook_payload_includes_version_and_ids() -> Result<()> {
        let event = HookEvent::new(HookNotification::ApprovalRequested {
            thread_id: "thread-1".to_string(),
            turn_id: None,
            cwd: Some("/tmp".to_string()),
            kind: ApprovalKind::Exec,
            call_id: Some("call-1".to_string()),
            reason: None,
            approval_policy: None,
            sandbox_policy: None,
            proposed_execpolicy_amendment: None,
            command: Some(vec!["echo".to_string(), "hi".to_string()]),
            paths: None,
            grant_root: None,
            server_name: None,
            request_id: None,
            message: None,
        });
        let payload = HookPayload::from_event(&event, "PermissionRequest");
        let serialized = serde_json::to_string(&payload)?;
        assert!(
            serialized.contains(r#""schema_version":1"#),
            "payload must include schema_version: {serialized}"
        );
        assert!(
            serialized.contains(r#""event_id":"#),
            "payload must include event_id: {serialized}"
        );
        assert!(
            serialized.contains(r#""timestamp":"#),
            "payload must include timestamp: {serialized}"
        );
        Ok(())
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn hooks_test_runs_configured_hook() -> Result<()> {
        let codex_home = TempDir::new()?;
        let hooks = HooksConfig {
            session_start: vec![vec![
                "bash".to_string(),
                "-lc".to_string(),
                "true".to_string(),
            ]],
            ..HooksConfig::default()
        };

        let report = hooks_test::run_hooks_test(
            codex_home.path().to_path_buf(),
            hooks,
            hooks_test::HooksTestTarget::All,
            vec![hooks_test::HooksTestEvent::SessionStart],
            std::time::Duration::from_secs(5),
        )
        .await?;

        assert_eq!(report.invocations.len(), 1);
        assert_eq!(report.invocations[0].exit_code, Some(0));
        Ok(())
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn hooks_command_runs_for_alias_event_and_claude_tool_name() -> Result<()> {
        use std::collections::HashMap;

        let codex_home = TempDir::new()?;
        let marker_path = codex_home.path().join("hooks.command.marker");

        let mut events = HashMap::new();
        events.insert(
            "PostToolUse".to_string(),
            vec![crate::config::HooksCommandMatcherConfig {
                matcher: Some("Write".to_string()),
                hooks: vec![crate::config::HooksCommandHookConfig {
                    payload: crate::config::HookPayloadFormat::Xcodex,
                    argv: Some(vec![
                        "python3".to_string(),
                        "-c".to_string(),
                        format!(
                            r#"import json, pathlib, sys
payload = json.load(sys.stdin)
assert payload.get("hook_event_name") == "PostToolUse", payload
assert payload.get("xcodex_event_type") == "tool-call-finished", payload
assert payload.get("tool_name") == "Write", payload
pathlib.Path({path:?}).write_text("ok", encoding="utf-8")
"#,
                            path = marker_path.to_string_lossy()
                        ),
                    ]),
                    command: None,
                    timeout_sec: Some(5),
                }],
            }],
        );

        let hooks = HooksConfig {
            command: crate::config::HooksCommandConfig {
                default_timeout_sec: 30,
                events,
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.tool_call_finished(
            "thread-1".to_string(),
            "turn-1".to_string(),
            "/tmp".to_string(),
            Uuid::new_v4(),
            0,
            "write_file".to_string(),
            "call-1".to_string(),
            ToolCallStatus::Completed,
            1,
            true,
            0,
            None,
            None,
            None,
        );

        let contents = read_to_string_eventually(&marker_path).await?;
        assert_eq!(contents.trim(), "ok");
        Ok(())
    }

    #[test]
    fn test_hook_stdin_envelope_has_payload_path() -> Result<()> {
        let event = HookEvent::new(HookNotification::AgentTurnComplete {
            thread_id: "t".to_string(),
            turn_id: "turn".to_string(),
            cwd: "/tmp".to_string(),
            input_messages: Vec::new(),
            last_assistant_message: None,
        });
        let payload = HookPayload::from_event(&event, "Stop");
        let envelope =
            HookStdinEnvelope::from_payload(&payload, PathBuf::from("/tmp/payload.json"));
        let serialized = serde_json::to_string(&envelope)?;
        assert!(
            serialized.contains(r#""payload_path":"/tmp/payload.json""#),
            "envelope must include payload_path: {serialized}"
        );
        Ok(())
    }

    #[test]
    fn tool_call_summary_log_matches_gallery_script() -> Result<()> {
        let codex_home = TempDir::new()?;
        let out_path = codex_home.path().join(TOOL_CALL_SUMMARY_LOG_FILENAME);
        let line = format!(
            "type=tool-call-finished tool=exec status={} success=true duration_ms=12 output_bytes=34 cwd=/tmp\n",
            tool_call_status_string(ToolCallStatus::Completed)
        );

        append_tool_call_summary_line(&out_path, &line)?;
        let contents = std::fs::read_to_string(&out_path)?;
        assert_eq!(contents, line);
        Ok(())
    }

    #[test]
    fn large_payload_uses_payload_path_envelope() -> Result<()> {
        let codex_home = TempDir::new()?;
        let event = HookEvent::new(HookNotification::AgentTurnComplete {
            thread_id: "t".to_string(),
            turn_id: "turn".to_string(),
            cwd: "/tmp".to_string(),
            input_messages: vec!["x".repeat(20_000)],
            last_assistant_message: None,
        });
        let payload = HookPayload::from_event(&event, "Stop");
        let payload_json = serde_json::to_vec(&payload)?;

        let stdin_payload =
            prepare_hook_stdin_payload(&payload, &payload_json, 16, 50, codex_home.path());

        let envelope: Value = serde_json::from_slice(&stdin_payload)?;
        let payload_path = envelope
            .get("payload_path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("expected payload_path envelope"))?;

        let read_back = std::fs::read(payload_path)?;
        assert_eq!(read_back, payload_json);
        Ok(())
    }

    #[tokio::test]
    async fn tool_call_summary_log_emits_from_user_hooks() -> Result<()> {
        let codex_home = TempDir::new()?;
        let hooks = HooksConfig {
            inproc_tool_call_summary: true,
            ..HooksConfig::default()
        };
        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.tool_call_finished(
            "thread-1".to_string(),
            "turn-1".to_string(),
            "/tmp".to_string(),
            Uuid::new_v4(),
            1,
            "exec".to_string(),
            "call-1".to_string(),
            ToolCallStatus::Completed,
            12,
            true,
            34,
            None,
            None,
            None,
        );

        let out_path = codex_home.path().join(TOOL_CALL_SUMMARY_LOG_FILENAME);
        let contents = read_to_string_eventually(&out_path).await?;
        assert!(
            contents.starts_with("type=tool-call-finished tool=exec status=completed"),
            "summary line missing expected prefix: {contents:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn tool_call_summary_inproc_list_dedupes() -> Result<()> {
        let codex_home = TempDir::new()?;
        let hooks = HooksConfig {
            inproc_tool_call_summary: true,
            inproc: vec![INPROC_TOOL_CALL_SUMMARY_HOOK_NAME.to_string()],
            ..HooksConfig::default()
        };
        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.tool_call_finished(
            "thread-1".to_string(),
            "turn-1".to_string(),
            "/tmp".to_string(),
            Uuid::new_v4(),
            1,
            "exec".to_string(),
            "call-1".to_string(),
            ToolCallStatus::Completed,
            12,
            true,
            34,
            None,
            None,
            None,
        );

        let out_path = codex_home.path().join(TOOL_CALL_SUMMARY_LOG_FILENAME);
        let contents = read_to_string_eventually(&out_path).await?;
        assert_eq!(contents.lines().count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn event_log_jsonl_emits_all_payloads() -> Result<()> {
        let codex_home = TempDir::new()?;
        let hooks = HooksConfig {
            inproc: vec![INPROC_EVENT_LOG_JSONL_HOOK_NAME.to_string()],
            ..HooksConfig::default()
        };
        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.session_start(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "exec".to_string(),
        );
        user_hooks.tool_call_finished(
            "thread-1".to_string(),
            "turn-1".to_string(),
            "/tmp".to_string(),
            Uuid::new_v4(),
            1,
            "exec".to_string(),
            "call-1".to_string(),
            ToolCallStatus::Completed,
            12,
            true,
            34,
            None,
            None,
            None,
        );

        let out_path = codex_home.path().join(HOOK_EVENT_LOG_JSONL_FILENAME);
        let contents = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&out_path)
                    && contents.lines().count() >= 2
                {
                    break contents;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        let types = contents
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|value| {
                value
                    .get("xcodex_event_type")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>();

        assert!(
            types.iter().any(|ty| ty == "session-start"),
            "expected session-start event; saw: {types:?}"
        );
        assert!(
            types.iter().any(|ty| ty == "tool-call-finished"),
            "expected tool-call-finished event; saw: {types:?}"
        );

        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hook_host_receives_events() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let codex_home = TempDir::new()?;
        let out_path = codex_home.path().join("hook-host.out.jsonl");
        let script_path = codex_home.path().join("host.sh");

        std::fs::write(
            &script_path,
            r#"#!/bin/sh
set -eu
out="$1"
mkdir -p "$(dirname "$out")"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$out"
done
"#,
        )?;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;

        let hooks = HooksConfig {
            host: crate::config::HookHostConfig {
                enabled: true,
                command: vec![
                    script_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("script path is not valid utf-8"))?
                        .to_string(),
                    out_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("output path is not valid utf-8"))?
                        .to_string(),
                ],
                sandbox_mode: None,
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.session_start(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "exec".to_string(),
        );

        let contents = read_to_string_eventually(&out_path).await?;
        let first: Value = serde_json::from_str(
            contents
                .lines()
                .next()
                .ok_or_else(|| anyhow::anyhow!("expected at least one host line"))?,
        )?;

        assert_eq!(first["type"], "hook-event");
        assert_eq!(first["event"]["xcodex_event_type"], "session-start");

        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hook_host_receives_multiple_events() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let codex_home = TempDir::new()?;
        let out_path = codex_home.path().join("hook-host.out.jsonl");
        let script_path = codex_home.path().join("host.sh");

        std::fs::write(
            &script_path,
            r#"#!/bin/sh
set -eu
out="$1"
mkdir -p "$(dirname "$out")"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$out"
done
"#,
        )?;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;

        let hooks = HooksConfig {
            host: crate::config::HookHostConfig {
                enabled: true,
                command: vec![
                    script_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("script path is not valid utf-8"))?
                        .to_string(),
                    out_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("output path is not valid utf-8"))?
                        .to_string(),
                ],
                sandbox_mode: None,
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.session_start(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "exec".to_string(),
        );
        user_hooks.user_prompt_submit(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "hello".to_string(),
        );
        user_hooks.tool_call_finished(
            "thread-1".to_string(),
            "turn-1".to_string(),
            "/tmp".to_string(),
            Uuid::new_v4(),
            1,
            "shell".to_string(),
            "call-1".to_string(),
            ToolCallStatus::Completed,
            12,
            true,
            34,
            None,
            Some(serde_json::json!({ "cmd": "echo hi" })),
            Some(serde_json::json!({ "stdout": "hi\n" })),
        );

        let contents = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&out_path)
                    && contents.lines().count() >= 3
                {
                    break contents;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        let types = contents
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|value| {
                value
                    .get("event")
                    .and_then(|event| event.get("xcodex_event_type"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>();

        assert!(
            types.iter().any(|ty| ty == "session-start"),
            "expected session-start event; saw: {types:?}"
        );
        assert!(
            types.iter().any(|ty| ty == "user-prompt-submit"),
            "expected user-prompt-submit event; saw: {types:?}"
        );
        assert!(
            types.iter().any(|ty| ty == "tool-call-finished"),
            "expected tool-call-finished event; saw: {types:?}"
        );

        Ok(())
    }

    fn hooks_test_events_all() -> Vec<hooks_test::HooksTestEvent> {
        vec![
            hooks_test::HooksTestEvent::SessionStart,
            hooks_test::HooksTestEvent::SessionEnd,
            hooks_test::HooksTestEvent::UserPromptSubmit,
            hooks_test::HooksTestEvent::PreCompact,
            hooks_test::HooksTestEvent::Notification,
            hooks_test::HooksTestEvent::SubagentStop,
            hooks_test::HooksTestEvent::ModelRequestStarted,
            hooks_test::HooksTestEvent::ModelResponseCompleted,
            hooks_test::HooksTestEvent::ToolCallStarted,
            hooks_test::HooksTestEvent::ToolCallFinished,
            hooks_test::HooksTestEvent::AgentTurnComplete,
            hooks_test::HooksTestEvent::ApprovalRequestedExec,
            hooks_test::HooksTestEvent::ApprovalRequestedApplyPatch,
            hooks_test::HooksTestEvent::ApprovalRequestedElicitation,
        ]
    }

    fn expected_default_hook_event_name(notification: &HookNotification) -> String {
        claude_compat::default_hook_event_name(notification)
            .unwrap_or_else(|| notification.event_type())
            .to_string()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hooks_command_runs_for_all_events_and_validates_payload_shape() -> Result<()> {
        use std::collections::HashMap;

        let codex_home = TempDir::new()?;
        let validate_path = codex_home.path().join("validate_payload.py");

        std::fs::write(
            &validate_path,
            r#"
import json
import pathlib
import sys

expected_event_type = sys.argv[1]
expected_hook_event_name = sys.argv[2]
required_keys = sys.argv[3].split(",") if len(sys.argv) > 3 and sys.argv[3] else []

payload = json.load(sys.stdin)
payload_path = payload.get("payload_path")
if payload_path:
    payload = json.loads(pathlib.Path(payload_path).read_text(encoding="utf-8"))

assert payload.get("xcodex_event_type") == expected_event_type, payload
assert payload.get("hook_event_name") == expected_hook_event_name, payload
for key in required_keys:
    if payload.get(key) is None:
        raise AssertionError(f"missing required key: {key} (payload: {payload})")
"#,
        )?;

        let mk_entry = |matcher: Option<&str>,
                        argv: Vec<String>|
         -> crate::config::HooksCommandMatcherConfig {
            crate::config::HooksCommandMatcherConfig {
                matcher: matcher.map(ToString::to_string),
                hooks: vec![crate::config::HooksCommandHookConfig {
                    payload: crate::config::HookPayloadFormat::Xcodex,
                    argv: Some(argv),
                    command: None,
                    timeout_sec: Some(5),
                }],
            }
        };

        let mk_hook_argv = |expected_event_type: &str,
                            expected_hook_event_name: &str,
                            required_keys: &[&str]|
         -> Vec<String> {
            vec![
                "python3".to_string(),
                validate_path
                    .to_str()
                    .expect("validate path must be valid utf-8")
                    .to_string(),
                expected_event_type.to_string(),
                expected_hook_event_name.to_string(),
                required_keys.join(","),
            ]
        };

        let mut events: HashMap<String, Vec<crate::config::HooksCommandMatcherConfig>> =
            HashMap::new();

        events.insert(
            "session_start".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "session-start",
                    "session_start",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "session_source",
                    ],
                ),
            )],
        );
        events.insert(
            "session_end".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "session-end",
                    "session_end",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "session_source",
                    ],
                ),
            )],
        );
        events.insert(
            "user_prompt_submit".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "user-prompt-submit",
                    "user_prompt_submit",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "prompt",
                    ],
                ),
            )],
        );
        events.insert(
            "pre_compact".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "pre-compact",
                    "pre_compact",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "trigger",
                    ],
                ),
            )],
        );
        events.insert(
            "notification".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "notification",
                    "notification",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "notification_type",
                    ],
                ),
            )],
        );
        events.insert(
            "SubagentStop".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "subagent-stop",
                    "SubagentStop",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "subagent",
                        "status",
                    ],
                ),
            )],
        );
        events.insert(
            "model_request_started".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "model-request-started",
                    "model_request_started",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "model_request_id",
                        "attempt",
                        "model",
                        "provider",
                        "input_item_count",
                        "tool_count",
                        "parallel_tool_calls",
                        "has_output_schema",
                    ],
                ),
            )],
        );
        events.insert(
            "model_response_completed".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "model-response-completed",
                    "model_response_completed",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "model_request_id",
                        "attempt",
                        "response_id",
                        "needs_follow_up",
                    ],
                ),
            )],
        );
        events.insert(
            "tool_call_started".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "tool-call-started",
                    "tool_call_started",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "turn_id",
                        "model_request_id",
                        "attempt",
                        "tool_name",
                        "tool_use_id",
                    ],
                ),
            )],
        );
        events.insert(
            "tool_call_finished".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "tool-call-finished",
                    "tool_call_finished",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "turn_id",
                        "model_request_id",
                        "attempt",
                        "tool_name",
                        "tool_use_id",
                        "status",
                        "duration_ms",
                        "success",
                        "output_bytes",
                    ],
                ),
            )],
        );
        events.insert(
            "Stop".to_string(),
            vec![mk_entry(
                None,
                mk_hook_argv(
                    "agent-turn-complete",
                    "Stop",
                    &[
                        "schema_version",
                        "event_id",
                        "timestamp",
                        "session_id",
                        "cwd",
                        "turn_id",
                        "input_messages",
                    ],
                ),
            )],
        );
        events.insert(
            "PermissionRequest".to_string(),
            vec![
                mk_entry(
                    Some("Bash"),
                    mk_hook_argv(
                        "approval-requested",
                        "PermissionRequest",
                        &[
                            "schema_version",
                            "event_id",
                            "timestamp",
                            "session_id",
                            "cwd",
                            "turn_id",
                            "kind",
                            "command",
                            "tool_name",
                            "tool_use_id",
                        ],
                    ),
                ),
                mk_entry(
                    Some("Edit"),
                    mk_hook_argv(
                        "approval-requested",
                        "PermissionRequest",
                        &[
                            "schema_version",
                            "event_id",
                            "timestamp",
                            "session_id",
                            "cwd",
                            "turn_id",
                            "kind",
                            "paths",
                            "grant_root",
                            "tool_name",
                            "tool_use_id",
                        ],
                    ),
                ),
                mk_entry(
                    Some("MCP"),
                    mk_hook_argv(
                        "approval-requested",
                        "PermissionRequest",
                        &[
                            "schema_version",
                            "event_id",
                            "timestamp",
                            "session_id",
                            "cwd",
                            "kind",
                            "server_name",
                            "request_id",
                            "message",
                            "tool_name",
                        ],
                    ),
                ),
            ],
        );

        let hooks = HooksConfig {
            max_stdin_payload_bytes: 1024 * 1024,
            command: crate::config::HooksCommandConfig {
                default_timeout_sec: 30,
                events,
            },
            ..HooksConfig::default()
        };

        let report = hooks_test::run_hooks_test(
            codex_home.path().to_path_buf(),
            hooks,
            hooks_test::HooksTestTarget::All,
            Vec::new(),
            Duration::from_secs(5),
        )
        .await?;

        assert_eq!(report.invocations.len(), 14);
        assert!(
            report
                .invocations
                .iter()
                .all(|inv| inv.exit_code == Some(0))
        );

        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hooks_command_accepts_opencode_aliases_for_emitted_events() -> Result<()> {
        use std::collections::HashMap;

        let codex_home = TempDir::new()?;
        let validate_path = codex_home.path().join("validate_payload.py");

        std::fs::write(
            &validate_path,
            r#"
import json
import pathlib
import sys

expected_event_type = sys.argv[1]
expected_hook_event_name = sys.argv[2]

payload = json.load(sys.stdin)
payload_path = payload.get("payload_path")
if payload_path:
    payload = json.loads(pathlib.Path(payload_path).read_text(encoding="utf-8"))

assert payload.get("xcodex_event_type") == expected_event_type, payload
assert payload.get("hook_event_name") == expected_hook_event_name, payload
"#,
        )?;

        let mk_entry = |argv: Vec<String>| crate::config::HooksCommandMatcherConfig {
            matcher: None,
            hooks: vec![crate::config::HooksCommandHookConfig {
                payload: crate::config::HookPayloadFormat::Xcodex,
                argv: Some(argv),
                command: None,
                timeout_sec: Some(5),
            }],
        };

        let mk_hook_argv = |expected_event_type: &str, expected_hook_event_name: &str| {
            vec![
                "python3".to_string(),
                validate_path
                    .to_str()
                    .expect("validate path must be valid utf-8")
                    .to_string(),
                expected_event_type.to_string(),
                expected_hook_event_name.to_string(),
            ]
        };

        let mut events: HashMap<String, Vec<crate::config::HooksCommandMatcherConfig>> =
            HashMap::new();
        events.insert(
            "session.start".to_string(),
            vec![mk_entry(mk_hook_argv("session-start", "session.start"))],
        );
        events.insert(
            "session.end".to_string(),
            vec![mk_entry(mk_hook_argv("session-end", "session.end"))],
        );
        events.insert(
            "tool.execute.before".to_string(),
            vec![mk_entry(mk_hook_argv(
                "tool-call-started",
                "tool.execute.before",
            ))],
        );
        events.insert(
            "tool.execute.after".to_string(),
            vec![mk_entry(mk_hook_argv(
                "tool-call-finished",
                "tool.execute.after",
            ))],
        );

        let hooks = HooksConfig {
            max_stdin_payload_bytes: 1024 * 1024,
            command: crate::config::HooksCommandConfig {
                default_timeout_sec: 30,
                events,
            },
            ..HooksConfig::default()
        };

        let report = hooks_test::run_hooks_test(
            codex_home.path().to_path_buf(),
            hooks,
            hooks_test::HooksTestTarget::All,
            vec![
                hooks_test::HooksTestEvent::SessionStart,
                hooks_test::HooksTestEvent::SessionEnd,
                hooks_test::HooksTestEvent::ToolCallStarted,
                hooks_test::HooksTestEvent::ToolCallFinished,
            ],
            Duration::from_secs(5),
        )
        .await?;

        assert_eq!(report.invocations.len(), 4);
        assert!(
            report
                .invocations
                .iter()
                .all(|inv| inv.exit_code == Some(0))
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hook_host_receives_all_event_types_with_default_hook_event_names() -> Result<()> {
        use std::collections::HashMap;
        use std::os::unix::fs::PermissionsExt;

        let codex_home = TempDir::new()?;
        let out_path = codex_home.path().join("hook-host.all-events.jsonl");
        let script_path = codex_home.path().join("host.sh");

        std::fs::write(
            &script_path,
            r#"#!/bin/sh
set -eu
out="$1"
mkdir -p "$(dirname "$out")"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$out"
done
"#,
        )?;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;

        let hooks = HooksConfig {
            host: crate::config::HookHostConfig {
                enabled: true,
                command: vec![
                    script_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("script path is not valid utf-8"))?
                        .to_string(),
                    out_path
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("output path is not valid utf-8"))?
                        .to_string(),
                ],
                sandbox_mode: None,
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        let mut expected: HashMap<(String, String), usize> = HashMap::new();
        for event in hooks_test_events_all() {
            let notification = hooks_test::build_notification_for_test(event);
            let expected_hook_event_name = expected_default_hook_event_name(&notification);
            let key = (
                notification.event_type().to_string(),
                expected_hook_event_name,
            );
            *expected.entry(key).or_insert(0) += 1;
            user_hooks.bus.emit(notification);
        }

        let contents = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&out_path)
                    && contents.lines().count() >= 14
                {
                    break contents;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        let mut actual: HashMap<(String, String), usize> = HashMap::new();
        for line in contents.lines() {
            let value: Value = serde_json::from_str(line)?;
            assert_eq!(value["type"], "hook-event");
            let event = value
                .get("event")
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("missing event object in host line"))?;

            let event_type = event
                .get("xcodex_event_type")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing xcodex_event_type in host line"))?;
            let hook_event_name = event
                .get("hook_event_name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing hook_event_name in host line"))?;

            *actual
                .entry((event_type.to_string(), hook_event_name.to_string()))
                .or_insert(0) += 1;
        }

        assert_eq!(actual, expected);
        Ok(())
    }

    #[cfg(feature = "pyo3-hooks")]
    #[tokio::test]
    async fn pyo3_inproc_hook_receives_all_event_types_with_default_hook_event_names() -> Result<()>
    {
        use std::collections::HashMap;

        let codex_home = TempDir::new()?;
        let marker_path = codex_home.path().join("pyo3-hook.all-events.txt");
        let hooks_dir = codex_home.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;
        let hook_path = hooks_dir.join("pyo3_hook.py");

        std::fs::write(
            &hook_path,
            format!(
                r#"
import pathlib

def on_event(event):
    path = pathlib.Path({path:?})
    line = event.get("xcodex_event_type", "") + "\t" + event.get("hook_event_name", "") + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)
"#,
                path = marker_path.to_string_lossy()
            ),
        )?;

        let hooks = HooksConfig {
            inproc: vec![INPROC_PYO3_HOOK_NAME.to_string()],
            enable_unsafe_inproc: true,
            pyo3: crate::config::HooksPyo3Config {
                script_path: Some("hooks/pyo3_hook.py".to_string()),
                callable: None,
                batch_size: None,
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        let mut expected: HashMap<(String, String), usize> = HashMap::new();
        for event in hooks_test_events_all() {
            let notification = hooks_test::build_notification_for_test(event);
            let expected_hook_event_name = expected_default_hook_event_name(&notification);
            let key = (
                notification.event_type().to_string(),
                expected_hook_event_name,
            );
            *expected.entry(key).or_insert(0) += 1;
            user_hooks.bus.emit(notification);
        }

        let contents = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&marker_path)
                    && contents.lines().count() >= 14
                {
                    break contents;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        let mut actual: HashMap<(String, String), usize> = HashMap::new();
        for line in contents.lines() {
            let mut parts = line.split('\t');
            let event_type = parts.next().unwrap_or_default();
            let hook_event_name = parts.next().unwrap_or_default();
            *actual
                .entry((event_type.to_string(), hook_event_name.to_string()))
                .or_insert(0) += 1;
        }

        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn hook_host_sandbox_policy_inherits_session_when_unset() {
        let session = SandboxPolicy::new_workspace_write_policy();
        let hooks = HooksConfig::default();

        let resolved = resolve_hook_host_sandbox_policy(Path::new("/tmp"), &session, &hooks);
        assert_eq!(resolved, session);
    }

    #[test]
    fn hook_host_sandbox_policy_override_mode() {
        for (mode, expected) in [
            (SandboxMode::ReadOnly, SandboxPolicy::new_read_only_policy()),
            (
                SandboxMode::WorkspaceWrite,
                SandboxPolicy::new_workspace_write_policy(),
            ),
            (
                SandboxMode::DangerFullAccess,
                SandboxPolicy::DangerFullAccess,
            ),
        ] {
            let session = SandboxPolicy::new_workspace_write_policy();
            let hooks = HooksConfig {
                host: crate::config::HookHostConfig {
                    enabled: true,
                    command: vec!["python3".to_string()],
                    sandbox_mode: Some(mode),
                    timeout_sec: None,
                    filters: crate::config::HookEventFiltersConfig::default(),
                },
                ..HooksConfig::default()
            };

            let resolved = resolve_hook_host_sandbox_policy(Path::new("/tmp"), &session, &hooks);
            assert_eq!(resolved, expected);
        }
    }

    #[test]
    fn hook_host_spawn_invocation_linux_seccomp_wraps_command() -> Result<()> {
        let tmp = TempDir::new()?;
        let sandbox_policy = SandboxPolicy::new_read_only_policy();
        let exe = Some(PathBuf::from("/opt/codex-linux-sandbox"));

        let invocation = build_hook_host_spawn_invocation(
            "python3".to_string(),
            vec!["-u".to_string(), "hooks/host/python/host.py".to_string()],
            crate::exec::SandboxType::LinuxSeccomp,
            &sandbox_policy,
            tmp.path(),
            &exe,
        );

        assert_eq!(invocation.program, "/opt/codex-linux-sandbox");
        assert_eq!(
            invocation.arg0_override.as_deref(),
            Some("codex-linux-sandbox")
        );

        let dashdash = invocation
            .args
            .iter()
            .position(|arg| arg == "--")
            .ok_or_else(|| anyhow::anyhow!("expected -- in linux sandbox args"))?;

        let expected = vec!["python3", "-u", "hooks/host/python/host.py"];
        let actual = invocation.args[dashdash + 1..]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn hook_host_sandbox_downgrades_linux_seccomp_without_helper() {
        let sandbox = downgrade_hook_host_sandbox_if_unavailable(
            crate::exec::SandboxType::LinuxSeccomp,
            &None,
        );
        assert_eq!(sandbox, crate::exec::SandboxType::None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hook_host_spawn_invocation_macos_seatbelt_wraps_command() {
        let tmp = TempDir::new().expect("tempdir");
        let sandbox_policy = SandboxPolicy::new_read_only_policy();

        let invocation = build_hook_host_spawn_invocation(
            "python3".to_string(),
            vec!["-u".to_string(), "hooks/host/python/host.py".to_string()],
            crate::exec::SandboxType::MacosSeatbelt,
            &sandbox_policy,
            tmp.path(),
            &None,
        );

        assert_eq!(
            invocation.program,
            crate::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE
        );
        assert_eq!(invocation.args.first().map(String::as_str), Some("-p"));
        assert!(invocation.args.iter().any(|arg| arg == "--"));
        assert!(invocation.args.iter().any(|arg| arg == "python3"));
    }

    #[tokio::test]
    async fn inproc_hooks_timeout_opens_breaker() -> Result<()> {
        struct SlowHook(std::sync::Arc<std::sync::atomic::AtomicU64>);

        impl HookHandler for SlowHook {
            fn on_event(&self, _ctx: &HookContext, _event: &HookEvent) -> HookResult {
                std::thread::sleep(Duration::from_millis(50));
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let codex_home = TempDir::new()?;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let provider = InprocHooksProvider::new_with_policy(
            codex_home.path().to_path_buf(),
            vec![InprocHookEntry {
                name: "slow".to_string(),
                hook: std::sync::Arc::new(SlowHook(std::sync::Arc::clone(&counter))),
                timeout: None,
            }],
            InprocHookPolicy {
                queue_capacity: 8,
                timeout: Duration::from_millis(10),
                failure_threshold: 1,
                circuit_breaker_open_duration: Duration::from_millis(200),
            },
        );

        let payload = HookEvent::new(HookNotification::SessionStart {
            thread_id: "t".to_string(),
            cwd: "/tmp".to_string(),
            session_source: "exec".to_string(),
        });

        provider.on_event(&payload);
        provider.on_event(&payload);

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn inproc_hooks_panic_does_not_crash() -> Result<()> {
        struct PanicHook(std::sync::Arc<std::sync::atomic::AtomicU64>);

        impl HookHandler for PanicHook {
            fn on_event(&self, _ctx: &HookContext, _event: &HookEvent) -> HookResult {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                panic!("boom");
            }
        }

        let codex_home = TempDir::new()?;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let provider = InprocHooksProvider::new_with_policy(
            codex_home.path().to_path_buf(),
            vec![InprocHookEntry {
                name: "panic".to_string(),
                hook: std::sync::Arc::new(PanicHook(std::sync::Arc::clone(&counter))),
                timeout: None,
            }],
            InprocHookPolicy {
                queue_capacity: 8,
                timeout: Duration::from_millis(50),
                failure_threshold: 1,
                circuit_breaker_open_duration: Duration::from_millis(200),
            },
        );

        let payload = HookEvent::new(HookNotification::SessionStart {
            thread_id: "t".to_string(),
            cwd: "/tmp".to_string(),
            session_source: "exec".to_string(),
        });

        provider.on_event(&payload);
        provider.on_event(&payload);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn pyo3_inproc_hook_is_gated_by_enable_unsafe_inproc() {
        let hooks = HooksConfig {
            inproc: vec![INPROC_PYO3_HOOK_NAME.to_string()],
            enable_unsafe_inproc: false,
            pyo3: crate::config::HooksPyo3Config {
                script_path: Some("hook.py".to_string()),
                callable: None,
                batch_size: None,
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let resolved = resolve_inproc_hooks(&hooks);
        assert!(resolved.is_empty());
    }

    #[cfg(feature = "pyo3-hooks")]
    #[tokio::test]
    async fn pyo3_inproc_hook_calls_python_on_event() -> Result<()> {
        let codex_home = TempDir::new()?;
        let marker_path = codex_home.path().join("pyo3-hook.marker");
        let hooks_dir = codex_home.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;
        std::fs::write(hooks_dir.join("xcodex_hooks_runtime.py"), "MARKER = 'ok'\n")?;
        let hook_path = hooks_dir.join("pyo3_hook.py");

        std::fs::write(
            &hook_path,
            format!(
                r#"
import pathlib
import xcodex_hooks_runtime

def on_event(event):
    if event.get("hook_event_name") != "SessionStart":
        return
    pathlib.Path({path:?}).write_text(xcodex_hooks_runtime.MARKER, encoding="utf-8")
"#,
                path = marker_path.to_string_lossy()
            ),
        )?;

        let hooks = HooksConfig {
            inproc: vec![INPROC_PYO3_HOOK_NAME.to_string()],
            enable_unsafe_inproc: true,
            pyo3: crate::config::HooksPyo3Config {
                script_path: Some("hooks/pyo3_hook.py".to_string()),
                callable: None,
                batch_size: None,
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.session_start(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "exec".to_string(),
        );

        let contents = read_to_string_eventually(&marker_path).await?;
        assert_eq!(contents, "ok");
        Ok(())
    }

    #[cfg(feature = "pyo3-hooks")]
    #[tokio::test]
    async fn pyo3_inproc_hook_receives_multiple_events() -> Result<()> {
        let codex_home = TempDir::new()?;
        let marker_path = codex_home.path().join("pyo3-hook.events.txt");
        let hooks_dir = codex_home.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;
        let hook_path = hooks_dir.join("pyo3_hook.py");

        std::fs::write(
            &hook_path,
            format!(
                r#"
import pathlib

def on_event(event):
    path = pathlib.Path({path:?})
    with path.open("a", encoding="utf-8") as f:
        f.write(event.get("xcodex_event_type", "") + "\n")
"#,
                path = marker_path.to_string_lossy()
            ),
        )?;

        let hooks = HooksConfig {
            inproc: vec![INPROC_PYO3_HOOK_NAME.to_string()],
            enable_unsafe_inproc: true,
            pyo3: crate::config::HooksPyo3Config {
                script_path: Some("hooks/pyo3_hook.py".to_string()),
                callable: None,
                batch_size: None,
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.session_start(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "exec".to_string(),
        );
        user_hooks.tool_call_finished(
            "thread-1".to_string(),
            "turn-1".to_string(),
            "/tmp".to_string(),
            Uuid::new_v4(),
            1,
            "shell".to_string(),
            "call-1".to_string(),
            ToolCallStatus::Completed,
            12,
            true,
            34,
            None,
            Some(serde_json::json!({ "cmd": "echo hi" })),
            Some(serde_json::json!({ "stdout": "hi\n" })),
        );

        let contents = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(&marker_path)
                    && contents.lines().count() >= 2
                {
                    break contents;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        let types = contents
            .lines()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(
            types.iter().any(|ty| ty == "session-start"),
            "expected session-start event; saw: {types:?}"
        );
        assert!(
            types.iter().any(|ty| ty == "tool-call-finished"),
            "expected tool-call-finished event; saw: {types:?}"
        );

        Ok(())
    }

    #[cfg(feature = "pyo3-hooks")]
    #[tokio::test]
    async fn pyo3_inproc_hook_can_batch_events_with_on_events() -> Result<()> {
        let codex_home = TempDir::new()?;
        let marker_path = codex_home.path().join("pyo3-hook.batch.marker");
        let hooks_dir = codex_home.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;
        let hook_path = hooks_dir.join("pyo3_hook.py");

        std::fs::write(
            &hook_path,
            format!(
                r#"
import pathlib

def on_event(event):
    raise RuntimeError("on_event should not be called when batching is enabled")

def on_events(events):
    pathlib.Path({path:?}).write_text(str(len(events)), encoding="utf-8")
"#,
                path = marker_path.to_string_lossy()
            ),
        )?;

        let hooks = HooksConfig {
            inproc: vec![INPROC_PYO3_HOOK_NAME.to_string()],
            enable_unsafe_inproc: true,
            pyo3: crate::config::HooksPyo3Config {
                script_path: Some("hooks/pyo3_hook.py".to_string()),
                callable: None,
                batch_size: Some(2),
                timeout_sec: None,
                filters: crate::config::HookEventFiltersConfig::default(),
            },
            ..HooksConfig::default()
        };

        let user_hooks = UserHooks::new(
            codex_home.path().to_path_buf(),
            hooks,
            None,
            SandboxPolicy::DangerFullAccess,
            None,
        );

        user_hooks.session_start(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "exec".to_string(),
        );
        user_hooks.session_start(
            "thread-1".to_string(),
            "/tmp".to_string(),
            "exec".to_string(),
        );

        let contents = read_to_string_eventually(&marker_path).await?;
        assert_eq!(contents, "2");
        Ok(())
    }
}
