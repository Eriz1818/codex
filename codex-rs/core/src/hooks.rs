//! Hook dispatch and payload types.

use std::collections::BTreeSet;
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
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tracing::error;
use tracing::warn;
use uuid::Uuid;

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

const MAX_CONCURRENT_HOOKS: usize = 8;
const TOOL_CALL_SUMMARY_LOG_FILENAME: &str = "hooks-tool-calls.log";
const HOOK_EVENT_LOG_JSONL_FILENAME: &str = "hooks.jsonl";
const INPROC_TOOL_CALL_SUMMARY_HOOK_NAME: &str = "tool_call_summary";
const INPROC_EVENT_LOG_JSONL_HOOK_NAME: &str = "event_log_jsonl";
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

pub trait HookHandler: Send + Sync {
    fn on_event(&self, ctx: &HookContext, payload: &HookPayload) -> HookResult;
}

trait HookProvider: Send + Sync {
    fn on_event(&self, payload: &HookPayload);

    fn on_event_detached(&self, payload: &HookPayload) {
        self.on_event(payload);
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

        let payload = HookPayload::new(notification);
        for provider in &self.providers {
            provider.on_event(&payload);
        }
    }

    fn emit_detached(&self, notification: HookNotification) {
        if self.providers.is_empty() {
            return;
        }

        let payload = HookPayload::new(notification);
        for provider in &self.providers {
            provider.on_event_detached(&payload);
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
}

#[derive(Clone)]
struct InprocHookWorker {
    name: String,
    tx_payload: mpsc::Sender<std::sync::Arc<HookPayload>>,
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

            tokio::spawn(async move {
                let mut breaker = InprocHookCircuitBreaker::default();
                while let Some(payload) = rx_payload.recv().await {
                    if breaker.is_open() {
                        warn!("skipping in-process hook due to open circuit breaker: {entry_name}");
                        continue;
                    }

                    let payload = std::sync::Arc::clone(&payload);
                    let ctx = ctx.clone();
                    let entry_name = entry_name.clone();
                    let handler = std::sync::Arc::clone(&handler);
                    let started_at = Instant::now();

                    let handle = tokio::task::spawn_blocking(move || {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            handler.on_event(&ctx, &payload)
                        }))
                    });

                    match tokio::time::timeout(policy.timeout, handle).await {
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
                            error!(
                                "in-process hook timed out after {}ms: {entry_name}",
                                policy.timeout.as_millis()
                            );
                            breaker.on_timeout(&policy);
                        }
                    }

                    let elapsed = started_at.elapsed();
                    if elapsed > policy.timeout {
                        warn!(
                            "in-process hook exceeded timeout budget ({}ms): {entry_name} ({}ms)",
                            policy.timeout.as_millis(),
                            elapsed.as_millis()
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
    fn on_event(&self, payload: &HookPayload) {
        let payload = std::sync::Arc::new(payload.clone());
        for hook in &self.hooks {
            if hook
                .tx_payload
                .try_send(std::sync::Arc::clone(&payload))
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
    fn on_event(&self, ctx: &HookContext, payload: &HookPayload) -> HookResult {
        let HookNotification::ToolCallFinished {
            tool_name,
            status,
            success,
            duration_ms,
            output_bytes,
            cwd,
            ..
        } = &payload.notification
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
    fn on_event(&self, ctx: &HookContext, payload: &HookPayload) -> HookResult {
        let out_path = ctx.codex_home.join(HOOK_EVENT_LOG_JSONL_FILENAME);
        append_hook_payload_jsonl_line(&out_path, payload)?;
        Ok(())
    }
}

struct ExternalCommandHooksProvider {
    hooks: HooksConfig,
    codex_home: PathBuf,
    tx_event: Option<Sender<Event>>,
    semaphore: std::sync::Arc<Semaphore>,
}

impl ExternalCommandHooksProvider {
    fn new(codex_home: PathBuf, hooks: HooksConfig, tx_event: Option<Sender<Event>>) -> Self {
        Self {
            hooks,
            codex_home,
            tx_event,
            semaphore: std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_HOOKS)),
        }
    }

    fn commands_for_event(&self, payload: &HookPayload) -> &[Vec<String>] {
        match payload.notification() {
            HookNotification::AgentTurnComplete { .. } => &self.hooks.agent_turn_complete,
            HookNotification::ApprovalRequested { .. } => &self.hooks.approval_requested,
            HookNotification::SessionStart { .. } => &self.hooks.session_start,
            HookNotification::SessionEnd { .. } => &self.hooks.session_end,
            HookNotification::ModelRequestStarted { .. } => &self.hooks.model_request_started,
            HookNotification::ModelResponseCompleted { .. } => &self.hooks.model_response_completed,
            HookNotification::ToolCallStarted { .. } => &self.hooks.tool_call_started,
            HookNotification::ToolCallFinished { .. } => &self.hooks.tool_call_finished,
        }
    }

    fn invoke_hook_commands(&self, commands: &[Vec<String>], payload: HookPayload) {
        if commands.is_empty() {
            return;
        }

        let Ok(payload_json) = serde_json::to_vec(&payload) else {
            error!("failed to serialise hook payload");
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

    fn invoke_hook_commands_detached(&self, commands: &[Vec<String>], payload: HookPayload) {
        if commands.is_empty() {
            return;
        }

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

impl HookProvider for ExternalCommandHooksProvider {
    fn on_event(&self, payload: &HookPayload) {
        let commands = self.commands_for_event(payload);
        if commands.is_empty() {
            return;
        }
        self.invoke_hook_commands(commands, payload.clone());
    }

    fn on_event_detached(&self, payload: &HookPayload) {
        let commands = self.commands_for_event(payload);
        if commands.is_empty() {
            return;
        }
        self.invoke_hook_commands_detached(commands, payload.clone());
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
}

#[derive(Clone)]
struct HookHostSpawnConfig {
    command: Vec<String>,
    codex_home: PathBuf,
    sandbox_policy: SandboxPolicy,
    codex_linux_sandbox_exe: Option<PathBuf>,
    keep_last_n_payloads: usize,
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

        let spawn_cfg = HookHostSpawnConfig {
            command: hooks.host.command.clone(),
            codex_home,
            sandbox_policy,
            codex_linux_sandbox_exe,
            keep_last_n_payloads: hooks.keep_last_n_payloads,
        };

        let policy = HookHostPolicy::default();
        let (tx_line, rx_line) = mpsc::channel(policy.queue_capacity);
        tokio::spawn(run_hook_host_manager(rx_line, spawn_cfg, policy));

        Some(Self { tx_line })
    }
}

impl HookProvider for HookHostProvider {
    fn on_event(&self, payload: &HookPayload) {
        let payload = std::sync::Arc::new(payload.clone());
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
    #[serde(rename = "schema-version")]
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
        if let Err(e) = stdin_handle.write_all(&line).await {
            warn!("failed to write hook event to host stdin: {e}");
            stdin = None;
            if let Some(mut child) = child.take() {
                let _ = child.start_kill();
            }
            breaker.on_failure(&policy);
        } else {
            breaker.on_success();
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
                });
            }
            INPROC_EVENT_LOG_JSONL_HOOK_NAME => {
                resolved.push(InprocHookEntry {
                    name: hook_name,
                    hook: std::sync::Arc::new(EventLogJsonlHook),
                });
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
        self.bus.emit(HookNotification::ApprovalRequested {
            thread_id,
            turn_id: Some(turn_id),
            cwd: Some(cwd),
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
        self.bus.emit(HookNotification::ApprovalRequested {
            thread_id,
            turn_id: Some(turn_id),
            cwd: Some(cwd),
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
    }

    pub(crate) fn approval_requested_elicitation(
        &self,
        thread_id: String,
        cwd: String,
        server_name: String,
        request_id: String,
        message: String,
    ) {
        self.bus.emit(HookNotification::ApprovalRequested {
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
            server_name: Some(server_name),
            request_id: Some(request_id),
            message: Some(message),
        });
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
    ) {
        self.bus.emit(HookNotification::ToolCallStarted {
            thread_id,
            turn_id,
            cwd,
            model_request_id,
            attempt,
            tool_name,
            call_id,
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

#[cfg_attr(feature = "hooks-schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct HookPayload {
    schema_version: u32,
    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    event_id: Uuid,
    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    timestamp: DateTime<Utc>,
    #[serde(flatten)]
    notification: HookNotification,
}

impl HookPayload {
    pub fn new(notification: HookNotification) -> Self {
        Self {
            schema_version: 1,
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            notification,
        }
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

    pub fn notification(&self) -> &HookNotification {
        &self.notification
    }

    pub fn event_type(&self) -> &'static str {
        self.notification.event_type()
    }
}

#[cfg_attr(feature = "hooks-schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct HookStdinEnvelope {
    schema_version: u32,
    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    event_id: Uuid,
    #[cfg_attr(feature = "hooks-schema", schemars(with = "String"))]
    timestamp: DateTime<Utc>,
    #[serde(rename = "type")]
    event_type: &'static str,
    payload_path: String,
}

impl HookStdinEnvelope {
    pub fn from_payload(payload: &HookPayload, payload_path: PathBuf) -> Self {
        Self {
            schema_version: payload.schema_version,
            event_id: payload.event_id,
            timestamp: payload.timestamp,
            event_type: payload.event_type(),
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

fn append_hook_payload_jsonl_line(path: &Path, payload: &HookPayload) -> HookResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    set_file_permissions(path, &file)?;
    serde_json::to_writer(&mut file, payload)?;
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
    },
}

impl HookNotification {
    pub fn event_type(&self) -> &'static str {
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

    pub async fn run_hooks_test(
        codex_home: PathBuf,
        hooks: HooksConfig,
        target: HooksTestTarget,
        requested_events: Vec<HooksTestEvent>,
        timeout: Duration,
    ) -> anyhow::Result<HooksTestReport> {
        let logs_dir = codex_home.join("tmp").join("hooks").join("logs");
        let payloads_dir = codex_home.join("tmp").join("hooks").join("payloads");

        let events = resolve_events(target, requested_events);
        let mut invocations = Vec::new();

        for event in events {
            let commands = commands_for_event(&hooks, event, target);
            if commands.is_empty() {
                continue;
            }

            let notification = build_notification_for_test(event);
            let payload = HookPayload::new(notification);
            let payload_json = serde_json::to_vec(&payload)?;
            let stdin_payload = prepare_hook_stdin_payload(
                &payload,
                &payload_json,
                hooks.max_stdin_payload_bytes,
                hooks.keep_last_n_payloads,
                &codex_home,
            );

            for command in commands {
                let exit_code = tokio::time::timeout(
                    timeout,
                    run_hook_command_for_test(
                        command.clone(),
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
                    event_type: payload.event_type(),
                    command,
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
        event: HooksTestEvent,
        target: HooksTestTarget,
    ) -> Vec<Vec<String>> {
        let configured = match event {
            HooksTestEvent::AgentTurnComplete => hooks.agent_turn_complete.clone(),
            HooksTestEvent::ApprovalRequestedExec
            | HooksTestEvent::ApprovalRequestedApplyPatch
            | HooksTestEvent::ApprovalRequestedElicitation => hooks.approval_requested.clone(),
            HooksTestEvent::SessionStart => hooks.session_start.clone(),
            HooksTestEvent::SessionEnd => hooks.session_end.clone(),
            HooksTestEvent::ModelRequestStarted => hooks.model_request_started.clone(),
            HooksTestEvent::ModelResponseCompleted => hooks.model_response_completed.clone(),
            HooksTestEvent::ToolCallStarted => hooks.tool_call_started.clone(),
            HooksTestEvent::ToolCallFinished => hooks.tool_call_finished.clone(),
        };

        match target {
            HooksTestTarget::Configured => configured,
            HooksTestTarget::All => configured,
        }
    }

    fn build_notification_for_test(event: HooksTestEvent) -> HookNotification {
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
                Ok(contents) => return Ok(contents),
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
        let payload = HookPayload::new(HookNotification::ApprovalRequested {
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
                    .get("type")
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
        assert_eq!(first["event"]["type"], "session-start");

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
            fn on_event(&self, _ctx: &HookContext, _payload: &HookPayload) -> HookResult {
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
            }],
            InprocHookPolicy {
                queue_capacity: 8,
                timeout: Duration::from_millis(10),
                failure_threshold: 1,
                circuit_breaker_open_duration: Duration::from_millis(200),
            },
        );

        let payload = HookPayload::new(HookNotification::SessionStart {
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
            fn on_event(&self, _ctx: &HookContext, _payload: &HookPayload) -> HookResult {
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
            }],
            InprocHookPolicy {
                queue_capacity: 8,
                timeout: Duration::from_millis(50),
                failure_threshold: 1,
                circuit_breaker_open_duration: Duration::from_millis(200),
            },
        );

        let payload = HookPayload::new(HookNotification::SessionStart {
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
}
