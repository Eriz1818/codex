use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use codex_app_server_protocol::AuthMode;
use codex_backend_client::Client as BackendClient;
use codex_core::config::Config;
use codex_core::config::ConstraintResult;
use codex_core::config::types::Notifications;
use codex_core::features::Feature;
use codex_core::git_info::GitHeadState;
use codex_core::git_info::GitWorktreeEntry;
use codex_core::git_info::current_branch_name;
use codex_core::git_info::local_git_branches;
use codex_core::models_manager::manager::ModelsManager;
use codex_core::project_doc::DEFAULT_PROJECT_DOC_FILENAME;
use codex_core::protocol::AgentMessageDeltaEvent;
use codex_core::protocol::AgentMessageEvent;
use codex_core::protocol::AgentReasoningDeltaEvent;
use codex_core::protocol::AgentReasoningEvent;
use codex_core::protocol::AgentReasoningRawContentDeltaEvent;
use codex_core::protocol::AgentReasoningRawContentEvent;
use codex_core::protocol::ApplyPatchApprovalRequestEvent;
use codex_core::protocol::BackgroundEventEvent;
use codex_core::protocol::CreditsSnapshot;
use codex_core::protocol::DeprecationNoticeEvent;
use codex_core::protocol::ErrorEvent;
use codex_core::protocol::Event;
use codex_core::protocol::EventMsg;
use codex_core::protocol::ExecApprovalRequestEvent;
use codex_core::protocol::ExecCommandBeginEvent;
use codex_core::protocol::ExecCommandEndEvent;
use codex_core::protocol::ExecCommandSource;
use codex_core::protocol::ExitedReviewModeEvent;
use codex_core::protocol::HookProcessBeginEvent;
use codex_core::protocol::HookProcessEndEvent;
use codex_core::protocol::ListCustomPromptsResponseEvent;
use codex_core::protocol::ListSkillsResponseEvent;
use codex_core::protocol::McpListToolsResponseEvent;
use codex_core::protocol::McpStartupCompleteEvent;
use codex_core::protocol::McpStartupStatus;
use codex_core::protocol::McpStartupUpdateEvent;
use codex_core::protocol::McpToolCallBeginEvent;
use codex_core::protocol::McpToolCallEndEvent;
use codex_core::protocol::Op;
use codex_core::protocol::PatchApplyBeginEvent;
use codex_core::protocol::RateLimitSnapshot;
use codex_core::protocol::ReviewRequest;
use codex_core::protocol::ReviewTarget;
use codex_core::protocol::SkillsListEntry;
use codex_core::protocol::StreamErrorEvent;
use codex_core::protocol::TerminalInteractionEvent;
use codex_core::protocol::TokenUsage;
use codex_core::protocol::TokenUsageInfo;
use codex_core::protocol::TurnAbortReason;
use codex_core::protocol::TurnCompleteEvent;
use codex_core::protocol::TurnDiffEvent;
use codex_core::protocol::UndoCompletedEvent;
use codex_core::protocol::UndoStartedEvent;
use codex_core::protocol::UserMessageEvent;
use codex_core::protocol::ViewImageToolCallEvent;
use codex_core::protocol::WarningEvent;
use codex_core::protocol::WebSearchBeginEvent;
use codex_core::protocol::WebSearchEndEvent;
use codex_core::skills::model::SkillMetadata;
use codex_protocol::ThreadId;
use codex_protocol::account::PlanType;
use codex_protocol::approvals::ElicitationRequestEvent;
use codex_protocol::parse_command::ParsedCommand;
use codex_protocol::user_input::UserInput;
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use rand::Rng;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::debug;

use crate::app_event::AppEvent;
#[cfg(target_os = "windows")]
use crate::app_event::WindowsSandboxEnableMode;
use crate::app_event::WindowsSandboxFallbackReason;
use crate::app_event_sender::AppEventSender;
use crate::bottom_pane::ApprovalRequest;
use crate::bottom_pane::BottomPane;
use crate::bottom_pane::BottomPaneParams;
use crate::bottom_pane::CancellationEvent;
use crate::bottom_pane::InputResult;
use crate::bottom_pane::SelectionAction;
use crate::bottom_pane::SelectionItem;
use crate::bottom_pane::SelectionViewParams;
use crate::bottom_pane::custom_prompt_view::CustomPromptView;
use crate::bottom_pane::parse_slash_name;
use crate::bottom_pane::popup_consts::standard_popup_hint_line;
use crate::clipboard_paste::paste_image_to_temp_png;
use crate::diff_render::display_path_for;
use crate::exec_cell::CommandOutput;
use crate::exec_cell::ExecCell;
use crate::exec_cell::new_active_exec_command;
use crate::exec_command::strip_bash_lc_and_escape;
use crate::get_git_diff::get_git_diff;
use crate::history_cell;
use crate::history_cell::AgentMessageCell;
use crate::history_cell::CompositeHistoryCell;
use crate::history_cell::HistoryCell;
use crate::history_cell::McpToolCallCell;
use crate::history_cell::PlainHistoryCell;
use crate::markdown::append_markdown;
use crate::render::Insets;
use crate::render::renderable::ColumnRenderable;
use crate::render::renderable::FlexRenderable;
use crate::render::renderable::Renderable;
use crate::render::renderable::RenderableExt;
use crate::render::renderable::RenderableItem;
use crate::slash_command::SlashCommand;
use crate::status::RateLimitSnapshotDisplay;
use crate::text_formatting::truncate_text;
use crate::tui::FrameRequester;
mod interrupts;
use self::interrupts::InterruptManager;
mod agent;
use self::agent::spawn_agent;
use self::agent::spawn_agent_from_existing;
mod session_header;
use self::session_header::SessionHeader;
use crate::streaming::controller::StreamController;
use std::path::Path;

use chrono::Local;
use codex_common::approval_presets::ApprovalPreset;
use codex_common::approval_presets::builtin_approval_presets;
use codex_core::AuthManager;
use codex_core::CodexAuth;
use codex_core::ThreadManager;
use codex_core::protocol::AskForApproval;
use codex_core::protocol::SandboxPolicy;
use codex_file_search::FileMatch;
use codex_protocol::openai_models::ModelPreset;
use codex_protocol::openai_models::ReasoningEffort as ReasoningEffortConfig;
use codex_protocol::plan_tool::UpdatePlanArgs;
use strum::IntoEnumIterator;

const USER_SHELL_COMMAND_HELP_TITLE: &str = "Prefix a command with ! to run it locally";
const USER_SHELL_COMMAND_HELP_HINT: &str = "Example: !ls";
// Track information about an in-flight exec command.
struct RunningCommand {
    command: Vec<String>,
    parsed_cmd: Vec<ParsedCommand>,
    source: ExecCommandSource,
}

struct UnifiedExecSessionSummary {
    key: String,
    command_display: String,
}

struct HookProcessSummary {
    key: String,
    command_display: String,
}

struct UnifiedExecWaitState {
    command_display: String,
}

impl UnifiedExecWaitState {
    fn new(command_display: String) -> Self {
        Self { command_display }
    }

    fn is_duplicate(&self, command_display: &str) -> bool {
        self.command_display == command_display
    }
}

const RATE_LIMIT_WARNING_THRESHOLDS: [f64; 3] = [75.0, 90.0, 95.0];
const NUDGE_MODEL_SLUG: &str = "gpt-5.1-codex-mini";
const RATE_LIMIT_SWITCH_PROMPT_THRESHOLD: f64 = 90.0;

#[derive(Default)]
struct RateLimitWarningState {
    secondary_index: usize,
    primary_index: usize,
}

impl RateLimitWarningState {
    fn take_warnings(
        &mut self,
        secondary_used_percent: Option<f64>,
        secondary_window_minutes: Option<i64>,
        primary_used_percent: Option<f64>,
        primary_window_minutes: Option<i64>,
    ) -> Vec<String> {
        let reached_secondary_cap =
            matches!(secondary_used_percent, Some(percent) if percent == 100.0);
        let reached_primary_cap = matches!(primary_used_percent, Some(percent) if percent == 100.0);
        if reached_secondary_cap || reached_primary_cap {
            return Vec::new();
        }

        let mut warnings = Vec::new();

        if let Some(secondary_used_percent) = secondary_used_percent {
            let mut highest_secondary: Option<f64> = None;
            while self.secondary_index < RATE_LIMIT_WARNING_THRESHOLDS.len()
                && secondary_used_percent >= RATE_LIMIT_WARNING_THRESHOLDS[self.secondary_index]
            {
                highest_secondary = Some(RATE_LIMIT_WARNING_THRESHOLDS[self.secondary_index]);
                self.secondary_index += 1;
            }
            if let Some(threshold) = highest_secondary {
                let limit_label = secondary_window_minutes
                    .map(get_limits_duration)
                    .unwrap_or_else(|| "weekly".to_string());
                let remaining_percent = 100.0 - threshold;
                warnings.push(format!(
                    "Heads up, you have less than {remaining_percent:.0}% of your {limit_label} limit left. Run /status for a breakdown."
                ));
            }
        }

        if let Some(primary_used_percent) = primary_used_percent {
            let mut highest_primary: Option<f64> = None;
            while self.primary_index < RATE_LIMIT_WARNING_THRESHOLDS.len()
                && primary_used_percent >= RATE_LIMIT_WARNING_THRESHOLDS[self.primary_index]
            {
                highest_primary = Some(RATE_LIMIT_WARNING_THRESHOLDS[self.primary_index]);
                self.primary_index += 1;
            }
            if let Some(threshold) = highest_primary {
                let limit_label = primary_window_minutes
                    .map(get_limits_duration)
                    .unwrap_or_else(|| "5h".to_string());
                let remaining_percent = 100.0 - threshold;
                warnings.push(format!(
                    "Heads up, you have less than {remaining_percent:.0}% of your {limit_label} limit left. Run /status for a breakdown."
                ));
            }
        }

        warnings
    }
}

pub(crate) fn get_limits_duration(windows_minutes: i64) -> String {
    const MINUTES_PER_HOUR: i64 = 60;
    const MINUTES_PER_DAY: i64 = 24 * MINUTES_PER_HOUR;
    const MINUTES_PER_WEEK: i64 = 7 * MINUTES_PER_DAY;
    const MINUTES_PER_MONTH: i64 = 30 * MINUTES_PER_DAY;
    const ROUNDING_BIAS_MINUTES: i64 = 3;

    let windows_minutes = windows_minutes.max(0);

    if windows_minutes <= MINUTES_PER_DAY.saturating_add(ROUNDING_BIAS_MINUTES) {
        let adjusted = windows_minutes.saturating_add(ROUNDING_BIAS_MINUTES);
        let hours = std::cmp::max(1, adjusted / MINUTES_PER_HOUR);
        format!("{hours}h")
    } else if windows_minutes <= MINUTES_PER_WEEK.saturating_add(ROUNDING_BIAS_MINUTES) {
        "weekly".to_string()
    } else if windows_minutes <= MINUTES_PER_MONTH.saturating_add(ROUNDING_BIAS_MINUTES) {
        "monthly".to_string()
    } else {
        "annual".to_string()
    }
}

/// Common initialization parameters shared by all `ChatWidget` constructors.
pub(crate) struct ChatWidgetInit {
    pub(crate) config: Config,
    pub(crate) frame_requester: FrameRequester,
    pub(crate) app_event_tx: AppEventSender,
    pub(crate) initial_prompt: Option<String>,
    pub(crate) initial_images: Vec<PathBuf>,
    pub(crate) enhanced_keys_supported: bool,
    pub(crate) auth_manager: Arc<AuthManager>,
    pub(crate) models_manager: Arc<ModelsManager>,
    pub(crate) feedback: codex_feedback::CodexFeedback,
    pub(crate) is_first_run: bool,
    pub(crate) model: String,
}

#[derive(Default)]
enum RateLimitSwitchPromptState {
    #[default]
    Idle,
    Pending,
    Shown,
}

pub(crate) struct ChatWidget {
    app_event_tx: AppEventSender,
    codex_op_tx: UnboundedSender<Op>,
    bottom_pane: BottomPane,
    active_cell: Option<Box<dyn HistoryCell>>,
    config: Config,
    model: String,
    auth_manager: Arc<AuthManager>,
    models_manager: Arc<ModelsManager>,
    session_header: SessionHeader,
    initial_user_message: Option<UserMessage>,
    auto_compact_enabled: bool,
    token_info: Option<TokenUsageInfo>,
    footer_token_info: Option<TokenUsageInfo>,
    pending_footer_token_info: Option<TokenUsageInfo>,
    footer_token_info_at_task_start: Option<i64>,
    context_estimate_details_visible: bool,
    last_context_estimate_details_update: Option<Instant>,
    last_context_estimate_details_percent: Option<i64>,
    rate_limit_snapshot: Option<RateLimitSnapshotDisplay>,
    plan_type: Option<PlanType>,
    rate_limit_warnings: RateLimitWarningState,
    rate_limit_switch_prompt: RateLimitSwitchPromptState,
    rate_limit_poller: Option<JoinHandle<()>>,
    status_bar_git_poller: Option<JoinHandle<()>>,
    worktree_list: Vec<GitWorktreeEntry>,
    worktree_list_error: Option<String>,
    worktree_list_refresh_in_progress: bool,
    shared_dirs_write_notice_shown: bool,
    // Stream lifecycle controller
    stream_controller: Option<StreamController>,
    running_commands: HashMap<String, RunningCommand>,
    suppressed_exec_calls: HashSet<String>,
    last_unified_wait: Option<UnifiedExecWaitState>,
    task_complete_pending: bool,
    unified_exec_sessions: Vec<UnifiedExecSessionSummary>,
    hook_processes: Vec<HookProcessSummary>,
    mcp_startup_status: Option<HashMap<String, McpStartupStatus>>,
    mcp_failed_servers: Vec<String>,
    mcp_startup_started_at: Option<Instant>,
    mcp_startup_duration: Option<Duration>,
    mcp_server_start_times: HashMap<String, Instant>,
    mcp_startup_durations: HashMap<String, Duration>,
    // Queue of interruptive UI events deferred during an active write cycle
    interrupts: InterruptManager,
    // Accumulates the current reasoning block text to extract a header
    reasoning_buffer: String,
    // Accumulates full reasoning content for transcript-only recording
    full_reasoning_buffer: String,
    // Current status header shown in the status indicator.
    current_status_header: String,
    // Previous status header to restore after a transient stream retry.
    retry_status_header: Option<String>,
    ramp_turn_index: u64,
    ramp_selected: crate::ramps::RampId,
    ramp_stage: crate::ramps::RampStage,
    ramp_context: Option<String>,
    last_turn_completion_label: Option<String>,
    conversation_id: Option<ThreadId>,
    frame_requester: FrameRequester,
    // Whether to include the initial welcome banner on session configured
    show_welcome_banner: bool,
    // When resuming an existing session (selected via resume picker or backtrack fork), avoid an
    // immediate redraw on SessionConfigured to prevent a gratuitous UI flicker.
    suppress_session_configured_redraw: bool,
    // User messages queued while a turn is in progress
    queued_user_messages: VecDeque<UserMessage>,
    // Pending notification to show when unfocused on next Draw
    pending_notification: Option<Notification>,
    // Simple review mode flag; used to adjust layout and banners.
    is_review_mode: bool,
    // Snapshot of token usage to restore after review mode exits.
    pre_review_token_info: Option<Option<TokenUsageInfo>>,
    // Whether to add a final message separator after the last message
    needs_final_message_separator: bool,
    turn_summary: history_cell::TurnSummary,
    session_stats: crate::status::SessionStats,

    last_rendered_width: std::cell::Cell<Option<usize>>,
    // Feedback sink for /feedback
    feedback: codex_feedback::CodexFeedback,
    // Current session rollout path (if known)
    current_rollout_path: Option<PathBuf>,
}

struct UserMessage {
    text: String,
    image_paths: Vec<PathBuf>,
}

impl From<String> for UserMessage {
    fn from(text: String) -> Self {
        Self {
            text,
            image_paths: Vec::new(),
        }
    }
}

impl From<&str> for UserMessage {
    fn from(text: &str) -> Self {
        Self {
            text: text.to_string(),
            image_paths: Vec::new(),
        }
    }
}

fn create_initial_user_message(text: String, image_paths: Vec<PathBuf>) -> Option<UserMessage> {
    if text.is_empty() && image_paths.is_empty() {
        None
    } else {
        Some(UserMessage { text, image_paths })
    }
}

impl ChatWidget {
    fn flush_answer_stream_with_separator(&mut self) {
        if let Some(mut controller) = self.stream_controller.take()
            && let Some(cell) = controller.finalize()
        {
            self.add_boxed_history(cell);
        }
    }

    /// Update the status indicator header and details.
    ///
    /// Passing `None` clears any existing details.
    fn set_status(&mut self, header: String, details: Option<String>) {
        self.current_status_header = header.clone();
        self.bottom_pane.update_status(header, details);
    }

    /// Convenience wrapper around [`Self::set_status`];
    /// updates the status indicator header and clears any existing details.
    fn set_status_header(&mut self, header: String) {
        self.set_status(header, None);
    }

    fn ramps_status_enabled(&self) -> bool {
        crate::ramps::ramps_enabled()
    }

    fn ramps_status_active(&self) -> bool {
        self.ramps_status_enabled() && self.bottom_pane.is_task_running()
    }

    fn ramp_header_string(&self) -> String {
        let stage = crate::ramps::stage_label(self.ramp_selected, self.ramp_stage);
        if let Some(context) = self.ramp_context.as_deref()
            && !context.is_empty()
        {
            format!("{stage} · {context}")
        } else {
            stage.to_string()
        }
    }

    fn sync_ramp_status_header(&mut self) {
        if !self.ramps_status_active() {
            return;
        }
        self.set_status_header(self.ramp_header_string());
    }

    fn set_ramp_stage(&mut self, stage: crate::ramps::RampStage) {
        if !self.ramps_status_active() || self.ramp_stage == stage {
            return;
        }
        self.ramp_stage = stage;
        self.sync_ramp_status_header();
    }

    fn set_ramp_context(&mut self, context: Option<String>) {
        if !self.ramps_status_active() && context.is_some() {
            return;
        }
        if self.ramp_context == context {
            return;
        }
        self.ramp_context = context;
        self.sync_ramp_status_header();
    }

    fn restore_retry_status_header_if_present(&mut self) {
        if let Some(header) = self.retry_status_header.take() {
            self.set_status_header(header);
        }
    }

    // --- Small event handlers ---
    fn on_session_configured(&mut self, event: codex_core::protocol::SessionConfiguredEvent) {
        self.mcp_startup_started_at = Some(Instant::now());
        self.mcp_startup_duration = None;
        self.mcp_startup_status = None;
        self.mcp_failed_servers.clear();
        self.set_mcp_startup_banner(None);
        self.mcp_server_start_times.clear();
        self.mcp_startup_durations.clear();
        self.bottom_pane
            .set_history_metadata(event.history_log_id, event.history_entry_count);
        self.set_skills(None);
        self.conversation_id = Some(event.session_id);
        self.current_rollout_path = Some(event.rollout_path.clone());
        let initial_messages = event.initial_messages.clone();
        let model_for_header = event.model.clone();
        self.session_header.set_model(&model_for_header);
        self.add_to_history(history_cell::new_session_info(
            &self.config,
            &model_for_header,
            event,
            self.show_welcome_banner,
        ));
        if let Some(messages) = initial_messages {
            self.replay_initial_messages(messages);
        }
        // Ask codex-core to enumerate custom prompts for this session.
        self.submit_op(Op::ListCustomPrompts);
        self.submit_op(Op::ListSkills {
            cwds: Vec::new(),
            force_reload: false,
        });
        if let Some(user_message) = self.initial_user_message.take() {
            self.submit_user_message(user_message);
        }
        if !self.suppress_session_configured_redraw {
            self.request_redraw();
        }
    }

    fn set_skills(&mut self, skills: Option<Vec<SkillMetadata>>) {
        self.bottom_pane.set_skills(skills);
    }

    fn set_skills_from_response(&mut self, response: &ListSkillsResponseEvent) {
        let skills = skills_for_cwd(&self.config.cwd, &response.skills);
        self.set_skills(Some(skills));
    }

    pub(crate) fn open_feedback_note(
        &mut self,
        category: crate::app_event::FeedbackCategory,
        include_logs: bool,
    ) {
        // Build a fresh snapshot at the time of opening the note overlay.
        let snapshot = self.feedback.snapshot(self.conversation_id);
        let rollout = if include_logs {
            self.current_rollout_path.clone()
        } else {
            None
        };
        let view = crate::bottom_pane::FeedbackNoteView::new(
            category,
            snapshot,
            rollout,
            self.app_event_tx.clone(),
            include_logs,
        );
        self.bottom_pane.show_view(Box::new(view));
        self.request_redraw();
    }

    pub(crate) fn open_feedback_consent(&mut self, category: crate::app_event::FeedbackCategory) {
        let params = crate::bottom_pane::feedback_upload_consent_params(
            self.app_event_tx.clone(),
            category,
            self.current_rollout_path.clone(),
        );
        self.bottom_pane.show_selection_view(params);
        self.request_redraw();
    }

    fn on_agent_message(&mut self, message: String) {
        // If we have a stream_controller, then the final agent message is redundant and will be a
        // duplicate of what has already been streamed.
        if self.stream_controller.is_none() {
            self.handle_streaming_delta(message);
        }
        self.flush_answer_stream_with_separator();
        self.handle_stream_finished();
        self.request_redraw();
    }

    fn on_agent_message_delta(&mut self, delta: String) {
        self.handle_streaming_delta(delta);
    }

    fn on_agent_reasoning_delta(&mut self, delta: String) {
        if self.config.hide_agent_reasoning {
            return;
        }

        // For reasoning deltas, do not stream to history. Accumulate the
        // current reasoning block and extract the first bold element
        // (between **/**) as the chunk header. Show this header as status.
        self.reasoning_buffer.push_str(&delta);

        if !self.config.hide_agent_reasoning
            && let Some(header) = extract_first_bold(&self.reasoning_buffer)
        {
            // Update the shimmer header to the extracted reasoning chunk header.
            if self.ramps_status_active() {
                self.set_ramp_context(Some(header));
            } else {
                self.set_status_header(header);
            }
        } else {
            // Fallback while we don't yet have a bold header: leave existing header as-is.
        }
        self.request_redraw();
    }

    fn on_agent_reasoning_final(&mut self) {
        if self.config.hide_agent_reasoning {
            self.reasoning_buffer.clear();
            self.full_reasoning_buffer.clear();
            return;
        }

        // At the end of a reasoning block, record transcript-only content.
        self.full_reasoning_buffer.push_str(&self.reasoning_buffer);
        if !self.full_reasoning_buffer.is_empty() {
            let cell = history_cell::new_reasoning_summary_block_with_visibility(
                self.full_reasoning_buffer.clone(),
                self.config.hide_agent_reasoning,
            );
            self.add_boxed_history(cell);
        }
        self.reasoning_buffer.clear();
        self.full_reasoning_buffer.clear();
        self.request_redraw();
    }

    fn on_reasoning_section_break(&mut self) {
        if self.config.hide_agent_reasoning {
            self.reasoning_buffer.clear();
            self.full_reasoning_buffer.clear();
            return;
        }

        // Start a new reasoning block for header extraction and accumulate transcript.
        self.full_reasoning_buffer.push_str(&self.reasoning_buffer);
        self.full_reasoning_buffer.push_str("\n\n");
        self.reasoning_buffer.clear();
    }

    // Raw reasoning uses the same flow as summarized reasoning

    fn on_task_started(&mut self) {
        self.bottom_pane.clear_ctrl_c_quit_hint();
        self.bottom_pane.set_task_running(true);
        self.retry_status_header = None;
        self.bottom_pane.set_interrupt_hint_visible(true);
        self.turn_summary = history_cell::TurnSummary::default();
        self.last_turn_completion_label = None;
        if self.ramps_status_enabled() {
            self.ramp_turn_index = self.ramp_turn_index.saturating_add(1);
            self.ramp_selected = crate::ramps::select_ramp(&self.config, self.ramp_turn_index);
            self.ramp_stage = crate::ramps::RampStage::Waiting;
            self.ramp_context = None;
            self.sync_ramp_status_header();
        } else {
            let header = if crate::xtreme::xtreme_ui_enabled(&self.config) {
                "Charging"
            } else {
                "Working"
            };
            self.set_status_header(header.to_string());
        }
        self.footer_token_info_at_task_start = self
            .footer_token_info
            .as_ref()
            .map(|info| info.last_token_usage.total_tokens);
        self.pending_footer_token_info = None;
        self.full_reasoning_buffer.clear();
        self.reasoning_buffer.clear();
        self.request_redraw();
    }

    fn on_task_complete(&mut self, last_agent_message: Option<String>) {
        // If a stream is currently active, finalize it.
        self.flush_answer_stream_with_separator();
        if self.ramps_status_enabled() {
            self.last_turn_completion_label =
                Some(crate::ramps::completion_label(self.ramp_selected).to_string());
        }
        // Mark task stopped and request redraw now that all content is in history.
        self.bottom_pane.set_task_running(false);
        self.apply_pending_footer_token_info_if_needed();
        self.running_commands.clear();
        self.suppressed_exec_calls.clear();
        self.last_unified_wait = None;
        self.request_redraw();

        // If there is a queued user message, send exactly one now to begin the next turn.
        self.maybe_send_next_queued_input();
        // Emit a notification when the turn completes (suppressed if focused).
        self.notify(Notification::AgentTurnComplete {
            response: last_agent_message.unwrap_or_default(),
        });

        self.maybe_show_pending_rate_limit_prompt();
        self.session_stats.turns_completed = self.session_stats.turns_completed.saturating_add(1);
    }

    pub(crate) fn set_token_info(&mut self, info: Option<TokenUsageInfo>) {
        match info {
            Some(info) => self.apply_token_info(info),
            None => {
                self.bottom_pane.set_context_window(None, None);
                self.token_info = None;
                self.footer_token_info = None;
                self.pending_footer_token_info = None;
                self.footer_token_info_at_task_start = None;
                self.context_estimate_details_visible = false;
                self.last_context_estimate_details_update = None;
                self.last_context_estimate_details_percent = None;
            }
        }
    }

    fn apply_pending_footer_token_info_if_needed(&mut self) {
        let Some(pending) = self.pending_footer_token_info.take() else {
            self.footer_token_info_at_task_start = None;
            return;
        };

        let footer_tokens = self
            .footer_token_info
            .as_ref()
            .map(|info| info.last_token_usage.total_tokens);
        if footer_tokens == self.footer_token_info_at_task_start {
            self.apply_footer_token_info(Some(pending));
        }

        self.footer_token_info_at_task_start = None;
    }

    fn clear_context_estimate_details_if_visible(&mut self) {
        if self.context_estimate_details_visible && self.current_status_header == "Working" {
            self.context_estimate_details_visible = false;
            self.last_context_estimate_details_update = None;
            self.last_context_estimate_details_percent = None;
            self.set_status(self.current_status_header.clone(), None);
        }
    }

    fn maybe_update_context_estimate_details(&mut self, info: &TokenUsageInfo) {
        if self.current_status_header != "Working" {
            return;
        }

        let percent = self.context_remaining_percent(info);
        if matches!(percent, Some(0)) {
            self.clear_context_estimate_details_if_visible();
            return;
        }

        let now = Instant::now();
        if let Some(last) = self.last_context_estimate_details_update
            && now.duration_since(last) < Duration::from_secs(2)
            && percent == self.last_context_estimate_details_percent
        {
            return;
        }

        self.last_context_estimate_details_percent = percent;
        self.last_context_estimate_details_update = Some(now);

        let details = if let Some(percent) = percent {
            format!("Est. next request: {percent}% context left")
        } else {
            format!(
                "Est. next request: ~{} tokens",
                info.last_token_usage.total_tokens
            )
        };

        self.context_estimate_details_visible = true;
        self.set_status(self.current_status_header.clone(), Some(details));
    }

    fn looks_like_prompt_estimate(info: &TokenUsageInfo) -> bool {
        let last = &info.last_token_usage;
        last.input_tokens == 0
            && last.cached_input_tokens == 0
            && last.output_tokens == 0
            && last.reasoning_output_tokens == 0
    }

    fn apply_token_info(&mut self, info: TokenUsageInfo) {
        let is_estimate = Self::looks_like_prompt_estimate(&info);
        self.token_info = Some(info.clone());

        if is_estimate && self.bottom_pane.is_task_running() {
            self.maybe_update_context_estimate_details(&info);
        } else {
            self.clear_context_estimate_details_if_visible();
        }

        if is_estimate && self.bottom_pane.is_task_running() && self.footer_token_info.is_some() {
            // Avoid jarring swings (especially to 0%) while a turn is in progress.
            // Keep showing the last known stable value until we receive real API usage.
            self.pending_footer_token_info = Some(info);
            return;
        }

        self.pending_footer_token_info = None;
        self.apply_footer_token_info(Some(info));
    }

    fn apply_footer_token_info(&mut self, info: Option<TokenUsageInfo>) {
        let Some(info) = info else {
            self.bottom_pane.set_context_window(None, None);
            self.footer_token_info = None;
            return;
        };

        let percent = self.context_remaining_percent(&info);
        let used_tokens = self.context_used_tokens(&info, percent.is_some());
        self.bottom_pane.set_context_window(percent, used_tokens);
        self.footer_token_info = Some(info);
    }

    fn context_remaining_percent(&self, info: &TokenUsageInfo) -> Option<i64> {
        info.model_context_window
            .or(info.full_model_context_window)
            .map(|window| {
                info.last_token_usage
                    .percent_of_context_window_remaining(window)
            })
    }

    fn context_used_tokens(&self, info: &TokenUsageInfo, percent_known: bool) -> Option<i64> {
        if percent_known {
            return None;
        }

        Some(info.total_token_usage.tokens_in_context_window())
    }

    fn restore_pre_review_token_info(&mut self) {
        if let Some(saved) = self.pre_review_token_info.take() {
            match saved {
                Some(info) => self.apply_token_info(info),
                None => {
                    self.bottom_pane.set_context_window(None, None);
                    self.token_info = None;
                    self.footer_token_info = None;
                    self.pending_footer_token_info = None;
                    self.footer_token_info_at_task_start = None;
                    self.context_estimate_details_visible = false;
                    self.last_context_estimate_details_update = None;
                    self.last_context_estimate_details_percent = None;
                }
            }
        }
    }

    pub(crate) fn on_rate_limit_snapshot(&mut self, snapshot: Option<RateLimitSnapshot>) {
        if let Some(mut snapshot) = snapshot {
            if snapshot.credits.is_none() {
                snapshot.credits = self
                    .rate_limit_snapshot
                    .as_ref()
                    .and_then(|display| display.credits.as_ref())
                    .map(|credits| CreditsSnapshot {
                        has_credits: credits.has_credits,
                        unlimited: credits.unlimited,
                        balance: credits.balance.clone(),
                    });
            }

            self.plan_type = snapshot.plan_type.or(self.plan_type);

            let warnings = self.rate_limit_warnings.take_warnings(
                snapshot
                    .secondary
                    .as_ref()
                    .map(|window| window.used_percent),
                snapshot
                    .secondary
                    .as_ref()
                    .and_then(|window| window.window_minutes),
                snapshot.primary.as_ref().map(|window| window.used_percent),
                snapshot
                    .primary
                    .as_ref()
                    .and_then(|window| window.window_minutes),
            );

            let high_usage = snapshot
                .secondary
                .as_ref()
                .map(|w| w.used_percent >= RATE_LIMIT_SWITCH_PROMPT_THRESHOLD)
                .unwrap_or(false)
                || snapshot
                    .primary
                    .as_ref()
                    .map(|w| w.used_percent >= RATE_LIMIT_SWITCH_PROMPT_THRESHOLD)
                    .unwrap_or(false);

            if high_usage
                && !self.rate_limit_switch_prompt_hidden()
                && self.model != NUDGE_MODEL_SLUG
                && !matches!(
                    self.rate_limit_switch_prompt,
                    RateLimitSwitchPromptState::Shown
                )
            {
                self.rate_limit_switch_prompt = RateLimitSwitchPromptState::Pending;
            }

            let display = crate::status::rate_limit_snapshot_display(&snapshot, Local::now());
            self.rate_limit_snapshot = Some(display);

            if !warnings.is_empty() {
                for warning in warnings {
                    self.add_to_history(history_cell::new_warning_event(warning));
                }
                self.request_redraw();
            }
        } else {
            self.rate_limit_snapshot = None;
        }
    }
    /// Finalize any active exec as failed and stop/clear running UI state.
    fn finalize_turn(&mut self) {
        // Ensure any spinner is replaced by a red ✗ and flushed into history.
        self.finalize_active_cell_as_failed();
        // Reset running state and clear streaming buffers.
        self.bottom_pane.set_task_running(false);
        self.apply_pending_footer_token_info_if_needed();
        self.running_commands.clear();
        self.suppressed_exec_calls.clear();
        self.last_unified_wait = None;
        self.stream_controller = None;
        self.maybe_show_pending_rate_limit_prompt();
    }

    fn on_error(&mut self, message: String) {
        self.finalize_turn();
        self.add_to_history(history_cell::new_error_event(message));
        self.request_redraw();

        // After an error ends the turn, try sending the next queued input.
        self.maybe_send_next_queued_input();
    }

    fn on_warning(&mut self, message: impl Into<String>) {
        self.add_to_history(history_cell::new_warning_event(message.into()));
        self.request_redraw();
    }

    fn set_mcp_startup_banner(&mut self, message: Option<String>) {
        self.bottom_pane.set_mcp_startup_banner(message);
    }

    fn parse_timeout_seconds(error: &str) -> Option<u64> {
        let lower = error.to_ascii_lowercase();
        if !lower.contains("timed out") {
            return None;
        }

        let after_idx = lower.rfind("after ")?;
        let mut digits = String::new();
        for ch in lower[after_idx + "after ".len()..].chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
            } else if !digits.is_empty() {
                break;
            }
        }
        if digits.is_empty() {
            return None;
        }
        digits.parse().ok()
    }

    fn timeout_tip_for_failure(server: &str, error: &str) -> Option<String> {
        let secs = Self::parse_timeout_seconds(error);
        if secs.is_none() && !error.to_ascii_lowercase().contains("timed out") {
            return None;
        }

        let suggested = secs.map_or(30, |secs| std::cmp::max(30, secs.saturating_mul(3)));
        Some(format!(
            "Tip: increase startup timeout: `/mcp timeout {server} {suggested}`."
        ))
    }

    fn timeout_tip_for_failures(
        failures: &[codex_core::protocol::McpStartupFailure],
    ) -> Option<String> {
        failures
            .iter()
            .find_map(|failure| Self::timeout_tip_for_failure(&failure.server, &failure.error))
    }

    fn on_mcp_startup_update(&mut self, ev: McpStartupUpdateEvent) {
        let mut status = self.mcp_startup_status.take().unwrap_or_default();
        let now = Instant::now();
        match &ev.status {
            McpStartupStatus::Starting => {
                self.mcp_server_start_times.insert(ev.server.clone(), now);
                self.mcp_startup_durations.remove(&ev.server);
            }
            McpStartupStatus::Ready
            | McpStartupStatus::Cancelled
            | McpStartupStatus::Failed { .. } => {
                if let Some(started_at) = self.mcp_server_start_times.remove(&ev.server) {
                    self.mcp_startup_durations
                        .insert(ev.server.clone(), now.saturating_duration_since(started_at));
                }
            }
        }
        status.insert(ev.server, ev.status);
        self.mcp_startup_status = Some(status);
        self.bottom_pane.set_task_running(true);
        if let Some(current) = &self.mcp_startup_status {
            let total = current.len();
            let mut starting: Vec<_> = current
                .iter()
                .filter_map(|(name, state)| {
                    if matches!(state, McpStartupStatus::Starting) {
                        Some(name)
                    } else {
                        None
                    }
                })
                .collect();
            starting.sort();
            if let Some(first) = starting.first() {
                let completed = total.saturating_sub(starting.len());
                let max_to_show = 3;
                let mut to_show: Vec<String> = starting
                    .iter()
                    .take(max_to_show)
                    .map(ToString::to_string)
                    .collect();
                if starting.len() > max_to_show {
                    to_show.push("…".to_string());
                }
                let header = if total > 1 {
                    format!(
                        "Starting MCP servers ({completed}/{total}): {}",
                        to_show.join(", ")
                    )
                } else {
                    format!("Booting MCP server: {first}")
                };
                self.set_status_header(header);
            }
        }
        self.request_redraw();
    }

    fn on_mcp_startup_complete(&mut self, ev: McpStartupCompleteEvent) {
        let now = Instant::now();
        if let Some(started_at) = self.mcp_startup_started_at {
            self.mcp_startup_duration = Some(now.saturating_duration_since(started_at));
        }

        let mut retryable: std::collections::BTreeSet<String> =
            self.mcp_failed_servers.drain(..).collect();
        for server in &ev.ready {
            retryable.remove(server);
        }
        for failure in &ev.failed {
            retryable.insert(failure.server.clone());
        }
        for server in &ev.cancelled {
            retryable.insert(server.clone());
        }
        self.mcp_failed_servers = retryable.into_iter().collect();

        if self.mcp_failed_servers.is_empty() {
            self.set_mcp_startup_banner(None);
        } else {
            let mut parts = Vec::new();
            if !ev.failed.is_empty() {
                let failed_servers: Vec<_> = ev.failed.iter().map(|f| f.server.as_str()).collect();
                let failed = failed_servers.join(", ");
                parts.push(format!("failed: {failed}"));
            }
            if !ev.cancelled.is_empty() {
                let cancelled = ev.cancelled.join(", ");
                parts.push(format!("not initialized: {cancelled}"));
            }
            let mut message = if parts.is_empty() {
                "MCP startup incomplete.".to_string()
            } else {
                let summary = parts.join("; ");
                format!("MCP startup incomplete ({summary}).")
            };
            let can_retry_in_place = self.queued_user_messages.is_empty()
                && self.composer_is_empty()
                && self.is_normal_backtrack_mode();
            if can_retry_in_place {
                message.push_str(" Press `r` or run `/mcp retry failed` to retry.");
            } else {
                message.push_str(" Run `/mcp retry failed` to retry.");
            }
            if let Some(tip) = Self::timeout_tip_for_failures(&ev.failed) {
                message.push(' ');
                message.push_str(&tip);
            }
            message.push_str(" Run `/mcp` for details.");

            // Only pin the banner when retry is directly actionable from the main view
            // (composer empty, no queued messages, and not currently "Working"). Otherwise
            // log a one-time warning and avoid sticking the banner above the composer.
            if can_retry_in_place {
                self.set_mcp_startup_banner(Some(message));
            } else {
                self.set_mcp_startup_banner(None);
                self.on_warning(message);
            }
        }

        for server in &ev.ready {
            if !self.mcp_startup_durations.contains_key(server)
                && let Some(started_at) = self.mcp_server_start_times.remove(server)
            {
                self.mcp_startup_durations
                    .insert(server.clone(), now.saturating_duration_since(started_at));
            }
        }
        for failure in &ev.failed {
            if !self.mcp_startup_durations.contains_key(&failure.server)
                && let Some(started_at) = self.mcp_server_start_times.remove(&failure.server)
            {
                self.mcp_startup_durations.insert(
                    failure.server.clone(),
                    now.saturating_duration_since(started_at),
                );
            }
        }
        for server in &ev.cancelled {
            if !self.mcp_startup_durations.contains_key(server)
                && let Some(started_at) = self.mcp_server_start_times.remove(server)
            {
                self.mcp_startup_durations
                    .insert(server.clone(), now.saturating_duration_since(started_at));
            }
        }

        let mut status = self.mcp_startup_status.take().unwrap_or_default();
        for server in &ev.ready {
            status.insert(server.clone(), McpStartupStatus::Ready);
        }
        for failure in &ev.failed {
            status.insert(
                failure.server.clone(),
                McpStartupStatus::Failed {
                    error: failure.error.clone(),
                },
            );
        }
        for server in &ev.cancelled {
            status.insert(server.clone(), McpStartupStatus::Cancelled);
        }
        self.mcp_startup_status = if status.is_empty() {
            None
        } else {
            Some(status)
        };
        self.bottom_pane.set_task_running(false);
        self.maybe_send_next_queued_input();
        self.request_redraw();
    }

    /// Handle a turn aborted due to user interrupt (Esc).
    /// When there are queued user messages, restore them into the composer
    /// separated by newlines rather than auto‑submitting the next one.
    fn on_interrupted_turn(&mut self, reason: TurnAbortReason) {
        // Finalize, log a gentle prompt, and clear running state.
        self.finalize_turn();

        if reason != TurnAbortReason::ReviewEnded {
            self.add_to_history(history_cell::new_error_event(
                "Conversation interrupted - tell the model what to do differently. Something went wrong? Hit `/feedback` to save a report.".to_owned(),
            ));
        }

        // If any messages were queued during the task, restore them into the composer.
        if !self.queued_user_messages.is_empty() {
            let queued_text = self
                .queued_user_messages
                .iter()
                .map(|m| m.text.clone())
                .collect::<Vec<_>>()
                .join("\n");
            let existing_text = self.bottom_pane.composer_text();
            let combined = if existing_text.is_empty() {
                queued_text
            } else if queued_text.is_empty() {
                existing_text
            } else {
                format!("{queued_text}\n{existing_text}")
            };
            self.bottom_pane.set_composer_text(combined);
            // Clear the queue and update the status indicator list.
            self.queued_user_messages.clear();
            self.refresh_queued_user_messages();
        }

        self.request_redraw();
    }

    fn on_plan_update(&mut self, update: UpdatePlanArgs) {
        self.add_to_history(history_cell::new_plan_update(update));
    }

    fn on_exec_approval_request(&mut self, id: String, ev: ExecApprovalRequestEvent) {
        let id2 = id.clone();
        let ev2 = ev.clone();
        self.defer_or_handle(
            |q| q.push_exec_approval(id, ev),
            |s| s.handle_exec_approval_now(id2, ev2),
        );
    }

    fn on_apply_patch_approval_request(&mut self, id: String, ev: ApplyPatchApprovalRequestEvent) {
        let id2 = id.clone();
        let ev2 = ev.clone();
        self.defer_or_handle(
            |q| q.push_apply_patch_approval(id, ev),
            |s| s.handle_apply_patch_approval_now(id2, ev2),
        );
    }

    fn on_elicitation_request(&mut self, ev: ElicitationRequestEvent) {
        let ev2 = ev.clone();
        self.defer_or_handle(
            |q| q.push_elicitation(ev),
            |s| s.handle_elicitation_request_now(ev2),
        );
    }

    fn on_exec_command_begin(&mut self, ev: ExecCommandBeginEvent) {
        self.flush_answer_stream_with_separator();
        if ev.source == ExecCommandSource::UnifiedExecStartup {
            self.track_unified_exec_session_begin(&ev);
        }
        let ev2 = ev.clone();
        self.defer_or_handle(|q| q.push_exec_begin(ev), |s| s.handle_exec_begin_now(ev2));
    }

    fn on_exec_command_output_delta(
        &mut self,
        _ev: codex_core::protocol::ExecCommandOutputDeltaEvent,
    ) {
        // TODO: Handle streaming exec output if/when implemented
    }

    fn on_terminal_interaction(&mut self, _ev: TerminalInteractionEvent) {
        // TODO: Handle once design is ready
    }

    fn on_hook_process_begin(&mut self, ev: HookProcessBeginEvent) {
        let key = ev.hook_id.to_string();
        let command_display = strip_bash_lc_and_escape(&ev.command);
        let command_display = format!("{} · {command_display}", ev.event_type);
        if let Some(existing) = self.hook_processes.iter_mut().find(|hook| hook.key == key) {
            existing.command_display = command_display;
        } else {
            self.hook_processes.push(HookProcessSummary {
                key,
                command_display,
            });
        }
    }

    fn on_hook_process_end(&mut self, ev: HookProcessEndEvent) {
        let key = ev.hook_id.to_string();
        self.hook_processes.retain(|hook| hook.key != key);
    }

    fn on_patch_apply_begin(&mut self, event: PatchApplyBeginEvent) {
        if self.ramps_status_active() {
            self.set_ramp_stage(crate::ramps::RampStage::Stabilizing);
        }
        self.add_to_history(history_cell::new_patch_event(
            event.changes,
            &self.config.cwd,
        ));
    }

    fn on_view_image_tool_call(&mut self, event: ViewImageToolCallEvent) {
        self.flush_answer_stream_with_separator();
        self.add_to_history(history_cell::new_view_image_tool_call(
            event.path,
            &self.config.cwd,
        ));
        self.request_redraw();
    }

    fn on_patch_apply_end(&mut self, event: codex_core::protocol::PatchApplyEndEvent) {
        let ev2 = event.clone();
        self.defer_or_handle(
            |q| q.push_patch_end(event),
            |s| s.handle_patch_apply_end_now(ev2),
        );
    }

    fn on_exec_command_end(&mut self, ev: ExecCommandEndEvent) {
        if ev.source == ExecCommandSource::UnifiedExecStartup {
            self.track_unified_exec_session_end(&ev);
        }
        let ev2 = ev.clone();
        self.defer_or_handle(|q| q.push_exec_end(ev), |s| s.handle_exec_end_now(ev2));
    }

    fn track_unified_exec_session_begin(&mut self, ev: &ExecCommandBeginEvent) {
        let key = ev.process_id.clone().unwrap_or_else(|| ev.call_id.clone());
        let command_display = strip_bash_lc_and_escape(&ev.command);
        if let Some(existing) = self
            .unified_exec_sessions
            .iter_mut()
            .find(|session| session.key == key)
        {
            existing.command_display = command_display;
        } else {
            self.unified_exec_sessions.push(UnifiedExecSessionSummary {
                key,
                command_display,
            });
        }
    }

    fn track_unified_exec_session_end(&mut self, ev: &ExecCommandEndEvent) {
        let key = ev.process_id.clone().unwrap_or_else(|| ev.call_id.clone());
        self.unified_exec_sessions
            .retain(|session| session.key != key);
    }

    fn on_mcp_tool_call_begin(&mut self, ev: McpToolCallBeginEvent) {
        let ev2 = ev.clone();
        self.defer_or_handle(|q| q.push_mcp_begin(ev), |s| s.handle_mcp_begin_now(ev2));
    }

    fn on_mcp_tool_call_end(&mut self, ev: McpToolCallEndEvent) {
        let ev2 = ev.clone();
        self.defer_or_handle(|q| q.push_mcp_end(ev), |s| s.handle_mcp_end_now(ev2));
    }

    fn on_web_search_begin(&mut self, _ev: WebSearchBeginEvent) {
        self.flush_answer_stream_with_separator();
    }

    fn on_web_search_end(&mut self, ev: WebSearchEndEvent) {
        self.flush_answer_stream_with_separator();
        self.add_to_history(history_cell::new_web_search_call(ev.query));
    }

    fn on_get_history_entry_response(
        &mut self,
        event: codex_core::protocol::GetHistoryEntryResponseEvent,
    ) {
        let codex_core::protocol::GetHistoryEntryResponseEvent {
            offset,
            log_id,
            entry,
        } = event;
        self.bottom_pane
            .on_history_entry_response(log_id, offset, entry.map(|e| e.text));
    }

    fn on_shutdown_complete(&mut self) {
        self.request_exit();
    }

    fn on_turn_diff(&mut self, unified_diff: String) {
        debug!("TurnDiffEvent: {unified_diff}");
    }

    fn on_deprecation_notice(&mut self, event: DeprecationNoticeEvent) {
        let DeprecationNoticeEvent { summary, details } = event;
        self.add_to_history(history_cell::new_deprecation_notice(summary, details));
        self.request_redraw();
    }

    fn on_background_event(&mut self, message: String) {
        debug!("BackgroundEvent: {message}");
        self.bottom_pane.ensure_status_indicator();
        self.bottom_pane.set_interrupt_hint_visible(true);
        if self.ramps_status_active() {
            self.set_ramp_context(Some(message));
        } else {
            self.set_status_header(message);
        }
    }

    fn on_undo_started(&mut self, event: UndoStartedEvent) {
        self.bottom_pane.ensure_status_indicator();
        self.bottom_pane.set_interrupt_hint_visible(false);
        let message = event
            .message
            .unwrap_or_else(|| "Undo in progress...".to_string());
        self.set_status_header(message);
    }

    fn on_undo_completed(&mut self, event: UndoCompletedEvent) {
        let UndoCompletedEvent { success, message } = event;
        self.bottom_pane.hide_status_indicator();
        let message = message.unwrap_or_else(|| {
            if success {
                "Undo completed successfully.".to_string()
            } else {
                "Undo failed.".to_string()
            }
        });
        if success {
            self.add_info_message(message, None);
        } else {
            self.add_error_message(message);
        }
    }

    fn on_stream_error(&mut self, message: String, additional_details: Option<String>) {
        if self.retry_status_header.is_none() {
            self.retry_status_header = Some(self.current_status_header.clone());
        }
        self.set_status(message, additional_details);
    }

    /// Periodic tick to commit at most one queued line to history with a small delay,
    /// animating the output.
    pub(crate) fn on_commit_tick(&mut self) {
        if let Some(controller) = self.stream_controller.as_mut() {
            let (cell, is_idle) = controller.on_commit_tick();
            if let Some(cell) = cell {
                self.bottom_pane.hide_status_indicator();
                self.add_boxed_history(cell);
                self.request_redraw();
            }
            if is_idle {
                self.app_event_tx.send(AppEvent::StopCommitAnimation);
            }
        }
    }

    fn flush_interrupt_queue(&mut self) {
        let mut mgr = std::mem::take(&mut self.interrupts);
        mgr.flush_all(self);
        self.interrupts = mgr;
    }

    #[inline]
    fn defer_or_handle(
        &mut self,
        push: impl FnOnce(&mut InterruptManager),
        handle: impl FnOnce(&mut Self),
    ) {
        // Preserve deterministic FIFO across queued interrupts: once anything
        // is queued due to an active write cycle, continue queueing until the
        // queue is flushed to avoid reordering (e.g., ExecEnd before ExecBegin).
        if self.stream_controller.is_some() || !self.interrupts.is_empty() {
            push(&mut self.interrupts);
        } else {
            handle(self);
        }
    }

    fn handle_stream_finished(&mut self) {
        if self.task_complete_pending {
            self.bottom_pane.hide_status_indicator();
            self.task_complete_pending = false;
        }
        // A completed stream indicates non-exec content was just inserted.
        self.flush_interrupt_queue();
    }

    #[inline]
    fn handle_streaming_delta(&mut self, delta: String) {
        // Before streaming agent content, flush any active exec cell group.
        let mut needs_redraw = self.active_cell.is_some();
        self.flush_active_cell();

        if self.ramps_status_active() && self.ramp_stage == crate::ramps::RampStage::Waiting {
            self.set_ramp_stage(crate::ramps::RampStage::Warmup);
        }

        if self.stream_controller.is_none() {
            if self.needs_final_message_separator {
                let elapsed_seconds = self
                    .bottom_pane
                    .status_widget()
                    .map(super::status_indicator_widget::StatusIndicatorWidget::elapsed_seconds);
                let show_ramp_separator = self.ramps_status_enabled();
                let xtreme_ui_enabled = crate::xtreme::xtreme_ui_enabled(&self.config);
                let completion_label = self.last_turn_completion_label.take();
                let turn_summary = if self.turn_summary.is_empty() {
                    None
                } else {
                    Some(self.turn_summary.clone())
                };
                self.add_to_history(history_cell::FinalMessageSeparator::new(
                    elapsed_seconds,
                    show_ramp_separator,
                    xtreme_ui_enabled,
                    completion_label,
                    turn_summary,
                ));
                self.needs_final_message_separator = false;
                needs_redraw = true;
            }
            // Streaming must not capture the current viewport width: width-derived wraps are
            // applied later, at render time, so the transcript can reflow on resize.
            self.stream_controller = Some(StreamController::new());
        }
        if let Some(controller) = self.stream_controller.as_mut()
            && controller.push(&delta)
        {
            self.app_event_tx.send(AppEvent::StartCommitAnimation);
        }
        if needs_redraw {
            self.request_redraw();
        }
    }

    pub(crate) fn handle_exec_end_now(&mut self, ev: ExecCommandEndEvent) {
        let running = self.running_commands.remove(&ev.call_id);
        let should_stabilize = self.ramps_status_active() && self.running_commands.is_empty();
        if self.suppressed_exec_calls.remove(&ev.call_id) {
            if should_stabilize {
                self.set_ramp_stage(crate::ramps::RampStage::Stabilizing);
            }
            return;
        }
        let (command, parsed, source) = match running {
            Some(rc) => (rc.command, rc.parsed_cmd, rc.source),
            None => (ev.command.clone(), ev.parsed_cmd.clone(), ev.source),
        };
        let is_unified_exec_interaction =
            matches!(source, ExecCommandSource::UnifiedExecInteraction);

        let needs_new = self
            .active_cell
            .as_ref()
            .map(|cell| cell.as_any().downcast_ref::<ExecCell>().is_none())
            .unwrap_or(true);
        if needs_new {
            self.flush_active_cell();
            self.active_cell = Some(Box::new(new_active_exec_command(
                ev.call_id.clone(),
                command,
                parsed,
                source,
                ev.interaction_input.clone(),
                self.config.animations,
            )));
        }

        if let Some(cell) = self
            .active_cell
            .as_mut()
            .and_then(|c| c.as_any_mut().downcast_mut::<ExecCell>())
        {
            let output = if is_unified_exec_interaction {
                CommandOutput {
                    exit_code: ev.exit_code,
                    formatted_output: String::new(),
                    aggregated_output: String::new(),
                }
            } else {
                CommandOutput {
                    exit_code: ev.exit_code,
                    formatted_output: ev.formatted_output.clone(),
                    aggregated_output: ev.aggregated_output.clone(),
                }
            };
            cell.complete_call(&ev.call_id, output, ev.duration);
            if cell.should_flush() {
                self.flush_active_cell();
            }
        }

        if should_stabilize {
            self.set_ramp_stage(crate::ramps::RampStage::Stabilizing);
        }
    }

    pub(crate) fn handle_patch_apply_end_now(
        &mut self,
        event: codex_core::protocol::PatchApplyEndEvent,
    ) {
        if event.success {
            self.turn_summary.patches = self.turn_summary.patches.saturating_add(1);
            self.turn_summary.files_changed = self
                .turn_summary
                .files_changed
                .saturating_add(event.changes.len());
            self.session_stats.patches = self.session_stats.patches.saturating_add(1);
            self.session_stats.files_changed = self
                .session_stats
                .files_changed
                .saturating_add(event.changes.len());
        }

        // If the patch was successful, just let the "Edited" block stand.
        // Otherwise, add a failure block.
        if !event.success {
            self.add_to_history(history_cell::new_patch_apply_failure(event.stderr));
        }
    }

    pub(crate) fn handle_exec_approval_now(&mut self, id: String, ev: ExecApprovalRequestEvent) {
        self.flush_answer_stream_with_separator();
        let command = shlex::try_join(ev.command.iter().map(String::as_str))
            .unwrap_or_else(|_| ev.command.join(" "));
        self.notify(Notification::ExecApprovalRequested { command });
        self.session_stats.approvals_requested =
            self.session_stats.approvals_requested.saturating_add(1);

        let request = ApprovalRequest::Exec {
            id,
            command: ev.command,
            reason: ev.reason,
            proposed_execpolicy_amendment: ev.proposed_execpolicy_amendment,
        };
        self.bottom_pane
            .push_approval_request(request, &self.config.features);
        self.request_redraw();
    }

    pub(crate) fn handle_apply_patch_approval_now(
        &mut self,
        id: String,
        ev: ApplyPatchApprovalRequestEvent,
    ) {
        self.flush_answer_stream_with_separator();
        self.session_stats.approvals_requested =
            self.session_stats.approvals_requested.saturating_add(1);

        let request = ApprovalRequest::ApplyPatch {
            id,
            reason: ev.reason,
            changes: ev.changes.clone(),
            cwd: self.config.cwd.clone(),
        };
        self.bottom_pane
            .push_approval_request(request, &self.config.features);
        self.request_redraw();
        self.notify(Notification::EditApprovalRequested {
            cwd: self.config.cwd.clone(),
            changes: ev.changes.keys().cloned().collect(),
        });
    }

    pub(crate) fn handle_elicitation_request_now(&mut self, ev: ElicitationRequestEvent) {
        self.flush_answer_stream_with_separator();

        self.notify(Notification::ElicitationRequested {
            server_name: ev.server_name.clone(),
        });

        let request = ApprovalRequest::McpElicitation {
            server_name: ev.server_name,
            request_id: ev.id,
            message: ev.message,
        };
        self.bottom_pane
            .push_approval_request(request, &self.config.features);
        self.request_redraw();
    }

    pub(crate) fn handle_exec_begin_now(&mut self, ev: ExecCommandBeginEvent) {
        // Ensure the status indicator is visible while the command runs.
        self.running_commands.insert(
            ev.call_id.clone(),
            RunningCommand {
                command: ev.command.clone(),
                parsed_cmd: ev.parsed_cmd.clone(),
                source: ev.source,
            },
        );
        let is_wait_interaction = matches!(ev.source, ExecCommandSource::UnifiedExecInteraction)
            && ev
                .interaction_input
                .as_deref()
                .map(str::is_empty)
                .unwrap_or(true);
        let command_display = ev.command.join(" ");
        let should_suppress_unified_wait = is_wait_interaction
            && self
                .last_unified_wait
                .as_ref()
                .is_some_and(|wait| wait.is_duplicate(&command_display));
        if is_wait_interaction {
            self.last_unified_wait = Some(UnifiedExecWaitState::new(command_display));
        } else {
            self.last_unified_wait = None;
        }
        if should_suppress_unified_wait {
            self.suppressed_exec_calls.insert(ev.call_id);
            return;
        }

        self.turn_summary.exec_commands = self.turn_summary.exec_commands.saturating_add(1);
        self.session_stats.exec_commands = self.session_stats.exec_commands.saturating_add(1);
        if crate::exec_command::strip_bash_lc_and_escape(&ev.command).starts_with("cargo test") {
            self.session_stats.tests_run = self.session_stats.tests_run.saturating_add(1);
        }
        if self.ramps_status_active() {
            self.set_ramp_stage(crate::ramps::RampStage::Active);
        } else if crate::xtreme::xtreme_ui_enabled(&self.config)
            && self.current_status_header == "Charging"
        {
            self.set_status_header("Overclocking".to_string());
        }

        let interaction_input = ev.interaction_input.clone();
        if let Some(cell) = self
            .active_cell
            .as_mut()
            .and_then(|c| c.as_any_mut().downcast_mut::<ExecCell>())
            && let Some(new_exec) = cell.with_added_call(
                ev.call_id.clone(),
                ev.command.clone(),
                ev.parsed_cmd.clone(),
                ev.source,
                interaction_input.clone(),
            )
        {
            *cell = new_exec;
        } else {
            self.flush_active_cell();

            self.active_cell = Some(Box::new(new_active_exec_command(
                ev.call_id.clone(),
                ev.command.clone(),
                ev.parsed_cmd,
                ev.source,
                interaction_input,
                self.config.animations,
            )));
        }

        self.request_redraw();
    }

    pub(crate) fn handle_mcp_begin_now(&mut self, ev: McpToolCallBeginEvent) {
        self.flush_answer_stream_with_separator();
        self.flush_active_cell();
        self.turn_summary.mcp_calls = self.turn_summary.mcp_calls.saturating_add(1);
        self.session_stats.mcp_calls = self.session_stats.mcp_calls.saturating_add(1);
        if self.ramps_status_active() {
            self.set_ramp_stage(crate::ramps::RampStage::Active);
        } else if crate::xtreme::xtreme_ui_enabled(&self.config)
            && self.current_status_header == "Charging"
        {
            self.set_status_header("Overclocking".to_string());
        }
        self.active_cell = Some(Box::new(history_cell::new_active_mcp_tool_call(
            ev.call_id,
            ev.invocation,
            self.config.animations,
        )));
        self.request_redraw();
    }
    pub(crate) fn handle_mcp_end_now(&mut self, ev: McpToolCallEndEvent) {
        self.flush_answer_stream_with_separator();

        let McpToolCallEndEvent {
            call_id,
            invocation,
            duration,
            result,
        } = ev;

        let extra_cell = match self
            .active_cell
            .as_mut()
            .and_then(|cell| cell.as_any_mut().downcast_mut::<McpToolCallCell>())
        {
            Some(cell) if cell.call_id() == call_id => cell.complete(duration, result),
            _ => {
                self.flush_active_cell();
                let mut cell = history_cell::new_active_mcp_tool_call(
                    call_id,
                    invocation,
                    self.config.animations,
                );
                let extra_cell = cell.complete(duration, result);
                self.active_cell = Some(Box::new(cell));
                extra_cell
            }
        };

        self.flush_active_cell();
        if let Some(extra) = extra_cell {
            self.add_boxed_history(extra);
        }
        if self.ramps_status_active() && self.running_commands.is_empty() {
            self.set_ramp_stage(crate::ramps::RampStage::Stabilizing);
        }
    }

    pub(crate) fn new(common: ChatWidgetInit, thread_manager: Arc<ThreadManager>) -> Self {
        let ChatWidgetInit {
            config,
            frame_requester,
            app_event_tx,
            initial_prompt,
            initial_images,
            enhanced_keys_supported,
            auth_manager,
            models_manager,
            feedback,
            is_first_run,
            model,
        } = common;
        let mut config = config;
        config.model = Some(model.clone());
        let xtreme_ui_enabled = crate::xtreme::xtreme_ui_enabled(&config);
        let mut rng = rand::rng();
        let placeholder = if codex_core::config::is_xcodex_invocation() {
            "Ask xcodex to do anything".to_string()
        } else {
            EXAMPLE_PROMPTS[rng.random_range(0..EXAMPLE_PROMPTS.len())].to_string()
        };
        let codex_op_tx = spawn_agent(config.clone(), app_event_tx.clone(), thread_manager);
        let auto_compact_enabled =
            codex_core::prefs::load_blocking(&config.codex_home).auto_compact_enabled;

        let mut widget = Self {
            app_event_tx: app_event_tx.clone(),
            frame_requester: frame_requester.clone(),
            codex_op_tx,
            bottom_pane: BottomPane::new(BottomPaneParams {
                frame_requester,
                app_event_tx,
                has_input_focus: true,
                enhanced_keys_supported,
                placeholder_text: placeholder,
                disable_paste_burst: config.disable_paste_burst,
                xtreme_ui_enabled,
                animations_enabled: config.animations,
                skills: None,
            }),
            active_cell: None,
            config,
            model: model.clone(),
            auth_manager,
            models_manager,
            session_header: SessionHeader::new(model),
            initial_user_message: create_initial_user_message(
                initial_prompt.unwrap_or_default(),
                initial_images,
            ),
            auto_compact_enabled,
            token_info: None,
            footer_token_info: None,
            pending_footer_token_info: None,
            footer_token_info_at_task_start: None,
            context_estimate_details_visible: false,
            last_context_estimate_details_update: None,
            last_context_estimate_details_percent: None,
            rate_limit_snapshot: None,
            plan_type: None,
            rate_limit_warnings: RateLimitWarningState::default(),
            rate_limit_switch_prompt: RateLimitSwitchPromptState::default(),
            rate_limit_poller: None,
            status_bar_git_poller: None,
            worktree_list: Vec::new(),
            worktree_list_error: None,
            worktree_list_refresh_in_progress: false,
            shared_dirs_write_notice_shown: false,
            stream_controller: None,
            running_commands: HashMap::new(),
            suppressed_exec_calls: HashSet::new(),
            last_unified_wait: None,
            task_complete_pending: false,
            unified_exec_sessions: Vec::new(),
            hook_processes: Vec::new(),
            mcp_startup_status: None,
            mcp_failed_servers: Vec::new(),
            mcp_startup_started_at: None,
            mcp_startup_duration: None,
            mcp_server_start_times: HashMap::new(),
            mcp_startup_durations: HashMap::new(),
            interrupts: InterruptManager::new(),
            reasoning_buffer: String::new(),
            full_reasoning_buffer: String::new(),
            current_status_header: String::from("Working"),
            retry_status_header: None,
            ramp_turn_index: 0,
            ramp_selected: crate::ramps::baseline_ramp(),
            ramp_stage: crate::ramps::RampStage::Waiting,
            ramp_context: None,
            last_turn_completion_label: None,
            conversation_id: None,
            queued_user_messages: VecDeque::new(),
            show_welcome_banner: is_first_run,
            suppress_session_configured_redraw: false,
            pending_notification: None,
            is_review_mode: false,
            pre_review_token_info: None,
            needs_final_message_separator: false,
            turn_summary: history_cell::TurnSummary::default(),
            session_stats: crate::status::SessionStats::default(),
            last_rendered_width: std::cell::Cell::new(None),
            feedback,
            current_rollout_path: None,
        };

        widget.bottom_pane.set_status_bar_git_options(
            widget.config.tui_status_bar_show_git_branch,
            widget.config.tui_status_bar_show_worktree,
        );
        widget.refresh_status_bar_git_poller();
        widget.spawn_worktree_detection(false);

        widget.prefetch_rate_limits();

        widget
    }

    /// Create a ChatWidget attached to an existing conversation (e.g., a fork).
    pub(crate) fn new_from_existing(
        common: ChatWidgetInit,
        conversation: std::sync::Arc<codex_core::CodexThread>,
        session_configured: codex_core::protocol::SessionConfiguredEvent,
    ) -> Self {
        let ChatWidgetInit {
            config,
            frame_requester,
            app_event_tx,
            initial_prompt,
            initial_images,
            enhanced_keys_supported,
            auth_manager,
            models_manager,
            feedback,
            ..
        } = common;
        let model = session_configured.model.clone();
        let mut config = config;
        config.model = Some(model.clone());
        let xtreme_ui_enabled = crate::xtreme::xtreme_ui_enabled(&config);
        let mut rng = rand::rng();
        let placeholder = if codex_core::config::is_xcodex_invocation() {
            "Ask xcodex to do anything".to_string()
        } else {
            EXAMPLE_PROMPTS[rng.random_range(0..EXAMPLE_PROMPTS.len())].to_string()
        };

        let codex_op_tx =
            spawn_agent_from_existing(conversation, session_configured, app_event_tx.clone());
        let auto_compact_enabled =
            codex_core::prefs::load_blocking(&config.codex_home).auto_compact_enabled;

        let mut widget = Self {
            app_event_tx: app_event_tx.clone(),
            frame_requester: frame_requester.clone(),
            codex_op_tx,
            bottom_pane: BottomPane::new(BottomPaneParams {
                frame_requester,
                app_event_tx,
                has_input_focus: true,
                enhanced_keys_supported,
                placeholder_text: placeholder,
                disable_paste_burst: config.disable_paste_burst,
                xtreme_ui_enabled,
                animations_enabled: config.animations,
                skills: None,
            }),
            active_cell: None,
            config,
            model: model.clone(),
            auth_manager,
            models_manager,
            session_header: SessionHeader::new(model),
            initial_user_message: create_initial_user_message(
                initial_prompt.unwrap_or_default(),
                initial_images,
            ),
            auto_compact_enabled,
            token_info: None,
            footer_token_info: None,
            pending_footer_token_info: None,
            footer_token_info_at_task_start: None,
            context_estimate_details_visible: false,
            last_context_estimate_details_update: None,
            last_context_estimate_details_percent: None,
            rate_limit_snapshot: None,
            plan_type: None,
            rate_limit_warnings: RateLimitWarningState::default(),
            rate_limit_switch_prompt: RateLimitSwitchPromptState::default(),
            rate_limit_poller: None,
            status_bar_git_poller: None,
            worktree_list: Vec::new(),
            worktree_list_error: None,
            worktree_list_refresh_in_progress: false,
            shared_dirs_write_notice_shown: false,
            stream_controller: None,
            running_commands: HashMap::new(),
            suppressed_exec_calls: HashSet::new(),
            last_unified_wait: None,
            task_complete_pending: false,
            unified_exec_sessions: Vec::new(),
            hook_processes: Vec::new(),
            mcp_startup_status: None,
            mcp_failed_servers: Vec::new(),
            mcp_startup_started_at: None,
            mcp_startup_duration: None,
            mcp_server_start_times: HashMap::new(),
            mcp_startup_durations: HashMap::new(),
            interrupts: InterruptManager::new(),
            reasoning_buffer: String::new(),
            full_reasoning_buffer: String::new(),
            current_status_header: String::from("Working"),
            retry_status_header: None,
            ramp_turn_index: 0,
            ramp_selected: crate::ramps::baseline_ramp(),
            ramp_stage: crate::ramps::RampStage::Waiting,
            ramp_context: None,
            last_turn_completion_label: None,
            conversation_id: None,
            queued_user_messages: VecDeque::new(),
            show_welcome_banner: false,
            suppress_session_configured_redraw: true,
            pending_notification: None,
            is_review_mode: false,
            pre_review_token_info: None,
            needs_final_message_separator: false,
            turn_summary: history_cell::TurnSummary::default(),
            session_stats: crate::status::SessionStats::default(),
            last_rendered_width: std::cell::Cell::new(None),
            feedback,
            current_rollout_path: None,
        };

        widget.bottom_pane.set_status_bar_git_options(
            widget.config.tui_status_bar_show_git_branch,
            widget.config.tui_status_bar_show_worktree,
        );
        widget.refresh_status_bar_git_poller();
        widget.spawn_worktree_detection(false);

        widget.prefetch_rate_limits();

        widget
    }

    pub(crate) fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event {
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers,
                kind: KeyEventKind::Press,
                ..
            } if modifiers.contains(KeyModifiers::CONTROL) && c.eq_ignore_ascii_case(&'c') => {
                self.on_ctrl_c();
                return;
            }
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers,
                kind: KeyEventKind::Press,
                ..
            } if modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                && c.eq_ignore_ascii_case(&'v') =>
            {
                match paste_image_to_temp_png() {
                    Ok((path, info)) => {
                        tracing::debug!(
                            "pasted image size={}x{} format={}",
                            info.width,
                            info.height,
                            info.encoded_format.label()
                        );
                        self.attach_image(path);
                    }
                    Err(err) => {
                        tracing::warn!("failed to paste image: {err}");
                        self.add_to_history(history_cell::new_error_event(format!(
                            "Failed to paste image: {err}",
                        )));
                    }
                }
                return;
            }
            other if other.kind == KeyEventKind::Press => {
                self.bottom_pane.clear_ctrl_c_quit_hint();
            }
            _ => {}
        }

        if matches!(
            key_event,
            KeyEvent {
                code: KeyCode::Char('r' | 'R'),
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                ..
            }
        ) && !self.mcp_failed_servers.is_empty()
            && self.queued_user_messages.is_empty()
            && self.composer_is_empty()
            && self.is_normal_backtrack_mode()
        {
            let servers = std::mem::take(&mut self.mcp_failed_servers);
            self.set_mcp_startup_banner(None);
            self.add_info_message("Retrying failed MCP servers…".to_string(), None);
            self.submit_op(Op::McpRetry { servers });
            return;
        }

        if matches!(
            key_event,
            KeyEvent {
                code: KeyCode::Char('o' | 'O'),
                modifiers: KeyModifiers::CONTROL,
                kind: KeyEventKind::Press,
                ..
            }
        ) && self.queued_user_messages.is_empty()
            && self.composer_is_empty()
            && self.is_normal_backtrack_mode()
        {
            let status_cell = self.status_menu_status_cell();
            let view = crate::bottom_pane::StatusMenuView::new(
                crate::bottom_pane::StatusMenuTab::Tools,
                self.app_event_tx.clone(),
                status_cell,
                self.config.tui_status_bar_show_git_branch,
                self.config.tui_status_bar_show_worktree,
                self.config.tui_xtreme_mode,
                self.config.tui_verbose_tool_output,
            );
            self.bottom_pane.show_view(Box::new(view));
            self.request_redraw();
            return;
        }

        match key_event {
            KeyEvent {
                code: KeyCode::Up,
                modifiers: KeyModifiers::ALT,
                kind: KeyEventKind::Press,
                ..
            } if !self.queued_user_messages.is_empty() => {
                // Prefer the most recently queued item.
                if let Some(user_message) = self.queued_user_messages.pop_back() {
                    self.bottom_pane.set_composer_text(user_message.text);
                    self.refresh_queued_user_messages();
                    self.request_redraw();
                }
            }
            _ => {
                match self.bottom_pane.handle_key_event(key_event) {
                    InputResult::Submitted(text) => {
                        // If a task is running, queue the user input to be sent after the turn completes.
                        let user_message = UserMessage {
                            text,
                            image_paths: self.bottom_pane.take_recent_submission_images(),
                        };
                        self.queue_user_message(user_message);
                    }
                    InputResult::Command(cmd) => {
                        self.dispatch_command(cmd);
                    }
                    InputResult::CommandWithArgs(cmd, args) => {
                        self.dispatch_command_with_args(cmd, args);
                    }
                    InputResult::None => {}
                }
            }
        }
    }

    pub(crate) fn attach_image(&mut self, path: PathBuf) {
        tracing::info!("attach_image path={path:?}");
        self.bottom_pane.attach_image(path);
        self.request_redraw();
    }

    pub(crate) fn dispatch_slash_command(&mut self, cmd: SlashCommand) {
        self.dispatch_command(cmd);
    }

    fn dispatch_command(&mut self, cmd: SlashCommand) {
        if !cmd.available_during_task() && self.bottom_pane.is_task_running() {
            let message = format!(
                "'/{}' is disabled while a task is in progress.",
                cmd.command()
            );
            self.add_to_history(history_cell::new_error_event(message));
            self.request_redraw();
            return;
        }
        match cmd {
            SlashCommand::Feedback => {
                if !self.config.feedback_enabled {
                    let params = crate::bottom_pane::feedback_disabled_params();
                    self.bottom_pane.show_selection_view(params);
                    self.request_redraw();
                    return;
                }
                // Step 1: pick a category (UI built in feedback_view)
                let params =
                    crate::bottom_pane::feedback_selection_params(self.app_event_tx.clone());
                self.bottom_pane.show_selection_view(params);
                self.request_redraw();
            }
            SlashCommand::New => {
                self.app_event_tx.send(AppEvent::NewSession);
            }
            SlashCommand::Resume => {
                self.app_event_tx.send(AppEvent::OpenResumePicker);
            }
            SlashCommand::Init => {
                let init_target = self.config.cwd.join(DEFAULT_PROJECT_DOC_FILENAME);
                if init_target.exists() {
                    let message = format!(
                        "{DEFAULT_PROJECT_DOC_FILENAME} already exists here. Skipping /init to avoid overwriting it."
                    );
                    self.add_info_message(message, None);
                    return;
                }
                const INIT_PROMPT: &str = include_str!("../prompt_for_init_command.md");
                self.submit_user_message(INIT_PROMPT.to_string().into());
            }
            SlashCommand::Compact => {
                self.clear_token_usage();
                self.app_event_tx.send(AppEvent::CodexOp(Op::Compact));
            }
            SlashCommand::Autocompact => {
                self.auto_compact_enabled = !self.auto_compact_enabled;
                let enabled = self.auto_compact_enabled;
                let status = if enabled { "enabled" } else { "disabled" };
                self.add_info_message(format!("Auto-compact {status}."), None);
                self.app_event_tx
                    .send(AppEvent::CodexOp(Op::SetAutoCompact { enabled }));
            }
            SlashCommand::Thoughts => {
                let hide = !self.config.hide_agent_reasoning;
                self.set_hide_agent_reasoning(hide);
                let status = if hide { "hidden" } else { "shown" };
                self.add_info_message(format!("Thoughts {status}."), None);
                self.app_event_tx
                    .send(AppEvent::UpdateHideAgentReasoning(hide));
                self.app_event_tx
                    .send(AppEvent::PersistHideAgentReasoning(hide));
                self.request_redraw();
            }
            SlashCommand::Review => {
                self.open_review_popup();
            }
            SlashCommand::Model => {
                self.open_model_popup();
            }
            SlashCommand::Approvals => {
                self.open_approvals_popup();
            }
            SlashCommand::ElevateSandbox => {
                #[cfg(target_os = "windows")]
                {
                    let windows_degraded_sandbox_enabled = codex_core::get_platform_sandbox()
                        .is_some()
                        && !codex_core::is_windows_elevated_sandbox_enabled();
                    if !windows_degraded_sandbox_enabled
                        || !codex_core::windows_sandbox::ELEVATED_SANDBOX_NUX_ENABLED
                    {
                        // This command should not be visible/recognized outside degraded mode,
                        // but guard anyway in case something dispatches it directly.
                        return;
                    }

                    let Some(preset) = builtin_approval_presets()
                        .into_iter()
                        .find(|preset| preset.id == "auto")
                    else {
                        // Avoid panicking in interactive UI; treat this as a recoverable
                        // internal error.
                        self.add_error_message(
                            "Internal error: missing the 'auto' approval preset.".to_string(),
                        );
                        return;
                    };

                    if let Err(err) = self.config.approval_policy.can_set(&preset.approval) {
                        self.add_error_message(err.to_string());
                        return;
                    }

                    self.app_event_tx
                        .send(AppEvent::BeginWindowsSandboxElevatedSetup { preset });
                }
                #[cfg(not(target_os = "windows"))]
                {
                    // Not supported; on non-Windows this command should never be reachable.
                };
            }
            SlashCommand::Quit | SlashCommand::Exit => {
                self.request_exit();
            }
            SlashCommand::Logout => {
                if let Err(e) = codex_core::auth::logout(
                    &self.config.codex_home,
                    self.config.cli_auth_credentials_store_mode,
                ) {
                    tracing::error!("failed to logout: {e}");
                }
                self.request_exit();
            }
            // SlashCommand::Undo => {
            //     self.app_event_tx.send(AppEvent::CodexOp(Op::Undo));
            // }
            SlashCommand::Diff => {
                self.add_diff_in_progress();
                let tx = self.app_event_tx.clone();
                tokio::spawn(async move {
                    let text = match get_git_diff().await {
                        Ok((is_git_repo, diff_text)) => {
                            if is_git_repo {
                                diff_text
                            } else {
                                "`/diff` — _not inside a git repository_".to_string()
                            }
                        }
                        Err(e) => format!("Failed to compute diff: {e}"),
                    };
                    tx.send(AppEvent::DiffResult(text));
                });
            }
            SlashCommand::Mention => {
                self.insert_str("@");
            }
            SlashCommand::Skills => {
                self.insert_str("$");
            }
            SlashCommand::Help => {
                self.add_help_topics_output();
            }
            SlashCommand::Status => {
                let status_cell = self.status_menu_status_cell();
                let view = crate::bottom_pane::StatusMenuView::new(
                    crate::bottom_pane::StatusMenuTab::Status,
                    self.app_event_tx.clone(),
                    status_cell,
                    self.config.tui_status_bar_show_git_branch,
                    self.config.tui_status_bar_show_worktree,
                    self.config.tui_xtreme_mode,
                    self.config.tui_verbose_tool_output,
                );
                self.bottom_pane.show_view(Box::new(view));
                self.request_redraw();
            }
            SlashCommand::Settings => {
                let status_cell = self.status_menu_status_cell();
                let view = crate::bottom_pane::StatusMenuView::new(
                    crate::bottom_pane::StatusMenuTab::Settings,
                    self.app_event_tx.clone(),
                    status_cell,
                    self.config.tui_status_bar_show_git_branch,
                    self.config.tui_status_bar_show_worktree,
                    self.config.tui_xtreme_mode,
                    self.config.tui_verbose_tool_output,
                );
                self.bottom_pane.show_view(Box::new(view));
                self.request_redraw();
            }
            SlashCommand::StatusMenu => {
                let status_cell = self.status_menu_status_cell();
                let view = crate::bottom_pane::StatusMenuView::new(
                    crate::bottom_pane::StatusMenuTab::Status,
                    self.app_event_tx.clone(),
                    status_cell,
                    self.config.tui_status_bar_show_git_branch,
                    self.config.tui_status_bar_show_worktree,
                    self.config.tui_xtreme_mode,
                    self.config.tui_verbose_tool_output,
                );
                self.bottom_pane.show_view(Box::new(view));
                self.request_redraw();
            }
            SlashCommand::Xtreme => {
                let status_cell = self.status_menu_status_cell();
                let view = crate::bottom_pane::StatusMenuView::new(
                    crate::bottom_pane::StatusMenuTab::Tools,
                    self.app_event_tx.clone(),
                    status_cell,
                    self.config.tui_status_bar_show_git_branch,
                    self.config.tui_status_bar_show_worktree,
                    self.config.tui_xtreme_mode,
                    self.config.tui_verbose_tool_output,
                );
                self.bottom_pane.show_view(Box::new(view));
                self.request_redraw();
            }
            SlashCommand::Worktree => {
                if self.worktree_list.is_empty() && !self.worktree_list_refresh_in_progress {
                    self.spawn_worktree_detection(true);
                } else {
                    self.open_worktree_picker();
                }
            }
            SlashCommand::Hooks => {
                self.add_hooks_output();
            }
            SlashCommand::Ps => {
                self.add_ps_output();
            }
            SlashCommand::PsKill => {
                self.open_kill_popup();
            }
            SlashCommand::Mcp => {
                self.add_mcp_output();
            }
            SlashCommand::Rollout => {
                if let Some(path) = self.rollout_path() {
                    self.add_info_message(
                        format!("Current rollout path: {}", path.display()),
                        None,
                    );
                } else {
                    self.add_info_message("Rollout path is not available yet.".to_string(), None);
                }
            }
            SlashCommand::TestApproval => {
                use codex_core::protocol::EventMsg;
                use std::collections::HashMap;

                use codex_core::protocol::ApplyPatchApprovalRequestEvent;
                use codex_core::protocol::FileChange;

                self.app_event_tx.send(AppEvent::CodexEvent(Event {
                    id: "1".to_string(),
                    // msg: EventMsg::ExecApprovalRequest(ExecApprovalRequestEvent {
                    //     call_id: "1".to_string(),
                    //     command: vec!["git".into(), "apply".into()],
                    //     cwd: self.config.cwd.clone(),
                    //     reason: Some("test".to_string()),
                    // }),
                    msg: EventMsg::ApplyPatchApprovalRequest(ApplyPatchApprovalRequestEvent {
                        call_id: "1".to_string(),
                        turn_id: "turn-1".to_string(),
                        changes: HashMap::from([
                            (
                                PathBuf::from("/tmp/test.txt"),
                                FileChange::Add {
                                    content: "test".to_string(),
                                },
                            ),
                            (
                                PathBuf::from("/tmp/test2.txt"),
                                FileChange::Update {
                                    unified_diff: "+test\n-test2".to_string(),
                                    move_path: None,
                                },
                            ),
                        ]),
                        reason: None,
                        grant_root: Some(PathBuf::from("/tmp")),
                    }),
                }));
            }
        }
    }

    fn dispatch_command_with_args(&mut self, cmd: SlashCommand, args: String) {
        if !cmd.available_during_task() && self.bottom_pane.is_task_running() {
            let message = format!(
                "'/{}' is disabled while a task is in progress.",
                cmd.command()
            );
            self.add_to_history(history_cell::new_error_event(message));
            self.request_redraw();
            return;
        }

        let trimmed = args.trim();
        match cmd {
            SlashCommand::Review if !trimmed.is_empty() => {
                self.submit_op(Op::Review {
                    review_request: ReviewRequest {
                        target: ReviewTarget::Custom {
                            instructions: trimmed.to_string(),
                        },
                        user_facing_hint: None,
                    },
                });
            }
            _ => self.dispatch_command(cmd),
        }
    }

    pub(crate) fn handle_paste(&mut self, text: String) {
        self.bottom_pane.handle_paste(text);
    }

    // Returns true if caller should skip rendering this frame (a future frame is scheduled).
    pub(crate) fn handle_paste_burst_tick(&mut self, frame_requester: FrameRequester) -> bool {
        if self.bottom_pane.flush_paste_burst_if_due() {
            // A paste just flushed; request an immediate redraw and skip this frame.
            self.request_redraw();
            true
        } else if self.bottom_pane.is_in_paste_burst() {
            // While capturing a burst, schedule a follow-up tick and skip this frame
            // to avoid redundant renders between ticks.
            frame_requester.schedule_frame_in(
                crate::bottom_pane::ChatComposer::recommended_paste_flush_delay(),
            );
            true
        } else {
            false
        }
    }

    fn flush_active_cell(&mut self) {
        if let Some(active) = self.active_cell.take() {
            self.needs_final_message_separator = true;
            self.app_event_tx.send(AppEvent::InsertHistoryCell(active));
        }
    }

    fn add_to_history(&mut self, cell: impl HistoryCell + 'static) {
        self.add_boxed_history(Box::new(cell));
    }

    fn add_boxed_history(&mut self, cell: Box<dyn HistoryCell>) {
        if !cell.display_lines(u16::MAX).is_empty() {
            // Only break exec grouping if the cell renders visible lines.
            self.flush_active_cell();
            self.needs_final_message_separator = true;
        }
        self.app_event_tx.send(AppEvent::InsertHistoryCell(cell));
    }

    fn queue_user_message(&mut self, user_message: UserMessage) {
        // MCP startup warnings should not remain pinned once the user proceeds with any prompt.
        if !(user_message.text.trim().is_empty() && user_message.image_paths.is_empty()) {
            self.set_mcp_startup_banner(None);
        }
        if self.bottom_pane.is_task_running() {
            self.queued_user_messages.push_back(user_message);
            self.refresh_queued_user_messages();
        } else {
            self.submit_user_message(user_message);
        }
    }

    fn submit_user_message(&mut self, user_message: UserMessage) {
        let UserMessage { text, image_paths } = user_message;
        if text.is_empty() && image_paths.is_empty() {
            return;
        }

        let mut items: Vec<UserInput> = Vec::new();

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "mcp"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            match args.as_slice() {
                [] | ["list"] => {
                    self.dispatch_command(SlashCommand::Mcp);
                }
                ["retry"] | ["retry", "failed"] => {
                    if self.mcp_failed_servers.is_empty() {
                        self.add_info_message("No failed MCP servers to retry.".to_string(), None);
                    } else {
                        let servers = self.mcp_failed_servers.clone();
                        self.set_mcp_startup_banner(None);
                        self.submit_op(Op::McpRetry { servers });
                    }
                }
                ["retry", server] => {
                    self.set_mcp_startup_banner(None);
                    self.submit_op(Op::McpRetry {
                        servers: vec![(*server).to_string()],
                    });
                }
                ["timeout", server, seconds] => {
                    let secs: u64 = match seconds.parse() {
                        Ok(secs) => secs,
                        Err(_) => {
                            self.add_info_message(
                                "Usage: /mcp timeout <name> <seconds>".to_string(),
                                None,
                            );
                            return;
                        }
                    };
                    let server = (*server).to_string();
                    self.set_mcp_startup_banner(None);
                    self.app_event_tx.send(AppEvent::PersistMcpStartupTimeout {
                        server: server.clone(),
                        startup_timeout_sec: secs,
                    });
                    self.submit_op(Op::McpSetStartupTimeout {
                        server: server.clone(),
                        startup_timeout_sec: secs,
                    });
                    self.submit_op(Op::McpRetry {
                        servers: vec![server],
                    });
                }
                _ => {
                    self.add_info_message(
                        "Usage: /mcp [list] | /mcp retry [failed|<name>] | /mcp timeout <name> <seconds>".to_string(),
                        None,
                    );
                }
            }
            return;
        }

        // Special-case: "!cmd" executes a local shell command instead of sending to the model.
        if let Some(stripped) = text.strip_prefix('!') {
            let cmd = stripped.trim();
            if cmd.is_empty() {
                self.app_event_tx.send(AppEvent::InsertHistoryCell(Box::new(
                    history_cell::new_info_event(
                        USER_SHELL_COMMAND_HELP_TITLE.to_string(),
                        Some(USER_SHELL_COMMAND_HELP_HINT.to_string()),
                    ),
                )));
                return;
            }
            self.submit_op(Op::RunUserShellCommand {
                command: cmd.to_string(),
            });
            return;
        }

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "autocompact"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            let next = match args.as_slice() {
                [] => Some(!self.auto_compact_enabled),
                [arg] => match arg.to_ascii_lowercase().as_str() {
                    "on" | "enable" | "true" => Some(true),
                    "off" | "disable" | "false" => Some(false),
                    "toggle" => Some(!self.auto_compact_enabled),
                    "status" | "show" => None,
                    _ => {
                        self.add_info_message(
                            "Usage: /autocompact [on|off|toggle|status]".to_string(),
                            None,
                        );
                        return;
                    }
                },
                _ => {
                    self.add_info_message(
                        "Usage: /autocompact [on|off|toggle|status]".to_string(),
                        None,
                    );
                    return;
                }
            };

            if let Some(enabled) = next {
                self.auto_compact_enabled = enabled;
                let status = if enabled { "enabled" } else { "disabled" };
                self.add_info_message(format!("Auto-compact {status}."), None);
                self.app_event_tx
                    .send(AppEvent::CodexOp(Op::SetAutoCompact { enabled }));
            } else {
                let status = if self.auto_compact_enabled {
                    "enabled"
                } else {
                    "disabled"
                };
                self.add_info_message(format!("Auto-compact is currently {status}."), None);
            }
            return;
        }

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "thoughts"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            let next_hide = match args.as_slice() {
                [] => Some(!self.config.hide_agent_reasoning),
                [arg] => match arg.to_ascii_lowercase().as_str() {
                    "on" | "show" | "true" => Some(false),
                    "off" | "hide" | "false" => Some(true),
                    "toggle" => Some(!self.config.hide_agent_reasoning),
                    "status" => None,
                    _ => {
                        self.add_info_message(
                            "Usage: /thoughts [on|off|toggle|status]".to_string(),
                            None,
                        );
                        return;
                    }
                },
                _ => {
                    self.add_info_message(
                        "Usage: /thoughts [on|off|toggle|status]".to_string(),
                        None,
                    );
                    return;
                }
            };

            if let Some(hide) = next_hide {
                self.set_hide_agent_reasoning(hide);
                let status = if hide { "hidden" } else { "shown" };
                self.add_info_message(format!("Thoughts {status}."), None);
                self.app_event_tx
                    .send(AppEvent::UpdateHideAgentReasoning(hide));
                self.app_event_tx
                    .send(AppEvent::PersistHideAgentReasoning(hide));
            } else {
                let status = if self.config.hide_agent_reasoning {
                    "hidden"
                } else {
                    "shown"
                };
                self.add_info_message(format!("Thoughts are currently {status}."), None);
            }
            self.request_redraw();
            return;
        }

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "verbose"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            let current = self.config.tui_verbose_tool_output;
            let next = match args.as_slice() {
                [] => Some(!current),
                [arg] => match arg.to_ascii_lowercase().as_str() {
                    "on" | "show" | "enable" | "true" => Some(true),
                    "off" | "hide" | "disable" | "false" => Some(false),
                    "toggle" => Some(!current),
                    "status" => None,
                    _ => {
                        self.add_info_message(
                            "Usage: /verbose [on|off|toggle|status]".to_string(),
                            None,
                        );
                        return;
                    }
                },
                _ => {
                    self.add_info_message(
                        "Usage: /verbose [on|off|toggle|status]".to_string(),
                        None,
                    );
                    return;
                }
            };

            if let Some(verbose) = next {
                let status = if verbose { "enabled" } else { "disabled" };
                self.add_info_message(format!("Verbose tool output {status}."), None);
                self.app_event_tx
                    .send(AppEvent::UpdateVerboseToolOutput(verbose));
                self.app_event_tx
                    .send(AppEvent::PersistVerboseToolOutput(verbose));
            } else {
                let status = if current { "enabled" } else { "disabled" };
                self.add_info_message(format!("Verbose tool output is currently {status}."), None);
            }

            self.request_redraw();
            return;
        }

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "help"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            let topic = match args.as_slice() {
                [] => {
                    self.add_help_topics_output();
                    return;
                }
                [topic] => topic.to_ascii_lowercase(),
                _ => {
                    self.add_info_message("Usage: /help <topic>".to_string(), None);
                    return;
                }
            };

            match topic.as_str() {
                "xcodex" => {
                    self.add_help_xcodex_output();
                }
                _ => {
                    self.add_info_message(
                        format!("Unknown help topic `{topic}`. Try: /help xcodex"),
                        None,
                    );
                }
            }
            return;
        }

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "hooks"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            match args.as_slice() {
                [] => {
                    self.dispatch_command(SlashCommand::Hooks);
                }
                ["init"] => {
                    use codex_common::hooks_samples_install::HookSample;
                    let mut lines = Vec::new();
                    lines.push(vec!["/hooks init".magenta()].into());
                    lines.push(Line::from(""));
                    lines.push(vec!["Choose a hook mode:".magenta().bold()].into());
                    lines.push(vec!["1) ".dim(), HookSample::External.title().into()].into());
                    lines.push(vec!["   ".into(), HookSample::External.description().dim()].into());
                    lines.push(Line::from(""));
                    lines.push(vec!["2) ".dim(), HookSample::PythonHost.title().into()].into());
                    lines.push(
                        vec!["   ".into(), HookSample::PythonHost.description().dim()].into(),
                    );
                    lines.push(Line::from(""));
                    lines.push(vec!["3) ".dim(), HookSample::Pyo3.title().into()].into());
                    lines.push(vec!["   ".into(), HookSample::Pyo3.description().dim()].into());
                    lines.push(Line::from(""));
                    lines.push(vec!["Run: ".dim(), "/hooks init external".cyan()].into());
                    lines.push(vec!["Run: ".dim(), "/hooks init python-host".cyan()].into());
                    lines.push(vec!["Run: ".dim(), "/hooks init pyo3".cyan()].into());
                    lines.push(Line::from(""));
                    lines.push(
                        vec![
                            "Note: ".dim(),
                            "installing writes files; re-run with ".dim(),
                            "--yes".cyan(),
                            " to apply.".dim(),
                        ]
                        .into(),
                    );
                    self.add_plain_history_lines(lines);
                }
                ["init", mode, rest @ ..] => {
                    let mut force = false;
                    let mut dry_run = false;
                    let mut yes = false;
                    for arg in rest {
                        match *arg {
                            "--force" => force = true,
                            "--dry-run" => dry_run = true,
                            "--yes" => yes = true,
                            _ => {
                                self.add_info_message(
                                    "Usage: /hooks init <external|python-host|pyo3> [--dry-run] [--force] [--yes]".to_string(),
                                    None,
                                );
                                return;
                            }
                        }
                    }

                    let sample = match mode.to_ascii_lowercase().as_str() {
                        "1" | "external" => {
                            codex_common::hooks_samples_install::HookSample::External
                        }
                        "2" | "python-host" | "pythonhost" | "python-box" | "py-box" => {
                            codex_common::hooks_samples_install::HookSample::PythonHost
                        }
                        "3" | "pyo3" => codex_common::hooks_samples_install::HookSample::Pyo3,
                        _ => {
                            self.add_info_message(
                                "Unknown hook mode. Try: /hooks init".to_string(),
                                None,
                            );
                            return;
                        }
                    };

                    let codex_home = self.config.codex_home.clone();
                    let plan = codex_common::hooks_samples_install::plan_install_samples(
                        &codex_home,
                        sample,
                        force,
                    );
                    let plan = match plan {
                        Ok(plan) => plan,
                        Err(err) => {
                            self.add_error_message(format!("hooks init failed: {err}"));
                            return;
                        }
                    };

                    let text = codex_common::hooks_samples_install::format_sample_install_plan(
                        &plan, sample,
                    )
                    .unwrap_or_else(|_| String::from("failed to format plan"));
                    self.add_plain_history_lines(
                        text.lines().map(|l| Line::from(l.to_string())).collect(),
                    );

                    if dry_run {
                        return;
                    }
                    if !yes {
                        self.add_info_message(
                            "Re-run with --yes to apply these changes.".to_string(),
                            None,
                        );
                        return;
                    }

                    if let Err(err) = codex_common::hooks_samples_install::apply_install_samples(
                        &codex_home,
                        sample,
                        force,
                    ) {
                        self.add_error_message(format!("hooks init failed: {err}"));
                    }
                }
                ["install", "sdks", "list"] | ["install", "sdks", "--list"] => {
                    let mut lines = Vec::new();
                    lines.push(vec!["/hooks install sdks list".magenta()].into());
                    lines.push(Line::from(""));
                    lines.push(vec!["Available SDKs:".magenta().bold()].into());
                    for sdk in codex_common::hooks_sdk_install::all_hook_sdks() {
                        lines.push(
                            vec![
                                "- ".dim(),
                                sdk.id().cyan(),
                                ": ".dim(),
                                sdk.description().into(),
                            ]
                            .into(),
                        );
                    }
                    lines.push(
                        vec![
                            "- ".dim(),
                            "all".cyan(),
                            ": ".dim(),
                            "install everything".into(),
                        ]
                        .into(),
                    );
                    self.add_plain_history_lines(lines);
                }
                ["install", "samples", "list"] | ["install", "samples", "--list"] => {
                    use codex_common::hooks_samples_install::HookSample;
                    let mut lines = Vec::new();
                    lines.push(vec!["/hooks install samples list".magenta()].into());
                    lines.push(Line::from(""));
                    lines.push(vec!["Available sample sets:".magenta().bold()].into());
                    for sample in [
                        HookSample::External,
                        HookSample::PythonHost,
                        HookSample::Pyo3,
                    ] {
                        lines.push(
                            vec![
                                "- ".dim(),
                                sample.id().cyan(),
                                ": ".dim(),
                                sample.description().into(),
                            ]
                            .into(),
                        );
                    }
                    lines.push(
                        vec![
                            "- ".dim(),
                            "all".cyan(),
                            ": ".dim(),
                            "install everything".into(),
                        ]
                        .into(),
                    );
                    self.add_plain_history_lines(lines);
                }
                ["install", "sdks", ..] => {
                    let mut force = false;
                    let mut dry_run = false;
                    let mut yes = false;
                    let mut sdk_name: Option<&str> = None;
                    for arg in &args[2..] {
                        match *arg {
                            "--force" => force = true,
                            "--dry-run" => dry_run = true,
                            "--yes" => yes = true,
                            _ if arg.starts_with('-') => {
                                self.add_info_message(
                                    "Usage: /hooks install sdks <sdk|all> [--dry-run] [--force] [--yes] | /hooks install sdks list"
                                        .to_string(),
                                    None,
                                );
                                return;
                            }
                            _ => {
                                if sdk_name.is_some() {
                                    self.add_info_message(
                                        "Usage: /hooks install sdks <sdk|all> [--dry-run] [--force] [--yes] | /hooks install sdks list"
                                            .to_string(),
                                        None,
                                    );
                                    return;
                                }
                                sdk_name = Some(*arg);
                            }
                        }
                    }

                    let Some(sdk_name) = sdk_name else {
                        self.add_info_message(
                            "Usage: /hooks install sdks <sdk|all> [--dry-run] [--force] [--yes] | /hooks install sdks list"
                                .to_string(),
                            None,
                        );
                        return;
                    };

                    let targets = if sdk_name.eq_ignore_ascii_case("all") {
                        codex_common::hooks_sdk_install::all_hook_sdks()
                    } else {
                        match sdk_name.parse::<codex_common::hooks_sdk_install::HookSdk>() {
                            Ok(sdk) => vec![sdk],
                            Err(_) => {
                                self.add_info_message(
                                    format!(
                                        "Unknown SDK `{sdk_name}`. Try: /hooks install sdks list"
                                    ),
                                    None,
                                );
                                return;
                            }
                        }
                    };

                    let codex_home = self.config.codex_home.clone();
                    let plan = codex_common::hooks_sdk_install::plan_install_hook_sdks(
                        &codex_home,
                        &targets,
                        force,
                    );
                    let plan = match plan {
                        Ok(plan) => plan,
                        Err(err) => {
                            self.add_error_message(format!("hooks install failed: {err}"));
                            return;
                        }
                    };
                    let text = codex_common::hooks_sdk_install::format_install_plan(&plan)
                        .unwrap_or_else(|_| String::from("failed to format plan"));
                    self.add_plain_history_lines(
                        text.lines().map(|l| Line::from(l.to_string())).collect(),
                    );

                    if dry_run {
                        return;
                    }
                    if !yes {
                        self.add_info_message(
                            "Re-run with --yes to apply these changes.".to_string(),
                            None,
                        );
                        return;
                    }

                    let report = codex_common::hooks_sdk_install::install_hook_sdks(
                        &codex_home,
                        &targets,
                        force,
                    );
                    match report {
                        Ok(report) => {
                            let text =
                                codex_common::hooks_sdk_install::format_install_report(&report)
                                    .unwrap_or_else(|_| String::from("installed hook SDK files"));
                            self.add_plain_history_lines(
                                text.lines().map(|l| Line::from(l.to_string())).collect(),
                            );
                        }
                        Err(err) => self.add_error_message(format!("hooks install failed: {err}")),
                    }
                }
                ["install", "samples", ..] => {
                    let mut force = false;
                    let mut dry_run = false;
                    let mut yes = false;
                    let mut sample_name: Option<&str> = None;
                    for arg in &args[2..] {
                        match *arg {
                            "--force" => force = true,
                            "--dry-run" => dry_run = true,
                            "--yes" => yes = true,
                            _ if arg.starts_with('-') => {
                                self.add_info_message(
                                    "Usage: /hooks install samples <external|python-host|pyo3|all> [--dry-run] [--force] [--yes] | /hooks install samples list"
                                        .to_string(),
                                    None,
                                );
                                return;
                            }
                            _ => {
                                if sample_name.is_some() {
                                    self.add_info_message(
                                        "Usage: /hooks install samples <external|python-host|pyo3|all> [--dry-run] [--force] [--yes] | /hooks install samples list"
                                            .to_string(),
                                        None,
                                    );
                                    return;
                                }
                                sample_name = Some(*arg);
                            }
                        }
                    }

                    let Some(sample_name) = sample_name else {
                        self.add_info_message(
                            "Usage: /hooks install samples <external|python-host|pyo3|all> [--dry-run] [--force] [--yes] | /hooks install samples list"
                                .to_string(),
                            None,
                        );
                        return;
                    };

                    let samples = if sample_name.eq_ignore_ascii_case("all") {
                        vec![
                            codex_common::hooks_samples_install::HookSample::External,
                            codex_common::hooks_samples_install::HookSample::PythonHost,
                            codex_common::hooks_samples_install::HookSample::Pyo3,
                        ]
                    } else {
                        let sample = match sample_name.to_ascii_lowercase().as_str() {
                            "external" => codex_common::hooks_samples_install::HookSample::External,
                            "python-host" | "pythonhost" | "python-box" | "py-box" => {
                                codex_common::hooks_samples_install::HookSample::PythonHost
                            }
                            "pyo3" => codex_common::hooks_samples_install::HookSample::Pyo3,
                            _ => {
                                self.add_info_message(
                                    "Unknown sample. Try: /hooks install samples list".to_string(),
                                    None,
                                );
                                return;
                            }
                        };
                        vec![sample]
                    };

                    let codex_home = self.config.codex_home.clone();
                    for sample in samples {
                        let plan = codex_common::hooks_samples_install::plan_install_samples(
                            &codex_home,
                            sample,
                            force,
                        );
                        let plan = match plan {
                            Ok(plan) => plan,
                            Err(err) => {
                                self.add_error_message(format!("hooks install failed: {err}"));
                                return;
                            }
                        };
                        let text = codex_common::hooks_samples_install::format_sample_install_plan(
                            &plan, sample,
                        )
                        .unwrap_or_else(|_| String::from("failed to format plan"));
                        self.add_plain_history_lines(
                            text.lines().map(|l| Line::from(l.to_string())).collect(),
                        );

                        if dry_run {
                            continue;
                        }
                        if !yes {
                            self.add_info_message(
                                "Re-run with --yes to apply these changes.".to_string(),
                                None,
                            );
                            return;
                        }
                        if let Err(err) = codex_common::hooks_samples_install::apply_install_samples(
                            &codex_home,
                            sample,
                            force,
                        ) {
                            self.add_error_message(format!("hooks install failed: {err}"));
                        }
                    }
                }
                _ => {
                    self.add_info_message(
                        "Usage: /hooks init | /hooks install sdks ... | /hooks install samples ..."
                            .to_string(),
                        None,
                    );
                }
            }
            return;
        }

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "settings"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            match args.as_slice() {
                [] => self.dispatch_command(SlashCommand::Settings),
                ["worktrees"] => self.open_worktrees_settings_view(),
                _ => {
                    self.add_info_message("Usage: /settings [worktrees]".to_string(), None);
                }
            }
            return;
        }

        if image_paths.is_empty()
            && text.lines().count() == 1
            && let Some((name, rest)) = parse_slash_name(text.as_str())
            && name == "worktree"
        {
            let args: Vec<&str> = rest.split_whitespace().collect();
            match args.as_slice() {
                [] => {
                    self.dispatch_command(SlashCommand::Worktree);
                }
                ["detect"] | ["refresh"] => {
                    self.spawn_worktree_detection(true);
                }
                ["shared"] | ["shared", "list"] => {
                    self.add_worktree_shared_dirs_output();
                }
                ["shared", "add", dir] => {
                    fn normalize_shared_dir_arg(raw: &str) -> Result<String, String> {
                        use std::path::Component;
                        use std::path::Path;

                        let mut value = raw.trim().trim_end_matches(['/', '\\']).to_string();
                        while value.starts_with("./") {
                            value = value.trim_start_matches("./").to_string();
                        }
                        if value.is_empty() {
                            return Err(String::from("shared dir is empty"));
                        }
                        if value.starts_with('~') {
                            return Err(String::from("shared dirs must be repo-relative (no '~')"));
                        }

                        let path = Path::new(&value);
                        if path.is_absolute() {
                            return Err(String::from("shared dirs must be repo-relative"));
                        }

                        for component in path.components() {
                            match component {
                                Component::ParentDir
                                | Component::RootDir
                                | Component::Prefix(_) => {
                                    return Err(String::from(
                                        "shared dirs must not contain parent/root components",
                                    ));
                                }
                                Component::CurDir => {}
                                Component::Normal(_) => {}
                            }
                        }

                        Ok(value)
                    }

                    let dir = match normalize_shared_dir_arg(dir) {
                        Ok(dir) => dir,
                        Err(err) => {
                            self.add_error_message(format!("`/worktree shared add` — {err}"));
                            return;
                        }
                    };

                    let mut next = self.config.worktrees_shared_dirs.clone();
                    if next.contains(&dir) {
                        self.add_info_message(
                            format!("Shared dir already configured: `{dir}`"),
                            Some(String::from("Tip: run `/worktree shared list`")),
                        );
                        return;
                    }
                    next.push(dir);
                    self.config.worktrees_shared_dirs = next.clone();
                    self.app_event_tx.send(AppEvent::UpdateWorktreesSharedDirs {
                        shared_dirs: next.clone(),
                    });
                    self.app_event_tx
                        .send(AppEvent::PersistWorktreesSharedDirs { shared_dirs: next });
                    self.add_worktree_shared_dirs_output();
                }
                ["shared", "rm", dir] | ["shared", "remove", dir] => {
                    fn normalize_shared_dir_arg(raw: &str) -> Result<String, String> {
                        use std::path::Component;
                        use std::path::Path;

                        let mut value = raw.trim().trim_end_matches(['/', '\\']).to_string();
                        while value.starts_with("./") {
                            value = value.trim_start_matches("./").to_string();
                        }
                        if value.is_empty() {
                            return Err(String::from("shared dir is empty"));
                        }
                        if value.starts_with('~') {
                            return Err(String::from("shared dirs must be repo-relative (no '~')"));
                        }

                        let path = Path::new(&value);
                        if path.is_absolute() {
                            return Err(String::from("shared dirs must be repo-relative"));
                        }

                        for component in path.components() {
                            match component {
                                Component::ParentDir
                                | Component::RootDir
                                | Component::Prefix(_) => {
                                    return Err(String::from(
                                        "shared dirs must not contain parent/root components",
                                    ));
                                }
                                Component::CurDir => {}
                                Component::Normal(_) => {}
                            }
                        }

                        Ok(value)
                    }

                    let dir = match normalize_shared_dir_arg(dir) {
                        Ok(dir) => dir,
                        Err(err) => {
                            self.add_error_message(format!("`/worktree shared rm` — {err}"));
                            return;
                        }
                    };

                    let mut next: Vec<String> = Vec::new();
                    let mut removed = 0usize;
                    for entry in &self.config.worktrees_shared_dirs {
                        let normalized_entry =
                            normalize_shared_dir_arg(entry).unwrap_or_else(|_| entry.clone());
                        if normalized_entry == dir {
                            removed += 1;
                            continue;
                        }
                        next.push(entry.clone());
                    }
                    if removed == 0 {
                        self.add_error_message(format!(
                            "`/worktree shared rm` — `{dir}` is not in `worktrees.shared_dirs`"
                        ));
                        return;
                    }
                    self.config.worktrees_shared_dirs = next.clone();
                    self.app_event_tx.send(AppEvent::UpdateWorktreesSharedDirs {
                        shared_dirs: next.clone(),
                    });
                    self.app_event_tx
                        .send(AppEvent::PersistWorktreesSharedDirs { shared_dirs: next });
                    self.add_worktree_shared_dirs_output();
                }
                ["init", name, branch] | ["init", name, branch, ..] => {
                    let provided_path = args.get(3).copied();
                    if args.len() > 4 {
                        self.add_info_message(
                            "Usage: /worktree init <name> <branch> [<path>]".to_string(),
                            None,
                        );
                        return;
                    }

                    let cwd = self.config.cwd.clone();
                    let shared_dirs = self.config.worktrees_shared_dirs.clone();
                    let tx = self.app_event_tx.clone();
                    let name = name.to_string();
                    let branch = branch.to_string();
                    let path = provided_path.map(PathBuf::from);
                    tokio::spawn(async move {
                        let Some(current_root) =
                            codex_core::git_info::resolve_git_worktree_head(&cwd)
                                .map(|head| head.worktree_root)
                        else {
                            tx.send(AppEvent::InsertHistoryCell(Box::new(
                                history_cell::new_error_event(String::from(
                                    "`/worktree init` — not inside a git worktree (start xcodex in a repo/worktree directory, or switch via `/worktree`)",
                                )),
                            )));
                            return;
                        };

                        let Some(workspace_root) =
                            codex_core::git_info::resolve_root_git_project_for_trust(&current_root)
                        else {
                            tx.send(AppEvent::InsertHistoryCell(Box::new(
                                history_cell::new_error_event(String::from(
                                    "`/worktree init` — failed to resolve workspace root (the main worktree root for this repo)",
                                )),
                            )));
                            return;
                        };

                        let result = codex_core::git_info::init_git_worktree(
                            &workspace_root,
                            &name,
                            &branch,
                            path.as_deref(),
                        )
                        .await;

                        let path = match result {
                            Ok(path) => path,
                            Err(err) => {
                                let resolved_path = if let Some(path) = &path {
                                    if path.is_absolute() {
                                        path.clone()
                                    } else {
                                        workspace_root.join(path)
                                    }
                                } else {
                                    workspace_root.join(".worktrees").join(&name)
                                };
                                let mut lines: Vec<Line<'static>> = Vec::new();
                                lines.push(Line::from("worktree init"));
                                lines.push(Line::from(format!("error: {err}")));
                                lines.push(Line::from(""));
                                lines.push(Line::from("Try running this outside xcodex:"));
                                lines.push(Line::from(format!(
                                    "  git -C {} worktree add -b {} {}",
                                    workspace_root.display(),
                                    branch,
                                    resolved_path.display()
                                )));
                                lines.push(Line::from(format!(
                                    "  git -C {} worktree add {} {}   (if branch already exists)",
                                    workspace_root.display(),
                                    resolved_path.display(),
                                    branch
                                )));
                                lines.push(Line::from(format!(
                                    "  git -C {} worktree list --porcelain",
                                    workspace_root.display()
                                )));
                                tx.send(AppEvent::InsertHistoryCell(Box::new(
                                    PlainHistoryCell::new(lines),
                                )));
                                return;
                            }
                        };

                        let mut lines: Vec<Line<'static>> = Vec::new();
                        lines.push(Line::from("worktree init"));
                        lines.push(Line::from(format!(
                            "workspace root: {}",
                            workspace_root.display()
                        )));
                        lines.push(Line::from(format!("created: {}", path.display())));

                        if !shared_dirs.is_empty() {
                            let actions = codex_core::git_info::link_worktree_shared_dirs(
                                &path,
                                &workspace_root,
                                &shared_dirs,
                            )
                            .await;

                            let mut linked_dirs: Vec<(String, PathBuf)> = Vec::new();
                            for action in actions {
                                if matches!(
                                    action.outcome,
                                    codex_core::git_info::SharedDirLinkOutcome::Linked
                                        | codex_core::git_info::SharedDirLinkOutcome::AlreadyLinked
                                ) {
                                    linked_dirs.push((action.shared_dir, action.target_path));
                                }
                            }

                            if !linked_dirs.is_empty() {
                                lines.push(Line::from(""));
                                lines.push(Line::from(
                                    "Shared dirs (writes land in workspace root):",
                                ));
                                for (dir, target) in linked_dirs {
                                    lines.push(Line::from(format!(
                                        "- {dir} -> {}",
                                        target.display()
                                    )));
                                }
                            }
                        }

                        tx.send(AppEvent::InsertHistoryCell(Box::new(
                            PlainHistoryCell::new(lines),
                        )));

                        tx.send(AppEvent::WorktreeSwitched(path.clone()));
                        tx.send(AppEvent::CodexOp(
                            codex_core::protocol::Op::OverrideTurnContext {
                                cwd: Some(path.clone()),
                                approval_policy: None,
                                sandbox_policy: None,
                                model: None,
                                effort: None,
                                summary: None,
                            },
                        ));
                        tx.send(AppEvent::CodexOp(codex_core::protocol::Op::ListSkills {
                            cwds: vec![path],
                            force_reload: true,
                        }));
                    });
                }
                ["doctor"] => {
                    let cwd = self.config.cwd.clone();
                    let shared_dirs = self.config.worktrees_shared_dirs.clone();
                    let tx = self.app_event_tx.clone();
                    tokio::spawn(async move {
                        let mut lines =
                            codex_core::git_info::worktree_doctor_lines(&cwd, &shared_dirs, 5)
                                .await;
                        if lines.first().is_some_and(|line| line == "worktree doctor") {
                            lines.remove(0);
                        }
                        while lines.first().is_some_and(|line| line.trim().is_empty()) {
                            lines.remove(0);
                        }

                        let lines = lines.into_iter().map(Line::from).collect();
                        let command = PlainHistoryCell::new(vec![Line::from(vec![
                            "/worktree doctor".magenta(),
                        ])]);
                        tx.send(AppEvent::InsertHistoryCell(Box::new(
                            CompositeHistoryCell::new(vec![
                                Box::new(command),
                                Box::new(PlainHistoryCell::new(lines)),
                            ]),
                        )));
                    });
                }
                ["link-shared", "migrate"] | ["link-shared", "--migrate"] => {
                    if self.config.worktrees_shared_dirs.is_empty() {
                        self.add_info_message(
                            "No shared dirs configured. Set `worktrees.shared_dirs` in config first."
                                .to_string(),
                            None,
                        );
                        return;
                    }

                    let show_notice = !self.shared_dirs_write_notice_shown;
                    self.shared_dirs_write_notice_shown = true;

                    let cwd = self.config.cwd.clone();
                    let Some(worktree_root) = codex_core::git_info::resolve_git_worktree_head(&cwd)
                        .map(|head| head.worktree_root)
                    else {
                        self.add_error_message(String::from(
                            "`/worktree link-shared` — not inside a git worktree (start xcodex in a repo/worktree directory, or switch via `/worktree`)",
                        ));
                        return;
                    };

                    let Some(workspace_root) =
                        codex_core::git_info::resolve_root_git_project_for_trust(&worktree_root)
                    else {
                        self.add_error_message(String::from(
                            "`/worktree link-shared` — failed to resolve workspace root (the main worktree root for this repo)",
                        ));
                        return;
                    };

                    if worktree_root == workspace_root {
                        self.add_to_history(history_cell::new_info_event(
                            String::from("Already in the workspace root worktree."),
                            None,
                        ));
                        return;
                    }

                    let view = crate::bottom_pane::WorktreeLinkSharedWizardView::new(
                        worktree_root,
                        workspace_root,
                        self.config.worktrees_shared_dirs.clone(),
                        true,
                        show_notice,
                        String::from("/worktree link-shared --migrate"),
                        self.app_event_tx.clone(),
                    );
                    self.bottom_pane.show_view(Box::new(view));
                    self.request_redraw();
                }
                ["link-shared"] => {
                    if self.config.worktrees_shared_dirs.is_empty() {
                        self.add_info_message(
                            "No shared dirs configured. Set `worktrees.shared_dirs` in config first."
                                .to_string(),
                            None,
                        );
                        return;
                    }

                    let show_notice = !self.shared_dirs_write_notice_shown;
                    self.shared_dirs_write_notice_shown = true;

                    let cwd = self.config.cwd.clone();
                    let Some(worktree_root) = codex_core::git_info::resolve_git_worktree_head(&cwd)
                        .map(|head| head.worktree_root)
                    else {
                        self.add_error_message(String::from(
                            "`/worktree link-shared` — not inside a git worktree (start xcodex in a repo/worktree directory, or switch via `/worktree`)",
                        ));
                        return;
                    };

                    let Some(workspace_root) =
                        codex_core::git_info::resolve_root_git_project_for_trust(&worktree_root)
                    else {
                        self.add_error_message(String::from(
                            "`/worktree link-shared` — failed to resolve workspace root (the main worktree root for this repo)",
                        ));
                        return;
                    };

                    if worktree_root == workspace_root {
                        self.add_to_history(history_cell::new_info_event(
                            String::from("Already in the workspace root worktree."),
                            None,
                        ));
                        return;
                    }

                    let view = crate::bottom_pane::WorktreeLinkSharedWizardView::new(
                        worktree_root,
                        workspace_root,
                        self.config.worktrees_shared_dirs.clone(),
                        false,
                        show_notice,
                        String::from("/worktree link-shared"),
                        self.app_event_tx.clone(),
                    );
                    self.bottom_pane.show_view(Box::new(view));
                    self.request_redraw();
                }
                [target] => {
                    let matches: Vec<&GitWorktreeEntry> = self
                        .worktree_list
                        .iter()
                        .filter(|entry| {
                            entry
                                .path
                                .file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| name.eq_ignore_ascii_case(target))
                        })
                        .collect();

                    let selected_path = if matches.len() == 1 {
                        Some(matches[0].path.clone())
                    } else if matches.len() > 1 {
                        self.add_info_message(
                            format!(
                                "Multiple worktrees match `{target}`. Use a full path or run `/worktree` to pick."
                            ),
                            None,
                        );
                        None
                    } else {
                        let candidate = PathBuf::from(target);
                        let candidate = if candidate.is_absolute() {
                            candidate
                        } else {
                            self.config.cwd.join(candidate)
                        };
                        if candidate.is_dir() {
                            Some(candidate)
                        } else {
                            if self.worktree_list.is_empty()
                                && !self.worktree_list_refresh_in_progress
                            {
                                self.spawn_worktree_detection(true);
                                self.add_info_message(
                                    format!(
                                        "Unknown worktree `{target}`. Refreshing worktrees; run `/worktree` to pick."
                                    ),
                                    None,
                                );
                            } else {
                                self.add_info_message(
                                    format!(
                                        "Unknown worktree `{target}`. Run `/worktree` to pick or `/worktree detect` to refresh."
                                    ),
                                    None,
                                );
                            }
                            None
                        }
                    };

                    if let Some(path) = selected_path {
                        self.app_event_tx
                            .send(AppEvent::WorktreeSwitched(path.clone()));
                        self.app_event_tx
                            .send(AppEvent::CodexOp(Op::OverrideTurnContext {
                                cwd: Some(path.clone()),
                                approval_policy: None,
                                sandbox_policy: None,
                                model: None,
                                effort: None,
                                summary: None,
                            }));
                        self.app_event_tx.send(AppEvent::CodexOp(Op::ListSkills {
                            cwds: vec![path],
                            force_reload: true,
                        }));
                    }
                }
                _ => {
                    self.add_info_message(
                        "Usage: /worktree [detect|doctor|shared|init|link-shared [--migrate]|<name|path>]"
                            .to_string(),
                        None,
                    );
                }
            }

            return;
        }

        for path in image_paths {
            items.push(UserInput::LocalImage { path });
        }

        if !text.is_empty() {
            items.push(UserInput::Text { text: text.clone() });
        }

        if let Some(skills) = self.bottom_pane.skills() {
            let skill_mentions = find_skill_mentions(&text, skills);
            for skill in skill_mentions {
                items.push(UserInput::Skill {
                    name: skill.name.clone(),
                    path: skill.path.clone(),
                });
            }
        }

        self.codex_op_tx
            .send(Op::UserInput {
                items,
                final_output_json_schema: None,
            })
            .unwrap_or_else(|e| {
                tracing::error!("failed to send message: {e}");
            });

        // Persist the text to cross-session message history.
        if !text.is_empty() {
            self.codex_op_tx
                .send(Op::AddToHistory { text: text.clone() })
                .unwrap_or_else(|e| {
                    tracing::error!("failed to send AddHistory op: {e}");
                });
        }

        // Only show the text portion in conversation history.
        if !text.is_empty() {
            self.add_to_history(history_cell::new_user_prompt(text));
        }
        self.needs_final_message_separator = false;
    }

    /// Replay a subset of initial events into the UI to seed the transcript when
    /// resuming an existing session. This approximates the live event flow and
    /// is intentionally conservative: only safe-to-replay items are rendered to
    /// avoid triggering side effects. Event ids are passed as `None` to
    /// distinguish replayed events from live ones.
    fn replay_initial_messages(&mut self, events: Vec<EventMsg>) {
        for msg in events {
            if matches!(msg, EventMsg::SessionConfigured(_)) {
                continue;
            }
            // `id: None` indicates a synthetic/fake id coming from replay.
            self.dispatch_event_msg(None, msg, true);
        }
    }

    pub(crate) fn handle_codex_event(&mut self, event: Event) {
        let Event { id, msg } = event;
        self.dispatch_event_msg(Some(id), msg, false);
    }

    /// Dispatch a protocol `EventMsg` to the appropriate handler.
    ///
    /// `id` is `Some` for live events and `None` for replayed events from
    /// `replay_initial_messages()`. Callers should treat `None` as a "fake" id
    /// that must not be used to correlate follow-up actions.
    fn dispatch_event_msg(&mut self, id: Option<String>, msg: EventMsg, from_replay: bool) {
        let is_stream_error = matches!(&msg, EventMsg::StreamError(_));
        if !is_stream_error {
            self.restore_retry_status_header_if_present();
        }

        match msg {
            EventMsg::AgentMessageDelta(_)
            | EventMsg::AgentReasoningDelta(_)
            | EventMsg::TerminalInteraction(_)
            | EventMsg::ExecCommandOutputDelta(_) => {}
            _ => {
                tracing::trace!("handle_codex_event: {:?}", msg);
            }
        }

        match msg {
            EventMsg::SessionConfigured(e) => self.on_session_configured(e),
            EventMsg::AgentMessage(AgentMessageEvent { message }) => self.on_agent_message(message),
            EventMsg::AgentMessageDelta(AgentMessageDeltaEvent { delta }) => {
                self.on_agent_message_delta(delta)
            }
            EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent { delta })
            | EventMsg::AgentReasoningRawContentDelta(AgentReasoningRawContentDeltaEvent {
                delta,
            }) => self.on_agent_reasoning_delta(delta),
            EventMsg::AgentReasoning(AgentReasoningEvent { .. }) => self.on_agent_reasoning_final(),
            EventMsg::AgentReasoningRawContent(AgentReasoningRawContentEvent { text }) => {
                self.on_agent_reasoning_delta(text);
                self.on_agent_reasoning_final();
            }
            EventMsg::AgentReasoningSectionBreak(_) => self.on_reasoning_section_break(),
            EventMsg::TurnStarted(_) => self.on_task_started(),
            EventMsg::TurnComplete(TurnCompleteEvent { last_agent_message }) => {
                self.on_task_complete(last_agent_message)
            }
            EventMsg::TokenCount(ev) => {
                if let Some(info) = ev.info {
                    self.set_token_info(Some(info));
                }
                self.on_rate_limit_snapshot(ev.rate_limits);
            }
            EventMsg::Warning(WarningEvent { message }) => self.on_warning(message),
            EventMsg::Error(ErrorEvent { message, .. }) => self.on_error(message),
            EventMsg::McpStartupUpdate(ev) => self.on_mcp_startup_update(ev),
            EventMsg::McpStartupComplete(ev) => self.on_mcp_startup_complete(ev),
            EventMsg::TurnAborted(ev) => match ev.reason {
                TurnAbortReason::Interrupted => {
                    self.on_interrupted_turn(ev.reason);
                }
                TurnAbortReason::Replaced => {
                    self.on_error("Turn aborted: replaced by a new task".to_owned())
                }
                TurnAbortReason::ReviewEnded => {
                    self.on_interrupted_turn(ev.reason);
                }
            },
            EventMsg::PlanUpdate(update) => self.on_plan_update(update),
            EventMsg::ExecApprovalRequest(ev) => {
                // For replayed events, synthesize an empty id (these should not occur).
                self.on_exec_approval_request(id.unwrap_or_default(), ev)
            }
            EventMsg::ApplyPatchApprovalRequest(ev) => {
                self.on_apply_patch_approval_request(id.unwrap_or_default(), ev)
            }
            EventMsg::ElicitationRequest(ev) => {
                self.on_elicitation_request(ev);
            }
            EventMsg::ExecCommandBegin(ev) => self.on_exec_command_begin(ev),
            EventMsg::TerminalInteraction(delta) => self.on_terminal_interaction(delta),
            EventMsg::HookProcessBegin(ev) => self.on_hook_process_begin(ev),
            EventMsg::HookProcessEnd(ev) => self.on_hook_process_end(ev),
            EventMsg::ExecCommandOutputDelta(delta) => self.on_exec_command_output_delta(delta),
            EventMsg::PatchApplyBegin(ev) => self.on_patch_apply_begin(ev),
            EventMsg::PatchApplyEnd(ev) => self.on_patch_apply_end(ev),
            EventMsg::ExecCommandEnd(ev) => self.on_exec_command_end(ev),
            EventMsg::ViewImageToolCall(ev) => self.on_view_image_tool_call(ev),
            EventMsg::McpToolCallBegin(ev) => self.on_mcp_tool_call_begin(ev),
            EventMsg::McpToolCallEnd(ev) => self.on_mcp_tool_call_end(ev),
            EventMsg::WebSearchBegin(ev) => self.on_web_search_begin(ev),
            EventMsg::WebSearchEnd(ev) => self.on_web_search_end(ev),
            EventMsg::GetHistoryEntryResponse(ev) => self.on_get_history_entry_response(ev),
            EventMsg::McpListToolsResponse(ev) => self.on_list_mcp_tools(ev),
            EventMsg::ListCustomPromptsResponse(ev) => self.on_list_custom_prompts(ev),
            EventMsg::ListSkillsResponse(ev) => self.on_list_skills(ev),
            EventMsg::SkillsUpdateAvailable => {
                self.submit_op(Op::ListSkills {
                    cwds: Vec::new(),
                    force_reload: true,
                });
            }
            EventMsg::ShutdownComplete => self.on_shutdown_complete(),
            EventMsg::TurnDiff(TurnDiffEvent { unified_diff }) => self.on_turn_diff(unified_diff),
            EventMsg::DeprecationNotice(ev) => self.on_deprecation_notice(ev),
            EventMsg::BackgroundEvent(BackgroundEventEvent { message }) => {
                self.on_background_event(message)
            }
            EventMsg::UndoStarted(ev) => self.on_undo_started(ev),
            EventMsg::UndoCompleted(ev) => self.on_undo_completed(ev),
            EventMsg::StreamError(StreamErrorEvent {
                message,
                additional_details,
                ..
            }) => self.on_stream_error(message, additional_details),
            EventMsg::UserMessage(ev) => {
                if from_replay {
                    self.on_user_message_event(ev);
                }
            }
            EventMsg::EnteredReviewMode(review_request) => {
                self.on_entered_review_mode(review_request)
            }
            EventMsg::ExitedReviewMode(review) => self.on_exited_review_mode(review),
            EventMsg::ContextCompacted(_) => self.on_agent_message("Context compacted".to_owned()),
            EventMsg::RawResponseItem(_)
            | EventMsg::ThreadRolledBack(_)
            | EventMsg::ItemStarted(_)
            | EventMsg::ItemCompleted(_)
            | EventMsg::AgentMessageContentDelta(_)
            | EventMsg::ReasoningContentDelta(_)
            | EventMsg::ReasoningRawContentDelta(_) => {}
        }
    }

    fn on_entered_review_mode(&mut self, review: ReviewRequest) {
        // Enter review mode and emit a concise banner
        if self.pre_review_token_info.is_none() {
            self.pre_review_token_info = Some(self.token_info.clone());
        }
        self.is_review_mode = true;
        let hint = review
            .user_facing_hint
            .unwrap_or_else(|| codex_core::review_prompts::user_facing_hint(&review.target));
        let banner = format!(">> Code review started: {hint} <<");
        self.add_to_history(history_cell::new_review_status_line(banner));
        self.request_redraw();
    }

    fn on_exited_review_mode(&mut self, review: ExitedReviewModeEvent) {
        // Leave review mode; if output is present, flush pending stream + show results.
        if let Some(output) = review.review_output {
            self.flush_answer_stream_with_separator();
            self.flush_interrupt_queue();
            self.flush_active_cell();

            if output.findings.is_empty() {
                let explanation = output.overall_explanation.trim().to_string();
                if explanation.is_empty() {
                    tracing::error!("Reviewer failed to output a response.");
                    self.add_to_history(history_cell::new_error_event(
                        "Reviewer failed to output a response.".to_owned(),
                    ));
                } else {
                    // Show explanation when there are no structured findings.
                    let mut rendered: Vec<ratatui::text::Line<'static>> = vec!["".into()];
                    append_markdown(&explanation, None, &mut rendered);
                    let body_cell = AgentMessageCell::new(rendered, false);
                    self.app_event_tx
                        .send(AppEvent::InsertHistoryCell(Box::new(body_cell)));
                }
            }
            // Final message is rendered as part of the AgentMessage.
        }

        self.is_review_mode = false;
        self.restore_pre_review_token_info();
        // Append a finishing banner at the end of this turn.
        self.add_to_history(history_cell::new_review_status_line(
            "<< Code review finished >>".to_string(),
        ));
        self.request_redraw();
    }

    fn on_user_message_event(&mut self, event: UserMessageEvent) {
        let message = event.message.trim();
        if !message.is_empty() {
            self.add_to_history(history_cell::new_user_prompt(message.to_string()));
        }
    }

    fn request_exit(&self) {
        self.app_event_tx.send(AppEvent::ExitRequest);
    }

    fn request_redraw(&mut self) {
        self.frame_requester.schedule_frame();
    }

    fn notify(&mut self, notification: Notification) {
        if !notification.allowed_for(&self.config.tui_notifications) {
            return;
        }
        self.pending_notification = Some(notification);
        self.request_redraw();
    }

    pub(crate) fn maybe_post_pending_notification(&mut self, tui: &mut crate::tui::Tui) {
        if let Some(notif) = self.pending_notification.take() {
            tui.notify(notif.display());
        }
    }

    /// Mark the active cell as failed (✗) and flush it into history.
    fn finalize_active_cell_as_failed(&mut self) {
        if let Some(mut cell) = self.active_cell.take() {
            // Insert finalized cell into history and keep grouping consistent.
            if let Some(exec) = cell.as_any_mut().downcast_mut::<ExecCell>() {
                exec.mark_failed();
            } else if let Some(tool) = cell.as_any_mut().downcast_mut::<McpToolCallCell>() {
                tool.mark_failed();
            }
            self.add_boxed_history(cell);
        }
    }

    // If idle and there are queued inputs, submit exactly one to start the next turn.
    fn maybe_send_next_queued_input(&mut self) {
        if self.bottom_pane.is_task_running() {
            return;
        }
        if let Some(user_message) = self.queued_user_messages.pop_front() {
            self.submit_user_message(user_message);
        }
        // Update the list to reflect the remaining queued messages (if any).
        self.refresh_queued_user_messages();
    }

    /// Rebuild and update the queued user messages from the current queue.
    fn refresh_queued_user_messages(&mut self) {
        let messages: Vec<String> = self
            .queued_user_messages
            .iter()
            .map(|m| m.text.clone())
            .collect();
        self.bottom_pane.set_queued_user_messages(messages);
    }

    pub(crate) fn add_diff_in_progress(&mut self) {
        self.request_redraw();
    }

    pub(crate) fn on_diff_complete(&mut self) {
        self.request_redraw();
    }

    pub(crate) fn status_menu_status_cell(&self) -> Box<dyn HistoryCell> {
        let default_usage = TokenUsage::default();
        let token_info = self.token_info.as_ref();
        let total_usage = token_info
            .map(|ti| &ti.total_token_usage)
            .unwrap_or(&default_usage);
        let session_stats = (!self.session_stats.is_empty()).then_some(&self.session_stats);

        crate::status::new_status_menu_summary_card_with_session_stats(
            &self.config,
            self.auth_manager.as_ref(),
            token_info,
            total_usage,
            &self.conversation_id,
            session_stats,
            self.rate_limit_snapshot.as_ref(),
            self.plan_type,
            Local::now(),
            &self.model,
        )
    }

    pub(crate) fn add_help_topics_output(&mut self) {
        let command = PlainHistoryCell::new(vec![Line::from(vec!["/help".magenta()])]);
        let body = PlainHistoryCell::new(vec![
            vec!["Topics: ".into(), "xcodex".cyan().bold()].into(),
            vec!["Try: ".dim(), "/help xcodex".cyan()].into(),
        ]);
        self.add_to_history(CompositeHistoryCell::new(vec![
            Box::new(command),
            Box::new(body),
        ]));
    }

    pub(crate) fn add_worktree_shared_dirs_output(&mut self) {
        let command = PlainHistoryCell::new(vec![Line::from(vec!["/worktree shared".magenta()])]);
        let mut lines: Vec<Line<'static>> = Vec::new();

        lines.push(
            vec![
                "worktrees.shared_dirs".cyan().bold(),
                " (shared across worktrees)".dim(),
            ]
            .into(),
        );

        if self.config.worktrees_shared_dirs.is_empty() {
            lines.push(vec!["(none)".dim()].into());
        } else {
            for dir in &self.config.worktrees_shared_dirs {
                lines.push(vec!["- ".dim(), dir.clone().into()].into());
            }
        }

        lines.push(Line::from(""));
        lines.push(vec!["Add: ".dim(), "/worktree shared add <dir>".cyan()].into());
        lines.push(vec!["Remove: ".dim(), "/worktree shared rm <dir>".cyan()].into());
        lines.push(
            vec![
                "Apply: ".dim(),
                "/worktree link-shared".cyan(),
                " ".dim(),
                "(in current worktree)".dim(),
            ]
            .into(),
        );
        lines.push(vec!["Docs: ".dim(), "docs/xcodex/worktrees.md".cyan()].into());

        self.add_to_history(CompositeHistoryCell::new(vec![
            Box::new(command),
            Box::new(PlainHistoryCell::new(lines)),
        ]));
    }

    pub(crate) fn add_hooks_output(&mut self) {
        let command = PlainHistoryCell::new(vec![Line::from(vec!["/hooks".magenta()])]);
        let codex_home = self.config.codex_home.clone();
        let logs_dir = codex_home.join("tmp").join("hooks").join("logs");
        let payloads_dir = codex_home.join("tmp").join("hooks").join("payloads");

        let lines: Vec<Line<'static>> = vec![
            Line::from(vec![
                "Automation hooks run external programs on lifecycle events. ".into(),
                "Treat hook payloads/logs as potentially sensitive.".dim(),
            ]),
            Line::from(""),
            Line::from(vec!["Quickstart:".magenta().bold()]),
            Line::from(vec!["  xcodex hooks init".cyan()]),
            Line::from(vec!["  xcodex hooks install sdks list".cyan()]),
            Line::from(vec!["  xcodex hooks install sdks python".cyan()]),
            Line::from(vec!["  xcodex hooks install samples list".cyan()]),
            Line::from(vec!["  xcodex hooks install samples external".cyan()]),
            Line::from(vec!["  xcodex hooks help".cyan()]),
            Line::from(vec![
                "  xcodex hooks test external --configured-only".cyan(),
            ]),
            Line::from(vec!["  xcodex hooks list".cyan()]),
            Line::from(vec!["  xcodex hooks paths".cyan()]),
            Line::from(""),
            Line::from(vec![
                "Config: ".dim(),
                format!("{}/config.toml", codex_home.display()).into(),
            ]),
            Line::from(vec!["Logs: ".dim(), logs_dir.display().to_string().into()]),
            Line::from(vec![
                "Payloads: ".dim(),
                payloads_dir.display().to_string().into(),
            ]),
            Line::from(""),
            Line::from(vec![
                "Docs: ".dim(),
                "docs/xcodex/hooks.md".cyan(),
                " and ".dim(),
                "docs/xcodex/hooks-gallery.md".cyan(),
                " and ".dim(),
                "docs/xcodex/hooks-sdks.md".cyan(),
                " and ".dim(),
                "docs/xcodex/hooks-python-host.md".cyan(),
                " and ".dim(),
                "docs/xcodex/hooks-pyo3.md".cyan(),
            ]),
        ];

        self.add_to_history(CompositeHistoryCell::new(vec![
            Box::new(command),
            Box::new(PlainHistoryCell::new(lines)),
        ]));
    }

    pub(crate) fn add_help_xcodex_output(&mut self) {
        let command = PlainHistoryCell::new(vec![Line::from(vec!["/help xcodex".magenta()])]);
        let body = PlainHistoryCell::new(vec![
            vec!["xcodex".cyan().bold(), " additions in this UI".dim()].into(),
            vec![
                "• ".dim(),
                "/settings".cyan(),
                " — ".dim(),
                "status bar items (git branch/worktree)".into(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Try: ".dim(),
                "/settings status-bar git-branch toggle".cyan(),
            ]
            .into(),
            vec!["  ".into(), "Try: ".dim(), "/settings worktrees".cyan()].into(),
            vec![
                "• ".dim(),
                "xcodex config".cyan(),
                " — ".dim(),
                "edit or diagnose $CODEX_HOME/config.toml".into(),
            ]
            .into(),
            vec!["  ".into(), "Try: ".dim(), "xcodex config edit".cyan()].into(),
            vec!["  ".into(), "Try: ".dim(), "xcodex config doctor".cyan()].into(),
            vec![
                "• ".dim(),
                "/worktree".cyan(),
                " — ".dim(),
                "switch this session between git worktrees".into(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Contract: ".dim(),
                "tool cwd = active worktree root".into(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Shared dirs (opt-in): ".dim(),
                "linked back to workspace root (writes land there)".into(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Pinned paths (opt-in): ".dim(),
                "worktrees.pinned_paths".cyan(),
                " ".dim(),
                "(file tools only)".dim(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Docs: ".dim(),
                "docs/xcodex/worktrees.md".cyan(),
            ]
            .into(),
            vec!["  ".into(), "Try: ".dim(), "/worktree detect".cyan()].into(),
            vec![
                "  ".into(),
                "Try: ".dim(),
                "/worktree doctor".cyan(),
                " ".dim(),
                "(shared dirs / untracked)".dim(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Try: ".dim(),
                "/worktree link-shared".cyan(),
                " ".dim(),
                "(apply shared-dir links)".dim(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Try: ".dim(),
                "/worktree link-shared --migrate".cyan(),
                " ".dim(),
                "(migrate git-untracked files, then link)".dim(),
            ]
            .into(),
            vec![
                "  ".into(),
                "Try: ".dim(),
                "/worktree shared add docs/impl-plans".cyan(),
                " ".dim(),
                "(configure shared dirs)".dim(),
            ]
            .into(),
            vec![
                "• ".dim(),
                "/thoughts".cyan(),
                " — ".dim(),
                "show/hide agent reasoning".into(),
            ]
            .into(),
            vec!["  ".into(), "Try: ".dim(), "/thoughts toggle".cyan()].into(),
        ]);
        self.add_to_history(CompositeHistoryCell::new(vec![
            Box::new(command),
            Box::new(body),
        ]));
    }

    pub(crate) fn add_ps_output(&mut self) {
        let sessions = self
            .unified_exec_sessions
            .iter()
            .map(|session| {
                history_cell::BackgroundActivityEntry::new(
                    session.key.clone(),
                    session.command_display.clone(),
                )
            })
            .collect();
        let hooks = self
            .hook_processes
            .iter()
            .map(|hook| {
                history_cell::BackgroundActivityEntry::new(
                    hook.key.clone(),
                    hook.command_display.clone(),
                )
            })
            .collect();
        self.add_to_history(history_cell::new_unified_exec_sessions_output(
            sessions, hooks,
        ));
    }

    fn open_kill_popup(&mut self) {
        if self.unified_exec_sessions.is_empty() {
            self.add_info_message("No background terminals running.".to_string(), None);
            return;
        }

        let mut items: Vec<SelectionItem> = Vec::new();

        let all_actions: Vec<SelectionAction> = vec![Box::new(|tx| {
            tx.send(AppEvent::CodexOp(Op::TerminateAllUnifiedExecSessions));
            tx.send(AppEvent::InsertHistoryCell(Box::new(
                history_cell::new_info_event(
                    "Terminating all background terminals…".to_string(),
                    None,
                ),
            )));
        })];
        items.push(SelectionItem {
            name: "Terminate all background terminals".to_string(),
            description: Some("Closes every running background terminal session.".to_string()),
            selected_description: None,
            is_current: false,
            actions: all_actions,
            dismiss_on_select: true,
            ..Default::default()
        });

        for session in &self.unified_exec_sessions {
            let process_id = session.key.clone();
            let process_id_for_action = process_id.clone();
            let command_display = session.command_display.clone();
            let search_value = format!("{process_id} {command_display}");
            let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                tx.send(AppEvent::CodexOp(Op::TerminateUnifiedExecSession {
                    process_id: process_id_for_action.clone(),
                }));
                tx.send(AppEvent::InsertHistoryCell(Box::new(
                    history_cell::new_info_event(
                        format!("Terminating background terminal {process_id_for_action}…"),
                        None,
                    ),
                )));
            })];
            items.push(SelectionItem {
                name: process_id,
                description: Some(command_display),
                selected_description: None,
                is_current: false,
                actions,
                dismiss_on_select: true,
                search_value: Some(search_value),
                ..Default::default()
            });
        }

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Terminate background terminals".to_string()),
            subtitle: Some("Select a unified-exec session id (shown by /ps).".to_string()),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            is_searchable: true,
            search_placeholder: Some("Search by id or command".to_string()),
            ..Default::default()
        });
        self.request_redraw();
    }

    fn stop_rate_limit_poller(&mut self) {
        if let Some(handle) = self.rate_limit_poller.take() {
            handle.abort();
        }
    }

    fn stop_status_bar_git_poller(&mut self) {
        if let Some(handle) = self.status_bar_git_poller.take() {
            handle.abort();
        }
    }

    fn refresh_status_bar_git_poller(&mut self) {
        self.stop_status_bar_git_poller();

        let show_branch = self.config.tui_status_bar_show_git_branch;
        let show_worktree = self.config.tui_status_bar_show_worktree;

        self.bottom_pane.set_status_bar_git_context(None, None);

        if !show_branch && !show_worktree {
            return;
        }

        let cwd = self.config.cwd.clone();
        let tx = self.app_event_tx.clone();

        let handle = tokio::spawn(async move {
            use notify::RecursiveMode;
            use notify::Watcher as _;

            let mut last_branch: Option<String> = None;
            let mut last_worktree_root: Option<PathBuf> = None;

            let (fs_tx, mut fs_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
            let mut watched_head_path: Option<PathBuf> = None;
            let mut watcher: Option<notify::RecommendedWatcher> = None;

            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            let mut dirty = true;

            loop {
                if dirty {
                    dirty = false;

                    let Some(worktree_head) = codex_core::git_info::resolve_git_worktree_head(&cwd)
                    else {
                        watched_head_path = None;
                        watcher = None;

                        if last_branch.is_some() || last_worktree_root.is_some() {
                            last_branch = None;
                            last_worktree_root = None;
                            tx.send(AppEvent::UpdateStatusBarGitContext {
                                git_branch: None,
                                worktree_root: None,
                            });
                        }
                        continue;
                    };

                    if watched_head_path.as_ref() != Some(&worktree_head.head_path) {
                        watched_head_path = Some(worktree_head.head_path.clone());
                        watcher = None;
                    }

                    if watcher.is_none()
                        && let Ok(mut new_watcher) = notify::recommended_watcher({
                            let fs_tx = fs_tx.clone();
                            move |res: Result<notify::Event, notify::Error>| {
                                if res.is_ok() {
                                    let _ = fs_tx.send(());
                                }
                            }
                        })
                        && new_watcher
                            .watch(&worktree_head.head_path, RecursiveMode::NonRecursive)
                            .is_ok()
                    {
                        watcher = Some(new_watcher);
                    }

                    let worktree_root = (show_worktree && !worktree_head.is_bare)
                        .then(|| worktree_head.worktree_root.clone());
                    let git_branch = if show_branch {
                        match codex_core::git_info::read_git_head_state(&worktree_head.head_path) {
                            Some(codex_core::git_info::GitHeadState::Branch(branch)) => {
                                Some(branch)
                            }
                            Some(codex_core::git_info::GitHeadState::Detached) => {
                                Some(String::from("(detached)"))
                            }
                            None => None,
                        }
                    } else {
                        None
                    };

                    if git_branch != last_branch || worktree_root != last_worktree_root {
                        last_branch = git_branch.clone();
                        last_worktree_root = worktree_root.clone();
                        tx.send(AppEvent::UpdateStatusBarGitContext {
                            git_branch,
                            worktree_root,
                        });
                    }
                }

                tokio::select! {
                    _ = interval.tick() => {
                        dirty = true;
                    }
                    Some(()) = fs_rx.recv() => {
                        dirty = true;
                    }
                }
            }
        });

        self.status_bar_git_poller = Some(handle);
    }

    pub(crate) fn set_status_bar_git_context(
        &mut self,
        git_branch: Option<String>,
        worktree_root: Option<PathBuf>,
    ) {
        let worktree_display = worktree_root.map(|path| {
            if let Some(rel) = crate::exec_command::relativize_to_home(&path) {
                if rel.as_os_str().is_empty() {
                    String::from("~")
                } else {
                    format!("~/{}", rel.display())
                }
            } else {
                path.display().to_string()
            }
        });
        self.bottom_pane
            .set_status_bar_git_context(git_branch, worktree_display);
    }

    pub(crate) fn set_slash_completion_branches(&mut self, branches: Vec<String>) {
        self.bottom_pane.set_slash_completion_branches(branches);
    }

    pub(crate) fn set_status_bar_git_options(
        &mut self,
        show_git_branch: bool,
        show_worktree: bool,
    ) {
        self.config.tui_status_bar_show_git_branch = show_git_branch;
        self.config.tui_status_bar_show_worktree = show_worktree;
        self.bottom_pane
            .set_status_bar_git_options(show_git_branch, show_worktree);
        self.refresh_status_bar_git_poller();
        self.request_redraw();
    }

    pub(crate) fn set_worktrees_shared_dirs(&mut self, shared_dirs: Vec<String>) {
        self.config.worktrees_shared_dirs = shared_dirs;
        self.request_redraw();
    }

    pub(crate) fn set_worktrees_pinned_paths(&mut self, pinned_paths: Vec<String>) {
        self.config.worktrees_pinned_paths = pinned_paths;
        self.request_redraw();
    }

    pub(crate) fn open_worktrees_settings_view(&mut self) {
        let view = crate::bottom_pane::WorktreesSettingsView::new(
            self.config.worktrees_shared_dirs.clone(),
            self.config.worktrees_pinned_paths.clone(),
            self.app_event_tx.clone(),
        );
        self.bottom_pane.show_view(Box::new(view));
        self.request_redraw();
    }

    pub(crate) fn spawn_worktree_detection(&mut self, open_picker: bool) {
        if self.worktree_list_refresh_in_progress {
            return;
        }
        if codex_core::git_info::resolve_git_worktree_head(&self.config.cwd).is_none() {
            self.worktree_list = Vec::new();
            self.worktree_list_error = None;
            self.worktree_list_refresh_in_progress = false;
            if open_picker {
                self.open_worktree_picker();
            }
            return;
        }

        self.worktree_list_refresh_in_progress = true;

        let cwd = self.config.cwd.clone();
        let tx = self.app_event_tx.clone();
        tokio::spawn(async move {
            match codex_core::git_info::try_list_git_worktrees(&cwd).await {
                Ok(worktrees) => {
                    tx.send(AppEvent::WorktreeListUpdated {
                        worktrees,
                        open_picker,
                    });
                }
                Err(error) => {
                    tx.send(AppEvent::WorktreeListUpdateFailed { error, open_picker });
                }
            }
        });
    }

    pub(crate) fn set_worktree_list(
        &mut self,
        mut worktrees: Vec<GitWorktreeEntry>,
        open_picker: bool,
    ) {
        worktrees.sort_by(|a, b| a.path.cmp(&b.path));
        self.worktree_list = worktrees;
        self.worktree_list_error = None;
        self.worktree_list_refresh_in_progress = false;

        if open_picker {
            self.open_worktree_picker();
        }
    }

    pub(crate) fn on_worktree_list_update_failed(&mut self, error: String, open_picker: bool) {
        self.worktree_list = Vec::new();
        self.worktree_list_error = Some(error);
        self.worktree_list_refresh_in_progress = false;

        if open_picker {
            self.open_worktree_picker();
        }
    }

    pub(crate) fn set_session_cwd(&mut self, cwd: PathBuf) {
        self.config.cwd = cwd.clone();
        self.refresh_status_bar_git_poller();
        self.spawn_worktree_detection(false);

        let display = crate::exec_command::relativize_to_home(&cwd)
            .map(|path| {
                if path.as_os_str().is_empty() {
                    String::from("~")
                } else {
                    format!("~/{}", path.display())
                }
            })
            .unwrap_or_else(|| cwd.display().to_string());
        self.add_info_message(format!("Session worktree set to {display}."), None);
    }

    fn open_worktree_picker(&mut self) {
        #[derive(Clone, Debug)]
        struct WorktreePickerRow {
            path: PathBuf,
            display: String,
            search_value: String,
            description: String,
            selected_description: String,
            is_current: bool,
            is_workspace_root: bool,
            is_bare: bool,
        }

        fn display_path(path: &Path) -> String {
            crate::exec_command::relativize_to_home(path)
                .map(|path| {
                    if path.as_os_str().is_empty() {
                        String::from("~")
                    } else {
                        format!("~/{}", path.display())
                    }
                })
                .unwrap_or_else(|| path.display().to_string())
        }

        fn build_worktree_picker_rows(
            worktrees: &[GitWorktreeEntry],
            current_root: Option<&Path>,
            workspace_root: Option<&Path>,
        ) -> Vec<WorktreePickerRow> {
            let mut rows: Vec<WorktreePickerRow> = worktrees
                .iter()
                .map(|entry| {
                    let is_current = current_root.is_some_and(|root| root == entry.path.as_path());
                    let is_workspace_root =
                        workspace_root.is_some_and(|root| root == entry.path.as_path());

                    let branch_label = match &entry.head {
                        GitHeadState::Branch(name) => name.clone(),
                        GitHeadState::Detached => String::from("(detached)"),
                    };

                    let display = display_path(&entry.path);
                    let mut search_value = String::new();
                    search_value.push_str(&branch_label);
                    search_value.push(' ');
                    search_value.push_str(&display);

                    let mut description = format!("branch: {branch_label}");
                    if entry.is_bare {
                        description.push_str(" (bare repository)");
                    } else if is_workspace_root {
                        description.push_str(" (workspace root)");
                    }

                    let mut selected_description = description.clone();
                    if is_current {
                        selected_description.push_str(" (current session)");
                    }

                    WorktreePickerRow {
                        path: entry.path.clone(),
                        display,
                        search_value,
                        description,
                        selected_description,
                        is_current,
                        is_workspace_root,
                        is_bare: entry.is_bare,
                    }
                })
                .collect();

            rows.sort_by(|a, b| {
                b.is_current
                    .cmp(&a.is_current)
                    .then_with(|| b.is_workspace_root.cmp(&a.is_workspace_root))
                    .then_with(|| a.is_bare.cmp(&b.is_bare))
                    .then_with(|| a.path.cmp(&b.path))
            });

            rows
        }

        let mut items: Vec<SelectionItem> = Vec::new();

        items.push(SelectionItem {
            name: "Refresh worktrees".to_string(),
            display_shortcut: Some(crate::key_hint::alt(KeyCode::Char('r'))),
            description: Some("Re-detect worktrees for this session.".to_string()),
            actions: vec![Box::new(|tx: &AppEventSender| {
                tx.send(AppEvent::WorktreeDetect { open_picker: true });
            })],
            dismiss_on_select: true,
            ..Default::default()
        });

        items.push(SelectionItem {
            name: "Worktrees settings…".to_string(),
            display_shortcut: Some(crate::key_hint::alt(KeyCode::Char('s'))),
            description: Some("Edit shared dirs and pinned paths.".to_string()),
            actions: vec![Box::new(|tx: &AppEventSender| {
                tx.send(AppEvent::OpenWorktreesSettingsView);
            })],
            dismiss_on_select: true,
            ..Default::default()
        });

        {
            let cwd = self.config.cwd.clone();
            let shared_dirs = self.config.worktrees_shared_dirs.clone();
            items.push(SelectionItem {
                name: "Worktree doctor".to_string(),
                display_shortcut: Some(crate::key_hint::alt(KeyCode::Char('d'))),
                description: Some(
                    "Show shared-dir + untracked status for this worktree.".to_string(),
                ),
                actions: vec![Box::new(move |tx: &AppEventSender| {
                    let cwd = cwd.clone();
                    let shared_dirs = shared_dirs.clone();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let lines =
                            codex_core::git_info::worktree_doctor_lines(&cwd, &shared_dirs, 5)
                                .await;
                        let lines = lines.into_iter().map(Line::from).collect();
                        tx.send(AppEvent::InsertHistoryCell(Box::new(
                            PlainHistoryCell::new(lines),
                        )));
                    });
                })],
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        let current_root = codex_core::git_info::resolve_git_worktree_head(&self.config.cwd)
            .map(|head| head.worktree_root);
        let workspace_root = current_root
            .as_ref()
            .and_then(|root| codex_core::git_info::resolve_root_git_project_for_trust(root));

        let rows = build_worktree_picker_rows(
            &self.worktree_list,
            current_root.as_deref(),
            workspace_root.as_deref(),
        );
        for row in rows {
            let dismiss_on_select = !row.is_bare;
            let actions: Vec<SelectionAction> = if row.is_bare {
                Vec::new()
            } else {
                vec![Box::new({
                    let path = row.path.clone();
                    move |tx: &AppEventSender| {
                        tx.send(AppEvent::WorktreeSwitched(path.clone()));
                        tx.send(AppEvent::CodexOp(Op::OverrideTurnContext {
                            cwd: Some(path.clone()),
                            approval_policy: None,
                            sandbox_policy: None,
                            model: None,
                            effort: None,
                            summary: None,
                        }));
                        tx.send(AppEvent::CodexOp(Op::ListSkills {
                            cwds: vec![path.clone()],
                            force_reload: true,
                        }));
                    }
                })]
            };

            items.push(SelectionItem {
                name: row.display,
                description: Some(row.description),
                selected_description: Some(row.selected_description),
                is_current: row.is_current,
                actions,
                dismiss_on_select,
                search_value: Some(row.search_value),
                ..Default::default()
            });
        }

        let subtitle = if let Some(err) = self.worktree_list_error.as_ref() {
            Some(format!("Failed to detect worktrees: {err}"))
        } else if self.worktree_list.is_empty() {
            Some("No worktrees detected for this session.".to_string())
        } else {
            None
        };

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Select a worktree".to_string()),
            subtitle,
            footer_hint: Some(Line::from(vec![
                crate::key_hint::plain(KeyCode::Up).into(),
                "/".into(),
                crate::key_hint::plain(KeyCode::Down).into(),
                " select  ".dim(),
                crate::key_hint::plain(KeyCode::Enter).into(),
                " open  ".dim(),
                crate::key_hint::alt(KeyCode::Char('r')).into(),
                " refresh  ".dim(),
                crate::key_hint::alt(KeyCode::Char('s')).into(),
                " settings  ".dim(),
                crate::key_hint::alt(KeyCode::Char('d')).into(),
                " doctor  ".dim(),
                "type to search  ".dim(),
                crate::key_hint::plain(KeyCode::Esc).into(),
                " close".dim(),
            ])),
            items,
            is_searchable: true,
            search_placeholder: Some("Type to search worktrees".to_string()),
            ..Default::default()
        });
        self.request_redraw();
    }

    fn prefetch_rate_limits(&mut self) {
        self.stop_rate_limit_poller();

        if self.auth_manager.auth_cached().map(|auth| auth.mode) != Some(AuthMode::ChatGPT) {
            return;
        }

        let base_url = self.config.chatgpt_base_url.clone();
        let app_event_tx = self.app_event_tx.clone();
        let auth_manager = Arc::clone(&self.auth_manager);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                if let Some(auth) = auth_manager.auth().await
                    && auth.mode == AuthMode::ChatGPT
                    && let Some(snapshot) = fetch_rate_limits(base_url.clone(), auth).await
                {
                    app_event_tx.send(AppEvent::RateLimitSnapshotFetched(snapshot));
                }
                interval.tick().await;
            }
        });

        self.rate_limit_poller = Some(handle);
    }

    fn lower_cost_preset(&self) -> Option<ModelPreset> {
        let models = self.models_manager.try_list_models(&self.config).ok()?;
        models
            .iter()
            .find(|preset| preset.show_in_picker && preset.model == NUDGE_MODEL_SLUG)
            .cloned()
    }

    fn rate_limit_switch_prompt_hidden(&self) -> bool {
        self.config
            .notices
            .hide_rate_limit_model_nudge
            .unwrap_or(false)
    }

    fn maybe_show_pending_rate_limit_prompt(&mut self) {
        if self.rate_limit_switch_prompt_hidden() {
            self.rate_limit_switch_prompt = RateLimitSwitchPromptState::Idle;
            return;
        }
        if !matches!(
            self.rate_limit_switch_prompt,
            RateLimitSwitchPromptState::Pending
        ) {
            return;
        }
        if let Some(preset) = self.lower_cost_preset() {
            self.open_rate_limit_switch_prompt(preset);
            self.rate_limit_switch_prompt = RateLimitSwitchPromptState::Shown;
        } else {
            self.rate_limit_switch_prompt = RateLimitSwitchPromptState::Idle;
        }
    }

    fn open_rate_limit_switch_prompt(&mut self, preset: ModelPreset) {
        let switch_model = preset.model.to_string();
        let display_name = preset.display_name.to_string();
        let default_effort: ReasoningEffortConfig = preset.default_reasoning_effort;

        let switch_actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
            tx.send(AppEvent::CodexOp(Op::OverrideTurnContext {
                cwd: None,
                approval_policy: None,
                sandbox_policy: None,
                model: Some(switch_model.clone()),
                effort: Some(Some(default_effort)),
                summary: None,
            }));
            tx.send(AppEvent::UpdateModel(switch_model.clone()));
            tx.send(AppEvent::UpdateReasoningEffort(Some(default_effort)));
        })];

        let keep_actions: Vec<SelectionAction> = Vec::new();
        let never_actions: Vec<SelectionAction> = vec![Box::new(|tx| {
            tx.send(AppEvent::UpdateRateLimitSwitchPromptHidden(true));
            tx.send(AppEvent::PersistRateLimitSwitchPromptHidden);
        })];
        let description = if preset.description.is_empty() {
            Some("Uses fewer credits for upcoming turns.".to_string())
        } else {
            Some(preset.description)
        };

        let items = vec![
            SelectionItem {
                name: format!("Switch to {display_name}"),
                description,
                selected_description: None,
                is_current: false,
                actions: switch_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: "Keep current model".to_string(),
                description: None,
                selected_description: None,
                is_current: false,
                actions: keep_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: "Keep current model (never show again)".to_string(),
                description: Some(
                    "Hide future rate limit reminders about switching models.".to_string(),
                ),
                selected_description: None,
                is_current: false,
                actions: never_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
        ];

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Approaching rate limits".to_string()),
            subtitle: Some(format!("Switch to {display_name} for lower credit usage?")),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            ..Default::default()
        });
    }

    /// Open a popup to choose a quick auto model. Selecting "All models"
    /// opens the full picker with every available preset.
    pub(crate) fn open_model_popup(&mut self) {
        let presets: Vec<ModelPreset> = match self.models_manager.try_list_models(&self.config) {
            Ok(models) => models,
            Err(_) => {
                self.add_info_message(
                    "Models are being updated; please try /model again in a moment.".to_string(),
                    None,
                );
                return;
            }
        };
        self.open_model_popup_with_presets(presets);
    }

    pub(crate) fn open_model_popup_with_presets(&mut self, presets: Vec<ModelPreset>) {
        let presets: Vec<ModelPreset> = presets
            .into_iter()
            .filter(|preset| preset.show_in_picker)
            .collect();

        let current_label = presets
            .iter()
            .find(|preset| preset.model == self.model)
            .map(|preset| preset.display_name.to_string())
            .unwrap_or_else(|| self.model.clone());

        let (mut auto_presets, other_presets): (Vec<ModelPreset>, Vec<ModelPreset>) = presets
            .into_iter()
            .partition(|preset| Self::is_auto_model(&preset.model));

        if auto_presets.is_empty() {
            self.open_all_models_popup(other_presets);
            return;
        }

        auto_presets.sort_by_key(|preset| Self::auto_model_order(&preset.model));

        let mut items: Vec<SelectionItem> = auto_presets
            .into_iter()
            .map(|preset| {
                let description =
                    (!preset.description.is_empty()).then_some(preset.description.clone());
                let model = preset.model.clone();
                let actions = Self::model_selection_actions(
                    model.clone(),
                    Some(preset.default_reasoning_effort),
                );
                SelectionItem {
                    name: preset.display_name.clone(),
                    description,
                    is_current: model == self.model,
                    is_default: preset.is_default,
                    actions,
                    dismiss_on_select: true,
                    ..Default::default()
                }
            })
            .collect();

        if !other_presets.is_empty() {
            let all_models = other_presets;
            let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                tx.send(AppEvent::OpenAllModelsPopup {
                    models: all_models.clone(),
                });
            })];

            let is_current = !items.iter().any(|item| item.is_current);
            let description = Some(format!(
                "Choose a specific model and reasoning level (current: {current_label})"
            ));

            items.push(SelectionItem {
                name: "All models".to_string(),
                description,
                is_current,
                actions,
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Select Model".to_string()),
            subtitle: Some("Pick a quick auto mode or browse all models.".to_string()),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            ..Default::default()
        });
    }

    fn is_auto_model(model: &str) -> bool {
        model.starts_with("codex-auto-")
    }

    fn auto_model_order(model: &str) -> usize {
        match model {
            "codex-auto-fast" => 0,
            "codex-auto-balanced" => 1,
            "codex-auto-thorough" => 2,
            _ => 3,
        }
    }

    pub(crate) fn open_all_models_popup(&mut self, presets: Vec<ModelPreset>) {
        if presets.is_empty() {
            self.add_info_message(
                "No additional models are available right now.".to_string(),
                None,
            );
            return;
        }

        let mut items: Vec<SelectionItem> = Vec::new();
        for preset in presets.into_iter() {
            let description =
                (!preset.description.is_empty()).then_some(preset.description.to_string());
            let is_current = preset.model == self.model;
            let single_supported_effort = preset.supported_reasoning_efforts.len() == 1;
            let preset_for_action = preset.clone();
            let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                let preset_for_event = preset_for_action.clone();
                tx.send(AppEvent::OpenReasoningPopup {
                    model: preset_for_event,
                });
            })];
            items.push(SelectionItem {
                name: preset.display_name.clone(),
                description,
                is_current,
                is_default: preset.is_default,
                actions,
                dismiss_on_select: single_supported_effort,
                ..Default::default()
            });
        }

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Select Model and Effort".to_string()),
            subtitle: Some(
                "Access legacy models by running codex -m <model_name> or in your config.toml"
                    .to_string(),
            ),
            footer_hint: Some("Press enter to select reasoning effort, or esc to dismiss.".into()),
            items,
            ..Default::default()
        });
    }

    fn model_selection_actions(
        model_for_action: String,
        effort_for_action: Option<ReasoningEffortConfig>,
    ) -> Vec<SelectionAction> {
        vec![Box::new(move |tx| {
            let effort_label = effort_for_action
                .map(|effort| effort.to_string())
                .unwrap_or_else(|| "default".to_string());
            tx.send(AppEvent::CodexOp(Op::OverrideTurnContext {
                cwd: None,
                approval_policy: None,
                sandbox_policy: None,
                model: Some(model_for_action.clone()),
                effort: Some(effort_for_action),
                summary: None,
            }));
            tx.send(AppEvent::UpdateModel(model_for_action.clone()));
            tx.send(AppEvent::UpdateReasoningEffort(effort_for_action));
            tx.send(AppEvent::PersistModelSelection {
                model: model_for_action.clone(),
                effort: effort_for_action,
            });
            tracing::info!(
                "Selected model: {}, Selected effort: {}",
                model_for_action,
                effort_label
            );
        })]
    }

    /// Open a popup to choose the reasoning effort (stage 2) for the given model.
    pub(crate) fn open_reasoning_popup(&mut self, preset: ModelPreset) {
        let default_effort: ReasoningEffortConfig = preset.default_reasoning_effort;
        let supported = preset.supported_reasoning_efforts;

        let warn_effort = if supported
            .iter()
            .any(|option| option.effort == ReasoningEffortConfig::XHigh)
        {
            Some(ReasoningEffortConfig::XHigh)
        } else if supported
            .iter()
            .any(|option| option.effort == ReasoningEffortConfig::High)
        {
            Some(ReasoningEffortConfig::High)
        } else {
            None
        };
        let warning_text = warn_effort.map(|effort| {
            let effort_label = Self::reasoning_effort_label(effort);
            format!("⚠ {effort_label} reasoning effort can quickly consume Plus plan rate limits.")
        });
        let warn_for_model = preset.model.starts_with("gpt-5.1-codex")
            || preset.model.starts_with("gpt-5.1-codex-max")
            || preset.model.starts_with("gpt-5.2");

        struct EffortChoice {
            stored: Option<ReasoningEffortConfig>,
            display: ReasoningEffortConfig,
        }
        let mut choices: Vec<EffortChoice> = Vec::new();
        for effort in ReasoningEffortConfig::iter() {
            if supported.iter().any(|option| option.effort == effort) {
                choices.push(EffortChoice {
                    stored: Some(effort),
                    display: effort,
                });
            }
        }
        if choices.is_empty() {
            choices.push(EffortChoice {
                stored: Some(default_effort),
                display: default_effort,
            });
        }

        if choices.len() == 1 {
            if let Some(effort) = choices.first().and_then(|c| c.stored) {
                self.apply_model_and_effort(preset.model, Some(effort));
            } else {
                self.apply_model_and_effort(preset.model, None);
            }
            return;
        }

        let default_choice: Option<ReasoningEffortConfig> = choices
            .iter()
            .any(|choice| choice.stored == Some(default_effort))
            .then_some(Some(default_effort))
            .flatten()
            .or_else(|| choices.iter().find_map(|choice| choice.stored))
            .or(Some(default_effort));

        let model_slug = preset.model.to_string();
        let is_current_model = self.model == preset.model;
        let highlight_choice = if is_current_model {
            self.config.model_reasoning_effort
        } else {
            default_choice
        };
        let selection_choice = highlight_choice.or(default_choice);
        let initial_selected_idx = choices
            .iter()
            .position(|choice| choice.stored == selection_choice)
            .or_else(|| {
                selection_choice
                    .and_then(|effort| choices.iter().position(|choice| choice.display == effort))
            });
        let mut items: Vec<SelectionItem> = Vec::new();
        for choice in choices.iter() {
            let effort = choice.display;
            let mut effort_label = Self::reasoning_effort_label(effort).to_string();
            if choice.stored == default_choice {
                effort_label.push_str(" (default)");
            }

            let description = choice
                .stored
                .and_then(|effort| {
                    supported
                        .iter()
                        .find(|option| option.effort == effort)
                        .map(|option| option.description.to_string())
                })
                .filter(|text| !text.is_empty());

            let show_warning = warn_for_model && warn_effort == Some(effort);
            let selected_description = if show_warning {
                warning_text.as_ref().map(|warning_message| {
                    description.as_ref().map_or_else(
                        || warning_message.clone(),
                        |d| format!("{d}\n{warning_message}"),
                    )
                })
            } else {
                None
            };

            let model_for_action = model_slug.clone();
            let actions = Self::model_selection_actions(model_for_action, choice.stored);

            items.push(SelectionItem {
                name: effort_label,
                description,
                selected_description,
                is_current: is_current_model && choice.stored == highlight_choice,
                actions,
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        let mut header = ColumnRenderable::new();
        header.push(Line::from(
            format!("Select Reasoning Level for {model_slug}").bold(),
        ));

        self.bottom_pane.show_selection_view(SelectionViewParams {
            header: Box::new(header),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            initial_selected_idx,
            ..Default::default()
        });
    }

    fn reasoning_effort_label(effort: ReasoningEffortConfig) -> &'static str {
        match effort {
            ReasoningEffortConfig::None => "None",
            ReasoningEffortConfig::Minimal => "Minimal",
            ReasoningEffortConfig::Low => "Low",
            ReasoningEffortConfig::Medium => "Medium",
            ReasoningEffortConfig::High => "High",
            ReasoningEffortConfig::XHigh => "Extra high",
        }
    }

    fn apply_model_and_effort(&self, model: String, effort: Option<ReasoningEffortConfig>) {
        self.app_event_tx
            .send(AppEvent::CodexOp(Op::OverrideTurnContext {
                cwd: None,
                approval_policy: None,
                sandbox_policy: None,
                model: Some(model.clone()),
                effort: Some(effort),
                summary: None,
            }));
        self.app_event_tx.send(AppEvent::UpdateModel(model.clone()));
        self.app_event_tx
            .send(AppEvent::UpdateReasoningEffort(effort));
        self.app_event_tx.send(AppEvent::PersistModelSelection {
            model: model.clone(),
            effort,
        });
        tracing::info!(
            "Selected model: {}, Selected effort: {}",
            model,
            effort
                .map(|e| e.to_string())
                .unwrap_or_else(|| "default".to_string())
        );
    }

    /// Open a popup to choose the approvals mode (ask for approval policy + sandbox policy).
    pub(crate) fn open_approvals_popup(&mut self) {
        let current_approval = self.config.approval_policy.value();
        let current_sandbox = self.config.sandbox_policy.get();
        let mut items: Vec<SelectionItem> = Vec::new();
        let presets: Vec<ApprovalPreset> = builtin_approval_presets();

        #[cfg(target_os = "windows")]
        let windows_degraded_sandbox_enabled = codex_core::get_platform_sandbox().is_some()
            && !codex_core::is_windows_elevated_sandbox_enabled();
        #[cfg(not(target_os = "windows"))]
        let windows_degraded_sandbox_enabled = false;

        let show_elevate_sandbox_hint = codex_core::windows_sandbox::ELEVATED_SANDBOX_NUX_ENABLED
            && windows_degraded_sandbox_enabled
            && presets.iter().any(|preset| preset.id == "auto");

        for preset in presets.into_iter() {
            let is_current =
                Self::preset_matches_current(current_approval, current_sandbox, &preset);
            let name = if preset.id == "auto" && windows_degraded_sandbox_enabled {
                "Agent (non-elevated sandbox)".to_string()
            } else {
                preset.label.to_string()
            };
            let description_text = preset.description;
            let description = Some(description_text.to_string());
            let requires_confirmation = preset.id == "full-access"
                && !self
                    .config
                    .notices
                    .hide_full_access_warning
                    .unwrap_or(false);
            let actions: Vec<SelectionAction> = if requires_confirmation {
                let preset_clone = preset.clone();
                vec![Box::new(move |tx| {
                    tx.send(AppEvent::OpenFullAccessConfirmation {
                        preset: preset_clone.clone(),
                    });
                })]
            } else if preset.id == "auto" {
                #[cfg(target_os = "windows")]
                {
                    if codex_core::get_platform_sandbox().is_none() {
                        let preset_clone = preset.clone();
                        if codex_core::windows_sandbox::ELEVATED_SANDBOX_NUX_ENABLED
                            && codex_core::windows_sandbox::sandbox_setup_is_complete(
                                self.config.codex_home.as_path(),
                            )
                        {
                            vec![Box::new(move |tx| {
                                tx.send(AppEvent::EnableWindowsSandboxForAgentMode {
                                    preset: preset_clone.clone(),
                                    mode: WindowsSandboxEnableMode::Elevated,
                                });
                            })]
                        } else {
                            vec![Box::new(move |tx| {
                                tx.send(AppEvent::OpenWindowsSandboxEnablePrompt {
                                    preset: preset_clone.clone(),
                                });
                            })]
                        }
                    } else if let Some((sample_paths, extra_count, failed_scan)) =
                        self.world_writable_warning_details()
                    {
                        let preset_clone = preset.clone();
                        vec![Box::new(move |tx| {
                            tx.send(AppEvent::OpenWorldWritableWarningConfirmation {
                                preset: Some(preset_clone.clone()),
                                sample_paths: sample_paths.clone(),
                                extra_count,
                                failed_scan,
                            });
                        })]
                    } else {
                        Self::approval_preset_actions(preset.approval, preset.sandbox.clone())
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Self::approval_preset_actions(preset.approval, preset.sandbox.clone())
                }
            } else {
                Self::approval_preset_actions(preset.approval, preset.sandbox.clone())
            };
            items.push(SelectionItem {
                name,
                description,
                is_current,
                actions,
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        let footer_note = show_elevate_sandbox_hint.then(|| {
            vec![
                "The non-elevated sandbox protects your files and prevents network access under most circumstances. However, it carries greater risk if prompt injected. To upgrade to the elevated sandbox, run ".dim(),
                "/setup-elevated-sandbox".cyan(),
                ".".dim(),
            ]
            .into()
        });

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Select Approval Mode".to_string()),
            footer_note,
            footer_hint: Some(standard_popup_hint_line()),
            items,
            header: Box::new(()),
            ..Default::default()
        });
    }

    fn approval_preset_actions(
        approval: AskForApproval,
        sandbox: SandboxPolicy,
    ) -> Vec<SelectionAction> {
        vec![Box::new(move |tx| {
            let sandbox_clone = sandbox.clone();
            tx.send(AppEvent::CodexOp(Op::OverrideTurnContext {
                cwd: None,
                approval_policy: Some(approval),
                sandbox_policy: Some(sandbox_clone.clone()),
                model: None,
                effort: None,
                summary: None,
            }));
            tx.send(AppEvent::UpdateAskForApprovalPolicy(approval));
            tx.send(AppEvent::UpdateSandboxPolicy(sandbox_clone));
        })]
    }

    fn preset_matches_current(
        current_approval: AskForApproval,
        current_sandbox: &SandboxPolicy,
        preset: &ApprovalPreset,
    ) -> bool {
        if current_approval != preset.approval {
            return false;
        }
        matches!(
            (&preset.sandbox, current_sandbox),
            (SandboxPolicy::ReadOnly, SandboxPolicy::ReadOnly)
                | (
                    SandboxPolicy::DangerFullAccess,
                    SandboxPolicy::DangerFullAccess
                )
                | (
                    SandboxPolicy::WorkspaceWrite { .. },
                    SandboxPolicy::WorkspaceWrite { .. }
                )
        )
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn world_writable_warning_details(&self) -> Option<(Vec<String>, usize, bool)> {
        if self
            .config
            .notices
            .hide_world_writable_warning
            .unwrap_or(false)
        {
            return None;
        }
        let cwd = self.config.cwd.clone();
        let env_map: std::collections::HashMap<String, String> = std::env::vars().collect();
        match codex_windows_sandbox::apply_world_writable_scan_and_denies(
            self.config.codex_home.as_path(),
            cwd.as_path(),
            &env_map,
            self.config.sandbox_policy.get(),
            Some(self.config.codex_home.as_path()),
        ) {
            Ok(_) => None,
            Err(_) => Some((Vec::new(), 0, true)),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    pub(crate) fn world_writable_warning_details(&self) -> Option<(Vec<String>, usize, bool)> {
        None
    }

    pub(crate) fn open_full_access_confirmation(&mut self, preset: ApprovalPreset) {
        let approval = preset.approval;
        let sandbox = preset.sandbox;
        let mut header_children: Vec<Box<dyn Renderable>> = Vec::new();
        let title_line = Line::from("Enable full access?").bold();
        let info_line = Line::from(vec![
            "When xcodex runs with full access, it can edit any file on your computer and run commands with network, without your approval. "
                .into(),
            "Exercise caution when enabling full access. This significantly increases the risk of data loss, leaks, or unexpected behavior."
                .fg(Color::Red),
        ]);
        header_children.push(Box::new(title_line));
        header_children.push(Box::new(
            Paragraph::new(vec![info_line]).wrap(Wrap { trim: false }),
        ));
        let header = ColumnRenderable::with(header_children);

        let mut accept_actions = Self::approval_preset_actions(approval, sandbox.clone());
        accept_actions.push(Box::new(|tx| {
            tx.send(AppEvent::UpdateFullAccessWarningAcknowledged(true));
        }));

        let mut accept_and_remember_actions = Self::approval_preset_actions(approval, sandbox);
        accept_and_remember_actions.push(Box::new(|tx| {
            tx.send(AppEvent::UpdateFullAccessWarningAcknowledged(true));
            tx.send(AppEvent::PersistFullAccessWarningAcknowledged);
        }));

        let deny_actions: Vec<SelectionAction> = vec![Box::new(|tx| {
            tx.send(AppEvent::OpenApprovalsPopup);
        })];

        let items = vec![
            SelectionItem {
                name: "Yes, continue anyway".to_string(),
                description: Some("Apply full access for this session".to_string()),
                actions: accept_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: "Yes, and don't ask again".to_string(),
                description: Some("Enable full access and remember this choice".to_string()),
                actions: accept_and_remember_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: "Cancel".to_string(),
                description: Some("Go back without enabling full access".to_string()),
                actions: deny_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
        ];

        self.bottom_pane.show_selection_view(SelectionViewParams {
            footer_hint: Some(standard_popup_hint_line()),
            items,
            header: Box::new(header),
            ..Default::default()
        });
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn open_world_writable_warning_confirmation(
        &mut self,
        preset: Option<ApprovalPreset>,
        sample_paths: Vec<String>,
        extra_count: usize,
        failed_scan: bool,
    ) {
        let (approval, sandbox) = match &preset {
            Some(p) => (Some(p.approval), Some(p.sandbox.clone())),
            None => (None, None),
        };
        let mut header_children: Vec<Box<dyn Renderable>> = Vec::new();
        let describe_policy = |policy: &SandboxPolicy| match policy {
            SandboxPolicy::WorkspaceWrite { .. } => "Agent mode",
            SandboxPolicy::ReadOnly => "Read-Only mode",
            _ => "Agent mode",
        };
        let mode_label = preset
            .as_ref()
            .map(|p| describe_policy(&p.sandbox))
            .unwrap_or_else(|| describe_policy(self.config.sandbox_policy.get()));
        let info_line = if failed_scan {
            Line::from(vec![
                "We couldn't complete the world-writable scan, so protections cannot be verified. "
                    .into(),
                format!("The Windows sandbox cannot guarantee protection in {mode_label}.")
                    .fg(Color::Red),
            ])
        } else {
            Line::from(vec![
                "The Windows sandbox cannot protect writes to folders that are writable by Everyone.".into(),
                " Consider removing write access for Everyone from the following folders:".into(),
            ])
        };
        header_children.push(Box::new(
            Paragraph::new(vec![info_line]).wrap(Wrap { trim: false }),
        ));

        if !sample_paths.is_empty() {
            // Show up to three examples and optionally an "and X more" line.
            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::from(""));
            for p in &sample_paths {
                lines.push(Line::from(format!("  - {p}")));
            }
            if extra_count > 0 {
                lines.push(Line::from(format!("and {extra_count} more")));
            }
            header_children.push(Box::new(Paragraph::new(lines).wrap(Wrap { trim: false })));
        }
        let header = ColumnRenderable::with(header_children);

        // Build actions ensuring acknowledgement happens before applying the new sandbox policy,
        // so downstream policy-change hooks don't re-trigger the warning.
        let mut accept_actions: Vec<SelectionAction> = Vec::new();
        // Suppress the immediate re-scan only when a preset will be applied (i.e., via /approvals),
        // to avoid duplicate warnings from the ensuing policy change.
        if preset.is_some() {
            accept_actions.push(Box::new(|tx| {
                tx.send(AppEvent::SkipNextWorldWritableScan);
            }));
        }
        if let (Some(approval), Some(sandbox)) = (approval, sandbox.clone()) {
            accept_actions.extend(Self::approval_preset_actions(approval, sandbox));
        }

        let mut accept_and_remember_actions: Vec<SelectionAction> = Vec::new();
        accept_and_remember_actions.push(Box::new(|tx| {
            tx.send(AppEvent::UpdateWorldWritableWarningAcknowledged(true));
            tx.send(AppEvent::PersistWorldWritableWarningAcknowledged);
        }));
        if let (Some(approval), Some(sandbox)) = (approval, sandbox) {
            accept_and_remember_actions.extend(Self::approval_preset_actions(approval, sandbox));
        }

        let items = vec![
            SelectionItem {
                name: "Continue".to_string(),
                description: Some(format!("Apply {mode_label} for this session")),
                actions: accept_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: "Continue and don't warn again".to_string(),
                description: Some(format!("Enable {mode_label} and remember this choice")),
                actions: accept_and_remember_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
        ];

        self.bottom_pane.show_selection_view(SelectionViewParams {
            footer_hint: Some(standard_popup_hint_line()),
            items,
            header: Box::new(header),
            ..Default::default()
        });
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn open_world_writable_warning_confirmation(
        &mut self,
        _preset: Option<ApprovalPreset>,
        _sample_paths: Vec<String>,
        _extra_count: usize,
        _failed_scan: bool,
    ) {
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn open_windows_sandbox_enable_prompt(&mut self, preset: ApprovalPreset) {
        use ratatui_macros::line;

        if !codex_core::windows_sandbox::ELEVATED_SANDBOX_NUX_ENABLED {
            // Legacy flow (pre-NUX): explain the experimental sandbox and let the user enable it
            // directly (no elevation prompts).
            let mut header = ColumnRenderable::new();
            header.push(*Box::new(
                Paragraph::new(vec![
                    line!["Agent mode on Windows uses an experimental sandbox to limit network and filesystem access.".bold()],
                    line!["Learn more: https://developers.openai.com/codex/windows"],
                ])
                .wrap(Wrap { trim: false }),
            ));

            let preset_clone = preset;
            let items = vec![
                SelectionItem {
                    name: "Enable experimental sandbox".to_string(),
                    description: None,
                    actions: vec![Box::new(move |tx| {
                        tx.send(AppEvent::EnableWindowsSandboxForAgentMode {
                            preset: preset_clone.clone(),
                            mode: WindowsSandboxEnableMode::Legacy,
                        });
                    })],
                    dismiss_on_select: true,
                    ..Default::default()
                },
                SelectionItem {
                    name: "Go back".to_string(),
                    description: None,
                    actions: vec![Box::new(|tx| {
                        tx.send(AppEvent::OpenApprovalsPopup);
                    })],
                    dismiss_on_select: true,
                    ..Default::default()
                },
            ];

            self.bottom_pane.show_selection_view(SelectionViewParams {
                title: None,
                footer_hint: Some(standard_popup_hint_line()),
                items,
                header: Box::new(header),
                ..Default::default()
            });
            return;
        }

        let current_approval = self.config.approval_policy.value();
        let current_sandbox = self.config.sandbox_policy.get();
        let presets = builtin_approval_presets();
        let stay_full_access = presets
            .iter()
            .find(|preset| preset.id == "full-access")
            .is_some_and(|preset| {
                Self::preset_matches_current(current_approval, current_sandbox, preset)
            });
        let stay_actions = if stay_full_access {
            Vec::new()
        } else {
            presets
                .iter()
                .find(|preset| preset.id == "read-only")
                .map(|preset| {
                    Self::approval_preset_actions(preset.approval, preset.sandbox.clone())
                })
                .unwrap_or_default()
        };
        let stay_label = if stay_full_access {
            "Stay in Agent Full Access".to_string()
        } else {
            "Stay in Read-Only".to_string()
        };

        let mut header = ColumnRenderable::new();
        header.push(*Box::new(
            Paragraph::new(vec![
                line!["Set Up Agent Sandbox".bold()],
                line![""],
                line!["Agent mode uses an experimental Windows sandbox that protects your files and prevents network access by default."],
                line!["Learn more: https://developers.openai.com/codex/windows"],
            ])
            .wrap(Wrap { trim: false }),
        ));

        let items = vec![
            SelectionItem {
                name: "Set up agent sandbox (requires elevation)".to_string(),
                description: None,
                actions: vec![Box::new(move |tx| {
                    tx.send(AppEvent::BeginWindowsSandboxElevatedSetup {
                        preset: preset.clone(),
                    });
                })],
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: stay_label,
                description: None,
                actions: stay_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
        ];

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: None,
            footer_hint: Some(standard_popup_hint_line()),
            items,
            header: Box::new(header),
            ..Default::default()
        });
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn open_windows_sandbox_enable_prompt(&mut self, _preset: ApprovalPreset) {}

    #[cfg(target_os = "windows")]
    pub(crate) fn open_windows_sandbox_fallback_prompt(
        &mut self,
        preset: ApprovalPreset,
        reason: WindowsSandboxFallbackReason,
    ) {
        use ratatui_macros::line;

        let _ = reason;

        let current_approval = self.config.approval_policy.value();
        let current_sandbox = self.config.sandbox_policy.get();
        let presets = builtin_approval_presets();
        let stay_full_access = presets
            .iter()
            .find(|preset| preset.id == "full-access")
            .is_some_and(|preset| {
                Self::preset_matches_current(current_approval, current_sandbox, preset)
            });
        let stay_actions = if stay_full_access {
            Vec::new()
        } else {
            presets
                .iter()
                .find(|preset| preset.id == "read-only")
                .map(|preset| {
                    Self::approval_preset_actions(preset.approval, preset.sandbox.clone())
                })
                .unwrap_or_default()
        };
        let stay_label = if stay_full_access {
            "Stay in Agent Full Access".to_string()
        } else {
            "Stay in Read-Only".to_string()
        };

        let mut lines = Vec::new();
        lines.push(line!["Use Non-Elevated Sandbox?".bold()]);
        lines.push(line![""]);
        lines.push(line![
            "Elevation failed. You can also use a non-elevated sandbox, which protects your files and prevents network access under most circumstances. However, it carries greater risk if prompt injected."
        ]);
        lines.push(line![
            "Learn more: https://developers.openai.com/codex/windows"
        ]);

        let mut header = ColumnRenderable::new();
        header.push(*Box::new(Paragraph::new(lines).wrap(Wrap { trim: false })));

        let elevated_preset = preset.clone();
        let legacy_preset = preset;
        let items = vec![
            SelectionItem {
                name: "Try elevated agent sandbox setup again".to_string(),
                description: None,
                actions: vec![Box::new(move |tx| {
                    tx.send(AppEvent::BeginWindowsSandboxElevatedSetup {
                        preset: elevated_preset.clone(),
                    });
                })],
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: "Use non-elevated agent sandbox".to_string(),
                description: None,
                actions: vec![Box::new(move |tx| {
                    tx.send(AppEvent::EnableWindowsSandboxForAgentMode {
                        preset: legacy_preset.clone(),
                        mode: WindowsSandboxEnableMode::Legacy,
                    });
                })],
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: stay_label,
                description: None,
                actions: stay_actions,
                dismiss_on_select: true,
                ..Default::default()
            },
        ];

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: None,
            footer_hint: Some(standard_popup_hint_line()),
            items,
            header: Box::new(header),
            ..Default::default()
        });
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn open_windows_sandbox_fallback_prompt(
        &mut self,
        _preset: ApprovalPreset,
        _reason: WindowsSandboxFallbackReason,
    ) {
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn maybe_prompt_windows_sandbox_enable(&mut self) {
        if self.config.forced_auto_mode_downgraded_on_windows
            && codex_core::get_platform_sandbox().is_none()
            && let Some(preset) = builtin_approval_presets()
                .into_iter()
                .find(|preset| preset.id == "auto")
        {
            self.open_windows_sandbox_enable_prompt(preset);
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn maybe_prompt_windows_sandbox_enable(&mut self) {}

    #[cfg(target_os = "windows")]
    pub(crate) fn show_windows_sandbox_setup_status(&mut self) {
        // While elevated sandbox setup runs, prevent typing so the user doesn't
        // accidentally queue messages that will run under an unexpected mode.
        self.bottom_pane.set_composer_input_enabled(
            false,
            Some("Input disabled until setup completes.".to_string()),
        );
        self.bottom_pane.ensure_status_indicator();
        self.bottom_pane.set_interrupt_hint_visible(false);
        self.set_status_header("Setting up agent sandbox. This can take a minute.".to_string());
        self.request_redraw();
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    pub(crate) fn show_windows_sandbox_setup_status(&mut self) {}

    #[cfg(target_os = "windows")]
    pub(crate) fn clear_windows_sandbox_setup_status(&mut self) {
        self.bottom_pane.set_composer_input_enabled(true, None);
        self.bottom_pane.hide_status_indicator();
        self.request_redraw();
    }

    #[cfg(not(target_os = "windows"))]
    pub(crate) fn clear_windows_sandbox_setup_status(&mut self) {}

    #[cfg(target_os = "windows")]
    pub(crate) fn clear_forced_auto_mode_downgrade(&mut self) {
        self.config.forced_auto_mode_downgraded_on_windows = false;
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    pub(crate) fn clear_forced_auto_mode_downgrade(&mut self) {}

    /// Set the approval policy in the widget's config copy.
    pub(crate) fn set_approval_policy(&mut self, policy: AskForApproval) {
        if let Err(err) = self.config.approval_policy.set(policy) {
            tracing::warn!(%err, "failed to set approval_policy on chat config");
        }
    }

    /// Set the sandbox policy in the widget's config copy.
    pub(crate) fn set_sandbox_policy(&mut self, policy: SandboxPolicy) -> ConstraintResult<()> {
        #[cfg(target_os = "windows")]
        let should_clear_downgrade = !matches!(&policy, SandboxPolicy::ReadOnly)
            || codex_core::get_platform_sandbox().is_some();

        self.config.sandbox_policy.set(policy)?;

        #[cfg(target_os = "windows")]
        if should_clear_downgrade {
            self.config.forced_auto_mode_downgraded_on_windows = false;
        }

        Ok(())
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) fn set_feature_enabled(&mut self, feature: Feature, enabled: bool) {
        if enabled {
            self.config.features.enable(feature);
        } else {
            self.config.features.disable(feature);
        }
    }

    pub(crate) fn set_full_access_warning_acknowledged(&mut self, acknowledged: bool) {
        self.config.notices.hide_full_access_warning = Some(acknowledged);
    }

    pub(crate) fn set_world_writable_warning_acknowledged(&mut self, acknowledged: bool) {
        self.config.notices.hide_world_writable_warning = Some(acknowledged);
    }

    pub(crate) fn set_rate_limit_switch_prompt_hidden(&mut self, hidden: bool) {
        self.config.notices.hide_rate_limit_model_nudge = Some(hidden);
        if hidden {
            self.rate_limit_switch_prompt = RateLimitSwitchPromptState::Idle;
        }
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) fn world_writable_warning_hidden(&self) -> bool {
        self.config
            .notices
            .hide_world_writable_warning
            .unwrap_or(false)
    }

    /// Set the reasoning effort in the widget's config copy.
    pub(crate) fn set_reasoning_effort(&mut self, effort: Option<ReasoningEffortConfig>) {
        self.config.model_reasoning_effort = effort;
    }

    pub(crate) fn set_verbose_tool_output(&mut self, verbose: bool) {
        self.config.tui_verbose_tool_output = verbose;
    }

    pub(crate) fn set_xtreme_mode(&mut self, mode: codex_core::config::types::XtremeMode) {
        self.config.tui_xtreme_mode = mode;
        self.bottom_pane
            .set_xtreme_ui_enabled(crate::xtreme::xtreme_ui_enabled(&self.config));
        self.request_redraw();
    }

    pub(crate) fn set_ramps_config(&mut self, rotate: bool, build: bool, devops: bool) {
        self.config.tui_ramps_rotate = rotate;
        self.config.tui_ramps_build = build;
        self.config.tui_ramps_devops = devops;
        self.request_redraw();
    }

    pub(crate) fn open_ramps_settings_view(&mut self) {
        if !self.ramps_status_enabled() {
            self.add_info_message("Ramps are only available in xcodex.".to_string(), None);
            return;
        }

        let rotate = self.config.tui_ramps_rotate;
        let build = self.config.tui_ramps_build;
        let devops = self.config.tui_ramps_devops;

        let mut items: Vec<SelectionItem> = Vec::new();

        {
            let next_rotate = !rotate;
            let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                tx.send(AppEvent::UpdateRampsConfig {
                    rotate: next_rotate,
                    build,
                    devops,
                });
                tx.send(AppEvent::PersistRampsConfig {
                    rotate: next_rotate,
                    build,
                    devops,
                });
                tx.send(AppEvent::OpenRampsSettingsView);
            })];

            items.push(SelectionItem {
                name: format!(
                    "[{}] Rotate ramps (random per turn)",
                    if rotate { "x" } else { " " }
                ),
                selected_description: Some(
                    "When enabled, xcodex picks one eligible ramp per turn. The chosen ramp stays stable for the entire turn.".to_string(),
                ),
                actions,
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        items.push(SelectionItem {
            name: "Hardware ramp (baseline)".to_string(),
            selected_description: Some(
                crate::ramps::preview_flow(crate::ramps::RampId::Hardware).to_string(),
            ),
            is_default: true,
            ..Default::default()
        });

        {
            let next_build = !build;
            let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                tx.send(AppEvent::UpdateRampsConfig {
                    rotate,
                    build: next_build,
                    devops,
                });
                tx.send(AppEvent::PersistRampsConfig {
                    rotate,
                    build: next_build,
                    devops,
                });
                tx.send(AppEvent::OpenRampsSettingsView);
            })];

            items.push(SelectionItem {
                name: format!("[{}] Build ramp", if build { "x" } else { " " }),
                selected_description: Some(
                    crate::ramps::preview_flow(crate::ramps::RampId::Build).to_string(),
                ),
                actions,
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        {
            let next_devops = !devops;
            let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                tx.send(AppEvent::UpdateRampsConfig {
                    rotate,
                    build,
                    devops: next_devops,
                });
                tx.send(AppEvent::PersistRampsConfig {
                    rotate,
                    build,
                    devops: next_devops,
                });
                tx.send(AppEvent::OpenRampsSettingsView);
            })];

            items.push(SelectionItem {
                name: format!("[{}] DevOps ramp", if devops { "x" } else { " " }),
                selected_description: Some(
                    crate::ramps::preview_flow(crate::ramps::RampId::DevOps).to_string(),
                ),
                actions,
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        let mut header = ColumnRenderable::new();
        header.push(Line::from("Ramps".bold()));
        header.push(Line::from(
            "Pick which ramp flows xcodex can rotate through.".dim(),
        ));

        self.bottom_pane.show_selection_view(SelectionViewParams {
            header: Box::new(header),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            initial_selected_idx: Some(0),
            ..Default::default()
        });
    }

    /// Set the model in the widget's config copy.
    pub(crate) fn set_model(&mut self, model: &str) {
        self.session_header.set_model(model);
        self.model = model.to_string();
    }

    pub(crate) fn set_hide_agent_reasoning(&mut self, hide: bool) {
        self.config.hide_agent_reasoning = hide;
        if hide {
            self.reasoning_buffer.clear();
            self.full_reasoning_buffer.clear();
        }
    }

    pub(crate) fn add_info_message(&mut self, message: String, hint: Option<String>) {
        self.add_to_history(history_cell::new_info_event(message, hint));
        self.request_redraw();
    }

    pub(crate) fn add_plain_history_lines(&mut self, lines: Vec<Line<'static>>) {
        self.add_boxed_history(Box::new(PlainHistoryCell::new(lines)));
        self.request_redraw();
    }

    pub(crate) fn add_error_message(&mut self, message: String) {
        self.add_to_history(history_cell::new_error_event(message));
        self.request_redraw();
    }

    pub(crate) fn add_mcp_output(&mut self) {
        if self.config.mcp_servers.is_empty() {
            self.add_to_history(history_cell::empty_mcp_output());
        } else {
            self.submit_op(Op::ListMcpTools);
        }
    }

    /// Forward file-search results to the bottom pane.
    pub(crate) fn apply_file_search_result(&mut self, query: String, matches: Vec<FileMatch>) {
        self.bottom_pane.on_file_search_result(query, matches);
    }

    /// Handle Ctrl-C key press.
    fn on_ctrl_c(&mut self) {
        if self.bottom_pane.on_ctrl_c() == CancellationEvent::Handled {
            return;
        }

        if self.bottom_pane.is_task_running() {
            self.bottom_pane.show_ctrl_c_quit_hint();
            self.submit_op(Op::Interrupt);
            return;
        }

        if self.config.tui_confirm_exit_with_running_hooks
            && !self.hook_processes.is_empty()
            && !self.bottom_pane.ctrl_c_quit_hint_visible()
        {
            self.bottom_pane.show_ctrl_c_quit_hint();
            return;
        }

        self.submit_op(Op::Shutdown);
    }

    pub(crate) fn composer_is_empty(&self) -> bool {
        self.bottom_pane.composer_is_empty()
    }

    pub(crate) fn composer_text(&self) -> String {
        self.bottom_pane.composer_text()
    }

    /// True when the UI is in the regular composer state with no running task,
    /// no modal overlay (e.g. approvals or status indicator), and no composer popups.
    /// In this state Esc-Esc backtracking is enabled.
    pub(crate) fn is_normal_backtrack_mode(&self) -> bool {
        self.bottom_pane.is_normal_backtrack_mode()
    }

    pub(crate) fn insert_str(&mut self, text: &str) {
        self.bottom_pane.insert_str(text);
    }

    /// Replace the composer content with the provided text and reset cursor.
    pub(crate) fn set_composer_text(&mut self, text: String) {
        self.bottom_pane.set_composer_text(text);
    }

    pub(crate) fn show_esc_backtrack_hint(&mut self) {
        self.bottom_pane.show_esc_backtrack_hint();
    }

    pub(crate) fn clear_esc_backtrack_hint(&mut self) {
        self.bottom_pane.clear_esc_backtrack_hint();
    }

    /// Return true when the bottom pane currently has an active task.
    ///
    /// This is used by the viewport to decide when mouse selections should
    /// disengage auto-follow behavior while responses are streaming.
    pub(crate) fn is_task_running(&self) -> bool {
        self.bottom_pane.is_task_running()
    }

    /// Inform the bottom pane about the current transcript scroll state.
    ///
    /// This is used by the footer to surface when the inline transcript is
    /// scrolled away from the bottom and to display the current
    /// `(visible_top, total)` scroll position alongside other shortcuts.
    pub(crate) fn set_transcript_ui_state(
        &mut self,
        scrolled: bool,
        selection_active: bool,
        scroll_position: Option<(usize, usize)>,
        copy_selection_key: crate::key_hint::KeyBinding,
        copy_feedback: Option<crate::transcript_copy_action::TranscriptCopyFeedback>,
    ) {
        self.bottom_pane.set_transcript_ui_state(
            scrolled,
            selection_active,
            scroll_position,
            copy_selection_key,
            copy_feedback,
        );
    }

    /// Forward an `Op` directly to codex.
    pub(crate) fn submit_op(&self, op: Op) {
        // Record outbound operation for session replay fidelity.
        crate::session_log::log_outbound_op(&op);
        if let Err(e) = self.codex_op_tx.send(op) {
            tracing::error!("failed to submit op: {e}");
        }
    }

    fn on_list_mcp_tools(&mut self, ev: McpListToolsResponseEvent) {
        let startup_durations =
            (!self.mcp_startup_durations.is_empty()).then_some(&self.mcp_startup_durations);
        self.add_to_history(history_cell::new_mcp_tools_output(
            &self.config,
            ev.tools,
            ev.resources,
            ev.resource_templates,
            &ev.auth_statuses,
            history_cell::McpStartupRenderInfo {
                statuses: self.mcp_startup_status.as_ref(),
                durations: startup_durations,
                ready_duration: self.mcp_startup_duration,
            },
        ));
    }

    fn on_list_custom_prompts(&mut self, ev: ListCustomPromptsResponseEvent) {
        let len = ev.custom_prompts.len();
        debug!("received {len} custom prompts");
        // Forward to bottom pane so the slash popup can show them now.
        self.bottom_pane.set_custom_prompts(ev.custom_prompts);
    }

    fn on_list_skills(&mut self, ev: ListSkillsResponseEvent) {
        self.set_skills_from_response(&ev);
    }

    pub(crate) fn open_review_popup(&mut self) {
        let mut items: Vec<SelectionItem> = Vec::new();

        items.push(SelectionItem {
            name: "Review against a base branch".to_string(),
            description: Some("(PR Style)".into()),
            actions: vec![Box::new({
                let cwd = self.config.cwd.clone();
                move |tx| {
                    tx.send(AppEvent::OpenReviewBranchPicker(cwd.clone()));
                }
            })],
            dismiss_on_select: false,
            ..Default::default()
        });

        items.push(SelectionItem {
            name: "Review uncommitted changes".to_string(),
            actions: vec![Box::new(move |tx: &AppEventSender| {
                tx.send(AppEvent::CodexOp(Op::Review {
                    review_request: ReviewRequest {
                        target: ReviewTarget::UncommittedChanges,
                        user_facing_hint: None,
                    },
                }));
            })],
            dismiss_on_select: true,
            ..Default::default()
        });

        // New: Review a specific commit (opens commit picker)
        items.push(SelectionItem {
            name: "Review a commit".to_string(),
            actions: vec![Box::new({
                let cwd = self.config.cwd.clone();
                move |tx| {
                    tx.send(AppEvent::OpenReviewCommitPicker(cwd.clone()));
                }
            })],
            dismiss_on_select: false,
            ..Default::default()
        });

        items.push(SelectionItem {
            name: "Custom review instructions".to_string(),
            actions: vec![Box::new(move |tx| {
                tx.send(AppEvent::OpenReviewCustomPrompt);
            })],
            dismiss_on_select: false,
            ..Default::default()
        });

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Select a review preset".into()),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            ..Default::default()
        });
    }

    pub(crate) async fn show_review_branch_picker(&mut self, cwd: &Path) {
        let branches = local_git_branches(cwd).await;
        let current_branch = current_branch_name(cwd)
            .await
            .unwrap_or_else(|| "(detached HEAD)".to_string());
        let mut items: Vec<SelectionItem> = Vec::with_capacity(branches.len());

        for option in branches {
            let branch = option.clone();
            items.push(SelectionItem {
                name: format!("{current_branch} -> {branch}"),
                actions: vec![Box::new(move |tx3: &AppEventSender| {
                    tx3.send(AppEvent::CodexOp(Op::Review {
                        review_request: ReviewRequest {
                            target: ReviewTarget::BaseBranch {
                                branch: branch.clone(),
                            },
                            user_facing_hint: None,
                        },
                    }));
                })],
                dismiss_on_select: true,
                search_value: Some(option),
                ..Default::default()
            });
        }

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Select a base branch".to_string()),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            is_searchable: true,
            search_placeholder: Some("Type to search branches".to_string()),
            ..Default::default()
        });
    }

    pub(crate) async fn show_review_commit_picker(&mut self, cwd: &Path) {
        let commits = codex_core::git_info::recent_commits(cwd, 100).await;

        let mut items: Vec<SelectionItem> = Vec::with_capacity(commits.len());
        for entry in commits {
            let subject = entry.subject.clone();
            let sha = entry.sha.clone();
            let search_val = format!("{subject} {sha}");

            items.push(SelectionItem {
                name: subject.clone(),
                actions: vec![Box::new(move |tx3: &AppEventSender| {
                    tx3.send(AppEvent::CodexOp(Op::Review {
                        review_request: ReviewRequest {
                            target: ReviewTarget::Commit {
                                sha: sha.clone(),
                                title: Some(subject.clone()),
                            },
                            user_facing_hint: None,
                        },
                    }));
                })],
                dismiss_on_select: true,
                search_value: Some(search_val),
                ..Default::default()
            });
        }

        self.bottom_pane.show_selection_view(SelectionViewParams {
            title: Some("Select a commit to review".to_string()),
            footer_hint: Some(standard_popup_hint_line()),
            items,
            is_searchable: true,
            search_placeholder: Some("Type to search commits".to_string()),
            ..Default::default()
        });
    }

    pub(crate) fn show_review_custom_prompt(&mut self) {
        let tx = self.app_event_tx.clone();
        let view = CustomPromptView::new(
            "Custom review instructions".to_string(),
            "Type instructions and press Enter".to_string(),
            None,
            Box::new(move |prompt: String| {
                let trimmed = prompt.trim().to_string();
                if trimmed.is_empty() {
                    return;
                }
                tx.send(AppEvent::CodexOp(Op::Review {
                    review_request: ReviewRequest {
                        target: ReviewTarget::Custom {
                            instructions: trimmed,
                        },
                        user_facing_hint: None,
                    },
                }));
            }),
        );
        self.bottom_pane.show_view(Box::new(view));
    }

    pub(crate) fn token_usage(&self) -> TokenUsage {
        self.token_info
            .as_ref()
            .map(|ti| ti.total_token_usage.clone())
            .unwrap_or_default()
    }

    pub(crate) fn conversation_id(&self) -> Option<ThreadId> {
        self.conversation_id
    }

    pub(crate) fn rollout_path(&self) -> Option<PathBuf> {
        self.current_rollout_path.clone()
    }

    /// Return a reference to the widget's current config (includes any
    /// runtime overrides applied via TUI, e.g., model or approval policy).
    pub(crate) fn config_ref(&self) -> &Config {
        &self.config
    }

    pub(crate) fn clear_token_usage(&mut self) {
        self.token_info = None;
    }

    fn as_renderable(&self) -> RenderableItem<'_> {
        let active_cell_renderable = match &self.active_cell {
            Some(cell) => RenderableItem::Borrowed(cell).inset(Insets::tlbr(1, 0, 0, 0)),
            None => RenderableItem::Owned(Box::new(())),
        };
        let mut flex = FlexRenderable::new();
        flex.push(1, active_cell_renderable);
        flex.push(
            0,
            RenderableItem::Borrowed(&self.bottom_pane).inset(Insets::tlbr(1, 0, 0, 0)),
        );
        RenderableItem::Owned(Box::new(flex))
    }
}

impl Drop for ChatWidget {
    fn drop(&mut self) {
        self.stop_rate_limit_poller();
    }
}

impl Renderable for ChatWidget {
    fn render(&self, area: Rect, buf: &mut Buffer) {
        self.as_renderable().render(area, buf);
        self.last_rendered_width.set(Some(area.width as usize));
    }

    fn desired_height(&self, width: u16) -> u16 {
        self.as_renderable().desired_height(width)
    }

    fn cursor_pos(&self, area: Rect) -> Option<(u16, u16)> {
        self.as_renderable().cursor_pos(area)
    }
}

enum Notification {
    AgentTurnComplete { response: String },
    ExecApprovalRequested { command: String },
    EditApprovalRequested { cwd: PathBuf, changes: Vec<PathBuf> },
    ElicitationRequested { server_name: String },
}

impl Notification {
    fn display(&self) -> String {
        match self {
            Notification::AgentTurnComplete { response } => {
                Notification::agent_turn_preview(response)
                    .unwrap_or_else(|| "Agent turn complete".to_string())
            }
            Notification::ExecApprovalRequested { command } => {
                format!("Approval requested: {}", truncate_text(command, 30))
            }
            Notification::EditApprovalRequested { cwd, changes } => {
                format!(
                    "xcodex wants to edit {}",
                    if changes.len() == 1 {
                        #[allow(clippy::unwrap_used)]
                        display_path_for(changes.first().unwrap(), cwd)
                    } else {
                        format!("{} files", changes.len())
                    }
                )
            }
            Notification::ElicitationRequested { server_name } => {
                format!("Approval requested by {server_name}")
            }
        }
    }

    fn type_name(&self) -> &str {
        match self {
            Notification::AgentTurnComplete { .. } => "agent-turn-complete",
            Notification::ExecApprovalRequested { .. }
            | Notification::EditApprovalRequested { .. }
            | Notification::ElicitationRequested { .. } => "approval-requested",
        }
    }

    fn allowed_for(&self, settings: &Notifications) -> bool {
        match settings {
            Notifications::Enabled(enabled) => *enabled,
            Notifications::Custom(allowed) => allowed.iter().any(|a| a == self.type_name()),
        }
    }

    fn agent_turn_preview(response: &str) -> Option<String> {
        let mut normalized = String::new();
        for part in response.split_whitespace() {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push_str(part);
        }
        let trimmed = normalized.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(truncate_text(trimmed, AGENT_NOTIFICATION_PREVIEW_GRAPHEMES))
        }
    }
}

const AGENT_NOTIFICATION_PREVIEW_GRAPHEMES: usize = 200;

const EXAMPLE_PROMPTS: [&str; 6] = [
    "Explain this codebase",
    "Summarize recent commits",
    "Implement {feature}",
    "Find and fix a bug in @filename",
    "Write tests for @filename",
    "Improve documentation in @filename",
];

// Extract the first bold (Markdown) element in the form **...** from `s`.
// Returns the inner text if found; otherwise `None`.
fn extract_first_bold(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'*' {
            let start = i + 2;
            let mut j = start;
            while j + 1 < bytes.len() {
                if bytes[j] == b'*' && bytes[j + 1] == b'*' {
                    // Found closing **
                    let inner = &s[start..j];
                    let trimmed = inner.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    } else {
                        return None;
                    }
                }
                j += 1;
            }
            // No closing; stop searching (wait for more deltas)
            return None;
        }
        i += 1;
    }
    None
}

async fn fetch_rate_limits(base_url: String, auth: CodexAuth) -> Option<RateLimitSnapshot> {
    match BackendClient::from_auth(base_url, &auth) {
        Ok(client) => match client.get_rate_limits().await {
            Ok(snapshot) => Some(snapshot),
            Err(err) => {
                debug!(error = ?err, "failed to fetch rate limits from /usage");
                None
            }
        },
        Err(err) => {
            debug!(error = ?err, "failed to construct backend client for rate limits");
            None
        }
    }
}

#[cfg(test)]
pub(crate) fn show_review_commit_picker_with_entries(
    chat: &mut ChatWidget,
    entries: Vec<codex_core::git_info::CommitLogEntry>,
) {
    let mut items: Vec<SelectionItem> = Vec::with_capacity(entries.len());
    for entry in entries {
        let subject = entry.subject.clone();
        let sha = entry.sha.clone();
        let search_val = format!("{subject} {sha}");

        items.push(SelectionItem {
            name: subject.clone(),
            actions: vec![Box::new(move |tx3: &AppEventSender| {
                tx3.send(AppEvent::CodexOp(Op::Review {
                    review_request: ReviewRequest {
                        target: ReviewTarget::Commit {
                            sha: sha.clone(),
                            title: Some(subject.clone()),
                        },
                        user_facing_hint: None,
                    },
                }));
            })],
            dismiss_on_select: true,
            search_value: Some(search_val),
            ..Default::default()
        });
    }

    chat.bottom_pane.show_selection_view(SelectionViewParams {
        title: Some("Select a commit to review".to_string()),
        footer_hint: Some(standard_popup_hint_line()),
        items,
        is_searchable: true,
        search_placeholder: Some("Type to search commits".to_string()),
        ..Default::default()
    });
}

fn find_skill_mentions(text: &str, skills: &[SkillMetadata]) -> Vec<SkillMetadata> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut matches: Vec<SkillMetadata> = Vec::new();
    for skill in skills {
        if seen.contains(&skill.name) {
            continue;
        }
        let needle = format!("${}", skill.name);
        if text.contains(&needle) {
            seen.insert(skill.name.clone());
            matches.push(skill.clone());
        }
    }
    matches
}

fn skills_for_cwd(cwd: &Path, skills_entries: &[SkillsListEntry]) -> Vec<SkillMetadata> {
    skills_entries
        .iter()
        .find(|entry| entry.cwd.as_path() == cwd)
        .map(|entry| {
            entry
                .skills
                .iter()
                .map(|skill| SkillMetadata {
                    name: skill.name.clone(),
                    description: skill.description.clone(),
                    short_description: skill.short_description.clone(),
                    path: skill.path.clone(),
                    scope: skill.scope,
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod tests;
