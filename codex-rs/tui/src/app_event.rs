//! Application-level events used to coordinate UI actions.
//!
//! `AppEvent` is the internal message bus between UI components and the top-level `App` loop.
//! Widgets emit events to request actions that must be handled at the app layer (like opening
//! pickers, persisting configuration, or shutting down the agent), without needing direct access to
//! `App` internals.
//!
//! Exit is modelled explicitly via `AppEvent::Exit(ExitMode)` so callers can request shutdown-first
//! quits without reaching into the app loop or coupling to shutdown/exit sequencing.

use std::path::PathBuf;

use codex_common::approval_presets::ApprovalPreset;
use codex_core::git_info::GitWorktreeEntry;
use codex_core::protocol::Event;
use codex_core::protocol::RateLimitSnapshot;
use codex_file_search::FileMatch;
use codex_protocol::ThreadId;
use codex_protocol::openai_models::ModelPreset;

use crate::bottom_pane::ApprovalRequest;
use crate::history_cell::HistoryCell;
use crate::slash_command::SlashCommand;

use codex_core::config::types::XtremeMode;
use codex_core::features::Feature;
use codex_core::protocol::AskForApproval;
use codex_core::protocol::SandboxPolicy;
use codex_protocol::openai_models::ReasoningEffort;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) enum WindowsSandboxEnableMode {
    Elevated,
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) enum WindowsSandboxFallbackReason {
    ElevationFailed,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum AppEvent {
    CodexEvent(Event),
    ExternalApprovalRequest {
        thread_id: ThreadId,
        event: Event,
    },

    /// Start a new session.
    NewSession,

    /// Open the resume picker inside the running TUI session.
    OpenResumePicker,

    /// Dispatch a local slash command from non-composer UI (e.g. tools menu).
    DispatchSlashCommand(SlashCommand),

    /// Open transcript overlay (same as pressing Ctrl+T).
    OpenTranscriptOverlay,

    /// Fork the current session into a new thread.
    ForkCurrentSession,

    /// Request to exit the application.
    ///
    /// Use `ShutdownFirst` for user-initiated quits so core cleanup runs and the
    /// UI exits only after `ShutdownComplete`. `Immediate` is a last-resort
    /// escape hatch that skips shutdown and may drop in-flight work (e.g.,
    /// background tasks, rollout flush, or child process cleanup).
    Exit(ExitMode),

    /// Request to exit the application due to a fatal error.
    FatalExitRequest(String),

    /// Forward an `Op` to the Agent. Using an `AppEvent` for this avoids
    /// bubbling channels through layers of widgets.
    CodexOp(codex_core::protocol::Op),

    /// Kick off an asynchronous file search for the given query (text after
    /// the `@`). Previous searches may be cancelled by the app layer so there
    /// is at most one in-flight search.
    StartFileSearch(String),

    /// Result of a completed asynchronous file search. The `query` echoes the
    /// original search term so the UI can decide whether the results are
    /// still relevant.
    FileSearchResult {
        query: String,
        matches: Vec<FileMatch>,
    },

    /// Result of refreshing rate limits
    RateLimitSnapshotFetched(RateLimitSnapshot),

    /// Result of computing a `/diff` command.
    DiffResult(String),

    /// Update git context shown in the bottom status bar (if enabled).
    UpdateStatusBarGitContext {
        git_branch: Option<String>,
        worktree_root: Option<PathBuf>,
    },

    /// Update cached git branches for slash arg completions (e.g. `/worktree init` branch suggestions).
    UpdateSlashCompletionBranches {
        branches: Vec<String>,
    },

    /// Update status bar item toggles (runtime).
    UpdateStatusBarGitOptions {
        show_git_branch: bool,
        show_worktree: bool,
    },

    /// Update whether tool output is shown verbosely in the transcript (runtime).
    UpdateVerboseToolOutput(bool),

    /// Update whether xtreme mode styling is enabled (runtime).
    UpdateXtremeMode(XtremeMode),

    /// Update xcodex ramp settings at runtime.
    UpdateRampsConfig {
        rotate: bool,
        build: bool,
        devops: bool,
    },

    /// Update `worktrees.shared_dirs` at runtime.
    UpdateWorktreesSharedDirs {
        shared_dirs: Vec<String>,
    },

    /// Update `worktrees.pinned_paths` at runtime.
    UpdateWorktreesPinnedPaths {
        pinned_paths: Vec<String>,
    },

    /// Replace the cached git worktree list.
    WorktreeListUpdated {
        worktrees: Vec<GitWorktreeEntry>,
        open_picker: bool,
    },

    /// Open the `/worktree` command menu in the composer (slash popup).
    #[allow(dead_code)]
    OpenWorktreeCommandMenu,

    /// Open a command by inserting it into the composer (when empty).
    #[allow(dead_code)]
    OpenToolsCommand {
        command: String,
    },

    /// Open the worktrees settings editor view.
    OpenWorktreesSettingsView,

    /// Open the `/worktree init` wizard.
    OpenWorktreeInitWizard {
        worktree_root: PathBuf,
        workspace_root: PathBuf,
        current_branch: Option<String>,
        shared_dirs: Vec<String>,
        branches: Vec<String>,
    },

    /// Refresh the git worktree list for the current session `cwd`.
    WorktreeDetect {
        open_picker: bool,
    },

    /// Report a worktree detection error (and optionally open the picker).
    WorktreeListUpdateFailed {
        error: String,
        open_picker: bool,
    },

    /// Switch the active git worktree for this session (typically via `/worktree`).
    WorktreeSwitched(PathBuf),

    /// Warning emitted after switching worktrees when untracked files are detected in the
    /// previously active worktree.
    WorktreeUntrackedFilesDetected {
        previous_worktree_root: PathBuf,
        total: usize,
        sample: Vec<String>,
    },

    InsertHistoryCell(Box<dyn HistoryCell>),

    StartCommitAnimation,
    StopCommitAnimation,
    CommitTick,

    /// Update the current reasoning effort in the running app and widget.
    UpdateReasoningEffort(Option<ReasoningEffort>),

    /// Update the current model slug in the running app and widget.
    UpdateModel(String),

    /// Update whether agent reasoning is displayed in the TUI.
    UpdateHideAgentReasoning(bool),

    /// Persist the selected model and reasoning effort to the appropriate config.
    PersistModelSelection {
        model: String,
        effort: Option<ReasoningEffort>,
    },

    /// Persist the agent reasoning visibility preference to the appropriate config.
    PersistHideAgentReasoning(bool),

    /// Persist status bar item toggles to the appropriate config.
    PersistStatusBarGitOptions {
        show_git_branch: bool,
        show_worktree: bool,
    },

    /// Persist whether tool output is shown verbosely in the transcript.
    PersistVerboseToolOutput(bool),

    /// Persist whether xtreme mode styling is enabled.
    PersistXtremeMode(XtremeMode),

    /// Persist xcodex ramp settings.
    PersistRampsConfig {
        rotate: bool,
        build: bool,
        devops: bool,
    },

    /// Open the xcodex ramp settings view.
    OpenRampsSettingsView,

    /// Persist `worktrees.shared_dirs` to config.
    PersistWorktreesSharedDirs {
        shared_dirs: Vec<String>,
    },

    /// Persist `worktrees.pinned_paths` to config.
    PersistWorktreesPinnedPaths {
        pinned_paths: Vec<String>,
    },

    /// Persist the startup timeout for a single MCP server.
    PersistMcpStartupTimeout {
        server: String,
        startup_timeout_sec: u64,
    },

    /// Open the reasoning selection popup after picking a model.
    OpenReasoningPopup {
        model: ModelPreset,
    },

    /// Open the full model picker (non-auto models).
    OpenAllModelsPopup {
        models: Vec<ModelPreset>,
    },

    /// Open the confirmation prompt before enabling full access mode.
    OpenFullAccessConfirmation {
        preset: ApprovalPreset,
    },

    /// Open the Windows world-writable directories warning.
    /// If `preset` is `Some`, the confirmation will apply the provided
    /// approval/sandbox configuration on Continue; if `None`, it performs no
    /// policy change and only acknowledges/dismisses the warning.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    OpenWorldWritableWarningConfirmation {
        preset: Option<ApprovalPreset>,
        /// Up to 3 sample world-writable directories to display in the warning.
        sample_paths: Vec<String>,
        /// If there are more than `sample_paths`, this carries the remaining count.
        extra_count: usize,
        /// True when the scan failed (e.g. ACL query error) and protections could not be verified.
        failed_scan: bool,
    },

    /// Prompt to enable the Windows sandbox feature before using Agent mode.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    OpenWindowsSandboxEnablePrompt {
        preset: ApprovalPreset,
    },

    /// Open the Windows sandbox fallback prompt after declining or failing elevation.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    OpenWindowsSandboxFallbackPrompt {
        preset: ApprovalPreset,
        reason: WindowsSandboxFallbackReason,
    },

    /// Begin the elevated Windows sandbox setup flow.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    BeginWindowsSandboxElevatedSetup {
        preset: ApprovalPreset,
    },

    /// Enable the Windows sandbox feature and switch to Agent mode.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    EnableWindowsSandboxForAgentMode {
        preset: ApprovalPreset,
        mode: WindowsSandboxEnableMode,
    },

    /// Update the current approval policy in the running app and widget.
    UpdateAskForApprovalPolicy(AskForApproval),

    /// Update the current sandbox policy in the running app and widget.
    UpdateSandboxPolicy(SandboxPolicy),

    /// Update feature flags and persist them to the top-level config.
    UpdateFeatureFlags {
        updates: Vec<(Feature, bool)>,
    },

    /// Update whether the full access warning prompt has been acknowledged.
    UpdateFullAccessWarningAcknowledged(bool),

    /// Update whether the world-writable directories warning has been acknowledged.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    UpdateWorldWritableWarningAcknowledged(bool),

    /// Update whether the rate limit switch prompt has been acknowledged for the session.
    UpdateRateLimitSwitchPromptHidden(bool),

    /// Persist the acknowledgement flag for the full access warning prompt.
    PersistFullAccessWarningAcknowledged,

    /// Persist the acknowledgement flag for the world-writable directories warning.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    PersistWorldWritableWarningAcknowledged,

    /// Persist the acknowledgement flag for the rate limit switch prompt.
    PersistRateLimitSwitchPromptHidden,

    /// Persist the acknowledgement flag for the model migration prompt.
    PersistModelMigrationPromptAcknowledged {
        from_model: String,
        to_model: String,
    },

    /// Skip the next world-writable scan (one-shot) after a user-confirmed continue.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    SkipNextWorldWritableScan,

    /// Re-open the approval presets popup.
    OpenApprovalsPopup,

    /// Open the branch picker option from the review popup.
    OpenReviewBranchPicker(PathBuf),

    /// Open the commit picker option from the review popup.
    OpenReviewCommitPicker(PathBuf),

    /// Open the custom prompt option from the review popup.
    OpenReviewCustomPrompt,

    /// Open the approval popup.
    FullScreenApprovalRequest(ApprovalRequest),

    /// Open the feedback note entry overlay after the user selects a category.
    OpenFeedbackNote {
        category: FeedbackCategory,
        include_logs: bool,
    },

    /// Open the upload consent popup for feedback after selecting a category.
    OpenFeedbackConsent {
        category: FeedbackCategory,
    },

    /// Launch the external editor after a normal draw has completed.
    LaunchExternalEditor,
}

/// The exit strategy requested by the UI layer.
///
/// Most user-initiated exits should use `ShutdownFirst` so core cleanup runs and the UI exits only
/// after core acknowledges completion. `Immediate` is an escape hatch for cases where shutdown has
/// already completed (or is being bypassed) and the UI loop should terminate right away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitMode {
    /// Shutdown core and exit after completion.
    ShutdownFirst,
    /// Exit the UI loop immediately without waiting for shutdown.
    ///
    /// This skips `Op::Shutdown`, so any in-flight work may be dropped and
    /// cleanup that normally runs before `ShutdownComplete` can be missed.
    Immediate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeedbackCategory {
    BadResult,
    GoodResult,
    Bug,
    Other,
}
