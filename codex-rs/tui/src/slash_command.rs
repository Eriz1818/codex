use strum::IntoEnumIterator;
use strum_macros::AsRefStr;
use strum_macros::EnumIter;
use strum_macros::EnumString;
use strum_macros::IntoStaticStr;

/// Commands that can be invoked by starting a message with a leading slash.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, EnumIter, AsRefStr, IntoStaticStr,
)]
#[strum(serialize_all = "kebab-case")]
pub enum SlashCommand {
    // DO NOT ALPHA-SORT! Enum order is presentation order in the popup, so
    // more frequently used commands should be listed first.
    Model,
    Approvals,
    Experimental,
    Skills,
    Help,
    Review,
    New,
    Resume,
    Init,
    Compact,
    Autocompact,
    Thoughts,
    // Undo,
    Diff,
    Mention,
    Status,
    Settings,
    StatusMenu,
    Worktree,
    Hooks,
    Mcp,
    Logout,
    Quit,
    Exit,
    Feedback,
    Rollout,
    Ps,
    PsKill,
    TestApproval,
}

impl SlashCommand {
    /// User-visible description shown in the popup.
    pub fn description(self) -> &'static str {
        match self {
            SlashCommand::Feedback => "save a local report for troubleshooting",
            SlashCommand::New => "start a new chat during a conversation",
            SlashCommand::Init => "create an AGENTS.md file with instructions for xcodex",
            SlashCommand::Compact => "summarize conversation to prevent hitting the context limit",
            SlashCommand::Autocompact => "toggle automatic conversation compaction (persists)",
            SlashCommand::Thoughts => "toggle showing agent thoughts/reasoning (persists)",
            SlashCommand::Review => "review my current changes and find issues",
            SlashCommand::Resume => "resume a saved chat",
            // SlashCommand::Undo => "ask Codex to undo a turn",
            SlashCommand::Quit | SlashCommand::Exit => "exit xcodex",
            SlashCommand::Diff => "show git diff (including untracked files)",
            SlashCommand::Mention => "mention a file",
            SlashCommand::Skills => "use skills to improve how xcodex performs specific tasks",
            SlashCommand::Help => "show help for a topic (e.g. /help xcodex)",
            SlashCommand::Status => "open the status/settings menu",
            SlashCommand::Settings => "open the status/settings menu",
            SlashCommand::StatusMenu => "open the status/settings menu (alias)",
            SlashCommand::Worktree => "switch this session to a different git worktree",
            SlashCommand::Hooks => "learn how to automate xcodex with hooks",
            SlashCommand::Ps => "list background terminals",
            SlashCommand::PsKill => "terminate background terminals",
            SlashCommand::Model => "choose what model and reasoning effort to use",
            SlashCommand::Approvals => "choose what xcodex can do without approval",
            SlashCommand::Experimental => "toggle beta features",
            SlashCommand::Mcp => "list configured MCP tools",
            SlashCommand::Logout => "log out of xcodex",
            SlashCommand::Rollout => "print the rollout file path",
            SlashCommand::TestApproval => "test approval request",
        }
    }

    /// Command string without the leading '/'. Provided for compatibility with
    /// existing code that expects a method named `command()`.
    pub fn command(self) -> &'static str {
        self.into()
    }

    /// Whether this command can be run while a task is in progress.
    pub fn available_during_task(self) -> bool {
        match self {
            SlashCommand::New
            | SlashCommand::Resume
            | SlashCommand::Init
            | SlashCommand::Compact
            | SlashCommand::Autocompact
            // | SlashCommand::Undo
            | SlashCommand::Model
            | SlashCommand::Approvals
            | SlashCommand::Experimental
            | SlashCommand::Review
            | SlashCommand::Logout => false,
            SlashCommand::Diff
            | SlashCommand::Mention
            | SlashCommand::Skills
            | SlashCommand::Help
            | SlashCommand::Status
            | SlashCommand::Settings
            | SlashCommand::StatusMenu
            | SlashCommand::Worktree
            | SlashCommand::Hooks
            | SlashCommand::Ps
            | SlashCommand::PsKill
            | SlashCommand::Mcp
            | SlashCommand::Feedback
            | SlashCommand::Quit
            | SlashCommand::Exit => true,
            SlashCommand::Thoughts => true,
            SlashCommand::Rollout => true,
            SlashCommand::TestApproval => true,
        }
    }

    fn is_visible(self) -> bool {
        match self {
            SlashCommand::Rollout | SlashCommand::TestApproval => cfg!(debug_assertions),
            _ => true,
        }
    }
}

/// Return all built-in commands in a Vec paired with their command string.
pub fn built_in_slash_commands() -> Vec<(&'static str, SlashCommand)> {
    SlashCommand::iter()
        .filter(|command| command.is_visible())
        .map(|c| (c.command(), c))
        .collect()
}
