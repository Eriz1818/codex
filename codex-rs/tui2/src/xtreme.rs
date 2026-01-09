use codex_core::config::Config;
use codex_core::config::types::XtremeMode;
use codex_core::protocol::AskForApproval;
use codex_core::protocol::SandboxPolicy;
use ratatui::prelude::*;
use ratatui::style::Stylize;

pub(crate) fn xtreme_ui_enabled(config: &Config) -> bool {
    match config.tui_xtreme_mode {
        XtremeMode::Auto => codex_core::config::is_xcodex_invocation(),
        XtremeMode::On => true,
        XtremeMode::Off => false,
    }
}

pub(crate) fn title_prefix_spans(xtreme_ui_enabled: bool) -> Vec<Span<'static>> {
    if xtreme_ui_enabled {
        vec![bolt_span(xtreme_ui_enabled), " ".into()]
    } else {
        vec![">_ ".into()]
    }
}

pub(crate) fn bolt_span(xtreme_ui_enabled: bool) -> Span<'static> {
    if xtreme_ui_enabled {
        Span::styled("⚡", Style::default().fg(Color::Yellow))
    } else {
        "⚡".into()
    }
}

fn approval_score(approval: AskForApproval) -> u8 {
    match approval {
        AskForApproval::UnlessTrusted => 1,
        AskForApproval::OnRequest => 2,
        AskForApproval::OnFailure | AskForApproval::Never => 3,
    }
}

fn sandbox_score(sandbox: &SandboxPolicy) -> u8 {
    match sandbox {
        SandboxPolicy::ReadOnly => 1,
        SandboxPolicy::WorkspaceWrite { .. } | SandboxPolicy::ExternalSandbox { .. } => 2,
        SandboxPolicy::DangerFullAccess => 3,
    }
}

pub(crate) fn power_meter_spans(
    xtreme_ui_enabled: bool,
    approval: AskForApproval,
    sandbox: &SandboxPolicy,
) -> Option<Vec<Span<'static>>> {
    if !xtreme_ui_enabled {
        return None;
    }

    let score = approval_score(approval).min(sandbox_score(sandbox));
    let filled = usize::from(score.min(3));

    let mut spans: Vec<Span<'static>> = vec!["power:".dim(), " ".into()];
    for idx in 0..3 {
        spans.push(if idx < filled {
            bolt_span(true)
        } else {
            "⚡".dim()
        });
    }

    Some(spans)
}
