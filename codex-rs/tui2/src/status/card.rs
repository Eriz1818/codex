use crate::history_cell::CompositeHistoryCell;
use crate::history_cell::HistoryCell;
use crate::history_cell::PlainHistoryCell;
use crate::history_cell::with_border_with_inner_width;
use crate::version::CODEX_CLI_VERSION;
use chrono::DateTime;
use chrono::Local;
use codex_common::create_config_summary_entries;
use codex_core::config::Config;
use codex_core::protocol::NetworkAccess;
use codex_core::protocol::SandboxPolicy;
use codex_core::protocol::TokenUsage;
use codex_core::protocol::TokenUsageInfo;
use codex_protocol::ThreadId;
use codex_protocol::account::PlanType;
use ratatui::prelude::*;
use ratatui::style::Stylize;
use std::collections::BTreeSet;
use std::path::PathBuf;
use url::Url;

use super::account::StatusAccountDisplay;
use super::format::FieldFormatter;
use super::format::line_display_width;
use super::format::push_label;
use super::format::truncate_line_to_width;
use super::helpers::compose_account_display;
use super::helpers::compose_agents_summary;
use super::helpers::compose_model_display;
use super::helpers::format_directory_display;
use super::helpers::format_tokens_compact;
use super::rate_limits::RateLimitSnapshotDisplay;
use super::rate_limits::StatusRateLimitData;
use super::rate_limits::StatusRateLimitRow;
use super::rate_limits::StatusRateLimitValue;
use super::rate_limits::compose_rate_limit_data;
use super::rate_limits::format_status_limit_summary;
use super::rate_limits::render_status_limit_progress_bar;
use crate::wrapping::RtOptions;
use crate::wrapping::word_wrap_lines;
use codex_core::AuthManager;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone)]
struct StatusContextWindowData {
    percent_remaining: i64,
    tokens_in_context: i64,
    window: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct StatusTokenUsageData {
    total: i64,
    input: i64,
    output: i64,
    context_window: Option<StatusContextWindowData>,
}

#[derive(Debug)]
struct StatusHistoryCell {
    ui_frontend: String,
    model_name: String,
    model_details: Vec<String>,
    directory: PathBuf,
    codex_home: PathBuf,
    approval: String,
    sandbox: String,
    agents_summary: String,
    auto_compact_enabled: bool,
    hide_agent_reasoning: bool,
    model_provider: Option<String>,
    account: Option<StatusAccountDisplay>,
    session_id: Option<String>,
    token_usage: StatusTokenUsageData,
    rate_limits: StatusRateLimitData,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn new_status_output(
    config: &Config,
    auth_manager: &AuthManager,
    token_info: Option<&TokenUsageInfo>,
    total_usage: &TokenUsage,
    session_id: &Option<ThreadId>,
    rate_limits: Option<&RateLimitSnapshotDisplay>,
    plan_type: Option<PlanType>,
    now: DateTime<Local>,
    model_name: &str,
) -> CompositeHistoryCell {
    let command = PlainHistoryCell::new(vec!["/status".magenta().into()]);
    let card = StatusHistoryCell::new(
        config,
        auth_manager,
        token_info,
        total_usage,
        session_id,
        rate_limits,
        plan_type,
        now,
        model_name,
    );

    CompositeHistoryCell::new(vec![Box::new(command), Box::new(card)])
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn new_status_menu_summary_card(
    config: &Config,
    auth_manager: &AuthManager,
    token_info: Option<&TokenUsageInfo>,
    total_usage: &TokenUsage,
    session_id: &Option<ThreadId>,
    rate_limits: Option<&RateLimitSnapshotDisplay>,
    plan_type: Option<PlanType>,
    now: DateTime<Local>,
    model_name: &str,
) -> Box<dyn HistoryCell> {
    Box::new(StatusMenuSummaryCell(StatusHistoryCell::new(
        config,
        auth_manager,
        token_info,
        total_usage,
        session_id,
        rate_limits,
        plan_type,
        now,
        model_name,
    )))
}

pub(crate) fn new_settings_card(
    show_git_branch: bool,
    show_worktree: bool,
    verbose_tool_output: bool,
) -> Box<dyn HistoryCell> {
    Box::new(SettingsHistoryCell {
        show_git_branch,
        show_worktree,
        verbose_tool_output,
    })
}

#[derive(Debug)]
struct SettingsHistoryCell {
    show_git_branch: bool,
    show_worktree: bool,
    verbose_tool_output: bool,
}

impl HistoryCell for SettingsHistoryCell {
    fn display_lines(&self, width: u16) -> Vec<Line<'static>> {
        let available_inner_width = usize::from(width.saturating_sub(4));
        if available_inner_width == 0 {
            return Vec::new();
        }

        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(vec![
            Span::from(format!("{}>_ ", FieldFormatter::INDENT)).dim(),
            "xtreme-Codex".bold(),
            " ".dim(),
            format!("(v{CODEX_CLI_VERSION})").dim(),
        ]));
        lines.push(Line::from(Vec::<Span<'static>>::new()));

        lines.push("Status bar items".bold().into());
        for (label, enabled) in [
            ("Git branch", self.show_git_branch),
            ("Active worktree path", self.show_worktree),
        ] {
            let checkbox = if enabled { "[x]" } else { "[ ]" };
            lines.push(Line::from(format!("  {checkbox} {label}")));
        }

        lines.push(Line::from(Vec::<Span<'static>>::new()));
        lines.push("Output".bold().into());
        {
            let (label, enabled) = ("Verbose tool output", self.verbose_tool_output);
            let checkbox = if enabled { "[x]" } else { "[ ]" };
            lines.push(Line::from(format!("  {checkbox} {label}")));
        }

        lines.push(Line::from(Vec::<Span<'static>>::new()));
        lines.push(
            vec![
                "Usage: ".dim(),
                "/settings status-bar <git-branch|worktree> [on|off|toggle|status]".cyan(),
            ]
            .into(),
        );
        lines.push(
            vec![
                "       ".dim(),
                "/settings output tool-output [on|off|toggle|status]".cyan(),
            ]
            .into(),
        );
        lines.push(vec!["       ".dim(), "/verbose [on|off|toggle|status]".cyan()].into());

        let content_width = lines.iter().map(line_display_width).max().unwrap_or(0);
        let inner_width = content_width.min(available_inner_width);
        let truncated_lines: Vec<Line<'static>> = lines
            .into_iter()
            .map(|line| truncate_line_to_width(line, inner_width))
            .collect();

        with_border_with_inner_width(truncated_lines, inner_width)
    }
}

#[derive(Debug)]
struct StatusMenuSummaryCell(StatusHistoryCell);

impl HistoryCell for StatusMenuSummaryCell {
    fn display_lines(&self, width: u16) -> Vec<Line<'static>> {
        let available_width = usize::from(width);
        if available_width == 0 {
            return Vec::new();
        }

        let status = &self.0;
        let limit_bar_indent = status_menu_limit_bar_indent(status);

        let mut labels: Vec<&'static str> = vec![
            "UI",
            "Model",
            "Directory",
            "Approval",
            "Sandbox",
            "Auto-compact",
            "Thoughts",
        ];

        if status.session_id.is_some() {
            labels.push("Session");
        }

        if !matches!(status.account, Some(StatusAccountDisplay::ChatGpt { .. })) {
            labels.push("Token usage");
        }

        if status.token_usage.context_window.is_some() {
            labels.push("Context");
        }

        labels.push("Limits");

        let formatter = FieldFormatter::from_labels(labels.iter().copied());
        let value_width = formatter.value_width(available_width);

        let mut lines: Vec<Line<'static>> = Vec::new();

        let mut model_spans = vec![Span::from(status.model_name.clone())];
        if !status.model_details.is_empty() {
            model_spans.push(" (".dim());
            model_spans.push(Span::from(status.model_details.join(", ")).dim());
            model_spans.push(")".dim());
        }

        let directory_value = format_directory_display(&status.directory, Some(value_width));

        lines.push(formatter.line("UI", vec![Span::from(status.ui_frontend.clone())]));
        lines.push(formatter.line("Model", model_spans));
        lines.push(formatter.line("Directory", vec![Span::from(directory_value)]));
        lines.push(formatter.line("Approval", vec![Span::from(status.approval.clone())]));
        lines.push(formatter.line("Sandbox", vec![Span::from(status.sandbox.clone())]));
        lines.push(formatter.line(
            "Auto-compact",
            vec![Span::from(if status.auto_compact_enabled {
                "enabled"
            } else {
                "disabled"
            })],
        ));
        lines.push(formatter.line(
            "Thoughts",
            vec![Span::from(if status.hide_agent_reasoning {
                "hidden"
            } else {
                "shown"
            })],
        ));

        if let Some(session) = status.session_id.as_ref() {
            lines.push(formatter.line("Session", vec![Span::from(session.clone())]));
        }

        if !matches!(status.account, Some(StatusAccountDisplay::ChatGpt { .. })) {
            lines.push(formatter.line("Token usage", status.token_usage_spans()));
        }

        if let Some(spans) = status.context_window_spans_for_menu(limit_bar_indent) {
            lines.push(formatter.line("Context", spans));
        }

        lines.extend(status_menu_limit_lines(status, &formatter));

        let truncated_lines: Vec<Line<'static>> = lines
            .into_iter()
            .map(|line| truncate_line_to_width(line, available_width))
            .collect();

        truncated_lines
    }
}

fn status_menu_limit_lines(
    status: &StatusHistoryCell,
    formatter: &FieldFormatter,
) -> Vec<Line<'static>> {
    let rows = match &status.rate_limits {
        StatusRateLimitData::Available(rows) | StatusRateLimitData::Stale(rows) => rows,
        StatusRateLimitData::Missing => {
            return vec![formatter.line("Limits", vec!["data not available yet".dim()])];
        }
    };

    let Some(row) = rows.first() else {
        return vec![formatter.line("Limits", vec!["data not available yet".dim()])];
    };

    let max_label_width = status_menu_limit_label_width(status).max(1);

    let mut lines = Vec::new();

    for (idx, row) in rows.iter().enumerate() {
        let padding = max_label_width.saturating_sub(UnicodeWidthStr::width(row.label.as_str()));
        let label_prefix = format!("{}{} ", row.label, " ".repeat(padding));
        let value_spans = match &row.value {
            StatusRateLimitValue::Window {
                percent_used,
                resets_at,
            } => {
                let percent_remaining = (100.0 - percent_used).clamp(0.0, 100.0);
                let mut spans = vec![
                    Span::from(label_prefix),
                    Span::from(render_status_limit_progress_bar(percent_remaining)),
                    Span::from(" "),
                    Span::from(format_status_limit_summary(percent_remaining)),
                ];
                if let Some(resets_at) = resets_at.as_ref() {
                    spans.push(Span::from(" ").dim());
                    spans.push(Span::from(format!("(resets {resets_at})")).dim());
                }
                spans
            }
            StatusRateLimitValue::Text(text) => vec![Span::from(format!("{label_prefix}{text}"))],
        };

        if idx == 0 {
            lines.push(formatter.line("Limits", value_spans));
        } else {
            lines.push(formatter.continuation(value_spans));
        }
    }

    if lines.is_empty() {
        lines.push(formatter.line("Limits", vec![Span::from(row.label.clone())]));
    }

    lines
}

impl StatusHistoryCell {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &Config,
        auth_manager: &AuthManager,
        token_info: Option<&TokenUsageInfo>,
        total_usage: &TokenUsage,
        session_id: &Option<ThreadId>,
        rate_limits: Option<&RateLimitSnapshotDisplay>,
        plan_type: Option<PlanType>,
        now: DateTime<Local>,
        model_name: &str,
    ) -> Self {
        let config_entries = create_config_summary_entries(config, model_name);
        let (model_name, model_details) = compose_model_display(model_name, &config_entries);
        let approval = config_entries
            .iter()
            .find(|(k, _)| *k == "approval")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "<unknown>".to_string());
        let sandbox = match config.sandbox_policy.get() {
            SandboxPolicy::DangerFullAccess => "danger-full-access".to_string(),
            SandboxPolicy::ReadOnly => "read-only".to_string(),
            SandboxPolicy::WorkspaceWrite { .. } => "workspace-write".to_string(),
            SandboxPolicy::ExternalSandbox { network_access } => {
                if matches!(network_access, NetworkAccess::Enabled) {
                    "external-sandbox (network access enabled)".to_string()
                } else {
                    "external-sandbox".to_string()
                }
            }
        };
        let agents_summary = compose_agents_summary(config);
        let auto_compact_enabled =
            codex_core::prefs::load_blocking(&config.codex_home).auto_compact_enabled;
        let model_provider = format_model_provider(config);
        let account = compose_account_display(auth_manager, plan_type);
        let session_id = session_id.as_ref().map(std::string::ToString::to_string);
        let default_usage = TokenUsage::default();
        let (context_usage, context_window) = match token_info {
            Some(info) => (&info.last_token_usage, info.model_context_window),
            None => (&default_usage, config.model_context_window),
        };
        let context_window = context_window.map(|window| StatusContextWindowData {
            percent_remaining: context_usage.percent_of_context_window_remaining(window),
            tokens_in_context: context_usage.tokens_in_context_window(),
            window,
        });

        let token_usage = StatusTokenUsageData {
            total: total_usage.blended_total(),
            input: total_usage.non_cached_input(),
            output: total_usage.output_tokens,
            context_window,
        };
        let rate_limits = compose_rate_limit_data(rate_limits, now);

        Self {
            ui_frontend: "tui2".to_string(),
            model_name,
            model_details,
            directory: config.cwd.clone(),
            codex_home: config.codex_home.clone(),
            approval,
            sandbox,
            agents_summary,
            auto_compact_enabled,
            hide_agent_reasoning: config.hide_agent_reasoning,
            model_provider,
            account,
            session_id,
            token_usage,
            rate_limits,
        }
    }

    fn token_usage_spans(&self) -> Vec<Span<'static>> {
        let total_fmt = format_tokens_compact(self.token_usage.total);
        let input_fmt = format_tokens_compact(self.token_usage.input);
        let output_fmt = format_tokens_compact(self.token_usage.output);

        vec![
            Span::from(total_fmt),
            Span::from(" total "),
            Span::from(" (").dim(),
            Span::from(input_fmt).dim(),
            Span::from(" input").dim(),
            Span::from(" + ").dim(),
            Span::from(output_fmt).dim(),
            Span::from(" output").dim(),
            Span::from(")").dim(),
        ]
    }

    fn context_window_spans(&self) -> Option<Vec<Span<'static>>> {
        let context = self.token_usage.context_window.as_ref()?;
        let percent = context.percent_remaining;
        let used_fmt = format_tokens_compact(context.tokens_in_context);
        let window_fmt = format_tokens_compact(context.window);
        let percent_remaining = (percent as f64).clamp(0.0, 100.0);

        Some(vec![
            Span::from(render_status_limit_progress_bar(percent_remaining)),
            Span::from(" "),
            Span::from(format!("{percent}% left")),
            Span::from(" (").dim(),
            Span::from(used_fmt).dim(),
            Span::from(" used / ").dim(),
            Span::from(window_fmt).dim(),
            Span::from(")").dim(),
        ])
    }

    fn context_window_spans_for_menu(&self, limit_bar_indent: usize) -> Option<Vec<Span<'static>>> {
        let mut spans = self.context_window_spans()?;
        if limit_bar_indent > 0 {
            spans.insert(0, Span::from(" ".repeat(limit_bar_indent)));
        }
        Some(spans)
    }

    fn rate_limit_lines(
        &self,
        available_inner_width: usize,
        formatter: &FieldFormatter,
    ) -> Vec<Line<'static>> {
        match &self.rate_limits {
            StatusRateLimitData::Available(rows_data) => {
                if rows_data.is_empty() {
                    return vec![
                        formatter.line("Limits", vec![Span::from("data not available yet").dim()]),
                    ];
                }

                self.rate_limit_row_lines(rows_data, available_inner_width, formatter)
            }
            StatusRateLimitData::Stale(rows_data) => {
                let mut lines =
                    self.rate_limit_row_lines(rows_data, available_inner_width, formatter);
                lines.push(formatter.line(
                    "Warning",
                    vec![Span::from("limits may be stale - start new turn to refresh.").dim()],
                ));
                lines
            }
            StatusRateLimitData::Missing => {
                vec![formatter.line("Limits", vec![Span::from("data not available yet").dim()])]
            }
        }
    }

    fn rate_limit_row_lines(
        &self,
        rows: &[StatusRateLimitRow],
        available_inner_width: usize,
        formatter: &FieldFormatter,
    ) -> Vec<Line<'static>> {
        let mut lines = Vec::with_capacity(rows.len().saturating_mul(2));

        for row in rows {
            match &row.value {
                StatusRateLimitValue::Window {
                    percent_used,
                    resets_at,
                } => {
                    let percent_remaining = (100.0 - percent_used).clamp(0.0, 100.0);
                    let value_spans = vec![
                        Span::from(render_status_limit_progress_bar(percent_remaining)),
                        Span::from(" "),
                        Span::from(format_status_limit_summary(percent_remaining)),
                    ];
                    let base_spans = formatter.full_spans(row.label.as_str(), value_spans);
                    let base_line = Line::from(base_spans.clone());

                    if let Some(resets_at) = resets_at.as_ref() {
                        let resets_span = Span::from(format!("(resets {resets_at})")).dim();
                        let mut inline_spans = base_spans.clone();
                        inline_spans.push(Span::from(" ").dim());
                        inline_spans.push(resets_span.clone());

                        if line_display_width(&Line::from(inline_spans.clone()))
                            <= available_inner_width
                        {
                            lines.push(Line::from(inline_spans));
                        } else {
                            lines.push(base_line);
                            lines.push(formatter.continuation(vec![resets_span]));
                        }
                    } else {
                        lines.push(base_line);
                    }
                }
                StatusRateLimitValue::Text(text) => {
                    let label = row.label.clone();
                    let spans =
                        formatter.full_spans(label.as_str(), vec![Span::from(text.clone())]);
                    lines.push(Line::from(spans));
                }
            }
        }

        lines
    }

    fn collect_rate_limit_labels(&self, seen: &mut BTreeSet<String>, labels: &mut Vec<String>) {
        match &self.rate_limits {
            StatusRateLimitData::Available(rows) => {
                if rows.is_empty() {
                    push_label(labels, seen, "Limits");
                } else {
                    for row in rows {
                        push_label(labels, seen, row.label.as_str());
                    }
                }
            }
            StatusRateLimitData::Stale(rows) => {
                for row in rows {
                    push_label(labels, seen, row.label.as_str());
                }
                push_label(labels, seen, "Warning");
            }
            StatusRateLimitData::Missing => push_label(labels, seen, "Limits"),
        }
    }
}

fn status_menu_limit_label_width(status: &StatusHistoryCell) -> usize {
    match &status.rate_limits {
        StatusRateLimitData::Available(rows) | StatusRateLimitData::Stale(rows) => rows
            .iter()
            .map(|row| UnicodeWidthStr::width(row.label.as_str()))
            .max()
            .unwrap_or(0),
        StatusRateLimitData::Missing => 0,
    }
}

fn status_menu_limit_bar_indent(status: &StatusHistoryCell) -> usize {
    let width = status_menu_limit_label_width(status);
    width.saturating_add(1)
}

impl HistoryCell for StatusHistoryCell {
    fn display_lines(&self, width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(vec![
            Span::from(format!("{}>_ ", FieldFormatter::INDENT)).dim(),
            Span::from("xtreme-Codex").bold(),
            Span::from(" ").dim(),
            Span::from(format!("(v{CODEX_CLI_VERSION})")).dim(),
        ]));
        lines.push(Line::from(Vec::<Span<'static>>::new()));

        let available_inner_width = usize::from(width.saturating_sub(4));
        if available_inner_width == 0 {
            return Vec::new();
        }

        let account_value = self.account.as_ref().map(|account| match account {
            StatusAccountDisplay::ChatGpt { email, plan } => match (email, plan) {
                (Some(email), Some(plan)) => format!("{email} ({plan})"),
                (Some(email), None) => email.clone(),
                (None, Some(plan)) => plan.clone(),
                (None, None) => "ChatGPT".to_string(),
            },
            StatusAccountDisplay::ApiKey => {
                "API key configured (run xcodex login to use ChatGPT)".to_string()
            }
        });

        let mut labels: Vec<String> = vec![
            "UI",
            "Model",
            "Directory",
            "CODEX_HOME",
            "Approval",
            "Sandbox",
            "Agents.md",
            "Auto-compact",
            "Thoughts",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let mut seen: BTreeSet<String> = labels.iter().cloned().collect();

        if self.model_provider.is_some() {
            push_label(&mut labels, &mut seen, "Model provider");
        }
        if account_value.is_some() {
            push_label(&mut labels, &mut seen, "Account");
        }
        if self.session_id.is_some() {
            push_label(&mut labels, &mut seen, "Session");
        }
        push_label(&mut labels, &mut seen, "Token usage");
        if self.token_usage.context_window.is_some() {
            push_label(&mut labels, &mut seen, "Context window");
        }
        self.collect_rate_limit_labels(&mut seen, &mut labels);

        let formatter = FieldFormatter::from_labels(labels.iter().map(String::as_str));
        let value_width = formatter.value_width(available_inner_width);

        let note_first_line = Line::from(vec![
            Span::from("Visit ").cyan(),
            "https://chatgpt.com/codex/settings/usage"
                .cyan()
                .underlined(),
            Span::from(" for up-to-date").cyan(),
        ]);
        let note_second_line = Line::from(vec![
            Span::from("information on rate limits and credits").cyan(),
        ]);
        let note_lines = word_wrap_lines(
            [note_first_line, note_second_line],
            RtOptions::new(available_inner_width),
        );
        lines.extend(note_lines);
        lines.push(Line::from(Vec::<Span<'static>>::new()));

        let mut model_spans = vec![Span::from(self.model_name.clone())];
        if !self.model_details.is_empty() {
            model_spans.push(Span::from(" (").dim());
            model_spans.push(Span::from(self.model_details.join(", ")).dim());
            model_spans.push(Span::from(")").dim());
        }

        let directory_value = format_directory_display(&self.directory, Some(value_width));
        let codex_home_value = format_directory_display(&self.codex_home, Some(value_width));

        lines.push(formatter.line("UI", vec![Span::from(self.ui_frontend.clone())]));
        lines.push(formatter.line("Model", model_spans));
        if let Some(model_provider) = self.model_provider.as_ref() {
            lines.push(formatter.line("Model provider", vec![Span::from(model_provider.clone())]));
        }
        lines.push(formatter.line("Directory", vec![Span::from(directory_value)]));
        lines.push(formatter.line("CODEX_HOME", vec![Span::from(codex_home_value)]));
        lines.push(formatter.line("Approval", vec![Span::from(self.approval.clone())]));
        lines.push(formatter.line("Sandbox", vec![Span::from(self.sandbox.clone())]));
        lines.push(formatter.line("Agents.md", vec![Span::from(self.agents_summary.clone())]));
        lines.push(formatter.line(
            "Auto-compact",
            vec![if self.auto_compact_enabled {
                "enabled".green().bold()
            } else {
                "disabled".dim()
            }],
        ));
        lines.push(formatter.line(
            "Thoughts",
            vec![Span::from(if self.hide_agent_reasoning {
                "hidden"
            } else {
                "shown"
            })],
        ));

        if let Some(account_value) = account_value {
            lines.push(formatter.line("Account", vec![Span::from(account_value)]));
        }

        if let Some(session) = self.session_id.as_ref() {
            lines.push(formatter.line("Session", vec![Span::from(session.clone())]));
        }

        lines.push(Line::from(Vec::<Span<'static>>::new()));
        // Hide token usage only for ChatGPT subscribers
        if !matches!(self.account, Some(StatusAccountDisplay::ChatGpt { .. })) {
            lines.push(formatter.line("Token usage", self.token_usage_spans()));
        }

        if let Some(spans) = self.context_window_spans() {
            lines.push(formatter.line("Context window", spans));
        }

        lines.extend(self.rate_limit_lines(available_inner_width, &formatter));

        let content_width = lines.iter().map(line_display_width).max().unwrap_or(0);
        let inner_width = content_width.min(available_inner_width);
        let truncated_lines: Vec<Line<'static>> = lines
            .into_iter()
            .map(|line| truncate_line_to_width(line, inner_width))
            .collect();

        with_border_with_inner_width(truncated_lines, inner_width)
    }
}

fn format_model_provider(config: &Config) -> Option<String> {
    let provider = &config.model_provider;
    let name = provider.name.trim();
    let provider_name = if name.is_empty() {
        config.model_provider_id.as_str()
    } else {
        name
    };
    let base_url = provider.base_url.as_deref().and_then(sanitize_base_url);
    let is_default_openai = provider.is_openai() && base_url.is_none();
    if is_default_openai {
        return None;
    }

    Some(match base_url {
        Some(base_url) => format!("{provider_name} - {base_url}"),
        None => provider_name.to_string(),
    })
}

fn sanitize_base_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let Ok(mut url) = Url::parse(trimmed) else {
        return None;
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string().trim_end_matches('/').to_string()).filter(|value| !value.is_empty())
}
