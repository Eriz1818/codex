use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyModifiers;
use ratatui::buffer::Buffer;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Widget;

use codex_core::config::types::XtremeMode;

use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use crate::history_cell::HistoryCell;
use crate::render::Insets;
use crate::render::RectExt as _;
use crate::render::renderable::Renderable;
use crate::style::user_message_style;

use super::CancellationEvent;
use super::bottom_pane_view::BottomPaneView;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusMenuTab {
    Status,
    Settings,
    Tools,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RadioDemo {
    Alpha,
    Beta,
    Gamma,
}

pub(crate) struct StatusMenuView {
    tab: StatusMenuTab,
    complete: bool,
    status_bar_show_git_branch: bool,
    status_bar_show_worktree: bool,
    verbose_tool_output: bool,
    xtreme_mode: XtremeMode,
    xtreme_ui_enabled: bool,
    status_scroll_y: u16,
    selected_settings_row: usize,
    selected_tools_row: usize,
    radio_demo: RadioDemo,
    app_event_tx: AppEventSender,
    status_cell: Box<dyn HistoryCell>,
}

impl StatusMenuView {
    pub(crate) fn new(
        tab: StatusMenuTab,
        app_event_tx: AppEventSender,
        status_cell: Box<dyn HistoryCell>,
        status_bar_show_git_branch: bool,
        status_bar_show_worktree: bool,
        xtreme_mode: XtremeMode,
        verbose_tool_output: bool,
    ) -> Self {
        let xtreme_ui_enabled = match xtreme_mode {
            XtremeMode::Auto => codex_core::config::is_xcodex_invocation(),
            XtremeMode::On => true,
            XtremeMode::Off => false,
        };
        Self {
            tab,
            complete: false,
            status_bar_show_git_branch,
            status_bar_show_worktree,
            verbose_tool_output,
            xtreme_mode,
            xtreme_ui_enabled,
            status_scroll_y: 0,
            selected_settings_row: 0,
            selected_tools_row: 0,
            radio_demo: RadioDemo::Alpha,
            app_event_tx,
            status_cell,
        }
    }

    fn footer_hint_line() -> Line<'static> {
        vec![
            "Tab".bold(),
            ": switch tab".dim(),
            "  ".into(),
            "↑/↓".bold(),
            ": select/scroll".dim(),
            "  ".into(),
            "Enter".bold(),
            ": toggle/run".dim(),
            "  ".into(),
            "Esc".bold(),
            ": close".dim(),
        ]
        .into()
    }

    fn tab_line(&self) -> Line<'static> {
        let status = match self.tab {
            StatusMenuTab::Status => "[ Status ]".bold().cyan(),
            StatusMenuTab::Settings | StatusMenuTab::Tools => "[ Status ]".dim(),
        };
        let settings = match self.tab {
            StatusMenuTab::Settings => "[ Settings ]".bold().cyan(),
            StatusMenuTab::Status | StatusMenuTab::Tools => "[ Settings ]".dim(),
        };
        let tools = match self.tab {
            StatusMenuTab::Tools => "[ ⚡Tools ]".bold().cyan(),
            StatusMenuTab::Status | StatusMenuTab::Settings => "[ ⚡Tools ]".dim(),
        };

        vec![
            status,
            "  ".into(),
            settings,
            "  ".into(),
            tools,
            "  ".into(),
            "(bottom-pane)".dim(),
        ]
        .into()
    }

    fn settings_row_count(&self) -> usize {
        4
    }

    fn tools_row_count(&self) -> usize {
        9
    }

    fn clamp_selected_row(&mut self) {
        let max = self.settings_row_count().saturating_sub(1);
        self.selected_settings_row = self.selected_settings_row.min(max);

        let max = self.tools_row_count().saturating_sub(1);
        self.selected_tools_row = self.selected_tools_row.min(max);
    }

    fn header_lines(&self) -> Vec<Line<'static>> {
        vec![self.tab_line(), Line::from("")]
    }

    fn body_lines(&self, status_width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        match self.tab {
            StatusMenuTab::Status => {
                lines.extend(self.status_cell.display_lines(status_width));
                lines.push(Line::from(""));
                lines.push(
                    vec![
                        "Tip: ".dim(),
                        "Tab".bold(),
                        " ".dim(),
                        "to toggle settings or open ⚡Tools.".dim(),
                    ]
                    .into(),
                );
            }
            StatusMenuTab::Settings => {
                lines.push("Settings".bold().into());
                lines.push("Toggles apply immediately and persist.".dim().into());
                lines.push(Line::from(""));
                lines.extend(self.build_settings_rows());
            }
            StatusMenuTab::Tools => {
                lines.push(
                    vec![
                        crate::xtreme::bolt_span(self.xtreme_ui_enabled),
                        "Tools".bold(),
                    ]
                    .into(),
                );
                lines.push("Toggles and shortcuts.".dim().into());
                lines.push(Line::from(""));
                lines.extend(self.build_tools_rows());
                lines.push(Line::from(""));
                lines.extend(self.selected_tool_hint_lines());
            }
        }

        lines
    }

    fn build_settings_rows(&self) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        let selected_prefix = |selected: bool| -> Span<'static> {
            if selected {
                "› ".bold().cyan()
            } else {
                "  ".into()
            }
        };

        let checkbox = |enabled: bool| -> Span<'static> {
            if enabled {
                "[x] ".green()
            } else {
                "[ ] ".dim()
            }
        };

        let radio = |active: bool| -> Span<'static> {
            if active {
                "(•) ".green()
            } else {
                "( ) ".dim()
            }
        };

        // Row 0: status bar git branch.
        {
            let selected = self.selected_settings_row == 0;
            lines.push(
                vec![
                    selected_prefix(selected),
                    checkbox(self.status_bar_show_git_branch),
                    "Status bar: git branch".into(),
                ]
                .into(),
            );
        }

        // Row 1: status bar worktree path.
        {
            let selected = self.selected_settings_row == 1;
            lines.push(
                vec![
                    selected_prefix(selected),
                    checkbox(self.status_bar_show_worktree),
                    "Status bar: worktree path".into(),
                ]
                .into(),
            );
        }

        // Row 2: tool output verbosity.
        {
            let selected = self.selected_settings_row == 2;
            lines.push(
                vec![
                    selected_prefix(selected),
                    checkbox(self.verbose_tool_output),
                    "Transcript: verbose tool output".into(),
                ]
                .into(),
            );
        }

        // Row 3: demo radio group (placeholder for future settings).
        {
            let selected = self.selected_settings_row == 3;
            lines.push(
                vec![
                    selected_prefix(selected),
                    "Demo radio: ".dim(),
                    radio(matches!(self.radio_demo, RadioDemo::Alpha)),
                    "Alpha".into(),
                    "  ".into(),
                    radio(matches!(self.radio_demo, RadioDemo::Beta)),
                    "Beta".into(),
                    "  ".into(),
                    radio(matches!(self.radio_demo, RadioDemo::Gamma)),
                    "Gamma".into(),
                ]
                .into(),
            );
        }

        lines.push(Line::from(""));
        lines.push(vec!["Tip: ".dim(), "Tab".bold(), " ".dim(), "to ⚡Tools.".dim()].into());

        lines
    }

    fn build_tools_rows(&self) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        let selected_prefix = |selected: bool| -> Span<'static> {
            if selected {
                "› ".bold().cyan()
            } else {
                "  ".into()
            }
        };

        let checkbox = |enabled: bool| -> Span<'static> {
            if enabled {
                "[x] ".green()
            } else {
                "[ ] ".dim()
            }
        };

        let xtreme_mode_label = match self.xtreme_mode {
            XtremeMode::Auto => "auto",
            XtremeMode::On => "on",
            XtremeMode::Off => "off",
        };

        // Row 0: toggle xtreme mode.
        {
            let selected = self.selected_tools_row == 0;
            lines.push(
                vec![
                    selected_prefix(selected),
                    checkbox(self.xtreme_ui_enabled),
                    "Xtreme mode ".into(),
                    format!("({xtreme_mode_label})").dim(),
                ]
                .into(),
            );
        }

        // Row 1: toggle verbose tool output.
        {
            let selected = self.selected_tools_row == 1;
            lines.push(
                vec![
                    selected_prefix(selected),
                    checkbox(self.verbose_tool_output),
                    "Verbose tool output".into(),
                ]
                .into(),
            );
        }

        // Rows 2+: quick actions.
        let items = [
            "Review…",
            "Model…",
            "Approvals…",
            "Worktrees…",
            "Hooks…",
            "Transcript…",
            "Resume…",
        ];
        for (idx, label) in items.iter().enumerate() {
            let row = idx + 2;
            let selected = self.selected_tools_row == row;
            lines.push(vec![selected_prefix(selected), (*label).into()].into());
        }

        lines
    }

    fn selected_tool_hint_lines(&self) -> Vec<Line<'static>> {
        let hint = match self.selected_tools_row {
            0 => "Toggle xtreme UI styling (persists).",
            1 => "Toggle verbose tool output in the transcript (persists).",
            2 => "Review your changes and spot issues fast.",
            3 => "Pick a model and reasoning effort.",
            4 => "Review and adjust approval/sandbox presets.",
            5 => "Switch worktrees and manage shared dirs.",
            6 => "Automate xcodex with hooks.",
            7 => "Open the full transcript in a scrollable view.",
            8 => "Pick a previous session to continue.",
            _ => return Vec::new(),
        };

        vec![vec![hint.dim()].into()]
    }

    fn switch_tab(&mut self) {
        self.tab = match self.tab {
            StatusMenuTab::Status => StatusMenuTab::Settings,
            StatusMenuTab::Settings => StatusMenuTab::Tools,
            StatusMenuTab::Tools => StatusMenuTab::Status,
        };
        self.clamp_selected_row();
    }

    fn move_up(&mut self) {
        match self.tab {
            StatusMenuTab::Settings => {
                if self.selected_settings_row > 0 {
                    self.selected_settings_row = self.selected_settings_row.saturating_sub(1);
                }
            }
            StatusMenuTab::Tools => {
                let max = self.tools_row_count().saturating_sub(1);
                if self.selected_tools_row == 0 {
                    self.selected_tools_row = max;
                } else {
                    self.selected_tools_row = self.selected_tools_row.saturating_sub(1);
                }
            }
            StatusMenuTab::Status => {
                self.status_scroll_y = self.status_scroll_y.saturating_sub(1);
            }
        }
    }

    fn move_down(&mut self) {
        match self.tab {
            StatusMenuTab::Settings => {
                let max = self.settings_row_count().saturating_sub(1);
                self.selected_settings_row = (self.selected_settings_row + 1).min(max);
            }
            StatusMenuTab::Tools => {
                let max = self.tools_row_count().saturating_sub(1);
                if self.selected_tools_row >= max {
                    self.selected_tools_row = 0;
                } else {
                    self.selected_tools_row = (self.selected_tools_row + 1).min(max);
                }
            }
            StatusMenuTab::Status => {
                self.status_scroll_y = self.status_scroll_y.saturating_add(1);
            }
        }
    }

    fn toggle_selected(&mut self) {
        match self.tab {
            StatusMenuTab::Settings => match self.selected_settings_row {
                0 => {
                    self.status_bar_show_git_branch = !self.status_bar_show_git_branch;
                    self.app_event_tx.send(AppEvent::UpdateStatusBarGitOptions {
                        show_git_branch: self.status_bar_show_git_branch,
                        show_worktree: self.status_bar_show_worktree,
                    });
                    self.app_event_tx
                        .send(AppEvent::PersistStatusBarGitOptions {
                            show_git_branch: self.status_bar_show_git_branch,
                            show_worktree: self.status_bar_show_worktree,
                        });
                }
                1 => {
                    self.status_bar_show_worktree = !self.status_bar_show_worktree;
                    self.app_event_tx.send(AppEvent::UpdateStatusBarGitOptions {
                        show_git_branch: self.status_bar_show_git_branch,
                        show_worktree: self.status_bar_show_worktree,
                    });
                    self.app_event_tx
                        .send(AppEvent::PersistStatusBarGitOptions {
                            show_git_branch: self.status_bar_show_git_branch,
                            show_worktree: self.status_bar_show_worktree,
                        });
                }
                2 => {
                    self.verbose_tool_output = !self.verbose_tool_output;
                    self.app_event_tx
                        .send(AppEvent::UpdateVerboseToolOutput(self.verbose_tool_output));
                    self.app_event_tx
                        .send(AppEvent::PersistVerboseToolOutput(self.verbose_tool_output));
                }
                3 => {
                    self.radio_demo = match self.radio_demo {
                        RadioDemo::Alpha => RadioDemo::Beta,
                        RadioDemo::Beta => RadioDemo::Gamma,
                        RadioDemo::Gamma => RadioDemo::Alpha,
                    };
                }
                _ => {}
            },
            StatusMenuTab::Tools => {
                match self.selected_tools_row {
                    0 => {
                        self.xtreme_ui_enabled = !self.xtreme_ui_enabled;
                        self.xtreme_mode = if self.xtreme_ui_enabled {
                            XtremeMode::On
                        } else {
                            XtremeMode::Off
                        };
                        self.app_event_tx
                            .send(AppEvent::UpdateXtremeMode(self.xtreme_mode));
                        self.app_event_tx
                            .send(AppEvent::PersistXtremeMode(self.xtreme_mode));
                    }
                    1 => {
                        self.verbose_tool_output = !self.verbose_tool_output;
                        self.app_event_tx
                            .send(AppEvent::UpdateVerboseToolOutput(self.verbose_tool_output));
                        self.app_event_tx
                            .send(AppEvent::PersistVerboseToolOutput(self.verbose_tool_output));
                    }
                    2 => self.app_event_tx.send(AppEvent::DispatchSlashCommand(
                        crate::slash_command::SlashCommand::Review,
                    )),
                    3 => self.app_event_tx.send(AppEvent::DispatchSlashCommand(
                        crate::slash_command::SlashCommand::Model,
                    )),
                    4 => self.app_event_tx.send(AppEvent::OpenApprovalsPopup),
                    5 => self.app_event_tx.send(AppEvent::OpenWorktreeCommandMenu),
                    6 => self.app_event_tx.send(AppEvent::DispatchSlashCommand(
                        crate::slash_command::SlashCommand::Hooks,
                    )),
                    7 => self.app_event_tx.send(AppEvent::OpenTranscriptOverlay),
                    8 => self.app_event_tx.send(AppEvent::OpenResumePicker),
                    _ => {}
                }
                if self.selected_tools_row >= 2 {
                    self.complete = true;
                }
            }
            StatusMenuTab::Status => {}
        }
    }
}

impl BottomPaneView for StatusMenuView {
    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event {
            KeyEvent {
                code: KeyCode::Tab,
                modifiers: KeyModifiers::NONE,
                ..
            }
            | KeyEvent {
                code: KeyCode::Right,
                modifiers: KeyModifiers::NONE,
                ..
            }
            | KeyEvent {
                code: KeyCode::Left,
                modifiers: KeyModifiers::NONE,
                ..
            } => self.switch_tab(),
            KeyEvent {
                code: KeyCode::Up, ..
            }
            | KeyEvent {
                code: KeyCode::Char('k'),
                modifiers: KeyModifiers::NONE,
                ..
            } => self.move_up(),
            KeyEvent {
                code: KeyCode::Down,
                ..
            }
            | KeyEvent {
                code: KeyCode::Char('j'),
                modifiers: KeyModifiers::NONE,
                ..
            } => self.move_down(),
            KeyEvent {
                code: KeyCode::PageUp,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.status_scroll_y = self.status_scroll_y.saturating_sub(5);
            }
            KeyEvent {
                code: KeyCode::PageDown,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.status_scroll_y = self.status_scroll_y.saturating_add(5);
            }
            KeyEvent {
                code: KeyCode::Home,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.status_scroll_y = 0;
            }
            KeyEvent {
                code: KeyCode::End,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.status_scroll_y = u16::MAX;
            }
            KeyEvent {
                code: KeyCode::Enter,
                modifiers: KeyModifiers::NONE,
                ..
            }
            | KeyEvent {
                code: KeyCode::Char(' '),
                modifiers: KeyModifiers::NONE,
                ..
            } => self.toggle_selected(),
            _ => {}
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn on_ctrl_c(&mut self) -> CancellationEvent {
        self.complete = true;
        CancellationEvent::Handled
    }
}

impl Renderable for StatusMenuView {
    fn render(&self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let footer_hint = Self::footer_hint_line();
        let [content_area, footer_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);

        Block::default()
            .style(user_message_style())
            .render(content_area, buf);

        let inner_area = content_area.inset(Insets::vh(1, 2));
        let status_width = inner_area.width.saturating_sub(2);
        let header_lines = self.header_lines();
        let header_height = u16::try_from(header_lines.len())
            .unwrap_or(0)
            .min(inner_area.height);
        let [header_area, body_area] =
            Layout::vertical([Constraint::Length(header_height), Constraint::Fill(1)])
                .areas(inner_area);

        Paragraph::new(header_lines).render(header_area, buf);

        let body_lines = self.body_lines(status_width);
        let max_scroll = if body_area.height == 0 {
            0
        } else {
            let visible = usize::from(body_area.height);
            u16::try_from(body_lines.len().saturating_sub(visible)).unwrap_or(0)
        };
        let scroll_y = if matches!(self.tab, StatusMenuTab::Status) {
            self.status_scroll_y.min(max_scroll)
        } else {
            0
        };

        Paragraph::new(body_lines)
            .scroll((scroll_y, 0))
            .render(body_area, buf);

        let hint_area = Rect {
            x: footer_area.x + 2,
            y: footer_area.y,
            width: footer_area.width.saturating_sub(2),
            height: footer_area.height,
        };
        footer_hint.dim().render(hint_area, buf);
    }

    fn desired_height(&self, width: u16) -> u16 {
        let max_height = 22;

        // Minimum height to render everything without internal blank padding:
        // - 1 footer line
        // - content area inset by 1 row top + 1 row bottom
        // - inner area shows header + body
        let header_height = u16::try_from(self.header_lines().len()).unwrap_or(0);

        let status_width = width.saturating_sub(6).max(1);
        let body_height = u16::try_from(self.body_lines(status_width).len()).unwrap_or(0);
        let ideal_height = header_height.saturating_add(body_height).saturating_add(3);

        ideal_height.min(max_height).max(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_event::AppEvent;
    use insta::assert_snapshot;
    use ratatui::layout::Rect;
    use tokio::sync::mpsc::unbounded_channel;

    fn render_lines(view: &StatusMenuView, width: u16) -> String {
        let height = view.desired_height(width);
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        view.render(area, &mut buf);

        let lines: Vec<String> = (0..area.height)
            .map(|row| {
                let mut line = String::new();
                for col in 0..area.width {
                    let symbol = buf[(area.x + col, area.y + row)].symbol();
                    if symbol.is_empty() {
                        line.push(' ');
                    } else {
                        line.push_str(symbol);
                    }
                }
                line
            })
            .collect();
        lines.join("\n")
    }

    #[test]
    fn status_menu_renders_status_tab() {
        let (tx_raw, _rx) = unbounded_channel::<AppEvent>();
        let tx = AppEventSender::new(tx_raw);
        let status_cell = Box::new(crate::history_cell::new_info_event(
            "Status card".to_string(),
            None,
        ));
        let view = StatusMenuView::new(
            StatusMenuTab::Status,
            tx,
            status_cell,
            true,
            false,
            XtremeMode::On,
            false,
        );
        assert_snapshot!("status_menu_status_tab", render_lines(&view, 60));
    }

    #[test]
    fn status_menu_renders_settings_tab_with_radio_rows() {
        let (tx_raw, _rx) = unbounded_channel::<AppEvent>();
        let tx = AppEventSender::new(tx_raw);
        let status_cell = Box::new(crate::history_cell::new_info_event(
            "Status card".to_string(),
            None,
        ));
        let mut view = StatusMenuView::new(
            StatusMenuTab::Status,
            tx,
            status_cell,
            true,
            false,
            XtremeMode::On,
            false,
        );
        view.handle_key_event(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        view.handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        view.handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        view.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_snapshot!("status_menu_settings_tab", render_lines(&view, 60));
    }

    #[test]
    fn status_menu_renders_tools_tab() {
        let (tx_raw, _rx) = unbounded_channel::<AppEvent>();
        let tx = AppEventSender::new(tx_raw);
        let status_cell = Box::new(crate::history_cell::new_info_event(
            "Status card".to_string(),
            None,
        ));
        let view = StatusMenuView::new(
            StatusMenuTab::Tools,
            tx,
            status_cell,
            true,
            false,
            XtremeMode::On,
            false,
        );
        assert_snapshot!("status_menu_tools_tab", render_lines(&view, 60));
    }

    #[test]
    fn tools_tab_toggle_xtreme_mode_sends_update_and_persist() {
        let (tx_raw, mut rx) = unbounded_channel::<AppEvent>();
        let tx = AppEventSender::new(tx_raw);
        let status_cell = Box::new(crate::history_cell::new_info_event(
            "Status card".to_string(),
            None,
        ));
        let mut view = StatusMenuView::new(
            StatusMenuTab::Tools,
            tx,
            status_cell,
            true,
            false,
            XtremeMode::On,
            false,
        );

        view.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(matches!(
            rx.try_recv(),
            Ok(AppEvent::UpdateXtremeMode(XtremeMode::Off))
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(AppEvent::PersistXtremeMode(XtremeMode::Off))
        ));
        assert!(rx.try_recv().is_err());
    }
}
