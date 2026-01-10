use std::path::Path;
use std::path::PathBuf;

use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyModifiers;
use ratatui::buffer::Buffer;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::Block;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Widget;

use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use crate::history_cell::CompositeHistoryCell;
use crate::history_cell::PlainHistoryCell;
use crate::render::Insets;
use crate::render::RectExt as _;
use crate::render::renderable::ColumnRenderable;
use crate::render::renderable::Renderable;
use crate::style::user_message_style;

use super::CancellationEvent;
use super::bottom_pane_view::BottomPaneView;
use super::popup_consts::MAX_POPUP_ROWS;
use super::scroll_state::ScrollState;
use super::selection_popup_common::GenericDisplayRow;
use super::selection_popup_common::measure_rows_height;
use super::selection_popup_common::render_rows;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    SelectActions,
    Confirm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedAction {
    Link,
    Migrate,
    Replace,
    Skip,
}

impl PlannedAction {
    fn label(self) -> &'static str {
        match self {
            PlannedAction::Link => "link",
            PlannedAction::Migrate => "migrate+link",
            PlannedAction::Replace => "replace+link",
            PlannedAction::Skip => "skip",
        }
    }

    fn next(self) -> Self {
        match self {
            PlannedAction::Link => PlannedAction::Migrate,
            PlannedAction::Migrate => PlannedAction::Replace,
            PlannedAction::Replace => PlannedAction::Skip,
            PlannedAction::Skip => PlannedAction::Link,
        }
    }
}

#[derive(Clone, Debug)]
struct SharedDirPlan {
    dir: String,
    action: PlannedAction,
}

pub(crate) struct WorktreeLinkSharedWizardView {
    worktree_root: PathBuf,
    workspace_root: PathBuf,
    invoked_from: String,
    show_notice: bool,
    ignore_shared_dirs_in_git: bool,
    step: Step,
    complete: bool,
    state: ScrollState,
    plans: Vec<SharedDirPlan>,
    app_event_tx: AppEventSender,
}

impl WorktreeLinkSharedWizardView {
    pub(crate) fn new(
        worktree_root: PathBuf,
        workspace_root: PathBuf,
        shared_dirs: Vec<String>,
        prefer_migrate: bool,
        show_notice: bool,
        invoked_from: String,
        app_event_tx: AppEventSender,
    ) -> Self {
        let plans = shared_dirs
            .into_iter()
            .map(|dir| {
                let action = if prefer_migrate {
                    PlannedAction::Migrate
                } else {
                    default_action_for_dir(&worktree_root, dir.as_str())
                };
                SharedDirPlan { dir, action }
            })
            .collect();

        let mut view = Self {
            worktree_root,
            workspace_root,
            invoked_from,
            show_notice,
            ignore_shared_dirs_in_git: true,
            step: Step::SelectActions,
            complete: false,
            state: ScrollState::new(),
            plans,
            app_event_tx,
        };
        view.state.selected_idx = (!view.plans.is_empty()).then_some(0);
        view
    }

    fn header(&self) -> ColumnRenderable<'_> {
        let mut header = ColumnRenderable::new();
        header.push(Line::from("Worktree link-shared".bold()));
        header.push(Line::from(vec![
            "Workspace root: ".dim(),
            self.workspace_root.display().to_string().into(),
        ]));
        header.push(Line::from(vec![
            "Active worktree: ".dim(),
            self.worktree_root.display().to_string().into(),
        ]));
        header
    }

    fn visible_len(&self) -> usize {
        self.plans.len()
    }

    fn move_up(&mut self) {
        let len = self.visible_len();
        if len == 0 {
            return;
        }
        self.state.move_up_wrap(len);
        self.state.ensure_visible(len, MAX_POPUP_ROWS.min(len));
    }

    fn move_down(&mut self) {
        let len = self.visible_len();
        if len == 0 {
            return;
        }
        self.state.move_down_wrap(len);
        self.state.ensure_visible(len, MAX_POPUP_ROWS.min(len));
    }

    fn cycle_selected_action(&mut self) {
        let Some(idx) = self.state.selected_idx else {
            return;
        };
        if let Some(plan) = self.plans.get_mut(idx) {
            plan.action = plan.action.next();
        }
    }

    fn go_back(&mut self) {
        match self.step {
            Step::SelectActions => self.complete = true,
            Step::Confirm => self.step = Step::SelectActions,
        }
    }

    fn toggle_ignore_shared_dirs_in_git(&mut self) {
        self.ignore_shared_dirs_in_git = !self.ignore_shared_dirs_in_git;
    }

    fn apply(&mut self) {
        let worktree_root = self.worktree_root.clone();
        let workspace_root = self.workspace_root.clone();
        let invoked_from = self.invoked_from.clone();
        let show_notice = self.show_notice;
        let ignore_shared_dirs_in_git = self.ignore_shared_dirs_in_git;
        let plans = self.plans.clone();
        let tx = self.app_event_tx.clone();

        tokio::spawn(async move {
            let mut lines: Vec<Line<'static>> = Vec::new();
            let mut had_skips_or_failures = false;
            lines.push(Line::from(vec![
                "workspace root: ".dim(),
                workspace_root.display().to_string().into(),
            ]));
            lines.push(Line::from(vec![
                "active worktree: ".dim(),
                worktree_root.display().to_string().into(),
            ]));
            lines.push(Line::from(""));

            if ignore_shared_dirs_in_git {
                let dirs_to_ignore: Vec<String> = plans
                    .iter()
                    .filter(|plan| plan.action != PlannedAction::Skip)
                    .map(|plan| plan.dir.clone())
                    .collect();
                if !dirs_to_ignore.is_empty() {
                    match codex_core::git_info::maybe_add_shared_dirs_to_git_info_exclude(
                        &workspace_root,
                        &dirs_to_ignore,
                    ) {
                        Ok(update) => {
                            if !update.added.is_empty() {
                                lines.push(Line::from(vec![
                                    "Updated ".dim(),
                                    update.path.display().to_string().cyan(),
                                    " to ignore shared dirs.".dim(),
                                ]));
                                lines.push(Line::from(""));
                            }
                        }
                        Err(err) => {
                            lines.push(Line::from(vec![
                                "Warning: ".dim(),
                                format!("failed to update .git/info/exclude: {err}").dim(),
                            ]));
                            lines.push(Line::from(""));
                        }
                    }
                }
            }

            for plan in plans {
                if plan.action == PlannedAction::Skip {
                    had_skips_or_failures = true;
                    lines.push(Line::from(format!("- {}: skipped (by user)", plan.dir)));
                    continue;
                }

                let mode = match plan.action {
                    PlannedAction::Link => codex_core::git_info::SharedDirLinkMode::LinkOnly,
                    PlannedAction::Migrate => codex_core::git_info::SharedDirLinkMode::Migrate {
                        include_ignored: true,
                    },
                    PlannedAction::Replace => codex_core::git_info::SharedDirLinkMode::Replace,
                    PlannedAction::Skip => unreachable!(),
                };

                let action = codex_core::git_info::link_worktree_shared_dir(
                    &worktree_root,
                    &workspace_root,
                    &plan.dir,
                    mode,
                )
                .await;

                match action.outcome {
                    codex_core::git_info::SharedDirLinkOutcome::Linked => {
                        lines.push(Line::from(format!(
                            "- {}: linked -> {}",
                            action.shared_dir,
                            action.target_path.display()
                        )));
                    }
                    codex_core::git_info::SharedDirLinkOutcome::AlreadyLinked => {
                        lines.push(Line::from(format!(
                            "- {}: already linked -> {}",
                            action.shared_dir,
                            action.target_path.display()
                        )));
                    }
                    codex_core::git_info::SharedDirLinkOutcome::Skipped(reason) => {
                        had_skips_or_failures = true;
                        lines.push(Line::from(format!(
                            "- {}: skipped ({reason})",
                            action.shared_dir
                        )));
                    }
                    codex_core::git_info::SharedDirLinkOutcome::Failed(reason) => {
                        had_skips_or_failures = true;
                        lines.push(Line::from(format!(
                            "- {}: failed ({reason})",
                            action.shared_dir
                        )));
                    }
                }
            }

            if had_skips_or_failures {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    "Tip: ".dim(),
                    "run `/worktree doctor` for details.".cyan(),
                ]));
            }

            if show_notice {
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Note: shared dirs are linked into the workspace root; writes under them persist across worktrees.",
                ));
            }

            let command = PlainHistoryCell::new(vec![Line::from(vec![invoked_from.magenta()])]);
            let output = PlainHistoryCell::new(lines);
            tx.send(AppEvent::InsertHistoryCell(Box::new(
                CompositeHistoryCell::new(vec![Box::new(command), Box::new(output)]),
            )));
        });

        self.complete = true;
    }

    fn build_rows(&self) -> Vec<GenericDisplayRow> {
        let selected_idx = self.state.selected_idx;
        self.plans
            .iter()
            .enumerate()
            .map(|(idx, plan)| {
                let prefix = if selected_idx == Some(idx) {
                    '›'
                } else {
                    ' '
                };
                let name = format!("{prefix} [{}] {}", plan.action.label(), plan.dir);
                let description = Some(String::from("Enter to cycle action; Esc to cancel/back"));
                GenericDisplayRow {
                    name,
                    description,
                    ..Default::default()
                }
            })
            .collect()
    }
}

fn default_action_for_dir(worktree_root: &Path, shared_dir: &str) -> PlannedAction {
    let path = worktree_root.join(shared_dir);
    let Ok(md) = std::fs::symlink_metadata(&path) else {
        return PlannedAction::Link;
    };
    if md.file_type().is_symlink() {
        return PlannedAction::Link;
    }
    if md.is_dir() {
        let Ok(mut entries) = std::fs::read_dir(&path) else {
            return PlannedAction::Skip;
        };
        return if entries.next().is_some() {
            PlannedAction::Migrate
        } else {
            PlannedAction::Link
        };
    }
    PlannedAction::Skip
}

impl BottomPaneView for WorktreeLinkSharedWizardView {
    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match self.step {
            Step::SelectActions => match key_event {
                KeyEvent {
                    code: KeyCode::Esc, ..
                } => self.go_back(),
                KeyEvent {
                    code: KeyCode::Up, ..
                } => self.move_up(),
                KeyEvent {
                    code: KeyCode::Down,
                    ..
                } => self.move_down(),
                KeyEvent {
                    code: KeyCode::Enter,
                    modifiers: KeyModifiers::NONE,
                    ..
                } => self.cycle_selected_action(),
                KeyEvent {
                    code: KeyCode::Tab, ..
                } => self.step = Step::Confirm,
                _ => {}
            },
            Step::Confirm => match key_event {
                KeyEvent {
                    code: KeyCode::Esc, ..
                } => self.go_back(),
                KeyEvent {
                    code: KeyCode::Char('i') | KeyCode::Char('I'),
                    modifiers: KeyModifiers::NONE,
                    ..
                } => self.toggle_ignore_shared_dirs_in_git(),
                KeyEvent {
                    code: KeyCode::Enter,
                    modifiers: KeyModifiers::NONE,
                    ..
                } => self.apply(),
                _ => {}
            },
        }
    }

    fn on_ctrl_c(&mut self) -> CancellationEvent {
        self.complete = true;
        CancellationEvent::Handled
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

impl Renderable for WorktreeLinkSharedWizardView {
    fn desired_height(&self, width: u16) -> u16 {
        let content_width = width.saturating_sub(4);
        let header_height = self.header().desired_height(content_width);
        let rows = self.build_rows();
        let rows_height = measure_rows_height(&rows, &self.state, MAX_POPUP_ROWS, content_width);
        header_height
            .saturating_add(rows_height)
            .saturating_add(4)
            .min(24)
    }

    fn render(&self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let [content_area, footer_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);

        Block::default()
            .style(user_message_style())
            .render(content_area, buf);

        let inner = content_area.inset(Insets::vh(1, 2));
        let header = self.header();
        let header_height = header.desired_height(inner.width);
        let [header_area, body_area] =
            Layout::vertical([Constraint::Length(header_height), Constraint::Fill(1)]).areas(inner);
        header.render(header_area, buf);

        match self.step {
            Step::SelectActions => {
                let rows = self.build_rows();
                let render_area = body_area.inset(Insets::vh(0, 0));
                render_rows(
                    render_area,
                    buf,
                    &rows,
                    &self.state,
                    MAX_POPUP_ROWS,
                    "  No shared dirs configured",
                );
                Paragraph::new(Line::from(vec![
                    "Tab".cyan(),
                    " = Review, ".dim(),
                    "Enter".cyan(),
                    " = Cycle action, ".dim(),
                    "Esc".cyan(),
                    " = Cancel".dim(),
                ]))
                .render(
                    Rect {
                        x: footer_area.x + 2,
                        y: footer_area.y,
                        width: footer_area.width.saturating_sub(2),
                        height: 1,
                    },
                    buf,
                );
                return;
            }
            Step::Confirm => {
                let mut lines: Vec<Line<'static>> = Vec::new();
                lines.push(Line::from("Planned actions:".bold()));
                for plan in &self.plans {
                    lines.push(Line::from(format!(
                        "- [{}] {}",
                        plan.action.label(),
                        plan.dir
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from("Options:".bold()));
                lines.push(Line::from(vec![
                    if self.ignore_shared_dirs_in_git {
                        "[x] ".green()
                    } else {
                        "[ ] ".dim()
                    },
                    "Add shared dirs to ".into(),
                    ".git/info/exclude".cyan(),
                    " (recommended)".dim(),
                ]));
                lines.push(Line::from(vec![
                    "    ".into(),
                    "Why: shared dirs are scratch space; ignoring them keeps ".dim(),
                    "git status".cyan(),
                    " clean across worktrees.".dim(),
                ]));
                Paragraph::new(lines).render(body_area, buf);
            }
        }

        Paragraph::new(Line::from(vec![
            "Enter".cyan(),
            " = Apply, ".dim(),
            "I".cyan(),
            " = Toggle ignore, ".dim(),
            "Esc".cyan(),
            " = Back".dim(),
        ]))
        .render(
            Rect {
                x: footer_area.x + 2,
                y: footer_area.y,
                width: footer_area.width.saturating_sub(2),
                height: 1,
            },
            buf,
        );
    }
}
