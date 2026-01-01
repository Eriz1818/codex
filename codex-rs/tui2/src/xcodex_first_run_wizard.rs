use crate::key_hint;
use crate::render::Insets;
use crate::render::renderable::ColumnRenderable;
use crate::render::renderable::Renderable;
use crate::render::renderable::RenderableExt as _;
use crate::selection_list::selection_option_row;
use crate::selection_list::selection_option_row_with_dim;
use crate::tui::FrameRequester;
use crate::tui::Tui;
use crate::tui::TuiEvent;
use codex_core::config::Config;
use codex_core::config::should_run_xcodex_first_run_wizard;
use codex_core::config::xcodex_first_run_wizard_marker_path;
use color_eyre::Result;
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::prelude::Widget;
use ratatui::style::Stylize as _;
use ratatui::text::Line;
use ratatui::widgets::Clear;
use ratatui::widgets::WidgetRef;
use std::path::Path;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use toml_edit::DocumentMut;
use toml_edit::Item;
use toml_edit::Table;

use crate::Cli;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WizardOutcome {
    Continue,
    ReloadConfig,
}

pub(crate) async fn run_xcodex_first_run_wizard_if_needed(
    tui: &mut Tui,
    cli: &Cli,
    config: &Config,
) -> Result<WizardOutcome> {
    let should_show =
        cli.force_setup_wizard || should_run_xcodex_first_run_wizard(&config.codex_home)?;
    if !should_show {
        return Ok(WizardOutcome::Continue);
    }

    let mut screen = XcodexFirstRunWizardScreen::new(
        tui.frame_requester(),
        &config.codex_home,
        cli.setup_dry_run,
    );

    tui.draw(u16::MAX, |frame| {
        frame.render_widget_ref(&screen, frame.area());
    })?;

    let events = tui.event_stream();
    tokio::pin!(events);
    while !screen.is_done() {
        if let Some(event) = events.next().await {
            screen.poll_apply_events();
            match event {
                TuiEvent::Key(key_event) => screen.handle_key(key_event),
                TuiEvent::Paste(pasted) => screen.handle_paste(pasted),
                TuiEvent::Mouse(_) => {}
                TuiEvent::Draw => {
                    tui.draw(u16::MAX, |frame| {
                        frame.render_widget_ref(&screen, frame.area());
                    })?;
                }
            }
        } else {
            break;
        }
    }

    tui.terminal.clear()?;
    Ok(screen.outcome())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Choose,
    Import,
    Review,
    ConfirmSensitive,
    Applying,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChooseSelection {
    StartFresh,
    CopyAllFromCodex,
    SelectFromCodex,
    Cancel,
    DontShowAgain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReviewSelection {
    Apply,
    Back,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupMode {
    StartFresh,
    CopyAll,
    SelectiveImport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportKind {
    File,
    Dir,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ImportItemId {
    ConfigToml,
    RulesDir,
    PromptsDir,
    SkillsDir,
    EnvFile,
    AuthJson,
    CredentialsJson,
    HistoryJsonl,
    SessionsDir,
    ArchivedSessionsDir,
    TmpDir,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ImportItemState {
    id: ImportItemId,
    label: String,
    kind: ImportKind,
    rel_path: PathBuf,
    is_sensitive: bool,
    restrict_permissions: bool,
    selected: bool,
}

impl ImportItemState {
    fn source_path(&self, source_home: &Path) -> PathBuf {
        source_home.join(&self.rel_path)
    }

    fn dest_path(&self, dest_home: &Path) -> PathBuf {
        dest_home.join(&self.rel_path)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PlanOp {
    CreateDir {
        path: PathBuf,
    },
    CopyFileIfMissing {
        src: PathBuf,
        dest: PathBuf,
        is_sensitive: bool,
        restrict_permissions: bool,
    },
    CopyDirMerge {
        src: PathBuf,
        dest: PathBuf,
        is_sensitive: bool,
        restrict_permissions: bool,
    },
    WriteFileIfMissing {
        path: PathBuf,
        contents: &'static str,
        is_sensitive: bool,
        restrict_permissions: bool,
    },
    WriteMarkerIfMissing {
        path: PathBuf,
    },
    MergeMcpServersAddMissing {
        src: PathBuf,
        dest: PathBuf,
    },
}

impl PlanOp {
    fn label(&self) -> String {
        match self {
            PlanOp::CreateDir { path } => format!("Create: {}/", path.display()),
            PlanOp::CopyFileIfMissing {
                src,
                dest,
                is_sensitive,
                ..
            } => {
                let mut s = format!("Copy: {} -> {} (if missing)", src.display(), dest.display());
                if *is_sensitive {
                    s.push_str(" (sensitive)");
                }
                s
            }
            PlanOp::CopyDirMerge {
                src,
                dest,
                is_sensitive,
                ..
            } => {
                let mut s = format!("Copy: {} -> {} (merge)", src.display(), dest.display());
                if *is_sensitive {
                    s.push_str(" (sensitive)");
                }
                s
            }
            PlanOp::WriteFileIfMissing { path, .. } => {
                format!("Write: {} (if missing)", path.display())
            }
            PlanOp::WriteMarkerIfMissing { path } => format!("Write: {} (marker)", path.display()),
            PlanOp::MergeMcpServersAddMissing { src, dest } => format!(
                "Merge: {} [mcp_servers] -> {} (add missing)",
                src.display(),
                dest.display()
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SetupPlan {
    mode: SetupMode,
    dest_home: PathBuf,
    ops: Vec<PlanOp>,
}

impl SetupPlan {
    fn planned_lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![Line::from(vec![
            "Home: ".dim(),
            self.dest_home.display().to_string().into(),
        ])];

        for op in &self.ops {
            lines.push(op.label().dim().into());
        }

        lines
    }
}

#[derive(Debug)]
enum ApplyEvent {
    Started(String),
    Skipped(String),
    Completed(String),
    Finished(std::io::Result<()>),
}

const DEFAULT_CONFIG_TOML_STUB: &str = "# Generated by xcodex first-run setup wizard.\n# Set CODEX_HOME to explicitly choose a shared home.\n";

fn default_upstream_codex_home_candidate() -> Option<PathBuf> {
    dirs::home_dir().map(|p| p.join(".codex"))
}

fn config_toml_path(codex_home: &Path) -> PathBuf {
    codex_home.join(codex_core::config::CONFIG_TOML_FILE)
}

fn marker_path(codex_home: &Path) -> PathBuf {
    xcodex_first_run_wizard_marker_path(codex_home)
}

fn write_marker_only(codex_home: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(codex_home)?;
    let marker = marker_path(codex_home);
    if !marker.exists() {
        std::fs::write(marker, "")?;
    }
    Ok(())
}

fn merge_mcp_servers_add_missing(src_path: &Path, dest_path: &Path) -> std::io::Result<usize> {
    let src = std::fs::read_to_string(src_path)?;
    let dest = std::fs::read_to_string(dest_path)?;
    let (merged, added) = merge_mcp_servers_add_missing_toml(&src, &dest)?;
    if added > 0 {
        std::fs::write(dest_path, merged)?;
    }
    Ok(added)
}

fn merge_mcp_servers_add_missing_toml(src: &str, dest: &str) -> std::io::Result<(String, usize)> {
    let src_doc = src.parse::<DocumentMut>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid TOML: {e}"),
        )
    })?;
    let mut dest_doc = dest.parse::<DocumentMut>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid TOML: {e}"),
        )
    })?;

    let Some(src_servers) = src_doc.get("mcp_servers").and_then(Item::as_table) else {
        return Ok((dest_doc.to_string(), 0));
    };

    let dest_servers_item = dest_doc
        .entry("mcp_servers")
        .or_insert(Item::Table(Table::new()));
    let Some(dest_servers) = dest_servers_item.as_table_mut() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "destination mcp_servers is not a table",
        ));
    };

    let mut added = 0usize;
    for (server_id, server_value) in src_servers.iter() {
        if dest_servers.contains_key(server_id) {
            continue;
        }
        dest_servers.insert(server_id, server_value.clone());
        added += 1;
    }

    Ok((dest_doc.to_string(), added))
}

fn apply_plan_with_progress(
    plan: SetupPlan,
    tx: mpsc::UnboundedSender<ApplyEvent>,
    request_frame: FrameRequester,
) {
    let send = |ev| {
        let _ = tx.send(ev);
        request_frame.schedule_frame();
    };

    let result = (|| -> std::io::Result<()> {
        for op in plan.ops {
            let label = op.label();
            send(ApplyEvent::Started(label.clone()));
            match op {
                PlanOp::CreateDir { path } => {
                    std::fs::create_dir_all(path)?;
                }
                PlanOp::CopyFileIfMissing {
                    src,
                    dest,
                    restrict_permissions,
                    ..
                } => {
                    if !src.exists() {
                        send(ApplyEvent::Skipped(format!("{label} (source missing)")));
                        continue;
                    }
                    if dest.exists() {
                        send(ApplyEvent::Skipped(format!("{label} (already exists)")));
                        continue;
                    }
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    copy_path(&src, &dest, restrict_permissions)?;
                }
                PlanOp::CopyDirMerge {
                    src,
                    dest,
                    restrict_permissions,
                    ..
                } => {
                    if !src.exists() {
                        send(ApplyEvent::Skipped(format!("{label} (source missing)")));
                        continue;
                    }
                    copy_dir_merge(&src, &dest, restrict_permissions)?;
                }
                PlanOp::WriteFileIfMissing {
                    path,
                    contents,
                    restrict_permissions,
                    ..
                } => {
                    if path.exists() {
                        send(ApplyEvent::Skipped(format!("{label} (already exists)")));
                        continue;
                    }
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&path, contents)?;
                    set_restrictive_permissions(&path, restrict_permissions)?;
                }
                PlanOp::WriteMarkerIfMissing { path } => {
                    if path.exists() {
                        send(ApplyEvent::Skipped(format!("{label} (already exists)")));
                        continue;
                    }
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&path, "")?;
                }
                PlanOp::MergeMcpServersAddMissing { src, dest } => {
                    if !src.exists() {
                        send(ApplyEvent::Skipped(format!("{label} (source missing)")));
                        continue;
                    }
                    if !dest.exists() {
                        send(ApplyEvent::Skipped(format!(
                            "{label} (destination missing)"
                        )));
                        continue;
                    }
                    let _added = merge_mcp_servers_add_missing(&src, &dest)?;
                }
            }

            send(ApplyEvent::Completed(label));
        }

        Ok(())
    })();

    send(ApplyEvent::Finished(result));
}

fn copy_dir_merge(src: &Path, dest: &Path, restrict_permissions: bool) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(src)?;
    if metadata.file_type().is_symlink() {
        copy_path(src, dest, restrict_permissions)?;
        return Ok(());
    }

    std::fs::create_dir_all(dest)?;
    set_restrictive_permissions(dest, restrict_permissions)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let dest_path = dest.join(entry.file_name());

        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            copy_dir_merge(&path, &dest_path, restrict_permissions)?;
            continue;
        }

        if dest_path.exists() {
            continue;
        }

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        copy_path(&path, &dest_path, restrict_permissions)?;
    }
    Ok(())
}

fn copy_path(src: &Path, dest: &Path, restrict_permissions: bool) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(src)?;
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(src)?;
        return create_symlink(&target, dest);
    }

    if metadata.is_dir() {
        copy_dir_merge(src, dest, restrict_permissions)?;
        return Ok(());
    }

    std::fs::copy(src, dest)?;
    set_restrictive_permissions(dest, restrict_permissions)?;
    Ok(())
}

fn set_restrictive_permissions(path: &Path, restrict_permissions: bool) -> std::io::Result<()> {
    if !restrict_permissions {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if path.is_dir() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        } else {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlinks are not supported on this platform",
    ))
}

struct XcodexFirstRunWizardScreen {
    request_frame: FrameRequester,
    dest_home: PathBuf,
    dry_run: bool,
    step: Step,
    choose_highlight: ChooseSelection,
    review_highlight: ReviewSelection,
    mode: SetupMode,
    import_highlight: usize,
    import_source_home: String,
    import_source_home_before_edit: String,
    import_source_home_is_editing: bool,
    import_items: Vec<ImportItemState>,
    plan: Option<SetupPlan>,
    apply_rx: Option<mpsc::UnboundedReceiver<ApplyEvent>>,
    apply_log: Vec<String>,
    error_message: Option<String>,
    outcome: Option<WizardOutcome>,
}

impl XcodexFirstRunWizardScreen {
    fn new(request_frame: FrameRequester, dest_home: &Path, dry_run: bool) -> Self {
        let upstream_home = default_upstream_codex_home_candidate();
        let import_source_home = upstream_home
            .as_ref()
            .filter(|p| p.exists())
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        Self {
            request_frame,
            dest_home: dest_home.to_path_buf(),
            dry_run,
            step: Step::Choose,
            choose_highlight: ChooseSelection::StartFresh,
            review_highlight: ReviewSelection::Apply,
            mode: SetupMode::StartFresh,
            import_highlight: 0,
            import_source_home_before_edit: import_source_home.clone(),
            import_source_home,
            import_source_home_is_editing: false,
            import_items: Vec::new(),
            plan: None,
            apply_rx: None,
            apply_log: Vec::new(),
            error_message: None,
            outcome: None,
        }
    }

    fn is_done(&self) -> bool {
        self.outcome.is_some()
    }

    fn outcome(&self) -> WizardOutcome {
        self.outcome.unwrap_or(WizardOutcome::Continue)
    }

    fn poll_apply_events(&mut self) {
        let Some(mut rx) = self.apply_rx.take() else {
            return;
        };

        let mut finished = false;
        while let Ok(ev) = rx.try_recv() {
            match ev {
                ApplyEvent::Started(label) => self.apply_log.push(format!("{label}…")),
                ApplyEvent::Skipped(label) => self.apply_log.push(format!("{label} (skipped)")),
                ApplyEvent::Completed(label) => self.apply_log.push(label),
                ApplyEvent::Finished(result) => {
                    match result {
                        Ok(()) => {
                            self.outcome = Some(WizardOutcome::ReloadConfig);
                        }
                        Err(err) => {
                            self.error_message = Some(err.to_string());
                            self.step = Step::Error;
                        }
                    }
                    finished = true;
                }
            }
        }

        if !finished {
            self.apply_rx = Some(rx);
        }
    }

    fn handle_paste(&mut self, pasted: String) {
        self.poll_apply_events();
        if self.import_source_home_is_editing {
            self.import_source_home.push_str(&pasted);
            self.request_frame.schedule_frame();
        }
    }

    fn handle_key(&mut self, key_event: KeyEvent) {
        if key_event.kind == KeyEventKind::Release {
            return;
        }

        self.poll_apply_events();

        if key_event.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key_event.code, KeyCode::Char('c') | KeyCode::Char('d'))
        {
            self.finish_cancel();
            self.request_frame.schedule_frame();
            return;
        }

        match self.step {
            Step::Choose => self.handle_choose_key(key_event.code),
            Step::Import => self.handle_import_key(key_event),
            Step::Review => self.handle_review_key(key_event.code),
            Step::ConfirmSensitive => self.handle_confirm_sensitive_key(key_event.code),
            Step::Applying => {}
            Step::Error => self.handle_error_key(key_event.code),
        }
    }

    fn handle_choose_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.set_choose_highlight(self.choose_prev()),
            KeyCode::Down | KeyCode::Char('j') => self.set_choose_highlight(self.choose_next()),
            KeyCode::Char('1') => self.enter_start_fresh_review(),
            KeyCode::Char('2') => self.enter_copy_all_from_codex(),
            KeyCode::Char('3') => self.enter_select_from_codex(),
            KeyCode::Char('4') => self.finish_cancel(),
            KeyCode::Char('5') => self.finish_dont_show_again(),
            KeyCode::Enter => match self.choose_highlight {
                ChooseSelection::StartFresh => self.enter_start_fresh_review(),
                ChooseSelection::CopyAllFromCodex => self.enter_copy_all_from_codex(),
                ChooseSelection::SelectFromCodex => self.enter_select_from_codex(),
                ChooseSelection::Cancel => self.finish_cancel(),
                ChooseSelection::DontShowAgain => self.finish_dont_show_again(),
            },
            KeyCode::Esc => self.finish_cancel(),
            _ => {}
        }
        self.request_frame.schedule_frame();
    }

    fn handle_import_key(&mut self, key_event: KeyEvent) {
        if self.import_source_home_is_editing {
            self.handle_import_source_edit_key(key_event);
            return;
        }

        match key_event.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.mode == SetupMode::SelectiveImport {
                    self.import_highlight = self.import_highlight.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.mode == SetupMode::SelectiveImport {
                    let max = self.import_items.len();
                    if max > 0 {
                        self.import_highlight = (self.import_highlight + 1).min(max - 1);
                    }
                }
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
                if self.mode == SetupMode::SelectiveImport {
                    self.toggle_import_row();
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                if self.mode == SetupMode::SelectiveImport {
                    self.select_all_import_items();
                }
            }
            KeyCode::Char('e') => self.start_edit_import_source_home(),
            KeyCode::Char('c') => self.enter_import_review(),
            KeyCode::Esc => self.step = Step::Choose,
            _ => {}
        }
        self.request_frame.schedule_frame();
    }

    fn handle_import_source_edit_key(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Enter => {
                self.import_source_home_is_editing = false;
                self.refresh_import_items_for_mode();
            }
            KeyCode::Esc => {
                self.import_source_home = self.import_source_home_before_edit.clone();
                self.import_source_home_is_editing = false;
                self.refresh_import_items_for_mode();
            }
            KeyCode::Backspace => {
                self.import_source_home.pop();
            }
            KeyCode::Char(c) => {
                if !key_event.modifiers.contains(KeyModifiers::CONTROL) {
                    self.import_source_home.push(c);
                }
            }
            _ => {}
        }
        self.request_frame.schedule_frame();
    }

    fn handle_review_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.set_review_highlight(self.review_prev()),
            KeyCode::Down | KeyCode::Char('j') => self.set_review_highlight(self.review_next()),
            KeyCode::Char('1') => self.apply_or_confirm(),
            KeyCode::Char('2') => self.step = self.back_step_for_review(),
            KeyCode::Enter => match self.review_highlight {
                ReviewSelection::Apply => self.apply_or_confirm(),
                ReviewSelection::Back => self.step = self.back_step_for_review(),
            },
            KeyCode::Esc => self.step = self.back_step_for_review(),
            _ => {}
        }
        self.request_frame.schedule_frame();
    }

    fn handle_confirm_sensitive_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => self.start_apply(),
            KeyCode::Esc => self.step = Step::Review,
            _ => {}
        }
        self.request_frame.schedule_frame();
    }

    fn handle_error_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter => self.step = Step::Review,
            KeyCode::Esc => self.finish_cancel(),
            _ => {}
        }
        self.request_frame.schedule_frame();
    }

    fn set_choose_highlight(&mut self, highlight: ChooseSelection) {
        self.choose_highlight = highlight;
    }

    fn choose_next(&self) -> ChooseSelection {
        match self.choose_highlight {
            ChooseSelection::StartFresh => ChooseSelection::CopyAllFromCodex,
            ChooseSelection::CopyAllFromCodex => ChooseSelection::SelectFromCodex,
            ChooseSelection::SelectFromCodex => ChooseSelection::Cancel,
            ChooseSelection::Cancel => ChooseSelection::DontShowAgain,
            ChooseSelection::DontShowAgain => ChooseSelection::StartFresh,
        }
    }

    fn choose_prev(&self) -> ChooseSelection {
        match self.choose_highlight {
            ChooseSelection::StartFresh => ChooseSelection::DontShowAgain,
            ChooseSelection::CopyAllFromCodex => ChooseSelection::StartFresh,
            ChooseSelection::SelectFromCodex => ChooseSelection::CopyAllFromCodex,
            ChooseSelection::Cancel => ChooseSelection::SelectFromCodex,
            ChooseSelection::DontShowAgain => ChooseSelection::Cancel,
        }
    }

    fn set_review_highlight(&mut self, highlight: ReviewSelection) {
        self.review_highlight = highlight;
    }

    fn review_next(&self) -> ReviewSelection {
        match self.review_highlight {
            ReviewSelection::Apply => ReviewSelection::Back,
            ReviewSelection::Back => ReviewSelection::Apply,
        }
    }

    fn review_prev(&self) -> ReviewSelection {
        match self.review_highlight {
            ReviewSelection::Apply => ReviewSelection::Back,
            ReviewSelection::Back => ReviewSelection::Apply,
        }
    }

    fn finish_cancel(&mut self) {
        self.outcome = Some(WizardOutcome::Continue);
    }

    fn finish_dont_show_again(&mut self) {
        if !self.dry_run
            && let Err(err) = write_marker_only(&self.dest_home)
        {
            self.error_message = Some(err.to_string());
            self.step = Step::Error;
            return;
        }
        self.outcome = Some(WizardOutcome::Continue);
    }

    fn enter_start_fresh_review(&mut self) {
        self.mode = SetupMode::StartFresh;
        self.plan = Some(build_start_fresh_plan(&self.dest_home));
        self.step = Step::Review;
    }

    fn enter_copy_all_from_codex(&mut self) {
        self.mode = SetupMode::CopyAll;
        self.refresh_import_items_for_mode();
        self.step = Step::Import;
    }

    fn enter_select_from_codex(&mut self) {
        self.mode = SetupMode::SelectiveImport;
        self.refresh_import_items_for_mode();
        self.step = Step::Import;
    }

    fn enter_import_review(&mut self) {
        if !self.source_home_exists() {
            return;
        }
        self.plan = Some(build_import_plan(
            self.mode,
            &self.dest_home,
            self.import_source_home.trim(),
            &self.import_items,
        ));
        self.step = Step::Review;
    }

    fn toggle_import_row(&mut self) {
        if let Some(item) = self.import_items.get_mut(self.import_highlight) {
            item.selected = !item.selected;
        }
    }

    fn select_all_import_items(&mut self) {
        for item in &mut self.import_items {
            item.selected = true;
        }
    }

    fn start_edit_import_source_home(&mut self) {
        self.import_source_home_before_edit = self.import_source_home.clone();
        self.import_source_home_is_editing = true;
    }

    fn source_home_path(&self) -> Option<PathBuf> {
        let source = self.import_source_home.trim();
        (!source.is_empty()).then(|| PathBuf::from(source))
    }

    fn source_home_exists(&self) -> bool {
        self.source_home_path()
            .as_ref()
            .is_some_and(|path| path.is_dir())
    }

    fn refresh_import_items_for_mode(&mut self) {
        let Some(source_home) = self.source_home_path() else {
            self.import_items.clear();
            self.import_highlight = 0;
            return;
        };

        if !source_home.is_dir() {
            self.import_items.clear();
            self.import_highlight = 0;
            return;
        }

        match scan_import_items(&source_home) {
            Ok(mut items) => {
                if self.mode == SetupMode::CopyAll {
                    for item in &mut items {
                        item.selected = true;
                    }
                }
                self.import_items = items;
                self.import_highlight = 0;
            }
            Err(err) => {
                tracing::debug!("failed to scan codex home for import: {err}");
                self.import_items.clear();
                self.import_highlight = 0;
            }
        }
    }

    fn back_step_for_review(&self) -> Step {
        match self.mode {
            SetupMode::StartFresh => Step::Choose,
            SetupMode::CopyAll | SetupMode::SelectiveImport => Step::Import,
        }
    }

    fn apply_or_confirm(&mut self) {
        if self.dry_run {
            self.outcome = Some(WizardOutcome::Continue);
            return;
        }

        if self.mode == SetupMode::CopyAll || has_selected_sensitive_items(&self.import_items) {
            self.step = Step::ConfirmSensitive;
            return;
        }

        self.start_apply();
    }

    fn start_apply(&mut self) {
        let Some(plan) = self.plan.clone() else {
            self.error_message = Some("No plan available".to_string());
            self.step = Step::Error;
            return;
        };

        let (tx, rx) = mpsc::unbounded_channel();
        self.apply_rx = Some(rx);
        self.apply_log.clear();
        self.step = Step::Applying;

        let request_frame = self.request_frame.clone();
        tokio::task::spawn_blocking(move || apply_plan_with_progress(plan, tx, request_frame));

        self.request_frame.schedule_frame();
    }
}

impl WidgetRef for &XcodexFirstRunWizardScreen {
    fn render_ref(&self, area: Rect, buf: &mut Buffer) {
        Clear.render(area, buf);
        let mut column = ColumnRenderable::new();

        column.push("");
        column.push(Line::from(vec![
            "  xcodex setup".bold(),
            " ".into(),
            "(first run)".dim(),
        ]));
        column.push("");

        match self.step {
            Step::Choose => {
                column.push(
                    Line::from(
                        "xcodex keeps its config/state separate by default so it can coexist with upstream codex."
                            .to_string(),
                    )
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
                column.push(
                    Line::from("MCP OAuth tokens are also isolated from upstream codex.".dim())
                        .inset(Insets::tlbr(0, 2, 0, 0)),
                );
                column.push(
                    Line::from("Some features differ from upstream; xcodex defaults to its own home directory.".dim())
                        .inset(Insets::tlbr(0, 2, 0, 0)),
                );
                column.push("");
                column.push(
                    Line::from(vec![
                        "Home: ".dim(),
                        self.dest_home.display().to_string().into(),
                    ])
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
                column.push("");

                column.push(selection_option_row(
                    0,
                    "Start from scratch (review changes)".to_string(),
                    self.choose_highlight == ChooseSelection::StartFresh,
                ));
                column.push(selection_option_row(
                    1,
                    "Copy all from existing codex home (includes sensitive data)".to_string(),
                    self.choose_highlight == ChooseSelection::CopyAllFromCodex,
                ));
                column.push(selection_option_row(
                    2,
                    "Select what you copy from existing codex home".to_string(),
                    self.choose_highlight == ChooseSelection::SelectFromCodex,
                ));
                column.push(selection_option_row(
                    3,
                    "Skip for now (continue; the wizard may appear again)".to_string(),
                    self.choose_highlight == ChooseSelection::Cancel,
                ));
                column.push(selection_option_row(
                    4,
                    "Don’t show again (continue; rerun with --force-setup-wizard)".to_string(),
                    self.choose_highlight == ChooseSelection::DontShowAgain,
                ));
                column.push("");
                column.push(
                    Line::from(vec![
                        "Press ".dim(),
                        key_hint::plain(KeyCode::Enter).into(),
                        " to continue".dim(),
                    ])
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
                if self.dry_run {
                    column.push(
                        Line::from(vec![
                            "Dry-run: ".dim(),
                            "no files will be written".cyan().dim(),
                        ])
                        .inset(Insets::tlbr(0, 2, 0, 0)),
                    );
                }
            }
            Step::Import => {
                let source_trimmed = self.import_source_home.trim();
                let source_path = self.source_home_path();
                let source_exists = source_path.as_ref().is_some_and(|p| p.is_dir());

                let heading = match self.mode {
                    SetupMode::CopyAll => "Copy all from upstream codex (includes sensitive data):",
                    SetupMode::SelectiveImport => {
                        "Import selected items from upstream codex (optional):"
                    }
                    SetupMode::StartFresh => "Import from upstream codex (optional):",
                };
                column.push(Line::from(heading.to_string()).inset(Insets::tlbr(0, 2, 0, 0)));
                column.push("");

                let edit_hint = if self.import_source_home_is_editing {
                    " (editing)".cyan().dim()
                } else {
                    " (press e to edit)".dim()
                };
                let src_display = if source_trimmed.is_empty() {
                    "<unset>".dim().to_string().into()
                } else {
                    self.import_source_home.clone().into()
                };
                let mut src_line = Line::from(vec!["Import from: ".dim(), src_display]);
                src_line.spans.push(edit_hint);
                column.push(src_line.inset(Insets::tlbr(0, 2, 0, 0)));

                if !source_trimmed.is_empty() && !source_exists {
                    column.push(
                        Line::from("Source directory not found; edit the path to continue.")
                            .dim()
                            .inset(Insets::tlbr(0, 2, 0, 0)),
                    );
                }
                column.push("");

                match self.mode {
                    SetupMode::CopyAll => {
                        column.push(
                            Line::from(
                                "Warning: this includes sensitive data (examples: .credentials.json, history.jsonl)."
                                    .red()
                                    .bold(),
                            )
                            .inset(Insets::tlbr(0, 2, 0, 0)),
                        );
                        column.push(
                            Line::from(
                                "Files are copied without overwriting existing ones. Review before applying."
                                    .dim(),
                            )
                            .inset(Insets::tlbr(0, 2, 0, 0)),
                        );
                    }
                    SetupMode::SelectiveImport => {
                        column.push(
                            Line::from(
                                "Select what to copy (Enter/Space toggles, a selects all):"
                                    .to_string(),
                            )
                            .inset(Insets::tlbr(0, 2, 0, 0)),
                        );
                        column.push("");

                        for (idx, item) in self.import_items.iter().enumerate() {
                            let marker = if item.selected { 'x' } else { ' ' };
                            let safety = match &item.id {
                                ImportItemId::Other(_) => "unclassified",
                                _ if item.is_sensitive => "sensitive",
                                _ => "safe",
                            };
                            let mut label = format!("[{marker}] {} ({safety})", item.label);
                            if let Some(src) = source_path.as_ref()
                                && !item.source_path(src).exists()
                            {
                                label.push_str(" (missing)");
                            }

                            let dim = source_path
                                .as_ref()
                                .is_some_and(|src| !item.source_path(src).exists());
                            column.push(selection_option_row_with_dim(
                                idx,
                                label,
                                self.import_highlight == idx,
                                dim,
                            ));
                        }
                    }
                    SetupMode::StartFresh => {}
                }

                column.push("");
                column.push(
                    Line::from(vec![
                        "Press ".dim(),
                        "c".cyan().dim(),
                        if source_exists {
                            " to continue (Review changes), ".dim()
                        } else {
                            " to continue (disabled; set a valid source first), ".dim()
                        },
                        key_hint::plain(KeyCode::Esc).into(),
                        " to go back".dim(),
                    ])
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
            }
            Step::Review => {
                column.push(
                    Line::from("Review planned changes:".to_string())
                        .inset(Insets::tlbr(0, 2, 0, 0)),
                );
                column.push("");

                let planned_lines = self
                    .plan
                    .as_ref()
                    .map(SetupPlan::planned_lines)
                    .unwrap_or_else(|| vec![Line::from("No plan available".red())]);
                for line in planned_lines {
                    column.push(line.inset(Insets::tlbr(0, 4, 0, 0)));
                }
                column.push("");

                let apply_label = if self.dry_run {
                    "Exit (dry-run)".to_string()
                } else {
                    "Apply".to_string()
                };
                column.push(selection_option_row(
                    0,
                    apply_label,
                    self.review_highlight == ReviewSelection::Apply,
                ));
                column.push(selection_option_row(
                    1,
                    "Back".to_string(),
                    self.review_highlight == ReviewSelection::Back,
                ));
                column.push("");
                column.push(
                    Line::from(vec![
                        "Press ".dim(),
                        key_hint::plain(KeyCode::Enter).into(),
                        " to select".dim(),
                    ])
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
            }
            Step::ConfirmSensitive => {
                let title = match self.mode {
                    SetupMode::CopyAll => "Copying sensitive data",
                    SetupMode::StartFresh | SetupMode::SelectiveImport => {
                        "Sensitive items selected"
                    }
                };
                column.push(Line::from(title.red().bold()).inset(Insets::tlbr(0, 2, 0, 0)));
                column.push("");

                match self.mode {
                    SetupMode::CopyAll => {
                        column.push(
                            Line::from(
                                "This copies everything from the selected codex home, including sensitive files."
                                    .to_string(),
                            )
                            .inset(Insets::tlbr(0, 2, 0, 0)),
                        );
                        column.push(
                            Line::from(
                                "Examples: .credentials.json, history.jsonl, auth.json, .env".dim(),
                            )
                            .inset(Insets::tlbr(0, 2, 0, 0)),
                        );
                    }
                    SetupMode::StartFresh | SetupMode::SelectiveImport => {
                        column.push(
                            Line::from(
                                "These files may contain credentials or private history. Review carefully before copying."
                                    .to_string(),
                            )
                            .inset(Insets::tlbr(0, 2, 0, 0)),
                        );
                        column.push("");
                        for item in self
                            .import_items
                            .iter()
                            .filter(|it| it.selected && it.is_sensitive)
                        {
                            column.push(
                                Line::from(vec!["- ".dim(), item.label.clone().into()])
                                    .inset(Insets::tlbr(0, 4, 0, 0)),
                            );
                        }
                    }
                }
                column.push("");
                column.push(
                    Line::from(vec![
                        "Press ".dim(),
                        "Y".cyan(),
                        " to apply, or ".dim(),
                        key_hint::plain(KeyCode::Esc).into(),
                        " to go back".dim(),
                    ])
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
            }
            Step::Applying => {
                column.push(
                    Line::from("Applying changes…".to_string()).inset(Insets::tlbr(0, 2, 0, 0)),
                );
                column.push("");

                let tail = self.apply_log.len().min(10);
                for line in self
                    .apply_log
                    .iter()
                    .skip(self.apply_log.len().saturating_sub(tail))
                {
                    column.push(Line::from(line.clone()).inset(Insets::tlbr(0, 4, 0, 0)));
                }

                column.push("");
                column.push(
                    Line::from(
                        "Files are copied without overwriting existing ones. This may take a moment."
                            .dim(),
                    )
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
            }
            Step::Error => {
                column
                    .push(Line::from("Setup failed".red().bold()).inset(Insets::tlbr(0, 2, 0, 0)));
                column.push("");
                if let Some(msg) = self.error_message.as_ref() {
                    column.push(Line::from(msg.clone()).inset(Insets::tlbr(0, 2, 0, 0)));
                }
                column.push("");
                column.push(
                    Line::from(vec![
                        "Press ".dim(),
                        key_hint::plain(KeyCode::Enter).into(),
                        " to go back, or ".dim(),
                        key_hint::plain(KeyCode::Esc).into(),
                        " to exit".dim(),
                    ])
                    .inset(Insets::tlbr(0, 2, 0, 0)),
                );
            }
        }

        column.render(area, buf);
    }
}

fn scan_import_items(source_home: &Path) -> std::io::Result<Vec<ImportItemState>> {
    let mut items = Vec::new();
    let mut included = std::collections::HashSet::<String>::new();

    let mut push_known = |id: ImportItemId,
                          label: &str,
                          kind: ImportKind,
                          rel_path: &str,
                          is_sensitive: bool,
                          restrict_permissions: bool,
                          selected: bool| {
        if source_home.join(rel_path).exists() {
            items.push(ImportItemState {
                id,
                label: label.to_string(),
                kind,
                rel_path: PathBuf::from(rel_path),
                is_sensitive,
                restrict_permissions,
                selected,
            });
            included.insert(rel_path.to_string());
        }
    };

    push_known(
        ImportItemId::ConfigToml,
        "config.toml",
        ImportKind::File,
        codex_core::config::CONFIG_TOML_FILE,
        false,
        false,
        true,
    );
    push_known(
        ImportItemId::RulesDir,
        "rules/",
        ImportKind::Dir,
        "rules",
        false,
        false,
        true,
    );
    push_known(
        ImportItemId::PromptsDir,
        "prompts/",
        ImportKind::Dir,
        "prompts",
        false,
        false,
        true,
    );
    push_known(
        ImportItemId::SkillsDir,
        "skills/",
        ImportKind::Dir,
        "skills",
        false,
        false,
        true,
    );

    push_known(
        ImportItemId::EnvFile,
        ".env",
        ImportKind::File,
        ".env",
        true,
        true,
        false,
    );
    push_known(
        ImportItemId::AuthJson,
        "auth.json",
        ImportKind::File,
        "auth.json",
        true,
        true,
        false,
    );
    push_known(
        ImportItemId::CredentialsJson,
        ".credentials.json",
        ImportKind::File,
        ".credentials.json",
        true,
        true,
        false,
    );
    push_known(
        ImportItemId::HistoryJsonl,
        "history.jsonl",
        ImportKind::File,
        "history.jsonl",
        true,
        true,
        false,
    );
    push_known(
        ImportItemId::SessionsDir,
        "sessions/",
        ImportKind::Dir,
        codex_core::SESSIONS_SUBDIR,
        true,
        true,
        false,
    );
    push_known(
        ImportItemId::ArchivedSessionsDir,
        "archived_sessions/",
        ImportKind::Dir,
        codex_core::ARCHIVED_SESSIONS_SUBDIR,
        true,
        true,
        false,
    );
    push_known(
        ImportItemId::TmpDir,
        "tmp/",
        ImportKind::Dir,
        "tmp",
        true,
        true,
        false,
    );

    let mut others = Vec::new();
    for entry in std::fs::read_dir(source_home)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy().to_string();
        if included.contains(&name) {
            continue;
        }

        let kind = std::fs::symlink_metadata(entry.path())
            .map(|meta| {
                if meta.is_dir() {
                    ImportKind::Dir
                } else {
                    ImportKind::File
                }
            })
            .unwrap_or(ImportKind::File);
        others.push((name, kind));
    }
    others.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (name, kind) in others {
        let label = match kind {
            ImportKind::Dir => format!("other: {name}/"),
            ImportKind::File => format!("other: {name}"),
        };
        items.push(ImportItemState {
            id: ImportItemId::Other(name.clone()),
            label,
            kind,
            rel_path: PathBuf::from(name),
            is_sensitive: true,
            restrict_permissions: false,
            selected: false,
        });
    }

    Ok(items)
}

fn build_start_fresh_plan(dest_home: &Path) -> SetupPlan {
    let ops = vec![
        PlanOp::CreateDir {
            path: dest_home.to_path_buf(),
        },
        PlanOp::WriteFileIfMissing {
            path: config_toml_path(dest_home),
            contents: DEFAULT_CONFIG_TOML_STUB,
            is_sensitive: false,
            restrict_permissions: false,
        },
        PlanOp::WriteMarkerIfMissing {
            path: marker_path(dest_home),
        },
    ];

    SetupPlan {
        mode: SetupMode::StartFresh,
        dest_home: dest_home.to_path_buf(),
        ops,
    }
}

fn build_import_plan(
    mode: SetupMode,
    dest_home: &Path,
    source_home: &str,
    items: &[ImportItemState],
) -> SetupPlan {
    let mut ops = Vec::new();
    ops.push(PlanOp::CreateDir {
        path: dest_home.to_path_buf(),
    });

    let source_home_str = source_home.trim();
    let source_home_path = (!source_home_str.is_empty()).then(|| PathBuf::from(source_home_str));
    if let Some(source_home_path) = source_home_path.as_ref() {
        for item in items.iter().filter(|it| it.selected) {
            let src = item.source_path(source_home_path);
            let dest = item.dest_path(dest_home);
            match item.kind {
                ImportKind::File => ops.push(PlanOp::CopyFileIfMissing {
                    src,
                    dest,
                    is_sensitive: item.is_sensitive,
                    restrict_permissions: item.restrict_permissions,
                }),
                ImportKind::Dir => ops.push(PlanOp::CopyDirMerge {
                    src,
                    dest,
                    is_sensitive: item.is_sensitive,
                    restrict_permissions: item.restrict_permissions,
                }),
            }
        }
    }

    if items.iter().any(|it| {
        it.selected && it.rel_path.as_path() == Path::new(codex_core::config::CONFIG_TOML_FILE)
    }) && !source_home_str.is_empty()
    {
        ops.push(PlanOp::MergeMcpServersAddMissing {
            src: PathBuf::from(source_home_str).join(codex_core::config::CONFIG_TOML_FILE),
            dest: config_toml_path(dest_home),
        });
    }

    ops.push(PlanOp::WriteFileIfMissing {
        path: config_toml_path(dest_home),
        contents: DEFAULT_CONFIG_TOML_STUB,
        is_sensitive: false,
        restrict_permissions: false,
    });
    ops.push(PlanOp::WriteMarkerIfMissing {
        path: marker_path(dest_home),
    });

    SetupPlan {
        mode,
        dest_home: dest_home.to_path_buf(),
        ops,
    }
}

fn has_selected_sensitive_items(items: &[ImportItemState]) -> bool {
    items.iter().any(|it| it.selected && it.is_sensitive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom_terminal::Terminal;
    use crate::test_backend::VT100Backend;
    use insta::assert_snapshot;
    use pretty_assertions::assert_eq;
    use ratatui::layout::Rect;

    fn render_snapshot(screen: &XcodexFirstRunWizardScreen) -> String {
        let width: u16 = 80;
        let height: u16 = 16;
        let backend = VT100Backend::new(width, height);
        let mut terminal = Terminal::with_options(backend).expect("terminal");
        terminal.set_viewport_area(Rect::new(0, 0, width, height));

        {
            let mut frame = terminal.get_frame();
            frame.render_widget_ref(screen, frame.area());
        }
        terminal.flush().expect("flush");
        terminal.backend().to_string()
    }

    #[test]
    fn first_run_wizard_choose_snapshot() {
        let screen = XcodexFirstRunWizardScreen::new(
            FrameRequester::test_dummy(),
            Path::new("XC_HOME_DOES_NOT_EXIST"),
            false,
        );
        assert_snapshot!("xcodex_first_run_wizard_choose", render_snapshot(&screen));
    }

    #[test]
    fn first_run_wizard_review_snapshot() {
        let mut screen = XcodexFirstRunWizardScreen::new(
            FrameRequester::test_dummy(),
            Path::new("XC_HOME_DOES_NOT_EXIST"),
            true,
        );
        screen.step = Step::Review;
        screen.plan = Some(build_start_fresh_plan(Path::new("XC_HOME_DOES_NOT_EXIST")));
        assert_snapshot!("xcodex_first_run_wizard_review", render_snapshot(&screen));
    }

    #[test]
    fn first_run_wizard_import_selective_snapshot() {
        let source = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(source.path().join("rules")).expect("rules dir");
        std::fs::create_dir_all(source.path().join("prompts")).expect("prompts dir");
        std::fs::create_dir_all(source.path().join("skills")).expect("skills dir");
        std::fs::write(source.path().join("config.toml"), "# config").expect("config.toml");

        let mut screen = XcodexFirstRunWizardScreen::new(
            FrameRequester::test_dummy(),
            Path::new("XC_HOME_DOES_NOT_EXIST"),
            true,
        );
        screen.mode = SetupMode::SelectiveImport;
        screen.step = Step::Import;
        screen.import_source_home = source.path().to_string_lossy().to_string();
        screen.refresh_import_items_for_mode();

        let snapshot =
            render_snapshot(&screen).replace(screen.import_source_home.trim(), "CODEX_HOME");
        assert_snapshot!("xcodex_first_run_wizard_import_selective", snapshot);
    }

    #[test]
    fn import_plan_defaults_are_safe_by_default() {
        let source = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(source.path().join("rules")).expect("rules dir");
        std::fs::create_dir_all(source.path().join("prompts")).expect("prompts dir");
        std::fs::create_dir_all(source.path().join("skills")).expect("skills dir");
        std::fs::create_dir_all(source.path().join("sessions")).expect("sessions dir");
        std::fs::create_dir_all(source.path().join("archived_sessions"))
            .expect("archived_sessions dir");
        std::fs::create_dir_all(source.path().join("tmp")).expect("tmp dir");

        std::fs::write(source.path().join("config.toml"), "# config").expect("config.toml");
        std::fs::write(source.path().join(".env"), "TOKEN=secret").expect(".env");
        std::fs::write(source.path().join("auth.json"), "{}").expect("auth.json");
        std::fs::write(source.path().join(".credentials.json"), "{}").expect(".credentials.json");
        std::fs::write(source.path().join("history.jsonl"), "").expect("history.jsonl");

        std::fs::create_dir_all(source.path().join("extra")).expect("extra dir");
        std::fs::write(source.path().join("notes.txt"), "hello").expect("notes.txt");

        let items = scan_import_items(source.path()).expect("scan import items");
        let selected: Vec<_> = items
            .iter()
            .filter(|it| it.selected)
            .map(|it| it.id.clone())
            .collect();
        assert_eq!(
            vec![
                ImportItemId::ConfigToml,
                ImportItemId::RulesDir,
                ImportItemId::PromptsDir,
                ImportItemId::SkillsDir,
            ],
            selected
        );
        assert_eq!(false, has_selected_sensitive_items(&items));
    }

    #[test]
    fn scan_import_items_includes_unclassified_entries_unselected() {
        let source = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(source.path().join("extra")).expect("extra dir");
        std::fs::write(source.path().join("notes.txt"), "hello").expect("notes.txt");

        let items = scan_import_items(source.path()).expect("scan import items");

        let extra = items
            .iter()
            .find(|item| item.id == ImportItemId::Other("extra".to_string()))
            .expect("extra item");
        assert_eq!(false, extra.selected);
        assert_eq!(false, extra.restrict_permissions);

        let notes = items
            .iter()
            .find(|item| item.id == ImportItemId::Other("notes.txt".to_string()))
            .expect("notes item");
        assert_eq!(false, notes.selected);
        assert_eq!(false, notes.restrict_permissions);
    }

    #[test]
    fn import_plan_copies_selected_unclassified_entries_without_restricting_permissions() {
        let source = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(source.path().join("extra")).expect("extra dir");
        std::fs::write(source.path().join("notes.txt"), "hello").expect("notes.txt");
        let dest = tempfile::tempdir().expect("tempdir");

        let mut items = scan_import_items(source.path()).expect("scan import items");
        for item in &mut items {
            if matches!(&item.id, ImportItemId::Other(name) if name == "extra" || name == "notes.txt")
            {
                item.selected = true;
            }
        }

        let plan = build_import_plan(
            SetupMode::SelectiveImport,
            dest.path(),
            source.path().to_string_lossy().as_ref(),
            &items,
        );

        let extra_src = source.path().join("extra");
        let extra_dest = dest.path().join("extra");
        assert_eq!(
            true,
            plan.ops.iter().any(|op| matches!(
                op,
                PlanOp::CopyDirMerge {
                    src,
                    dest,
                    is_sensitive: true,
                    restrict_permissions: false,
                } if src == &extra_src && dest == &extra_dest
            ))
        );

        let notes_src = source.path().join("notes.txt");
        let notes_dest = dest.path().join("notes.txt");
        assert_eq!(
            true,
            plan.ops.iter().any(|op| matches!(
                op,
                PlanOp::CopyFileIfMissing {
                    src,
                    dest,
                    is_sensitive: true,
                    restrict_permissions: false,
                } if src == &notes_src && dest == &notes_dest
            ))
        );
    }

    #[test]
    fn import_plan_includes_prompts_and_skills_by_default_when_present() {
        let source = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(source.path().join("prompts")).expect("prompts dir");
        std::fs::create_dir_all(source.path().join("skills")).expect("skills dir");
        std::fs::write(source.path().join("config.toml"), "# config").expect("config.toml");

        let dest = tempfile::tempdir().expect("tempdir");

        let items = scan_import_items(source.path()).expect("scan import items");
        let plan = build_import_plan(
            SetupMode::SelectiveImport,
            dest.path(),
            source.path().to_string_lossy().as_ref(),
            &items,
        );

        let prompts_src = source.path().join("prompts");
        let prompts_dest = dest.path().join("prompts");
        assert_eq!(
            true,
            plan.ops.iter().any(|op| matches!(
                op,
                PlanOp::CopyDirMerge { src, dest, .. } if src == &prompts_src && dest == &prompts_dest
            ))
        );

        let skills_src = source.path().join("skills");
        let skills_dest = dest.path().join("skills");
        assert_eq!(
            true,
            plan.ops.iter().any(|op| matches!(
                op,
                PlanOp::CopyDirMerge { src, dest, .. } if src == &skills_src && dest == &skills_dest
            ))
        );
    }

    #[test]
    fn merge_mcp_servers_adds_missing_only() {
        let src = r#"
[mcp_servers.foo]
command = "foo"

[mcp_servers.bar]
command = "bar"
"#;
        let dest = r#"
[mcp_servers.foo]
command = "existing"

[other]
value = 1
"#;

        let (merged, added) = merge_mcp_servers_add_missing_toml(src, dest).expect("merge");
        assert_eq!(1, added);

        let doc = merged.parse::<DocumentMut>().expect("parse merged");
        let servers = doc
            .get("mcp_servers")
            .and_then(Item::as_table)
            .expect("mcp_servers table");
        assert_eq!(true, servers.contains_key("foo"));
        assert_eq!(true, servers.contains_key("bar"));
    }
}
