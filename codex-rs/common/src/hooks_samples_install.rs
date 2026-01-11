use std::io;
use std::path::Path;
use std::path::PathBuf;

use crate::hooks_sdk_install;
use crate::hooks_sdk_install::HookSdk;
use crate::hooks_sdk_install::PlannedInstallAction;
use crate::hooks_sdk_install::PlannedInstallFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookSample {
    External,
    PythonHost,
    Pyo3,
}

impl HookSample {
    pub fn id(self) -> &'static str {
        match self {
            HookSample::External => "external",
            HookSample::PythonHost => "python-host",
            HookSample::Pyo3 => "pyo3",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            HookSample::External => "External hooks (spawn per event)",
            HookSample::PythonHost => "Python Host hooks (long-lived)",
            HookSample::Pyo3 => "PyO3 hooks (in-proc; separate build)",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            HookSample::External => {
                "Runs one-shot external commands for lifecycle events (safe-ish, simplest)."
            }
            HookSample::PythonHost => {
                "Streams events to a long-lived host process (Python box) for stateful hooks."
            }
            HookSample::Pyo3 => {
                "Runs Python in-process via PyO3 (advanced; requires a separate build)."
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SampleInstallPlan {
    pub codex_home: PathBuf,
    pub hooks_dir: PathBuf,
    pub files: Vec<PlannedInstallFile>,
    pub config_snippet: String,
    pub notes: Vec<String>,
}

pub fn plan_install_samples(
    codex_home: &Path,
    sample: HookSample,
    force: bool,
) -> io::Result<SampleInstallPlan> {
    let hooks_dir = codex_home.join("hooks");

    let mut notes = Vec::new();
    let mut files = Vec::new();

    let python_sdk_plan = match sample {
        HookSample::External | HookSample::PythonHost | HookSample::Pyo3 => Some(
            hooks_sdk_install::plan_install_hook_sdks(codex_home, &[HookSdk::Python], force)?,
        ),
    };

    if let Some(plan) = python_sdk_plan {
        files.extend(plan.files);
    }

    match sample {
        HookSample::External => {
            notes.push(
                "These scripts use the installed Python helper `xcodex_hooks.py` to parse stdin/envelopes."
                    .to_string(),
            );

            files.extend(plan_sample_file(
                &hooks_dir,
                "log_all_jsonl.py",
                include_str!("hooks_samples_assets/python/log_all_jsonl.py"),
                true,
                force,
            )?);
            files.extend(plan_sample_file(
                &hooks_dir,
                "tool_call_summary.py",
                include_str!("hooks_samples_assets/python/tool_call_summary.py"),
                true,
                force,
            )?);
            files.extend(plan_sample_file(
                &hooks_dir,
                "approval_notify_macos_terminal_notifier.py",
                include_str!(
                    "hooks_samples_assets/python/approval_notify_macos_terminal_notifier.py"
                ),
                true,
                force,
            )?);
            files.extend(plan_sample_file(
                &hooks_dir,
                "notify_linux_notify_send.py",
                include_str!("hooks_samples_assets/python/notify_linux_notify_send.py"),
                true,
                force,
            )?);
            files.extend(plan_sample_file(
                &hooks_dir,
                "claude_compat_smoke.py",
                include_str!("hooks_samples_assets/python/claude_compat_smoke.py"),
                true,
                force,
            )?);
        }
        HookSample::PythonHost => {
            notes.push("This installs the reference Python host runner under `hooks/host/python/` and an example module (`example_hook.py`).".to_string());
        }
        HookSample::Pyo3 => {
            notes.push(
                "PyO3 hooks require a separately-built binary (not included in the default xcodex build)."
                    .to_string(),
            );
            notes.push(
                "After installing samples, run `xcodex hooks doctor pyo3` to confirm prerequisites and next steps."
                    .to_string(),
            );

            files.extend(plan_sample_file(
                &hooks_dir,
                "pyo3_hook.py",
                include_str!("hooks_samples_assets/python/pyo3_hook.py"),
                true,
                force,
            )?);
        }
    }

    let config_snippet = match sample {
        HookSample::External => format!(
            "[hooks.command]\ndefault_timeout_sec = 30\n\n[[hooks.command.agent_turn_complete]]\n  [[hooks.command.agent_turn_complete.hooks]]\n  argv = [\"python3\", \"{}\"]\n\n[[hooks.command.tool_call_finished]]\n  [[hooks.command.tool_call_finished.hooks]]\n  argv = [\"python3\", \"{}\"]\n\n# [[hooks.command.approval_requested]]\n# matcher = \"exec\" # also accepts Claude aliases like \"Bash\"\n#   [[hooks.command.approval_requested.hooks]]\n#   argv = [\"python3\", \"{}\"]\n\n# [[hooks.command.approval_requested]]\n# matcher = \"*\"\n#   [[hooks.command.approval_requested.hooks]]\n#   argv = [\"python3\", \"{}\"]\n\n# Claude-compat smoke (uses Claude alias keys, so `hook_event_name` matches Claude docs):\n# [[hooks.command.Stop]]\n#   [[hooks.command.Stop.hooks]]\n#   argv = [\"python3\", \"{}\"]\n#\n# [[hooks.command.PostToolUse]]\n# matcher = \"Write|Edit\"\n#   [[hooks.command.PostToolUse.hooks]]\n#   argv = [\"python3\", \"{}\"]\n",
            hooks_dir.join("log_all_jsonl.py").display(),
            hooks_dir.join("tool_call_summary.py").display(),
            hooks_dir
                .join("approval_notify_macos_terminal_notifier.py")
                .display(),
            hooks_dir.join("notify_linux_notify_send.py").display(),
            hooks_dir.join("claude_compat_smoke.py").display(),
            hooks_dir.join("claude_compat_smoke.py").display(),
        ),
        HookSample::PythonHost => String::from(
            "[hooks.host]\nenabled = true\ncommand = [\"python3\", \"-u\", \"hooks/host/python/host.py\", \"hooks/host/python/example_hook.py\"]\n",
        ),
        HookSample::Pyo3 => String::from(
            "[hooks]\nenable_unsafe_inproc = true\ninproc = [\"pyo3\"]\n\n[hooks.pyo3]\nscript_path = \"hooks/pyo3_hook.py\"\ncallable = \"on_event\"\n",
        ),
    };

    Ok(SampleInstallPlan {
        codex_home: codex_home.to_path_buf(),
        hooks_dir,
        files,
        config_snippet,
        notes,
    })
}

pub fn apply_install_samples(codex_home: &Path, sample: HookSample, force: bool) -> io::Result<()> {
    std::fs::create_dir_all(codex_home.join("hooks"))?;

    let required_sdks = match sample {
        HookSample::External | HookSample::PythonHost | HookSample::Pyo3 => vec![HookSdk::Python],
    };
    let _ = hooks_sdk_install::install_hook_sdks(codex_home, &required_sdks, force)?;

    let hooks_dir = codex_home.join("hooks");
    match sample {
        HookSample::External => {
            write_sample_file(
                &hooks_dir,
                "log_all_jsonl.py",
                include_str!("hooks_samples_assets/python/log_all_jsonl.py"),
                true,
                force,
            )?;
            write_sample_file(
                &hooks_dir,
                "tool_call_summary.py",
                include_str!("hooks_samples_assets/python/tool_call_summary.py"),
                true,
                force,
            )?;
            write_sample_file(
                &hooks_dir,
                "approval_notify_macos_terminal_notifier.py",
                include_str!(
                    "hooks_samples_assets/python/approval_notify_macos_terminal_notifier.py"
                ),
                true,
                force,
            )?;
            write_sample_file(
                &hooks_dir,
                "notify_linux_notify_send.py",
                include_str!("hooks_samples_assets/python/notify_linux_notify_send.py"),
                true,
                force,
            )?;
            write_sample_file(
                &hooks_dir,
                "claude_compat_smoke.py",
                include_str!("hooks_samples_assets/python/claude_compat_smoke.py"),
                true,
                force,
            )?;
        }
        HookSample::PythonHost => {}
        HookSample::Pyo3 => {
            write_sample_file(
                &hooks_dir,
                "pyo3_hook.py",
                include_str!("hooks_samples_assets/python/pyo3_hook.py"),
                true,
                force,
            )?;
        }
    }

    Ok(())
}

pub fn format_sample_install_plan(
    plan: &SampleInstallPlan,
    sample: HookSample,
) -> io::Result<String> {
    fn describe(action: PlannedInstallAction) -> &'static str {
        match action {
            PlannedInstallAction::Create => "create",
            PlannedInstallAction::Overwrite => "overwrite",
            PlannedInstallAction::SkipExisting => "skip (exists)",
        }
    }

    let mut out = String::new();
    out.push_str(&format!("Sample: {} ({})\n", sample.id(), sample.title()));
    out.push_str(&format!("CODEX_HOME: {}\n", plan.codex_home.display()));
    out.push_str(&format!("Hooks dir: {}\n", plan.hooks_dir.display()));
    out.push('\n');
    out.push_str("Planned changes:\n");
    for file in &plan.files {
        let exec = if file.executable { " (executable)" } else { "" };
        out.push_str(&format!(
            "- {}: {}{}\n",
            describe(file.action),
            file.path.display(),
            exec
        ));
    }
    if !plan.notes.is_empty() {
        out.push('\n');
        out.push_str("Notes:\n");
        for note in &plan.notes {
            out.push_str(&format!("- {note}\n"));
        }
    }
    out.push('\n');
    out.push_str("Config snippet to paste into CODEX_HOME/config.toml:\n");
    out.push_str(&plan.config_snippet);
    Ok(out)
}

fn plan_sample_file(
    hooks_dir: &Path,
    file_name: &str,
    _content: &'static str,
    executable: bool,
    force: bool,
) -> io::Result<Vec<PlannedInstallFile>> {
    let path = hooks_dir.join(file_name);
    let action = if path.exists() {
        if force {
            PlannedInstallAction::Overwrite
        } else {
            PlannedInstallAction::SkipExisting
        }
    } else {
        PlannedInstallAction::Create
    };
    Ok(vec![PlannedInstallFile {
        path,
        action,
        executable,
    }])
}

fn write_sample_file(
    hooks_dir: &Path,
    file_name: &str,
    content: &'static str,
    executable: bool,
    force: bool,
) -> io::Result<()> {
    let path = hooks_dir.join(file_name);
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, content)?;
    if executable {
        set_executable(&path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(path, perm)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}
