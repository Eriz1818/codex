//! Apply Patch runtime: executes verified patches under the orchestrator.
//!
//! Assumes `apply_patch` verification/approval happened upstream. Reuses that
//! decision to avoid re-prompting, builds the self-invocation command for
//! `codex --codex-run-as-apply-patch`, and runs under the current
//! `SandboxAttempt` with a minimal environment.
use crate::CODEX_APPLY_PATCH_ARG1;
use crate::exec::ExecToolCallOutput;
use crate::exec::StreamOutput;
use crate::protocol::SandboxPolicy;
use crate::sandboxing::CommandSpec;
use crate::sandboxing::SandboxPermissions;
use crate::sandboxing::execute_env;
use crate::tools::sandboxing::Approvable;
use crate::tools::sandboxing::ApprovalCtx;
use crate::tools::sandboxing::SandboxAttempt;
use crate::tools::sandboxing::Sandboxable;
use crate::tools::sandboxing::SandboxablePreference;
use crate::tools::sandboxing::ToolCtx;
use crate::tools::sandboxing::ToolError;
use crate::tools::sandboxing::ToolRuntime;
use crate::tools::sandboxing::with_cached_approval;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::ReviewDecision;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct ApplyPatchRequest {
    pub patch: String,
    pub cwd: PathBuf,
    pub timeout_ms: Option<u64>,
    pub user_explicitly_approved: bool,
    pub codex_exe: Option<PathBuf>,
}

#[derive(Default)]
pub struct ApplyPatchRuntime;

#[derive(serde::Serialize, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct ApprovalKey {
    patch: String,
    cwd: PathBuf,
}

impl ApplyPatchRuntime {
    pub fn new() -> Self {
        Self
    }

    fn apply_patch_in_process(req: &ApplyPatchRequest) -> ExecToolCallOutput {
        let start = Instant::now();
        let parsed = match codex_apply_patch::parse_patch(&req.patch) {
            Ok(parsed) => parsed,
            Err(err) => {
                let message = format!("apply_patch parse failed: {err}\n");
                return Self::error_output(start.elapsed(), message);
            }
        };

        if parsed.hunks.is_empty() {
            return Self::error_output(start.elapsed(), "No files were modified.\n".to_string());
        }

        let mut added: Vec<PathBuf> = Vec::new();
        let mut modified: Vec<PathBuf> = Vec::new();
        let mut deleted: Vec<PathBuf> = Vec::new();

        for hunk in parsed.hunks {
            match hunk {
                codex_apply_patch::Hunk::AddFile { path, contents } => {
                    let abs = req.cwd.join(&path);
                    if let Some(parent) = abs.parent()
                        && !parent.as_os_str().is_empty()
                    {
                        if let Err(err) = std::fs::create_dir_all(parent) {
                            let display = path.display();
                            return Self::error_output(
                                start.elapsed(),
                                format!(
                                    "Failed to create parent directories for {display}: {err}\n"
                                ),
                            );
                        }
                    }
                    if let Err(err) = std::fs::write(&abs, contents) {
                        let display = path.display();
                        return Self::error_output(
                            start.elapsed(),
                            format!("Failed to write file {display}: {err}\n"),
                        );
                    }
                    added.push(path);
                }
                codex_apply_patch::Hunk::DeleteFile { path } => {
                    let abs = req.cwd.join(&path);
                    if let Err(err) = std::fs::remove_file(&abs) {
                        let display = path.display();
                        return Self::error_output(
                            start.elapsed(),
                            format!("Failed to delete file {display}: {err}\n"),
                        );
                    }
                    deleted.push(path);
                }
                codex_apply_patch::Hunk::UpdateFile {
                    path,
                    move_path,
                    chunks,
                } => {
                    let abs = req.cwd.join(&path);
                    let update = match codex_apply_patch::unified_diff_from_chunks(&abs, &chunks) {
                        Ok(update) => update,
                        Err(err) => {
                            let abs_display = abs.display().to_string();
                            let rel_display = path.display().to_string();
                            let message = err.to_string().replace(&abs_display, &rel_display);
                            return Self::error_output(start.elapsed(), format!("{message}\n"));
                        }
                    };
                    if let Some(dest) = move_path {
                        let abs_dest = req.cwd.join(&dest);
                        if let Some(parent) = abs_dest.parent()
                            && !parent.as_os_str().is_empty()
                        {
                            if let Err(err) = std::fs::create_dir_all(parent) {
                                let display = dest.display();
                                return Self::error_output(
                                    start.elapsed(),
                                    format!(
                                        "Failed to create parent directories for {display}: {err}\n"
                                    ),
                                );
                            }
                        }
                        if let Err(err) = std::fs::write(&abs_dest, update.content()) {
                            let display = dest.display();
                            return Self::error_output(
                                start.elapsed(),
                                format!("Failed to write file {display}: {err}\n"),
                            );
                        }
                        if let Err(err) = std::fs::remove_file(&abs) {
                            let display = path.display();
                            return Self::error_output(
                                start.elapsed(),
                                format!("Failed to remove original {display}: {err}\n"),
                            );
                        }
                        modified.push(dest);
                    } else {
                        if let Err(err) = std::fs::write(&abs, update.content()) {
                            let display = path.display();
                            return Self::error_output(
                                start.elapsed(),
                                format!("Failed to write file {display}: {err}\n"),
                            );
                        }
                        modified.push(path);
                    }
                }
            }
        }

        let mut stdout = String::new();
        stdout.push_str("Success. Updated the following files:\n");
        for path in &added {
            stdout.push_str(&format!("A {}\n", path.display()));
        }
        for path in &modified {
            stdout.push_str(&format!("M {}\n", path.display()));
        }
        for path in &deleted {
            stdout.push_str(&format!("D {}\n", path.display()));
        }

        ExecToolCallOutput {
            exit_code: 0,
            stdout: StreamOutput::new(stdout.clone()),
            stderr: StreamOutput::new(String::new()),
            aggregated_output: StreamOutput::new(stdout),
            duration: start.elapsed(),
            timed_out: false,
        }
    }

    fn error_output(duration: std::time::Duration, stderr: String) -> ExecToolCallOutput {
        ExecToolCallOutput {
            exit_code: 1,
            stdout: StreamOutput::new(String::new()),
            stderr: StreamOutput::new(stderr.clone()),
            aggregated_output: StreamOutput::new(stderr),
            duration,
            timed_out: false,
        }
    }

    fn build_command_spec(req: &ApplyPatchRequest) -> Result<CommandSpec, ToolError> {
        use std::env;
        let exe = if let Some(path) = &req.codex_exe {
            path.clone()
        } else {
            env::current_exe()
                .map_err(|e| ToolError::Rejected(format!("failed to determine codex exe: {e}")))?
        };
        let program = exe.to_string_lossy().to_string();
        Ok(CommandSpec {
            program,
            args: vec![CODEX_APPLY_PATCH_ARG1.to_string(), req.patch.clone()],
            cwd: req.cwd.clone(),
            expiration: req.timeout_ms.into(),
            // Run apply_patch with a minimal environment for determinism and to avoid leaks.
            env: HashMap::new(),
            sandbox_permissions: SandboxPermissions::UseDefault,
            justification: None,
        })
    }

    fn stdout_stream(ctx: &ToolCtx<'_>) -> Option<crate::exec::StdoutStream> {
        Some(crate::exec::StdoutStream {
            sub_id: ctx.turn.sub_id.clone(),
            call_id: ctx.call_id.clone(),
            tx_event: ctx.session.get_tx_event(),
        })
    }
}

impl Sandboxable for ApplyPatchRuntime {
    fn sandbox_preference(&self) -> SandboxablePreference {
        SandboxablePreference::Auto
    }
    fn escalate_on_failure(&self) -> bool {
        true
    }
}

impl Approvable<ApplyPatchRequest> for ApplyPatchRuntime {
    type ApprovalKey = ApprovalKey;

    fn approval_key(&self, req: &ApplyPatchRequest) -> Self::ApprovalKey {
        ApprovalKey {
            patch: req.patch.clone(),
            cwd: req.cwd.clone(),
        }
    }

    fn start_approval_async<'a>(
        &'a mut self,
        req: &'a ApplyPatchRequest,
        ctx: ApprovalCtx<'a>,
    ) -> BoxFuture<'a, ReviewDecision> {
        let key = self.approval_key(req);
        let session = ctx.session;
        let turn = ctx.turn;
        let call_id = ctx.call_id.to_string();
        let cwd = req.cwd.clone();
        let retry_reason = ctx.retry_reason.clone();
        let user_explicitly_approved = req.user_explicitly_approved;
        Box::pin(async move {
            with_cached_approval(&session.services, key, move || async move {
                if let Some(reason) = retry_reason {
                    session
                        .request_command_approval(
                            turn,
                            call_id,
                            vec!["apply_patch".to_string()],
                            cwd,
                            Some(reason),
                            None,
                        )
                        .await
                } else if user_explicitly_approved {
                    ReviewDecision::ApprovedForSession
                } else {
                    ReviewDecision::Approved
                }
            })
            .await
        })
    }

    fn wants_no_sandbox_approval(&self, policy: AskForApproval) -> bool {
        !matches!(policy, AskForApproval::Never)
    }
}

impl ToolRuntime<ApplyPatchRequest, ExecToolCallOutput> for ApplyPatchRuntime {
    async fn run(
        &mut self,
        req: &ApplyPatchRequest,
        attempt: &SandboxAttempt<'_>,
        ctx: &ToolCtx<'_>,
    ) -> Result<ExecToolCallOutput, ToolError> {
        if attempt.sandbox == crate::exec::SandboxType::None
            && matches!(attempt.policy, SandboxPolicy::DangerFullAccess)
        {
            return Ok(Self::apply_patch_in_process(req));
        }

        let spec = Self::build_command_spec(req)?;
        let env = attempt
            .env_for(spec)
            .map_err(|err| ToolError::Codex(err.into()))?;
        let out = execute_env(env, attempt.policy, Self::stdout_stream(ctx))
            .await
            .map_err(ToolError::Codex)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use pretty_assertions::assert_eq;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn apply_patch_in_process_rejects_empty_patch() {
        let dir = tempdir().expect("tempdir");
        let req = ApplyPatchRequest {
            patch: "*** Begin Patch\n*** End Patch".to_string(),
            cwd: dir.path().to_path_buf(),
            timeout_ms: None,
            user_explicitly_approved: true,
            codex_exe: None,
        };

        let out = ApplyPatchRuntime::apply_patch_in_process(&req);

        assert_eq!(out.exit_code, 1);
        assert_eq!(out.stdout.text, "");
        assert_eq!(out.stderr.text, "No files were modified.\n");
    }

    #[test]
    fn apply_patch_in_process_avoids_absolute_paths_in_errors() {
        let dir = tempdir().expect("tempdir");
        let req = ApplyPatchRequest {
            patch: "*** Begin Patch\n*** Update File: missing.txt\n@@\n-old\n+new\n*** End Patch"
                .to_string(),
            cwd: dir.path().to_path_buf(),
            timeout_ms: None,
            user_explicitly_approved: true,
            codex_exe: None,
        };

        let out = ApplyPatchRuntime::apply_patch_in_process(&req);

        assert_eq!(out.exit_code, 1);
        assert!(
            out.stderr.text.contains("missing.txt"),
            "expected missing file name in stderr, got {:?}",
            out.stderr.text
        );
        assert!(
            !out.stderr.text.contains(&dir.path().display().to_string()),
            "expected stderr to avoid absolute cwd, got {:?}",
            out.stderr.text
        );
    }

    #[test]
    fn apply_patch_in_process_updates_files_and_reports_summary() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("update.txt");
        fs::write(&path, "foo\nbar\n").expect("seed file");
        let req = ApplyPatchRequest {
            patch: "*** Begin Patch\n*** Update File: update.txt\n@@\n-bar\n+baz\n*** End Patch"
                .to_string(),
            cwd: dir.path().to_path_buf(),
            timeout_ms: None,
            user_explicitly_approved: true,
            codex_exe: None,
        };

        let out = ApplyPatchRuntime::apply_patch_in_process(&req);

        assert_eq!(out.exit_code, 0);
        assert_eq!(
            out.stdout.text,
            "Success. Updated the following files:\nM update.txt\n"
        );
        assert_eq!(
            fs::read_to_string(path).expect("read updated file"),
            "foo\nbaz\n"
        );
    }
}
