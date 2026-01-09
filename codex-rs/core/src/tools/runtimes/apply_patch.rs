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
use crate::tools::sandboxing::ExecApprovalRequirement;
use crate::tools::sandboxing::SandboxAttempt;
use crate::tools::sandboxing::Sandboxable;
use crate::tools::sandboxing::SandboxablePreference;
use crate::tools::sandboxing::ToolCtx;
use crate::tools::sandboxing::ToolError;
use crate::tools::sandboxing::ToolRuntime;
use crate::tools::sandboxing::with_cached_approval;
use codex_apply_patch::ApplyPatchAction;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::FileChange;
use codex_protocol::protocol::ReviewDecision;
use codex_utils_absolute_path::AbsolutePathBuf;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug)]
pub struct ApplyPatchRequest {
    pub action: ApplyPatchAction,
    pub file_paths: Vec<AbsolutePathBuf>,
    pub changes: std::collections::HashMap<PathBuf, FileChange>,
    pub exec_approval_requirement: ExecApprovalRequirement,
    pub timeout_ms: Option<u64>,
    pub codex_exe: Option<PathBuf>,
}

#[derive(Default)]
pub struct ApplyPatchRuntime;

impl ApplyPatchRuntime {
    pub fn new() -> Self {
        Self
    }

    fn apply_patch_in_process(req: &ApplyPatchRequest) -> ExecToolCallOutput {
        let start = Instant::now();
        let parsed = match codex_apply_patch::parse_patch(&req.action.patch) {
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
                    let abs = req.action.cwd.join(&path);
                    if let Some(parent) = abs.parent()
                        && !parent.as_os_str().is_empty()
                        && let Err(err) = std::fs::create_dir_all(parent)
                    {
                        let display = path.display();
                        return Self::error_output(
                            start.elapsed(),
                            format!("Failed to create parent directories for {display}: {err}\n"),
                        );
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
                    let abs = req.action.cwd.join(&path);
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
                    let abs = req.action.cwd.join(&path);
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
                        let abs_dest = req.action.cwd.join(&dest);
                        if let Some(parent) = abs_dest.parent()
                            && !parent.as_os_str().is_empty()
                            && let Err(err) = std::fs::create_dir_all(parent)
                        {
                            let display = dest.display();
                            return Self::error_output(
                                start.elapsed(),
                                format!(
                                    "Failed to create parent directories for {display}: {err}\n"
                                ),
                            );
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
            args: vec![CODEX_APPLY_PATCH_ARG1.to_string(), req.action.patch.clone()],
            cwd: req.action.cwd.clone(),
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
    type ApprovalKey = AbsolutePathBuf;

    fn approval_keys(&self, req: &ApplyPatchRequest) -> Vec<Self::ApprovalKey> {
        req.file_paths.clone()
    }

    fn start_approval_async<'a>(
        &'a mut self,
        req: &'a ApplyPatchRequest,
        ctx: ApprovalCtx<'a>,
    ) -> BoxFuture<'a, ReviewDecision> {
        let session = ctx.session;
        let turn = ctx.turn;
        let call_id = ctx.call_id.to_string();
        let retry_reason = ctx.retry_reason.clone();
        let approval_keys = self.approval_keys(req);
        let changes = req.changes.clone();
        Box::pin(async move {
            if let Some(reason) = retry_reason {
                let rx_approve = session
                    .request_patch_approval(turn, call_id, changes.clone(), Some(reason), None)
                    .await;
                return rx_approve.await.unwrap_or_default();
            }

            with_cached_approval(&session.services, approval_keys, || async move {
                let rx_approve = session
                    .request_patch_approval(turn, call_id, changes, None, None)
                    .await;
                rx_approve.await.unwrap_or_default()
            })
            .await
        })
    }

    fn wants_no_sandbox_approval(&self, policy: AskForApproval) -> bool {
        !matches!(policy, AskForApproval::Never)
    }

    // apply_patch approvals are decided upstream by assess_patch_safety.
    //
    // This override ensures the orchestrator runs the patch approval flow when required instead
    // of falling back to the global exec approval policy.
    fn exec_approval_requirement(
        &self,
        req: &ApplyPatchRequest,
    ) -> Option<ExecApprovalRequirement> {
        Some(req.exec_approval_requirement.clone())
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
    use codex_apply_patch::MaybeApplyPatchVerified;
    use pretty_assertions::assert_eq;
    use std::fs;
    use tempfile::tempdir;

    fn make_test_request(dir: &tempfile::TempDir, patch: &str) -> ApplyPatchRequest {
        let argv = vec!["apply_patch".to_string(), patch.to_string()];
        let action = match codex_apply_patch::maybe_parse_apply_patch_verified(&argv, dir.path()) {
            MaybeApplyPatchVerified::Body(action) => action,
            other => panic!("expected Body apply_patch action, got {other:?}"),
        };

        ApplyPatchRequest {
            action,
            file_paths: Vec::new(),
            changes: HashMap::new(),
            exec_approval_requirement: ExecApprovalRequirement::Skip {
                bypass_sandbox: false,
                proposed_execpolicy_amendment: None,
            },
            timeout_ms: None,
            codex_exe: None,
        }
    }

    #[test]
    fn apply_patch_in_process_rejects_empty_patch() {
        let dir = tempdir().expect("tempdir");
        let req = make_test_request(&dir, "*** Begin Patch\n*** End Patch");

        let out = ApplyPatchRuntime::apply_patch_in_process(&req);

        assert_eq!(out.exit_code, 1);
        assert_eq!(out.stdout.text, "");
        assert_eq!(out.stderr.text, "No files were modified.\n");
    }

    #[test]
    fn apply_patch_in_process_avoids_absolute_paths_in_errors() {
        let dir = tempdir().expect("tempdir");
        let missing_path = dir.path().join("missing.txt");
        fs::write(&missing_path, "old\n").expect("seed file");
        let req = make_test_request(
            &dir,
            "*** Begin Patch\n*** Update File: missing.txt\n@@\n-old\n+new\n*** End Patch",
        );
        fs::remove_file(&missing_path).expect("delete file after verification");

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
        let req = make_test_request(
            &dir,
            "*** Begin Patch\n*** Update File: update.txt\n@@\n-bar\n+baz\n*** End Patch",
        );

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
