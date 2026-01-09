use std::collections::HashSet;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use crate::util::resolve_path;
use codex_app_server_protocol::GitSha;
use codex_protocol::protocol::GitInfo;
use futures::future::join_all;
use serde::Deserialize;
use serde::Serialize;
use tokio::process::Command;
use tokio::time::Duration as TokioDuration;
use tokio::time::timeout;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWorktreeHead {
    pub worktree_root: PathBuf,
    pub head_path: PathBuf,
    pub is_bare: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitHeadState {
    Branch(String),
    Detached,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWorktreeEntry {
    pub path: PathBuf,
    pub head: GitHeadState,
    pub is_bare: bool,
}

/// Return `true` if the project folder specified by the `Config` is inside a
/// Git repository.
///
/// The check walks up the directory hierarchy looking for a `.git` file or
/// directory (note `.git` can be a file that contains a `gitdir` entry). This
/// approach does **not** require the `git` binary or the `git2` crate and is
/// therefore fairly lightweight.
///
/// Note that this does **not** detect *work‑trees* created with
/// `git worktree add` where the checkout lives outside the main repository
/// directory. If you need Codex to work from such a checkout simply pass the
/// `--allow-no-git-exec` CLI flag that disables the repo requirement.
pub fn get_git_repo_root(base_dir: &Path) -> Option<PathBuf> {
    let mut dir = base_dir.to_path_buf();

    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }

        // Pop one component (go up one directory).  `pop` returns false when
        // we have reached the filesystem root.
        if !dir.pop() {
            break;
        }
    }

    None
}

pub fn resolve_git_worktree_head(base_dir: &Path) -> Option<GitWorktreeHead> {
    let mut dir = base_dir.to_path_buf();

    loop {
        let git_path = dir.join(".git");
        if git_path.is_dir() {
            return Some(GitWorktreeHead {
                worktree_root: dir,
                head_path: git_path.join("HEAD"),
                is_bare: false,
            });
        }

        if git_path.is_file()
            && let Ok(content) = std::fs::read_to_string(&git_path)
            && let Some(gitdir) = parse_gitdir_pointer(&content)
        {
            let gitdir = resolve_path(&dir, &gitdir);
            return Some(GitWorktreeHead {
                worktree_root: dir,
                head_path: gitdir.join("HEAD"),
                is_bare: false,
            });
        }

        let head_path = dir.join("HEAD");
        if head_path.is_file() && dir.join("objects").is_dir() && dir.join("refs").is_dir() {
            return Some(GitWorktreeHead {
                worktree_root: dir,
                head_path,
                is_bare: true,
            });
        }

        if !dir.pop() {
            break;
        }
    }

    None
}

pub fn read_git_head_state(head_path: &Path) -> Option<GitHeadState> {
    let content = std::fs::read_to_string(head_path).ok()?;
    let content = content.trim();
    if content.is_empty() {
        return None;
    }

    if let Some(rest) = content.strip_prefix("ref:") {
        let reference = rest.trim();
        if let Some(branch) = reference.strip_prefix("refs/heads/") {
            return Some(GitHeadState::Branch(branch.to_string()));
        }
        return Some(GitHeadState::Branch(reference.to_string()));
    }

    Some(GitHeadState::Detached)
}

fn parse_git_worktree_list_porcelain(text: &str, cwd: &Path) -> Vec<GitWorktreeEntry> {
    let mut entries: Vec<GitWorktreeEntry> = Vec::new();
    let mut current_path: Option<PathBuf> = None;
    let mut current_head: Option<GitHeadState> = None;
    let mut current_is_bare = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            if let (Some(path), Some(head)) = (current_path.take(), current_head.take()) {
                entries.push(GitWorktreeEntry {
                    path,
                    head,
                    is_bare: current_is_bare,
                });
            }
            current_is_bare = false;
            continue;
        }

        if let Some(rest) = line.strip_prefix("worktree ") {
            let path = PathBuf::from(rest.trim());
            current_path = Some(if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            });
            continue;
        }

        if line == "bare" {
            current_is_bare = true;
            continue;
        }

        if line == "detached" {
            current_head = Some(GitHeadState::Detached);
            continue;
        }

        if let Some(rest) = line.strip_prefix("branch ") {
            let reference = rest.trim();
            if let Some(branch) = reference.strip_prefix("refs/heads/") {
                current_head = Some(GitHeadState::Branch(branch.to_string()));
            } else {
                current_head = Some(GitHeadState::Branch(reference.to_string()));
            }
            continue;
        }
    }

    if let (Some(path), Some(head)) = (current_path.take(), current_head.take()) {
        entries.push(GitWorktreeEntry {
            path,
            head,
            is_bare: current_is_bare,
        });
    }

    entries
}

pub async fn try_list_git_worktrees(cwd: &Path) -> Result<Vec<GitWorktreeEntry>, String> {
    let Some(output) =
        run_git_command_with_timeout(&["worktree", "list", "--porcelain"], cwd).await
    else {
        return Err(String::from("Failed to run `git worktree list`"));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            String::from("`git worktree list` failed")
        } else {
            format!("`git worktree list` failed: {}", stderr.trim())
        });
    }

    let text = String::from_utf8(output.stdout)
        .map_err(|_| String::from("`git worktree list` returned non-utf8 output"))?;

    Ok(parse_git_worktree_list_porcelain(&text, cwd))
}

pub async fn list_git_worktrees(cwd: &Path) -> Vec<GitWorktreeEntry> {
    try_list_git_worktrees(cwd).await.unwrap_or_default()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitUntrackedSummary {
    pub total: usize,
    pub sample: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SharedDirLinkOutcome {
    Linked,
    AlreadyLinked,
    Skipped(String),
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedDirLinkMode {
    /// Link to workspace root if possible; skip on non-empty directories.
    LinkOnly,
    /// Migrate untracked files into the workspace root (conflict-safe), then link.
    /// When `include_ignored` is true, also migrates ignored-but-not-tracked paths.
    Migrate { include_ignored: bool },
    /// Replace the worktree path with a link to the workspace root, even if it
    /// means deleting existing contents.
    Replace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedDirLinkAction {
    pub shared_dir: String,
    pub link_path: PathBuf,
    pub target_path: PathBuf,
    pub outcome: SharedDirLinkOutcome,
}

fn validate_repo_relative_dir(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(String::from("shared dir path is empty"));
    }

    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Err(String::from(
            "shared dir path must be repo-relative (not absolute)",
        ));
    }

    for component in path.components() {
        match component {
            Component::CurDir | Component::ParentDir => {
                return Err(String::from(
                    "shared dir path must not contain `.` or `..` segments",
                ));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(String::from("shared dir path must be repo-relative"));
            }
            Component::Normal(_) => {}
        }
    }

    Ok(path)
}

fn pinned_prefix_from_spec(spec: &str) -> Option<PathBuf> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed.trim_end_matches("/**");
    let trimmed = trimmed.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return None;
    }

    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return None;
    }

    Some(path)
}

fn path_is_pinned(pinned_paths: &[String], candidate: &Path) -> bool {
    pinned_paths
        .iter()
        .filter_map(|spec| pinned_prefix_from_spec(spec))
        .any(|prefix| candidate.starts_with(prefix))
}

pub(crate) fn resolve_worktree_pinned_path(
    worktree_root: &Path,
    workspace_root: Option<&Path>,
    pinned_paths: &[String],
    path: &Path,
) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    if let Some(workspace_root) = workspace_root
        && !pinned_paths.is_empty()
        && path_is_pinned(pinned_paths, path)
    {
        return workspace_root.join(path);
    }

    worktree_root.join(path)
}

pub(crate) fn rewrite_apply_patch_input_for_pinned_paths(
    patch: &str,
    worktree_root: &Path,
    workspace_root: Option<&Path>,
    pinned_paths: &[String],
) -> String {
    if pinned_paths.is_empty() || workspace_root.is_none() {
        return patch.to_string();
    }

    let mut out = String::with_capacity(patch.len());
    for (idx, line) in patch.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }

        let (leading_ws, trimmed) = line
            .char_indices()
            .find(|(_, ch)| !ch.is_whitespace())
            .map_or((line, ""), |(i, _)| line.split_at(i));

        let (marker, raw_path) = if let Some(rest) = trimmed.strip_prefix("*** Add File: ") {
            ("*** Add File: ", rest)
        } else if let Some(rest) = trimmed.strip_prefix("*** Delete File: ") {
            ("*** Delete File: ", rest)
        } else if let Some(rest) = trimmed.strip_prefix("*** Update File: ") {
            ("*** Update File: ", rest)
        } else if let Some(rest) = trimmed.strip_prefix("*** Move to: ") {
            ("*** Move to: ", rest)
        } else {
            out.push_str(line);
            continue;
        };

        let raw_path = raw_path.trim();
        if raw_path.is_empty() {
            out.push_str(line);
            continue;
        }

        let path = PathBuf::from(raw_path);
        if path.is_absolute() || !path_is_pinned(pinned_paths, &path) {
            out.push_str(line);
            continue;
        }

        let resolved =
            resolve_worktree_pinned_path(worktree_root, workspace_root, pinned_paths, &path);

        out.push_str(leading_ws);
        out.push_str(marker);
        out.push_str(&resolved.to_string_lossy());
    }

    out
}

async fn has_tracked_files_under(cwd: &Path, pathspec: &Path) -> Result<bool, String> {
    let spec = pathspec.to_string_lossy();
    let Some(output) = run_git_command_with_timeout(&["ls-files", "--", &spec], cwd).await else {
        return Err(String::from("Failed to run `git ls-files`"));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            String::from("`git ls-files` failed")
        } else {
            format!("`git ls-files` failed: {}", stderr.trim())
        });
    }

    Ok(!output.stdout.is_empty())
}

pub async fn summarize_git_untracked_files_under(
    cwd: &Path,
    pathspec: &Path,
    sample_limit: usize,
) -> Result<GitUntrackedSummary, String> {
    if sample_limit == 0 {
        return Ok(GitUntrackedSummary {
            total: 0,
            sample: Vec::new(),
        });
    }

    let spec = pathspec.to_string_lossy();
    let Some(output) = run_git_command_with_timeout(
        &[
            "ls-files",
            "--others",
            "--exclude-standard",
            "--directory",
            "--",
            &spec,
        ],
        cwd,
    )
    .await
    else {
        return Err(String::from("Failed to run `git ls-files`"));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            String::from("`git ls-files` failed")
        } else {
            format!("`git ls-files` failed: {}", stderr.trim())
        });
    }

    let text = String::from_utf8(output.stdout)
        .map_err(|_| String::from("`git ls-files` returned non-utf8 output"))?;

    let mut total = 0usize;
    let mut sample: Vec<String> = Vec::new();
    for entry in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        total += 1;
        if sample.len() < sample_limit {
            sample.push(entry.to_string());
        }
    }

    Ok(GitUntrackedSummary { total, sample })
}

pub async fn summarize_git_untracked_files(
    cwd: &Path,
    sample_limit: usize,
) -> Result<GitUntrackedSummary, String> {
    if sample_limit == 0 {
        return Ok(GitUntrackedSummary {
            total: 0,
            sample: Vec::new(),
        });
    }

    let Some(output) = run_git_command_with_timeout(
        &["ls-files", "--others", "--exclude-standard", "--directory"],
        cwd,
    )
    .await
    else {
        return Err(String::from("Failed to run `git ls-files`"));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            String::from("`git ls-files` failed")
        } else {
            format!("`git ls-files` failed: {}", stderr.trim())
        });
    }

    let text = String::from_utf8(output.stdout)
        .map_err(|_| String::from("`git ls-files` returned non-utf8 output"))?;

    let entries: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect();

    let sample: Vec<String> = entries.iter().take(sample_limit).cloned().collect();

    Ok(GitUntrackedSummary {
        total: entries.len(),
        sample,
    })
}

fn canonicalize_or(path: &Path, fallback: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| fallback.to_path_buf())
}

fn path_entry_exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn path_points_to(path: &Path, target: &Path) -> bool {
    if !path_entry_exists(path) || !target.exists() {
        return false;
    }

    let path_canon = canonicalize_or(path, path);
    let target_canon = canonicalize_or(target, target);
    path_canon == target_canon
}

fn dir_is_empty(path: &Path) -> Result<bool, String> {
    let mut entries = std::fs::read_dir(path)
        .map_err(|err| format!("Failed to read {}: {err}", path.display()))?;
    Ok(entries.next().is_none())
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("Failed to stat {}: {err}", path.display()))?;
    if metadata.is_dir() {
        std::fs::remove_dir(path)
            .map_err(|err| format!("Failed to remove {}: {err}", path.display()))?;
        return Ok(());
    }

    std::fs::remove_file(path)
        .map_err(|err| format!("Failed to remove {}: {err}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn create_dir_link(target: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|err| format!("Failed to create symlink {}: {err}", link.display()))
}

#[cfg(target_os = "windows")]
fn create_dir_link(target: &Path, link: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt as _;

    let link_s = link.to_string_lossy().to_string();
    let target_s = target.to_string_lossy().to_string();
    let link_quoted = format!("\"{link_s}\"");
    let target_quoted = format!("\"{target_s}\"");

    let output = std::process::Command::new("cmd")
        .raw_arg("/c")
        .raw_arg("mklink")
        .raw_arg("/J")
        .raw_arg(&link_quoted)
        .raw_arg(&target_quoted)
        .output()
        .map_err(|err| format!("Failed to run `mklink` to create {}: {err}", link.display()))?;

    if output.status.success() && link.exists() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "`mklink` failed creating {} -> {} (status={:?}, stdout={}, stderr={})",
        link.display(),
        target.display(),
        output.status,
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(not(any(unix, windows)))]
fn create_dir_link(_target: &Path, link: &Path) -> Result<(), String> {
    Err(format!(
        "Linking shared dirs is not supported on this platform ({}).",
        link.display()
    ))
}

fn next_available_path(base: &Path) -> PathBuf {
    if !path_entry_exists(base) {
        return base.to_path_buf();
    }

    let Some(parent) = base.parent() else {
        return base.to_path_buf();
    };

    let file_name = base
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("migrated");

    for i in 1..=10_000usize {
        let candidate = parent.join(format!("{file_name}.migrated-{i}"));
        if !path_entry_exists(&candidate) {
            return candidate;
        }
    }

    base.to_path_buf()
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    std::fs::create_dir_all(destination)
        .map_err(|err| format!("Failed to create {}: {err}", destination.display()))?;

    for entry in std::fs::read_dir(source)
        .map_err(|err| format!("Failed to read {}: {err}", source.display()))?
    {
        let entry = entry.map_err(|err| format!("Failed to read dir entry: {err}"))?;
        let file_type = entry
            .file_type()
            .map_err(|err| format!("Failed to stat dir entry: {err}"))?;
        let src = entry.path();
        let dst = destination.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else if file_type.is_file() {
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("Failed to create {}: {err}", parent.display()))?;
            }
            std::fs::copy(&src, &dst)
                .map_err(|err| format!("Failed to copy {}: {err}", src.display()))?;
        } else if file_type.is_symlink() {
            #[cfg(unix)]
            {
                let target = std::fs::read_link(&src)
                    .map_err(|err| format!("Failed to read link {}: {err}", src.display()))?;
                std::os::unix::fs::symlink(&target, &dst)
                    .map_err(|err| format!("Failed to create symlink {}: {err}", dst.display()))?;
            }

            #[cfg(not(unix))]
            {
                return Err(format!(
                    "Cannot migrate symlink {} on this platform.",
                    src.display()
                ));
            }
        }
    }

    Ok(())
}

fn move_path(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create {}: {err}", parent.display()))?;
    }

    match std::fs::rename(source, destination) {
        Ok(()) => return Ok(()),
        Err(err) if err.kind() != std::io::ErrorKind::CrossesDevices => {
            return Err(format!(
                "Failed to move {} -> {}: {err}",
                source.display(),
                destination.display()
            ));
        }
        Err(_) => {}
    }

    let metadata = std::fs::symlink_metadata(source)
        .map_err(|err| format!("Failed to stat {}: {err}", source.display()))?;

    if metadata.is_file() {
        std::fs::copy(source, destination)
            .map_err(|err| format!("Failed to copy {}: {err}", source.display()))?;
        std::fs::remove_file(source)
            .map_err(|err| format!("Failed to remove {}: {err}", source.display()))?;
        return Ok(());
    }

    if metadata.is_dir() {
        copy_dir_recursive(source, destination)?;
        std::fs::remove_dir_all(source)
            .map_err(|err| format!("Failed to remove {}: {err}", source.display()))?;
        return Ok(());
    }

    Err(format!(
        "Cannot migrate non-file path {}.",
        source.display()
    ))
}

async fn list_git_untracked_entries_under(
    cwd: &Path,
    pathspec: &Path,
    include_ignored: bool,
) -> Result<Vec<String>, String> {
    let spec = pathspec.to_string_lossy();

    let mut args = vec!["ls-files", "--others", "--exclude-standard", "--directory"];
    if include_ignored {
        args.push("--ignored");
    }
    args.push("--");
    args.push(&spec);

    let Some(output) = run_git_command_with_timeout(&args, cwd).await else {
        return Err(String::from("Failed to run `git ls-files`"));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.trim().is_empty() {
            String::from("`git ls-files` failed")
        } else {
            format!("`git ls-files` failed: {}", stderr.trim())
        });
    }

    let text = String::from_utf8(output.stdout)
        .map_err(|_| String::from("`git ls-files` returned non-utf8 output"))?;

    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

async fn link_one_shared_dir(
    worktree_root: &Path,
    workspace_root: &Path,
    shared_dir: &str,
    mode: SharedDirLinkMode,
) -> SharedDirLinkAction {
    let (migrate_untracked, include_ignored, replace_existing) = match mode {
        SharedDirLinkMode::LinkOnly => (false, false, false),
        SharedDirLinkMode::Migrate { include_ignored } => (true, include_ignored, false),
        SharedDirLinkMode::Replace => (false, false, true),
    };

    let pathspec = match validate_repo_relative_dir(shared_dir) {
        Ok(pathspec) => pathspec,
        Err(err) => {
            return SharedDirLinkAction {
                shared_dir: shared_dir.to_string(),
                link_path: worktree_root.join(shared_dir),
                target_path: workspace_root.join(shared_dir),
                outcome: SharedDirLinkOutcome::Failed(err),
            };
        }
    };

    let link_path = worktree_root.join(&pathspec);
    let target_path = workspace_root.join(&pathspec);

    if link_path == target_path {
        let _ = std::fs::create_dir_all(&target_path);
        return SharedDirLinkAction {
            shared_dir: shared_dir.to_string(),
            link_path,
            target_path,
            outcome: SharedDirLinkOutcome::AlreadyLinked,
        };
    }

    if path_points_to(&link_path, &target_path) {
        return SharedDirLinkAction {
            shared_dir: shared_dir.to_string(),
            link_path,
            target_path,
            outcome: SharedDirLinkOutcome::AlreadyLinked,
        };
    }

    if let Err(err) = std::fs::create_dir_all(&target_path) {
        let target_display = target_path.display().to_string();
        return SharedDirLinkAction {
            shared_dir: shared_dir.to_string(),
            link_path,
            target_path,
            outcome: SharedDirLinkOutcome::Failed(format!(
                "Failed to create {target_display}: {err}"
            )),
        };
    }

    match has_tracked_files_under(worktree_root, &pathspec).await {
        Ok(true) => {
            return SharedDirLinkAction {
                shared_dir: shared_dir.to_string(),
                link_path,
                target_path,
                outcome: SharedDirLinkOutcome::Skipped(String::from(
                    "Contains tracked files; refusing to link.",
                )),
            };
        }
        Ok(false) => {}
        Err(err) => {
            return SharedDirLinkAction {
                shared_dir: shared_dir.to_string(),
                link_path,
                target_path,
                outcome: SharedDirLinkOutcome::Failed(err),
            };
        }
    }

    if path_entry_exists(&link_path) {
        let link_display = link_path.display().to_string();
        let link_metadata = match std::fs::symlink_metadata(&link_path) {
            Ok(metadata) => metadata,
            Err(err) => {
                return SharedDirLinkAction {
                    shared_dir: shared_dir.to_string(),
                    link_path,
                    target_path,
                    outcome: SharedDirLinkOutcome::Failed(format!(
                        "Failed to stat {link_display}: {err}"
                    )),
                };
            }
        };
        let link_is_symlink = link_metadata.file_type().is_symlink();
        let mut removed_for_replace = false;

        if replace_existing {
            if link_is_symlink || link_metadata.is_file() {
                if let Err(err) = std::fs::remove_file(&link_path) {
                    return SharedDirLinkAction {
                        shared_dir: shared_dir.to_string(),
                        link_path,
                        target_path,
                        outcome: SharedDirLinkOutcome::Failed(format!(
                            "Failed to remove {link_display}: {err}"
                        )),
                    };
                }
                removed_for_replace = true;
            } else if link_metadata.is_dir() {
                if let Err(err) = std::fs::remove_dir_all(&link_path) {
                    return SharedDirLinkAction {
                        shared_dir: shared_dir.to_string(),
                        link_path,
                        target_path,
                        outcome: SharedDirLinkOutcome::Failed(format!(
                            "Failed to remove {link_display}: {err}"
                        )),
                    };
                }
                removed_for_replace = true;
            } else {
                return SharedDirLinkAction {
                    shared_dir: shared_dir.to_string(),
                    link_path,
                    target_path,
                    outcome: SharedDirLinkOutcome::Skipped(String::from(
                        "Path exists and is not a directory or a link; refusing to replace it with a link.",
                    )),
                };
            }
        } else if link_is_symlink {
            // The path is already a symlink (potentially broken or pointing elsewhere). It's safe
            // to replace it with the desired link target.
        } else if link_metadata.is_dir() {
            let empty = match dir_is_empty(&link_path) {
                Ok(empty) => empty,
                Err(err) => {
                    return SharedDirLinkAction {
                        shared_dir: shared_dir.to_string(),
                        link_path,
                        target_path,
                        outcome: SharedDirLinkOutcome::Failed(err),
                    };
                }
            };

            if !empty && migrate_untracked {
                match list_git_untracked_entries_under(worktree_root, &pathspec, include_ignored)
                    .await
                {
                    Ok(entries) if entries.is_empty() => {
                        return SharedDirLinkAction {
                            shared_dir: shared_dir.to_string(),
                            link_path,
                            target_path,
                            outcome: SharedDirLinkOutcome::Skipped(String::from(
                                "Directory is not empty but contains no git-untracked files; migrate manually.",
                            )),
                        };
                    }
                    Ok(entries) => {
                        for entry in entries {
                            let entry = entry.trim_end_matches('/');
                            if entry.is_empty() {
                                continue;
                            }
                            let source = worktree_root.join(entry);
                            if !path_entry_exists(&source) {
                                continue;
                            }
                            let desired_destination = workspace_root.join(entry);
                            let destination = next_available_path(&desired_destination);
                            if let Err(err) = move_path(&source, &destination) {
                                return SharedDirLinkAction {
                                    shared_dir: shared_dir.to_string(),
                                    link_path,
                                    target_path,
                                    outcome: SharedDirLinkOutcome::Failed(err),
                                };
                            }
                        }
                    }
                    Err(err) => {
                        return SharedDirLinkAction {
                            shared_dir: shared_dir.to_string(),
                            link_path,
                            target_path,
                            outcome: SharedDirLinkOutcome::Failed(err),
                        };
                    }
                }
            }

            match dir_is_empty(&link_path) {
                Ok(true) => {}
                Ok(false) => {
                    let reason = if migrate_untracked {
                        "Directory is not empty; refusing to replace it with a link after migration."
                    } else {
                        "Directory is not empty; run `/worktree link-shared` to migrate+link, or migrate manually."
                    };
                    return SharedDirLinkAction {
                        shared_dir: shared_dir.to_string(),
                        link_path,
                        target_path,
                        outcome: SharedDirLinkOutcome::Skipped(String::from(reason)),
                    };
                }
                Err(err) => {
                    return SharedDirLinkAction {
                        shared_dir: shared_dir.to_string(),
                        link_path,
                        target_path,
                        outcome: SharedDirLinkOutcome::Failed(err),
                    };
                }
            }
        } else {
            return SharedDirLinkAction {
                shared_dir: shared_dir.to_string(),
                link_path,
                target_path,
                outcome: SharedDirLinkOutcome::Skipped(String::from(
                    "Path exists and is not an empty directory; refusing to replace it with a link.",
                )),
            };
        }

        if !removed_for_replace {
            if let Err(err) = remove_if_exists(&link_path) {
                return SharedDirLinkAction {
                    shared_dir: shared_dir.to_string(),
                    link_path,
                    target_path,
                    outcome: SharedDirLinkOutcome::Failed(err),
                };
            }
        }
    } else if let Some(parent) = link_path.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        let parent_display = parent.display().to_string();
        return SharedDirLinkAction {
            shared_dir: shared_dir.to_string(),
            link_path,
            target_path,
            outcome: SharedDirLinkOutcome::Failed(format!(
                "Failed to create {parent_display}: {err}"
            )),
        };
    }

    match create_dir_link(&target_path, &link_path) {
        Ok(()) => SharedDirLinkAction {
            shared_dir: shared_dir.to_string(),
            link_path,
            target_path,
            outcome: SharedDirLinkOutcome::Linked,
        },
        Err(err) => SharedDirLinkAction {
            shared_dir: shared_dir.to_string(),
            link_path,
            target_path,
            outcome: SharedDirLinkOutcome::Failed(err),
        },
    }
}

pub async fn link_worktree_shared_dir(
    worktree_root: &Path,
    workspace_root: &Path,
    shared_dir: &str,
    mode: SharedDirLinkMode,
) -> SharedDirLinkAction {
    link_one_shared_dir(worktree_root, workspace_root, shared_dir, mode).await
}

pub async fn link_worktree_shared_dirs(
    worktree_root: &Path,
    workspace_root: &Path,
    shared_dirs: &[String],
) -> Vec<SharedDirLinkAction> {
    let mut results: Vec<SharedDirLinkAction> = Vec::new();

    for shared_dir in shared_dirs {
        results.push(
            link_worktree_shared_dir(
                worktree_root,
                workspace_root,
                shared_dir,
                SharedDirLinkMode::LinkOnly,
            )
            .await,
        );
    }

    results
}

pub async fn link_worktree_shared_dirs_migrating_untracked(
    worktree_root: &Path,
    workspace_root: &Path,
    shared_dirs: &[String],
) -> Vec<SharedDirLinkAction> {
    let mut results: Vec<SharedDirLinkAction> = Vec::new();

    for shared_dir in shared_dirs {
        results.push(
            link_worktree_shared_dir(
                worktree_root,
                workspace_root,
                shared_dir,
                SharedDirLinkMode::Migrate {
                    include_ignored: true,
                },
            )
            .await,
        );
    }

    results
}

pub async fn worktree_doctor_lines(
    cwd: &Path,
    shared_dirs: &[String],
    sample_limit: usize,
) -> Vec<String> {
    let Some(head) = resolve_git_worktree_head(cwd) else {
        return vec![String::from("worktree doctor — not inside a git worktree.")];
    };

    let worktree_root = head.worktree_root;
    let workspace_root = resolve_root_git_project_for_trust(&worktree_root);

    let mut lines: Vec<String> = Vec::new();
    lines.push(String::from("worktree doctor"));
    lines.push(format!("active worktree: {}", worktree_root.display()));
    if let Some(root) = &workspace_root {
        lines.push(format!("workspace root: {}", root.display()));
    } else {
        lines.push(String::from("workspace root: (unknown)"));
    }

    if shared_dirs.is_empty() {
        lines.push(String::from("shared dirs: (none configured)"));
        lines.push(String::from(
            "Tip: add shared dirs via `/worktree shared add <dir>`, then run `/worktree link-shared`.",
        ));
        return lines;
    }

    lines.push(format!("shared dirs: {}", shared_dirs.join(", ")));

    let Some(workspace_root) = workspace_root else {
        lines.push(String::from(
            "Cannot resolve workspace root; skipping shared-dir checks.",
        ));
        return lines;
    };

    for shared_dir in shared_dirs {
        let pathspec = match validate_repo_relative_dir(shared_dir) {
            Ok(pathspec) => pathspec,
            Err(err) => {
                lines.push(format!("- {shared_dir}: invalid path ({err})"));
                continue;
            }
        };

        let link_path = worktree_root.join(&pathspec);
        let target_path = workspace_root.join(&pathspec);
        let linked = path_points_to(&link_path, &target_path);
        let link_is_symlink =
            std::fs::symlink_metadata(&link_path).is_ok_and(|md| md.file_type().is_symlink());

        let tracked = (has_tracked_files_under(&worktree_root, &pathspec).await).ok();

        let untracked =
            summarize_git_untracked_files_under(&worktree_root, &pathspec, sample_limit)
                .await
                .ok();

        let mut status = String::new();
        if linked {
            status.push_str("linked");
        } else if path_entry_exists(&link_path) {
            if link_is_symlink {
                status.push_str("link present (not pointing at workspace root)");
            } else {
                status.push_str("not linked");
            }
        } else {
            status.push_str("missing");
        }

        if let Some(tracked) = tracked {
            if tracked {
                status.push_str(", tracked files present");
            } else {
                status.push_str(", no tracked files");
            }
        }

        if let Some(summary) = &untracked {
            if summary.total > 0 {
                status.push_str(&format!(", untracked={}", summary.total));
            } else {
                status.push_str(", untracked=0");
            }
        }

        lines.push(format!("- {shared_dir}: {status}"));
        if let Some(summary) = untracked
            && summary.total > 0
            && !summary.sample.is_empty()
        {
            for sample in summary.sample.into_iter().take(3) {
                lines.push(format!("    - {sample}"));
            }
            if summary.total > 3 {
                lines.push(format!("    - … +{} more", summary.total - 3));
            }
        }

        if !linked {
            if path_entry_exists(&link_path) {
                if tracked == Some(true) {
                    lines.push(String::from(
                        "    action: remove this dir from `worktrees.shared_dirs` (tracked files present)",
                    ));
                } else if link_is_symlink {
                    lines.push(String::from(
                        "    action: run `/worktree link-shared` to re-link to workspace root",
                    ));
                } else {
                    lines.push(String::from(
                        "    action: run `/worktree link-shared` and choose migrate+link if needed",
                    ));
                }
            } else {
                lines.push(String::from("    action: run `/worktree link-shared`"));
            }
        }
    }

    lines.push(String::from("Next steps:"));
    lines.push(String::from(
        "- Run `/worktree link-shared` to apply links for configured shared dirs.",
    ));
    lines.push(String::from(
        "- If a shared dir is refused due to non-empty content, rerun `/worktree link-shared` and choose migrate+link (or replace+link), or migrate files into the workspace root first, then retry.",
    ));
    lines.push(String::from(
        "- If you want shared-dir links applied automatically on switch, enable `worktrees.auto_link_shared_dirs = true`.",
    ));
    lines.push(String::from(
        "- If you created worktrees outside xcodex, run `/worktree detect` to refresh the picker list.",
    ));

    lines
}

fn validate_git_branch_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(String::from("branch name is empty"));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(String::from("branch name must not contain whitespace"));
    }
    Ok(trimmed.to_string())
}

async fn git_branch_exists(cwd: &Path, branch: &str) -> Result<bool, String> {
    let Some(output) = run_git_command_with_timeout(
        &[
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
        cwd,
    )
    .await
    else {
        return Err(String::from("Failed to run `git show-ref`"));
    };

    Ok(output.status.success())
}

async fn run_git_command_with_timeout_result(
    args: &[&str],
    cwd: &Path,
) -> Result<std::process::Output, String> {
    timeout(
        GIT_COMMAND_TIMEOUT,
        Command::new("git").args(args).current_dir(cwd).output(),
    )
    .await
    .map_err(|_| format!("`git {}` timed out", args.join(" ")))?
    .map_err(|err| format!("Failed to run `git {}`: {err}", args.join(" ")))
}

pub async fn init_git_worktree(
    workspace_root: &Path,
    name: &str,
    branch: &str,
    worktree_path: Option<&Path>,
) -> Result<PathBuf, String> {
    let branch_exists = git_branch_exists(workspace_root, branch.trim()).await?;
    init_git_worktree_with_mode(
        workspace_root,
        name,
        branch,
        worktree_path,
        !branch_exists,
        None,
    )
    .await
}

pub async fn init_git_worktree_with_mode(
    workspace_root: &Path,
    name: &str,
    branch: &str,
    worktree_path: Option<&Path>,
    create_branch: bool,
    base_ref: Option<&str>,
) -> Result<PathBuf, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(String::from("worktree name is empty"));
    }

    let branch = validate_git_branch_name(branch)?;

    let default_path = workspace_root.join(".worktrees").join(name);
    let path = worktree_path.unwrap_or(&default_path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    };

    if path_entry_exists(&path) {
        return Err(format!("Worktree path already exists: {}", path.display()));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create {}: {err}", parent.display()))?;
    }

    let mut args: Vec<String> = Vec::new();
    args.push(String::from("worktree"));
    args.push(String::from("add"));
    if create_branch {
        args.push(String::from("-b"));
        args.push(branch.clone());
        args.push(path.display().to_string());
        if let Some(base_ref) = base_ref {
            let base_ref = base_ref.trim();
            if !base_ref.is_empty() {
                args.push(base_ref.to_string());
            }
        }
    } else {
        args.push(path.display().to_string());
        args.push(branch.clone());
    }

    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_git_command_with_timeout_result(&args_ref, workspace_root).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = stderr.trim();
        let stdout = stdout.trim();
        let mut message = format!("`git {}` failed", args.join(" "));
        if !stderr.is_empty() {
            message.push_str(&format!(": {stderr}"));
        } else if !stdout.is_empty() {
            message.push_str(&format!(": {stdout}"));
        }
        return Err(message);
    }

    Ok(path)
}

fn parse_gitdir_pointer(content: &str) -> Option<PathBuf> {
    content.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("gitdir:")
            .map(str::trim)
            .filter(|rest| !rest.is_empty())
            .map(PathBuf::from)
    })
}

/// Timeout for git commands to prevent freezing on large repositories
const GIT_COMMAND_TIMEOUT: TokioDuration = TokioDuration::from_secs(5);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GitDiffToRemote {
    pub sha: GitSha,
    pub diff: String,
}

/// Collect git repository information from the given working directory using command-line git.
/// Returns None if no git repository is found or if git operations fail.
/// Uses timeouts to prevent freezing on large repositories.
/// All git commands (except the initial repo check) run in parallel for better performance.
pub async fn collect_git_info(cwd: &Path) -> Option<GitInfo> {
    // Check if we're in a git repository first
    let is_git_repo = run_git_command_with_timeout(&["rev-parse", "--git-dir"], cwd)
        .await?
        .status
        .success();

    if !is_git_repo {
        return None;
    }

    // Run all git info collection commands in parallel
    let (commit_result, branch_result, url_result) = tokio::join!(
        run_git_command_with_timeout(&["rev-parse", "HEAD"], cwd),
        run_git_command_with_timeout(&["rev-parse", "--abbrev-ref", "HEAD"], cwd),
        run_git_command_with_timeout(&["remote", "get-url", "origin"], cwd)
    );

    let mut git_info = GitInfo {
        commit_hash: None,
        branch: None,
        repository_url: None,
    };

    // Process commit hash
    if let Some(output) = commit_result
        && output.status.success()
        && let Ok(hash) = String::from_utf8(output.stdout)
    {
        git_info.commit_hash = Some(hash.trim().to_string());
    }

    // Process branch name
    if let Some(output) = branch_result
        && output.status.success()
        && let Ok(branch) = String::from_utf8(output.stdout)
    {
        let branch = branch.trim();
        if branch != "HEAD" {
            git_info.branch = Some(branch.to_string());
        }
    }

    // Process repository URL
    if let Some(output) = url_result
        && output.status.success()
        && let Ok(url) = String::from_utf8(output.stdout)
    {
        git_info.repository_url = Some(url.trim().to_string());
    }

    Some(git_info)
}

#[cfg(test)]
mod untracked_summary_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn summarize_git_untracked_files_reports_untracked_entries() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        let init = Command::new("git")
            .args(["init"])
            .current_dir(root)
            .output()
            .await
            .expect("git init");
        assert!(init.status.success());

        fs::write(root.join("tracked.txt"), "tracked").expect("write tracked");
        let add = Command::new("git")
            .args(["add", "tracked.txt"])
            .current_dir(root)
            .output()
            .await
            .expect("git add");
        assert!(add.status.success());

        fs::write(root.join("untracked.txt"), "untracked").expect("write untracked");
        fs::create_dir_all(root.join("untracked_dir")).expect("mkdir");
        fs::write(root.join("untracked_dir").join("file.txt"), "x").expect("write untracked dir");

        let summary = summarize_git_untracked_files(root, 10)
            .await
            .expect("summarize");

        assert!(summary.total >= 2, "{summary:?}");
        assert!(
            summary.sample.iter().any(|p| p == "untracked.txt"),
            "{summary:?}"
        );
        assert!(
            summary.sample.iter().any(|p| p == "untracked_dir/"),
            "{summary:?}"
        );
    }
}

/// A minimal commit summary entry used for pickers (subject + timestamp + sha).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitLogEntry {
    pub sha: String,
    /// Unix timestamp (seconds since epoch) of the commit time (committer time).
    pub timestamp: i64,
    /// Single-line subject of the commit message.
    pub subject: String,
}

/// Return the last `limit` commits reachable from HEAD for the current branch.
/// Each entry contains the SHA, commit timestamp (seconds), and subject line.
/// Returns an empty vector if not in a git repo or on error/timeout.
pub async fn recent_commits(cwd: &Path, limit: usize) -> Vec<CommitLogEntry> {
    // Ensure we're in a git repo first to avoid noisy errors.
    let Some(out) = run_git_command_with_timeout(&["rev-parse", "--git-dir"], cwd).await else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }

    let fmt = "%H%x1f%ct%x1f%s"; // <sha> <US> <commit_time> <US> <subject>
    let limit_arg = (limit > 0).then(|| limit.to_string());
    let mut args: Vec<String> = vec!["log".to_string()];
    if let Some(n) = &limit_arg {
        args.push("-n".to_string());
        args.push(n.clone());
    }
    args.push(format!("--pretty=format:{fmt}"));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some(log_out) = run_git_command_with_timeout(&arg_refs, cwd).await else {
        return Vec::new();
    };
    if !log_out.status.success() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(&log_out.stdout);
    let mut entries: Vec<CommitLogEntry> = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\u{001f}');
        let sha = parts.next().unwrap_or("").trim();
        let ts_s = parts.next().unwrap_or("").trim();
        let subject = parts.next().unwrap_or("").trim();
        if sha.is_empty() || ts_s.is_empty() {
            continue;
        }
        let timestamp = ts_s.parse::<i64>().unwrap_or(0);
        entries.push(CommitLogEntry {
            sha: sha.to_string(),
            timestamp,
            subject: subject.to_string(),
        });
    }

    entries
}

/// Returns the closest git sha to HEAD that is on a remote as well as the diff to that sha.
pub async fn git_diff_to_remote(cwd: &Path) -> Option<GitDiffToRemote> {
    get_git_repo_root(cwd)?;

    let remotes = get_git_remotes(cwd).await?;
    let branches = branch_ancestry(cwd).await?;
    let base_sha = find_closest_sha(cwd, &branches, &remotes).await?;
    let diff = diff_against_sha(cwd, &base_sha).await?;

    Some(GitDiffToRemote {
        sha: base_sha,
        diff,
    })
}

/// Run a git command with a timeout to prevent blocking on large repositories
async fn run_git_command_with_timeout(args: &[&str], cwd: &Path) -> Option<std::process::Output> {
    let result = timeout(
        GIT_COMMAND_TIMEOUT,
        Command::new("git").args(args).current_dir(cwd).output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => Some(output),
        _ => None, // Timeout or error
    }
}

async fn get_git_remotes(cwd: &Path) -> Option<Vec<String>> {
    let output = run_git_command_with_timeout(&["remote"], cwd).await?;
    if !output.status.success() {
        return None;
    }
    let mut remotes: Vec<String> = String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .map(str::to_string)
        .collect();
    if let Some(pos) = remotes.iter().position(|r| r == "origin") {
        let origin = remotes.remove(pos);
        remotes.insert(0, origin);
    }
    Some(remotes)
}

/// Attempt to determine the repository's default branch name.
///
/// Preference order:
/// 1) The symbolic ref at `refs/remotes/<remote>/HEAD` for the first remote (origin prioritized)
/// 2) `git remote show <remote>` parsed for "HEAD branch: <name>"
/// 3) Local fallback to existing `main` or `master` if present
async fn get_default_branch(cwd: &Path) -> Option<String> {
    // Prefer the first remote (with origin prioritized)
    let remotes = get_git_remotes(cwd).await.unwrap_or_default();
    for remote in remotes {
        // Try symbolic-ref, which returns something like: refs/remotes/origin/main
        if let Some(symref_output) = run_git_command_with_timeout(
            &[
                "symbolic-ref",
                "--quiet",
                &format!("refs/remotes/{remote}/HEAD"),
            ],
            cwd,
        )
        .await
            && symref_output.status.success()
            && let Ok(sym) = String::from_utf8(symref_output.stdout)
        {
            let trimmed = sym.trim();
            if let Some((_, name)) = trimmed.rsplit_once('/') {
                return Some(name.to_string());
            }
        }

        // Fall back to parsing `git remote show <remote>` output
        if let Some(show_output) =
            run_git_command_with_timeout(&["remote", "show", &remote], cwd).await
            && show_output.status.success()
            && let Ok(text) = String::from_utf8(show_output.stdout)
        {
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("HEAD branch:") {
                    let name = rest.trim();
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
        }
    }

    // No remote-derived default; try common local defaults if they exist
    get_default_branch_local(cwd).await
}

/// Determine the repository's default branch name, if available.
///
/// This inspects remote configuration first (including the symbolic `HEAD`
/// reference) and falls back to common local defaults such as `main` or
/// `master`. Returns `None` when the information cannot be determined, for
/// example when the current directory is not inside a Git repository.
pub async fn default_branch_name(cwd: &Path) -> Option<String> {
    get_default_branch(cwd).await
}

/// Attempt to determine the repository's default branch name from local branches.
async fn get_default_branch_local(cwd: &Path) -> Option<String> {
    for candidate in ["main", "master"] {
        if let Some(verify) = run_git_command_with_timeout(
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("refs/heads/{candidate}"),
            ],
            cwd,
        )
        .await
            && verify.status.success()
        {
            return Some(candidate.to_string());
        }
    }

    None
}

/// Build an ancestry of branches starting at the current branch and ending at the
/// repository's default branch (if determinable)..
async fn branch_ancestry(cwd: &Path) -> Option<Vec<String>> {
    // Discover current branch (ignore detached HEAD by treating it as None)
    let current_branch = run_git_command_with_timeout(&["rev-parse", "--abbrev-ref", "HEAD"], cwd)
        .await
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .filter(|s| s != "HEAD");

    // Discover default branch
    let default_branch = get_default_branch(cwd).await;

    let mut ancestry: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(cb) = current_branch.clone() {
        seen.insert(cb.clone());
        ancestry.push(cb);
    }
    if let Some(db) = default_branch
        && !seen.contains(&db)
    {
        seen.insert(db.clone());
        ancestry.push(db);
    }

    // Expand candidates: include any remote branches that already contain HEAD.
    // This addresses cases where we're on a new local-only branch forked from a
    // remote branch that isn't the repository default. We prioritize remotes in
    // the order returned by get_git_remotes (origin first).
    let remotes = get_git_remotes(cwd).await.unwrap_or_default();
    for remote in remotes {
        if let Some(output) = run_git_command_with_timeout(
            &[
                "for-each-ref",
                "--format=%(refname:short)",
                "--contains=HEAD",
                &format!("refs/remotes/{remote}"),
            ],
            cwd,
        )
        .await
            && output.status.success()
            && let Ok(text) = String::from_utf8(output.stdout)
        {
            for line in text.lines() {
                let short = line.trim();
                // Expect format like: "origin/feature"; extract the branch path after "remote/"
                if let Some(stripped) = short.strip_prefix(&format!("{remote}/"))
                    && !stripped.is_empty()
                    && !seen.contains(stripped)
                {
                    seen.insert(stripped.to_string());
                    ancestry.push(stripped.to_string());
                }
            }
        }
    }

    // Ensure we return Some vector, even if empty, to allow caller logic to proceed
    Some(ancestry)
}

// Helper for a single branch: return the remote SHA if present on any remote
// and the distance (commits ahead of HEAD) for that branch. The first item is
// None if the branch is not present on any remote. Returns None if distance
// could not be computed due to git errors/timeouts.
async fn branch_remote_and_distance(
    cwd: &Path,
    branch: &str,
    remotes: &[String],
) -> Option<(Option<GitSha>, usize)> {
    // Try to find the first remote ref that exists for this branch (origin prioritized by caller).
    let mut found_remote_sha: Option<GitSha> = None;
    let mut found_remote_ref: Option<String> = None;
    for remote in remotes {
        let remote_ref = format!("refs/remotes/{remote}/{branch}");
        let Some(verify_output) =
            run_git_command_with_timeout(&["rev-parse", "--verify", "--quiet", &remote_ref], cwd)
                .await
        else {
            // Mirror previous behavior: if the verify call times out/fails at the process level,
            // treat the entire branch as unusable.
            return None;
        };
        if !verify_output.status.success() {
            continue;
        }
        let Ok(sha) = String::from_utf8(verify_output.stdout) else {
            // Mirror previous behavior and skip the entire branch on parse failure.
            return None;
        };
        found_remote_sha = Some(GitSha::new(sha.trim()));
        found_remote_ref = Some(remote_ref);
        break;
    }

    // Compute distance as the number of commits HEAD is ahead of the branch.
    // Prefer local branch name if it exists; otherwise fall back to the remote ref (if any).
    let count_output = if let Some(local_count) =
        run_git_command_with_timeout(&["rev-list", "--count", &format!("{branch}..HEAD")], cwd)
            .await
    {
        if local_count.status.success() {
            local_count
        } else if let Some(remote_ref) = &found_remote_ref {
            match run_git_command_with_timeout(
                &["rev-list", "--count", &format!("{remote_ref}..HEAD")],
                cwd,
            )
            .await
            {
                Some(remote_count) => remote_count,
                None => return None,
            }
        } else {
            return None;
        }
    } else if let Some(remote_ref) = &found_remote_ref {
        match run_git_command_with_timeout(
            &["rev-list", "--count", &format!("{remote_ref}..HEAD")],
            cwd,
        )
        .await
        {
            Some(remote_count) => remote_count,
            None => return None,
        }
    } else {
        return None;
    };

    if !count_output.status.success() {
        return None;
    }
    let Ok(distance_str) = String::from_utf8(count_output.stdout) else {
        return None;
    };
    let Ok(distance) = distance_str.trim().parse::<usize>() else {
        return None;
    };

    Some((found_remote_sha, distance))
}

// Finds the closest sha that exist on any of branches and also exists on any of the remotes.
async fn find_closest_sha(cwd: &Path, branches: &[String], remotes: &[String]) -> Option<GitSha> {
    // A sha and how many commits away from HEAD it is.
    let mut closest_sha: Option<(GitSha, usize)> = None;
    for branch in branches {
        let Some((maybe_remote_sha, distance)) =
            branch_remote_and_distance(cwd, branch, remotes).await
        else {
            continue;
        };
        let Some(remote_sha) = maybe_remote_sha else {
            // Preserve existing behavior: skip branches that are not present on a remote.
            continue;
        };
        match &closest_sha {
            None => closest_sha = Some((remote_sha, distance)),
            Some((_, best_distance)) if distance < *best_distance => {
                closest_sha = Some((remote_sha, distance));
            }
            _ => {}
        }
    }
    closest_sha.map(|(sha, _)| sha)
}

async fn diff_against_sha(cwd: &Path, sha: &GitSha) -> Option<String> {
    let output =
        run_git_command_with_timeout(&["diff", "--no-textconv", "--no-ext-diff", &sha.0], cwd)
            .await?;
    // 0 is success and no diff.
    // 1 is success but there is a diff.
    let exit_ok = output.status.code().is_some_and(|c| c == 0 || c == 1);
    if !exit_ok {
        return None;
    }
    let mut diff = String::from_utf8(output.stdout).ok()?;

    if let Some(untracked_output) =
        run_git_command_with_timeout(&["ls-files", "--others", "--exclude-standard"], cwd).await
        && untracked_output.status.success()
    {
        let untracked: Vec<String> = String::from_utf8(untracked_output.stdout)
            .ok()?
            .lines()
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .collect();

        if !untracked.is_empty() {
            // Use platform-appropriate null device and guard paths with `--`.
            let null_device: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };
            let futures_iter = untracked.into_iter().map(|file| async move {
                let file_owned = file;
                let args_vec: Vec<&str> = vec![
                    "diff",
                    "--no-textconv",
                    "--no-ext-diff",
                    "--binary",
                    "--no-index",
                    // -- ensures that filenames that start with - are not treated as options.
                    "--",
                    null_device,
                    &file_owned,
                ];
                run_git_command_with_timeout(&args_vec, cwd).await
            });
            let results = join_all(futures_iter).await;
            for extra in results.into_iter().flatten() {
                if extra.status.code().is_some_and(|c| c == 0 || c == 1)
                    && let Ok(s) = String::from_utf8(extra.stdout)
                {
                    diff.push_str(&s);
                }
            }
        }
    }

    Some(diff)
}

/// Resolve the path that should be used for trust checks. Similar to
/// `[get_git_repo_root]`, but resolves to the root of the main
/// repository. Handles worktrees.
pub fn resolve_root_git_project_for_trust(cwd: &Path) -> Option<PathBuf> {
    let base = if cwd.is_dir() { cwd } else { cwd.parent()? };

    // TODO: we should make this async, but it's primarily used deep in
    // callstacks of sync code, and should almost always be fast
    let git_dir_out = std::process::Command::new("git")
        .args(["rev-parse", "--git-common-dir"])
        .current_dir(base)
        .output()
        .ok()?;
    if !git_dir_out.status.success() {
        return None;
    }
    let git_dir_s = String::from_utf8(git_dir_out.stdout)
        .ok()?
        .trim()
        .to_string();

    let git_dir_path_raw = resolve_path(base, &PathBuf::from(&git_dir_s));

    // Normalize to handle macOS /var vs /private/var and resolve ".." segments.
    let git_dir_path = std::fs::canonicalize(&git_dir_path_raw).unwrap_or(git_dir_path_raw);
    git_dir_path.parent().map(Path::to_path_buf)
}

/// Returns a list of local git branches.
/// Includes the default branch at the beginning of the list, if it exists.
pub async fn local_git_branches(cwd: &Path) -> Vec<String> {
    let mut branches: Vec<String> = if let Some(out) =
        run_git_command_with_timeout(&["branch", "--format=%(refname:short)"], cwd).await
        && out.status.success()
    {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    branches.sort_unstable();

    if let Some(base) = get_default_branch_local(cwd).await
        && let Some(pos) = branches.iter().position(|name| name == &base)
    {
        let base_branch = branches.remove(pos);
        branches.insert(0, base_branch);
    }

    branches
}

/// Returns the current checked out branch name.
pub async fn current_branch_name(cwd: &Path) -> Option<String> {
    let out = run_git_command_with_timeout(&["branch", "--show-current"], cwd).await?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    use core_test_support::skip_if_sandbox;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn read_git_head_state_branch() {
        let tmp = TempDir::new().expect("tempdir");
        let head = tmp.path().join("HEAD");
        std::fs::write(&head, "ref: refs/heads/feat/x\n").unwrap();
        assert_eq!(
            read_git_head_state(&head),
            Some(GitHeadState::Branch("feat/x".to_string()))
        );
    }

    #[test]
    fn read_git_head_state_detached() {
        let tmp = TempDir::new().expect("tempdir");
        let head = tmp.path().join("HEAD");
        std::fs::write(&head, "0123456789abcdef\n").unwrap();
        assert_eq!(read_git_head_state(&head), Some(GitHeadState::Detached));
    }

    #[test]
    fn resolve_worktree_pinned_path_pins_to_workspace_root_for_prefixes() {
        let tmp = TempDir::new().expect("tempdir");
        let workspace_root = tmp.path().join("workspace");
        let worktree_root = workspace_root.join(".worktrees").join("feat-a");

        let pinned = vec![String::from("docs/impl-plans")];
        let candidate = PathBuf::from("docs/impl-plans/xcodex-qol.md");
        assert_eq!(
            resolve_worktree_pinned_path(
                &worktree_root,
                Some(&workspace_root),
                &pinned,
                &candidate
            ),
            workspace_root.join(candidate),
        );

        let non_pinned = PathBuf::from("src/main.rs");
        assert_eq!(
            resolve_worktree_pinned_path(
                &worktree_root,
                Some(&workspace_root),
                &pinned,
                &non_pinned
            ),
            worktree_root.join(non_pinned),
        );
    }

    #[test]
    fn rewrite_apply_patch_input_for_pinned_paths_rewrites_hunk_headers() {
        let tmp = TempDir::new().expect("tempdir");
        let workspace_root = tmp.path().join("workspace");
        let worktree_root = workspace_root.join(".worktrees").join("feat-a");
        let pinned = vec![String::from("docs/impl-plans/**")];

        let patch = "\
*** Begin Patch
*** Update File: docs/impl-plans/xcodex-qol.md
@@
-before
+after
*** Update File: src/main.rs
@@
-old
+new
*** End Patch";

        let rewritten = rewrite_apply_patch_input_for_pinned_paths(
            patch,
            &worktree_root,
            Some(&workspace_root),
            &pinned,
        );

        let expected_path = workspace_root.join("docs/impl-plans/xcodex-qol.md");
        assert!(rewritten.contains(&format!("*** Update File: {}", expected_path.display())));
        assert!(rewritten.contains("*** Update File: src/main.rs"));
    }

    #[tokio::test]
    async fn list_git_worktrees_returns_empty_outside_repo() {
        let temp_dir = TempDir::new().expect("tempdir");
        let worktrees = list_git_worktrees(temp_dir.path()).await;
        assert!(worktrees.is_empty());
    }

    // Helper function to create a test git repository
    async fn create_test_git_repo(temp_dir: &TempDir) -> PathBuf {
        let repo_path = temp_dir.path().join("repo");
        fs::create_dir(&repo_path).expect("Failed to create repo dir");
        let envs = vec![
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ];

        // Initialize git repo
        Command::new("git")
            .envs(envs.clone())
            .args(["init"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to init git repo");

        // Configure git user (required for commits)
        Command::new("git")
            .envs(envs.clone())
            .args(["config", "user.name", "Test User"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to set git user name");

        Command::new("git")
            .envs(envs.clone())
            .args(["config", "user.email", "test@example.com"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to set git user email");

        // Create a test file and commit it
        let test_file = repo_path.join("test.txt");
        fs::write(&test_file, "test content").expect("Failed to write test file");

        Command::new("git")
            .envs(envs.clone())
            .args(["add", "."])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to add files");

        Command::new("git")
            .envs(envs.clone())
            .args(["commit", "-m", "Initial commit"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to commit");

        repo_path
    }

    #[tokio::test]
    async fn test_recent_commits_non_git_directory_returns_empty() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let entries = recent_commits(temp_dir.path(), 10).await;
        assert!(entries.is_empty(), "expected no commits outside a git repo");
    }

    #[tokio::test]
    async fn test_recent_commits_orders_and_limits() {
        skip_if_sandbox!();
        use tokio::time::Duration;
        use tokio::time::sleep;

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        // Make three distinct commits with small delays to ensure ordering by timestamp.
        fs::write(repo_path.join("file.txt"), "one").unwrap();
        Command::new("git")
            .args(["add", "file.txt"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("git add");
        Command::new("git")
            .args(["commit", "-m", "first change"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("git commit 1");

        sleep(Duration::from_millis(1100)).await;

        fs::write(repo_path.join("file.txt"), "two").unwrap();
        Command::new("git")
            .args(["add", "file.txt"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("git add 2");
        Command::new("git")
            .args(["commit", "-m", "second change"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("git commit 2");

        sleep(Duration::from_millis(1100)).await;

        fs::write(repo_path.join("file.txt"), "three").unwrap();
        Command::new("git")
            .args(["add", "file.txt"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("git add 3");
        Command::new("git")
            .args(["commit", "-m", "third change"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("git commit 3");

        // Request the latest 3 commits; should be our three changes in reverse time order.
        let entries = recent_commits(&repo_path, 3).await;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].subject, "third change");
        assert_eq!(entries[1].subject, "second change");
        assert_eq!(entries[2].subject, "first change");
        // Basic sanity on SHA formatting
        for e in entries {
            assert!(e.sha.len() >= 7 && e.sha.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    async fn create_test_git_repo_with_remote(temp_dir: &TempDir) -> (PathBuf, String) {
        let repo_path = create_test_git_repo(temp_dir).await;
        let remote_path = temp_dir.path().join("remote.git");

        Command::new("git")
            .args(["init", "--bare", remote_path.to_str().unwrap()])
            .output()
            .await
            .expect("Failed to init bare remote");

        Command::new("git")
            .args(["remote", "add", "origin", remote_path.to_str().unwrap()])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to add remote");

        let output = Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to get branch");
        let branch = String::from_utf8(output.stdout).unwrap().trim().to_string();

        Command::new("git")
            .args(["push", "-u", "origin", &branch])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to push initial commit");

        (repo_path, branch)
    }

    #[tokio::test]
    async fn test_collect_git_info_non_git_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let result = collect_git_info(temp_dir.path()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_collect_git_info_git_repository() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        let git_info = collect_git_info(&repo_path)
            .await
            .expect("Should collect git info from repo");

        // Should have commit hash
        assert!(git_info.commit_hash.is_some());
        let commit_hash = git_info.commit_hash.unwrap();
        assert_eq!(commit_hash.len(), 40); // SHA-1 hash should be 40 characters
        assert!(commit_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Should have branch (likely "main" or "master")
        assert!(git_info.branch.is_some());
        let branch = git_info.branch.unwrap();
        assert!(branch == "main" || branch == "master");

        // Repository URL might be None for local repos without remote
        // This is acceptable behavior
    }

    #[tokio::test]
    async fn test_collect_git_info_with_remote() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        // Add a remote origin
        Command::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example/repo.git",
            ])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to add remote");

        let git_info = collect_git_info(&repo_path)
            .await
            .expect("Should collect git info from repo");

        let remote_url_output = Command::new("git")
            .args(["remote", "get-url", "origin"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to read remote url");
        // Some dev environments rewrite remotes (e.g., force SSH), so compare against
        // whatever URL Git reports instead of a fixed placeholder.
        let expected_remote = String::from_utf8(remote_url_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Should have repository URL
        assert_eq!(git_info.repository_url, Some(expected_remote));
    }

    #[tokio::test]
    async fn test_collect_git_info_detached_head() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        // Get the current commit hash
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to get HEAD");
        let commit_hash = String::from_utf8(output.stdout).unwrap().trim().to_string();

        // Checkout the commit directly (detached HEAD)
        Command::new("git")
            .args(["checkout", &commit_hash])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to checkout commit");

        let git_info = collect_git_info(&repo_path)
            .await
            .expect("Should collect git info from repo");

        // Should have commit hash
        assert!(git_info.commit_hash.is_some());
        // Branch should be None for detached HEAD (since rev-parse --abbrev-ref HEAD returns "HEAD")
        assert!(git_info.branch.is_none());
    }

    #[tokio::test]
    async fn test_collect_git_info_with_branch() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        // Create and checkout a new branch
        Command::new("git")
            .args(["checkout", "-b", "feature-branch"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to create branch");

        let git_info = collect_git_info(&repo_path)
            .await
            .expect("Should collect git info from repo");

        // Should have the new branch name
        assert_eq!(git_info.branch, Some("feature-branch".to_string()));
    }

    #[tokio::test]
    async fn test_get_git_working_tree_state_clean_repo() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let (repo_path, branch) = create_test_git_repo_with_remote(&temp_dir).await;

        let remote_sha = Command::new("git")
            .args(["rev-parse", &format!("origin/{branch}")])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to rev-parse remote");
        let remote_sha = String::from_utf8(remote_sha.stdout)
            .unwrap()
            .trim()
            .to_string();

        let state = git_diff_to_remote(&repo_path)
            .await
            .expect("Should collect working tree state");
        assert_eq!(state.sha, GitSha::new(&remote_sha));
        assert!(state.diff.is_empty());
    }

    #[tokio::test]
    async fn test_get_git_working_tree_state_with_changes() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let (repo_path, branch) = create_test_git_repo_with_remote(&temp_dir).await;

        let tracked = repo_path.join("test.txt");
        fs::write(&tracked, "modified").unwrap();
        fs::write(repo_path.join("untracked.txt"), "new").unwrap();

        let remote_sha = Command::new("git")
            .args(["rev-parse", &format!("origin/{branch}")])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to rev-parse remote");
        let remote_sha = String::from_utf8(remote_sha.stdout)
            .unwrap()
            .trim()
            .to_string();

        let state = git_diff_to_remote(&repo_path)
            .await
            .expect("Should collect working tree state");
        assert_eq!(state.sha, GitSha::new(&remote_sha));
        assert!(state.diff.contains("test.txt"));
        assert!(state.diff.contains("untracked.txt"));
    }

    #[tokio::test]
    async fn test_get_git_working_tree_state_branch_fallback() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let (repo_path, _branch) = create_test_git_repo_with_remote(&temp_dir).await;

        Command::new("git")
            .args(["checkout", "-b", "feature"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to create feature branch");
        Command::new("git")
            .args(["push", "-u", "origin", "feature"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to push feature branch");

        Command::new("git")
            .args(["checkout", "-b", "local-branch"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to create local branch");

        let remote_sha = Command::new("git")
            .args(["rev-parse", "origin/feature"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to rev-parse remote");
        let remote_sha = String::from_utf8(remote_sha.stdout)
            .unwrap()
            .trim()
            .to_string();

        let state = git_diff_to_remote(&repo_path)
            .await
            .expect("Should collect working tree state");
        assert_eq!(state.sha, GitSha::new(&remote_sha));
    }

    #[test]
    fn resolve_root_git_project_for_trust_returns_none_outside_repo() {
        let tmp = TempDir::new().expect("tempdir");
        assert!(resolve_root_git_project_for_trust(tmp.path()).is_none());
    }

    #[tokio::test]
    async fn resolve_root_git_project_for_trust_regular_repo_returns_repo_root() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;
        let expected = std::fs::canonicalize(&repo_path).unwrap();

        assert_eq!(
            resolve_root_git_project_for_trust(&repo_path),
            Some(expected.clone())
        );
        let nested = repo_path.join("sub/dir");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(resolve_root_git_project_for_trust(&nested), Some(expected));
    }

    #[tokio::test]
    async fn resolve_root_git_project_for_trust_detects_worktree_and_returns_main_root() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        // Create a linked worktree
        let wt_root = temp_dir.path().join("wt");
        let _ = std::process::Command::new("git")
            .args([
                "worktree",
                "add",
                wt_root.to_str().unwrap(),
                "-b",
                "feature/x",
            ])
            .current_dir(&repo_path)
            .output()
            .expect("git worktree add");

        let expected = std::fs::canonicalize(&repo_path).ok();
        let got = resolve_root_git_project_for_trust(&wt_root)
            .and_then(|p| std::fs::canonicalize(p).ok());
        assert_eq!(got, expected);
        let nested = wt_root.join("nested/sub");
        std::fs::create_dir_all(&nested).unwrap();
        let got_nested =
            resolve_root_git_project_for_trust(&nested).and_then(|p| std::fs::canonicalize(p).ok());
        assert_eq!(got_nested, expected);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn link_shared_dirs_replaces_existing_symlink() {
        skip_if_sandbox!();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        let wt_root = temp_dir.path().join("wt");
        let _ = std::process::Command::new("git")
            .args([
                "worktree",
                "add",
                wt_root.to_str().unwrap(),
                "-b",
                "feature/shared-symlink",
            ])
            .current_dir(&repo_path)
            .output()
            .expect("git worktree add");

        let shared_dir = String::from("notes");
        let wrong_target = wt_root.join("elsewhere");
        std::fs::create_dir_all(&wrong_target).unwrap();
        std::os::unix::fs::symlink(&wrong_target, wt_root.join(&shared_dir)).unwrap();

        let actions =
            link_worktree_shared_dirs(&wt_root, &repo_path, std::slice::from_ref(&shared_dir))
                .await;
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].outcome, SharedDirLinkOutcome::Linked));
        assert!(path_points_to(
            &wt_root.join(&shared_dir),
            &repo_path.join(&shared_dir)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn link_shared_dirs_migrate_includes_ignored_content() {
        skip_if_sandbox!();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let repo_path = create_test_git_repo(&temp_dir).await;

        // Ensure the shared dir is ignored so "untracked only" migration would miss it.
        std::fs::write(repo_path.join(".gitignore"), "notes/\n").unwrap();
        let _ = std::process::Command::new("git")
            .args(["add", ".gitignore"])
            .current_dir(&repo_path)
            .output()
            .expect("git add .gitignore");
        let _ = std::process::Command::new("git")
            .args(["commit", "-m", "add ignore for notes"])
            .current_dir(&repo_path)
            .output()
            .expect("git commit");

        // Create a linked worktree and put ignored content in it.
        let wt_root = temp_dir.path().join("wt");
        let _ = std::process::Command::new("git")
            .args([
                "worktree",
                "add",
                wt_root.to_str().unwrap(),
                "-b",
                "feature/ignored-migrate",
            ])
            .current_dir(&repo_path)
            .output()
            .expect("git worktree add");

        let ignored_dir = wt_root.join("notes");
        std::fs::create_dir_all(&ignored_dir).unwrap();
        std::fs::write(ignored_dir.join("scratch.txt"), "hello").unwrap();

        let shared_dir = String::from("notes");
        let actions = link_worktree_shared_dirs_migrating_untracked(
            &wt_root,
            &repo_path,
            std::slice::from_ref(&shared_dir),
        )
        .await;
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].outcome, SharedDirLinkOutcome::Linked));

        // Ignored content is migrated into workspace root.
        assert!(repo_path.join("notes").join("scratch.txt").is_file());
        assert!(path_points_to(
            &wt_root.join("notes"),
            &repo_path.join("notes")
        ));
    }

    #[test]
    fn resolve_root_git_project_for_trust_non_worktrees_gitdir_returns_none() {
        let tmp = TempDir::new().expect("tempdir");
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(proj.join("nested")).unwrap();

        // `.git` is a file but does not point to a worktrees path
        std::fs::write(
            proj.join(".git"),
            format!(
                "gitdir: {}\n",
                tmp.path().join("some/other/location").display()
            ),
        )
        .unwrap();

        assert!(resolve_root_git_project_for_trust(&proj).is_none());
        assert!(resolve_root_git_project_for_trust(&proj.join("nested")).is_none());
    }

    #[tokio::test]
    async fn test_get_git_working_tree_state_unpushed_commit() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let (repo_path, branch) = create_test_git_repo_with_remote(&temp_dir).await;

        let remote_sha = Command::new("git")
            .args(["rev-parse", &format!("origin/{branch}")])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to rev-parse remote");
        let remote_sha = String::from_utf8(remote_sha.stdout)
            .unwrap()
            .trim()
            .to_string();

        fs::write(repo_path.join("test.txt"), "updated").unwrap();
        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to add file");
        Command::new("git")
            .args(["commit", "-m", "local change"])
            .current_dir(&repo_path)
            .output()
            .await
            .expect("Failed to commit");

        let state = git_diff_to_remote(&repo_path)
            .await
            .expect("Should collect working tree state");
        assert_eq!(state.sha, GitSha::new(&remote_sha));
        assert!(state.diff.contains("updated"));
    }

    #[test]
    fn test_git_info_serialization() {
        let git_info = GitInfo {
            commit_hash: Some("abc123def456".to_string()),
            branch: Some("main".to_string()),
            repository_url: Some("https://github.com/example/repo.git".to_string()),
        };

        let json = serde_json::to_string(&git_info).expect("Should serialize GitInfo");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse JSON");

        assert_eq!(parsed["commit_hash"], "abc123def456");
        assert_eq!(parsed["branch"], "main");
        assert_eq!(
            parsed["repository_url"],
            "https://github.com/example/repo.git"
        );
    }

    #[test]
    fn test_git_info_serialization_with_nones() {
        let git_info = GitInfo {
            commit_hash: None,
            branch: None,
            repository_url: None,
        };

        let json = serde_json::to_string(&git_info).expect("Should serialize GitInfo");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse JSON");

        // Fields with None values should be omitted due to skip_serializing_if
        assert!(!parsed.as_object().unwrap().contains_key("commit_hash"));
        assert!(!parsed.as_object().unwrap().contains_key("branch"));
        assert!(!parsed.as_object().unwrap().contains_key("repository_url"));
    }
}
