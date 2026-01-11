use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::Path;
use std::path::PathBuf;

/// Shared installer for the xCodex hooks kit.
///
/// This module is used by:
/// - `xcodex hooks install sdks ...` (headless-friendly)
/// - `/hooks install sdks ...` inside the TUI/TUI2 (convenience wrapper)
///
/// The installer vendors small helper files and templates into `$CODEX_HOME/hooks/`,
/// so hook authors can start from readable, well-commented examples without
/// needing external package installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HookSdk {
    Python,
    Rust,
    JavaScript,
    TypeScript,
    Go,
    Ruby,
    Java,
}

impl HookSdk {
    pub fn id(self) -> &'static str {
        match self {
            HookSdk::Python => "python",
            HookSdk::Rust => "rust",
            HookSdk::JavaScript => "javascript",
            HookSdk::TypeScript => "typescript",
            HookSdk::Go => "go",
            HookSdk::Ruby => "ruby",
            HookSdk::Java => "java",
        }
    }

    pub fn aliases(self) -> &'static [&'static str] {
        match self {
            HookSdk::Python => &["python", "py"],
            HookSdk::Rust => &["rust", "rs"],
            HookSdk::JavaScript => &["javascript", "js", "node"],
            HookSdk::TypeScript => &["typescript", "ts"],
            HookSdk::Go => &["go", "golang"],
            HookSdk::Ruby => &["ruby", "rb"],
            HookSdk::Java => &["java"],
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            HookSdk::Python => "Python helper + template hook",
            HookSdk::Rust => "Cargo hook template (serde_json)",
            HookSdk::JavaScript => "Node.js helper + template hook (ESM)",
            HookSdk::TypeScript => "TypeScript types + template hook (uses Node helper)",
            HookSdk::Go => "Go module template (encoding/json)",
            HookSdk::Ruby => "Ruby helper + template hook (JSON stdlib)",
            HookSdk::Java => "Maven template (Jackson)",
        }
    }
}

pub fn all_hook_sdks() -> Vec<HookSdk> {
    vec![
        HookSdk::Python,
        HookSdk::Rust,
        HookSdk::JavaScript,
        HookSdk::TypeScript,
        HookSdk::Go,
        HookSdk::Ruby,
        HookSdk::Java,
    ]
}

impl std::str::FromStr for HookSdk {
    type Err = HookSdkParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim().to_ascii_lowercase();
        for sdk in all_hook_sdks() {
            if sdk.aliases().iter().any(|alias| *alias == value) {
                return Ok(sdk);
            }
        }
        Err(HookSdkParseError { value })
    }
}

#[derive(Debug, Clone)]
pub struct HookSdkParseError {
    value: String,
}

impl fmt::Display for HookSdkParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown hook SDK: {}", self.value)
    }
}

impl std::error::Error for HookSdkParseError {}

#[derive(Debug, Clone)]
pub struct InstallReport {
    pub codex_home: PathBuf,
    pub hooks_dir: PathBuf,
    pub wrote: Vec<PathBuf>,
    pub skipped: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannedInstallAction {
    Create,
    Overwrite,
    SkipExisting,
}

#[derive(Debug, Clone)]
pub struct PlannedInstallFile {
    pub path: PathBuf,
    pub action: PlannedInstallAction,
    pub executable: bool,
}

#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub codex_home: PathBuf,
    pub hooks_dir: PathBuf,
    pub files: Vec<PlannedInstallFile>,
}

#[derive(Debug, Clone, Copy)]
struct Asset {
    rel_path: &'static str,
    content: &'static str,
    executable: bool,
}

pub fn plan_install_hook_sdks(
    codex_home: &Path,
    targets: &[HookSdk],
    force: bool,
) -> io::Result<InstallPlan> {
    let hooks_dir = codex_home.join("hooks");

    let mut assets: BTreeMap<&'static str, Asset> = BTreeMap::new();
    for sdk in targets {
        for asset in assets_for(*sdk) {
            assets.insert(asset.rel_path, asset);
        }
    }

    let mut files = Vec::new();
    for (_rel, asset) in assets {
        let path = hooks_dir.join(asset.rel_path);
        let action = if path.exists() {
            if force {
                PlannedInstallAction::Overwrite
            } else {
                PlannedInstallAction::SkipExisting
            }
        } else {
            PlannedInstallAction::Create
        };
        files.push(PlannedInstallFile {
            path,
            action,
            executable: asset.executable,
        });
    }

    Ok(InstallPlan {
        codex_home: codex_home.to_path_buf(),
        hooks_dir,
        files,
    })
}

pub fn install_hook_sdks(
    codex_home: &Path,
    targets: &[HookSdk],
    force: bool,
) -> io::Result<InstallReport> {
    // Writes are intentionally scoped under `$CODEX_HOME/hooks/` to avoid modifying
    // arbitrary locations on disk.
    let hooks_dir = codex_home.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let mut assets: BTreeMap<&'static str, Asset> = BTreeMap::new();
    for sdk in targets {
        for asset in assets_for(*sdk) {
            assets.insert(asset.rel_path, asset);
        }
    }

    let mut wrote = Vec::new();
    let mut skipped = Vec::new();

    for (_rel, asset) in assets {
        let out_path = hooks_dir.join(asset.rel_path);
        if out_path.exists() && !force {
            skipped.push(out_path);
            continue;
        }

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&out_path, asset.content)?;
        if asset.executable {
            set_executable(&out_path)?;
        }

        wrote.push(out_path);
    }

    Ok(InstallReport {
        codex_home: codex_home.to_path_buf(),
        hooks_dir,
        wrote,
        skipped,
    })
}

pub fn format_install_plan(plan: &InstallPlan) -> io::Result<String> {
    fn describe(action: PlannedInstallAction) -> &'static str {
        match action {
            PlannedInstallAction::Create => "create",
            PlannedInstallAction::Overwrite => "overwrite",
            PlannedInstallAction::SkipExisting => "skip (exists)",
        }
    }

    let mut out = String::new();
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
    Ok(out)
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

fn assets_for(sdk: HookSdk) -> Vec<Asset> {
    match sdk {
        HookSdk::Python => vec![
            Asset {
                rel_path: "xcodex_hooks.py",
                content: include_str!("hooks_sdk_assets/python/xcodex_hooks.py"),
                executable: false,
            },
            Asset {
                rel_path: "xcodex_hooks_types.py",
                content: include_str!("hooks_sdk_assets/python/xcodex_hooks_types.py"),
                executable: false,
            },
            Asset {
                rel_path: "xcodex_hooks_models.py",
                content: include_str!("hooks_sdk_assets/python/xcodex_hooks_models.py"),
                executable: false,
            },
            Asset {
                rel_path: "xcodex_hooks_runtime.py",
                content: include_str!("hooks_sdk_assets/python/xcodex_hooks_runtime.py"),
                executable: false,
            },
            Asset {
                rel_path: "host/python/host.py",
                content: include_str!("hooks_sdk_assets/python/hook_host.py"),
                executable: true,
            },
            Asset {
                rel_path: "host/python/example_hook.py",
                content: include_str!("hooks_sdk_assets/python/hook_host_example.py"),
                executable: false,
            },
            Asset {
                rel_path: "templates/python/log_jsonl.py",
                content: include_str!("hooks_sdk_assets/python/template_hook.py"),
                executable: true,
            },
        ],
        HookSdk::JavaScript => vec![
            Asset {
                rel_path: "xcodex_hooks.mjs",
                content: include_str!("hooks_sdk_assets/js/xcodex_hooks.mjs"),
                executable: false,
            },
            Asset {
                rel_path: "xcodex_hooks.d.ts",
                content: include_str!("hooks_sdk_assets/js/xcodex_hooks.d.ts"),
                executable: false,
            },
            Asset {
                rel_path: "templates/js/log_jsonl.mjs",
                content: include_str!("hooks_sdk_assets/js/template_hook.mjs"),
                executable: true,
            },
        ],
        HookSdk::TypeScript => vec![
            Asset {
                rel_path: "xcodex_hooks.mjs",
                content: include_str!("hooks_sdk_assets/js/xcodex_hooks.mjs"),
                executable: false,
            },
            Asset {
                rel_path: "xcodex_hooks.d.ts",
                content: include_str!("hooks_sdk_assets/js/xcodex_hooks.d.ts"),
                executable: false,
            },
            Asset {
                rel_path: "templates/ts/log_jsonl.ts",
                content: include_str!("hooks_sdk_assets/js/template_hook.ts"),
                executable: false,
            },
        ],
        HookSdk::Ruby => vec![
            Asset {
                rel_path: "xcodex_hooks.rb",
                content: include_str!("hooks_sdk_assets/ruby/xcodex_hooks.rb"),
                executable: false,
            },
            Asset {
                rel_path: "templates/ruby/log_jsonl.rb",
                content: include_str!("hooks_sdk_assets/ruby/template_hook.rb"),
                executable: true,
            },
        ],
        HookSdk::Go => vec![
            Asset {
                rel_path: "templates/go/go.mod",
                content: include_str!("hooks_sdk_assets/go/go.mod"),
                executable: false,
            },
            Asset {
                rel_path: "templates/go/README.md",
                content: include_str!("hooks_sdk_assets/go/README.md"),
                executable: false,
            },
            Asset {
                rel_path: "templates/go/hooksdk/hooksdk.go",
                content: include_str!("hooks_sdk_assets/go/hooksdk/hooksdk.go"),
                executable: false,
            },
            Asset {
                rel_path: "templates/go/hooksdk/types.go",
                content: include_str!("hooks_sdk_assets/go/hooksdk/types.go"),
                executable: false,
            },
            Asset {
                rel_path: "templates/go/cmd/log_jsonl/main.go",
                content: include_str!("hooks_sdk_assets/go/cmd/log_jsonl/main.go"),
                executable: false,
            },
        ],
        HookSdk::Rust => vec![
            Asset {
                rel_path: "sdk/rust/Cargo.toml",
                content: include_str!("../../hooks-sdk/Cargo.install.toml"),
                executable: false,
            },
            Asset {
                rel_path: "sdk/rust/src/lib.rs",
                content: include_str!("../../hooks-sdk/src/lib.rs"),
                executable: false,
            },
            Asset {
                rel_path: "sdk/rust/src/generated.rs",
                content: include_str!("../../hooks-sdk/src/generated.rs"),
                executable: false,
            },
            Asset {
                rel_path: "templates/rust/Cargo.toml",
                content: include_str!("hooks_sdk_assets/rust/Cargo.install.toml"),
                executable: false,
            },
            Asset {
                rel_path: "templates/rust/README.md",
                content: include_str!("hooks_sdk_assets/rust/README.md"),
                executable: false,
            },
            Asset {
                rel_path: "templates/rust/src/main.rs",
                content: include_str!("hooks_sdk_assets/rust/src/main.rs"),
                executable: false,
            },
        ],
        HookSdk::Java => vec![
            Asset {
                rel_path: "templates/java/pom.xml",
                content: include_str!("hooks_sdk_assets/java/pom.xml"),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/README.md",
                content: include_str!("hooks_sdk_assets/java/README.md"),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/pom.xml",
                content: include_str!("hooks_sdk_assets/java/sdk/pom.xml"),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/HookReader.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/HookReader.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/HookParser.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/HookParser.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/HookEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/HookEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/UnknownHookEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/UnknownHookEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/AgentTurnCompleteEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/AgentTurnCompleteEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ApprovalRequestedEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ApprovalRequestedEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/SessionStartEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/SessionStartEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/SessionEndEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/SessionEndEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ModelRequestStartedEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ModelRequestStartedEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ModelResponseCompletedEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ModelResponseCompletedEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ToolCallStartedEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ToolCallStartedEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ToolCallFinishedEvent.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/ToolCallFinishedEvent.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/sdk/src/main/java/dev/xcodex/hooks/sdk/TokenUsage.java",
                content: include_str!(
                    "hooks_sdk_assets/java/sdk/src/main/java/dev/xcodex/hooks/sdk/TokenUsage.java"
                ),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/template/pom.xml",
                content: include_str!("hooks_sdk_assets/java/template/pom.xml"),
                executable: false,
            },
            Asset {
                rel_path: "templates/java/template/src/main/java/dev/xcodex/hooks/LogJsonlHook.java",
                content: include_str!(
                    "hooks_sdk_assets/java/template/src/main/java/dev/xcodex/hooks/LogJsonlHook.java"
                ),
                executable: false,
            },
        ],
    }
}

pub fn format_install_report(report: &InstallReport) -> io::Result<String> {
    use std::fmt::Write;

    let mut out = String::new();
    writeln!(&mut out, "CODEX_HOME: {}", report.codex_home.display())
        .map_err(|_| io::Error::other("formatting failed"))?;
    writeln!(&mut out, "Hooks dir: {}", report.hooks_dir.display())
        .map_err(|_| io::Error::other("formatting failed"))?;

    if report.wrote.is_empty() {
        writeln!(&mut out, "Wrote 0 files.").map_err(|_| io::Error::other("formatting failed"))?;
    } else {
        writeln!(&mut out, "Wrote {} file(s):", report.wrote.len())
            .map_err(|_| io::Error::other("formatting failed"))?;
        for path in &report.wrote {
            writeln!(&mut out, "- {}", path.display())
                .map_err(|_| io::Error::other("formatting failed"))?;
        }
    }

    if !report.skipped.is_empty() {
        writeln!(
            &mut out,
            "Skipped {} existing file(s) (use --force to overwrite):",
            report.skipped.len()
        )
        .map_err(|_| io::Error::other("formatting failed"))?;
        for path in &report.skipped {
            writeln!(&mut out, "- {}", path.display())
                .map_err(|_| io::Error::other("formatting failed"))?;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;
    use tempfile::TempDir;

    fn tool_works(tool: &str, version_arg: &str) -> bool {
        Command::new(tool)
            .arg(version_arg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn escape_json_string(input: &str) -> String {
        input.replace('\\', "\\\\").replace('"', "\\\"")
    }

    fn run_script_with_envelope(
        tool: &str,
        script_path: &Path,
        codex_home: &Path,
    ) -> io::Result<String> {
        let marker_key = "__xcodex_smoke_test_marker__";
        let marker_value = "marker-1234567890";

        let payload_path = codex_home.join("payload.json");
        let full_payload = format!(
            "{{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"SessionStart\",\"xcodex_event_type\":\"session-start\",\"cwd\":\"/tmp\",\"{marker_key}\":\"{marker_value}\"}}"
        );
        std::fs::write(&payload_path, full_payload)?;

        let payload_path_json = escape_json_string(payload_path.to_string_lossy().as_ref());
        let envelope = format!("{{\"payload_path\":\"{payload_path_json}\"}}");

        let hooks_jsonl = codex_home.join("hooks.jsonl");
        assert!(!hooks_jsonl.exists());

        let mut child = Command::new(tool)
            .arg(script_path)
            .env("CODEX_HOME", codex_home)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("stdin"))?;
        stdin.write_all(envelope.as_bytes())?;
        drop(stdin);

        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let log = std::fs::read_to_string(&hooks_jsonl)?;
        assert!(log.contains(marker_key));
        assert!(log.contains(marker_value));
        Ok(log)
    }

    #[test]
    fn installs_python_sdk_assets() -> io::Result<()> {
        let home = TempDir::new()?;
        let report = install_hook_sdks(home.path(), &[HookSdk::Python], false)?;
        assert!(
            report
                .wrote
                .iter()
                .any(|path| path.ends_with("hooks/xcodex_hooks.py"))
        );
        Ok(())
    }

    #[test]
    fn installs_go_sdk_assets() -> io::Result<()> {
        let home = TempDir::new()?;
        let report = install_hook_sdks(home.path(), &[HookSdk::Go], false)?;
        assert!(
            report
                .wrote
                .iter()
                .any(|path| path.ends_with("hooks/templates/go/hooksdk/types.go"))
        );
        Ok(())
    }

    #[test]
    fn installs_rust_sdk_assets() -> io::Result<()> {
        let home = TempDir::new()?;
        let report = install_hook_sdks(home.path(), &[HookSdk::Rust], false)?;
        assert!(
            report
                .wrote
                .iter()
                .any(|path| path.ends_with("hooks/sdk/rust/src/lib.rs"))
        );
        assert!(
            report
                .wrote
                .iter()
                .any(|path| path.ends_with("hooks/templates/rust/Cargo.toml"))
        );
        Ok(())
    }

    #[test]
    fn installs_java_sdk_assets() -> io::Result<()> {
        let home = TempDir::new()?;
        let report = install_hook_sdks(home.path(), &[HookSdk::Java], false)?;
        assert!(
            report
                .wrote
                .iter()
                .any(|path| path.ends_with("hooks/templates/java/sdk/pom.xml"))
        );
        assert!(
            report
                .wrote
                .iter()
                .any(|path| path.ends_with("hooks/templates/java/template/pom.xml"))
        );
        Ok(())
    }

    #[test]
    fn install_skips_existing_without_force() -> io::Result<()> {
        let home = TempDir::new()?;
        let hooks_dir = home.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;
        std::fs::write(hooks_dir.join("xcodex_hooks.py"), "junk")?;

        let report = install_hook_sdks(home.path(), &[HookSdk::Python], false)?;
        assert!(
            report
                .skipped
                .iter()
                .any(|path| path.ends_with("xcodex_hooks.py"))
        );
        Ok(())
    }

    #[test]
    fn install_overwrites_existing_with_force() -> io::Result<()> {
        let home = TempDir::new()?;
        let hooks_dir = home.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir)?;
        let out_path = hooks_dir.join("xcodex_hooks.py");
        std::fs::write(&out_path, "junk")?;

        let report = install_hook_sdks(home.path(), &[HookSdk::Python], true)?;
        assert!(report.wrote.iter().any(|path| path == &out_path));

        let contents = std::fs::read_to_string(&out_path)?;
        assert_eq!(contents.contains("def read_payload"), true);
        Ok(())
    }

    #[test]
    fn python_template_hook_runs() -> io::Result<()> {
        if !tool_works("python3", "--version") {
            return Ok(());
        }

        let home = TempDir::new()?;
        install_hook_sdks(home.path(), &[HookSdk::Python], false)?;

        let hooks_dir = home.path().join("hooks");
        let output = Command::new("python3")
            .arg("-c")
            .arg("import xcodex_hooks_models; xcodex_hooks_models.parse_hook_payload({'schema_version':1,'event_id':'e','timestamp':'t','session_id':'th','transcript_path':'','permission_mode':'default','hook_event_name':'SessionStart','xcodex_event_type':'session-start','cwd':'/tmp'})")
            .env("PYTHONPATH", &hooks_dir)
            .stdin(Stdio::null())
            .output()?;
        assert!(
            output.status.success(),
            "python import failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let script_path = home.path().join("hooks/templates/python/log_jsonl.py");
        run_script_with_envelope("python3", &script_path, home.path())?;
        Ok(())
    }

    #[test]
    fn python_hook_host_runs() -> io::Result<()> {
        if !tool_works("python3", "--version") {
            return Ok(());
        }

        let home = TempDir::new()?;
        install_hook_sdks(home.path(), &[HookSdk::Python], false)?;

        let hooks_dir = home.path().join("hooks");
        let host_path = hooks_dir.join("host/python/host.py");
        let example_path = hooks_dir.join("host/python/example_hook.py");

        let input = r#"{"schema_version":1,"type":"hook-event","seq":1,"event":{"schema_version":1,"event_id":"e","timestamp":"t","session_id":"th","transcript_path":"","permission_mode":"default","hook_event_name":"PostToolUse","xcodex_event_type":"tool-call-finished","turn_id":"tu","cwd":"/tmp","tool_name":"Bash","tool_use_id":"c","tool_response":null,"status":"completed","duration_ms":1,"success":true,"output_bytes":0}}"#;

        let mut child = Command::new("python3")
            .arg("-u")
            .arg(&host_path)
            .arg(&example_path)
            .env("CODEX_HOME", home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("stdin not available"))?;
            writeln!(&mut stdin, "{input}")?;
        }

        let status = child.wait()?;
        assert!(status.success(), "python host exited with {status:?}");

        let out_path = home.path().join("hooks-host-tool-calls.log");
        let contents = std::fs::read_to_string(out_path)?;
        assert!(contents.contains("tool=Bash"));
        Ok(())
    }

    #[test]
    fn node_template_hook_runs() -> io::Result<()> {
        if !tool_works("node", "--version") {
            return Ok(());
        }

        let home = TempDir::new()?;
        install_hook_sdks(home.path(), &[HookSdk::JavaScript], false)?;

        let script_path = home.path().join("hooks/templates/js/log_jsonl.mjs");
        run_script_with_envelope("node", &script_path, home.path())?;
        Ok(())
    }

    #[test]
    fn ruby_template_hook_runs() -> io::Result<()> {
        if !tool_works("ruby", "--version") {
            return Ok(());
        }

        let home = TempDir::new()?;
        install_hook_sdks(home.path(), &[HookSdk::Ruby], false)?;

        let script_path = home.path().join("hooks/templates/ruby/log_jsonl.rb");
        run_script_with_envelope("ruby", &script_path, home.path())?;
        Ok(())
    }

    #[test]
    fn typescript_template_imports_installed_helper() -> io::Result<()> {
        let home = TempDir::new()?;
        install_hook_sdks(home.path(), &[HookSdk::TypeScript], false)?;

        let template = home.path().join("hooks/templates/ts/log_jsonl.ts");
        let contents = std::fs::read_to_string(template)?;
        assert!(contents.contains(r#"from "../../xcodex_hooks.mjs""#));
        Ok(())
    }
}
