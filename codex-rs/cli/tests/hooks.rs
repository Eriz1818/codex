use std::fs;

use assert_cmd::Command;
use pretty_assertions::assert_eq;
use tempfile::TempDir;

#[test]
fn hooks_init_is_idempotent_without_force() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "init"])
        .output()?;
    assert!(output.status.success());

    let hooks_dir = codex_home.path().join("hooks");
    let script = hooks_dir.join("log_all_jsonl.py");
    assert!(script.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&script)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    fs::write(
        &script,
        format!("{}\n# marker\n", fs::read_to_string(&script)?),
    )?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "init"])
        .output()?;
    assert!(output.status.success());

    let contents = fs::read_to_string(&script)?;
    assert!(contents.contains("# marker"));

    Ok(())
}

#[test]
fn hooks_list_prints_configured_events_in_stable_order() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;
    fs::write(
        codex_home.path().join("config.toml"),
        r#"
[hooks]
agent_turn_complete = [["python3", "/tmp/hook1.py"]]
tool_call_finished = [["python3", "/tmp/hook2.py"]]
"#,
    )?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "list"])
        .output()?;
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("hooks.session_start:"));
    assert!(stdout.contains("hooks.agent_turn_complete:"));
    assert!(stdout.contains("hooks.tool_call_finished:"));

    let agent_idx = stdout
        .find("hooks.agent_turn_complete:")
        .expect("agent_turn_complete present");
    let tool_idx = stdout
        .find("hooks.tool_call_finished:")
        .expect("tool_call_finished present");
    assert!(tool_idx > agent_idx);

    Ok(())
}
