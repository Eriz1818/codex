use std::fs;

use assert_cmd::Command;
use pretty_assertions::assert_eq;
use tempfile::TempDir;

#[test]
fn hooks_init_is_idempotent_without_force() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "init", "external", "--yes"])
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
        .args(["hooks", "init", "external", "--yes"])
        .output()?;
    assert!(output.status.success());

    let contents = fs::read_to_string(&script)?;
    assert!(contents.contains("# marker"));

    Ok(())
}

#[test]
fn hooks_install_legacy_prints_redirect() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "install", "python"])
        .output()?;
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("This install command syntax has changed."));
    assert!(stdout.contains("xcodex hooks install sdks"));

    Ok(())
}

#[test]
fn hooks_install_sdks_writes_with_yes() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "install", "sdks", "python", "--yes"])
        .output()?;
    assert!(output.status.success());

    let hooks_dir = codex_home.path().join("hooks");
    assert!(hooks_dir.join("xcodex_hooks.py").exists());
    assert!(hooks_dir.join("host/python/host.py").exists());

    Ok(())
}

#[test]
fn hooks_install_samples_external_writes_with_yes() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "install", "samples", "external", "--yes"])
        .output()?;
    assert!(output.status.success());

    let hooks_dir = codex_home.path().join("hooks");
    assert!(hooks_dir.join("log_all_jsonl.py").exists());
    assert!(hooks_dir.join("tool_call_summary.py").exists());

    Ok(())
}

#[test]
fn hooks_install_samples_python_host_writes_with_yes() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "install", "samples", "python-host", "--yes"])
        .output()?;
    assert!(output.status.success());

    let hooks_dir = codex_home.path().join("hooks");
    assert!(hooks_dir.join("host/python/host.py").exists());
    assert!(hooks_dir.join("host/python/example_hook.py").exists());

    Ok(())
}

#[test]
fn hooks_install_samples_pyo3_writes_with_yes() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "install", "samples", "pyo3", "--yes"])
        .output()?;
    assert!(output.status.success());

    let hooks_dir = codex_home.path().join("hooks");
    assert!(hooks_dir.join("pyo3_hook.py").exists());

    Ok(())
}

#[test]
fn hooks_pyo3_legacy_subcommands_print_redirects() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "pyo3", "doctor"])
        .output()?;
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("This command has moved."));
    assert!(stdout.contains("Use: xcodex hooks doctor pyo3"));

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "pyo3", "bootstrap"])
        .output()?;
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("This command has moved."));
    assert!(stdout.contains("Use: xcodex hooks build pyo3"));

    Ok(())
}

#[test]
fn hooks_install_samples_pyo3_requires_yes_when_non_interactive()
-> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "install", "samples", "pyo3"])
        .write_stdin("")
        .output()?;
    assert!(output.status.success());

    let hooks_dir = codex_home.path().join("hooks");
    assert!(!hooks_dir.join("pyo3_hook.py").exists());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Re-run with --yes to apply these changes."));

    Ok(())
}

#[test]
fn hooks_init_pyo3_requires_yes_when_non_interactive() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let output = Command::new(codex_utils_cargo_bin::cargo_bin("codex")?)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "init", "pyo3"])
        .write_stdin("")
        .output()?;
    assert!(output.status.success());

    let hooks_dir = codex_home.path().join("hooks");
    assert!(!hooks_dir.join("pyo3_hook.py").exists());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Re-run with --yes to apply these changes."));

    Ok(())
}

#[test]
fn hooks_test_routing_is_non_fatal_when_unconfigured() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;
    let codex_bin = codex_utils_cargo_bin::cargo_bin("codex")?;

    let output = Command::new(&codex_bin)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "test", "external", "--configured-only"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Invoked 0 hook command(s)."));

    let output = Command::new(&codex_bin)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "test", "python-host", "--configured-only"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hooks.host is not enabled; skipping (configured-only)."));

    let output = Command::new(&codex_bin)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "test", "pyo3", "--configured-only"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pyo3 hooks are not enabled; skipping (configured-only)."));

    let output = Command::new(&codex_bin)
        .env("CODEX_HOME", codex_home.path())
        .args(["hooks", "test", "all"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("== external =="));
    assert!(stdout.contains("== python-host =="));
    assert!(stdout.contains("== pyo3 =="));
    assert!(stdout.contains("hooks.host is not enabled; skipping (configured-only)."));
    assert!(stdout.contains("pyo3 hooks are not enabled; skipping (configured-only)."));

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
