use std::fs;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn xcodex_exec_requires_first_run_setup() -> Result<(), Box<dyn std::error::Error>> {
    let codex_home = TempDir::new()?;

    let codex_bin = codex_utils_cargo_bin::cargo_bin("codex")?;
    let xcodex_dir = TempDir::new()?;
    let xcodex_path = if cfg!(windows) {
        xcodex_dir.path().join("xcodex.exe")
    } else {
        xcodex_dir.path().join("xcodex")
    };
    fs::copy(&codex_bin, &xcodex_path)?;

    Command::new(&xcodex_path)
        .env("CODEX_HOME", codex_home.path())
        .args(["exec", "hello"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("xcodex first-run setup required"));

    Ok(())
}
