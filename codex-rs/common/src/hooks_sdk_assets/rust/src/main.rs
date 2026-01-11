use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // xCodex hooks kit: Rust template hook (logs payloads to hooks.jsonl).
    //
    // This file is installed under `$CODEX_HOME/hooks/templates/rust/` and is meant
    // as a starting point you copy and edit.
    let payload = codex_hooks_sdk::read_payload_json_from_stdin()?;

    let codex_home = std::env::var("CODEX_HOME")
        .or_else(|_| std::env::var("HOME").map(|home| format!("{home}/.xcodex")))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let out_path = codex_home.join("hooks.jsonl");
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out_path)?;
    serde_json::to_writer(&mut file, &payload)?;
    file.write_all(b"\n")?;
    Ok(())
}
