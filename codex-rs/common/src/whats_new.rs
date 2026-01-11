pub const WHATS_NEW_MD: &str = include_str!("whats_new.md");

pub fn whats_new_bullets_for_version(version: &str) -> Option<Vec<String>> {
    let mut in_section = false;
    let mut bullets = Vec::new();
    let version_token = format!("v{version}");

    for line in WHATS_NEW_MD.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("What's new in") {
            if in_section {
                break;
            }
            if trimmed.contains(&version_token) {
                in_section = true;
            }
            continue;
        }

        if !in_section {
            continue;
        }

        let Some(rest) = trimmed.strip_prefix('-') else {
            continue;
        };
        let bullet = rest.trim();
        if bullet.is_empty() {
            continue;
        }
        bullets.push(bullet.to_string());
    }

    (!bullets.is_empty()).then_some(bullets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn extracts_bullets_for_matching_version() {
        let bullets = whats_new_bullets_for_version("0.2.0").expect("expected bullets");
        assert_eq!(
            bullets,
            vec![
                "Hooks: external hooks (spawn), Python Host “py-box” hooks (persistent), and PyO3 in-proc hooks (advanced)".to_string(),
                "Hooks tooling: guided setup (`xcodex hooks init`), installers for SDKs + samples, and `xcodex hooks test`".to_string(),
                "Hook ecosystem: typed SDK templates (Python/Rust/JS/TS/Go/Ruby/Java), copy/paste gallery, and a JSON Schema bundle".to_string(),
                "Worktrees: switch between git worktrees with `/worktree` (plus shared dirs)".to_string(),
                "⚡Tools: open the tools panel with `Ctrl+O` or `/xtreme`".to_string(),
                "Status + settings: richer `/status` and `/settings` menus (worktrees, tools, toggles)".to_string(),
                "Faster startup when resuming sessions".to_string(),
                "Improved approval prompts in workspace-write mode".to_string(),
                "Fix: better handling for remote arm64 builds".to_string(),
                "Read more: docs/xcodex/releases/0.2.0.md".to_string(),
            ]
        );
    }

    #[test]
    fn returns_none_for_unknown_version() {
        assert_eq!(whats_new_bullets_for_version("9.9.9"), None);
    }
}
