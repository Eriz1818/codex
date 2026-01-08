use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::live_wrap::take_prefix_by_width;
use crate::render::renderable::Renderable;

pub(crate) struct UnifiedExecFooter {
    hooks: Vec<String>,
    processes: Vec<String>,
}

impl UnifiedExecFooter {
    pub(crate) fn new() -> Self {
        Self {
            hooks: Vec::new(),
            processes: Vec::new(),
        }
    }

    pub(crate) fn set_processes(&mut self, processes: Vec<String>) -> bool {
        if self.processes == processes {
            return false;
        }
        self.processes = processes;
        true
    }

    pub(crate) fn set_hooks(&mut self, hooks: Vec<String>) -> bool {
        if self.hooks == hooks {
            return false;
        }
        self.hooks = hooks;
        true
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.processes.is_empty() && self.hooks.is_empty()
    }

    fn render_lines(&self, width: u16) -> Vec<Line<'static>> {
        if (self.processes.is_empty() && self.hooks.is_empty()) || width < 4 {
            return Vec::new();
        }

        let mut parts = Vec::new();
        let count = self.processes.len();
        if count > 0 {
            let plural = if count == 1 { "" } else { "s" };
            parts.push(format!("{count} background terminal{plural} running"));
        }
        let hook_count = self.hooks.len();
        if hook_count > 0 {
            let plural = if hook_count == 1 { "" } else { "s" };
            parts.push(format!("{hook_count} hook{plural} running"));
        }
        if count > 0 {
            parts.push(String::from("/ps to view"));
        }
        if hook_count > 0 {
            parts.push(String::from("/hooks to view"));
        }

        let message = format!("  {}", parts.join(" · "));
        let (truncated, _, _) = take_prefix_by_width(&message, width as usize);
        vec![Line::from(truncated.dim())]
    }
}

impl Renderable for UnifiedExecFooter {
    fn render(&self, area: Rect, buf: &mut Buffer) {
        if area.is_empty() {
            return;
        }

        Paragraph::new(self.render_lines(area.width)).render(area, buf);
    }

    fn desired_height(&self, width: u16) -> u16 {
        self.render_lines(width).len() as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;
    use pretty_assertions::assert_eq;

    #[test]
    fn desired_height_empty() {
        let footer = UnifiedExecFooter::new();
        assert_eq!(footer.desired_height(40), 0);
    }

    #[test]
    fn render_more_sessions() {
        let mut footer = UnifiedExecFooter::new();
        footer.set_processes(vec!["rg \"foo\" src".to_string()]);
        let width = 50;
        let height = footer.desired_height(width);
        let mut buf = Buffer::empty(Rect::new(0, 0, width, height));
        footer.render(Rect::new(0, 0, width, height), &mut buf);
        assert_snapshot!("render_more_sessions", format!("{buf:?}"));
    }

    #[test]
    fn render_many_sessions() {
        let mut footer = UnifiedExecFooter::new();
        footer.set_processes((0..123).map(|idx| format!("cmd {idx}")).collect());
        let width = 50;
        let height = footer.desired_height(width);
        let mut buf = Buffer::empty(Rect::new(0, 0, width, height));
        footer.render(Rect::new(0, 0, width, height), &mut buf);
        assert_snapshot!("render_many_sessions", format!("{buf:?}"));
    }

    #[test]
    fn render_hooks_only() {
        let mut footer = UnifiedExecFooter::new();
        footer.set_hooks(vec!["agent-turn-complete · hook.sh".to_string()]);
        let width = 50;
        let height = footer.desired_height(width);
        let mut buf = Buffer::empty(Rect::new(0, 0, width, height));
        footer.render(Rect::new(0, 0, width, height), &mut buf);
        assert_snapshot!("render_hooks_only", format!("{buf:?}"));
    }
}
