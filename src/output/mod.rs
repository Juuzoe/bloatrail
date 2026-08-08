//! Terminal presentation.
//!
//! Rendering is kept strictly downstream of analysis: nothing in this module is
//! imported by the scanner, the classifier or the cleanup engine, and nothing
//! here makes decisions. It receives finished results and turns them into text.

pub mod json;
pub mod terminal;
pub mod tree;

use std::io::{IsTerminal, Write};

use anstyle::{AnsiColor, Style};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Product banner. Deliberately small — one line, no ASCII art.
pub const BRAND: &str = "BLOATRAIL";

/// How much colour to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// Decide from the environment.
    Auto,
    /// Never emit escape sequences.
    Never,
    /// Always emit escape sequences.
    Always,
}

/// The glyph set in use.
#[derive(Debug, Clone, Copy)]
pub struct Glyphs {
    /// `├── `
    pub branch: &'static str,
    /// `└── `
    pub last: &'static str,
    /// `│   `
    pub vertical: &'static str,
    /// Four spaces.
    pub blank: &'static str,
    /// Filled bar segment.
    pub bar_full: &'static str,
    /// Empty bar segment.
    pub bar_empty: &'static str,
}

const UNICODE_GLYPHS: Glyphs = Glyphs {
    branch: "├── ",
    last: "└── ",
    vertical: "│   ",
    blank: "    ",
    bar_full: "█",
    bar_empty: "░",
};

const ASCII_GLYPHS: Glyphs = Glyphs {
    branch: "|-- ",
    last: "`-- ",
    vertical: "|   ",
    blank: "    ",
    bar_full: "#",
    bar_empty: ".",
};

/// Everything a renderer needs to know about the terminal.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    color: bool,
    ascii: bool,
    glyphs: Glyphs,
    /// Usable width in columns.
    pub width: usize,
}

impl Default for Theme {
    fn default() -> Self {
        Theme::new(ColorMode::Never, true)
    }
}

impl Theme {
    /// Resolve a theme from the requested colour mode.
    #[must_use]
    pub fn new(mode: ColorMode, ascii: bool) -> Self {
        Theme {
            color: resolve_color(mode),
            ascii,
            glyphs: if ascii { ASCII_GLYPHS } else { UNICODE_GLYPHS },
            width: terminal_width().unwrap_or(100).clamp(40, 200),
        }
    }

    /// Whether output is restricted to ASCII.
    #[must_use]
    pub fn ascii(&self) -> bool {
        self.ascii
    }

    /// Whether colour is enabled.
    #[must_use]
    pub fn color(&self) -> bool {
        self.color
    }

    /// The active glyph set.
    #[must_use]
    pub fn glyphs(&self) -> Glyphs {
        self.glyphs
    }

    /// Wrap `text` in `style` when colour is enabled.
    #[must_use]
    pub fn paint(&self, style: Style, text: &str) -> String {
        if !self.color || text.is_empty() {
            return text.to_string();
        }
        format!("{}{}{}", style.render(), text, style.render_reset())
    }

    /// Bold section heading.
    #[must_use]
    pub fn heading(&self, text: &str) -> String {
        self.paint(Style::new().bold(), text)
    }

    /// Secondary text.
    #[must_use]
    pub fn dim(&self, text: &str) -> String {
        self.paint(Style::new().dimmed(), text)
    }

    /// Something that can be removed safely.
    #[must_use]
    pub fn safe(&self, text: &str) -> String {
        self.paint(Style::new().fg_color(Some(AnsiColor::Green.into())), text)
    }

    /// Something that needs a human decision.
    #[must_use]
    pub fn review(&self, text: &str) -> String {
        self.paint(Style::new().fg_color(Some(AnsiColor::Yellow.into())), text)
    }

    /// Something that must not be removed.
    #[must_use]
    pub fn danger(&self, text: &str) -> String {
        self.paint(Style::new().fg_color(Some(AnsiColor::Red.into())), text)
    }

    /// Neutral informational highlight.
    #[must_use]
    pub fn info(&self, text: &str) -> String {
        self.paint(Style::new().fg_color(Some(AnsiColor::Cyan.into())), text)
    }

    /// Colour a piece of text according to a cleanup classification.
    #[must_use]
    pub fn by_safety(&self, safety: crate::analysis::CleanupSafety, text: &str) -> String {
        use crate::analysis::CleanupSafety::*;
        match safety {
            Safe | ProbablySafe => self.safe(text),
            Review => self.review(text),
            Dangerous | NeverDelete => self.danger(text),
        }
    }

    /// Marker glyph for a cleanup classification, in the active glyph set.
    #[must_use]
    pub fn safety_glyph(&self, safety: crate::analysis::CleanupSafety) -> &'static str {
        if self.ascii {
            safety.ascii_glyph()
        } else {
            safety.glyph()
        }
    }

    /// Draw a proportional bar `width` cells wide.
    #[must_use]
    pub fn bar(&self, fraction: f64, width: usize) -> String {
        let fraction = fraction.clamp(0.0, 1.0);
        let mut filled = ((fraction * width as f64).round() as usize).min(width);
        // A non-zero quantity should never render as an entirely empty bar: the
        // reader would conclude there is nothing there at all.
        if filled == 0 && fraction > 0.0 {
            filled = 1;
        }
        let mut bar = String::with_capacity(width * 3);
        for _ in 0..filled {
            bar.push_str(self.glyphs.bar_full);
        }
        for _ in filled..width {
            bar.push_str(self.glyphs.bar_empty);
        }
        bar
    }
}

fn resolve_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Never => false,
        ColorMode::Always => true,
        ColorMode::Auto => {
            // https://no-color.org — any value, including an empty one, disables.
            if std::env::var_os("NO_COLOR").is_some() {
                return false;
            }
            if std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| v != "0") {
                return true;
            }
            if std::env::var("TERM").is_ok_and(|term| term == "dumb") {
                return false;
            }
            std::io::stdout().is_terminal()
        }
    }
}

/// Terminal width in columns, when it can be determined.
#[must_use]
pub fn terminal_width() -> Option<usize> {
    terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| usize::from(w))
}

/// Write a fully rendered report to stdout.
///
/// Output goes through `anstream`, which enables virtual-terminal processing on
/// Windows consoles and strips escapes when stdout is redirected.
///
/// # Errors
///
/// Propagates write failures other than a closed pipe, which is treated as a
/// normal end of output (`bloatrail scan | head` should not print an error).
pub fn emit(text: &str) -> std::io::Result<()> {
    let mut out = anstream::AutoStream::auto(std::io::stdout().lock());
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// How many terminal columns `text` occupies.
///
/// Not the same as its character count: CJK ideographs and many emoji are two
/// columns wide, so counting characters silently breaks every aligned table
/// containing a non-Latin filename.
#[must_use]
pub fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/// Pad `text` to `width` display columns.
#[must_use]
pub fn pad_right(text: &str, width: usize) -> String {
    let used = display_width(text);
    if used >= width {
        return text.to_string();
    }
    let mut padded = String::with_capacity(text.len() + width - used);
    padded.push_str(text);
    for _ in used..width {
        padded.push(' ');
    }
    padded
}

/// Right-align `text` within `width` display columns.
#[must_use]
pub fn pad_left(text: &str, width: usize) -> String {
    let used = display_width(text);
    if used >= width {
        return text.to_string();
    }
    let mut padded = String::with_capacity(text.len() + width - used);
    for _ in used..width {
        padded.push(' ');
    }
    padded.push_str(text);
    padded
}

/// Shorten a path from the left so the informative tail stays visible.
#[must_use]
pub fn elide_start(text: &str, width: usize) -> String {
    if display_width(text) <= width || width < 4 {
        return text.to_string();
    }

    // Take characters from the end until one more would overflow the budget.
    let budget = width - 1;
    let mut used = 0usize;
    let mut start = text.len();
    for (index, ch) in text.char_indices().rev() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + ch_width > budget {
            break;
        }
        used += ch_width;
        start = index;
    }

    let mut out = String::with_capacity(text.len() - start + 4);
    out.push('…');
    out.push_str(&text[start..]);
    out
}

/// Shorten text from the right.
#[must_use]
pub fn truncate(text: &str, width: usize) -> String {
    if display_width(text) <= width || width == 0 {
        return text.to_string();
    }

    let budget = width.saturating_sub(1);
    let mut used = 0usize;
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + ch_width > budget {
            break;
        }
        used += ch_width;
        out.push(ch);
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::CleanupSafety;

    #[test]
    fn no_color_theme_emits_plain_text() {
        let theme = Theme::new(ColorMode::Never, false);
        assert_eq!(theme.heading("Storage"), "Storage");
        assert_eq!(theme.safe("ok"), "ok");
        assert!(!theme.color());
    }

    #[test]
    fn colour_theme_wraps_text_in_escapes() {
        let theme = Theme::new(ColorMode::Always, false);
        let painted = theme.danger("stop");
        assert!(painted.contains("stop"));
        assert!(painted.len() > "stop".len());
    }

    #[test]
    fn bars_are_proportional_and_bounded() {
        let theme = Theme::new(ColorMode::Never, true);
        assert_eq!(theme.bar(0.0, 4), "....");
        assert_eq!(theme.bar(1.0, 4), "####");
        assert_eq!(theme.bar(0.5, 4), "##..");
        assert_eq!(theme.bar(5.0, 4), "####");
        assert_eq!(theme.bar(-1.0, 4), "....");
    }

    #[test]
    fn a_tiny_but_nonzero_share_still_shows_something() {
        let theme = Theme::new(ColorMode::Never, true);
        assert_eq!(theme.bar(0.001, 20), "#...................");
        assert_eq!(theme.bar(0.0, 20), "....................");
    }

    #[test]
    fn ascii_mode_uses_ascii_glyphs_everywhere() {
        let theme = Theme::new(ColorMode::Never, true);
        assert_eq!(theme.glyphs().branch, "|-- ");
        assert_eq!(theme.safety_glyph(CleanupSafety::Safe), "+");
        assert_eq!(theme.safety_glyph(CleanupSafety::NeverDelete), "x");
    }

    #[test]
    fn unicode_mode_uses_box_drawing() {
        let theme = Theme::new(ColorMode::Never, false);
        assert_eq!(theme.glyphs().branch, "├── ");
        assert_eq!(theme.safety_glyph(CleanupSafety::Safe), "✓");
    }

    #[test]
    fn padding_counts_columns_not_bytes() {
        assert_eq!(pad_right("ab", 5), "ab   ");
        assert_eq!(pad_left("ab", 5), "   ab");
        assert_eq!(display_width(&pad_right("ααα", 5)), 5);
        assert_eq!(pad_right("toolong", 3), "toolong");
    }

    #[test]
    fn wide_characters_occupy_two_columns() {
        // Each ideograph is two columns, so three of them fill six.
        assert_eq!(display_width("プロジェクト"), 12);
        assert_eq!(display_width(&pad_right("日本語", 10)), 10);
        assert_eq!(display_width(&pad_left("日本語", 10)), 10);
    }

    #[test]
    fn elision_keeps_the_tail_of_a_path() {
        let elided = elide_start("/very/long/path/to/a/file.txt", 12);
        assert!(display_width(&elided) <= 12);
        assert!(elided.ends_with("file.txt"));
        assert!(elided.starts_with('…'));
    }

    #[test]
    fn elision_and_truncation_respect_wide_characters() {
        let wide = "/home/dev/プロジェクト/データ/報告書.pdf";
        for width in [10usize, 15, 20, 25] {
            assert!(
                display_width(&elide_start(wide, width)) <= width,
                "elide_start overflowed at width {width}"
            );
            assert!(
                display_width(&truncate(wide, width)) <= width,
                "truncate overflowed at width {width}"
            );
        }
    }

    #[test]
    fn truncation_keeps_the_head() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
