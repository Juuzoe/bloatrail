//! Live scan progress.
//!
//! Progress must never become the bottleneck it is reporting on, so the hot
//! path only ever performs relaxed atomic increments. A dedicated thread wakes
//! ten times a second, reads the counters and redraws a fixed block of lines on
//! stderr. If stderr is not a terminal, nothing is drawn and nothing is spent.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::units::{format_bytes, format_count, format_rate};

/// Counters written by scanner threads and read by the renderer.
#[derive(Debug, Default)]
pub struct Counters {
    files: AtomicU64,
    dirs: AtomicU64,
    bytes: AtomicU64,
    skipped: AtomicU64,
    current: Mutex<String>,
}

impl Counters {
    /// Record a file of `bytes` bytes.
    #[inline]
    pub fn file(&self, bytes: u64) {
        self.files.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a directory.
    #[inline]
    pub fn dir(&self) {
        self.dirs.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an inaccessible location.
    #[inline]
    pub fn skipped(&self) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish the directory currently being scanned.
    ///
    /// Called only for shallow directories, so the lock is uncontended in
    /// practice and never appears on the per-file path.
    pub fn set_current(&self, path: &str) {
        if let Ok(mut guard) = self.current.lock() {
            guard.clear();
            guard.push_str(path);
        }
    }

    /// A consistent-enough snapshot for rendering.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            files: self.files.load(Ordering::Relaxed),
            dirs: self.dirs.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            current: self
                .current
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default(),
        }
    }
}

/// A point-in-time view of the counters.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Files seen so far.
    pub files: u64,
    /// Directories seen so far.
    pub dirs: u64,
    /// Bytes accounted for so far.
    pub bytes: u64,
    /// Locations that could not be read.
    pub skipped: u64,
    /// Directory currently being traversed.
    pub current: String,
}

/// Owns the render thread and shuts it down cleanly on drop.
pub struct ProgressReporter {
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ProgressReporter {
    /// Start a reporter. Rendering happens only when `enabled` and stderr is a
    /// terminal.
    #[must_use]
    pub fn start(enabled: bool) -> Self {
        let counters = Arc::new(Counters::default());
        let stop = Arc::new(AtomicBool::new(false));

        let render = enabled && std::io::stderr().is_terminal();
        let handle = if render {
            let counters = Arc::clone(&counters);
            let stop = Arc::clone(&stop);
            Some(std::thread::spawn(move || render_loop(&counters, &stop)))
        } else {
            None
        };

        ProgressReporter {
            counters,
            stop,
            handle,
        }
    }

    /// A progress reporter that renders nothing.
    #[must_use]
    pub fn disabled() -> Self {
        ProgressReporter {
            counters: Arc::new(Counters::default()),
            stop: Arc::new(AtomicBool::new(true)),
            handle: None,
        }
    }

    /// Handle scanner threads write to.
    #[must_use]
    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    /// Stop rendering and erase the progress block.
    pub fn finish(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ProgressReporter {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Number of lines the progress block occupies.
const LINES: usize = 6;

fn render_loop(counters: &Counters, stop: &AtomicBool) {
    let started = Instant::now();
    let mut drawn = false;

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let snapshot = counters.snapshot();
        // Wait until there is something worth showing; short scans should not
        // flash a progress block at all.
        if snapshot.files == 0 && snapshot.dirs == 0 {
            continue;
        }
        if started.elapsed() < Duration::from_millis(250) {
            continue;
        }
        draw(&snapshot, started.elapsed().as_secs_f64(), drawn);
        drawn = true;
    }

    if drawn {
        erase();
    }
}

fn draw(snapshot: &Snapshot, elapsed: f64, redraw: bool) {
    let width = crate::output::terminal_width().unwrap_or(80);
    let mut out = String::with_capacity(512);

    if redraw {
        // Move back to the top of the block.
        out.push_str(&format!("\x1b[{LINES}A"));
    }

    let label_width = 14;
    let line = |label: &str, value: &str, out: &mut String| {
        out.push_str("\x1b[2K");
        let text = format!("  {label:<label_width$}{value}");
        push_truncated(out, &text, width);
        out.push('\n');
    };

    let mut body = String::new();
    line("Scanning", "", &mut body);
    line("Files", &format_count(snapshot.files), &mut body);
    line("Directories", &format_count(snapshot.dirs), &mut body);
    line("Scanned", &format_bytes(snapshot.bytes), &mut body);
    line("Speed", &format_rate(snapshot.bytes, elapsed), &mut body);
    line("Current", &snapshot.current, &mut body);
    out.push_str(&body);

    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(out.as_bytes());
    let _ = stderr.flush();
}

fn erase() {
    let mut out = String::new();
    out.push_str(&format!("\x1b[{LINES}A"));
    for _ in 0..LINES {
        out.push_str("\x1b[2K\n");
    }
    out.push_str(&format!("\x1b[{LINES}A"));
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(out.as_bytes());
    let _ = stderr.flush();
}

/// Append `text`, truncating on a character boundary so multi-byte paths never
/// produce mangled output.
fn push_truncated(out: &mut String, text: &str, width: usize) {
    if text.chars().count() <= width {
        out.push_str(text);
        return;
    }
    let keep = width.saturating_sub(1);
    for ch in text.chars().take(keep) {
        out.push(ch);
    }
    out.push('…');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let counters = Counters::default();
        counters.file(100);
        counters.file(200);
        counters.dir();
        counters.skipped();
        counters.set_current("~/Developer");

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.files, 2);
        assert_eq!(snapshot.bytes, 300);
        assert_eq!(snapshot.dirs, 1);
        assert_eq!(snapshot.skipped, 1);
        assert_eq!(snapshot.current, "~/Developer");
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        let mut out = String::new();
        push_truncated(&mut out, "ααααααααββββ", 5);
        assert_eq!(out.chars().count(), 5);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn short_text_is_not_truncated() {
        let mut out = String::new();
        push_truncated(&mut out, "short", 20);
        assert_eq!(out, "short");
    }

    #[test]
    fn disabled_reporter_starts_no_thread() {
        let mut reporter = ProgressReporter::disabled();
        reporter.counters().file(1);
        reporter.finish();
    }
}
