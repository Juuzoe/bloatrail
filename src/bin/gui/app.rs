//! Application state and background work.
//!
//! The UI thread never scans and never deletes. Both run on worker threads
//! that report back over a channel; the frame loop polls the channel and the
//! scan's shared counters. Cancellation uses the same [`CancelToken`] the CLI
//! wires to Ctrl+C.

use eframe::egui;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use bloatrail::analysis::Classifier;
use bloatrail::analysis::CleanupSafety;
use bloatrail::cleanup::executor::{ExecutionOptions, ExecutionReport, Executor};
use bloatrail::cleanup::planner::{CleanupGroup, CleanupPlan};
use bloatrail::pattern::ExcludeSet;
use bloatrail::platform::KnownPaths;
use bloatrail::scanner::progress::Counters;
use bloatrail::scanner::tree::NodeId;
use bloatrail::scanner::{self, CancelToken, ScanOptions, ScanResult};

/// Which main view is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// Category breakdown and the directory tree.
    Overview,
    /// The cleanup plan: review, select, remove to the Recycle Bin.
    Cleanup,
    /// Largest files and directories.
    Largest,
}

/// Ranked list shown in the Largest view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LargestMode {
    /// Individual files.
    Files,
    /// Whole directories.
    Directories,
}

/// A completed scan plus everything derived from it.
pub struct Bundle {
    /// The scan itself.
    pub scan: ScanResult,
    /// The cleanup proposal built from it.
    pub plan: CleanupPlan,
    /// Well-known locations, used to abbreviate paths for display.
    pub known: KnownPaths,
}

/// Messages from worker threads.
enum Msg {
    ScanFinished(Box<Result<Bundle, String>>),
    CleanFinished(Box<ExecutionReport>),
    WorkerDied(&'static str),
}

/// Sends [`Msg::WorkerDied`] if a worker unwinds before its normal send.
///
/// Release builds abort on panic, so this matters for debug builds, where a
/// panicking worker would otherwise leave the app in Scanning or cleaning
/// forever with no way out.
struct DeathNotice {
    tx: Sender<Msg>,
    repaint: egui::Context,
    what: &'static str,
    armed: bool,
}

impl DeathNotice {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for DeathNotice {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.tx.send(Msg::WorkerDied(self.what));
            self.repaint.request_repaint();
        }
    }
}

/// Live handles into a scan in progress.
struct ScanJob {
    counters: Arc<Counters>,
    cancel: CancelToken,
    /// The results that were showing before this scan, restored if it fails.
    previous: Option<Arc<Bundle>>,
}

/// What the app is currently doing.
///
/// Results live behind an `Arc` so the frame loop can hold the data and mutate
/// unrelated app state (selection, expansion) in the same pass.
enum Phase {
    Idle,
    Scanning(ScanJob),
    Ready(Arc<Bundle>),
}

/// The desktop application.
pub struct App {
    /// Contents of the folder field.
    pub path_text: String,
    /// Active main view.
    pub view: View,
    /// Files or directories in the Largest view.
    pub largest_mode: LargestMode,
    /// Tree node whose details are showing.
    pub selected_node: Option<NodeId>,
    /// Tree nodes the user has expanded.
    pub expanded: HashSet<NodeId>,
    /// Indices into `plan.groups` the user has ticked.
    pub selected_groups: HashSet<usize>,
    /// Whether the removal confirmation is open.
    pub confirm_open: bool,
    /// Set for one frame after the confirmation opens, to focus Cancel.
    pub confirm_just_opened: bool,
    /// Result of the last preview or removal.
    pub last_report: Option<ExecutionReport>,
    /// Whether a removal is running.
    pub cleaning: bool,
    /// The most recent error, shown in the status bar.
    pub error: Option<String>,
    /// The user asked to close while a removal was running; close when done.
    pub close_after_clean: bool,
    /// Scripted self-screenshot driver; `None` in normal runs.
    pub shot: Option<crate::shot::ShotDriver>,

    phase: Phase,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    scan_elapsed: std::time::Instant,
}

impl App {
    /// Build the app and apply the visual style.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);

        let (tx, rx) = std::sync::mpsc::channel();
        let start_path = dirs::home_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        App {
            path_text: start_path,
            view: View::Overview,
            largest_mode: LargestMode::Files,
            selected_node: None,
            expanded: HashSet::new(),
            selected_groups: HashSet::new(),
            confirm_open: false,
            confirm_just_opened: false,
            last_report: None,
            cleaning: false,
            error: None,
            close_after_clean: false,
            shot: crate::shot::ShotDriver::from_env(),
            phase: Phase::Idle,
            tx,
            rx,
            scan_elapsed: std::time::Instant::now(),
        }
    }

    /// Whether a scan is running.
    pub fn is_scanning(&self) -> bool {
        matches!(self.phase, Phase::Scanning(_))
    }

    /// The finished results, if any.
    pub fn bundle(&self) -> Option<Arc<Bundle>> {
        match &self.phase {
            Phase::Ready(bundle) => Some(Arc::clone(bundle)),
            _ => None,
        }
    }

    /// Live counters while scanning.
    pub fn progress(&self) -> Option<bloatrail::scanner::progress::Snapshot> {
        match &self.phase {
            Phase::Scanning(job) => Some(job.counters.snapshot()),
            _ => None,
        }
    }

    /// Seconds the current scan has been running.
    pub fn scan_seconds(&self) -> f64 {
        self.scan_elapsed.elapsed().as_secs_f64()
    }

    /// Start scanning the folder in the path field.
    pub fn start_scan(&mut self, ctx: &egui::Context) {
        // A scan must not race a removal over the same tree: it would measure
        // a half-deleted state and build a plan pointing at trashed targets.
        if self.is_scanning() || self.cleaning {
            return;
        }
        let trimmed = self.path_text.trim();
        if trimmed.is_empty() {
            self.error = Some("Pick a folder first.".to_string());
            return;
        }
        // Validate before discarding anything: a typo in the path field must
        // not cost the user their current results.
        let root = PathBuf::from(trimmed);
        if !root.is_dir() {
            self.error = Some(format!("`{trimmed}` is not a folder that exists."));
            return;
        }

        self.error = None;
        self.selected_node = None;
        self.expanded.clear();
        self.selected_groups.clear();
        self.last_report = None;
        self.scan_elapsed = std::time::Instant::now();

        let counters = Arc::new(Counters::default());
        let cancel = CancelToken::new();
        let previous = self.bundle();
        let job = ScanJob {
            counters: Arc::clone(&counters),
            cancel: cancel.clone(),
            previous,
        };

        let tx = self.tx.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let notice = DeathNotice {
                tx: tx.clone(),
                repaint: repaint.clone(),
                what: "scan",
                armed: true,
            };
            let options = ScanOptions {
                cancel,
                ..ScanOptions::new(root)
            };
            let classifier = Classifier::with_default_detectors();
            let known = KnownPaths::discover();
            let result = scanner::scan_with_progress(&options, &classifier, &known, counters)
                .map(|scan| {
                    let plan = CleanupPlan::from_scan(&scan);
                    Bundle { scan, plan, known }
                })
                .map_err(|error| error.to_string());
            notice.disarm();
            let _ = tx.send(Msg::ScanFinished(Box::new(result)));
            repaint.request_repaint();
        });

        self.phase = Phase::Scanning(job);
    }

    /// Ask the running scan to stop; partial results arrive normally.
    pub fn cancel_scan(&mut self) {
        if let Phase::Scanning(job) = &self.phase {
            job.cancel.cancel();
        }
    }

    /// Groups currently ticked, in plan order.
    pub fn selection<'a>(&self, plan: &'a CleanupPlan) -> Vec<&'a CleanupGroup> {
        plan.groups
            .iter()
            .enumerate()
            .filter(|(index, group)| self.selected_groups.contains(index) && group.is_selectable())
            .map(|(_, group)| group)
            .collect()
    }

    /// Total bytes and locations in the current selection.
    pub fn selection_totals(&self, plan: &CleanupPlan) -> (u64, usize) {
        let selection = self.selection(plan);
        (
            selection.iter().map(|g| g.bytes).sum(),
            selection.iter().map(|g| g.location_count()).sum(),
        )
    }

    /// Run the executor over the current selection.
    ///
    /// The GUI never deletes permanently: everything goes to the platform
    /// trash, where it can be restored.
    pub fn run_cleanup(&mut self, ctx: &egui::Context, dry_run: bool) {
        let Phase::Ready(bundle) = &self.phase else {
            return;
        };
        if self.cleaning {
            return;
        }

        let bundle = Arc::clone(bundle);
        let root = bundle.plan.root.clone();
        let groups: Vec<CleanupGroup> = self.selection(&bundle.plan).into_iter().cloned().collect();
        if groups.is_empty() {
            return;
        }
        let limit = groups
            .iter()
            .map(|group| group.safety)
            .max()
            .unwrap_or(CleanupSafety::Safe)
            .min(CleanupSafety::Review);

        self.cleaning = true;
        let tx = self.tx.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let notice = DeathNotice {
                tx: tx.clone(),
                repaint: repaint.clone(),
                what: "removal",
                armed: true,
            };
            let classifier = Classifier::with_default_detectors();
            let known = KnownPaths::discover();
            let executor = Executor::new(
                &root,
                &known,
                &classifier,
                ExecutionOptions {
                    dry_run,
                    permanent: false,
                    limit,
                    excludes: ExcludeSet::default(),
                },
            );
            let report = executor.run(groups.iter());
            notice.disarm();
            let _ = tx.send(Msg::CleanFinished(Box::new(report)));
            repaint.request_repaint();
        });
    }

    /// Drain worker messages. Called once per frame.
    pub fn poll(&mut self) {
        while let Ok(message) = self.rx.try_recv() {
            match message {
                Msg::ScanFinished(result) => match *result {
                    Ok(bundle) => {
                        // Expand the first level so the tree is not a wall of
                        // closed rows.
                        self.expanded.insert(bundle.scan.tree.root());
                        self.phase = Phase::Ready(Arc::new(bundle));
                        self.view = View::Overview;
                    }
                    Err(message) => {
                        self.error = Some(message);
                        // A failed scan restores the results it interrupted;
                        // losing them to a typo would be pure punishment.
                        let previous = match std::mem::replace(&mut self.phase, Phase::Idle) {
                            Phase::Scanning(job) => job.previous,
                            other => {
                                self.phase = other;
                                None
                            }
                        };
                        if let Some(bundle) = previous {
                            self.phase = Phase::Ready(bundle);
                        }
                    }
                },
                Msg::CleanFinished(report) => {
                    self.cleaning = false;
                    let was_real = !report.dry_run;
                    self.last_report = Some(*report);
                    if was_real {
                        // The disk changed; the old plan and selection no
                        // longer describe it.
                        self.selected_groups.clear();
                    }
                }
                Msg::WorkerDied(what) => {
                    self.error = Some(format!("the {what} worker stopped unexpectedly"));
                    self.cleaning = false;
                    // Leave a Ready phase alone (a dead cleanup worker does not
                    // invalidate the results); a dead scan restores what it
                    // interrupted.
                    let phase = std::mem::replace(&mut self.phase, Phase::Idle);
                    self.phase = match phase {
                        Phase::Scanning(job) => match job.previous {
                            Some(bundle) => Phase::Ready(bundle),
                            None => Phase::Idle,
                        },
                        other => other,
                    };
                }
            }
        }
    }
}

/// One place for every style decision.
///
/// Deliberate constraints: no gradients, no icon fonts, no rounded cards. The
/// look aims at a working desktop tool — hairline separators, 2px corners,
/// monospace numerals — rather than a marketing page.
fn configure_style(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(12.0, 5.0);
        style.spacing.menu_margin = egui::Margin::same(8.0);
        style.spacing.scroll = egui::style::ScrollStyle::solid();

        let rounding = egui::Rounding::same(2.0);
        style.visuals.widgets.noninteractive.rounding = rounding;
        style.visuals.widgets.inactive.rounding = rounding;
        style.visuals.widgets.hovered.rounding = rounding;
        style.visuals.widgets.active.rounding = rounding;
        style.visuals.widgets.open.rounding = rounding;
        style.visuals.window_rounding = egui::Rounding::same(4.0);
        style.visuals.menu_rounding = egui::Rounding::same(2.0);

        // Focus states must be visible for keyboard use.
        style.visuals.selection.stroke.width = 1.0;
    });
}
