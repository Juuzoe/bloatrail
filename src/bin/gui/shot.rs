//! Self-screenshot driver, used for smoke tests and documentation captures.
//!
//! When `BLOATRAIL_SHOT_DIR` is set the app drives itself: it captures the
//! idle state, scans `BLOATRAIL_SHOT_SCAN` (when given), walks through every
//! view capturing a PNG of each, then exits. Everything flows through the same
//! code paths a person would use — the only synthetic part is the input.
//!
//! Undocumented on purpose: it is test scaffolding, not a feature.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;

use crate::app::{App, View};

/// Where the driver is in its walk through the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Settle(u8),
    Request(&'static str),
    Wait(&'static str),
    StartScan,
    WaitReady,
    PrepareOverview,
    PrepareCleanup,
    RunPreview,
    WaitReport,
    OpenConfirm,
    CloseConfirm,
    PrepareLargest,
    Close,
    Done,
}

/// Scripted sequence of stages after each capture completes.
pub struct ShotDriver {
    dir: PathBuf,
    scan: Option<PathBuf>,
    stage: Stage,
    queue: Vec<Stage>,
}

impl ShotDriver {
    /// Build the driver from the environment, if requested.
    pub fn from_env() -> Option<Self> {
        let dir = std::env::var_os("BLOATRAIL_SHOT_DIR").map(PathBuf::from)?;
        let scan = std::env::var_os("BLOATRAIL_SHOT_SCAN").map(PathBuf::from);

        // `Request` transitions into its own `Wait`, so waits are not queued.
        let mut queue = vec![Stage::Settle(20), Stage::Request("idle")];
        if scan.is_some() {
            queue.extend([
                Stage::StartScan,
                Stage::WaitReady,
                Stage::PrepareOverview,
                Stage::Settle(8),
                Stage::Request("overview"),
                Stage::PrepareCleanup,
                Stage::Settle(8),
                Stage::Request("cleanup"),
                // Exercise the preview and confirmation paths; the preview is
                // a dry run and the dialog is closed without confirming, so
                // nothing on disk changes.
                Stage::RunPreview,
                Stage::WaitReport,
                Stage::Settle(8),
                Stage::Request("cleanup-preview"),
                Stage::OpenConfirm,
                Stage::Settle(8),
                Stage::Request("confirm"),
                Stage::CloseConfirm,
                Stage::PrepareLargest,
                Stage::Settle(8),
                Stage::Request("largest"),
            ]);
        }
        queue.push(Stage::Close);
        queue.reverse(); // popped from the back

        Some(ShotDriver {
            dir,
            scan,
            stage: Stage::Done,
            queue,
        })
    }

    fn advance(&mut self) {
        self.stage = self.queue.pop().unwrap_or(Stage::Done);
    }
}

impl App {
    /// Run one step of the screenshot script. No-op without the env vars.
    pub fn drive_shot(&mut self, ctx: &egui::Context) {
        let Some(mut driver) = self.shot.take() else {
            return;
        };
        // Keep frames flowing; nothing else animates while scripted.
        ctx.request_repaint_after(std::time::Duration::from_millis(30));

        if driver.stage == Stage::Done {
            driver.advance();
        }

        // Collect any screenshot events delivered this frame.
        let images: Vec<Arc<egui::ColorImage>> = ctx.input(|input| {
            input
                .events
                .iter()
                .filter_map(|event| match event {
                    egui::Event::Screenshot { image, .. } => Some(Arc::clone(image)),
                    _ => None,
                })
                .collect()
        });

        match driver.stage {
            Stage::Settle(frames) => {
                if frames == 0 {
                    driver.advance();
                } else {
                    driver.stage = Stage::Settle(frames - 1);
                }
            }
            Stage::Request(name) => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
                driver.stage = Stage::Wait(name);
            }
            Stage::Wait(name) => {
                if let Some(image) = images.first() {
                    save_png(image, &driver.dir.join(format!("{name}.png")));
                    driver.advance();
                }
            }
            Stage::StartScan => {
                if let Some(path) = &driver.scan {
                    self.path_text = path.display().to_string();
                }
                self.start_scan(ctx);
                driver.advance();
            }
            Stage::WaitReady => {
                if self.bundle().is_some() {
                    driver.advance();
                } else if !self.is_scanning() && self.error.is_some() {
                    // The scan failed; capture nothing further, just close.
                    driver.stage = Stage::Close;
                }
            }
            Stage::PrepareOverview => {
                self.view = View::Overview;
                if let Some(bundle) = self.bundle() {
                    let tree = &bundle.scan.tree;
                    self.expanded.insert(tree.root());

                    // Select the largest directory that carries a full
                    // explanation, so the details panel shows the evidence and
                    // the regeneration command rather than an empty state.
                    let target = tree
                        .iter()
                        .filter(|(_, node)| {
                            node.detection.as_ref().is_some_and(|d| {
                                !d.evidence.is_empty() && d.regenerated_by.is_some()
                            })
                        })
                        .max_by_key(|(_, node)| node.total.bytes)
                        .map(|(id, _)| id);

                    if let Some(id) = target {
                        // Expand every ancestor so the selected row is visible.
                        let mut current = tree.node(id).parent;
                        while let Some(parent) = current {
                            self.expanded.insert(parent);
                            current = tree.node(parent).parent;
                        }
                        self.selected_node = Some(id);
                    }
                }
                driver.advance();
            }
            Stage::PrepareCleanup => {
                self.view = View::Cleanup;
                self.selected_node = None;
                if let Some(bundle) = self.bundle() {
                    use bloatrail::analysis::CleanupSafety;
                    self.selected_groups = bundle
                        .plan
                        .groups
                        .iter()
                        .enumerate()
                        .filter(|(_, g)| g.safety == CleanupSafety::Safe && g.is_selectable())
                        .map(|(index, _)| index)
                        .collect();
                }
                driver.advance();
            }
            Stage::RunPreview => {
                self.run_cleanup(ctx, true);
                driver.advance();
            }
            Stage::WaitReport => {
                if !self.cleaning && self.last_report.is_some() {
                    driver.advance();
                }
            }
            Stage::OpenConfirm => {
                self.confirm_open = true;
                self.confirm_just_opened = true;
                driver.advance();
            }
            Stage::CloseConfirm => {
                self.confirm_open = false;
                driver.advance();
            }
            Stage::PrepareLargest => {
                self.view = View::Largest;
                driver.advance();
            }
            Stage::Close => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                driver.stage = Stage::Done;
            }
            Stage::Done => {}
        }

        self.shot = Some(driver);
    }
}

fn save_png(image: &egui::ColorImage, path: &std::path::Path) {
    let [width, height] = image.size;
    let mut raw = Vec::with_capacity(width * height * 4);
    for pixel in &image.pixels {
        raw.extend_from_slice(&[pixel.r(), pixel.g(), pixel.b(), pixel.a()]);
    }
    let Some(buffer) = image::RgbaImage::from_raw(width as u32, height as u32, raw) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = buffer.save(path);
}
