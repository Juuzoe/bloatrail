//! All rendering.
//!
//! Layout: toolbar on top, navigation on the left, a details panel on the
//! right when a directory is selected, status bar at the bottom, content in
//! the middle. Numbers are monospace and right-aligned; colour carries only
//! the cleanup-safety states, and always next to the words that say the same
//! thing.

use std::sync::Arc;

use bloatrail::analysis::domain::{CleanupSafety, Detection};
use bloatrail::scanner::tree::NodeId;
use bloatrail::units::{format_count, ByteSize};
use eframe::egui;
use eframe::egui::{Align, Align2, Color32, Layout, RichText, Sense};

use crate::app::{App, Bundle, LargestMode, View};

const ROW_HEIGHT: f32 = 22.0;
const TREE_CHILD_LIMIT: usize = 60;

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

fn accent(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(106, 148, 187)
    } else {
        Color32::from_rgb(45, 88, 128)
    }
}

fn on_accent(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(18, 24, 31)
    } else {
        Color32::WHITE
    }
}

fn safety_color(safety: CleanupSafety, dark: bool) -> Color32 {
    match safety {
        CleanupSafety::Safe | CleanupSafety::ProbablySafe => {
            if dark {
                Color32::from_rgb(127, 185, 148)
            } else {
                Color32::from_rgb(30, 100, 60)
            }
        }
        CleanupSafety::Review => {
            if dark {
                Color32::from_rgb(212, 167, 86)
            } else {
                Color32::from_rgb(141, 98, 15)
            }
        }
        CleanupSafety::Dangerous | CleanupSafety::NeverDelete => {
            if dark {
                Color32::from_rgb(222, 133, 138)
            } else {
                Color32::from_rgb(153, 45, 50)
            }
        }
    }
}

fn bar_color(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(96, 118, 138)
    } else {
        Color32::from_rgb(151, 170, 187)
    }
}

fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).monospace()
}

fn dim(ui: &egui::Ui, text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(ui.visuals().weak_text_color())
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.drive_shot(ctx);
        if self.is_scanning() || self.cleaning {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }

        // Closing mid-removal would kill the executor thread between targets.
        // Hold the window until the run finishes, then close on its behalf.
        if ctx.input(|i| i.viewport().close_requested()) && self.cleaning {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_after_clean = true;
        }
        if self.close_after_clean && !self.cleaning {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        let bundle = self.bundle();
        let modal = self.confirm_open;

        egui::TopBottomPanel::top("toolbar")
            .exact_height(44.0)
            .show(ctx, |ui| {
                ui.add_enabled_ui(!modal, |ui| toolbar(self, ui, ctx));
            });

        egui::TopBottomPanel::bottom("status")
            .exact_height(26.0)
            .show(ctx, |ui| {
                status_bar(self, bundle.as_deref(), ui);
            });

        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(150.0)
            .show(ctx, |ui| {
                ui.add_enabled_ui(!modal, |ui| nav(self, bundle.is_some(), ui));
            });

        let details_open =
            bundle.is_some() && self.selected_node.is_some() && self.view == View::Overview;
        egui::SidePanel::right("details")
            .resizable(true)
            .default_width(330.0)
            .width_range(260.0..=460.0)
            .show_animated(ctx, details_open, |ui| {
                if let (Some(bundle), Some(id)) = (bundle.as_deref(), self.selected_node) {
                    ui.add_enabled_ui(!modal, |ui| details(self, bundle, id, ui));
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!modal, |ui| match (&bundle, self.is_scanning()) {
                (_, true) => progress(self, ui),
                (Some(bundle), false) => match self.view {
                    View::Overview => overview(self, bundle, ui),
                    View::Cleanup => cleanup(self, bundle, ui, ctx),
                    View::Largest => largest(self, bundle, ui),
                },
                (None, false) => idle(self, ui),
            });
        });

        if self.confirm_open {
            if let Some(bundle) = bundle.clone() {
                confirm_dialog(self, &bundle, ctx);
            } else {
                self.confirm_open = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chrome
// ---------------------------------------------------------------------------

fn toolbar(app: &mut App, ui: &mut egui::Ui, ctx: &egui::Context) {
    let dark = ui.visuals().dark_mode;
    ui.horizontal_centered(|ui| {
        ui.label(dim(ui, "Folder"));

        let scanning = app.is_scanning();
        // While a removal runs, starting a scan would race the executor over
        // the same tree, so the whole scan affordance goes quiet.
        let busy = scanning || app.cleaning;
        // Reserve room for the two buttons so the field takes the rest.
        let field_width = (ui.available_width() - 200.0).max(160.0);
        let response = ui.add_enabled(
            !busy,
            egui::TextEdit::singleline(&mut app.path_text)
                .desired_width(field_width)
                .font(egui::TextStyle::Monospace),
        );
        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            app.start_scan(ctx);
        }

        if ui
            .add_enabled(!busy, egui::Button::new("Browse…"))
            .clicked()
        {
            let start = std::path::PathBuf::from(app.path_text.trim());
            let mut dialog = rfd::FileDialog::new();
            if start.is_dir() {
                dialog = dialog.set_directory(&start);
            }
            if let Some(folder) = dialog.pick_folder() {
                app.path_text = folder.display().to_string();
            }
        }

        if scanning {
            if ui.button("Cancel").clicked() {
                app.cancel_scan();
            }
        } else {
            let scan =
                egui::Button::new(RichText::new("Scan").color(on_accent(dark))).fill(accent(dark));
            if ui.add_enabled(!busy, scan).clicked() {
                app.start_scan(ctx);
            }
        }
    });
}

fn nav(app: &mut App, has_data: bool, ui: &mut egui::Ui) {
    ui.add_space(8.0);
    for (view, label) in [
        (View::Overview, "Overview"),
        (View::Cleanup, "Cleanup"),
        (View::Largest, "Largest files"),
    ] {
        let enabled = has_data || view == View::Overview;
        let selected = app.view == view;
        if ui
            .add_enabled(enabled, egui::SelectableLabel::new(selected, label))
            .clicked()
        {
            app.view = view;
        }
    }
}

fn status_bar(app: &App, bundle: Option<&Bundle>, ui: &mut egui::Ui) {
    let dark = ui.visuals().dark_mode;
    ui.horizontal_centered(|ui| {
        if let Some(error) = &app.error {
            ui.label(RichText::new(error).color(safety_color(CleanupSafety::Dangerous, dark)));
        } else if app.close_after_clean {
            ui.label(dim(ui, "Finishing the removal, then closing…"));
        } else if app.is_scanning() {
            ui.label(dim(ui, "Scanning…"));
        } else if let Some(bundle) = bundle {
            let scan = &bundle.scan;
            let mut summary = format!(
                "{} in {} files, {} directories",
                ByteSize(scan.totals.bytes),
                format_count(scan.totals.files),
                format_count(scan.totals.dirs),
            );
            if scan.skipped_count > 0 {
                summary.push_str(&format!(" — {} skipped", scan.skipped_count));
            }
            if scan.cancelled {
                summary.push_str(" — stopped early");
            }
            ui.label(dim(ui, summary));
        } else {
            ui.label(dim(ui, "Pick a folder and press Scan."));
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(dim(ui, format!("Bloatrail {}", env!("CARGO_PKG_VERSION"))));
        });
    });
}

// ---------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------

fn idle(_app: &mut App, ui: &mut egui::Ui) {
    ui.add_space(ui.available_height() * 0.35);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new("No scan yet").size(16.0));
        ui.add_space(4.0);
        ui.label(dim(
            ui,
            "Pick a folder above and press Scan. Nothing is written or removed \
             until you ask for it in Cleanup.",
        ));
    });
}

fn progress(app: &mut App, ui: &mut egui::Ui) {
    let Some(snapshot) = app.progress() else {
        return;
    };
    ui.add_space(ui.available_height() * 0.25);
    ui.vertical_centered(|ui| {
        egui::Grid::new("scan-progress")
            .num_columns(2)
            .spacing([28.0, 8.0])
            .show(ui, |ui| {
                let rows = [
                    ("Files", format_count(snapshot.files)),
                    ("Directories", format_count(snapshot.dirs)),
                    ("Scanned", ByteSize(snapshot.bytes).to_string()),
                    (
                        "Speed",
                        bloatrail::units::format_rate(snapshot.bytes, app.scan_seconds()),
                    ),
                ];
                for (label, value) in rows {
                    ui.label(dim(ui, label));
                    ui.label(mono(value).size(15.0));
                    ui.end_row();
                }
            });
        ui.add_space(10.0);
        if !snapshot.current.is_empty() {
            ui.label(dim(ui, bloatrail::output::truncate(&snapshot.current, 70)));
        }
        ui.add_space(12.0);
        if ui.button("Stop and keep results").clicked() {
            app.cancel_scan();
        }
    });
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

fn overview(app: &mut App, bundle: &Arc<Bundle>, ui: &mut egui::Ui) {
    let dark = ui.visuals().dark_mode;
    let scan = &bundle.scan;

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.label(mono(ByteSize(scan.totals.bytes).to_string()).size(24.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let summary = format!(
                "{} files, {} directories, {}",
                format_count(scan.totals.files),
                format_count(scan.totals.dirs),
                bloatrail::output::terminal::format_duration(scan.duration),
            );
            ui.label(dim(ui, summary));
        });
    });
    ui.label(dim(ui, bundle.known.display(&scan.root)));
    if scan.cancelled {
        ui.label(
            RichText::new("Stopped early; figures cover only what was reached.")
                .color(safety_color(CleanupSafety::Review, dark)),
        );
    }
    ui.add_space(8.0);
    ui.separator();

    // Category breakdown: label, proportional bar, size.
    let ranked = scan.categories.ranked();
    let largest = ranked
        .first()
        .map(|(_, bytes, _)| *bytes)
        .max(Some(1))
        .unwrap_or(1);
    for (category, bytes, _) in ranked.iter().take(12) {
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), 18.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(190.0, 16.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.add(egui::Label::new(RichText::new(category.label())).truncate());
                    },
                );
                let bar_width = (ui.available_width() - 100.0).max(60.0);
                draw_bar(
                    ui,
                    *bytes as f32 / largest as f32,
                    bar_width,
                    bar_color(dark),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(mono(ByteSize(*bytes).to_string()));
                });
            },
        );
    }

    ui.add_space(8.0);
    ui.separator();
    ui.label(dim(ui, "Directories. Click a row for details."));
    ui.add_space(2.0);

    egui::ScrollArea::vertical()
        .id_salt("overview-tree")
        .auto_shrink(false)
        .show(ui, |ui| {
            draw_node(app, bundle, ui, scan.tree.root(), 0);
        });
}

fn draw_bar(ui: &mut egui::Ui, fraction: f32, width: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 9.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, 1.0, ui.visuals().faint_bg_color);
    let fraction = fraction.clamp(0.0, 1.0);
    if fraction > 0.0 {
        let mut fill = rect;
        fill.set_width((rect.width() * fraction).max(2.0));
        ui.painter().rect_filled(fill, 1.0, color);
    }
}

fn draw_node(app: &mut App, bundle: &Arc<Bundle>, ui: &mut egui::Ui, id: NodeId, depth: usize) {
    let dark = ui.visuals().dark_mode;
    let tree = &bundle.scan.tree;
    let node = tree.node(id);
    let has_children = !node.children.is_empty();
    let open = app.expanded.contains(&id);

    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), ROW_HEIGHT),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.add_space(depth as f32 * 14.0 + 2.0);

            if has_children {
                let symbol = if open { "\u{2212}" } else { "+" };
                let toggle = egui::Button::new(mono(symbol))
                    .min_size(egui::vec2(18.0, 18.0))
                    .frame(false);
                if ui.add(toggle).clicked() {
                    if open {
                        app.expanded.remove(&id);
                    } else {
                        app.expanded.insert(id);
                    }
                }
            } else {
                ui.add_space(22.0);
            }

            let name = if node.parent.is_none() {
                bundle.known.display(&bundle.scan.root)
            } else {
                node.name.to_string()
            };
            let selected = app.selected_node == Some(id);
            if ui
                .selectable_label(selected, bloatrail::output::truncate(&name, 52))
                .clicked()
            {
                app.selected_node = if selected { None } else { Some(id) };
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(4.0);
                ui.label(mono(ByteSize(node.total.bytes).to_string()));
                ui.add_space(8.0);
                if let Some(detection) = &node.detection {
                    ui.label(
                        RichText::new(detection.reason.as_ref())
                            .color(safety_color(detection.cleanup, dark))
                            .small(),
                    );
                }
            });
        },
    );

    if open && has_children {
        for child in node.children.iter().take(TREE_CHILD_LIMIT) {
            draw_node(app, bundle, ui, *child, depth + 1);
        }
        let hidden = node.children.len().saturating_sub(TREE_CHILD_LIMIT);
        if hidden > 0 {
            ui.horizontal(|ui| {
                ui.add_space(depth as f32 * 14.0 + 40.0);
                ui.label(dim(ui, format!("… {hidden} more, largest first")));
            });
        }
    }
}

fn details(app: &mut App, bundle: &Bundle, id: NodeId, ui: &mut egui::Ui) {
    let dark = ui.visuals().dark_mode;
    let tree = &bundle.scan.tree;
    if id as usize >= tree.len() {
        return;
    }
    let node = tree.node(id);
    let path = tree.path_of(id);

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Details").strong());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("Close").clicked() {
                app.selected_node = None;
            }
        });
    });
    ui.separator();

    egui::ScrollArea::vertical()
        .id_salt("details")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.label(mono(bundle.known.display(&path)).small());
            ui.add_space(6.0);

            egui::Grid::new("details-stats")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.label(dim(ui, "Size"));
                    ui.label(mono(ByteSize(node.total.bytes).to_string()));
                    ui.end_row();
                    ui.label(dim(ui, "Files"));
                    ui.label(mono(format_count(node.total.files)));
                    ui.end_row();
                    ui.label(dim(ui, "Directories"));
                    ui.label(mono(format_count(node.total.dirs)));
                    ui.end_row();
                });

            ui.add_space(8.0);
            match &node.detection {
                Some(detection) => detection_block(detection, dark, ui),
                None => {
                    ui.label(dim(
                        ui,
                        "No classification. Bloatrail only proposes removing what it can \
                         identify, so nothing here is offered for cleanup.",
                    ));
                }
            }

            ui.add_space(10.0);
            if ui.button("Show in file manager").clicked() {
                open_in_file_manager(&path);
            }
        });
}

fn detection_block(detection: &Detection, dark: bool, ui: &mut egui::Ui) {
    ui.label(RichText::new(detection.reason.as_ref()).strong());
    ui.label(RichText::new(detection.cleanup.label()).color(safety_color(detection.cleanup, dark)));
    ui.label(dim(
        ui,
        bloatrail::cleanup::safety::describe_permission(detection),
    ));

    if !detection.evidence.is_empty() {
        ui.add_space(6.0);
        ui.label(dim(ui, "Why"));
        for line in &detection.evidence {
            ui.label(RichText::new(line.as_ref()).small());
        }
    }

    if let Some(command) = &detection.regenerated_by {
        ui.add_space(6.0);
        ui.label(dim(ui, "Regenerated by"));
        ui.label(mono(command.as_ref()).small());
    }
}

fn open_in_file_manager(path: &std::path::Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(path).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(path).spawn();
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

fn cleanup(app: &mut App, bundle: &Arc<Bundle>, ui: &mut egui::Ui, ctx: &egui::Context) {
    let dark = ui.visuals().dark_mode;
    let plan = &bundle.plan;

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Potential cleanup").size(16.0));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(dim(
                ui,
                format!(
                    "recoverable {}, safe without review {}",
                    plan.recoverable(),
                    plan.automatically_safe()
                ),
            ));
        });
    });
    ui.add_space(4.0);
    ui.separator();

    let footer_height = 40.0;
    let list_height = (ui.available_height() - footer_height).max(120.0);

    egui::ScrollArea::vertical()
        .id_salt("cleanup-list")
        .auto_shrink(false)
        .max_height(list_height)
        .show(ui, |ui| {
            for safety in [
                CleanupSafety::Safe,
                CleanupSafety::ProbablySafe,
                CleanupSafety::Review,
            ] {
                let rows: Vec<usize> = plan
                    .groups
                    .iter()
                    .enumerate()
                    .filter(|(_, group)| group.safety == safety)
                    .map(|(index, _)| index)
                    .collect();
                if rows.is_empty() {
                    continue;
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new(safety.label())
                        .color(safety_color(safety, dark))
                        .small(),
                );
                for index in rows {
                    group_row(app, bundle, index, ui);
                }
            }

            if !plan.protected.is_empty() {
                ui.add_space(8.0);
                ui.label(
                    RichText::new("NOT OFFERED")
                        .color(safety_color(CleanupSafety::NeverDelete, dark))
                        .small(),
                );
                for row in &plan.protected {
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), ROW_HEIGHT),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.add_space(26.0);
                            ui.label(dim(ui, row.label.clone()));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.add_space(4.0);
                                ui.label(mono(ByteSize(row.bytes).to_string()));
                            });
                        },
                    );
                }
            }

            if let Some(report) = app.last_report.clone() {
                ui.add_space(10.0);
                ui.separator();
                report_block(&report, bundle, ui);
            }
            ui.add_space(8.0);
        });

    ui.separator();
    ui.horizontal(|ui| {
        let busy = app.cleaning;
        if ui
            .add_enabled(!busy, egui::Button::new("Select safe"))
            .clicked()
        {
            app.selected_groups = plan
                .groups
                .iter()
                .enumerate()
                .filter(|(_, g)| g.safety == CleanupSafety::Safe && g.is_selectable())
                .map(|(index, _)| index)
                .collect();
        }
        if ui.add_enabled(!busy, egui::Button::new("Clear")).clicked() {
            app.selected_groups.clear();
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let (bytes, locations) = app.selection_totals(plan);
            let any = bytes > 0 || locations > 0;
            let busy = app.cleaning;

            let remove =
                egui::Button::new(RichText::new("Move to Recycle Bin…").color(on_accent(dark)))
                    .fill(accent(dark));
            if ui.add_enabled(any && !busy, remove).clicked() {
                app.confirm_open = true;
                app.confirm_just_opened = true;
            }
            if ui
                .add_enabled(any && !busy, egui::Button::new("Preview"))
                .clicked()
            {
                app.run_cleanup(ctx, true);
            }
            if busy {
                ui.label(dim(ui, "Working…"));
            } else if any {
                ui.label(dim(
                    ui,
                    format!(
                        "{} in {} location{}",
                        ByteSize(bytes),
                        locations,
                        if locations == 1 { "" } else { "s" }
                    ),
                ));
            }
        });
    });
}

fn group_row(app: &mut App, bundle: &Arc<Bundle>, index: usize, ui: &mut egui::Ui) {
    let group = &bundle.plan.groups[index];
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), ROW_HEIGHT),
        Layout::left_to_right(Align::Center),
        |ui| {
            if group.is_selectable() {
                let mut checked = app.selected_groups.contains(&index);
                // Frozen while a removal runs: the running job took a snapshot,
                // so edits here would neither affect it nor survive it.
                if ui
                    .add_enabled(!app.cleaning, egui::Checkbox::new(&mut checked, ""))
                    .changed()
                {
                    if checked {
                        app.selected_groups.insert(index);
                    } else {
                        app.selected_groups.remove(&index);
                    }
                }
            } else {
                ui.add_space(26.0);
            }

            ui.label(bloatrail::output::truncate(&group.title, 56));
            let note = if group.external {
                "external tool".to_string()
            } else if group.location_count() > 1 {
                format!("{} locations", group.location_count())
            } else if let Some(target) = group.targets.first() {
                bloatrail::output::elide_start(&bundle.known.display(&target.path), 40)
            } else {
                String::new()
            };
            if !note.is_empty() {
                ui.label(dim(ui, note).small());
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(4.0);
                ui.label(mono(ByteSize(group.bytes).to_string()));
            });
        },
    );
}

fn report_block(
    report: &bloatrail::cleanup::executor::ExecutionReport,
    bundle: &Bundle,
    ui: &mut egui::Ui,
) {
    let dark = ui.visuals().dark_mode;
    let heading = if report.dry_run {
        "Preview: nothing was changed"
    } else {
        "Moved to Recycle Bin"
    };
    ui.label(RichText::new(heading).strong());

    for removal in report.removed.iter().take(14) {
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            ui.label(
                mono(bloatrail::output::elide_start(
                    &bundle.known.display(&removal.path),
                    58,
                ))
                .small(),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(mono(ByteSize(removal.bytes).to_string()).small());
            });
        });
    }
    if report.removed.len() > 14 {
        ui.label(dim(ui, format!("… {} more", report.removed.len() - 14)));
    }

    for failure in &report.failures {
        ui.label(
            RichText::new(format!(
                "Refused: {} — {}",
                bundle.known.display(&failure.path),
                failure.reason
            ))
            .color(safety_color(CleanupSafety::Review, dark))
            .small(),
        );
    }

    let verb = if report.dry_run {
        "Would free"
    } else {
        "Freed"
    };
    ui.label(format!(
        "{verb} {} across {} location{}.",
        ByteSize(report.bytes_freed),
        report.removed.len(),
        if report.removed.len() == 1 { "" } else { "s" }
    ));
    if !report.dry_run && !report.removed.is_empty() {
        ui.label(dim(
            ui,
            "Restore anything you want back from the Recycle Bin.",
        ));
    }
}

fn confirm_dialog(app: &mut App, bundle: &Arc<Bundle>, ctx: &egui::Context) {
    // Dim everything behind the dialog.
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Middle,
        egui::Id::new("confirm-dim"),
    ));
    painter.rect_filled(ctx.screen_rect(), 0.0, Color32::from_black_alpha(90));

    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        app.confirm_open = false;
        return;
    }

    let (bytes, locations) = app.selection_totals(&bundle.plan);
    let selection: Vec<(String, u64)> = app
        .selection(&bundle.plan)
        .iter()
        .map(|group| (group.title.clone(), group.bytes))
        .collect();

    egui::Window::new("Move to Recycle Bin")
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            let dark = ui.visuals().dark_mode;
            ui.set_min_width(360.0);
            ui.label(format!(
                "Move {} in {} location{} to the Recycle Bin?",
                ByteSize(bytes),
                locations,
                if locations == 1 { "" } else { "s" }
            ));
            ui.add_space(6.0);
            for (title, group_bytes) in selection.iter().take(8) {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new(title).small());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(mono(ByteSize(*group_bytes).to_string()).small());
                    });
                });
            }
            if selection.len() > 8 {
                ui.label(dim(ui, format!("… {} more groups", selection.len() - 8)));
            }
            ui.add_space(6.0);
            ui.label(dim(
                ui,
                "Bloatrail re-checks every location before removing it. You can \
                 restore items from the Recycle Bin.",
            ));
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                let cancel = ui.button("Cancel");
                if app.confirm_just_opened {
                    cancel.request_focus();
                    app.confirm_just_opened = false;
                }
                if cancel.clicked() {
                    app.confirm_open = false;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let go = egui::Button::new(
                        RichText::new("Move to Recycle Bin").color(on_accent(dark)),
                    )
                    .fill(accent(dark));
                    if ui.add(go).clicked() {
                        app.confirm_open = false;
                        app.run_cleanup(ctx, false);
                    }
                });
            });
        });
}

// ---------------------------------------------------------------------------
// Largest
// ---------------------------------------------------------------------------

fn largest(app: &mut App, bundle: &Arc<Bundle>, ui: &mut egui::Ui) {
    let dark = ui.visuals().dark_mode;
    let scan = &bundle.scan;

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        for (mode, label) in [
            (LargestMode::Files, "Files"),
            (LargestMode::Directories, "Directories"),
        ] {
            if ui
                .selectable_label(app.largest_mode == mode, label)
                .clicked()
            {
                app.largest_mode = mode;
            }
        }
    });
    ui.add_space(4.0);
    ui.separator();

    let now = bloatrail::timefmt::now_seconds();
    egui::ScrollArea::vertical()
        .id_salt("largest")
        .auto_shrink(false)
        .show(ui, |ui| match app.largest_mode {
            LargestMode::Files => {
                for (rank, entry) in scan.largest_files.iter().take(100).enumerate() {
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), ROW_HEIGHT),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.label(mono(format!("{:>3}.", rank + 1)));
                            ui.label(
                                mono(bloatrail::output::elide_start(
                                    &bundle.known.display(&entry.path),
                                    64,
                                ))
                                .small(),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.add_space(4.0);
                                ui.label(mono(ByteSize(entry.size).to_string()));
                                ui.add_space(8.0);
                                let mut annotation = entry.category.label().to_string();
                                if let Some(modified) = entry.modified {
                                    annotation.push_str(&format!(
                                        ", {}",
                                        bloatrail::timefmt::humanize_age(modified, now)
                                    ));
                                }
                                ui.label(dim(ui, annotation).small());
                            });
                        },
                    );
                }
            }
            LargestMode::Directories => {
                for (rank, (id, bytes)) in scan.largest_directories(60).into_iter().enumerate() {
                    let node = scan.tree.node(id);
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), ROW_HEIGHT),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.label(mono(format!("{:>3}.", rank + 1)));
                            ui.label(
                                mono(bloatrail::output::elide_start(
                                    &bundle.known.display(&scan.tree.path_of(id)),
                                    64,
                                ))
                                .small(),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.add_space(4.0);
                                ui.label(mono(ByteSize(bytes).to_string()));
                                ui.add_space(8.0);
                                if let Some(detection) = &node.detection {
                                    ui.label(
                                        RichText::new(detection.reason.as_ref())
                                            .color(safety_color(detection.cleanup, dark))
                                            .small(),
                                    );
                                }
                            });
                        },
                    );
                }
            }
        });
}
