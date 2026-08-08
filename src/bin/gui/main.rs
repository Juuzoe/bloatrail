//! The Bloatrail desktop application.
//!
//! A thin shell over the same library the CLI uses: the scanner, the
//! classifier and the cleanup engine are shared, so the two frontends can
//! never disagree about what is safe to remove. Deletion from the GUI always
//! goes to the Recycle Bin; permanent removal exists only in the CLI, behind
//! its explicitly named flag.

// A windowed application, not a console one: launching from Explorer must not
// flash a terminal window.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
#[cfg(feature = "screenshots")]
mod shot;
mod views;

use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Bloatrail")
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([840.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Bloatrail",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
