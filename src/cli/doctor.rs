//! `bloatrail doctor` — a read-only health check.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::Context;
use crate::doctor::Thresholds;
use crate::output::{json, terminal};

/// Arguments for `bloatrail doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Directory to examine. Defaults to the current directory.
    pub path: Option<PathBuf>,

    /// Do not query Docker.
    #[arg(long)]
    pub no_docker: bool,

    /// List every location the scan could not read.
    #[arg(long)]
    pub show_skipped: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the path cannot be scanned or the output cannot be written.
pub fn run(context: &Context, args: &DoctorArgs) -> Result<()> {
    let root = context.resolve(args.path.as_ref())?;
    let scan = context.scan(root.clone())?;

    let docker = if args.no_docker {
        crate::docker::DockerStatus::NotChecked
    } else {
        crate::docker::status()
    };
    let disk = crate::platform::disk_usage(&scan.root);
    let report =
        crate::doctor::diagnose(&scan, &context.known, &docker, disk, &Thresholds::default());

    if context.json {
        let document = json::doctor_document(&scan.root, &report, &docker);
        return context.emit(&json::to_string(&document)?);
    }

    let mut out = terminal::doctor(&report, &context.theme);

    if docker.is_available() {
        out.push('\n');
        out.push_str(&terminal::docker_status(&docker, &context.theme));
    }

    if args.show_skipped {
        out.push('\n');
        out.push_str(&terminal::skipped_detail(
            &scan,
            &context.theme,
            &context.known,
        ));
    }

    context.emit(&out)
}
