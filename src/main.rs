//! The `bloatrail` binary.
//!
//! Everything of substance lives in the library; this file exists to parse
//! arguments, dispatch, and turn an error chain into a readable message.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;

use bloatrail::cli::{self, Cli};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Print an error and its causes to stderr.
///
/// Written directly rather than through `anyhow`'s `Debug` formatting so the
/// output reads like a message rather than a backtrace.
fn report(error: &anyhow::Error) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "bloatrail: {error}");
    for cause in error.chain().skip(1) {
        let _ = writeln!(stderr, "  caused by: {cause}");
    }
}
