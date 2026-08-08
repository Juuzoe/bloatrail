//! Bloatrail — a developer-aware disk analyser.
//!
//! Most disk tools tell you *where* your space went. Bloatrail tries to tell you
//! *why* it went there and what you can safely do about it.
//!
//! # Architecture
//!
//! The crate is layered, and each layer only depends on the ones above it:
//!
//! ```text
//! platform   where things live on this OS, disk capacity, protected paths
//! units      byte quantities and their formatting
//! analysis   the vocabulary (Category, Confidence, CleanupSafety) and the
//!            rules engine that produces a Detection from directory context
//! detectors  one module per ecosystem, all implementing analysis::Detector
//! scanner    the parallel walk; produces sizes, a tree, and classifications
//! cleanup    planner → safety guard → executor
//! output     terminal and JSON rendering; imported by nothing below it
//! cli        argument parsing and command dispatch
//! ```
//!
//! The important boundary is the last one: nothing in `scanner`, `analysis` or
//! `cleanup` knows that a terminal exists, which is what makes the engine
//! testable without capturing output and reusable as a library.
//!
//! # Example
//!
//! ```no_run
//! use bloatrail::{analysis::Classifier, platform::KnownPaths, scanner};
//!
//! let classifier = Classifier::with_default_detectors();
//! let known = KnownPaths::discover();
//! let options = scanner::ScanOptions::new(".");
//!
//! let result = scanner::scan(&options, &classifier, &known)?;
//! println!("{} in {} files", bloatrail::units::ByteSize(result.totals.bytes), result.totals.files);
//!
//! let plan = bloatrail::cleanup::CleanupPlan::from_scan(&result);
//! println!("recoverable: {}", plan.recoverable());
//! # Ok::<(), bloatrail::error::Error>(())
//! ```
//!
//! # Safety model
//!
//! Nothing is ever removed on the strength of a directory name. A location must
//! be classified by a rule that saw its surrounding project context, survive
//! re-verification against the live filesystem at deletion time, and be
//! explicitly selected and confirmed by a human. Dry runs are structural: the
//! executor returns before any mutating call, and the test suite asserts it.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod analysis;
pub mod cleanup;
pub mod cli;
pub mod config;
pub mod detectors;
pub mod docker;
pub mod doctor;
pub mod duplicates;
pub mod error;
pub mod history;
pub mod output;
pub mod pattern;
pub mod platform;
pub mod scanner;
pub mod timefmt;
pub mod units;

pub use error::{Error, Result};
pub use units::ByteSize;

/// The product name, as shown in the terminal header.
pub const NAME: &str = "BLOATRAIL";

/// The crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
