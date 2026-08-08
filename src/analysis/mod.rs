//! Turning raw filesystem facts into meaning.
//!
//! The analysis layer is deliberately free of I/O and of terminal concerns. It
//! takes the evidence the scanner gathered ([`context::DirContext`]) and
//! produces [`domain::Detection`] values that the cleanup planner and the
//! renderers consume.

pub mod categorize;
pub mod context;
pub mod domain;
pub mod engine;
pub mod reclaim;
pub mod sensitive;

pub use context::{DirContext, Markers};
pub use domain::{
    Category, CategoryTotals, CleanupSafety, Confidence, Detection, Reclaim, Technology,
};
pub use engine::{Classifier, Detector, Trigger};
