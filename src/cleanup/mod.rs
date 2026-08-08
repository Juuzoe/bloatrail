//! The cleanup engine.
//!
//! The pipeline is deliberately linear and one-directional:
//!
//! ```text
//! detect  →  explain  →  classify  →  plan  →  preview  →  confirm  →  remove
//! ```
//!
//! Each stage lives in its own module and can only see the stage before it.
//! [`planner`] cannot delete, [`executor`] cannot classify, and [`safety`] sits
//! between them refusing anything that does not survive re-verification.

pub mod executor;
pub mod planner;
pub mod safety;

pub use executor::{ExecutionOptions, ExecutionReport, Executor, Removal, RemovalMethod};
pub use planner::{CleanupGroup, CleanupPlan, CleanupTarget, TargetKind};
pub use safety::SafetyGuard;
