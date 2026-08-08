//! Rust / Cargo detection.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_WEAK};

/// Classifies `target/` directories.
///
/// `target` is the canonical example of why Bloatrail is context-aware: next to
/// a `Cargo.toml` it is regenerable compiler output, next to a `pom.xml` it
/// belongs to Maven, and on its own it is just a directory called "target".
pub struct RustTarget;

static TRIGGERS: &[Trigger] = &[Trigger::Name("target")];

impl Detector for RustTarget {
    fn id(&self) -> &'static str {
        "rust.target"
    }

    fn triggers(&self) -> &'static [Trigger] {
        TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        // A `target` next to a `pom.xml` or a Gradle build script belongs to the
        // JVM detectors, which will produce a better-supported detection.
        if ctx.parent_is_project(Markers::POM_XML) && !ctx.parent_is_project(Markers::CARGO_TOML) {
            return None;
        }

        if ctx.parent_is_project(Markers::CARGO_TOML) {
            let mut detection = Detection::new(
                Category::BuildArtifact,
                Confidence::High,
                CleanupSafety::Safe,
                "Rust build artifacts",
            )
            .with_technology(Technology::Rust)
            .with_evidence("A `Cargo.toml` file exists in the parent directory.")
            .with_evidence(
                "Cargo writes every compiled artifact, dependency build and incremental \
                 compilation cache into `target/`.",
            )
            .with_evidence("Removing it does not touch any source file.")
            .regenerated_by("cargo build")
            .collapsed()
            .with_specificity(SPEC_CONTEXT);

            if ctx.parent_is_project(Markers::CARGO_LOCK) {
                detection = detection
                    .with_evidence("A `Cargo.lock` file confirms this is a Cargo project root.");
            }
            return Some(detection);
        }

        // A `target` directory with a `CACHEDIR.TAG`-like layout but no project
        // marker: name matched, context did not. Say so, and refuse to treat it
        // as disposable.
        Some(
            Detection::new(
                Category::Unknown,
                Confidence::Low,
                CleanupSafety::Review,
                "Directory named `target` with no project context",
            )
            .with_evidence(
                "The name matches a Rust build directory, but no `Cargo.toml` was found in the \
                 parent directory.",
            )
            .with_evidence("Bloatrail will not treat this as regenerable build output.")
            .with_specificity(SPEC_WEAK),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::ctx;

    #[test]
    fn target_next_to_cargo_toml_is_safe_rust_output() {
        let env = crate::platform::KnownPaths::empty();
        let context = ctx("target", Markers::CARGO_TOML | Markers::CARGO_LOCK, &env);
        let detection = RustTarget.detect(&context).expect("detection");
        assert_eq!(detection.category, Category::BuildArtifact);
        assert_eq!(detection.technology, Some(Technology::Rust));
        assert_eq!(detection.confidence, Confidence::High);
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
        assert!(detection.collapse);
        assert_eq!(detection.regenerated_by.as_deref(), Some("cargo build"));
    }

    #[test]
    fn target_without_cargo_toml_is_low_confidence_and_not_safe() {
        let env = crate::platform::KnownPaths::empty();
        let context = ctx("target", Markers::empty(), &env);
        let detection = RustTarget.detect(&context).expect("detection");
        assert_eq!(detection.confidence, Confidence::Low);
        assert_eq!(detection.cleanup, CleanupSafety::Review);
        assert_ne!(detection.category, Category::BuildArtifact);
        assert!(!detection.collapse);
    }

    #[test]
    fn maven_target_is_left_to_the_jvm_detector() {
        let env = crate::platform::KnownPaths::empty();
        let context = ctx("target", Markers::POM_XML, &env);
        assert!(RustTarget.detect(&context).is_none());
    }
}
