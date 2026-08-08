//! Go project detection.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::SPEC_CONTEXT;

/// Compiled binaries and vendored modules inside a Go module.
pub struct GoOutput;

static TRIGGERS: &[Trigger] = &[Trigger::Name("bin"), Trigger::Name("vendor")];

impl Detector for GoOutput {
    fn id(&self) -> &'static str {
        "go.output"
    }

    fn triggers(&self) -> &'static [Trigger] {
        TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if !ctx.parent_is_project(Markers::GO_MOD) {
            return None;
        }

        match ctx.name_lower {
            "vendor" => Some(
                Detection::new(
                    Category::Dependency,
                    Confidence::High,
                    CleanupSafety::ProbablySafe,
                    "Vendored Go modules",
                )
                .with_technology(Technology::Go)
                .with_evidence("A `go.mod` file exists in the parent directory.")
                .with_evidence(
                    "Vendored sources are reproducible from `go.mod`, but some builds are \
                     configured to require the vendor directory.",
                )
                .regenerated_by("go mod vendor")
                .collapsed()
                .with_specificity(SPEC_CONTEXT),
            ),
            "bin" => Some(
                Detection::new(
                    Category::BuildArtifact,
                    Confidence::Medium,
                    CleanupSafety::ProbablySafe,
                    "Compiled Go binaries",
                )
                .with_technology(Technology::Go)
                .with_evidence("A `go.mod` file exists in the parent directory.")
                .with_evidence("Rebuilt by `go build`, though the directory may also hold scripts.")
                .regenerated_by("go build ./...")
                .collapsed()
                .with_specificity(SPEC_CONTEXT - 20),
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::ctx;
    use crate::platform::KnownPaths;

    #[test]
    fn vendor_requires_go_mod() {
        let env = KnownPaths::empty();
        assert!(GoOutput
            .detect(&ctx("vendor", Markers::empty(), &env))
            .is_none());
        let detection = GoOutput
            .detect(&ctx("vendor", Markers::GO_MOD, &env))
            .expect("detection");
        assert_eq!(detection.technology, Some(Technology::Go));
        assert_eq!(detection.cleanup, CleanupSafety::ProbablySafe);
    }

    #[test]
    fn go_bin_is_never_marked_safe() {
        let env = KnownPaths::empty();
        let detection = GoOutput
            .detect(&ctx("bin", Markers::GO_MOD, &env))
            .expect("detection");
        assert_ne!(detection.cleanup, CleanupSafety::Safe);
    }
}
