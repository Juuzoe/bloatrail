//! Unreal Engine build artifact and cache detection.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::SPEC_CONTEXT;

/// Unreal Engine project directories: `Intermediate/`, `Binaries/`, `DerivedDataCache/`, `Saved/`.
pub struct UnrealEngineOutput;

static TRIGGERS: &[Trigger] = &[
    Trigger::Name("intermediate"),
    Trigger::Name("binaries"),
    Trigger::Name("deriveddatacache"),
    Trigger::Name("saved"),
];

impl Detector for UnrealEngineOutput {
    fn id(&self) -> &'static str {
        "unreal.output"
    }

    fn triggers(&self) -> &'static [Trigger] {
        TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if !ctx.parent_is_project(Markers::UPROJECT) {
            return None;
        }

        match ctx.name_lower {
            "intermediate" => Some(
                Detection::new(
                    Category::BuildArtifact,
                    Confidence::High,
                    CleanupSafety::Safe,
                    "Unreal Engine intermediate build files",
                )
                .with_technology(Technology::UnrealEngine)
                .with_evidence("A `.uproject` file exists in the parent directory.")
                .with_evidence(
                    "Unreal Engine regenerates `Intermediate/` on the next compile or build.",
                )
                .regenerated_by("Build the project in Unreal Editor or your IDE")
                .collapsed()
                .with_specificity(SPEC_CONTEXT),
            ),
            "binaries" => Some(
                Detection::new(
                    Category::BuildArtifact,
                    Confidence::High,
                    CleanupSafety::Safe,
                    "Unreal Engine compiled binaries",
                )
                .with_technology(Technology::UnrealEngine)
                .with_evidence("A `.uproject` file exists in the parent directory.")
                .with_evidence(
                    "Compiled modules and executables regenerated when the project is built.",
                )
                .regenerated_by("Build the project in Unreal Editor or your IDE")
                .collapsed()
                .with_specificity(SPEC_CONTEXT),
            ),
            "deriveddatacache" => Some(
                Detection::new(
                    Category::Cache,
                    Confidence::High,
                    CleanupSafety::Safe,
                    "Unreal Engine derived data cache",
                )
                .with_technology(Technology::UnrealEngine)
                .with_evidence("A `.uproject` file exists in the parent directory.")
                .with_evidence(
                    "Derived Data Cache (DDC) contains processed assets regenerated on demand.",
                )
                .regenerated_by("Open the project in Unreal Editor")
                .collapsed()
                .with_specificity(SPEC_CONTEXT),
            ),
            "saved" => Some(
                Detection::new(
                    Category::Cache,
                    Confidence::High,
                    CleanupSafety::Review,
                    "Unreal Engine saved data",
                )
                .with_technology(Technology::UnrealEngine)
                .with_evidence("A `.uproject` file exists in the parent directory.")
                .with_evidence(
                    "Contains crash logs, autosaves, and local configuration; review before deleting.",
                )
                .collapsed()
                .with_specificity(SPEC_CONTEXT),
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
    fn unreal_directories_require_uproject_marker() {
        let env = KnownPaths::empty();
        for dir in ["intermediate", "binaries", "deriveddatacache", "saved"] {
            assert!(
                UnrealEngineOutput
                    .detect(&ctx(dir, Markers::empty(), &env))
                    .is_none(),
                "`{dir}` without .uproject must not be detected"
            );
        }
    }

    #[test]
    fn intermediate_and_binaries_are_safe_build_artifacts() {
        let env = KnownPaths::empty();
        let intermediate = UnrealEngineOutput
            .detect(&ctx("intermediate", Markers::UPROJECT, &env))
            .expect("intermediate detection");
        assert_eq!(intermediate.category, Category::BuildArtifact);
        assert_eq!(intermediate.confidence, Confidence::High);
        assert_eq!(intermediate.cleanup, CleanupSafety::Safe);
        assert_eq!(intermediate.technology, Some(Technology::UnrealEngine));
        assert!(intermediate.collapse);

        let binaries = UnrealEngineOutput
            .detect(&ctx("binaries", Markers::UPROJECT, &env))
            .expect("binaries detection");
        assert_eq!(binaries.category, Category::BuildArtifact);
        assert_eq!(binaries.confidence, Confidence::High);
        assert_eq!(binaries.cleanup, CleanupSafety::Safe);
        assert_eq!(binaries.technology, Some(Technology::UnrealEngine));
        assert!(binaries.collapse);
    }

    #[test]
    fn derived_data_cache_is_safe_cache() {
        let env = KnownPaths::empty();
        let ddc = UnrealEngineOutput
            .detect(&ctx("deriveddatacache", Markers::UPROJECT, &env))
            .expect("deriveddatacache detection");
        assert_eq!(ddc.category, Category::Cache);
        assert_eq!(ddc.confidence, Confidence::High);
        assert_eq!(ddc.cleanup, CleanupSafety::Safe);
        assert_eq!(ddc.technology, Some(Technology::UnrealEngine));
        assert!(ddc.collapse);
    }

    #[test]
    fn saved_is_review_safety() {
        let env = KnownPaths::empty();
        let saved = UnrealEngineOutput
            .detect(&ctx("saved", Markers::UPROJECT, &env))
            .expect("saved detection");
        assert_eq!(saved.category, Category::Cache);
        assert_eq!(saved.confidence, Confidence::High);
        assert_eq!(saved.cleanup, CleanupSafety::Review);
        assert_eq!(saved.technology, Some(Technology::UnrealEngine));
        assert!(saved.collapse);
    }
}
