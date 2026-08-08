//! IDE storage.
//!
//! The distinction that matters here is between *project configuration* — run
//! configurations, debug targets, workspace settings that a developer wrote by
//! hand — and *disposable indexes*. Bloatrail keeps the former and offers the
//! latter.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_STRONG};

/// Project-local IDE directories.
pub struct IdeStorage;

static TRIGGERS: &[Trigger] = &[
    Trigger::Name(".idea"),
    Trigger::Name(".vscode"),
    Trigger::Name(".fleet"),
    Trigger::Name(".zed"),
    Trigger::Name(".history"),
    Trigger::Name("xcuserdata"),
    Trigger::Name("deriveddata"),
    Trigger::Name(".devcontainer"),
];

impl Detector for IdeStorage {
    fn id(&self) -> &'static str {
        "ide.storage"
    }

    fn triggers(&self) -> &'static [Trigger] {
        TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        match ctx.name_lower {
            ".idea" => Some(
                Detection::new(
                    Category::Cache,
                    Confidence::High,
                    CleanupSafety::Review,
                    "JetBrains project settings",
                )
                .with_technology(Technology::JetBrains)
                .with_evidence(
                    "Mixes disposable indexes with hand-written run configurations, code style \
                     settings and scopes.",
                )
                .with_evidence(
                    "Delete only if you are willing to recreate your run configurations.",
                )
                .with_specificity(SPEC_STRONG),
            ),
            ".vscode" | ".zed" | ".fleet" | ".devcontainer" => Some(
                Detection::new(
                    Category::SourceCode,
                    Confidence::High,
                    CleanupSafety::NeverDelete,
                    "Editor project configuration",
                )
                .with_technology(Technology::VsCode)
                .with_evidence(
                    "Contains checked-in workspace settings, tasks and launch configurations. \
                     It is project source, not cache.",
                )
                .with_specificity(SPEC_STRONG),
            ),
            ".history" => Some(
                Detection::new(
                    Category::Cache,
                    Confidence::Medium,
                    CleanupSafety::Review,
                    "Editor local history",
                )
                .with_technology(Technology::VsCode)
                .with_evidence("Local file history can be the only copy of an uncommitted change.")
                .with_specificity(SPEC_STRONG - 20),
            ),
            "xcuserdata" => Some(
                Detection::new(
                    Category::Cache,
                    Confidence::High,
                    CleanupSafety::ProbablySafe,
                    "Xcode per-user state",
                )
                .with_technology(Technology::Xcode)
                .with_evidence("Window layout, breakpoints and scheme selections.")
                .collapsed()
                .with_specificity(SPEC_STRONG),
            ),
            "deriveddata" => {
                if !ctx.parent_markers.contains(Markers::XCODE_PROJECT)
                    && !ctx.parent_markers.contains(Markers::SWIFT_PACKAGE)
                {
                    return None;
                }
                Some(
                    Detection::new(
                        Category::BuildArtifact,
                        Confidence::High,
                        CleanupSafety::Safe,
                        "Xcode derived data",
                    )
                    .with_technology(Technology::Xcode)
                    .with_evidence("Build products and indexes; Xcode regenerates them.")
                    .regenerated_by("xcodebuild build")
                    .collapsed()
                    .with_specificity(SPEC_CONTEXT),
                )
            }
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
    fn vscode_settings_are_treated_as_source() {
        let env = KnownPaths::empty();
        let detection = IdeStorage
            .detect(&ctx(".vscode", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.category, Category::SourceCode);
        assert_eq!(detection.cleanup, CleanupSafety::NeverDelete);
    }

    #[test]
    fn jetbrains_project_dir_needs_review_not_auto_deletion() {
        let env = KnownPaths::empty();
        let detection = IdeStorage
            .detect(&ctx(".idea", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.cleanup, CleanupSafety::Review);
        assert!(!detection.cleanup.is_auto_selectable());
    }

    #[test]
    fn derived_data_requires_an_xcode_project_nearby() {
        let env = KnownPaths::empty();
        assert!(IdeStorage
            .detect(&ctx("deriveddata", Markers::empty(), &env))
            .is_none());
        assert!(IdeStorage
            .detect(&ctx("deriveddata", Markers::XCODE_PROJECT, &env))
            .is_some());
    }
}
