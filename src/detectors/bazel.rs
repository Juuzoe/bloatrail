//! Bazel build system output detection.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_WEAK};

/// Bazel's convenience links in a workspace root: `bazel-out`, `bazel-bin`,
/// `bazel-testlogs` and `bazel-<workspace>`.
///
/// Bazel creates these as symlinks (junctions on Windows) into its output base,
/// so a default scan, which does not follow links, sees them only as links and
/// the safety guard never removes one. They are classified anyway because
/// `--follow-symlinks`, a copied workspace or an archive extracted without
/// links turns them into ordinary directories.
pub struct BazelOutput;

static BAZEL_TRIGGERS: &[Trigger] = &[Trigger::Prefix("bazel-")];

impl Detector for BazelOutput {
    fn id(&self) -> &'static str {
        "bazel.output"
    }

    fn triggers(&self) -> &'static [Trigger] {
        BAZEL_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        let in_workspace = ctx.parent_is_project(Markers::BAZEL_WORKSPACE);

        let (category, label, command) = match ctx.name_lower {
            "bazel-out" => (
                Category::BuildArtifact,
                "Bazel build output",
                "bazel build //...",
            ),
            "bazel-bin" => (
                Category::BuildArtifact,
                "Bazel binary output",
                "bazel build //...",
            ),
            "bazel-testlogs" => (Category::Log, "Bazel test logs", "bazel test //..."),
            name => {
                // `bazel-<workspace>` is named after the workspace directory
                // itself. Matching that exact name, rather than any `bazel-`
                // prefix, keeps a hand-made `bazel-tools/` or `bazel-configs/`
                // in the same repository out of the cleanup plan.
                let rest = name.strip_prefix("bazel-")?;
                let named_after_parent = ctx
                    .parent_name
                    .is_some_and(|parent| parent.eq_ignore_ascii_case(rest));
                if !(in_workspace && named_after_parent) {
                    return None;
                }
                (
                    Category::BuildArtifact,
                    "Bazel execution root",
                    "bazel build //...",
                )
            }
        };

        if !in_workspace {
            return Some(
                Detection::new(
                    Category::Unknown,
                    Confidence::Low,
                    CleanupSafety::Review,
                    "Bazel-style directory with no workspace around it",
                )
                .with_technology(Technology::Bazel)
                .with_evidence(
                    "The name matches a Bazel output link, but no `WORKSPACE` or \
                     `MODULE.bazel` file was found in the parent directory.",
                )
                .with_evidence("Bloatrail will not treat this as regenerable build output.")
                .with_specificity(SPEC_WEAK),
            );
        }

        Some(
            Detection::new(category, Confidence::High, CleanupSafety::Safe, label)
                .with_technology(Technology::Bazel)
                .with_evidence("A Bazel workspace file exists in the parent directory.")
                .with_evidence(
                    "Bazel recreates this link and everything behind it on the next build; \
                     `bazel clean` removes the same data.",
                )
                .regenerated_by(command)
                .collapsed()
                .with_specificity(SPEC_CONTEXT),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::ctx;
    use crate::platform::KnownPaths;

    #[test]
    fn bazel_out_in_workspace_is_high_confidence() {
        let env = KnownPaths::empty();
        let detection = BazelOutput
            .detect(&ctx("bazel-out", Markers::BAZEL_WORKSPACE, &env))
            .expect("detection");
        assert_eq!(detection.category, Category::BuildArtifact);
        assert_eq!(detection.confidence, Confidence::High);
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
        assert_eq!(detection.technology, Some(Technology::Bazel));
        assert!(detection.collapse);
    }

    #[test]
    fn bazel_bin_and_testlogs_detected() {
        let env = KnownPaths::empty();
        let bin = BazelOutput
            .detect(&ctx("bazel-bin", Markers::BAZEL_WORKSPACE, &env))
            .expect("bin detection");
        assert_eq!(bin.category, Category::BuildArtifact);
        assert_eq!(bin.cleanup, CleanupSafety::Safe);

        let testlogs = BazelOutput
            .detect(&ctx("bazel-testlogs", Markers::BAZEL_WORKSPACE, &env))
            .expect("testlogs detection");
        assert_eq!(testlogs.category, Category::Log);
        assert_eq!(testlogs.cleanup, CleanupSafety::Safe);
    }

    #[test]
    fn output_names_without_a_workspace_are_never_safe() {
        let env = KnownPaths::empty();
        for name in ["bazel-out", "bazel-bin", "bazel-testlogs"] {
            let detection = BazelOutput
                .detect(&ctx(name, Markers::empty(), &env))
                .expect("name match is reported");
            assert_eq!(detection.cleanup, CleanupSafety::Review, "{name}");
            assert_eq!(detection.confidence, Confidence::Low, "{name}");
        }
    }

    #[test]
    fn the_execution_root_link_must_be_named_after_the_workspace() {
        let env = KnownPaths::empty();
        let mut named = ctx("bazel-myproject", Markers::BAZEL_WORKSPACE, &env);
        named.parent_name = Some("MyProject");
        let detection = BazelOutput.detect(&named).expect("execution root");
        assert_eq!(detection.category, Category::BuildArtifact);
        assert_eq!(detection.cleanup, CleanupSafety::Safe);

        // A directory a person made, in the same workspace, that merely
        // starts with `bazel-`.
        let mut handmade = ctx("bazel-configs", Markers::BAZEL_WORKSPACE, &env);
        handmade.parent_name = Some("myproject");
        assert!(BazelOutput.detect(&handmade).is_none());

        let mut unmarked = ctx("bazel-myproject", Markers::empty(), &env);
        unmarked.parent_name = Some("myproject");
        assert!(BazelOutput.detect(&unmarked).is_none());
    }
}
