//! Bazel build system output detection.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_STRONG};

/// Bazel build output and execution roots.
///
/// Bazel workspaces link symlinks/directories in the workspace root like
/// `bazel-out`, `bazel-bin`, `bazel-testlogs`, and `bazel-<workspace-name>`.
pub struct BazelOutput;

static BAZEL_TRIGGERS: &[Trigger] = &[
    Trigger::Name("bazel-out"),
    Trigger::Name("bazel-bin"),
    Trigger::Name("bazel-testlogs"),
    Trigger::Prefix("bazel-"),
];

impl Detector for BazelOutput {
    fn id(&self) -> &'static str {
        "bazel.output"
    }

    fn triggers(&self) -> &'static [Trigger] {
        BAZEL_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if !ctx.name_lower.starts_with("bazel-") {
            return None;
        }

        let in_workspace = ctx.parent_markers.contains(Markers::BAZEL_WORKSPACE);

        match ctx.name_lower {
            "bazel-out" => {
                let confidence = if in_workspace {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                Some(
                    Detection::new(
                        Category::BuildArtifact,
                        confidence,
                        CleanupSafety::Safe,
                        "Bazel build output directory",
                    )
                    .with_technology(Technology::Bazel)
                    .with_evidence(if in_workspace {
                        "A Bazel workspace marker exists in the parent directory."
                    } else {
                        "Directory matches standard Bazel output layout."
                    })
                    .regenerated_by("bazel build ...")
                    .collapsed()
                    .with_specificity(if in_workspace {
                        SPEC_CONTEXT
                    } else {
                        SPEC_STRONG
                    }),
                )
            }
            "bazel-bin" => {
                let confidence = if in_workspace {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                Some(
                    Detection::new(
                        Category::BuildArtifact,
                        confidence,
                        CleanupSafety::Safe,
                        "Bazel binary output convenience symlink/directory",
                    )
                    .with_technology(Technology::Bazel)
                    .with_evidence(if in_workspace {
                        "A Bazel workspace marker exists in the parent directory."
                    } else {
                        "Directory matches standard Bazel binary output layout."
                    })
                    .regenerated_by("bazel build ...")
                    .collapsed()
                    .with_specificity(if in_workspace {
                        SPEC_CONTEXT
                    } else {
                        SPEC_STRONG
                    }),
                )
            }
            "bazel-testlogs" => {
                let confidence = if in_workspace {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                Some(
                    Detection::new(
                        Category::Log,
                        confidence,
                        CleanupSafety::Safe,
                        "Bazel test logs directory",
                    )
                    .with_technology(Technology::Bazel)
                    .with_evidence(if in_workspace {
                        "A Bazel workspace marker exists in the parent directory."
                    } else {
                        "Directory matches standard Bazel testlogs layout."
                    })
                    .regenerated_by("bazel test ...")
                    .collapsed()
                    .with_specificity(if in_workspace {
                        SPEC_CONTEXT
                    } else {
                        SPEC_STRONG
                    }),
                )
            }
            _ => {
                // bazel-<workspace> convenience symlink / execution root directory
                if !in_workspace {
                    return None;
                }
                Some(
                    Detection::new(
                        Category::BuildArtifact,
                        Confidence::High,
                        CleanupSafety::Safe,
                        "Bazel workspace execution root symlink/directory",
                    )
                    .with_technology(Technology::Bazel)
                    .with_evidence("A Bazel workspace marker exists in the parent directory.")
                    .regenerated_by("bazel build ...")
                    .collapsed()
                    .with_specificity(SPEC_CONTEXT - 10),
                )
            }
        }
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
    fn bazel_named_workspace_symlink_detected_with_marker() {
        let env = KnownPaths::empty();
        let custom = BazelOutput
            .detect(&ctx("bazel-myproject", Markers::BAZEL_WORKSPACE, &env))
            .expect("custom workspace detection");
        assert_eq!(custom.category, Category::BuildArtifact);
        assert_eq!(custom.cleanup, CleanupSafety::Safe);

        let without_marker = BazelOutput.detect(&ctx("bazel-myproject", Markers::empty(), &env));
        assert!(without_marker.is_none());
    }
}
