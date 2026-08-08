//! Java / Kotlin / Scala build output detection.
//!
//! The JVM world reuses the most ambiguous directory names in existence
//! (`target`, `build`, `out`, `bin`), so every rule here demands a build script
//! in the parent directory before claiming anything.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::SPEC_CONTEXT;

/// Maven's `target/` output directory.
pub struct MavenTarget;

static MAVEN_TRIGGERS: &[Trigger] = &[Trigger::Name("target")];

impl Detector for MavenTarget {
    fn id(&self) -> &'static str {
        "jvm.maven_target"
    }

    fn triggers(&self) -> &'static [Trigger] {
        MAVEN_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if !ctx.parent_is_project(Markers::POM_XML) {
            return None;
        }
        Some(
            Detection::new(
                Category::BuildArtifact,
                Confidence::High,
                CleanupSafety::Safe,
                "Maven build output",
            )
            .with_technology(Technology::Maven)
            .with_evidence("A `pom.xml` file exists in the parent directory.")
            .with_evidence("Maven writes compiled classes, test reports and packaged jars here.")
            .regenerated_by("mvn package")
            .collapsed()
            .with_specificity(SPEC_CONTEXT),
        )
    }
}

/// Gradle project output and the project-local `.gradle` cache.
pub struct GradleOutput;

static GRADLE_TRIGGERS: &[Trigger] = &[
    Trigger::Name("build"),
    Trigger::Name(".gradle"),
    Trigger::Name("out"),
    Trigger::Name(".kotlin"),
];

impl Detector for GradleOutput {
    fn id(&self) -> &'static str {
        "jvm.gradle"
    }

    fn triggers(&self) -> &'static [Trigger] {
        GRADLE_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        match ctx.name_lower {
            ".gradle" => {
                if !ctx.parent_is_project(Markers::JVM_PROJECT) {
                    return None;
                }
                Some(
                    Detection::new(
                        Category::Cache,
                        Confidence::High,
                        CleanupSafety::Safe,
                        "Gradle project cache",
                    )
                    .with_technology(Technology::Gradle)
                    .with_evidence(
                        "Per-project incremental build state, rebuilt on the next build.",
                    )
                    .regenerated_by("gradle build")
                    .collapsed()
                    .with_specificity(SPEC_CONTEXT),
                )
            }
            ".kotlin" => {
                if !ctx.parent_is_project(Markers::JVM_PROJECT) {
                    return None;
                }
                Some(
                    Detection::new(
                        Category::Cache,
                        Confidence::High,
                        CleanupSafety::Safe,
                        "Kotlin compiler session cache",
                    )
                    .with_technology(Technology::Jvm)
                    .regenerated_by("gradle build")
                    .collapsed()
                    .with_specificity(SPEC_CONTEXT),
                )
            }
            "build" | "out" => {
                let gradle = ctx.parent_is_project(Markers::GRADLE_BUILD | Markers::GRADLE_WRAPPER);
                // Multi-module Gradle builds put the settings file one level up.
                let gradle_module = !gradle
                    && ctx
                        .grandparent_markers
                        .intersects(Markers::GRADLE_BUILD | Markers::GRADLE_WRAPPER);
                if !gradle && !gradle_module {
                    return None;
                }
                let confidence = if gradle {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                Some(
                    Detection::new(
                        Category::BuildArtifact,
                        confidence,
                        CleanupSafety::Safe,
                        "Gradle build output",
                    )
                    .with_technology(Technology::Gradle)
                    .with_evidence(if gradle {
                        "A Gradle build script exists in the parent directory."
                    } else {
                        "A Gradle build script exists in the enclosing multi-module project."
                    })
                    .regenerated_by("gradle build")
                    .collapsed()
                    .with_specificity(SPEC_CONTEXT - 10),
                )
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::{ctx, ctx_full};
    use crate::platform::KnownPaths;

    #[test]
    fn maven_target_requires_a_pom() {
        let env = KnownPaths::empty();
        assert!(MavenTarget
            .detect(&ctx("target", Markers::empty(), &env))
            .is_none());
        let detection = MavenTarget
            .detect(&ctx("target", Markers::POM_XML, &env))
            .expect("detection");
        assert_eq!(detection.technology, Some(Technology::Maven));
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
    }

    #[test]
    fn gradle_build_dir_requires_a_build_script() {
        let env = KnownPaths::empty();
        assert!(GradleOutput
            .detect(&ctx("build", Markers::empty(), &env))
            .is_none());
        let detection = GradleOutput
            .detect(&ctx("build", Markers::GRADLE_BUILD, &env))
            .expect("detection");
        assert_eq!(detection.confidence, Confidence::High);
    }

    #[test]
    fn gradle_submodule_output_is_accepted_with_lower_confidence() {
        let env = KnownPaths::empty();
        let context = ctx_full(
            "build",
            Markers::empty(),
            Markers::empty(),
            Markers::GRADLE_WRAPPER,
            &env,
        );
        let detection = GradleOutput.detect(&context).expect("detection");
        assert_eq!(detection.confidence, Confidence::Medium);
    }

    #[test]
    fn project_gradle_cache_needs_project_context() {
        let env = KnownPaths::empty();
        assert!(GradleOutput
            .detect(&ctx(".gradle", Markers::empty(), &env))
            .is_none());
        assert!(GradleOutput
            .detect(&ctx(".gradle", Markers::GRADLE_BUILD, &env))
            .is_some());
    }
}
