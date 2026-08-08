//! .NET build output detection.
//!
//! `bin/` and `obj/` are only meaningful next to a project or solution file —
//! `bin` in particular is a normal name for a directory of scripts.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_WEAK};

/// `bin/`, `obj/` and the Visual Studio per-solution cache.
pub struct DotNetOutput;

static TRIGGERS: &[Trigger] = &[
    Trigger::Name("bin"),
    Trigger::Name("obj"),
    Trigger::Name(".vs"),
    Trigger::Name("packages"),
];

impl Detector for DotNetOutput {
    fn id(&self) -> &'static str {
        "dotnet.output"
    }

    fn triggers(&self) -> &'static [Trigger] {
        TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        let near_project = ctx.parent_is_project(Markers::DOTNET_PROJECT | Markers::DOTNET_PROPS);
        let near_solution = ctx.parent_is_project(Markers::DOTNET_SOLUTION);
        let in_solution_tree = ctx
            .grandparent_markers
            .intersects(Markers::DOTNET_SOLUTION | Markers::DOTNET_PROJECT);

        match ctx.name_lower {
            ".vs" => {
                if !near_project && !near_solution {
                    return None;
                }
                Some(
                    Detection::new(
                        Category::Cache,
                        Confidence::High,
                        CleanupSafety::Safe,
                        "Visual Studio solution cache",
                    )
                    .with_technology(Technology::VisualStudio)
                    .with_evidence(
                        "Holds IntelliSense databases and per-solution UI state. Visual Studio \
                         rebuilds it when the solution is next opened.",
                    )
                    .collapsed()
                    .with_specificity(SPEC_CONTEXT),
                )
            }
            "packages" => {
                if !near_solution {
                    return None;
                }
                Some(
                    Detection::new(
                        Category::PackageCache,
                        Confidence::Medium,
                        CleanupSafety::ProbablySafe,
                        "NuGet solution packages",
                    )
                    .with_technology(Technology::DotNet)
                    .with_evidence("Legacy `packages.config` restore directory, re-downloadable.")
                    .regenerated_by("dotnet restore")
                    .collapsed()
                    .with_specificity(SPEC_WEAK + 30),
                )
            }
            "bin" | "obj" => {
                if !near_project && !near_solution && !in_solution_tree {
                    return None;
                }
                let confidence = if near_project {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                let label = if ctx.name_lower == "obj" {
                    ".NET intermediate build output"
                } else {
                    ".NET compiled output"
                };
                Some(
                    Detection::new(
                        Category::BuildArtifact,
                        confidence,
                        CleanupSafety::Safe,
                        label,
                    )
                    .with_technology(Technology::DotNet)
                    .with_evidence(if ctx.parent_is_project(Markers::DOTNET_PROJECT) {
                        "A .NET project file exists in the parent directory."
                    } else if near_project {
                        "A `Directory.Build.props` file exists in the parent directory."
                    } else if near_solution {
                        "A .NET solution file exists in the parent directory."
                    } else {
                        "This directory sits inside a .NET solution tree."
                    })
                    .with_evidence("`dotnet build` recreates both `bin/` and `obj/` from source.")
                    .regenerated_by("dotnet build")
                    .collapsed()
                    .with_specificity(if near_project {
                        SPEC_CONTEXT
                    } else {
                        SPEC_CONTEXT - 20
                    }),
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
    fn a_bare_bin_directory_is_not_dotnet_output() {
        let env = KnownPaths::empty();
        assert!(DotNetOutput
            .detect(&ctx("bin", Markers::empty(), &env))
            .is_none());
    }

    #[test]
    fn bin_next_to_a_csproj_is_safe_build_output() {
        let env = KnownPaths::empty();
        let detection = DotNetOutput
            .detect(&ctx("bin", Markers::DOTNET_PROJECT, &env))
            .expect("detection");
        assert_eq!(detection.category, Category::BuildArtifact);
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
        assert_eq!(detection.confidence, Confidence::High);
    }

    #[test]
    fn obj_inside_a_solution_tree_is_medium_confidence() {
        let env = KnownPaths::empty();
        let context = ctx_full(
            "obj",
            Markers::empty(),
            Markers::empty(),
            Markers::DOTNET_SOLUTION,
            &env,
        );
        let detection = DotNetOutput.detect(&context).expect("detection");
        assert_eq!(detection.confidence, Confidence::Medium);
    }

    #[test]
    fn vs_cache_requires_project_context() {
        let env = KnownPaths::empty();
        assert!(DotNetOutput
            .detect(&ctx(".vs", Markers::empty(), &env))
            .is_none());
        assert!(DotNetOutput
            .detect(&ctx(".vs", Markers::DOTNET_SOLUTION, &env))
            .is_some());
    }
}
