//! The detector registry.
//!
//! Each submodule owns one ecosystem. Adding support for a new toolchain means
//! writing a detector and appending it to [`all`] — nothing else in the
//! codebase needs to change.

use crate::analysis::engine::Detector;

pub mod cpp;
pub mod dotnet;
pub mod generic;
pub mod git;
pub mod go;
pub mod ide;
pub mod javascript;
pub mod jvm;
pub mod native_pkg;
pub mod python;
pub mod rust;

/// Specificity for detections corroborated by project marker files.
pub(crate) const SPEC_CONTEXT: u16 = 90;
/// Specificity for names that are unambiguous on their own (`node_modules`).
pub(crate) const SPEC_STRONG: u16 = 70;
/// Specificity for ambiguous names classified on weak evidence.
pub(crate) const SPEC_WEAK: u16 = 20;

/// Every detector Bloatrail ships with, in registration order.
#[must_use]
pub fn all() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(rust::RustTarget),
        Box::new(javascript::NodeModules),
        Box::new(javascript::JsFrameworkCache),
        Box::new(javascript::JsBuildOutput),
        Box::new(python::PythonCache),
        Box::new(python::VirtualEnv),
        Box::new(python::PythonBuild),
        Box::new(jvm::MavenTarget),
        Box::new(jvm::GradleOutput),
        Box::new(dotnet::DotNetOutput),
        Box::new(go::GoOutput),
        Box::new(cpp::CMakeOutput),
        Box::new(cpp::NativeBuildDir),
        Box::new(git::VersionControl),
        Box::new(ide::IdeStorage),
        Box::new(native_pkg::VendoredDependencies),
        Box::new(native_pkg::LanguageBuildDirs),
        Box::new(generic::LogDirectory),
        Box::new(generic::TempDirectory),
        Box::new(generic::CacheDirectory),
        Box::new(generic::ContainerDirectory),
    ]
}

/// Shared helpers for detector unit tests.
///
/// Detectors are pure functions of [`crate::analysis::context::DirContext`], so
/// their tests need no filesystem at all — only a context to hand them.
#[cfg(test)]
pub(crate) mod tests_support {
    use crate::analysis::context::{DirContext, Markers};
    use crate::platform::KnownPaths;
    use std::path::Path;

    /// Context for a directory whose *parent* carries `parent_markers`.
    pub(crate) fn ctx<'a>(
        name: &'a str,
        parent_markers: Markers,
        env: &'a KnownPaths,
    ) -> DirContext<'a> {
        ctx_full(
            name,
            Markers::empty(),
            parent_markers,
            Markers::empty(),
            env,
        )
    }

    /// Context with full control over the marker sets at each level.
    pub(crate) fn ctx_full<'a>(
        name: &'a str,
        markers: Markers,
        parent_markers: Markers,
        grandparent_markers: Markers,
        env: &'a KnownPaths,
    ) -> DirContext<'a> {
        debug_assert_eq!(
            name,
            name.to_lowercase(),
            "test helper expects an already-lowercase directory name"
        );
        DirContext {
            path: Path::new("/workspace/project/dir"),
            name,
            name_lower: name,
            parent_name: Some("project"),
            markers,
            parent_markers,
            grandparent_markers,
            depth: 2,
            subdir_count: 1,
            file_count: 1,
            env,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn detector_ids_are_unique() {
        let mut seen = HashSet::new();
        for detector in all() {
            assert!(
                seen.insert(detector.id()),
                "duplicate detector id `{}`",
                detector.id()
            );
        }
    }

    #[test]
    fn every_detector_declares_at_least_one_trigger() {
        for detector in all() {
            assert!(
                !detector.triggers().is_empty(),
                "detector `{}` would never run",
                detector.id()
            );
        }
    }

    #[test]
    fn no_trigger_can_be_unreachable() {
        use crate::analysis::engine::Trigger;

        for detector in all() {
            for trigger in detector.triggers() {
                let text = match trigger {
                    Trigger::Name(t) | Trigger::Prefix(t) | Trigger::Suffix(t) => *t,
                    Trigger::Always => continue,
                };
                // Dispatch compares against a single lowercased path component.
                assert!(
                    !text.contains('/') && !text.contains('\\'),
                    "`{}` in `{}` contains a path separator and could never match",
                    text,
                    detector.id()
                );
                assert_eq!(
                    text,
                    text.to_lowercase(),
                    "`{}` in `{}` has uppercase characters and could never match",
                    text,
                    detector.id()
                );
                assert!(
                    !text.is_empty(),
                    "detector `{}` has an empty trigger",
                    detector.id()
                );
            }
        }
    }
}
