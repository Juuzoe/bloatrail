//! The rules engine that turns directory context into a [`Detection`].
//!
//! Detection is a two-stage process:
//!
//! 1. A **dispatch** stage narrows the candidate detectors using the directory
//!    name. Most directories in a real scan (`src`, `assets`, `2024-08`) match
//!    nothing at all and cost one hash lookup.
//! 2. A **scoring** stage runs the surviving detectors and keeps the
//!    highest-ranked result, where rank is `(confidence, specificity)`.
//!
//! Detectors never touch the filesystem. Everything they are allowed to know is
//! in [`DirContext`], which the walker fills in from data it had already read.
//! That makes classification deterministic, allocation-free and unit-testable
//! without creating any files.

use std::collections::HashMap;

use crate::analysis::context::DirContext;
use crate::analysis::domain::Detection;

/// Condition under which a detector is considered for a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The lowercased directory name equals this string.
    Name(&'static str),
    /// The lowercased directory name starts with this string.
    Prefix(&'static str),
    /// The lowercased directory name ends with this string.
    Suffix(&'static str),
    /// Always considered. Use sparingly: these run for every directory.
    Always,
}

/// A classification rule.
///
/// Implementors are registered in [`Classifier::with_default_detectors`] and are
/// shared read-only across all scanner threads.
pub trait Detector: Send + Sync {
    /// Stable identifier, used in `--json` output and in test failures.
    fn id(&self) -> &'static str;

    /// Names or prefixes that make this detector worth running.
    fn triggers(&self) -> &'static [Trigger];

    /// Classify `ctx`, or return `None` if this rule does not apply.
    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection>;
}

/// The registry of detectors plus its dispatch index.
pub struct Classifier {
    detectors: Vec<Box<dyn Detector>>,
    by_name: HashMap<&'static str, Vec<usize>>,
    by_prefix: Vec<(&'static str, usize)>,
    by_suffix: Vec<(&'static str, usize)>,
    always: Vec<usize>,
}

impl std::fmt::Debug for Classifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Classifier")
            .field("detectors", &self.detectors.len())
            .field("names", &self.by_name.len())
            .field("prefixes", &self.by_prefix.len())
            .field("suffixes", &self.by_suffix.len())
            .field("always", &self.always.len())
            .finish()
    }
}

impl Default for Classifier {
    fn default() -> Self {
        Self::with_default_detectors()
    }
}

impl Classifier {
    /// Build a classifier from an explicit detector list (used by tests).
    #[must_use]
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        let mut by_name: HashMap<&'static str, Vec<usize>> = HashMap::new();
        let mut by_prefix = Vec::new();
        let mut by_suffix = Vec::new();
        let mut always = Vec::new();

        for (index, detector) in detectors.iter().enumerate() {
            for trigger in detector.triggers() {
                match trigger {
                    Trigger::Name(name) => by_name.entry(name).or_default().push(index),
                    Trigger::Prefix(prefix) => by_prefix.push((*prefix, index)),
                    Trigger::Suffix(suffix) => by_suffix.push((*suffix, index)),
                    Trigger::Always => always.push(index),
                }
            }
        }

        Classifier {
            detectors,
            by_name,
            by_prefix,
            by_suffix,
            always,
        }
    }

    /// The standard registry: every ecosystem Bloatrail knows about.
    ///
    /// Order matters only as a tie-break for detections of identical rank, so
    /// the more specific ecosystems are registered first.
    #[must_use]
    pub fn with_default_detectors() -> Self {
        Self::new(crate::detectors::all())
    }

    /// Number of registered detectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Classify a directory, returning the best-supported detection.
    ///
    /// Well-known machine locations (`~/.cargo/registry`, Docker's data
    /// directory, and so on) are consulted first because they carry evidence no
    /// name-based rule can reproduce; they still compete on rank with the
    /// context-aware detectors rather than short-circuiting them.
    #[must_use]
    pub fn classify(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        let mut best: Option<Detection> = None;

        if let Some(known) = ctx.env.detect(ctx.path, ctx.name_lower) {
            best = Some(known.clone());
        }

        let consider = |detector: &dyn Detector, best: &mut Option<Detection>| {
            if let Some(candidate) = detector.detect(ctx) {
                let better = match best {
                    Some(current) => candidate.rank() > current.rank(),
                    None => true,
                };
                if better {
                    *best = Some(candidate);
                }
            }
        };

        if let Some(indices) = self.by_name.get(ctx.name_lower) {
            for index in indices {
                consider(self.detectors[*index].as_ref(), &mut best);
            }
        }

        for (prefix, index) in &self.by_prefix {
            if ctx.name_lower.starts_with(prefix) {
                consider(self.detectors[*index].as_ref(), &mut best);
            }
        }

        for (suffix, index) in &self.by_suffix {
            if ctx.name_lower.ends_with(suffix) {
                consider(self.detectors[*index].as_ref(), &mut best);
            }
        }

        for index in &self.always {
            consider(self.detectors[*index].as_ref(), &mut best);
        }

        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::context::Markers;
    use crate::analysis::domain::{Category, CleanupSafety, Confidence};
    use crate::platform::KnownPaths;
    use std::path::Path;

    struct Fixed {
        id: &'static str,
        triggers: &'static [Trigger],
        detection: Detection,
    }

    impl Detector for Fixed {
        fn id(&self) -> &'static str {
            self.id
        }
        fn triggers(&self) -> &'static [Trigger] {
            self.triggers
        }
        fn detect(&self, _ctx: &DirContext<'_>) -> Option<Detection> {
            Some(self.detection.clone())
        }
    }

    fn context<'a>(name: &'a str, env: &'a KnownPaths, path: &'a Path) -> DirContext<'a> {
        DirContext {
            path,
            name,
            name_lower: name,
            parent_name: None,
            markers: Markers::empty(),
            parent_markers: Markers::empty(),
            grandparent_markers: Markers::empty(),
            depth: 1,
            subdir_count: 0,
            file_count: 0,
            env,
        }
    }

    #[test]
    fn dispatch_only_runs_matching_detectors() {
        static TRIGGERS: &[Trigger] = &[Trigger::Name("target")];
        let classifier = Classifier::new(vec![Box::new(Fixed {
            id: "fixed",
            triggers: TRIGGERS,
            detection: Detection::new(
                Category::BuildArtifact,
                Confidence::High,
                CleanupSafety::Safe,
                "hit",
            ),
        })]);

        let env = KnownPaths::empty();
        assert!(classifier
            .classify(&context("target", &env, Path::new("/p/target")))
            .is_some());
        assert!(classifier
            .classify(&context("src", &env, Path::new("/p/src")))
            .is_none());
    }

    #[test]
    fn prefix_triggers_match_generated_directory_names() {
        static TRIGGERS: &[Trigger] = &[Trigger::Prefix("cmake-build-")];
        let classifier = Classifier::new(vec![Box::new(Fixed {
            id: "cmake",
            triggers: TRIGGERS,
            detection: Detection::new(
                Category::BuildArtifact,
                Confidence::High,
                CleanupSafety::Safe,
                "hit",
            ),
        })]);
        let env = KnownPaths::empty();
        assert!(classifier
            .classify(&context("cmake-build-debug", &env, Path::new("/p/x")))
            .is_some());
        assert!(classifier
            .classify(&context("cmake", &env, Path::new("/p/x")))
            .is_none());
    }

    #[test]
    fn higher_confidence_wins_regardless_of_registration_order() {
        static TRIGGERS: &[Trigger] = &[Trigger::Name("build")];
        let low = Detection::new(
            Category::Unknown,
            Confidence::Low,
            CleanupSafety::Review,
            "low",
        );
        let high = Detection::new(
            Category::BuildArtifact,
            Confidence::High,
            CleanupSafety::Safe,
            "high",
        );

        let classifier = Classifier::new(vec![
            Box::new(Fixed {
                id: "low",
                triggers: TRIGGERS,
                detection: low.clone(),
            }),
            Box::new(Fixed {
                id: "high",
                triggers: TRIGGERS,
                detection: high.clone(),
            }),
        ]);
        let env = KnownPaths::empty();
        let result = classifier
            .classify(&context("build", &env, Path::new("/p/build")))
            .expect("a detection");
        assert_eq!(result.reason, high.reason);

        // Reversed registration order must produce the same winner.
        let classifier = Classifier::new(vec![
            Box::new(Fixed {
                id: "high",
                triggers: TRIGGERS,
                detection: high.clone(),
            }),
            Box::new(Fixed {
                id: "low",
                triggers: TRIGGERS,
                detection: low,
            }),
        ]);
        let result = classifier
            .classify(&context("build", &env, Path::new("/p/build")))
            .expect("a detection");
        assert_eq!(result.reason, high.reason);
    }

    #[test]
    fn specificity_breaks_ties_at_equal_confidence() {
        static TRIGGERS: &[Trigger] = &[Trigger::Name("dist")];
        let generic = Detection::new(
            Category::BuildArtifact,
            Confidence::High,
            CleanupSafety::Safe,
            "generic",
        )
        .with_specificity(10);
        let specific = Detection::new(
            Category::BuildArtifact,
            Confidence::High,
            CleanupSafety::Safe,
            "specific",
        )
        .with_specificity(90);

        let classifier = Classifier::new(vec![
            Box::new(Fixed {
                id: "generic",
                triggers: TRIGGERS,
                detection: generic,
            }),
            Box::new(Fixed {
                id: "specific",
                triggers: TRIGGERS,
                detection: specific,
            }),
        ]);
        let env = KnownPaths::empty();
        let result = classifier
            .classify(&context("dist", &env, Path::new("/p/dist")))
            .expect("a detection");
        assert_eq!(result.reason, "specific");
    }

    #[test]
    fn default_registry_is_populated() {
        let classifier = Classifier::with_default_detectors();
        assert!(classifier.len() > 5, "expected a real detector registry");
        assert!(!classifier.is_empty());
    }
}
