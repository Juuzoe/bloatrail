//! Version-control metadata.
//!
//! Bloatrail reports the size of repository metadata and never proposes
//! deleting it. A `.git` directory contains history that may exist nowhere
//! else — including unpushed commits and stashes — so it is classified
//! [`CleanupSafety::NeverDelete`] no matter how large it is.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{
    Category, CleanupSafety, Confidence, Detection, Reclaim, Technology,
};
use crate::analysis::engine::{Detector, Trigger};

use super::SPEC_CONTEXT;

/// `.git`, `.hg`, `.svn`, `.jj` and friends.
pub struct VersionControl;

static TRIGGERS: &[Trigger] = &[
    Trigger::Name(".git"),
    Trigger::Name(".hg"),
    Trigger::Name(".svn"),
    Trigger::Name(".jj"),
    Trigger::Name(".bzr"),
];

impl Detector for VersionControl {
    fn id(&self) -> &'static str {
        "vcs.repository"
    }

    fn triggers(&self) -> &'static [Trigger] {
        TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        let (label, technology) = match ctx.name_lower {
            ".git" => ("Git repository data", Technology::Git),
            ".hg" => ("Mercurial repository data", Technology::Git),
            ".svn" => ("Subversion working copy metadata", Technology::Git),
            ".jj" => ("Jujutsu repository data", Technology::Git),
            ".bzr" => ("Bazaar repository data", Technology::Git),
            _ => return None,
        };

        // A directory holding `HEAD`, `objects/` and `refs/` is a git directory
        // beyond any doubt.
        //
        // Bare repositories have exactly this layout but can be named anything,
        // so no name trigger reaches them; they are measured as ordinary
        // directories. Recognising them would mean running a structural check on
        // every directory in the scan, which is not a trade worth making for a
        // classification that would be `NeverDelete` either way.
        let structurally_certain = ctx.name_lower == ".git"
            && ctx
                .markers
                .contains(Markers::GIT_HEAD | Markers::GIT_OBJECTS | Markers::GIT_REFS);

        let confidence = if structurally_certain {
            Confidence::Certain
        } else {
            Confidence::High
        };

        let mut detection = Detection::new(
            Category::GitData,
            confidence,
            CleanupSafety::NeverDelete,
            label,
        )
        .with_technology(technology)
        .with_evidence(
            "Repository metadata holds your entire history, including commits and stashes that \
             may not exist on any remote.",
        )
        .with_evidence(
            "Bloatrail never deletes version-control data. To shrink it safely, run \
             `git gc --aggressive --prune=now` inside the repository.",
        )
        .with_reclaim(Reclaim::None)
        .collapsed()
        .with_specificity(SPEC_CONTEXT);

        if structurally_certain {
            detection = detection
                .with_evidence("`HEAD`, `objects/` and `refs/` are all present in this directory.");
        }

        Some(detection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::{ctx, ctx_full};
    use crate::platform::KnownPaths;

    #[test]
    fn git_directories_are_never_deletable() {
        let env = KnownPaths::empty();
        let detection = VersionControl
            .detect(&ctx(".git", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.cleanup, CleanupSafety::NeverDelete);
        assert_eq!(detection.reclaim, Reclaim::None);
        assert!(!detection.cleanup.is_deletable());
    }

    #[test]
    fn full_git_layout_is_certain() {
        let env = KnownPaths::empty();
        let context = ctx_full(
            ".git",
            Markers::GIT_HEAD | Markers::GIT_OBJECTS | Markers::GIT_REFS,
            Markers::empty(),
            Markers::empty(),
            &env,
        );
        let detection = VersionControl.detect(&context).expect("detection");
        assert_eq!(detection.confidence, Confidence::Certain);
    }

    #[test]
    fn other_vcs_systems_are_recognised_too() {
        let env = KnownPaths::empty();
        for name in [".hg", ".svn", ".jj"] {
            let detection = VersionControl
                .detect(&ctx(name, Markers::empty(), &env))
                .unwrap_or_else(|| panic!("{name} should be detected"));
            assert_eq!(detection.category, Category::GitData);
            assert_eq!(detection.cleanup, CleanupSafety::NeverDelete);
        }
    }
}
