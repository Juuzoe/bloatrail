//! The last line of defence before anything is removed.
//!
//! Every check here assumes the planner, the detectors or the caller might be
//! wrong. A target must survive *all* of them, and a refusal is an ordinary,
//! explainable outcome rather than a crash:
//!
//! 1. The path is absolute, contains no `..`, and lies inside the scan root.
//! 2. It is not a filesystem root, a home directory, an OS directory or a known
//!    credential store.
//! 3. Its recorded classification permits deletion at all.
//! 4. Re-running the classifier on the live filesystem still agrees.
//! 5. For anything below `High` confidence, a shallow scan finds no sensitive
//!    files inside.

use std::path::{Component, Path};

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{CleanupSafety, Confidence, Detection};
use crate::analysis::{sensitive, Classifier};
use crate::cleanup::planner::{is_within, CleanupTarget, TargetKind};
use crate::error::{Error, Result};
use crate::platform::KnownPaths;

/// Depth of the shallow sensitive-content scan for lower-confidence targets.
const SENSITIVE_SCAN_DEPTH: usize = 3;

/// Entries examined by the shallow scan before it gives up and refuses.
const SENSITIVE_SCAN_BUDGET: usize = 4_096;

/// Validates targets immediately before removal.
pub struct SafetyGuard<'a> {
    root: &'a Path,
    known: &'a KnownPaths,
    classifier: &'a Classifier,
    /// The most permissive classification the caller opted into.
    limit: CleanupSafety,
}

impl<'a> SafetyGuard<'a> {
    /// Create a guard for one cleanup run.
    #[must_use]
    pub fn new(
        root: &'a Path,
        known: &'a KnownPaths,
        classifier: &'a Classifier,
        limit: CleanupSafety,
    ) -> Self {
        SafetyGuard {
            root,
            known,
            classifier,
            limit,
        }
    }

    /// Check a target. `Ok(())` means removal may proceed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RefusedDeletion`] with a human-readable reason for every
    /// rejection.
    pub fn verify(&self, target: &CleanupTarget) -> Result<()> {
        let path = target.path.as_path();

        if target.kind == TargetKind::External {
            return Err(Error::refused(
                path,
                "this storage must be reclaimed through its own tool, not by deleting files",
            ));
        }

        self.check_shape(path)?;
        self.check_protected(path)?;
        self.check_classification(target)?;
        self.reverify_detection(target)?;
        self.check_sensitive_contents(target)?;
        Ok(())
    }

    /// Structural checks that need no filesystem access.
    fn check_shape(&self, path: &Path) -> Result<()> {
        if !path.is_absolute() {
            return Err(Error::refused(path, "the path is not absolute"));
        }
        if path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(Error::refused(
                path,
                "the path contains `.` or `..` components",
            ));
        }
        if !is_within(self.root, path) {
            return Err(Error::refused(
                path,
                "the path is outside the directory that was scanned",
            ));
        }
        // The lexical test above can be satisfied by a path that physically
        // lives elsewhere, because `--follow-symlinks` lets the tree contain
        // links. Compare the resolved locations too.
        if let (Ok(resolved), Ok(root)) = (
            std::fs::canonicalize(path),
            std::fs::canonicalize(self.root),
        ) {
            if !is_within(&root, &resolved) {
                return Err(Error::refused(
                    path,
                    format!(
                        "it resolves to `{}`, which is outside the directory that was scanned",
                        resolved.display()
                    ),
                ));
            }
        }
        if path == self.root && self.root.parent().is_none() {
            return Err(Error::refused(path, "the path is a filesystem root"));
        }
        Ok(())
    }

    /// Locations that are off limits regardless of what any detector concluded.
    fn check_protected(&self, path: &Path) -> Result<()> {
        if crate::platform::is_filesystem_root(path) {
            return Err(Error::refused(path, "the path is a filesystem root"));
        }
        if self.known.is_protected(path) {
            return Err(Error::refused(
                path,
                "this is a protected system or user directory",
            ));
        }
        for component in path.components() {
            if let Component::Normal(part) = component {
                if let Some(name) = part.to_str() {
                    if sensitive::is_protected_directory(name) {
                        return Err(Error::refused(
                            path,
                            format!("the path passes through the credential directory `{name}`"),
                        ));
                    }
                }
            }
        }
        // A symlink target could point anywhere; removing the link is not what
        // the user asked for, and following it certainly is not.
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() || crate::platform::is_reparse_point(&meta) {
                return Err(Error::refused(
                    path,
                    "the path is a symbolic link or reparse point",
                ));
            }
        }
        Ok(())
    }

    fn check_classification(&self, target: &CleanupTarget) -> Result<()> {
        let safety = target.detection.cleanup;
        if !safety.is_deletable() {
            return Err(Error::refused(
                &target.path,
                format!("it is classified {}", safety.label()),
            ));
        }
        if safety > self.limit {
            return Err(Error::refused(
                &target.path,
                format!(
                    "it is classified {} and this run only permits up to {}",
                    safety.label(),
                    self.limit.label()
                ),
            ));
        }
        Ok(())
    }

    /// Re-run classification against the live filesystem.
    ///
    /// The plan may have been built seconds or hours ago. If the directory no
    /// longer looks like what was detected — the `Cargo.toml` next to it is
    /// gone, someone replaced `target/` with their thesis — the removal is
    /// abandoned.
    fn reverify_detection(&self, target: &CleanupTarget) -> Result<()> {
        let path = &target.path;
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Err(Error::refused(
                path,
                "the path has no readable final component",
            ));
        };

        let metadata = std::fs::metadata(path)
            .map_err(|error| Error::refused(path, format!("it could not be inspected: {error}")))?;
        if !metadata.is_dir() {
            return Err(Error::refused(path, "it is no longer a directory"));
        }

        let markers = read_markers(path);
        let parent = path.parent();
        let parent_markers = parent.map(read_markers).unwrap_or_default();
        let grandparent_markers = parent
            .and_then(Path::parent)
            .map(read_markers)
            .unwrap_or_default();

        let lowered = name.to_lowercase();
        let ctx = DirContext {
            path,
            name,
            name_lower: &lowered,
            parent_name: parent.and_then(Path::file_name).and_then(|n| n.to_str()),
            markers,
            parent_markers,
            grandparent_markers,
            // Depth only affects the generic low-confidence rules, which refuse
            // to fire at the root of a scan; any non-zero value is correct here.
            depth: 1,
            subdir_count: 0,
            file_count: 0,
            env: self.known,
        };

        let Some(current) = self.classifier.classify(&ctx) else {
            return Err(Error::refused(
                path,
                "it no longer matches any known cleanup rule",
            ));
        };

        if current.category != target.detection.category {
            return Err(Error::refused(
                path,
                format!(
                    "it is now classified as {} rather than {}",
                    current.category.label(),
                    target.detection.category.label()
                ),
            ));
        }
        if !current.cleanup.is_deletable() || current.cleanup > self.limit {
            return Err(Error::refused(
                path,
                format!("it is now classified {}", current.cleanup.label()),
            ));
        }
        Ok(())
    }

    /// For anything Bloatrail is not highly confident about, look inside for
    /// keys, credentials and databases before removing it.
    ///
    /// This is skipped for high-confidence build output because those trees
    /// routinely contain test fixtures named `key.pem`, and blocking on those
    /// would make the tool useless without making anyone safer.
    fn check_sensitive_contents(&self, target: &CleanupTarget) -> Result<()> {
        let needs_check = target.confidence < Confidence::High
            || target.detection.cleanup == CleanupSafety::Review;
        if !needs_check {
            return Ok(());
        }

        let mut budget = SENSITIVE_SCAN_BUDGET;
        match scan_for_sensitive(&target.path, SENSITIVE_SCAN_DEPTH, &mut budget) {
            SensitiveScan::Clean => Ok(()),
            SensitiveScan::Found { path, reason } => Err(Error::refused(
                &target.path,
                format!("it contains `{}`, which {reason}", path.display()),
            )),
            SensitiveScan::Exhausted => Err(Error::refused(
                &target.path,
                "it is too large to check for sensitive files at this confidence level",
            )),
        }
    }
}

enum SensitiveScan {
    Clean,
    Found {
        path: std::path::PathBuf,
        reason: &'static str,
    },
    Exhausted,
}

fn scan_for_sensitive(dir: &Path, depth: usize, budget: &mut usize) -> SensitiveScan {
    if depth == 0 {
        return SensitiveScan::Clean;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return SensitiveScan::Clean;
    };

    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        if *budget == 0 {
            return SensitiveScan::Exhausted;
        }
        *budget -= 1;

        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);

        if is_dir {
            if sensitive::is_protected_directory(name) {
                return SensitiveScan::Found {
                    path: entry.path(),
                    reason: "is a credential directory",
                };
            }
            subdirs.push(entry.path());
            continue;
        }
        if let Some(kind) = sensitive::classify(name) {
            return SensitiveScan::Found {
                path: entry.path(),
                reason: kind.describe(),
            };
        }
    }

    for subdir in subdirs {
        match scan_for_sensitive(&subdir, depth - 1, budget) {
            SensitiveScan::Clean => {}
            other => return other,
        }
    }
    SensitiveScan::Clean
}

fn read_markers(path: &Path) -> Markers {
    let mut markers = Markers::empty();
    let Ok(entries) = std::fs::read_dir(path) else {
        return markers;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        match name.to_str() {
            Some(name) => markers.observe(name, is_dir),
            None => markers.observe(&name.to_string_lossy(), is_dir),
        }
    }
    markers
}

/// Human-readable explanation of what a detection permits.
#[must_use]
pub fn describe_permission(detection: &Detection) -> String {
    match detection.cleanup {
        CleanupSafety::Safe => {
            "Safe to remove: the contents are regenerated automatically.".to_string()
        }
        CleanupSafety::ProbablySafe => {
            "Recoverable, but regenerating it costs time or bandwidth.".to_string()
        }
        CleanupSafety::Review => {
            "Needs a decision from you; Bloatrail cannot tell whether it is still wanted."
                .to_string()
        }
        CleanupSafety::Dangerous => {
            "Removing this is likely to destroy something valuable.".to_string()
        }
        CleanupSafety::NeverDelete => {
            "Bloatrail will never remove this, whatever options are passed.".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::Category;
    use std::path::PathBuf;

    fn target(path: PathBuf, detection: Detection, confidence: Confidence) -> CleanupTarget {
        CleanupTarget {
            path,
            bytes: 10,
            files: 1,
            kind: TargetKind::Directory,
            confidence,
            detection,
        }
    }

    fn rust_target_detection() -> Detection {
        Detection::new(
            Category::BuildArtifact,
            Confidence::High,
            CleanupSafety::Safe,
            "Rust build artifacts",
        )
    }

    #[test]
    fn relative_paths_are_refused() {
        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let root = PathBuf::from("/scan");
        let guard = SafetyGuard::new(&root, &known, &classifier, CleanupSafety::Review);

        let error = guard
            .verify(&target(
                PathBuf::from("relative/target"),
                rust_target_detection(),
                Confidence::High,
            ))
            .unwrap_err();
        assert!(error.to_string().contains("not absolute"));
    }

    #[test]
    fn paths_outside_the_scan_root_are_refused() {
        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let root = std::env::temp_dir().join("bloatrail-guard-root");
        let guard = SafetyGuard::new(&root, &known, &classifier, CleanupSafety::Review);

        let outside = std::env::temp_dir().join("somewhere-else");
        let error = guard
            .verify(&target(outside, rust_target_detection(), Confidence::High))
            .unwrap_err();
        assert!(error.to_string().contains("outside"));
    }

    #[test]
    fn credential_directories_are_refused_anywhere_in_the_path() {
        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let root = std::env::temp_dir();
        let guard = SafetyGuard::new(&root, &known, &classifier, CleanupSafety::Review);

        let path = root.join(".ssh").join("target");
        let error = guard
            .verify(&target(path, rust_target_detection(), Confidence::High))
            .unwrap_err();
        assert!(error.to_string().contains(".ssh"));
    }

    #[test]
    fn never_delete_classifications_are_refused() {
        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let root = std::env::temp_dir();
        let guard = SafetyGuard::new(&root, &known, &classifier, CleanupSafety::Review);

        let detection = Detection::new(
            Category::GitData,
            Confidence::Certain,
            CleanupSafety::NeverDelete,
            "Git repository data",
        );
        let error = guard
            .verify(&target(root.join("x"), detection, Confidence::Certain))
            .unwrap_err();
        assert!(error.to_string().contains("DO NOT AUTO DELETE"));
    }

    #[test]
    fn a_safety_limit_below_the_target_classification_refuses() {
        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let root = std::env::temp_dir();
        let guard = SafetyGuard::new(&root, &known, &classifier, CleanupSafety::Safe);

        let detection = Detection::new(
            Category::Cache,
            Confidence::High,
            CleanupSafety::Review,
            "Cache directory",
        );
        let error = guard
            .verify(&target(root.join("x"), detection, Confidence::High))
            .unwrap_err();
        assert!(error.to_string().contains("only permits"));
    }

    #[test]
    fn external_targets_are_never_deleted_directly() {
        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let root = std::env::temp_dir();
        let guard = SafetyGuard::new(&root, &known, &classifier, CleanupSafety::Review);

        let mut candidate = target(
            root.join("docker"),
            rust_target_detection(),
            Confidence::High,
        );
        candidate.kind = TargetKind::External;
        let error = guard.verify(&candidate).unwrap_err();
        assert!(error.to_string().contains("its own tool"));
    }
}
