//! Executing an approved cleanup selection.
//!
//! The executor is structured so that a dry run is not a *policy* but a
//! *structure*: every mutating call funnels through one private `remove`
//! method whose first statement returns when [`ExecutionOptions::dry_run`] is
//! set, and the integration tests assert that every file survives a dry run of
//! a plan that would otherwise delete them.
//!
//! Removal defaults to the platform trash. Permanent deletion exists but has to
//! be asked for by name.

use std::path::{Path, PathBuf};

use crate::analysis::domain::CleanupSafety;
use crate::analysis::{sensitive, Classifier};
use crate::cleanup::planner::{CleanupGroup, CleanupTarget, TargetKind};
use crate::cleanup::safety::SafetyGuard;
use crate::error::{Error, Result};
use crate::pattern::ExcludeSet;
use crate::platform::KnownPaths;

/// How a removal was performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalMethod {
    /// Moved to the platform trash / recycle bin.
    Trash,
    /// Deleted irreversibly.
    Permanent,
    /// Nothing happened; this was a dry run.
    Simulated,
}

impl RemovalMethod {
    /// Human-readable description.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            RemovalMethod::Trash => "moved to trash",
            RemovalMethod::Permanent => "deleted",
            RemovalMethod::Simulated => "would be removed",
        }
    }
}

/// One completed (or simulated) removal.
#[derive(Debug, Clone)]
pub struct Removal {
    /// What was removed.
    pub path: PathBuf,
    /// How many bytes it accounted for.
    pub bytes: u64,
    /// How it was removed.
    pub method: RemovalMethod,
}

/// One removal that did not happen.
#[derive(Debug, Clone)]
pub struct Failure {
    /// What was not removed.
    pub path: PathBuf,
    /// Why not.
    pub reason: String,
    /// `true` when Bloatrail declined on safety grounds rather than failing.
    pub refused: bool,
}

/// The outcome of an execution.
#[derive(Debug, Clone, Default)]
pub struct ExecutionReport {
    /// Successful (or simulated) removals.
    pub removed: Vec<Removal>,
    /// Everything that was skipped, with a reason.
    pub failures: Vec<Failure>,
    /// Bytes accounted for by `removed`.
    pub bytes_freed: u64,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

impl ExecutionReport {
    /// Number of locations refused by the safety layer.
    #[must_use]
    pub fn refused_count(&self) -> usize {
        self.failures.iter().filter(|f| f.refused).count()
    }

    /// Number of locations that failed for other reasons.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.failures.iter().filter(|f| !f.refused).count()
    }
}

/// Execution settings.
#[derive(Debug, Clone, Default)]
pub struct ExecutionOptions {
    /// When set, absolutely nothing is modified.
    pub dry_run: bool,
    /// Delete permanently instead of moving to the trash.
    pub permanent: bool,
    /// The most permissive classification this run may act on.
    pub limit: CleanupSafety,
    /// The same exclusions the scan used.
    ///
    /// Age-limited removal re-walks a directory rather than replaying a stored
    /// file list, so without these it could delete files the scan was told to
    /// ignore — and which therefore never appeared in the preview.
    pub excludes: ExcludeSet,
}

impl ExecutionOptions {
    /// A dry run that would act on nothing more permissive than `Safe`.
    #[must_use]
    pub fn dry_run() -> Self {
        ExecutionOptions {
            dry_run: true,
            permanent: false,
            limit: CleanupSafety::Safe,
            excludes: ExcludeSet::default(),
        }
    }
}

/// Performs removals under the supervision of a [`SafetyGuard`].
pub struct Executor<'a> {
    guard: SafetyGuard<'a>,
    options: ExecutionOptions,
}

impl<'a> Executor<'a> {
    /// Build an executor for one run.
    #[must_use]
    pub fn new(
        root: &'a Path,
        known: &'a KnownPaths,
        classifier: &'a Classifier,
        options: ExecutionOptions,
    ) -> Self {
        Executor {
            guard: SafetyGuard::new(root, known, classifier, options.limit),
            options,
        }
    }

    /// Execute every target in `groups`.
    #[must_use]
    pub fn run<'g>(&self, groups: impl IntoIterator<Item = &'g CleanupGroup>) -> ExecutionReport {
        let mut report = ExecutionReport {
            dry_run: self.options.dry_run,
            ..ExecutionReport::default()
        };

        for group in groups {
            if !group.is_selectable() {
                report.failures.push(Failure {
                    path: PathBuf::from(&group.title),
                    reason: "this group cannot be removed by Bloatrail".to_string(),
                    refused: true,
                });
                continue;
            }
            for target in &group.targets {
                match self.execute_target(target) {
                    Ok(removals) => {
                        for removal in removals {
                            report.bytes_freed = report.bytes_freed.saturating_add(removal.bytes);
                            report.removed.push(removal);
                        }
                    }
                    Err(error) => report.failures.push(Failure {
                        path: target.path.clone(),
                        reason: error.to_string(),
                        refused: matches!(error, Error::RefusedDeletion { .. }),
                    }),
                }
            }
        }

        report
    }

    fn execute_target(&self, target: &CleanupTarget) -> Result<Vec<Removal>> {
        self.guard.verify(target)?;

        match target.kind {
            TargetKind::Directory => {
                let removal = self.remove(&target.path, target.bytes)?;
                Ok(vec![removal])
            }
            TargetKind::AgedFiles { days } => self.remove_aged_files(&target.path, days),
            TargetKind::External => Err(Error::refused(
                &target.path,
                "this storage is managed by an external tool",
            )),
        }
    }

    /// Remove one path.
    ///
    /// Every mutating call in Bloatrail funnels through this function, and the
    /// dry-run check is its first statement.
    fn remove(&self, path: &Path, bytes: u64) -> Result<Removal> {
        if self.options.dry_run {
            return Ok(Removal {
                path: path.to_path_buf(),
                bytes,
                method: RemovalMethod::Simulated,
            });
        }

        if self.options.permanent {
            let result = if path.is_dir() {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_file(path)
            };
            result.map_err(|error| Error::io(path, error))?;
            return Ok(Removal {
                path: path.to_path_buf(),
                bytes,
                method: RemovalMethod::Permanent,
            });
        }

        trash::delete(path).map_err(|error| Error::Trash {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        Ok(Removal {
            path: path.to_path_buf(),
            bytes,
            method: RemovalMethod::Trash,
        })
    }

    /// Remove files older than `days` beneath `dir`, leaving the directory
    /// structure intact.
    ///
    /// Directories are never removed here: an empty `Downloads/receipts/` is
    /// harmless, whereas removing it could break something that expects it.
    fn remove_aged_files(&self, dir: &Path, days: u32) -> Result<Vec<Removal>> {
        let cutoff = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(u64::from(days) * 86_400))
            .ok_or_else(|| Error::refused(dir, "the age threshold is out of range"))?;

        let mut removals = Vec::new();
        let mut stack = vec![dir.to_path_buf()];

        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                let Ok(meta) = entry.metadata() else { continue };
                // Never follow a link or a junction: its target may be anywhere.
                if file_type.is_symlink() || crate::platform::is_reparse_point(&meta) {
                    continue;
                }

                let raw_name = entry.file_name();
                let name = raw_name.to_string_lossy();

                // The scan never saw excluded paths, so they never appeared in
                // the preview and must not be removed here either.
                if self.options.excludes.excludes(&entry.path(), &name) {
                    continue;
                }

                if file_type.is_dir() {
                    if sensitive::is_protected_directory(&name) {
                        continue;
                    }
                    stack.push(entry.path());
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                if sensitive::classify(&name).is_some() {
                    continue;
                }

                let Ok(modified) = meta.modified() else {
                    continue;
                };
                if modified >= cutoff {
                    continue;
                }

                match self.remove(&entry.path(), meta.len()) {
                    Ok(removal) => removals.push(removal),
                    // One locked file must not abort the rest of the cleanup.
                    Err(_) => continue,
                }
            }
        }

        Ok(removals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::{Category, Confidence, Detection};
    use crate::cleanup::planner::CleanupGroup;

    fn cargo_project(root: &Path) -> PathBuf {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[package]\nname=\"x\"\n").unwrap();
        std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        let target = root.join("target");
        std::fs::create_dir_all(target.join("debug")).unwrap();
        std::fs::write(target.join("debug/artifact.bin"), vec![0u8; 2048]).unwrap();
        target
    }

    fn group_for(target_path: PathBuf) -> CleanupGroup {
        let detection = Detection::new(
            Category::BuildArtifact,
            Confidence::High,
            CleanupSafety::Safe,
            "Rust build artifacts",
        );
        CleanupGroup {
            index: Some(1),
            title: "Rust build artifacts".to_string(),
            safety: CleanupSafety::Safe,
            category: Category::BuildArtifact,
            technology: None,
            evidence: Vec::new(),
            regenerated_by: Some("cargo build".to_string()),
            targets: vec![CleanupTarget {
                path: target_path,
                bytes: 2048,
                files: 1,
                kind: TargetKind::Directory,
                confidence: Confidence::High,
                detection,
            }],
            bytes: 2048,
            external: false,
        }
    }

    #[test]
    fn dry_run_deletes_absolutely_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let target = cargo_project(root);
        let group = group_for(target.clone());

        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let executor = Executor::new(
            root,
            &known,
            &classifier,
            ExecutionOptions {
                dry_run: true,
                permanent: false,
                limit: CleanupSafety::Safe,
                excludes: ExcludeSet::default(),
            },
        );

        let report = executor.run([&group]);
        assert!(report.dry_run);
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed[0].method, RemovalMethod::Simulated);
        assert_eq!(report.bytes_freed, 2048);

        assert!(target.exists(), "a dry run must not remove the directory");
        assert!(target.join("debug/artifact.bin").exists());
        assert!(root.join("src/main.rs").exists());
    }

    #[test]
    fn permanent_removal_deletes_only_the_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let target = cargo_project(root);
        let group = group_for(target.clone());

        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let executor = Executor::new(
            root,
            &known,
            &classifier,
            ExecutionOptions {
                dry_run: false,
                permanent: true,
                limit: CleanupSafety::Safe,
                excludes: ExcludeSet::default(),
            },
        );

        let report = executor.run([&group]);
        assert!(
            report.failures.is_empty(),
            "unexpected failures: {:?}",
            report.failures
        );
        assert_eq!(report.removed[0].method, RemovalMethod::Permanent);
        assert!(!target.exists(), "the target should be gone");
        assert!(root.join("src/main.rs").exists(), "source must survive");
        assert!(root.join("Cargo.toml").exists());
    }

    #[test]
    fn a_target_that_no_longer_looks_like_build_output_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let target = cargo_project(root);
        let group = group_for(target.clone());

        // Someone removed the manifest: `target/` is now just a directory.
        std::fs::remove_file(root.join("Cargo.toml")).unwrap();

        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let executor = Executor::new(
            root,
            &known,
            &classifier,
            ExecutionOptions {
                dry_run: false,
                permanent: true,
                limit: CleanupSafety::Safe,
                excludes: ExcludeSet::default(),
            },
        );

        let report = executor.run([&group]);
        assert!(report.removed.is_empty());
        assert_eq!(report.refused_count(), 1);
        assert!(
            target.exists(),
            "a re-verification failure must preserve the target"
        );
    }

    #[test]
    fn unselectable_groups_are_never_executed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let target = cargo_project(root);
        let mut group = group_for(target.clone());
        group.index = None;

        let known = KnownPaths::empty();
        let classifier = Classifier::with_default_detectors();
        let executor = Executor::new(
            root,
            &known,
            &classifier,
            ExecutionOptions {
                dry_run: false,
                permanent: true,
                limit: CleanupSafety::Review,
                excludes: ExcludeSet::default(),
            },
        );

        let report = executor.run([&group]);
        assert!(report.removed.is_empty());
        assert!(target.exists());
    }
}
