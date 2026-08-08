//! Python ecosystem detection.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_STRONG};

/// Interpreter and tooling caches. These are the safest thing on the disk to
/// delete: Python rewrites them on the next import.
pub struct PythonCache;

static CACHE_TRIGGERS: &[Trigger] = &[
    Trigger::Name("__pycache__"),
    Trigger::Name(".pytest_cache"),
    Trigger::Name(".mypy_cache"),
    Trigger::Name(".ruff_cache"),
    Trigger::Name(".hypothesis"),
    Trigger::Name(".ipynb_checkpoints"),
    Trigger::Name(".tox"),
    Trigger::Name(".nox"),
    Trigger::Name(".pytype"),
];

impl Detector for PythonCache {
    fn id(&self) -> &'static str {
        "python.cache"
    }

    fn triggers(&self) -> &'static [Trigger] {
        CACHE_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        let (label, evidence, command) = match ctx.name_lower {
            "__pycache__" => (
                "Python bytecode cache",
                "CPython writes compiled `.pyc` files here and regenerates them silently on the \
                 next import.",
                "python -c ''",
            ),
            ".pytest_cache" => (
                "pytest cache",
                "Stores the last test run's state so `--lf` works; regenerated on the next run.",
                "pytest",
            ),
            ".mypy_cache" => (
                "mypy incremental cache",
                "Speeds up repeat type checks and is rebuilt automatically.",
                "mypy .",
            ),
            ".ruff_cache" => (
                "Ruff lint cache",
                "Rebuilt on the next lint run.",
                "ruff check .",
            ),
            ".hypothesis" => (
                "Hypothesis example database",
                "Stores failing examples found by property tests. Deleting it loses the \
                 shrunken counter-examples from previous runs, but not any code.",
                "pytest",
            ),
            ".ipynb_checkpoints" => (
                "Jupyter notebook checkpoints",
                "Autosaved notebook snapshots. Deleting them removes the ability to revert an \
                 unsaved notebook to its last checkpoint.",
                "",
            ),
            ".tox" => (
                "tox virtual environments",
                "Recreated by the next `tox` run, which re-downloads and reinstalls packages.",
                "tox",
            ),
            ".nox" => (
                "nox virtual environments",
                "Recreated by the next `nox` run.",
                "nox",
            ),
            ".pytype" => (
                "pytype cache",
                "Rebuilt on the next type-check run.",
                "pytype",
            ),
            _ => return None,
        };

        // `.tox`/`.nox` hold full environments: safe, but expensive to rebuild.
        let safety = if matches!(ctx.name_lower, ".tox" | ".nox" | ".hypothesis") {
            CleanupSafety::ProbablySafe
        } else {
            CleanupSafety::Safe
        };

        let mut detection = Detection::new(Category::Cache, Confidence::High, safety, label)
            .with_technology(Technology::Python)
            .with_evidence(evidence)
            .collapsed()
            .with_specificity(SPEC_STRONG);

        if !command.is_empty() {
            detection = detection.regenerated_by(command);
        }
        Some(detection)
    }
}

/// Virtual environments.
///
/// These are recoverable but disruptive: an editor pointing at `.venv` stops
/// working until the environment is recreated, and locally installed editable
/// packages are not always reproducible.
pub struct VirtualEnv;

static VENV_TRIGGERS: &[Trigger] = &[
    Trigger::Name(".venv"),
    Trigger::Name("venv"),
    Trigger::Name("env"),
    Trigger::Name(".virtualenv"),
    Trigger::Name("site-packages"),
    Trigger::Name("__pypackages__"),
];

impl Detector for VirtualEnv {
    fn id(&self) -> &'static str {
        "python.virtualenv"
    }

    fn triggers(&self) -> &'static [Trigger] {
        VENV_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if ctx.name_lower == "site-packages" || ctx.name_lower == "__pypackages__" {
            return Some(
                Detection::new(
                    Category::Dependency,
                    Confidence::High,
                    CleanupSafety::ProbablySafe,
                    "Installed Python packages",
                )
                .with_technology(Technology::Python)
                .with_evidence("Third-party packages installed by pip or an equivalent tool.")
                .regenerated_by("pip install -r requirements.txt")
                .collapsed()
                .with_specificity(SPEC_STRONG),
            );
        }

        // `env` and `venv` are far too generic to act on by name alone. A
        // `pyvenv.cfg` inside the directory is what actually makes it a virtual
        // environment, and the walker has already seen it.
        let is_venv = ctx.has(Markers::PYVENV_CFG);
        if !is_venv {
            if ctx.name_lower == ".venv" && ctx.parent_is_project(Markers::PY_PROJECT) {
                // `.venv` is conventional enough to accept with project context,
                // even if the config file could not be read.
                return Some(venv_detection(Confidence::Medium, false));
            }
            return None;
        }

        Some(venv_detection(Confidence::Certain, true))
    }
}

fn venv_detection(confidence: Confidence, has_cfg: bool) -> Detection {
    let mut detection = Detection::new(
        Category::Dependency,
        confidence,
        CleanupSafety::ProbablySafe,
        "Python virtual environment",
    )
    .with_technology(Technology::Python)
    .with_evidence(
        "A virtual environment contains an interpreter copy and installed packages, not your \
         code.",
    )
    .with_evidence(
        "Recreating it requires re-running the install step, and editable or locally built \
         packages may not reinstall cleanly.",
    )
    .regenerated_by("python -m venv .venv && pip install -r requirements.txt")
    .collapsed()
    .with_specificity(SPEC_CONTEXT);

    if has_cfg {
        detection = detection
            .with_evidence("A `pyvenv.cfg` file inside this directory identifies it definitively.");
    }
    detection
}

/// Packaging output produced by setuptools / build backends.
pub struct PythonBuild;

static BUILD_TRIGGERS: &[Trigger] = &[
    Trigger::Name(".eggs"),
    Trigger::Name("build"),
    Trigger::Name("dist"),
    Trigger::Suffix(".egg-info"),
];

impl Detector for PythonBuild {
    fn id(&self) -> &'static str {
        "python.build"
    }

    fn triggers(&self) -> &'static [Trigger] {
        BUILD_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if ctx.name_lower.ends_with(".egg-info") {
            return Some(
                Detection::new(
                    Category::BuildArtifact,
                    Confidence::High,
                    CleanupSafety::Safe,
                    "setuptools package metadata",
                )
                .with_technology(Technology::Python)
                .with_evidence(
                    "Regenerated whenever the package is built or installed in editable mode.",
                )
                .regenerated_by("pip install -e .")
                .collapsed()
                .with_specificity(SPEC_STRONG),
            );
        }
        if !ctx.parent_is_project(Markers::PY_PROJECT) {
            return None;
        }
        // Do not fight the JS detector over a `dist` in a mixed project.
        if ctx.parent_is_project(Markers::JS_PROJECT) {
            return None;
        }

        let label = match ctx.name_lower {
            ".eggs" => "setuptools egg cache",
            "build" => "Python build directory",
            "dist" => "Python distribution artifacts",
            _ => return None,
        };

        Some(
            Detection::new(
                Category::BuildArtifact,
                Confidence::Medium,
                CleanupSafety::ProbablySafe,
                label,
            )
            .with_technology(Technology::Python)
            .with_evidence("Produced by the packaging backend when building a wheel or sdist.")
            .regenerated_by("python -m build")
            .collapsed()
            .with_specificity(SPEC_STRONG - 20),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::{ctx, ctx_full};
    use crate::platform::KnownPaths;

    #[test]
    fn pycache_is_safe_everywhere() {
        let env = KnownPaths::empty();
        let detection = PythonCache
            .detect(&ctx("__pycache__", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
        assert_eq!(detection.category, Category::Cache);
        assert!(detection.collapse);
    }

    #[test]
    fn tox_environments_are_only_probably_safe() {
        let env = KnownPaths::empty();
        let detection = PythonCache
            .detect(&ctx(".tox", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.cleanup, CleanupSafety::ProbablySafe);
    }

    #[test]
    fn a_directory_called_env_is_not_a_virtualenv_without_evidence() {
        let env = KnownPaths::empty();
        assert!(VirtualEnv
            .detect(&ctx("env", Markers::empty(), &env))
            .is_none());
        assert!(VirtualEnv
            .detect(&ctx("venv", Markers::empty(), &env))
            .is_none());
    }

    #[test]
    fn pyvenv_cfg_identifies_a_virtualenv_definitively() {
        let env = KnownPaths::empty();
        let context = ctx_full(
            "env",
            Markers::PYVENV_CFG,
            Markers::empty(),
            Markers::empty(),
            &env,
        );
        let detection = VirtualEnv.detect(&context).expect("detection");
        assert_eq!(detection.confidence, Confidence::Certain);
        assert_eq!(detection.cleanup, CleanupSafety::ProbablySafe);
    }

    #[test]
    fn virtualenvs_are_never_marked_safe() {
        let env = KnownPaths::empty();
        let context = ctx_full(
            ".venv",
            Markers::PYVENV_CFG,
            Markers::PYPROJECT,
            Markers::empty(),
            &env,
        );
        let detection = VirtualEnv.detect(&context).expect("detection");
        assert_ne!(
            detection.cleanup,
            CleanupSafety::Safe,
            "deleting a virtualenv is more disruptive than deleting __pycache__"
        );
    }

    #[test]
    fn python_build_requires_python_project_markers() {
        let env = KnownPaths::empty();
        assert!(PythonBuild
            .detect(&ctx("build", Markers::empty(), &env))
            .is_none());
        assert!(PythonBuild
            .detect(&ctx("build", Markers::PYPROJECT, &env))
            .is_some());
    }

    #[test]
    fn python_build_defers_to_javascript_in_mixed_projects() {
        let env = KnownPaths::empty();
        let context = ctx("dist", Markers::PYPROJECT | Markers::PACKAGE_JSON, &env);
        assert!(PythonBuild.detect(&context).is_none());
    }
}
