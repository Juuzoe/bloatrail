//! Context-poor names.
//!
//! `logs`, `tmp` and `cache` mean roughly what they say, but "roughly" is the
//! operative word: these rules always report [`Confidence::Medium`] or lower and
//! never claim more than partial reclaimability, so nothing here can be selected
//! by an unattended `bloatrail clean`.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{
    Category, CleanupSafety, Confidence, Detection, Reclaim, Technology,
};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_STRONG, SPEC_WEAK};

/// Application log directories.
pub struct LogDirectory;

static LOG_TRIGGERS: &[Trigger] = &[Trigger::Name("logs"), Trigger::Name("log")];

impl Detector for LogDirectory {
    fn id(&self) -> &'static str {
        "generic.logs"
    }

    fn triggers(&self) -> &'static [Trigger] {
        LOG_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        // A `log` directory at the root of a scan is more likely to be someone's
        // data directory than a rotating application log.
        if ctx.depth == 0 {
            return None;
        }
        Some(
            Detection::new(
                Category::Log,
                Confidence::Medium,
                CleanupSafety::Review,
                "Application logs",
            )
            .with_evidence(
                "Log files are usually disposable, but they are also the only record of what a \
                 service did. Bloatrail proposes only files older than 30 days.",
            )
            .with_reclaim(Reclaim::OlderThan { days: 30 })
            .with_specificity(SPEC_WEAK),
        )
    }
}

/// Scratch directories.
pub struct TempDirectory;

static TEMP_TRIGGERS: &[Trigger] = &[
    Trigger::Name("tmp"),
    Trigger::Name("temp"),
    Trigger::Name(".tmp"),
    Trigger::Name("tempfiles"),
];

impl Detector for TempDirectory {
    fn id(&self) -> &'static str {
        "generic.temp"
    }

    fn triggers(&self) -> &'static [Trigger] {
        TEMP_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if ctx.depth == 0 {
            return None;
        }
        Some(
            Detection::new(
                Category::Temporary,
                Confidence::Medium,
                CleanupSafety::Review,
                "Temporary files",
            )
            .with_evidence(
                "Scratch storage. Files still held open by a running program cannot be removed \
                 and are skipped automatically.",
            )
            .with_reclaim(Reclaim::OlderThan { days: 7 })
            .with_specificity(SPEC_WEAK),
        )
    }
}

/// Generic cache directories with no ecosystem attached.
pub struct CacheDirectory;

static CACHE_TRIGGERS: &[Trigger] = &[
    Trigger::Name("cache"),
    Trigger::Name(".cache"),
    Trigger::Name("caches"),
];

impl Detector for CacheDirectory {
    fn id(&self) -> &'static str {
        "generic.cache"
    }

    fn triggers(&self) -> &'static [Trigger] {
        CACHE_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if ctx.depth == 0 {
            return None;
        }
        Some(
            Detection::new(
                Category::Cache,
                Confidence::Medium,
                CleanupSafety::Review,
                "Cache directory",
            )
            .with_evidence(
                "The name says cache, but nothing here identifies which program owns it or \
                 whether it can regenerate the contents.",
            )
            .with_reclaim(Reclaim::OlderThan { days: 30 })
            .with_specificity(SPEC_WEAK),
        )
    }
}

/// Container-engine storage found outside the well-known locations.
pub struct ContainerDirectory;

static CONTAINER_TRIGGERS: &[Trigger] = &[
    Trigger::Name("overlay2"),
    Trigger::Name("containerd"),
    Trigger::Name("buildkit"),
    Trigger::Name("docker-desktop-data"),
];

/// Marker files that mean "this is somebody's source tree", not engine storage.
///
/// `containerd` and `buildkit` are the names of two widely cloned open-source
/// projects as well as two storage directories. A checkout of either would
/// otherwise be collapsed and reported as container data — hiding its contents
/// and mis-attributing its source code.
const SOURCE_FINGERPRINT: Markers = Markers::GIT_DIR
    .union(Markers::GO_MOD)
    .union(Markers::CARGO_TOML)
    .union(Markers::PACKAGE_JSON)
    .union(Markers::PYPROJECT)
    .union(Markers::POM_XML)
    .union(Markers::GRADLE_BUILD)
    .union(Markers::CMAKELISTS)
    .union(Markers::MAKEFILE)
    .union(Markers::DOTNET_PROJECT);

/// Directory names that plausibly contain a container engine's storage.
fn parent_looks_like_container_root(ctx: &DirContext<'_>) -> bool {
    ctx.parent_name.is_some_and(|parent| {
        matches!(
            parent.to_ascii_lowercase().as_str(),
            "docker"
                | "containers"
                | "storage"
                | "moby"
                | "lib"
                | "wsl"
                | "docker-desktop-data"
                | "com.docker.docker"
        )
    })
}

impl Detector for ContainerDirectory {
    fn id(&self) -> &'static str {
        "generic.container"
    }

    fn triggers(&self) -> &'static [Trigger] {
        CONTAINER_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if ctx.markers.intersects(SOURCE_FINGERPRINT) {
            return None;
        }
        // `overlay2` and `docker-desktop-data` are storage-only names. The other
        // two are also project names, so they have to earn it.
        if matches!(ctx.name_lower, "containerd" | "buildkit")
            && !parent_looks_like_container_root(ctx)
        {
            return None;
        }

        Some(
            Detection::new(
                Category::ContainerData,
                Confidence::High,
                CleanupSafety::Review,
                "Container engine storage",
            )
            .with_technology(Technology::Docker)
            .with_evidence(
                "Image layers and container state. Deleting these files directly corrupts the \
                 container engine's metadata.",
            )
            .with_evidence("Reclaim this space with `docker system prune` instead.")
            .with_reclaim(Reclaim::External)
            .collapsed()
            .with_specificity(SPEC_STRONG),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::{ctx, ctx_full};
    use crate::platform::KnownPaths;

    #[test]
    fn generic_rules_never_report_high_confidence() {
        let env = KnownPaths::empty();
        for (detector, name) in [
            (&LogDirectory as &dyn Detector, "logs"),
            (&TempDirectory as &dyn Detector, "tmp"),
            (&CacheDirectory as &dyn Detector, "cache"),
        ] {
            let detection = detector
                .detect(&ctx(name, Markers::empty(), &env))
                .unwrap_or_else(|| panic!("{name} should be detected"));
            assert!(
                detection.confidence <= Confidence::Medium,
                "{name} must not be high confidence"
            );
            assert!(
                !detection.cleanup.is_auto_selectable(),
                "{name} must not be auto-selected"
            );
        }
    }

    #[test]
    fn generic_rules_only_offer_aged_content() {
        let env = KnownPaths::empty();
        let detection = LogDirectory
            .detect(&ctx("logs", Markers::empty(), &env))
            .expect("detection");
        assert!(matches!(detection.reclaim, Reclaim::OlderThan { .. }));
    }

    #[test]
    fn container_storage_is_flagged_for_external_tooling() {
        let env = KnownPaths::empty();
        let detection = ContainerDirectory
            .detect(&ctx("overlay2", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.reclaim, Reclaim::External);
        assert_eq!(detection.cleanup, CleanupSafety::Review);
    }

    #[test]
    fn a_source_checkout_of_containerd_is_not_container_storage() {
        let env = KnownPaths::empty();
        // `~/src/containerd` — a clone of the project, not a storage directory.
        let context = ctx_full(
            "containerd",
            Markers::GO_MOD | Markers::GIT_DIR,
            Markers::empty(),
            Markers::empty(),
            &env,
        );
        assert!(
            ContainerDirectory.detect(&context).is_none(),
            "a Go module with a .git directory is somebody's source tree"
        );
    }

    #[test]
    fn ambiguous_container_names_require_a_plausible_parent() {
        let env = KnownPaths::empty();

        // `~/projects/buildkit` — no evidence at all beyond the name.
        let bare = ctx_full(
            "buildkit",
            Markers::empty(),
            Markers::empty(),
            Markers::empty(),
            &env,
        );
        assert!(ContainerDirectory.detect(&bare).is_none());

        // `/var/lib/docker/buildkit` — the parent identifies it.
        let mut in_docker = bare;
        in_docker.parent_name = Some("docker");
        assert!(ContainerDirectory.detect(&in_docker).is_some());
    }

    #[test]
    fn storage_only_names_still_match_without_a_parent_hint() {
        let env = KnownPaths::empty();
        for name in ["overlay2", "docker-desktop-data"] {
            let context = ctx_full(
                name,
                Markers::empty(),
                Markers::empty(),
                Markers::empty(),
                &env,
            );
            assert!(
                ContainerDirectory.detect(&context).is_some(),
                "`{name}` is only ever engine storage"
            );
        }
    }
}
