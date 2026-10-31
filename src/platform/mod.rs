//! Platform awareness: where things live, how much room is left, and which
//! paths must never be touched.
//!
//! Everything platform-specific is funnelled through this module so the
//! scanner, classifier and cleanup engine stay portable. Features that only
//! exist on one OS degrade to `None`/`false` elsewhere rather than being
//! `#[cfg]`-ed out of the call sites.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::analysis::domain::{
    Category, CleanupSafety, Confidence, Detection, Reclaim, Technology,
};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{disk_usage, file_identity, is_reparse_point, volume_id};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{disk_usage, file_identity, is_reparse_point, volume_id};

#[cfg(not(any(windows, unix)))]
mod fallback;
#[cfg(not(any(windows, unix)))]
pub use fallback::{disk_usage, file_identity, is_reparse_point, volume_id};

/// What the filesystem reveals about a file's on-disk identity.
///
/// The two facts are deliberately separate, because filesystems can supply one
/// without the other: a link count with an untrustworthy file ID (ReFS reports
/// an all-ones marker for IDs that do not fit in 64 bits) still tells a caller
/// the file has several names, even though it cannot say which paths they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// A (volume, file) pair: two paths with the same pair are the same bytes
    /// on disk under two names. `None` when the filesystem's file IDs cannot
    /// be trusted to distinguish files.
    pub id: Option<(u64, u64)>,
    /// How many directory entries point at the file in total — including names
    /// outside whatever set the caller happens to be looking at. At least 1.
    pub links: u64,
}

/// Free and total capacity of the filesystem holding a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage {
    /// Total capacity in bytes.
    pub total: u64,
    /// Bytes available to the current user.
    pub available: u64,
}

impl DiskUsage {
    /// Bytes currently in use.
    #[must_use]
    pub const fn used(self) -> u64 {
        self.total.saturating_sub(self.available)
    }

    /// Used fraction in `0.0..=1.0`.
    #[must_use]
    pub fn used_fraction(self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.used() as f64 / self.total as f64).clamp(0.0, 1.0)
    }
}

/// A well-known directory with a pre-computed classification.
#[derive(Debug, Clone)]
struct KnownEntry {
    detection: Detection,
}

/// Machine-specific locations Bloatrail knows about.
///
/// Built once at startup and shared (read-only) across every scanner thread.
/// Lookup is a two-step process: a cheap `HashSet<&str>` test on the directory
/// name, then a hash lookup on the normalised full path. The name pre-filter
/// means the overwhelming majority of directories cost one string hash.
#[derive(Debug, Default)]
pub struct KnownPaths {
    /// The current user's home directory, if it could be determined.
    pub home: Option<PathBuf>,
    /// The user's downloads directory.
    pub downloads: Option<PathBuf>,
    /// The user's documents directory.
    pub documents: Option<PathBuf>,
    /// The system temporary directory.
    pub temp: PathBuf,
    lookup: HashMap<String, KnownEntry>,
    trigger_names: HashSet<String>,
    protected: Vec<PathBuf>,
    /// Every registration as a machine-independent identity, sorted.
    rules: Vec<String>,
}

impl KnownPaths {
    /// Discover the well-known locations for this machine.
    #[must_use]
    pub fn discover() -> Self {
        Self::build(dirs::home_dir())
    }

    /// The registry this platform builds around `home`.
    fn build(home: Option<PathBuf>) -> Self {
        let mut builder = Builder::new(home);

        builder.common();
        #[cfg(windows)]
        builder.windows();
        #[cfg(target_os = "macos")]
        builder.macos();
        #[cfg(all(unix, not(target_os = "macos")))]
        builder.linux();

        builder.finish()
    }

    /// An empty registry: used by tests that want detection to depend only on
    /// project context, not on the machine running the test.
    #[must_use]
    pub fn empty() -> Self {
        KnownPaths {
            home: None,
            downloads: None,
            documents: None,
            temp: std::env::temp_dir(),
            lookup: HashMap::new(),
            trigger_names: HashSet::new(),
            protected: Vec::new(),
            rules: Vec::new(),
        }
    }

    /// The registered locations as rules rather than paths, sorted.
    ///
    /// Each rule names where a location is anchored (`~`, `%LOCALAPPDATA%`,
    /// the Downloads folder), the path beneath that anchor as written in the
    /// registry, and what the registration does to the bytes inside: their
    /// category, and whether the subtree is collapsed or claimed. No resolved
    /// path appears, so two machines with different user names, or one whose
    /// Downloads folder lives on another drive, produce the same list, and a
    /// rule counts whether or not its location exists here. This is what the
    /// scan's coverage stamp hashes.
    #[must_use]
    pub fn rules(&self) -> &[String] {
        &self.rules
    }

    /// Look up a directory by path. `name_lower` must be the lowercased final
    /// component; it is used as a fast reject.
    #[must_use]
    pub fn detect(&self, path: &Path, name_lower: &str) -> Option<&Detection> {
        if !self.trigger_names.contains(name_lower) {
            return None;
        }
        self.lookup.get(&normalise_key(path)).map(|e| &e.detection)
    }

    /// Whether this path is one Bloatrail refuses to delete regardless of
    /// classification: home itself, filesystem roots, OS directories, and the
    /// user's document folders.
    #[must_use]
    pub fn is_protected(&self, path: &Path) -> bool {
        if is_filesystem_root(path) {
            return true;
        }
        let key = normalise_key(path);
        self.protected.iter().any(|p| normalise_key(p) == key)
    }

    /// Render a path for humans, abbreviating the home directory as `~`.
    #[must_use]
    pub fn display(&self, path: &Path) -> String {
        if let Some(home) = &self.home {
            if let Ok(rest) = path.strip_prefix(home) {
                if rest.as_os_str().is_empty() {
                    return "~".to_string();
                }
                let sep = std::path::MAIN_SEPARATOR;
                return format!("~{sep}{}", rest.display());
            }
        }
        path.display().to_string()
    }

    /// Number of registered well-known locations (used by `doctor`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lookup.len()
    }

    /// Whether no well-known locations were registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lookup.is_empty()
    }
}

/// Normalise a path into a comparison key.
///
/// Windows paths are case-insensitive, so keys are lowercased there. Trailing
/// separators are stripped everywhere so `C:\x\` and `C:\x` compare equal.
#[must_use]
pub fn normalise_key(path: &Path) -> String {
    let mut s = path.to_string_lossy().into_owned();
    while s.len() > 1 && (s.ends_with('/') || s.ends_with('\\')) {
        s.pop();
    }
    if cfg!(windows) {
        s = s.replace('/', "\\").to_lowercase();
    }
    s
}

/// Whether `path` is the root of a filesystem (`/`, `C:\`, `\\server\share`).
#[must_use]
pub fn is_filesystem_root(path: &Path) -> bool {
    let mut components = path.components();
    match components.next() {
        None => true,
        Some(Component::Prefix(_)) => {
            // `C:` then optionally `\`.
            matches!(components.next(), None | Some(Component::RootDir))
                && components.next().is_none()
        }
        Some(Component::RootDir) => components.next().is_none(),
        _ => false,
    }
}

/// Where a well-known location is rooted.
///
/// A registration names its anchor rather than a resolved path so that the
/// rule itself carries no machine-specific detail: see [`KnownPaths::rules`].
#[derive(Debug, Clone, Copy)]
enum Anchor {
    /// The user's home directory.
    Home,
    /// The platform's Downloads folder, wherever the user has moved it.
    Downloads,
    /// The platform's Documents folder.
    Documents,
    /// The platform's Videos folder.
    Videos,
    /// The platform's Pictures folder.
    Pictures,
    /// The platform's Music folder.
    Music,
    /// `%LOCALAPPDATA%`.
    #[cfg(windows)]
    LocalAppData,
    /// `%APPDATA%`.
    #[cfg(windows)]
    RoamingAppData,
    /// A fixed absolute path, the same on every machine.
    #[cfg(unix)]
    Fixed(&'static str),
}

impl Anchor {
    /// How the anchor is written in a rule identity.
    fn tag(self) -> &'static str {
        match self {
            Anchor::Home => "~",
            Anchor::Downloads => "{downloads}",
            Anchor::Documents => "{documents}",
            Anchor::Videos => "{videos}",
            Anchor::Pictures => "{pictures}",
            Anchor::Music => "{music}",
            #[cfg(windows)]
            Anchor::LocalAppData => "%LOCALAPPDATA%",
            #[cfg(windows)]
            Anchor::RoamingAppData => "%APPDATA%",
            #[cfg(unix)]
            Anchor::Fixed(path) => path,
        }
    }
}

/// Stands for the current user's login name inside a registered path.
///
/// Bazel names its output root after the user (`_bazel_<user>`), so that one
/// path cannot be written down without it. The rule keeps the placeholder; the
/// resolved path gets the name.
const USER: &str = "{user}";

/// The login name tools put into per-user paths, as Bazel reads it.
fn login_name() -> Option<String> {
    let variable = if cfg!(windows) { "USERNAME" } else { "USER" };
    std::env::var(variable).ok().filter(|name| !name.is_empty())
}

/// Builder that assembles the well-known location registry.
struct Builder {
    home: Option<PathBuf>,
    user: Option<String>,
    entries: Vec<(PathBuf, Detection)>,
    protected: Vec<PathBuf>,
    rules: Vec<String>,
}

impl Builder {
    fn new(home: Option<PathBuf>) -> Self {
        Builder {
            home,
            user: login_name(),
            entries: Vec::new(),
            protected: Vec::new(),
            rules: Vec::new(),
        }
    }

    fn resolve(&self, anchor: Anchor) -> Option<PathBuf> {
        match anchor {
            Anchor::Home => self.home.clone(),
            Anchor::Downloads => dirs::download_dir(),
            Anchor::Documents => dirs::document_dir(),
            Anchor::Videos => dirs::video_dir(),
            Anchor::Pictures => dirs::picture_dir(),
            Anchor::Music => dirs::audio_dir(),
            #[cfg(windows)]
            Anchor::LocalAppData => dirs::data_local_dir(),
            #[cfg(windows)]
            Anchor::RoamingAppData => dirs::data_dir(),
            #[cfg(unix)]
            Anchor::Fixed(path) => Some(PathBuf::from(path)),
        }
    }

    /// Register `anchor/rel` when the anchor resolves on this machine.
    ///
    /// The rule is recorded either way: the registry's rules describe what
    /// this build of Bloatrail knows, not what this machine happens to have.
    fn add(&mut self, anchor: Anchor, rel: &str, detection: Detection) {
        self.rules.push(rule_identity(anchor, rel, &detection));

        let Some(mut path) = self.resolve(anchor) else {
            return;
        };
        if !rel.is_empty() {
            let rel = if rel.contains(USER) {
                let Some(user) = &self.user else { return };
                rel.replace(USER, user)
            } else {
                rel.to_string()
            };
            for part in rel.split('/') {
                path.push(part);
            }
        }
        self.entries.push((path, detection));
    }

    fn home_rel(&self, rel: &str) -> Option<PathBuf> {
        self.home.as_ref().map(|h| {
            let mut p = h.clone();
            for part in rel.split('/') {
                p.push(part);
            }
            p
        })
    }

    fn protect(&mut self, path: Option<PathBuf>) {
        if let Some(path) = path {
            self.protected.push(path);
        }
    }

    fn finish(self) -> KnownPaths {
        let mut lookup = HashMap::with_capacity(self.entries.len());
        let mut trigger_names = HashSet::new();
        for (path, detection) in self.entries {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                trigger_names.insert(name.to_lowercase());
            }
            lookup.insert(normalise_key(&path), KnownEntry { detection });
        }
        let mut rules = self.rules;
        rules.sort_unstable();
        KnownPaths {
            home: self.home.clone(),
            downloads: dirs::download_dir(),
            documents: dirs::document_dir(),
            temp: std::env::temp_dir(),
            lookup,
            trigger_names,
            protected: self.protected,
            rules,
        }
    }

    /// Locations that exist on every desktop platform.
    fn common(&mut self) {
        let home = self.home.clone();
        self.protect(home.clone());
        self.protect(dirs::document_dir());
        self.protect(dirs::desktop_dir());
        self.protect(dirs::picture_dir());
        self.protect(self.home_rel(".ssh"));
        self.protect(self.home_rel(".gnupg"));
        self.protect(self.home_rel(".aws"));
        self.protect(self.home_rel(".kube"));
        self.protect(self.home_rel(".config"));

        // ---- Rust -------------------------------------------------------
        self.add(
            Anchor::Home,
            ".cargo/registry",
            cache(
                Category::PackageCache,
                Technology::Rust,
                CleanupSafety::ProbablySafe,
                "Cargo registry cache",
            )
            .with_evidence(
                "Cargo stores downloaded crate sources and `.crate` archives here. \
                 They are re-downloaded automatically on the next build that needs them.",
            )
            .regenerated_by("cargo fetch")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".cargo/git",
            cache(
                Category::PackageCache,
                Technology::Rust,
                CleanupSafety::ProbablySafe,
                "Cargo git dependency checkouts",
            )
            .with_evidence("Checkouts of git dependencies; Cargo re-clones them when needed.")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".rustup/toolchains",
            cache(
                Category::Application,
                Technology::Rust,
                CleanupSafety::Review,
                "Installed Rust toolchains",
            )
            .with_evidence(
                "Removing a toolchain breaks builds that pin it. Use `rustup toolchain uninstall` \
                 to remove the ones you no longer use.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".rustup/downloads",
            cache(
                Category::Cache,
                Technology::Rust,
                CleanupSafety::Safe,
                "rustup download cache",
            )
            .with_evidence("Partially downloaded toolchain archives; rustup refetches them.")
            .collapsed(),
        );

        // ---- JavaScript -------------------------------------------------
        self.add(
            Anchor::Home,
            ".npm/_cacache",
            cache(
                Category::PackageCache,
                Technology::Node,
                CleanupSafety::Safe,
                "npm content-addressable cache",
            )
            .with_evidence("npm re-downloads any package it cannot find in the cache.")
            .regenerated_by("npm cache clean --force")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".yarn/berry/cache",
            cache(
                Category::PackageCache,
                Technology::Node,
                CleanupSafety::ProbablySafe,
                "Yarn Berry cache",
            )
            .with_evidence(
                "Yarn Plug'n'Play projects resolve packages straight out of this cache, so \
                 removing it forces a reinstall in every project using PnP.",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".cache/yarn",
            cache(
                Category::PackageCache,
                Technology::Node,
                CleanupSafety::Safe,
                "Yarn classic cache",
            )
            .regenerated_by("yarn cache clean")
            .collapsed(),
        );
        self.add(Anchor::Home, ".pnpm-store", pnpm_store());
        self.add(
            Anchor::Home,
            ".bun/install/cache",
            cache(
                Category::PackageCache,
                Technology::Bun,
                CleanupSafety::Safe,
                "Bun install cache",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".deno",
            cache(
                Category::PackageCache,
                Technology::Deno,
                CleanupSafety::ProbablySafe,
                "Deno dependency cache",
            )
            .with_evidence("Deno re-fetches remote modules on the next run.")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".node-gyp",
            cache(
                Category::Cache,
                Technology::Node,
                CleanupSafety::Safe,
                "node-gyp header cache",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".electron",
            cache(
                Category::Cache,
                Technology::Node,
                CleanupSafety::ProbablySafe,
                "Electron binary cache",
            )
            .collapsed(),
        );

        // ---- Python -----------------------------------------------------
        self.add(
            Anchor::Home,
            ".cache/pip",
            cache(
                Category::PackageCache,
                Technology::Python,
                CleanupSafety::Safe,
                "pip download cache",
            )
            .regenerated_by("pip cache purge")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".cache/uv",
            cache(
                Category::PackageCache,
                Technology::Python,
                CleanupSafety::Safe,
                "uv package cache",
            )
            .regenerated_by("uv cache clean")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".cache/pypoetry",
            cache(
                Category::PackageCache,
                Technology::Python,
                CleanupSafety::Safe,
                "Poetry cache",
            )
            .collapsed(),
        );
        for conda in [
            ".conda/pkgs",
            "anaconda3/pkgs",
            "miniconda3/pkgs",
            "miniforge3/pkgs",
        ] {
            self.add(
                Anchor::Home,
                conda,
                cache(
                    Category::PackageCache,
                    Technology::Python,
                    CleanupSafety::ProbablySafe,
                    "Conda package cache",
                )
                .regenerated_by("conda clean --all")
                .collapsed(),
            );
        }

        // ---- JVM / Android ----------------------------------------------
        self.add(
            Anchor::Home,
            ".m2/repository",
            cache(
                Category::PackageCache,
                Technology::Maven,
                CleanupSafety::ProbablySafe,
                "Maven local repository",
            )
            .with_evidence(
                "Re-downloading a large Maven repository can take a long time, and locally \
                 installed (`mvn install`) artifacts are not recoverable from the internet.",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".gradle/caches",
            cache(
                Category::PackageCache,
                Technology::Gradle,
                CleanupSafety::ProbablySafe,
                "Gradle build cache",
            )
            .with_evidence("Gradle rebuilds and re-downloads what it needs on the next build.")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".gradle/daemon",
            cache(
                Category::Log,
                Technology::Gradle,
                CleanupSafety::Safe,
                "Gradle daemon logs",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".android/avd",
            cache(
                Category::VirtualMachine,
                Technology::Android,
                CleanupSafety::Review,
                "Android emulator images",
            )
            .with_evidence("Emulator snapshots may contain app state you have not backed up.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".gradle/wrapper",
            cache(
                Category::PackageCache,
                Technology::Gradle,
                CleanupSafety::ProbablySafe,
                "Gradle wrapper distributions",
            )
            .collapsed(),
        );

        // ---- .NET / Go / others -----------------------------------------
        self.add(
            Anchor::Home,
            ".nuget/packages",
            cache(
                Category::PackageCache,
                Technology::DotNet,
                CleanupSafety::ProbablySafe,
                "NuGet global package cache",
            )
            .regenerated_by("dotnet nuget locals all --clear")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            "go/pkg/mod",
            cache(
                Category::PackageCache,
                Technology::Go,
                CleanupSafety::ProbablySafe,
                "Go module cache",
            )
            .with_evidence("Module sources are re-downloaded on the next build.")
            .regenerated_by("go clean -modcache")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".cache/go-build",
            cache(
                Category::Cache,
                Technology::Go,
                CleanupSafety::Safe,
                "Go build cache",
            )
            .regenerated_by("go clean -cache")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".cargo/bin",
            cache(
                Category::Application,
                Technology::Rust,
                CleanupSafety::NeverDelete,
                "Cargo-installed binaries",
            )
            .with_evidence("These are tools you installed with `cargo install`."),
        );
        self.add(
            Anchor::Home,
            ".cache/composer",
            cache(
                Category::PackageCache,
                Technology::Php,
                CleanupSafety::Safe,
                "Composer cache",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".terraform.d/plugin-cache",
            cache(
                Category::PackageCache,
                Technology::Terraform,
                CleanupSafety::Safe,
                "Terraform provider cache",
            )
            .collapsed(),
        );

        // ---- Test tooling ------------------------------------------------
        for (rel, label) in [
            (".cache/ms-playwright", "Playwright browser downloads"),
            (".cache/puppeteer", "Puppeteer browser downloads"),
            (".cache/Cypress", "Cypress binary cache"),
        ] {
            self.add(Anchor::Home, rel, browser_download(label));
        }

        // ---- Machine learning model caches --------------------------------
        for (rel, label) in [
            (".cache/huggingface", "Hugging Face model cache"),
            (".ollama/models", "Ollama model storage"),
            (".cache/torch", "PyTorch model cache"),
        ] {
            self.add(
                Anchor::Home,
                rel,
                cache(
                    Category::Cache,
                    Technology::Python,
                    CleanupSafety::Review,
                    label,
                )
                .with_evidence(
                    "Model weights are re-downloadable but often many gigabytes; delete only \
                         models you no longer use.",
                )
                .with_reclaim(Reclaim::External)
                .collapsed(),
            );
        }

        self.language_stores();
        self.version_managers();
        self.embedded_toolchains();
        self.virtual_machines();

        // ---- Containers ---------------------------------------------------
        self.add(
            Anchor::Home,
            ".docker",
            cache(
                Category::ContainerData,
                Technology::Docker,
                CleanupSafety::Review,
                "Docker client configuration and data",
            )
            .with_evidence("Contains credentials and CLI configuration as well as cached data.")
            .with_reclaim(Reclaim::External),
        );

        // ---- User content --------------------------------------------------
        self.add(
            Anchor::Downloads,
            "",
            Detection::new(
                Category::Download,
                Confidence::High,
                CleanupSafety::Review,
                "Downloads folder",
            )
            .with_evidence(
                "Downloaded files are rarely needed once installed, but only you know which \
                 ones still matter.",
            )
            .with_reclaim(Reclaim::OlderThan { days: 90 })
            .claiming_contents()
            .with_specificity(60),
        );
        self.add(
            Anchor::Documents,
            "",
            Detection::new(
                Category::Document,
                Confidence::High,
                CleanupSafety::NeverDelete,
                "Documents folder",
            )
            .with_evidence("User documents are never removed by Bloatrail.")
            .claiming_contents()
            .with_specificity(60),
        );
        self.add(
            Anchor::Videos,
            "",
            Detection::new(
                Category::Video,
                Confidence::High,
                CleanupSafety::NeverDelete,
                "Videos folder",
            )
            .claiming_contents()
            .with_specificity(60),
        );
        self.add(
            Anchor::Pictures,
            "",
            Detection::new(
                Category::Image,
                Confidence::High,
                CleanupSafety::NeverDelete,
                "Pictures folder",
            )
            .claiming_contents()
            .with_specificity(60),
        );
        self.add(
            Anchor::Music,
            "",
            Detection::new(
                Category::Audio,
                Confidence::High,
                CleanupSafety::NeverDelete,
                "Music folder",
            )
            .claiming_contents()
            .with_specificity(60),
        );
    }

    /// Shared package stores of language ecosystems, in the same place on
    /// every platform.
    fn language_stores(&mut self) {
        // ---- Dart ----------------------------------------------------------
        self.add(Anchor::Home, ".pub-cache", pub_cache());

        // ---- JVM: Ivy, sbt ---------------------------------------------------
        self.add(
            Anchor::Home,
            ".ivy2/cache",
            cache(
                Category::PackageCache,
                Technology::Jvm,
                CleanupSafety::ProbablySafe,
                "Ivy dependency cache",
            )
            .with_evidence(
                "sbt and Ivy download anything missing again on the next build. Artifacts \
                 published with `sbt publishLocal` live beside it in `~/.ivy2/local` and are \
                 not part of this.",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".sbt/boot",
            cache(
                Category::PackageCache,
                Technology::Jvm,
                CleanupSafety::ProbablySafe,
                "sbt launcher downloads",
            )
            .with_evidence(
                "The sbt and Scala versions the launcher fetched for your builds; it downloads \
                 one again when a build asks for it. Global settings and plugins elsewhere in \
                 `~/.sbt` are not part of this.",
            )
            .collapsed(),
        );

        // ---- Haskell: Stack ------------------------------------------------
        self.add(
            Anchor::Home,
            ".stack/pantry",
            cache(
                Category::PackageCache,
                Technology::Haskell,
                CleanupSafety::ProbablySafe,
                "Stack package index and downloads",
            )
            .with_evidence(
                "Stack downloads the Hackage index and package sources again on the next build \
                 that needs them; the index alone is a sizeable download.",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".stack/snapshots",
            cache(
                Category::BuildArtifact,
                Technology::Haskell,
                CleanupSafety::ProbablySafe,
                "Stack snapshot builds",
            )
            .with_evidence(
                "Libraries compiled once per resolver snapshot and shared by every project on \
                 it. Stack rebuilds them on the next build, which can take a long time.",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".stack/programs",
            cache(
                Category::Application,
                Technology::Haskell,
                CleanupSafety::Review,
                "GHC versions installed by Stack",
            )
            .with_evidence(
                "Stack installs a missing compiler again when a project's resolver needs it, but \
                 each one is a large download. Delete the versions you no longer use rather \
                 than all of them.",
            )
            .collapsed(),
        );

        // ---- C/C++: Conan --------------------------------------------------
        for (rel, label) in [
            (".conan2/p", "Conan package cache"),
            (".conan/data", "Conan 1 package cache"),
        ] {
            self.add(
                Anchor::Home,
                rel,
                cache(
                    Category::PackageCache,
                    Technology::Cpp,
                    CleanupSafety::ProbablySafe,
                    label,
                )
                .with_evidence(
                    "Packages downloaded from a remote are fetched again, but packages built \
                     here from source (`--build`, `conan create`) have to be built again, which \
                     for large libraries can take hours, and ones you never uploaded cannot be \
                     downloaded again.",
                )
                .collapsed(),
            );
        }

        // ---- Elixir, OCaml -----------------------------------------------------
        self.add(
            Anchor::Home,
            ".hex/packages",
            cache(
                Category::PackageCache,
                Technology::Elixir,
                CleanupSafety::Safe,
                "Hex package cache",
            )
            .with_evidence(
                "Package archives Hex keeps after fetching; Mix downloads any it needs again.",
            )
            .regenerated_by("mix deps.get")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".opam/download-cache",
            cache(
                Category::PackageCache,
                Technology::Ocaml,
                CleanupSafety::Safe,
                "opam download cache",
            )
            .with_evidence(
                "Source archives opam keeps after installing a package; it downloads them again \
                 when it needs them.",
            )
            .regenerated_by("opam clean --download-cache")
            .collapsed(),
        );

        // ---- Julia -----------------------------------------------------------
        self.add(
            Anchor::Home,
            ".julia/packages",
            cache(
                Category::PackageCache,
                Technology::Julia,
                CleanupSafety::ProbablySafe,
                "Julia package sources",
            )
            .with_evidence(
                "Pkg downloads the versions an environment needs again on `Pkg.instantiate()`, \
                 but until then `using` fails in every environment that relied on them. \
                 Packages you are developing live in `~/.julia/dev` and are not part of this.",
            )
            .with_evidence("`Pkg.gc()` removes only the versions no environment uses any more.")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".julia/artifacts",
            cache(
                Category::PackageCache,
                Technology::Julia,
                CleanupSafety::ProbablySafe,
                "Julia binary artifacts",
            )
            .with_evidence(
                "Prebuilt libraries and data that packages download on demand; Pkg fetches them \
                 again for an environment on `Pkg.instantiate()`.",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".julia/compiled",
            cache(
                Category::Cache,
                Technology::Julia,
                CleanupSafety::Safe,
                "Julia precompilation cache",
            )
            .with_evidence(
                "Julia precompiles packages again the next time they are loaded, which can take \
                 minutes for a large environment.",
            )
            .collapsed(),
        );

        // ---- Hook runners --------------------------------------------------
        self.add(
            Anchor::Home,
            ".cache/pre-commit",
            cache(
                Category::Cache,
                Technology::Python,
                CleanupSafety::Safe,
                "pre-commit hook environments",
            )
            .with_evidence("pre-commit clones and installs each hook again on its next run.")
            .regenerated_by("pre-commit clean")
            .collapsed(),
        );
    }

    /// Toolchain and runtime versions installed per user by a version manager.
    ///
    /// The versions themselves are choices — a default the shell runs, a pin a
    /// project needs — so they are `Review` and removed through the manager.
    /// Only the managers' download caches are offered outright.
    fn version_managers(&mut self) {
        self.add(
            Anchor::Home,
            ".nvm/versions",
            cache(
                Category::Application,
                Technology::Node,
                CleanupSafety::Review,
                "Node.js versions installed with nvm",
            )
            .with_evidence(
                "Each version carries the global npm packages installed into it, and a shell \
                 that uses it stops working when it is gone.",
            )
            .with_evidence("Remove the versions you no longer use with `nvm uninstall <version>`.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".nvm/.cache",
            cache(
                Category::Cache,
                Technology::Node,
                CleanupSafety::Safe,
                "nvm download cache",
            )
            .with_evidence(
                "Node.js archives nvm keeps after installing; installed versions do not need \
                 them.",
            )
            .regenerated_by("nvm cache clear")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".pyenv/versions",
            cache(
                Category::Application,
                Technology::Python,
                CleanupSafety::Review,
                "Python versions installed with pyenv",
            )
            .with_evidence(
                "pyenv builds each version from source, and pyenv-virtualenv keeps its virtual \
                 environments here too, so an entry can be an environment holding packages you \
                 installed by hand.",
            )
            .with_evidence("Remove the ones you no longer use with `pyenv uninstall <version>`.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".sdkman/candidates",
            cache(
                Category::Application,
                Technology::Jvm,
                CleanupSafety::Review,
                "SDKs installed with SDKMAN!",
            )
            .with_evidence(
                "JDKs and build tools you chose to install, including the defaults your shell \
                 runs. Remove a version with `sdk uninstall <candidate> <version>`.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".sdkman/archives",
            cache(
                Category::PackageCache,
                Technology::Jvm,
                CleanupSafety::Safe,
                "SDKMAN! download archives",
            )
            .with_evidence(
                "Archives SDKMAN! keeps after installing; installed SDKs do not need them.",
            )
            .regenerated_by("sdk flush archives")
            .collapsed(),
        );
        self.add(Anchor::Home, ".volta/tools/image", volta_toolchains());
        self.add(Anchor::Home, ".volta/tools/inventory", volta_downloads());
        self.add(
            Anchor::Home,
            ".elan/toolchains",
            cache(
                Category::Application,
                Technology::Lean,
                CleanupSafety::Review,
                "Lean toolchains installed by elan",
            )
            .with_evidence(
                "A project pins its toolchain in `lean-toolchain` and elan downloads it again \
                 when it is missing, but each is a large download. Remove the ones you no \
                 longer use with `elan toolchain uninstall <name>`.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".ghcup/ghc",
            cache(
                Category::Application,
                Technology::Haskell,
                CleanupSafety::Review,
                "GHC versions installed by GHCup",
            )
            .with_evidence(
                "Compilers you chose to install, including the one `ghc` runs by default. \
                 Remove a version with `ghcup rm ghc <version>`.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".ghcup/cache",
            cache(
                Category::PackageCache,
                Technology::Haskell,
                CleanupSafety::Safe,
                "GHCup download cache",
            )
            .with_evidence(
                "Release archives GHCup keeps after installing; installed tools do not need them.",
            )
            .regenerated_by("ghcup gc --cache")
            .collapsed(),
        );
    }

    /// Embedded toolchains, which download compilers and SDKs per board.
    fn embedded_toolchains(&mut self) {
        for (rel, label) in [
            (
                ".platformio/packages",
                "PlatformIO toolchains and frameworks",
            ),
            (".platformio/platforms", "PlatformIO development platforms"),
        ] {
            self.add(
                Anchor::Home,
                rel,
                cache(
                    Category::PackageCache,
                    Technology::PlatformIo,
                    CleanupSafety::ProbablySafe,
                    label,
                )
                .with_evidence(
                    "PlatformIO installs what a project's `platformio.ini` asks for again on its \
                     next build, but toolchains and frameworks are large downloads.",
                )
                .collapsed(),
            );
        }
        self.add(
            Anchor::Home,
            ".platformio/.cache",
            cache(
                Category::Cache,
                Technology::PlatformIo,
                CleanupSafety::Safe,
                "PlatformIO download cache",
            )
            .with_evidence("Downloads and registry responses PlatformIO fetches again when needed.")
            .collapsed(),
        );

        self.add(
            Anchor::Home,
            ".espressif/dist",
            cache(
                Category::PackageCache,
                Technology::EspIdf,
                CleanupSafety::Safe,
                "ESP-IDF tool downloads",
            )
            .with_evidence(
                "Archives ESP-IDF's tool installer keeps after unpacking; installed tools do \
                 not need them.",
            )
            .collapsed(),
        );
        for (rel, category, label) in [
            (
                ".espressif/tools",
                Category::PackageCache,
                "ESP-IDF toolchains",
            ),
            (
                ".espressif/python_env",
                Category::Dependency,
                "ESP-IDF Python environments",
            ),
        ] {
            self.add(
                Anchor::Home,
                rel,
                cache(
                    category,
                    Technology::EspIdf,
                    CleanupSafety::ProbablySafe,
                    label,
                )
                .with_evidence(
                    "ESP-IDF's install script (`install.sh` or `install.bat` in the ESP-IDF \
                     directory) puts these here and recreates them, but they are large \
                     downloads, and ESP-IDF will not build until it has run again.",
                )
                .collapsed(),
            );
        }
    }

    /// Virtual machines and the images they are made from.
    ///
    /// `.lima`, `.colima` and `.minikube` are not traversed by default: they
    /// hold SSH keys and cluster certificates beside the disks, so their rules
    /// apply with `--include-hidden` or when one is scanned directly. Machine
    /// disks are `Review` and reclaimed through the tool that owns them:
    /// deleting the files destroys whatever lives inside the VM.
    fn virtual_machines(&mut self) {
        self.add(
            Anchor::Home,
            ".vagrant.d/boxes",
            cache(
                Category::VirtualMachine,
                Technology::Vagrant,
                CleanupSafety::Review,
                "Vagrant base boxes",
            )
            .with_evidence(
                "Base images that `vagrant up` creates machines from. Vagrant downloads a \
                 missing box again when a Vagrantfile needs it, provided its host still offers \
                 that version.",
            )
            .with_evidence(
                "Remove old versions with `vagrant box prune`, or one box with \
                 `vagrant box remove <name>`.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".minikube/cache",
            cache(
                Category::Cache,
                Technology::Kubernetes,
                CleanupSafety::ProbablySafe,
                "minikube download cache",
            )
            .with_evidence(
                "VM images, preloaded container images and Kubernetes binaries; \
                 `minikube start` downloads what it needs again.",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".minikube/machines",
            cache(
                Category::VirtualMachine,
                Technology::Kubernetes,
                CleanupSafety::Review,
                "minikube cluster machines",
            )
            .with_evidence(
                "Clusters run with a VM driver keep their disks here, holding every workload, \
                 image and volume inside them. Remove a cluster with `minikube delete`.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".lima",
            cache(
                Category::VirtualMachine,
                Technology::Lima,
                CleanupSafety::Review,
                "Lima virtual machines",
            )
            .with_evidence(
                "Each instance's disk holds everything installed and stored inside that VM. \
                 Remove an instance with `limactl delete <name>`.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".colima",
            cache(
                Category::VirtualMachine,
                Technology::Docker,
                CleanupSafety::Review,
                "Colima virtual machines",
            )
            .with_evidence(
                "The VM disk holds every image, container and volume of the container runtime \
                 inside it. Free space inside it with `docker system prune`, or remove a \
                 profile with `colima delete`.",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
    }

    #[cfg(windows)]
    fn windows(&mut self) {
        self.protect(Some(PathBuf::from(r"C:\Windows")));
        self.protect(Some(PathBuf::from(r"C:\Program Files")));
        self.protect(Some(PathBuf::from(r"C:\Program Files (x86)")));

        self.add(
            Anchor::LocalAppData,
            "Temp",
            cache(
                Category::Temporary,
                Technology::System,
                CleanupSafety::ProbablySafe,
                "Windows user temporary files",
            )
            .with_evidence(
                "Files still open by a running program cannot be removed and are skipped.",
            )
            .with_reclaim(Reclaim::OlderThan { days: 7 })
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "npm-cache",
            cache(
                Category::PackageCache,
                Technology::Node,
                CleanupSafety::Safe,
                "npm cache",
            )
            .regenerated_by("npm cache clean --force")
            .collapsed(),
        );
        self.add(Anchor::LocalAppData, "pnpm/store", pnpm_store());
        self.add(
            Anchor::LocalAppData,
            "Yarn/Cache",
            cache(
                Category::PackageCache,
                Technology::Node,
                CleanupSafety::Safe,
                "Yarn cache",
            )
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "pip/Cache",
            cache(
                Category::PackageCache,
                Technology::Python,
                CleanupSafety::Safe,
                "pip download cache",
            )
            .regenerated_by("pip cache purge")
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "uv/cache",
            cache(
                Category::PackageCache,
                Technology::Python,
                CleanupSafety::Safe,
                "uv package cache",
            )
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "ms-playwright",
            cache(
                Category::Cache,
                Technology::Node,
                CleanupSafety::ProbablySafe,
                "Playwright browser downloads",
            )
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "Docker/wsl",
            cache(
                Category::ContainerData,
                Technology::Docker,
                CleanupSafety::Review,
                "Docker Desktop WSL virtual disk",
            )
            .with_evidence(
                "Docker Desktop stores images, containers and volumes inside a virtual disk here. \
                 Deleting these files destroys every container and volume on the machine.",
            )
            .with_evidence("Reclaim space with `docker system prune` instead of deleting files.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "Docker",
            cache(
                Category::ContainerData,
                Technology::Docker,
                CleanupSafety::Review,
                "Docker Desktop data",
            )
            .with_reclaim(Reclaim::External),
        );
        self.add(
            Anchor::LocalAppData,
            "CrashDumps",
            cache(
                Category::Temporary,
                Technology::System,
                CleanupSafety::Safe,
                "Application crash dumps",
            )
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "JetBrains",
            cache(
                Category::Cache,
                Technology::JetBrains,
                CleanupSafety::Review,
                "JetBrains IDE caches and indexes",
            )
            .with_evidence("Indexes are rebuilt on next start, which can take several minutes.")
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "Microsoft/VisualStudio",
            cache(
                Category::Cache,
                Technology::VisualStudio,
                CleanupSafety::Review,
                "Visual Studio caches and settings",
            )
            .with_evidence("Also contains per-user settings, not only regenerable caches."),
        );
        self.add(
            Anchor::LocalAppData,
            "NuGet/v3-cache",
            cache(
                Category::PackageCache,
                Technology::DotNet,
                CleanupSafety::Safe,
                "NuGet HTTP cache",
            )
            .regenerated_by("dotnet nuget locals http-cache --clear")
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "Microsoft/Windows/INetCache",
            cache(
                Category::Cache,
                Technology::System,
                CleanupSafety::ProbablySafe,
                "Windows internet cache",
            )
            .collapsed(),
        );
        self.add(
            Anchor::RoamingAppData,
            "Code/CachedData",
            cache(
                Category::Cache,
                Technology::VsCode,
                CleanupSafety::Safe,
                "VS Code cached data",
            )
            .collapsed(),
        );
        self.add(
            Anchor::RoamingAppData,
            "Code/Cache",
            cache(
                Category::Cache,
                Technology::VsCode,
                CleanupSafety::Safe,
                "VS Code cache",
            )
            .collapsed(),
        );
        self.add(
            Anchor::LocalAppData,
            "Temp/chocolatey",
            cache(
                Category::PackageCache,
                Technology::System,
                CleanupSafety::Safe,
                "Chocolatey download cache",
            )
            .collapsed(),
        );

        // The Windows homes of stores that live under `~` elsewhere.
        self.add(Anchor::LocalAppData, "Pub/Cache", pub_cache());
        self.add(Anchor::LocalAppData, "Coursier/cache", coursier_cache());
        self.add(
            Anchor::LocalAppData,
            "Volta/tools/image",
            volta_toolchains(),
        );
        self.add(
            Anchor::LocalAppData,
            "Volta/tools/inventory",
            volta_downloads(),
        );
        self.add(Anchor::LocalAppData, "Arduino15/packages", arduino_cores());
        self.add(
            Anchor::LocalAppData,
            "Arduino15/staging",
            arduino_downloads(),
        );
        self.add(Anchor::Home, "_bazel_{user}", bazel_output_root());
        self.add(Anchor::LocalAppData, "bazelisk", bazelisk_cache());
        self.add(Anchor::LocalAppData, "electron/Cache", electron_cache());
        self.add(Anchor::LocalAppData, "node-gyp/Cache", node_gyp_cache());
        self.add(
            Anchor::LocalAppData,
            "Cypress/Cache",
            browser_download("Cypress binary cache"),
        );
    }

    #[cfg(target_os = "macos")]
    fn macos(&mut self) {
        self.protect(Some(PathBuf::from("/System")));
        self.protect(Some(PathBuf::from("/Library")));
        self.protect(Some(PathBuf::from("/Applications")));

        self.add(
            Anchor::Home,
            "Library/Developer/Xcode/DerivedData",
            cache(
                Category::BuildArtifact,
                Technology::Xcode,
                CleanupSafety::Safe,
                "Xcode derived data",
            )
            .with_evidence("Xcode regenerates derived data on the next build.")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            "Library/Developer/Xcode/Archives",
            cache(
                Category::Archive,
                Technology::Xcode,
                CleanupSafety::Review,
                "Xcode archives",
            )
            .with_evidence("Archives are needed to symbolicate crash reports from shipped builds.")
            .with_reclaim(Reclaim::OlderThan { days: 180 })
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            "Library/Developer/Xcode/iOS DeviceSupport",
            cache(
                Category::Cache,
                Technology::Xcode,
                CleanupSafety::ProbablySafe,
                "Xcode device support files",
            )
            .with_evidence("Regenerated when you next connect a device running that iOS version.")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            "Library/Developer/CoreSimulator/Devices",
            cache(
                Category::VirtualMachine,
                Technology::Xcode,
                CleanupSafety::Review,
                "iOS simulator devices",
            )
            .with_evidence("Simulators contain installed apps and their data.")
            .regenerated_by("xcrun simctl delete unavailable")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            "Library/Caches/Homebrew",
            cache(
                Category::PackageCache,
                Technology::Homebrew,
                CleanupSafety::Safe,
                "Homebrew download cache",
            )
            .regenerated_by("brew cleanup --prune=all")
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            "Library/Caches/JetBrains",
            cache(
                Category::Cache,
                Technology::JetBrains,
                CleanupSafety::Review,
                "JetBrains IDE caches and indexes",
            )
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            "Library/Caches",
            cache(
                Category::Cache,
                Technology::System,
                CleanupSafety::ProbablySafe,
                "macOS application caches",
            )
            .with_evidence(
                "Most applications regenerate their caches, but a few keep state here. \
                 Quit applications before clearing.",
            ),
        );
        self.add(
            Anchor::Home,
            "Library/Containers/com.docker.docker/Data",
            cache(
                Category::ContainerData,
                Technology::Docker,
                CleanupSafety::Review,
                "Docker Desktop virtual disk",
            )
            .with_evidence("Deleting these files destroys every container and volume.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".Trash",
            cache(
                Category::Temporary,
                Technology::System,
                CleanupSafety::Review,
                "Trash",
            )
            .with_evidence("Emptying the Trash is irreversible; Bloatrail leaves it to Finder.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );

        // The macOS homes of stores that live under `~/.cache` on Linux.
        self.add(Anchor::Home, "Library/Caches/Coursier", coursier_cache());
        self.add(Anchor::Home, "Library/Arduino15/packages", arduino_cores());
        self.add(
            Anchor::Home,
            "Library/Arduino15/staging",
            arduino_downloads(),
        );
        self.add(
            Anchor::Fixed("/private/var/tmp"),
            "_bazel_{user}",
            bazel_output_root(),
        );
        self.add(Anchor::Home, "Library/Caches/bazelisk", bazelisk_cache());
        self.add(Anchor::Home, "Library/Caches/electron", electron_cache());
        self.add(Anchor::Home, "Library/Caches/node-gyp", node_gyp_cache());
        self.add(
            Anchor::Home,
            "Library/Caches/ms-playwright",
            browser_download("Playwright browser downloads"),
        );
        self.add(
            Anchor::Home,
            "Library/Caches/Cypress",
            browser_download("Cypress binary cache"),
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn linux(&mut self) {
        self.protect(Some(PathBuf::from("/")));
        self.protect(Some(PathBuf::from("/usr")));
        self.protect(Some(PathBuf::from("/etc")));
        self.protect(Some(PathBuf::from("/boot")));
        self.protect(Some(PathBuf::from("/nix/store")));

        self.add(
            Anchor::Home,
            ".cache",
            cache(
                Category::Cache,
                Technology::System,
                CleanupSafety::ProbablySafe,
                "XDG user cache directory",
            )
            .with_evidence("Applications regenerate their caches, though some do so slowly."),
        );
        self.add(
            Anchor::Home,
            ".local/share/Trash",
            cache(
                Category::Temporary,
                Technology::System,
                CleanupSafety::Review,
                "Trash",
            )
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Home,
            ".local/share/containers",
            cache(
                Category::ContainerData,
                Technology::Docker,
                CleanupSafety::Review,
                "Podman container storage",
            )
            .with_evidence("Manage with `podman system prune` rather than deleting files.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Fixed("/var/lib/docker"),
            "",
            cache(
                Category::ContainerData,
                Technology::Docker,
                CleanupSafety::Review,
                "Docker engine storage",
            )
            .with_evidence("Contains every image, container and volume on this machine.")
            .with_evidence("Reclaim space with `docker system prune`, never by deleting files.")
            .with_reclaim(Reclaim::External)
            .collapsed(),
        );
        self.add(
            Anchor::Fixed("/var/log"),
            "",
            cache(
                Category::Log,
                Technology::System,
                CleanupSafety::Review,
                "System logs",
            )
            .with_evidence("Use `journalctl --vacuum-size=` to trim systemd logs safely.")
            .with_reclaim(Reclaim::External),
        );
        self.add(
            Anchor::Home,
            ".var/app",
            cache(
                Category::Application,
                Technology::System,
                CleanupSafety::Review,
                "Flatpak application data",
            )
            .with_reclaim(Reclaim::External),
        );
        self.add(
            Anchor::Home,
            "snap",
            cache(
                Category::Application,
                Technology::System,
                CleanupSafety::Review,
                "Snap application data",
            )
            .with_reclaim(Reclaim::External),
        );

        // XDG cache homes of stores that live elsewhere on macOS and Windows.
        self.add(Anchor::Home, ".cache/coursier", coursier_cache());
        self.add(Anchor::Home, ".arduino15/packages", arduino_cores());
        self.add(Anchor::Home, ".arduino15/staging", arduino_downloads());
        self.add(Anchor::Home, ".cache/bazel", bazel_output_root());
        self.add(Anchor::Home, ".cache/bazelisk", bazelisk_cache());
        self.add(Anchor::Home, ".cache/electron", electron_cache());
        self.add(Anchor::Home, ".cache/node-gyp", node_gyp_cache());
    }
}

/// One registration, written so that only a change in what Bloatrail knows can
/// change it: the anchor, the path under it as written, and what the rule does
/// to the bytes beneath — their category, and whether the subtree is collapsed
/// (which decides the directories a snapshot can list) or merely claimed.
/// Wording, evidence and cleanup advice are left out; they change what a report
/// says, not what a scan counts.
fn rule_identity(anchor: Anchor, rel: &str, detection: &Detection) -> String {
    let scope = if detection.collapse {
        "collapse"
    } else if detection.claims_contents {
        "claim"
    } else {
        "name"
    };
    let tag = anchor.tag();
    let location = if rel.is_empty() {
        tag.to_string()
    } else {
        format!("{tag}/{rel}")
    };
    format!("{location} {} {scope}", detection.category.id())
}

/// Shorthand for a known-location detection.
fn cache(
    category: Category,
    technology: Technology,
    safety: CleanupSafety,
    reason: &'static str,
) -> Detection {
    Detection::new(category, Confidence::High, safety, reason)
        .with_technology(technology)
        .with_specificity(80)
}

/// The pnpm store needs the same warning on every platform, so it lives here.
fn pnpm_store() -> Detection {
    cache(
        Category::PackageCache,
        Technology::Node,
        CleanupSafety::ProbablySafe,
        "pnpm content-addressable store",
    )
    .with_evidence(
        "pnpm hard-links packages from this store into every `node_modules`. Removing it \
         leaves existing installs with broken links until you run `pnpm install` again.",
    )
    .regenerated_by("pnpm store prune")
    .collapsed()
}

// The stores below live in a different place on each platform but need the
// same classification and the same words wherever they are found.

fn pub_cache() -> Detection {
    cache(
        Category::PackageCache,
        Technology::Dart,
        CleanupSafety::ProbablySafe,
        "Dart pub package cache",
    )
    .with_evidence(
        "Dart and Flutter projects resolve their packages straight out of this cache, so each \
         needs `dart pub get` (or `flutter pub get`) again before it builds.",
    )
    .with_evidence(
        "Tools installed with `dart pub global activate` live here too and have to be \
         activated again.",
    )
    .regenerated_by("dart pub get")
    .collapsed()
}

fn coursier_cache() -> Detection {
    cache(
        Category::PackageCache,
        Technology::Jvm,
        CleanupSafety::ProbablySafe,
        "Coursier artifact cache",
    )
    .with_evidence(
        "sbt, Mill, Scala CLI and Metals fetch dependencies through Coursier, which downloads \
         anything missing again; a large cache takes a while to rebuild.",
    )
    .with_evidence(
        "JVMs Coursier manages (`cs java`) are unpacked here as well, so a `JAVA_HOME` pointing \
         at one stops working until Coursier fetches it again.",
    )
    .collapsed()
}

fn volta_toolchains() -> Detection {
    cache(
        Category::Application,
        Technology::Node,
        CleanupSafety::Review,
        "Node.js toolchains installed by Volta",
    )
    .with_evidence(
        "The Node.js, npm and Yarn versions Volta runs for your projects and as your default. \
         Volta fetches a version a project pins again when it is missing, but a default you \
         chose with `volta install` has to be installed again.",
    )
    .collapsed()
}

fn volta_downloads() -> Detection {
    cache(
        Category::PackageCache,
        Technology::Node,
        CleanupSafety::Safe,
        "Volta download cache",
    )
    .with_evidence(
        "Archives of the tool versions Volta has downloaded; installed versions do not need \
         them.",
    )
    .collapsed()
}

fn arduino_cores() -> Detection {
    cache(
        Category::Application,
        Technology::Arduino,
        CleanupSafety::Review,
        "Arduino board cores and toolchains",
    )
    .with_evidence(
        "Installed through the Boards Manager; sketches for those boards will not build until \
         the cores are installed again.",
    )
    .with_evidence(
        "Remove a core from the Boards Manager, or with `arduino-cli core uninstall <core>`.",
    )
    .with_reclaim(Reclaim::External)
    .collapsed()
}

fn arduino_downloads() -> Detection {
    cache(
        Category::PackageCache,
        Technology::Arduino,
        CleanupSafety::Safe,
        "Arduino download cache",
    )
    .with_evidence(
        "Archives the Boards and Library Managers keep after installing; installed cores and \
         libraries do not need them.",
    )
    .regenerated_by("arduino-cli cache clean")
    .collapsed()
}

fn bazel_output_root() -> Detection {
    cache(
        Category::BuildArtifact,
        Technology::Bazel,
        CleanupSafety::Review,
        "Bazel output root",
    )
    .with_evidence(
        "Every workspace's build outputs and fetched external repositories, Bazel's repository \
         cache and its own unpacked install. Bazel rebuilds and re-fetches all of it, which can \
         take hours for a large workspace.",
    )
    .with_evidence(
        "Run `bazel clean --expunge` in a workspace rather than deleting files here: a running \
         Bazel server keeps this directory open, and Bazel marks its outputs read-only.",
    )
    .with_reclaim(Reclaim::External)
    .collapsed()
}

fn bazelisk_cache() -> Detection {
    cache(
        Category::PackageCache,
        Technology::Bazel,
        CleanupSafety::Safe,
        "Bazelisk download cache",
    )
    .with_evidence(
        "Bazel releases Bazelisk downloaded; it fetches the version a workspace pins again on \
         its next run.",
    )
    .collapsed()
}

fn electron_cache() -> Detection {
    cache(
        Category::Cache,
        Technology::Node,
        CleanupSafety::ProbablySafe,
        "Electron binary cache",
    )
    .with_evidence("Re-downloaded by the next install that needs it, but the download is large.")
    .collapsed()
}

fn node_gyp_cache() -> Detection {
    cache(
        Category::Cache,
        Technology::Node,
        CleanupSafety::Safe,
        "node-gyp header cache",
    )
    .with_evidence("Node.js headers node-gyp downloads again on the next native build.")
    .collapsed()
}

fn browser_download(label: &'static str) -> Detection {
    cache(
        Category::Cache,
        Technology::Node,
        CleanupSafety::ProbablySafe,
        label,
    )
    .with_evidence("Re-downloaded automatically, but the download is large.")
    .collapsed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_roots_are_recognised() {
        assert!(is_filesystem_root(Path::new("/")));
        if cfg!(windows) {
            assert!(is_filesystem_root(Path::new(r"C:\")));
            assert!(is_filesystem_root(Path::new("C:/")));
            assert!(!is_filesystem_root(Path::new(r"C:\Users")));
        }
        assert!(!is_filesystem_root(Path::new("/home")));
    }

    #[test]
    fn normalisation_strips_trailing_separators() {
        assert_eq!(
            normalise_key(Path::new("/a/b/")),
            normalise_key(Path::new("/a/b"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_keys_are_case_insensitive() {
        assert_eq!(
            normalise_key(Path::new(r"C:\Users\Test")),
            normalise_key(Path::new(r"c:\users\test"))
        );
    }

    #[test]
    fn empty_registry_never_matches() {
        let known = KnownPaths::empty();
        assert!(known.detect(Path::new("/anything"), "anything").is_none());
        assert!(known.is_empty());
    }

    #[test]
    fn discovery_registers_locations_and_protects_home() {
        let known = KnownPaths::discover();
        if let Some(home) = known.home.clone() {
            assert!(known.is_protected(&home), "home must be protected");
            assert_eq!(known.display(&home), "~");
        }
    }

    #[test]
    fn rules_name_anchors_never_resolved_paths() {
        let here = KnownPaths::build(Some(PathBuf::from("/home/alice-unique")));
        let there = KnownPaths::build(Some(PathBuf::from("/srv/people/bob-unique")));
        let nowhere = KnownPaths::build(None);

        assert!(!here.rules().is_empty());
        assert_eq!(
            here.rules(),
            there.rules(),
            "where home is must not change the rules"
        );
        assert_eq!(
            here.rules(),
            nowhere.rules(),
            "a rule counts whether or not it resolves on this machine"
        );
        assert!(
            here.rules()
                .iter()
                .all(|rule| !rule.contains("alice-unique")),
            "no resolved path may appear in a rule"
        );
        assert!(here.rules().windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            here.rules()
                .iter()
                .any(|rule| rule == "~/.cargo/registry package_cache collapse"),
            "a rule names its anchor, its path, its category and its scope"
        );
    }

    /// The test home every registry below is built around.
    fn test_home() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            r"C:\Users\tester"
        } else {
            "/home/tester"
        })
    }

    /// How `path`, made of `/`-separated parts under `base`, is classified.
    fn safety_at(known: &KnownPaths, base: &Path, rel: &str) -> CleanupSafety {
        let path = rel
            .split('/')
            .fold(base.to_path_buf(), |p, part| p.join(part));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a named path")
            .to_lowercase();
        known
            .detect(&path, &name)
            .unwrap_or_else(|| panic!("`{}` is not registered", path.display()))
            .cleanup
    }

    #[test]
    fn shared_developer_stores_are_registered_with_honest_safety() {
        let home = test_home();
        let known = KnownPaths::build(Some(home.clone()));
        let expect = |rel: &str, safety: CleanupSafety| {
            assert_eq!(safety_at(&known, &home, rel), safety, "`~/{rel}`");
        };

        // Caches the owning tool refills on its own, holding nothing else.
        for rel in [
            ".cache/pre-commit",
            ".hex/packages",
            ".opam/download-cache",
            ".julia/compiled",
            ".nvm/.cache",
            ".sdkman/archives",
            ".ghcup/cache",
            ".volta/tools/inventory",
            ".espressif/dist",
            ".platformio/.cache",
        ] {
            expect(rel, CleanupSafety::Safe);
        }

        // Fetched or built again on demand, at a real cost in time or
        // bandwidth, or with something to redo before projects build.
        for rel in [
            ".pub-cache",
            ".ivy2/cache",
            ".sbt/boot",
            ".stack/pantry",
            ".stack/snapshots",
            ".conan2/p",
            ".conan/data",
            ".julia/packages",
            ".julia/artifacts",
            ".platformio/packages",
            ".platformio/platforms",
            ".espressif/tools",
            ".espressif/python_env",
            ".minikube/cache",
        ] {
            expect(rel, CleanupSafety::ProbablySafe);
        }

        // Choices and state: toolchain versions someone installed, virtual
        // machines and the images they come from, downloaded models.
        for rel in [
            ".nvm/versions",
            ".pyenv/versions",
            ".sdkman/candidates",
            ".volta/tools/image",
            ".elan/toolchains",
            ".ghcup/ghc",
            ".stack/programs",
            ".vagrant.d/boxes",
            ".minikube/machines",
            ".lima",
            ".colima",
            ".android/avd",
            ".ollama/models",
            ".cache/huggingface",
            ".cache/torch",
        ] {
            expect(rel, CleanupSafety::Review);
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_cache_homes_of_shared_stores_are_registered() {
        let home = test_home();
        let known = KnownPaths::build(Some(home.clone()));
        for (rel, safety) in [
            (".cache/coursier", CleanupSafety::ProbablySafe),
            (".cache/bazel", CleanupSafety::Review),
            (".cache/bazelisk", CleanupSafety::Safe),
            (".cache/electron", CleanupSafety::ProbablySafe),
            (".cache/node-gyp", CleanupSafety::Safe),
            (".cache/ms-playwright", CleanupSafety::ProbablySafe),
            (".cache/Cypress", CleanupSafety::ProbablySafe),
            (".arduino15/packages", CleanupSafety::Review),
            (".arduino15/staging", CleanupSafety::Safe),
        ] {
            assert_eq!(safety_at(&known, &home, rel), safety, "`~/{rel}`");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_cache_homes_of_shared_stores_are_registered() {
        let home = test_home();
        let known = KnownPaths::build(Some(home.clone()));
        for (rel, safety) in [
            ("Library/Caches/Coursier", CleanupSafety::ProbablySafe),
            ("Library/Caches/bazelisk", CleanupSafety::Safe),
            ("Library/Caches/electron", CleanupSafety::ProbablySafe),
            ("Library/Caches/node-gyp", CleanupSafety::Safe),
            ("Library/Caches/ms-playwright", CleanupSafety::ProbablySafe),
            ("Library/Caches/Cypress", CleanupSafety::ProbablySafe),
            ("Library/Arduino15/packages", CleanupSafety::Review),
            ("Library/Arduino15/staging", CleanupSafety::Safe),
        ] {
            assert_eq!(safety_at(&known, &home, rel), safety, "`~/{rel}`");
        }
        if let Some(user) = login_name() {
            let root = format!("_bazel_{user}");
            assert_eq!(
                safety_at(&known, Path::new("/private/var/tmp"), &root),
                CleanupSafety::Review
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_homes_of_shared_stores_are_registered() {
        let home = test_home();
        let known = KnownPaths::build(Some(home.clone()));
        let local = dirs::data_local_dir().expect("%LOCALAPPDATA%");
        for (rel, safety) in [
            ("Pub/Cache", CleanupSafety::ProbablySafe),
            ("Coursier/cache", CleanupSafety::ProbablySafe),
            ("Volta/tools/image", CleanupSafety::Review),
            ("Volta/tools/inventory", CleanupSafety::Safe),
            ("Arduino15/packages", CleanupSafety::Review),
            ("Arduino15/staging", CleanupSafety::Safe),
            ("bazelisk", CleanupSafety::Safe),
            ("electron/Cache", CleanupSafety::ProbablySafe),
            ("node-gyp/Cache", CleanupSafety::Safe),
            ("Cypress/Cache", CleanupSafety::ProbablySafe),
        ] {
            assert_eq!(safety_at(&known, &local, rel), safety, "`{rel}`");
        }
        if let Some(user) = login_name() {
            let root = format!("_bazel_{user}");
            assert_eq!(safety_at(&known, &home, &root), CleanupSafety::Review);
        }
    }

    #[test]
    fn machines_and_installed_software_are_never_offered_outright() {
        // A VM disk, a container store or an installed toolchain is state
        // someone chose. Whatever else changes in the registry, none of them
        // may become something `clean` selects without a human decision.
        let known = KnownPaths::build(Some(test_home()));
        for (key, entry) in &known.lookup {
            let detection = &entry.detection;
            if matches!(
                detection.category,
                Category::VirtualMachine | Category::ContainerData | Category::Application
            ) {
                assert!(
                    detection.cleanup >= CleanupSafety::Review,
                    "`{key}` ({}) is {}",
                    detection.reason,
                    detection.cleanup.label()
                );
            }
        }
    }

    #[test]
    fn file_identity_reports_link_counts_and_matches_hardlinked_names() {
        let temp = tempfile::tempdir().unwrap();
        let single = temp.path().join("single.bin");
        std::fs::write(&single, b"payload").unwrap();

        let lone = file_identity(&single).expect("a plain file must be readable");
        assert_eq!(lone.links, 1, "one directory entry so far");

        let linked = temp.path().join("linked.bin");
        if let Err(error) = std::fs::hard_link(&single, &linked) {
            // The filesystem refused; nothing to verify here. A missing source
            // would be a test bug, though, and must not skip.
            assert!(
                single.exists(),
                "hard_link failed for a missing source: {error}"
            );
            return;
        }
        let a = file_identity(&single).expect("still readable");
        let b = file_identity(&linked).expect("the new name is readable too");
        assert_eq!(a.links, 2, "the file now has exactly two names");
        assert_eq!(a, b, "both names must resolve to the same storage");
        assert!(
            a.id.is_some(),
            "an ordinary local filesystem should supply a usable file ID"
        );

        let other = temp.path().join("other.bin");
        std::fs::write(&other, b"payload").unwrap();
        let other_link = temp.path().join("other-link.bin");
        std::fs::hard_link(&other, &other_link).unwrap();
        assert_ne!(
            file_identity(&other).and_then(|identity| identity.id),
            a.id,
            "different files must have different identities"
        );
    }

    #[test]
    fn disk_usage_fraction_is_bounded() {
        let usage = DiskUsage {
            total: 100,
            available: 25,
        };
        assert_eq!(usage.used(), 75);
        assert!((usage.used_fraction() - 0.75).abs() < f64::EPSILON);

        let empty = DiskUsage {
            total: 0,
            available: 0,
        };
        assert_eq!(empty.used_fraction(), 0.0);
    }
}
