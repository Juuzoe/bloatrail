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
}

impl KnownPaths {
    /// Discover the well-known locations for this machine.
    #[must_use]
    pub fn discover() -> Self {
        let home = dirs::home_dir();
        let mut builder = Builder::new(home.clone());

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
        }
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

/// Builder that assembles the well-known location registry.
struct Builder {
    home: Option<PathBuf>,
    entries: Vec<(PathBuf, Detection)>,
    protected: Vec<PathBuf>,
}

impl Builder {
    fn new(home: Option<PathBuf>) -> Self {
        Builder {
            home,
            entries: Vec::new(),
            protected: Vec::new(),
        }
    }

    /// Register `base/rel` if `base` exists.
    fn add(&mut self, base: Option<PathBuf>, rel: &str, detection: Detection) {
        let Some(base) = base else { return };
        let path = if rel.is_empty() {
            base
        } else {
            let mut p = base;
            for part in rel.split('/') {
                p.push(part);
            }
            p
        };
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
        KnownPaths {
            home: self.home.clone(),
            downloads: dirs::download_dir(),
            documents: dirs::document_dir(),
            temp: std::env::temp_dir(),
            lookup,
            trigger_names,
            protected: self.protected,
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
            self.home_rel(".cargo/registry"),
            "",
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
            self.home_rel(".cargo/git"),
            "",
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
            self.home_rel(".rustup/toolchains"),
            "",
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
            self.home_rel(".rustup/downloads"),
            "",
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
            self.home_rel(".npm/_cacache"),
            "",
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
            self.home_rel(".yarn/berry/cache"),
            "",
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
            self.home_rel(".cache/yarn"),
            "",
            cache(
                Category::PackageCache,
                Technology::Node,
                CleanupSafety::Safe,
                "Yarn classic cache",
            )
            .regenerated_by("yarn cache clean")
            .collapsed(),
        );
        self.add(self.home_rel(".pnpm-store"), "", pnpm_store());
        self.add(
            self.home_rel(".bun/install/cache"),
            "",
            cache(
                Category::PackageCache,
                Technology::Bun,
                CleanupSafety::Safe,
                "Bun install cache",
            )
            .collapsed(),
        );
        self.add(
            self.home_rel(".deno"),
            "",
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
            self.home_rel(".node-gyp"),
            "",
            cache(
                Category::Cache,
                Technology::Node,
                CleanupSafety::Safe,
                "node-gyp header cache",
            )
            .collapsed(),
        );
        self.add(
            self.home_rel(".electron"),
            "",
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
            self.home_rel(".cache/pip"),
            "",
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
            self.home_rel(".cache/uv"),
            "",
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
            self.home_rel(".cache/pypoetry"),
            "",
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
                self.home_rel(conda),
                "",
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
            self.home_rel(".m2/repository"),
            "",
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
            self.home_rel(".gradle/caches"),
            "",
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
            self.home_rel(".gradle/daemon"),
            "",
            cache(
                Category::Log,
                Technology::Gradle,
                CleanupSafety::Safe,
                "Gradle daemon logs",
            )
            .collapsed(),
        );
        self.add(
            self.home_rel(".android/avd"),
            "",
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
            self.home_rel(".gradle/wrapper"),
            "",
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
            self.home_rel(".nuget/packages"),
            "",
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
            self.home_rel("go/pkg/mod"),
            "",
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
            self.home_rel(".cache/go-build"),
            "",
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
            self.home_rel(".cargo/bin"),
            "",
            cache(
                Category::Application,
                Technology::Rust,
                CleanupSafety::NeverDelete,
                "Cargo-installed binaries",
            )
            .with_evidence("These are tools you installed with `cargo install`."),
        );
        self.add(
            self.home_rel(".cache/composer"),
            "",
            cache(
                Category::PackageCache,
                Technology::Php,
                CleanupSafety::Safe,
                "Composer cache",
            )
            .collapsed(),
        );
        self.add(
            self.home_rel(".terraform.d/plugin-cache"),
            "",
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
            self.add(
                self.home_rel(rel),
                "",
                cache(
                    Category::Cache,
                    Technology::Node,
                    CleanupSafety::ProbablySafe,
                    label,
                )
                .with_evidence("Re-downloaded automatically, but the download is large.")
                .collapsed(),
            );
        }

        // ---- Machine learning model caches --------------------------------
        for (rel, label) in [
            (".cache/huggingface", "Hugging Face model cache"),
            (".ollama/models", "Ollama model storage"),
            (".cache/torch", "PyTorch model cache"),
        ] {
            self.add(
                self.home_rel(rel),
                "",
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

        // ---- Containers ---------------------------------------------------
        self.add(
            self.home_rel(".docker"),
            "",
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
            dirs::download_dir(),
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
            dirs::document_dir(),
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
            dirs::video_dir(),
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
            dirs::picture_dir(),
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
            dirs::audio_dir(),
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

    #[cfg(windows)]
    fn windows(&mut self) {
        let local = dirs::data_local_dir();
        let roaming = dirs::data_dir();

        self.protect(Some(PathBuf::from(r"C:\Windows")));
        self.protect(Some(PathBuf::from(r"C:\Program Files")));
        self.protect(Some(PathBuf::from(r"C:\Program Files (x86)")));

        self.add(
            local.clone(),
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
            local.clone(),
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
        self.add(local.clone(), "pnpm/store", pnpm_store());
        self.add(
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            local.clone(),
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
            roaming.clone(),
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
            roaming,
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
            local,
            "Temp/chocolatey",
            cache(
                Category::PackageCache,
                Technology::System,
                CleanupSafety::Safe,
                "Chocolatey download cache",
            )
            .collapsed(),
        );
    }

    #[cfg(target_os = "macos")]
    fn macos(&mut self) {
        self.protect(Some(PathBuf::from("/System")));
        self.protect(Some(PathBuf::from("/Library")));
        self.protect(Some(PathBuf::from("/Applications")));

        self.add(
            self.home_rel("Library/Developer/Xcode/DerivedData"),
            "",
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
            self.home_rel("Library/Developer/Xcode/Archives"),
            "",
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
            self.home_rel("Library/Developer/Xcode/iOS DeviceSupport"),
            "",
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
            self.home_rel("Library/Developer/CoreSimulator/Devices"),
            "",
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
            self.home_rel("Library/Caches/Homebrew"),
            "",
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
            self.home_rel("Library/Caches/JetBrains"),
            "",
            cache(
                Category::Cache,
                Technology::JetBrains,
                CleanupSafety::Review,
                "JetBrains IDE caches and indexes",
            )
            .collapsed(),
        );
        self.add(
            self.home_rel("Library/Caches"),
            "",
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
            self.home_rel("Library/Containers/com.docker.docker/Data"),
            "",
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
            self.home_rel(".Trash"),
            "",
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
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn linux(&mut self) {
        self.protect(Some(PathBuf::from("/")));
        self.protect(Some(PathBuf::from("/usr")));
        self.protect(Some(PathBuf::from("/etc")));
        self.protect(Some(PathBuf::from("/boot")));
        self.protect(Some(PathBuf::from("/nix/store")));

        self.add(
            self.home_rel(".cache"),
            "",
            cache(
                Category::Cache,
                Technology::System,
                CleanupSafety::ProbablySafe,
                "XDG user cache directory",
            )
            .with_evidence("Applications regenerate their caches, though some do so slowly."),
        );
        self.add(
            self.home_rel(".local/share/Trash"),
            "",
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
            self.home_rel(".local/share/containers"),
            "",
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
            Some(PathBuf::from("/var/lib/docker")),
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
            Some(PathBuf::from("/var/log")),
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
            self.home_rel(".var/app"),
            "",
            cache(
                Category::Application,
                Technology::System,
                CleanupSafety::Review,
                "Flatpak application data",
            )
            .with_reclaim(Reclaim::External),
        );
        self.add(
            self.home_rel("snap"),
            "",
            cache(
                Category::Application,
                Technology::System,
                CleanupSafety::Review,
                "Snap application data",
            )
            .with_reclaim(Reclaim::External),
        );
    }
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
