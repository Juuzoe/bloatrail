//! Core vocabulary of the analysis layer.
//!
//! Everything downstream — the cleanup planner, the renderers, the JSON schema
//! — is expressed in terms of these types. They deliberately separate three
//! orthogonal questions:
//!
//! * **What is it?** ([`Category`], [`Technology`])
//! * **How sure are we?** ([`Confidence`])
//! * **May it be removed?** ([`CleanupSafety`], [`Reclaim`])
//!
//! Conflating those is how disk cleaners end up deleting people's source code.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// What a file or directory *is*, conceptually.
///
/// This is a storage-meaning taxonomy, not a file-extension bucket: a 4 GB
/// `target/` directory is a [`Category::BuildArtifact`] regardless of the
/// extensions inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Hand-written project code and project configuration.
    SourceCode,
    /// Third-party code fetched by a package manager into a project.
    Dependency,
    /// Compiler/bundler output that can be regenerated from source.
    BuildArtifact,
    /// General-purpose caches (framework, IDE, browser, OS).
    Cache,
    /// Package-manager download/registry caches shared across projects.
    PackageCache,
    /// Container engine images, layers, volumes and build cache.
    ContainerData,
    /// Version-control metadata (`.git`, `.hg`, `.svn`).
    GitData,
    /// Virtual machine disks and snapshots.
    VirtualMachine,
    /// Application and system logs.
    Log,
    /// Scratch/temporary storage.
    Temporary,
    /// Files that arrived from the internet.
    Download,
    /// Compressed archives and disk images.
    Archive,
    /// Video files.
    Video,
    /// Images and photos.
    Image,
    /// Audio files.
    Audio,
    /// Documents, spreadsheets, presentations, ebooks.
    Document,
    /// Installed applications and executables.
    Application,
    /// Game installs and assets.
    Game,
    /// Operating-system managed storage.
    System,
    /// Not confidently classified.
    Unknown,
}

impl Category {
    /// Every category, in the order used for the storage breakdown table.
    pub const ALL: [Category; 20] = [
        Category::Video,
        Category::Dependency,
        Category::ContainerData,
        Category::BuildArtifact,
        Category::Download,
        Category::Cache,
        Category::PackageCache,
        Category::GitData,
        Category::VirtualMachine,
        Category::Game,
        Category::Application,
        Category::Archive,
        Category::Image,
        Category::Audio,
        Category::Document,
        Category::SourceCode,
        Category::Log,
        Category::Temporary,
        Category::System,
        Category::Unknown,
    ];

    /// Label used in human-facing output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Category::SourceCode => "Source code",
            Category::Dependency => "Developer dependencies",
            Category::BuildArtifact => "Build artifacts",
            Category::Cache => "Caches",
            Category::PackageCache => "Package caches",
            Category::ContainerData => "Containers",
            Category::GitData => "Git repositories",
            Category::VirtualMachine => "Virtual machines",
            Category::Log => "Logs",
            Category::Temporary => "Temporary files",
            Category::Download => "Downloads",
            Category::Archive => "Archives",
            Category::Video => "Videos",
            Category::Image => "Images",
            Category::Audio => "Audio",
            Category::Document => "Documents",
            Category::Application => "Applications",
            Category::Game => "Games",
            Category::System => "System files",
            Category::Unknown => "Other",
        }
    }

    /// Stable machine-readable identifier, mirroring the serde representation.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Category::SourceCode => "source_code",
            Category::Dependency => "dependency",
            Category::BuildArtifact => "build_artifact",
            Category::Cache => "cache",
            Category::PackageCache => "package_cache",
            Category::ContainerData => "container_data",
            Category::GitData => "git_data",
            Category::VirtualMachine => "virtual_machine",
            Category::Log => "log",
            Category::Temporary => "temporary",
            Category::Download => "download",
            Category::Archive => "archive",
            Category::Video => "video",
            Category::Image => "image",
            Category::Audio => "audio",
            Category::Document => "document",
            Category::Application => "application",
            Category::Game => "game",
            Category::System => "system",
            Category::Unknown => "unknown",
        }
    }

    /// Index into a [`CategoryTotals`] array.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The ecosystem a detection belongs to.
///
/// Used both for grouping cleanup suggestions ("Rust build artifacts") and for
/// explaining *why* something was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Technology {
    /// Rust / Cargo.
    Rust,
    /// Node.js, and by extension the JavaScript/TypeScript ecosystem.
    Node,
    /// Deno.
    Deno,
    /// Bun.
    Bun,
    /// Python.
    Python,
    /// Java and other JVM languages.
    Jvm,
    /// Gradle build system.
    Gradle,
    /// Maven build system.
    Maven,
    /// .NET / C#.
    DotNet,
    /// Go.
    Go,
    /// C and C++.
    Cpp,
    /// CMake build system.
    CMake,
    /// Swift / Apple platforms.
    Swift,
    /// Ruby.
    Ruby,
    /// PHP / Composer.
    Php,
    /// Dart / Flutter.
    Dart,
    /// Elixir / Erlang.
    Elixir,
    /// Haskell.
    Haskell,
    /// Zig.
    Zig,
    /// Nim.
    Nim,
    /// Nix.
    Nix,
    /// Terraform.
    Terraform,
    /// Android tooling.
    Android,
    /// Unity game engine.
    Unity,
    /// Docker or a compatible container engine.
    Docker,
    /// Git.
    Git,
    /// Visual Studio Code.
    VsCode,
    /// JetBrains IDEs.
    JetBrains,
    /// Visual Studio.
    VisualStudio,
    /// Xcode.
    Xcode,
    /// Homebrew.
    Homebrew,
    /// The operating system itself.
    System,
}

impl Technology {
    /// Human-facing name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Technology::Rust => "Rust",
            Technology::Node => "Node.js",
            Technology::Deno => "Deno",
            Technology::Bun => "Bun",
            Technology::Python => "Python",
            Technology::Jvm => "JVM",
            Technology::Gradle => "Gradle",
            Technology::Maven => "Maven",
            Technology::DotNet => ".NET",
            Technology::Go => "Go",
            Technology::Cpp => "C/C++",
            Technology::CMake => "CMake",
            Technology::Swift => "Swift",
            Technology::Ruby => "Ruby",
            Technology::Php => "PHP",
            Technology::Dart => "Dart",
            Technology::Elixir => "Elixir",
            Technology::Haskell => "Haskell",
            Technology::Zig => "Zig",
            Technology::Nim => "Nim",
            Technology::Nix => "Nix",
            Technology::Terraform => "Terraform",
            Technology::Android => "Android",
            Technology::Unity => "Unity",
            Technology::Docker => "Docker",
            Technology::Git => "Git",
            Technology::VsCode => "VS Code",
            Technology::JetBrains => "JetBrains",
            Technology::VisualStudio => "Visual Studio",
            Technology::Xcode => "Xcode",
            Technology::Homebrew => "Homebrew",
            Technology::System => "System",
        }
    }
}

impl fmt::Display for Technology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How strongly the evidence supports a detection.
///
/// Confidence is deliberately independent of [`CleanupSafety`]: we can be
/// *certain* something is a `.git` directory and still refuse to delete it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Name matched, but the surrounding context did not corroborate it.
    Low,
    /// Reasonable evidence, some ambiguity remains.
    Medium,
    /// Corroborated by project context (marker files, known locations).
    High,
    /// Structurally unambiguous (e.g. a directory containing `HEAD` + `objects`).
    Certain,
}

impl Confidence {
    /// Human-facing name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Confidence::Low => "LOW",
            Confidence::Medium => "MEDIUM",
            Confidence::High => "HIGH",
            Confidence::Certain => "CERTAIN",
        }
    }

    /// Numeric weight used when ranking competing detections.
    #[must_use]
    pub const fn weight(self) -> u16 {
        match self {
            Confidence::Low => 10,
            Confidence::Medium => 40,
            Confidence::High => 70,
            Confidence::Certain => 100,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How a detection may be treated by the cleanup engine.
///
/// The ordering is meaningful: `Safe < ProbablySafe < Review < Dangerous <
/// NeverDelete`, so `safety <= CleanupSafety::ProbablySafe` reads naturally as
/// "eligible for unattended cleanup".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CleanupSafety {
    /// Fully regenerable by a documented, local command. No user data.
    ///
    /// This is the default: anything that has not made a case for itself gets
    /// the most restrictive treatment a caller can ask for.
    #[default]
    Safe,
    /// Regenerable, but regeneration costs time or bandwidth.
    ProbablySafe,
    /// Might be wanted. Requires a human decision.
    Review,
    /// Removal is likely to destroy something valuable.
    Dangerous,
    /// Bloatrail will never delete this, whatever the flags say.
    NeverDelete,
}

impl CleanupSafety {
    /// Short uppercase tag used in report headings.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CleanupSafety::Safe => "SAFE",
            CleanupSafety::ProbablySafe => "PROBABLY SAFE",
            CleanupSafety::Review => "REVIEW",
            CleanupSafety::Dangerous => "DANGEROUS",
            CleanupSafety::NeverDelete => "DO NOT AUTO DELETE",
        }
    }

    /// Marker glyph used in reports (`✓`, `!`, `×`).
    #[must_use]
    pub const fn glyph(self) -> &'static str {
        match self {
            CleanupSafety::Safe | CleanupSafety::ProbablySafe => "✓",
            CleanupSafety::Review => "!",
            CleanupSafety::Dangerous | CleanupSafety::NeverDelete => "×",
        }
    }

    /// ASCII fallback for [`CleanupSafety::glyph`].
    #[must_use]
    pub const fn ascii_glyph(self) -> &'static str {
        match self {
            CleanupSafety::Safe | CleanupSafety::ProbablySafe => "+",
            CleanupSafety::Review => "!",
            CleanupSafety::Dangerous | CleanupSafety::NeverDelete => "x",
        }
    }

    /// Whether `bloatrail clean` may select this without an explicit opt-in.
    #[must_use]
    pub const fn is_auto_selectable(self) -> bool {
        matches!(self, CleanupSafety::Safe)
    }

    /// Whether the executor is ever allowed to delete this, under any flag.
    #[must_use]
    pub const fn is_deletable(self) -> bool {
        matches!(
            self,
            CleanupSafety::Safe | CleanupSafety::ProbablySafe | CleanupSafety::Review
        )
    }
}

impl fmt::Display for CleanupSafety {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How much of a detected location can actually be reclaimed.
///
/// Keeping this separate from [`CleanupSafety`] is what lets Bloatrail say
/// "Downloads: 14.2 GB, 6.3 GB reclaimable" instead of pretending the whole
/// directory is disposable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reclaim {
    /// Nothing here should be counted as recoverable.
    None,
    /// The whole location is recoverable.
    All,
    /// Only entries older than `days` are candidates.
    OlderThan {
        /// Age threshold in days.
        days: u32,
    },
    /// Recoverable, but only via an external tool (e.g. `docker system prune`).
    External,
}

impl Reclaim {
    /// Whether this location contributes to the "recoverable" headline figure.
    #[must_use]
    pub const fn contributes(self) -> bool {
        !matches!(self, Reclaim::None)
    }
}

/// A single piece of evidence supporting a detection.
///
/// These are surfaced verbatim by `bloatrail explain`, so they are written as
/// complete sentences.
pub type Evidence = Cow<'static, str>;

/// The result of classifying a directory (or, occasionally, a file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// What the location is.
    pub category: Category,
    /// Which ecosystem it belongs to, when that is meaningful.
    pub technology: Option<Technology>,
    /// How strongly the evidence supports the conclusion.
    pub confidence: Confidence,
    /// Whether, and how carefully, it may be removed.
    pub cleanup: CleanupSafety,
    /// Short label, e.g. `"Rust build artifacts"`.
    pub reason: Evidence,
    /// Longer supporting statements, one per line in `explain` output.
    pub evidence: Vec<Evidence>,
    /// How much of it is recoverable.
    pub reclaim: Reclaim,
    /// Command that regenerates the contents, if one exists.
    pub regenerated_by: Option<Evidence>,
    /// When `true`, the scanner stops retaining per-child detail below here.
    ///
    /// Sizes are still counted exactly; only the tree nodes are collapsed. This
    /// is what keeps a 50 000-directory `node_modules` from dominating memory.
    /// Implies [`Detection::claims_contents`].
    pub collapse: bool,
    /// When `true`, every byte beneath this directory counts towards
    /// [`Detection::category`] instead of being categorised file by file.
    ///
    /// `~/Downloads` sets this without collapsing: the storage breakdown should
    /// say "Downloads", but the tree view should still show what is inside.
    pub claims_contents: bool,
    /// Tie-breaker among detections of equal confidence. Higher wins.
    pub specificity: u16,
}

impl Detection {
    /// Start building a detection with the mandatory fields.
    #[must_use]
    pub fn new(
        category: Category,
        confidence: Confidence,
        cleanup: CleanupSafety,
        reason: impl Into<Evidence>,
    ) -> Self {
        Detection {
            category,
            technology: None,
            confidence,
            cleanup,
            reason: reason.into(),
            evidence: Vec::new(),
            reclaim: match cleanup {
                CleanupSafety::Safe | CleanupSafety::ProbablySafe => Reclaim::All,
                _ => Reclaim::None,
            },
            regenerated_by: None,
            collapse: false,
            claims_contents: false,
            specificity: 0,
        }
    }

    /// Attach the owning ecosystem.
    #[must_use]
    pub fn with_technology(mut self, technology: Technology) -> Self {
        self.technology = Some(technology);
        self
    }

    /// Append a human-readable justification.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<Evidence>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    /// Override the default reclaim policy implied by the safety level.
    #[must_use]
    pub fn with_reclaim(mut self, reclaim: Reclaim) -> Self {
        self.reclaim = reclaim;
        self
    }

    /// Record the command that regenerates this location's contents.
    #[must_use]
    pub fn regenerated_by(mut self, command: impl Into<Evidence>) -> Self {
        self.regenerated_by = Some(command.into());
        self
    }

    /// Stop retaining child directories below this node, and attribute every
    /// byte beneath it to this detection's category.
    #[must_use]
    pub fn collapsed(mut self) -> Self {
        self.collapse = true;
        self.claims_contents = true;
        self
    }

    /// Attribute every byte beneath this directory to this category while still
    /// retaining and classifying the directories inside it.
    #[must_use]
    pub fn claiming_contents(mut self) -> Self {
        self.claims_contents = true;
        self
    }

    /// Set the tie-breaking specificity score.
    #[must_use]
    pub fn with_specificity(mut self, specificity: u16) -> Self {
        self.specificity = specificity;
        self
    }

    /// Ranking key used to pick a winner among competing detectors.
    #[must_use]
    pub fn rank(&self) -> (u16, u16) {
        (self.confidence.weight(), self.specificity)
    }
}

/// Per-category byte totals.
///
/// A fixed-size array keyed by [`Category::index`]: no allocation, cheap to
/// merge across rayon workers, and exhaustive by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CategoryTotals {
    bytes: [u64; 20],
    files: [u64; 20],
}

impl CategoryTotals {
    /// An empty set of totals.
    #[must_use]
    pub const fn new() -> Self {
        CategoryTotals {
            bytes: [0; 20],
            files: [0; 20],
        }
    }

    /// Record `bytes` belonging to one file in `category`.
    #[inline]
    pub fn add_file(&mut self, category: Category, bytes: u64) {
        let index = category.index();
        self.bytes[index] = self.bytes[index].saturating_add(bytes);
        self.files[index] = self.files[index].saturating_add(1);
    }

    /// Record `bytes` and `files` in bulk (used for collapsed subtrees).
    #[inline]
    pub fn add_bulk(&mut self, category: Category, bytes: u64, files: u64) {
        let index = category.index();
        self.bytes[index] = self.bytes[index].saturating_add(bytes);
        self.files[index] = self.files[index].saturating_add(files);
    }

    /// Fold another set of totals into this one.
    pub fn merge(&mut self, other: &CategoryTotals) {
        for i in 0..self.bytes.len() {
            self.bytes[i] = self.bytes[i].saturating_add(other.bytes[i]);
            self.files[i] = self.files[i].saturating_add(other.files[i]);
        }
    }

    /// Bytes attributed to `category`.
    #[inline]
    #[must_use]
    pub fn bytes(&self, category: Category) -> u64 {
        self.bytes[category.index()]
    }

    /// Files attributed to `category`.
    #[inline]
    #[must_use]
    pub fn files(&self, category: Category) -> u64 {
        self.files[category.index()]
    }

    /// Total bytes across every category.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.bytes.iter().fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Non-empty categories, largest first.
    #[must_use]
    pub fn ranked(&self) -> Vec<(Category, u64, u64)> {
        let mut rows: Vec<(Category, u64, u64)> = Category::ALL
            .iter()
            .map(|c| (*c, self.bytes(*c), self.files(*c)))
            .filter(|(_, bytes, _)| *bytes > 0)
            .collect();
        // `Unknown` is a bucket, not a finding: it always sorts last.
        rows.sort_by(|a, b| {
            let a_other = a.0 == Category::Unknown;
            let b_other = b.0 == Category::Unknown;
            a_other.cmp(&b_other).then(b.1.cmp(&a.1))
        });
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_ordering_supports_threshold_comparisons() {
        assert!(CleanupSafety::Safe < CleanupSafety::ProbablySafe);
        assert!(CleanupSafety::Review < CleanupSafety::Dangerous);
        assert!(CleanupSafety::Dangerous < CleanupSafety::NeverDelete);
        assert!(CleanupSafety::ProbablySafe <= CleanupSafety::Review);
    }

    #[test]
    fn only_safe_is_auto_selectable() {
        assert!(CleanupSafety::Safe.is_auto_selectable());
        for safety in [
            CleanupSafety::ProbablySafe,
            CleanupSafety::Review,
            CleanupSafety::Dangerous,
            CleanupSafety::NeverDelete,
        ] {
            assert!(
                !safety.is_auto_selectable(),
                "{safety:?} must not auto-select"
            );
        }
    }

    #[test]
    fn dangerous_and_never_delete_are_not_deletable() {
        assert!(!CleanupSafety::Dangerous.is_deletable());
        assert!(!CleanupSafety::NeverDelete.is_deletable());
        assert!(CleanupSafety::Safe.is_deletable());
    }

    #[test]
    fn confidence_is_ordered_low_to_certain() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
        assert!(Confidence::High < Confidence::Certain);
    }

    #[test]
    fn detection_defaults_reclaim_from_safety() {
        let safe = Detection::new(
            Category::BuildArtifact,
            Confidence::High,
            CleanupSafety::Safe,
            "x",
        );
        assert_eq!(safe.reclaim, Reclaim::All);

        let never = Detection::new(
            Category::GitData,
            Confidence::High,
            CleanupSafety::NeverDelete,
            "x",
        );
        assert_eq!(never.reclaim, Reclaim::None);
    }

    #[test]
    fn category_all_covers_every_variant_exactly_once() {
        let mut seen = [false; 20];
        for category in Category::ALL {
            assert!(!seen[category.index()], "{category:?} listed twice");
            seen[category.index()] = true;
        }
        assert!(
            seen.iter().all(|s| *s),
            "Category::ALL is missing a variant"
        );
    }

    #[test]
    fn ranked_sorts_by_size_and_puts_other_last() {
        let mut totals = CategoryTotals::new();
        totals.add_file(Category::Unknown, 1_000_000);
        totals.add_file(Category::Video, 500);
        totals.add_file(Category::Dependency, 900);

        let ranked = totals.ranked();
        assert_eq!(ranked[0].0, Category::Dependency);
        assert_eq!(ranked[1].0, Category::Video);
        assert_eq!(ranked[2].0, Category::Unknown);
    }

    #[test]
    fn merging_totals_is_additive() {
        let mut a = CategoryTotals::new();
        a.add_file(Category::Cache, 10);
        let mut b = CategoryTotals::new();
        b.add_bulk(Category::Cache, 5, 3);
        a.merge(&b);
        assert_eq!(a.bytes(Category::Cache), 15);
        assert_eq!(a.files(Category::Cache), 4);
    }
}
