//! The evidence a detector gets to reason about.
//!
//! The central idea of Bloatrail's classifier is that a directory name alone is
//! nearly meaningless. `target/` is a Rust build directory next to a
//! `Cargo.toml`, a Maven output directory next to a `pom.xml`, and just a
//! folder called "target" everywhere else.
//!
//! [`Markers`] captures the marker files present in a directory as a bitset.
//! The walker computes it once per directory from the entry names it has
//! already read — no extra syscalls — and passes it down to children, so every
//! detector sees both its own and its parent's project fingerprint.

use std::path::Path;

use bitflags::bitflags;

bitflags! {
    /// Project "fingerprint" files present in a directory.
    ///
    /// Computed from directory entry names during traversal, so testing for
    /// project context costs a bitwise AND rather than a `stat`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Markers: u64 {
        /// `Cargo.toml`
        const CARGO_TOML       = 1 << 0;
        /// `Cargo.lock`
        const CARGO_LOCK       = 1 << 1;
        /// `package.json`
        const PACKAGE_JSON     = 1 << 2;
        /// `package-lock.json`
        const NPM_LOCK         = 1 << 3;
        /// `pnpm-lock.yaml`
        const PNPM_LOCK        = 1 << 4;
        /// `yarn.lock`
        const YARN_LOCK        = 1 << 5;
        /// `bun.lock` / `bun.lockb`
        const BUN_LOCK         = 1 << 6;
        /// `deno.json` / `deno.jsonc` / `deno.lock`
        const DENO_CONFIG      = 1 << 7;
        /// `next.config.*`
        const NEXT_CONFIG      = 1 << 8;
        /// `nuxt.config.*`
        const NUXT_CONFIG      = 1 << 9;
        /// `pyproject.toml`
        const PYPROJECT        = 1 << 10;
        /// `requirements.txt`
        const REQUIREMENTS     = 1 << 11;
        /// `setup.py` / `setup.cfg`
        const SETUP_PY         = 1 << 12;
        /// `poetry.lock`
        const POETRY_LOCK      = 1 << 13;
        /// `pom.xml`
        const POM_XML          = 1 << 14;
        /// `build.gradle` / `build.gradle.kts` / `settings.gradle*`
        const GRADLE_BUILD     = 1 << 15;
        /// Any `*.csproj` / `*.fsproj` / `*.vbproj`
        const DOTNET_PROJECT   = 1 << 16;
        /// Any `*.sln`
        const DOTNET_SOLUTION  = 1 << 17;
        /// `go.mod`
        const GO_MOD           = 1 << 18;
        /// `go.sum`
        const GO_SUM           = 1 << 19;
        /// `CMakeLists.txt`
        const CMAKELISTS       = 1 << 20;
        /// `Makefile` / `makefile` / `GNUmakefile`
        const MAKEFILE         = 1 << 21;
        /// `meson.build`
        const MESON_BUILD      = 1 << 22;
        /// `configure` / `configure.ac`
        const AUTOCONF         = 1 << 23;
        /// `Package.swift`
        const SWIFT_PACKAGE    = 1 << 24;
        /// Any `*.xcodeproj` / `*.xcworkspace`
        const XCODE_PROJECT    = 1 << 25;
        /// `Gemfile`
        const GEMFILE          = 1 << 26;
        /// `composer.json`
        const COMPOSER_JSON    = 1 << 27;
        /// `pubspec.yaml`
        const PUBSPEC          = 1 << 28;
        /// `mix.exs`
        const MIX_EXS          = 1 << 29;
        /// `stack.yaml` / `*.cabal`
        const HASKELL_PROJECT  = 1 << 30;
        /// `Dockerfile` / `compose.yaml` / `docker-compose.yml`
        const DOCKERFILE       = 1 << 31;
        /// `.git` present as an entry
        const GIT_DIR          = 1 << 32;
        /// `flake.nix` / `default.nix` / `shell.nix`
        const NIX_FILE         = 1 << 33;
        /// `*.tf`
        const TERRAFORM        = 1 << 34;
        /// `gradlew` / `gradlew.bat`
        const GRADLE_WRAPPER   = 1 << 35;
        /// An `Assets` directory (half of the Unity project layout)
        const UNITY_ASSETS     = 1 << 36;
        /// A `ProjectSettings` directory (the other half)
        const UNITY_SETTINGS   = 1 << 47;
        /// `pyvenv.cfg` (marks the directory itself as a virtualenv)
        const PYVENV_CFG       = 1 << 37;
        /// `HEAD` (used together with `objects`/`refs` to identify a git dir)
        const GIT_HEAD         = 1 << 38;
        /// `objects` directory
        const GIT_OBJECTS      = 1 << 39;
        /// `refs` directory
        const GIT_REFS         = 1 << 40;
        /// `angular.json`
        const ANGULAR_JSON     = 1 << 41;
        /// `vite.config.*`
        const VITE_CONFIG      = 1 << 42;
        /// `tsconfig.json`
        const TSCONFIG         = 1 << 43;
        /// `Pipfile`
        const PIPFILE          = 1 << 44;
        /// `Podfile`
        const PODFILE          = 1 << 45;
        /// `.csproj`-adjacent `Directory.Build.props`
        const DOTNET_PROPS     = 1 << 46;
        /// `build.zig` / `build.zig.zon`
        const BUILD_ZIG        = 1 << 48;
        /// `wrangler.toml` / `wrangler.json(c)` (Cloudflare Workers)
        const WRANGLER         = 1 << 49;
    }
}

impl Markers {
    /// Marker set implying "this directory is a JavaScript project root".
    pub const JS_PROJECT: Markers = Markers::PACKAGE_JSON
        .union(Markers::NPM_LOCK)
        .union(Markers::PNPM_LOCK)
        .union(Markers::YARN_LOCK)
        .union(Markers::BUN_LOCK);

    /// Marker set implying "this directory is a Python project root".
    pub const PY_PROJECT: Markers = Markers::PYPROJECT
        .union(Markers::REQUIREMENTS)
        .union(Markers::SETUP_PY)
        .union(Markers::POETRY_LOCK)
        .union(Markers::PIPFILE);

    /// Marker set implying a JVM project.
    pub const JVM_PROJECT: Markers = Markers::POM_XML
        .union(Markers::GRADLE_BUILD)
        .union(Markers::GRADLE_WRAPPER);

    /// Marker set implying a C/C++ project.
    pub const NATIVE_PROJECT: Markers = Markers::CMAKELISTS
        .union(Markers::MAKEFILE)
        .union(Markers::MESON_BUILD)
        .union(Markers::AUTOCONF);

    /// A Unity project needs *both* halves of its layout.
    ///
    /// One bit could not express that, and a lone `Assets/` directory is far too
    /// common — any website with an `Assets` folder and a `Temp` folder would
    /// otherwise have `Temp` classified as disposable Unity scratch data.
    pub const UNITY_PROJECT: Markers = Markers::UNITY_ASSETS.union(Markers::UNITY_SETTINGS);

    /// Whether both halves of the Unity layout are present.
    #[inline]
    #[must_use]
    pub fn is_unity_project(self) -> bool {
        self.contains(Markers::UNITY_PROJECT)
    }

    /// Update the bitset from a single directory entry name.
    ///
    /// `is_dir` matters because a few markers (`.git`, `objects`) are
    /// directories, and the two halves of the Unity layout are recorded
    /// separately so that detectors can demand both.
    pub fn observe(&mut self, name: &str, is_dir: bool) {
        if is_dir {
            match name {
                ".git" => *self |= Markers::GIT_DIR,
                "objects" => *self |= Markers::GIT_OBJECTS,
                "refs" => *self |= Markers::GIT_REFS,
                "Assets" => *self |= Markers::UNITY_ASSETS,
                "ProjectSettings" => *self |= Markers::UNITY_SETTINGS,
                _ => {}
            }
            // `*.xcodeproj` bundles are directories on macOS.
            if has_extension(name, "xcodeproj") || has_extension(name, "xcworkspace") {
                *self |= Markers::XCODE_PROJECT;
            }
            return;
        }

        match name {
            "Cargo.toml" => *self |= Markers::CARGO_TOML,
            "Cargo.lock" => *self |= Markers::CARGO_LOCK,
            "package.json" => *self |= Markers::PACKAGE_JSON,
            "package-lock.json" | "npm-shrinkwrap.json" => *self |= Markers::NPM_LOCK,
            "pnpm-lock.yaml" | "pnpm-workspace.yaml" => *self |= Markers::PNPM_LOCK,
            "yarn.lock" => *self |= Markers::YARN_LOCK,
            "bun.lock" | "bun.lockb" => *self |= Markers::BUN_LOCK,
            "deno.json" | "deno.jsonc" | "deno.lock" => *self |= Markers::DENO_CONFIG,
            "angular.json" => *self |= Markers::ANGULAR_JSON,
            "tsconfig.json" => *self |= Markers::TSCONFIG,
            "pyproject.toml" => *self |= Markers::PYPROJECT,
            "requirements.txt" | "requirements-dev.txt" => *self |= Markers::REQUIREMENTS,
            "setup.py" | "setup.cfg" => *self |= Markers::SETUP_PY,
            "poetry.lock" => *self |= Markers::POETRY_LOCK,
            "Pipfile" | "Pipfile.lock" => *self |= Markers::PIPFILE,
            "pyvenv.cfg" => *self |= Markers::PYVENV_CFG,
            "pom.xml" => *self |= Markers::POM_XML,
            "gradlew" | "gradlew.bat" => *self |= Markers::GRADLE_WRAPPER,
            "go.mod" => *self |= Markers::GO_MOD,
            "go.sum" => *self |= Markers::GO_SUM,
            "CMakeLists.txt" => *self |= Markers::CMAKELISTS,
            "Makefile" | "makefile" | "GNUmakefile" => *self |= Markers::MAKEFILE,
            "meson.build" => *self |= Markers::MESON_BUILD,
            "configure" | "configure.ac" | "configure.in" => *self |= Markers::AUTOCONF,
            "Package.swift" => *self |= Markers::SWIFT_PACKAGE,
            "Podfile" | "Podfile.lock" => *self |= Markers::PODFILE,
            "Gemfile" | "Gemfile.lock" => *self |= Markers::GEMFILE,
            "composer.json" => *self |= Markers::COMPOSER_JSON,
            "pubspec.yaml" => *self |= Markers::PUBSPEC,
            "mix.exs" => *self |= Markers::MIX_EXS,
            "stack.yaml" | "cabal.project" => *self |= Markers::HASKELL_PROJECT,
            "flake.nix" | "default.nix" | "shell.nix" => *self |= Markers::NIX_FILE,
            "HEAD" => *self |= Markers::GIT_HEAD,
            "Directory.Build.props" => *self |= Markers::DOTNET_PROPS,
            "build.zig" | "build.zig.zon" => *self |= Markers::BUILD_ZIG,
            "wrangler.toml" | "wrangler.json" | "wrangler.jsonc" => *self |= Markers::WRANGLER,
            _ => {}
        }

        // Prefix / extension based markers.
        if name.starts_with("build.gradle") || name.starts_with("settings.gradle") {
            *self |= Markers::GRADLE_BUILD;
        }
        if name.starts_with("next.config.") {
            *self |= Markers::NEXT_CONFIG;
        }
        if name.starts_with("nuxt.config.") {
            *self |= Markers::NUXT_CONFIG;
        }
        if name.starts_with("vite.config.") {
            *self |= Markers::VITE_CONFIG;
        }
        if name == "Dockerfile"
            || name.starts_with("Dockerfile.")
            || name == "compose.yaml"
            || name == "compose.yml"
            || name == "docker-compose.yml"
            || name == "docker-compose.yaml"
        {
            *self |= Markers::DOCKERFILE;
        }

        match extension_of(name) {
            Some("csproj" | "fsproj" | "vbproj" | "vcxproj") => *self |= Markers::DOTNET_PROJECT,
            Some("sln" | "slnx") => *self |= Markers::DOTNET_SOLUTION,
            Some("cabal") => *self |= Markers::HASKELL_PROJECT,
            Some("tf") => *self |= Markers::TERRAFORM,
            _ => {}
        }
    }

    /// `true` if any of `other`'s bits are present.
    #[inline]
    #[must_use]
    pub fn any(self, other: Markers) -> bool {
        self.intersects(other)
    }
}

/// Lowercase extension of a file name, if any.
#[must_use]
pub fn extension_of(name: &str) -> Option<&str> {
    let dot = name.rfind('.')?;
    if dot == 0 || dot + 1 == name.len() {
        return None;
    }
    Some(&name[dot + 1..])
}

fn has_extension(name: &str, ext: &str) -> bool {
    extension_of(name).is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Everything a [`crate::analysis::Detector`] is allowed to look at.
///
/// Detectors receive a borrowed view and must not perform filesystem I/O: all
/// the evidence they need was already gathered by the walker. That keeps
/// classification deterministic, cheap, and trivially testable.
#[derive(Debug, Clone, Copy)]
pub struct DirContext<'a> {
    /// Full path of the directory being classified.
    pub path: &'a Path,
    /// Final component of `path`.
    pub name: &'a str,
    /// `name` lowercased, for case-insensitive comparisons. Borrowed when the
    /// name is already lowercase, so the common case does not allocate.
    pub name_lower: &'a str,
    /// Name of the parent directory, if there is one.
    pub parent_name: Option<&'a str>,
    /// Marker files found *inside* this directory.
    pub markers: Markers,
    /// Marker files found in the parent directory.
    pub parent_markers: Markers,
    /// Marker files found in the grandparent directory.
    ///
    /// Needed for layouts like `<project>/build/classes`, where the project
    /// fingerprint is two levels up.
    pub grandparent_markers: Markers,
    /// Depth below the scan root (`0` for the root itself).
    pub depth: u16,
    /// Number of immediate subdirectories.
    pub subdir_count: u32,
    /// Number of immediate files.
    pub file_count: u32,
    /// Well-known locations for this machine (home, caches, container roots).
    pub env: &'a crate::platform::KnownPaths,
}

impl<'a> DirContext<'a> {
    /// Whether the parent looks like the root of a project in `markers`.
    #[inline]
    #[must_use]
    pub fn parent_is_project(&self, markers: Markers) -> bool {
        self.parent_markers.intersects(markers)
    }

    /// Whether this directory itself carries any of `markers`.
    #[inline]
    #[must_use]
    pub fn has(&self, markers: Markers) -> bool {
        self.markers.intersects(markers)
    }

    /// Case-insensitive comparison of the directory name.
    #[inline]
    #[must_use]
    pub fn name_is(&self, candidate: &str) -> bool {
        self.name_lower == candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn markers_from(files: &[&str], dirs: &[&str]) -> Markers {
        let mut markers = Markers::empty();
        for f in files {
            markers.observe(f, false);
        }
        for d in dirs {
            markers.observe(d, true);
        }
        markers
    }

    #[test]
    fn detects_rust_project_markers() {
        let markers = markers_from(&["Cargo.toml", "Cargo.lock"], &["src"]);
        assert!(markers.contains(Markers::CARGO_TOML));
        assert!(markers.contains(Markers::CARGO_LOCK));
        assert!(!markers.contains(Markers::PACKAGE_JSON));
    }

    #[test]
    fn detects_javascript_package_managers_individually() {
        assert!(markers_from(&["pnpm-lock.yaml"], &[]).contains(Markers::PNPM_LOCK));
        assert!(markers_from(&["yarn.lock"], &[]).contains(Markers::YARN_LOCK));
        assert!(markers_from(&["bun.lockb"], &[]).contains(Markers::BUN_LOCK));
        assert!(markers_from(&["package-lock.json"], &[]).contains(Markers::NPM_LOCK));
    }

    #[test]
    fn gradle_markers_accept_kotlin_dsl() {
        assert!(markers_from(&["build.gradle.kts"], &[]).contains(Markers::GRADLE_BUILD));
        assert!(markers_from(&["build.gradle"], &[]).contains(Markers::GRADLE_BUILD));
        assert!(markers_from(&["settings.gradle.kts"], &[]).contains(Markers::GRADLE_BUILD));
    }

    #[test]
    fn dotnet_markers_come_from_extensions() {
        assert!(markers_from(&["Api.csproj"], &[]).contains(Markers::DOTNET_PROJECT));
        assert!(markers_from(&["App.fsproj"], &[]).contains(Markers::DOTNET_PROJECT));
        assert!(markers_from(&["Solution.sln"], &[]).contains(Markers::DOTNET_SOLUTION));
    }

    #[test]
    fn directories_only_contribute_directory_markers() {
        // A *file* called `.git` (a git worktree pointer) is not a git dir.
        let as_file = markers_from(&[".git"], &[]);
        assert!(!as_file.contains(Markers::GIT_DIR));
        let as_dir = markers_from(&[], &[".git"]);
        assert!(as_dir.contains(Markers::GIT_DIR));
    }

    #[test]
    fn next_config_variants_are_recognised() {
        for name in ["next.config.js", "next.config.mjs", "next.config.ts"] {
            assert!(
                markers_from(&[name], &[]).contains(Markers::NEXT_CONFIG),
                "{name} should mark a Next.js project"
            );
        }
    }

    #[test]
    fn extension_helper_ignores_dotfiles_and_trailing_dots() {
        assert_eq!(extension_of("file.tar.gz"), Some("gz"));
        assert_eq!(extension_of(".gitignore"), None);
        assert_eq!(extension_of("noext"), None);
        assert_eq!(extension_of("trailing."), None);
    }

    #[test]
    fn unity_needs_both_halves_of_its_layout() {
        // A website with an `Assets` folder is not a Unity project.
        let assets_only = markers_from(&[], &["Assets"]);
        assert!(assets_only.contains(Markers::UNITY_ASSETS));
        assert!(!assets_only.is_unity_project());

        let settings_only = markers_from(&[], &["ProjectSettings"]);
        assert!(!settings_only.is_unity_project());

        let both = markers_from(&[], &["Assets", "ProjectSettings"]);
        assert!(both.is_unity_project());
    }

    #[test]
    fn composite_marker_sets_match_any_member() {
        let js = markers_from(&["yarn.lock"], &[]);
        assert!(js.any(Markers::JS_PROJECT));
        let py = markers_from(&["pyproject.toml"], &[]);
        assert!(py.any(Markers::PY_PROJECT));
        assert!(!py.any(Markers::JS_PROJECT));
    }
}
