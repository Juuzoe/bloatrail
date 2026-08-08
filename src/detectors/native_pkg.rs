//! Remaining language ecosystems: Ruby, PHP, Swift, Dart, Elixir, Haskell,
//! Terraform and Unity.
//!
//! These share two rules — vendored dependency directories and per-language
//! build output — so they live together rather than in a file each.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_STRONG};

/// Dependencies vendored into a project by a package manager.
pub struct VendoredDependencies;

static VENDOR_TRIGGERS: &[Trigger] = &[
    Trigger::Name("vendor"),
    Trigger::Name("pods"),
    Trigger::Name(".terraform"),
    Trigger::Name("deps"),
    Trigger::Name(".packages"),
    Trigger::Name("library"),
];

impl Detector for VendoredDependencies {
    fn id(&self) -> &'static str {
        "pkg.vendored"
    }

    fn triggers(&self) -> &'static [Trigger] {
        VENDOR_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        match ctx.name_lower {
            "vendor" => {
                if ctx.parent_is_project(Markers::COMPOSER_JSON) {
                    return Some(
                        dependency("Composer dependencies", Technology::Php, "composer install")
                            .with_evidence(
                                "A `composer.json` file exists in the parent directory.",
                            ),
                    );
                }
                if ctx.parent_is_project(Markers::GEMFILE) {
                    return Some(
                        dependency("Bundled Ruby gems", Technology::Ruby, "bundle install")
                            .with_evidence("A `Gemfile` exists in the parent directory."),
                    );
                }
                None
            }
            "pods" => {
                if !ctx.parent_is_project(Markers::PODFILE) {
                    return None;
                }
                Some(
                    dependency("CocoaPods dependencies", Technology::Swift, "pod install")
                        .with_evidence("A `Podfile` exists in the parent directory."),
                )
            }
            ".terraform" => Some(
                dependency(
                    "Terraform providers and modules",
                    Technology::Terraform,
                    "terraform init",
                )
                .with_evidence(
                    "Provider plugins are re-downloaded by `terraform init`; state files live \
                     elsewhere and are not touched.",
                ),
            ),
            "deps" => {
                if !ctx.parent_is_project(Markers::MIX_EXS) {
                    return None;
                }
                Some(
                    dependency("Elixir dependencies", Technology::Elixir, "mix deps.get")
                        .with_evidence("A `mix.exs` file exists in the parent directory."),
                )
            }
            ".packages" => {
                if !ctx.parent_is_project(Markers::PUBSPEC) {
                    return None;
                }
                Some(
                    dependency("Dart package links", Technology::Dart, "dart pub get")
                        .with_evidence("A `pubspec.yaml` file exists in the parent directory."),
                )
            }
            "library" => {
                // Unity's `Library/` is a large regenerable import cache — but
                // only inside a Unity project.
                if !ctx.parent_markers.is_unity_project() {
                    return None;
                }
                Some(
                    Detection::new(
                        Category::Cache,
                        Confidence::High,
                        CleanupSafety::ProbablySafe,
                        "Unity asset import cache",
                    )
                    .with_technology(Technology::Unity)
                    .with_evidence(
                        "Unity regenerates `Library/` by reimporting every asset, which can take \
                         a long time on a large project.",
                    )
                    .collapsed()
                    .with_specificity(SPEC_CONTEXT),
                )
            }
            _ => None,
        }
    }
}

fn dependency(label: &'static str, technology: Technology, command: &'static str) -> Detection {
    Detection::new(
        Category::Dependency,
        Confidence::High,
        CleanupSafety::ProbablySafe,
        label,
    )
    .with_technology(technology)
    .regenerated_by(command)
    .collapsed()
    .with_specificity(SPEC_CONTEXT)
}

/// Per-language build output that does not fit the `build/`-`target/` pattern.
pub struct LanguageBuildDirs;

static BUILD_TRIGGERS: &[Trigger] = &[
    Trigger::Name("_build"),
    Trigger::Name("dist-newstyle"),
    Trigger::Name(".stack-work"),
    Trigger::Name("elm-stuff"),
    Trigger::Name(".dart_tool"),
    Trigger::Name(".build"),
    Trigger::Name("temp"),
    Trigger::Name("obj"),
    Trigger::Name("zig-out"),
    Trigger::Name("zig-cache"),
    Trigger::Name(".zig-cache"),
    Trigger::Name("nimcache"),
];

impl Detector for LanguageBuildDirs {
    fn id(&self) -> &'static str {
        "pkg.language_build"
    }

    fn triggers(&self) -> &'static [Trigger] {
        BUILD_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        match ctx.name_lower {
            "_build" if ctx.parent_is_project(Markers::MIX_EXS) => Some(build(
                "Elixir build output",
                Technology::Elixir,
                "mix compile",
            )),
            "dist-newstyle" | ".stack-work" => Some(build(
                "Haskell build output",
                Technology::Haskell,
                "cabal build",
            )),
            "elm-stuff" => Some(build("Elm build output", Technology::Node, "elm make")),
            ".dart_tool" if ctx.parent_is_project(Markers::PUBSPEC) => {
                Some(build("Dart tool cache", Technology::Dart, "dart pub get"))
            }
            ".build" if ctx.parent_is_project(Markers::SWIFT_PACKAGE) => Some(build(
                "Swift Package Manager build output",
                Technology::Swift,
                "swift build",
            )),
            "temp" | "obj" if ctx.parent_markers.is_unity_project() => Some(build(
                "Unity build scratch data",
                Technology::Unity,
                "Unity build",
            )),
            // `zig-out` next to a `build.zig` is compiled output. Without the
            // build script the name alone stays unclaimed: "out" names are too
            // easy to reuse.
            "zig-out" if ctx.parent_is_project(Markers::BUILD_ZIG) => Some(
                build("Zig build output", Technology::Zig, "zig build")
                    .with_evidence("A `build.zig` file exists in the parent directory."),
            ),
            // The cache directory names are effectively unique to Zig, so they
            // are accepted without a marker, at reduced confidence.
            "zig-cache" | ".zig-cache" => {
                let corroborated = ctx.parent_is_project(Markers::BUILD_ZIG);
                let mut detection = Detection::new(
                    Category::Cache,
                    if corroborated {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    },
                    CleanupSafety::Safe,
                    "Zig build cache",
                )
                .with_technology(Technology::Zig)
                .with_evidence("Incremental compilation state; the next `zig build` recreates it.")
                .regenerated_by("zig build")
                .collapsed()
                .with_specificity(SPEC_STRONG);
                if corroborated {
                    detection = detection
                        .with_evidence("A `build.zig` file exists in the parent directory.");
                }
                Some(detection)
            }
            // Nim writes compiled C sources and objects here; no other tool
            // uses the name.
            "nimcache" => Some(
                Detection::new(
                    Category::Cache,
                    Confidence::Medium,
                    CleanupSafety::Safe,
                    "Nim compilation cache",
                )
                .with_technology(Technology::Nim)
                .with_evidence("Recreated by the next `nim c` invocation.")
                .regenerated_by("nim c <file>")
                .collapsed()
                .with_specificity(SPEC_STRONG),
            ),
            _ => None,
        }
    }
}

fn build(label: &'static str, technology: Technology, command: &'static str) -> Detection {
    Detection::new(
        Category::BuildArtifact,
        Confidence::High,
        CleanupSafety::Safe,
        label,
    )
    .with_technology(technology)
    .with_evidence("Compiler output, regenerated from source on the next build.")
    .regenerated_by(command)
    .collapsed()
    .with_specificity(SPEC_STRONG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::ctx;
    use crate::platform::KnownPaths;

    #[test]
    fn vendor_meaning_depends_on_the_manifest() {
        let env = KnownPaths::empty();
        let php = VendoredDependencies
            .detect(&ctx("vendor", Markers::COMPOSER_JSON, &env))
            .expect("detection");
        assert_eq!(php.technology, Some(Technology::Php));

        let ruby = VendoredDependencies
            .detect(&ctx("vendor", Markers::GEMFILE, &env))
            .expect("detection");
        assert_eq!(ruby.technology, Some(Technology::Ruby));

        assert!(VendoredDependencies
            .detect(&ctx("vendor", Markers::empty(), &env))
            .is_none());
    }

    #[test]
    fn unity_library_needs_a_unity_project() {
        let env = KnownPaths::empty();
        assert!(VendoredDependencies
            .detect(&ctx("library", Markers::empty(), &env))
            .is_none());
        let detection = VendoredDependencies
            .detect(&ctx("library", Markers::UNITY_PROJECT, &env))
            .expect("detection");
        assert_eq!(detection.technology, Some(Technology::Unity));
    }

    #[test]
    fn a_lone_assets_folder_does_not_make_temp_disposable() {
        let env = KnownPaths::empty();
        // `~/site/Assets/` + `~/site/Temp/` is an ordinary website layout. Its
        // `Temp` directory must not become SAFE-to-delete Unity scratch data.
        for name in ["temp", "obj"] {
            assert!(
                LanguageBuildDirs
                    .detect(&ctx(name, Markers::UNITY_ASSETS, &env))
                    .is_none(),
                "`{name}` next to a lone `Assets/` must not be claimed"
            );
        }
        assert!(VendoredDependencies
            .detect(&ctx("library", Markers::UNITY_ASSETS, &env))
            .is_none());

        // Both halves present: a real Unity project.
        assert!(LanguageBuildDirs
            .detect(&ctx("temp", Markers::UNITY_PROJECT, &env))
            .is_some());
    }

    #[test]
    fn elixir_build_requires_mix() {
        let env = KnownPaths::empty();
        assert!(LanguageBuildDirs
            .detect(&ctx("_build", Markers::empty(), &env))
            .is_none());
        assert!(LanguageBuildDirs
            .detect(&ctx("_build", Markers::MIX_EXS, &env))
            .is_some());
    }

    #[test]
    fn zig_output_needs_the_build_script_but_the_cache_does_not() {
        let env = KnownPaths::empty();

        assert!(
            LanguageBuildDirs
                .detect(&ctx("zig-out", Markers::empty(), &env))
                .is_none(),
            "zig-out without build.zig stays unclaimed"
        );

        let out = LanguageBuildDirs
            .detect(&ctx("zig-out", Markers::BUILD_ZIG, &env))
            .expect("detection");
        assert_eq!(out.technology, Some(Technology::Zig));
        assert_eq!(out.cleanup, CleanupSafety::Safe);

        let cache = LanguageBuildDirs
            .detect(&ctx(".zig-cache", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(cache.confidence, Confidence::Medium);

        let corroborated = LanguageBuildDirs
            .detect(&ctx("zig-cache", Markers::BUILD_ZIG, &env))
            .expect("detection");
        assert_eq!(corroborated.confidence, Confidence::High);
    }

    #[test]
    fn nimcache_is_recognised_by_name() {
        let env = KnownPaths::empty();
        let detection = LanguageBuildDirs
            .detect(&ctx("nimcache", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.technology, Some(Technology::Nim));
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
    }

    #[test]
    fn haskell_build_dirs_are_unambiguous_by_name() {
        let env = KnownPaths::empty();
        let detection = LanguageBuildDirs
            .detect(&ctx("dist-newstyle", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.technology, Some(Technology::Haskell));
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
    }
}
