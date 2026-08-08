//! JavaScript / TypeScript ecosystem detection.

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection, Technology};
use crate::analysis::engine::{Detector, Trigger};

use super::{SPEC_CONTEXT, SPEC_STRONG, SPEC_WEAK};

/// Which package manager installed a `node_modules` tree, inferred from the
/// lockfile sitting next to it.
fn package_manager(markers: Markers) -> (Technology, &'static str, &'static str) {
    if markers.contains(Markers::PNPM_LOCK) {
        (Technology::Node, "pnpm dependencies", "pnpm install")
    } else if markers.contains(Markers::YARN_LOCK) {
        (Technology::Node, "yarn dependencies", "yarn install")
    } else if markers.contains(Markers::BUN_LOCK) {
        (Technology::Bun, "bun dependencies", "bun install")
    } else {
        (Technology::Node, "npm dependencies", "npm install")
    }
}

/// `node_modules` — the single largest source of developer disk bloat.
pub struct NodeModules;

static NODE_MODULES_TRIGGERS: &[Trigger] = &[Trigger::Name("node_modules")];

impl Detector for NodeModules {
    fn id(&self) -> &'static str {
        "javascript.node_modules"
    }

    fn triggers(&self) -> &'static [Trigger] {
        NODE_MODULES_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        let has_project = ctx.parent_is_project(Markers::JS_PROJECT);
        let (technology, label, command) = package_manager(ctx.parent_markers);

        let (confidence, safety, specificity) = if has_project {
            (Confidence::High, CleanupSafety::Safe, SPEC_CONTEXT)
        } else {
            // The name is essentially unique to Node, so this is still a solid
            // detection — but without a manifest we cannot promise a reinstall
            // will reproduce it.
            (Confidence::Medium, CleanupSafety::ProbablySafe, SPEC_STRONG)
        };

        let mut detection = Detection::new(Category::Dependency, confidence, safety, label)
            .with_technology(technology)
            .with_evidence(
                "`node_modules` holds packages downloaded by a JavaScript package manager. \
                 None of it is written by hand.",
            )
            .regenerated_by(command)
            .collapsed()
            .with_specificity(specificity);

        if has_project {
            detection = detection.with_evidence(
                "A package manifest in the parent directory lets the exact same tree be \
                 reinstalled.",
            );
        } else {
            detection = detection.with_evidence(
                "No `package.json` was found next to it, so reinstalling may not reproduce the \
                 same versions.",
            );
        }

        if ctx.parent_markers.contains(Markers::PNPM_LOCK) {
            detection = detection.with_evidence(
                "pnpm links these packages from a shared store, so most of the space is \
                 already deduplicated.",
            );
        }

        Some(detection)
    }
}

/// Framework and bundler caches: `.next`, `.nuxt`, `.turbo`, `.parcel-cache`, …
pub struct JsFrameworkCache;

// `.eslintcache` is a file, not a directory, so it is deliberately absent:
// detectors only ever run against directories.
static FRAMEWORK_TRIGGERS: &[Trigger] = &[
    Trigger::Name(".next"),
    Trigger::Name(".nuxt"),
    Trigger::Name(".turbo"),
    Trigger::Name(".parcel-cache"),
    Trigger::Name(".svelte-kit"),
    Trigger::Name(".astro"),
    Trigger::Name(".angular"),
    Trigger::Name(".docusaurus"),
    Trigger::Name(".expo"),
    Trigger::Name(".vite"),
    Trigger::Name(".rollup.cache"),
    Trigger::Name(".yarn"),
    Trigger::Name(".wrangler"),
];

impl Detector for JsFrameworkCache {
    fn id(&self) -> &'static str {
        "javascript.framework_cache"
    }

    fn triggers(&self) -> &'static [Trigger] {
        FRAMEWORK_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        let in_project = ctx.parent_is_project(Markers::JS_PROJECT)
            || ctx.parent_markers.contains(Markers::TSCONFIG);

        let (label, command, tech): (&'static str, &'static str, Technology) = match ctx.name_lower
        {
            ".next" => ("Next.js build cache", "next build", Technology::Node),
            ".nuxt" => ("Nuxt build cache", "nuxt build", Technology::Node),
            ".turbo" => ("Turborepo cache", "turbo run build", Technology::Node),
            ".parcel-cache" => ("Parcel cache", "parcel build", Technology::Node),
            ".svelte-kit" => ("SvelteKit build cache", "vite build", Technology::Node),
            ".astro" => ("Astro build cache", "astro build", Technology::Node),
            ".angular" => ("Angular build cache", "ng build", Technology::Node),
            ".docusaurus" => (
                "Docusaurus build cache",
                "docusaurus build",
                Technology::Node,
            ),
            ".expo" => ("Expo build cache", "expo start", Technology::Node),
            ".vite" => ("Vite dependency cache", "vite", Technology::Node),
            ".rollup.cache" => ("Rollup cache", "rollup -c", Technology::Node),
            ".yarn" => return yarn_directory(ctx),
            ".wrangler" => return wrangler_directory(ctx),
            _ => return None,
        };

        // Without a manifest next to it there is no command that will
        // definitely rebuild the cache, so the classification is downgraded to
        // match: `Safe` means "regenerated automatically", and that promise
        // depends on the project being there.
        let (confidence, safety, specificity) = if in_project {
            (Confidence::High, CleanupSafety::Safe, SPEC_CONTEXT)
        } else {
            (Confidence::Medium, CleanupSafety::ProbablySafe, SPEC_STRONG)
        };

        Some(
            Detection::new(Category::Cache, confidence, safety, label)
                .with_technology(tech)
                .with_evidence("Regenerated automatically by the next build or dev-server start.")
                .regenerated_by(command)
                .collapsed()
                .with_specificity(specificity),
        )
    }
}

/// `.yarn/` holds both a disposable cache and, for Plug'n'Play projects, the
/// packages themselves — so it gets its own treatment.
fn yarn_directory(ctx: &DirContext<'_>) -> Option<Detection> {
    if !ctx.parent_is_project(Markers::JS_PROJECT) {
        return None;
    }
    Some(
        Detection::new(
            Category::PackageCache,
            Confidence::High,
            CleanupSafety::ProbablySafe,
            "Yarn project cache",
        )
        .with_technology(Technology::Node)
        .with_evidence(
            "Yarn stores package archives here. Plug'n'Play projects resolve imports directly \
             from this directory, so removing it requires a reinstall before the project runs.",
        )
        .regenerated_by("yarn install")
        .collapsed()
        .with_specificity(SPEC_CONTEXT),
    )
}

/// `.wrangler/` holds Wrangler's build cache and its *local development state*
/// — simulated D1 databases and KV stores included — so it never earns `Safe`.
fn wrangler_directory(ctx: &DirContext<'_>) -> Option<Detection> {
    if !ctx.parent_is_project(Markers::JS_PROJECT) && !ctx.parent_is_project(Markers::WRANGLER) {
        return None;
    }
    Some(
        Detection::new(
            Category::Cache,
            Confidence::High,
            CleanupSafety::ProbablySafe,
            "Cloudflare Wrangler local state",
        )
        .with_technology(Technology::Node)
        .with_evidence(
            "Holds Wrangler's build cache and the local D1/KV state used by `wrangler dev`. \
             Removing it resets local development data; production is untouched.",
        )
        .regenerated_by("wrangler dev")
        .collapsed()
        .with_specificity(SPEC_CONTEXT),
    )
}

/// Bundler output directories, which only mean something inside a JS project.
pub struct JsBuildOutput;

static OUTPUT_TRIGGERS: &[Trigger] = &[
    Trigger::Name("dist"),
    Trigger::Name("out"),
    Trigger::Name("coverage"),
    Trigger::Name("storybook-static"),
    Trigger::Name("bower_components"),
    Trigger::Name(".output"),
];

impl Detector for JsBuildOutput {
    fn id(&self) -> &'static str {
        "javascript.build_output"
    }

    fn triggers(&self) -> &'static [Trigger] {
        OUTPUT_TRIGGERS
    }

    fn detect(&self, ctx: &DirContext<'_>) -> Option<Detection> {
        if ctx.name_lower == "bower_components" {
            return Some(
                Detection::new(
                    Category::Dependency,
                    Confidence::Medium,
                    CleanupSafety::ProbablySafe,
                    "Bower dependencies",
                )
                .with_technology(Technology::Node)
                .with_evidence(
                    "Installed by Bower, a package manager that is no longer maintained.",
                )
                .regenerated_by("bower install")
                .collapsed()
                .with_specificity(SPEC_STRONG),
            );
        }

        let in_project = ctx.parent_is_project(Markers::JS_PROJECT)
            || ctx.parent_markers.contains(Markers::TSCONFIG)
            || ctx.parent_markers.contains(Markers::VITE_CONFIG)
            || ctx.parent_markers.contains(Markers::ANGULAR_JSON);
        if !in_project {
            return None;
        }

        let (label, safety, evidence) = match ctx.name_lower {
            "coverage" => (
                "Test coverage reports",
                CleanupSafety::Safe,
                "Regenerated every time the test suite runs with coverage enabled.",
            ),
            "storybook-static" => (
                "Storybook static build",
                CleanupSafety::Safe,
                "Regenerated by `storybook build`.",
            ),
            _ => (
                "JavaScript build output",
                CleanupSafety::ProbablySafe,
                "Produced by the project's build script. Some projects commit this directory, \
                 so check before removing it.",
            ),
        };

        Some(
            Detection::new(Category::BuildArtifact, Confidence::Medium, safety, label)
                .with_technology(Technology::Node)
                .with_evidence(evidence)
                .regenerated_by("npm run build")
                .collapsed()
                .with_specificity(SPEC_WEAK + 20),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests_support::ctx;
    use crate::platform::KnownPaths;

    #[test]
    fn node_modules_with_manifest_is_safe() {
        let env = KnownPaths::empty();
        let detection = NodeModules
            .detect(&ctx("node_modules", Markers::PACKAGE_JSON, &env))
            .expect("detection");
        assert_eq!(detection.category, Category::Dependency);
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
        assert_eq!(detection.confidence, Confidence::High);
        assert!(detection.collapse);
    }

    #[test]
    fn node_modules_without_manifest_is_downgraded() {
        let env = KnownPaths::empty();
        let detection = NodeModules
            .detect(&ctx("node_modules", Markers::empty(), &env))
            .expect("detection");
        assert_eq!(detection.confidence, Confidence::Medium);
        assert_eq!(detection.cleanup, CleanupSafety::ProbablySafe);
    }

    #[test]
    fn package_manager_is_inferred_from_the_lockfile() {
        let env = KnownPaths::empty();
        let pnpm = NodeModules
            .detect(&ctx(
                "node_modules",
                Markers::PACKAGE_JSON | Markers::PNPM_LOCK,
                &env,
            ))
            .expect("detection");
        assert_eq!(pnpm.reason, "pnpm dependencies");
        assert_eq!(pnpm.regenerated_by.as_deref(), Some("pnpm install"));

        let yarn = NodeModules
            .detect(&ctx(
                "node_modules",
                Markers::PACKAGE_JSON | Markers::YARN_LOCK,
                &env,
            ))
            .expect("detection");
        assert_eq!(yarn.regenerated_by.as_deref(), Some("yarn install"));

        let bun = NodeModules
            .detect(&ctx(
                "node_modules",
                Markers::PACKAGE_JSON | Markers::BUN_LOCK,
                &env,
            ))
            .expect("detection");
        assert_eq!(bun.technology, Some(Technology::Bun));
    }

    #[test]
    fn next_cache_is_safe_inside_a_project() {
        let env = KnownPaths::empty();
        let detection = JsFrameworkCache
            .detect(&ctx(
                ".next",
                Markers::PACKAGE_JSON | Markers::NEXT_CONFIG,
                &env,
            ))
            .expect("detection");
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
        assert_eq!(detection.confidence, Confidence::High);
        assert_eq!(detection.reason, "Next.js build cache");
    }

    #[test]
    fn wrangler_state_needs_project_context_and_is_never_safe() {
        let env = KnownPaths::empty();
        assert!(
            JsFrameworkCache
                .detect(&ctx(".wrangler", Markers::empty(), &env))
                .is_none(),
            "a bare .wrangler directory stays unclaimed"
        );

        let detection = JsFrameworkCache
            .detect(&ctx(
                ".wrangler",
                Markers::PACKAGE_JSON | Markers::WRANGLER,
                &env,
            ))
            .expect("detection");
        assert_eq!(
            detection.cleanup,
            CleanupSafety::ProbablySafe,
            "local D1/KV state must never be marked Safe"
        );
    }

    #[test]
    fn dist_outside_a_js_project_is_not_claimed() {
        let env = KnownPaths::empty();
        assert!(JsBuildOutput
            .detect(&ctx("dist", Markers::empty(), &env))
            .is_none());
    }

    #[test]
    fn dist_inside_a_js_project_is_only_probably_safe() {
        let env = KnownPaths::empty();
        let detection = JsBuildOutput
            .detect(&ctx("dist", Markers::PACKAGE_JSON, &env))
            .expect("detection");
        assert_eq!(detection.cleanup, CleanupSafety::ProbablySafe);
        assert_eq!(detection.category, Category::BuildArtifact);
    }
}
