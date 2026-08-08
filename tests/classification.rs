//! Classification against a real filesystem.
//!
//! The central claim these tests defend is that Bloatrail classifies by
//! *context*, not by name. The same directory name must produce different
//! conclusions depending on what sits next to it, and an unsupported directory
//! must never inherit the confidence of a supported one.

mod support;

use bloatrail::analysis::{Category, CleanupSafety, Confidence, Technology};
use support::{detection_for, Fixture};

#[test]
fn target_next_to_a_cargo_manifest_is_rust_build_output() {
    let fixture = Fixture::new();
    fixture.rust_project("backend", 4096);

    let scan = fixture.scan();
    let detection = detection_for(&scan, "backend/target").expect("target should be classified");

    assert_eq!(detection.category, Category::BuildArtifact);
    assert_eq!(detection.technology, Some(Technology::Rust));
    assert_eq!(detection.confidence, Confidence::High);
    assert_eq!(detection.cleanup, CleanupSafety::Safe);
    assert_eq!(detection.regenerated_by.as_deref(), Some("cargo build"));
    assert!(
        detection
            .evidence
            .iter()
            .any(|line| line.contains("Cargo.toml")),
        "the explanation must name the evidence it used"
    );
}

#[test]
fn target_without_a_project_is_not_treated_the_same_way() {
    let fixture = Fixture::new();
    fixture.decoy_target("random-folder", 4096);

    let scan = fixture.scan();
    let detection =
        detection_for(&scan, "random-folder/target").expect("the directory should be described");

    assert_ne!(
        detection.category,
        Category::BuildArtifact,
        "a bare `target` must not be called build output"
    );
    assert_eq!(detection.confidence, Confidence::Low);
    assert_ne!(detection.cleanup, CleanupSafety::Safe);
    assert!(!detection.cleanup.is_auto_selectable());
}

#[test]
fn the_same_name_in_two_projects_gets_two_different_answers() {
    let fixture = Fixture::new();
    fixture.rust_project("rusty", 2048);
    fixture.decoy_target("notrusty", 2048);

    let scan = fixture.scan();
    let rust = detection_for(&scan, "rusty/target").expect("rust target");
    let decoy = detection_for(&scan, "notrusty/target").expect("decoy target");

    assert_ne!(rust.category, decoy.category);
    assert!(rust.confidence > decoy.confidence);
    assert!(
        rust.cleanup < decoy.cleanup,
        "the decoy must be more cautious"
    );
}

#[test]
fn maven_and_cargo_both_use_target_and_are_told_apart() {
    let fixture = Fixture::new();
    fixture.rust_project("rusty", 1024);
    fixture.write("javaish/pom.xml", b"<project/>");
    fixture.file("javaish/target/classes/App.class", 1024);

    let scan = fixture.scan();
    let rust = detection_for(&scan, "rusty/target").expect("rust target");
    let maven = detection_for(&scan, "javaish/target").expect("maven target");

    assert_eq!(rust.technology, Some(Technology::Rust));
    assert_eq!(maven.technology, Some(Technology::Maven));
    assert_eq!(maven.cleanup, CleanupSafety::Safe);
}

#[test]
fn node_modules_is_recognised_and_the_package_manager_is_inferred() {
    let fixture = Fixture::new();
    fixture.write("app/package.json", b"{}");
    fixture.write("app/pnpm-lock.yaml", b"lockfileVersion: 9\n");
    fixture.file("app/node_modules/dep/index.js", 2048);

    let scan = fixture.scan();
    let detection = detection_for(&scan, "app/node_modules").expect("node_modules");

    assert_eq!(detection.category, Category::Dependency);
    assert_eq!(detection.cleanup, CleanupSafety::Safe);
    assert_eq!(detection.reason, "pnpm dependencies");
    assert_eq!(detection.regenerated_by.as_deref(), Some("pnpm install"));
}

#[test]
fn build_directories_resolve_through_the_surrounding_build_system() {
    let fixture = Fixture::new();

    fixture.write("gradle-app/build.gradle.kts", b"plugins {}\n");
    fixture.file("gradle-app/build/libs/app.jar", 1024);

    fixture.write("cmake-app/CMakeLists.txt", b"project(app)\n");
    fixture.file("cmake-app/build/CMakeCache.txt", 1024);

    fixture.file("plain/build/whatever.dat", 1024);

    let scan = fixture.scan();

    let gradle = detection_for(&scan, "gradle-app/build").expect("gradle build");
    assert_eq!(gradle.technology, Some(Technology::Gradle));
    assert_eq!(gradle.cleanup, CleanupSafety::Safe);

    let cmake = detection_for(&scan, "cmake-app/build").expect("cmake build");
    assert_eq!(cmake.technology, Some(Technology::Cpp));
    assert_eq!(
        cmake.cleanup,
        CleanupSafety::ProbablySafe,
        "reconfiguring a native build tree is not free"
    );

    assert!(
        detection_for(&scan, "plain/build").is_none(),
        "a `build` directory with no build system nearby is just a directory"
    );
}

#[test]
fn dotnet_output_needs_a_project_file() {
    let fixture = Fixture::new();
    fixture.write("svc/Svc.csproj", b"<Project/>");
    fixture.file("svc/bin/Debug/Svc.dll", 4096);
    fixture.file("svc/obj/project.assets.json", 1024);
    fixture.file("scripts/bin/helper.sh", 512);

    let scan = fixture.scan();

    let bin = detection_for(&scan, "svc/bin").expect("bin");
    assert_eq!(bin.technology, Some(Technology::DotNet));
    assert_eq!(bin.cleanup, CleanupSafety::Safe);
    assert!(detection_for(&scan, "svc/obj").is_some());

    assert!(
        detection_for(&scan, "scripts/bin").is_none(),
        "a `bin` directory of scripts is not .NET output"
    );
}

#[test]
fn git_directories_are_measured_but_never_offered() {
    let fixture = Fixture::new();
    fixture.rust_project("repo", 1024);
    fixture.write("repo/.git/HEAD", b"ref: refs/heads/main\n");
    fixture.dir("repo/.git/refs/heads");
    fixture.file("repo/.git/objects/pack/pack-1.pack", 8192);

    let scan = fixture.scan();
    let detection = detection_for(&scan, "repo/.git").expect(".git should be classified");

    assert_eq!(detection.category, Category::GitData);
    assert_eq!(detection.cleanup, CleanupSafety::NeverDelete);
    assert_eq!(
        detection.confidence,
        Confidence::Certain,
        "HEAD + objects/ + refs/ is unambiguous"
    );
    assert!(!detection.cleanup.is_deletable());
    assert!(scan.categories.bytes(Category::GitData) >= 8192);
}

#[test]
fn python_caches_are_safe_but_virtualenvs_are_not() {
    let fixture = Fixture::new();
    fixture.write("py/pyproject.toml", b"[project]\nname='p'\n");
    fixture.file("py/__pycache__/mod.cpython-312.pyc", 2048);
    fixture.write("py/.venv/pyvenv.cfg", b"home = /usr\n");
    fixture.file("py/.venv/lib/site-packages/dep/__init__.py", 4096);

    let scan = fixture.scan();

    let cache = detection_for(&scan, "py/__pycache__").expect("__pycache__");
    assert_eq!(cache.cleanup, CleanupSafety::Safe);

    let venv = detection_for(&scan, "py/.venv").expect(".venv");
    assert_eq!(venv.category, Category::Dependency);
    assert_eq!(
        venv.cleanup,
        CleanupSafety::ProbablySafe,
        "deleting a virtualenv is more disruptive than deleting bytecode"
    );
    assert_eq!(venv.confidence, Confidence::Certain);
}

#[test]
fn collapsed_directories_keep_exact_sizes_without_retaining_children() {
    let fixture = Fixture::new();
    fixture.write("app/package.json", b"{}");
    for index in 0..12 {
        fixture.file(&format!("app/node_modules/dep{index}/index.js"), 1024);
    }

    let scan = fixture.scan();
    let node = support::node_named(&scan, "app/node_modules").expect("node_modules");

    assert_eq!(node.total.bytes, 12 * 1024, "sizes must remain exact");
    assert_eq!(node.total.files, 12);
    assert!(node.truncated, "children should not be retained");
    assert!(node.children.is_empty());
}

#[test]
fn the_scan_root_is_never_collapsed_so_it_can_be_inspected() {
    let fixture = Fixture::new();
    fixture.write("app/package.json", b"{}");
    fixture.file("app/node_modules/a/index.js", 512);
    fixture.file("app/node_modules/b/index.js", 512);

    // Pointing the scan at `node_modules` itself must still show what is inside.
    let scan = fixture.scan_path("app/node_modules");
    let root = scan.tree.node(scan.tree.root());
    assert!(
        !root.children.is_empty(),
        "the scan root must always be explorable"
    );
    assert_eq!(root.total.bytes, 1024);
}

#[test]
fn new_dot_directory_detectors_fire_on_default_scans() {
    // Regression: a detector whose trigger names a dot-directory is dead code
    // unless the walker traverses that directory without --include-hidden.
    let fixture = Fixture::new();
    fixture.write("zig-app/build.zig", b"const std = @import(\"std\");\n");
    fixture.file("zig-app/.zig-cache/o/artifact.o", 2048);
    fixture.write("worker/package.json", b"{}");
    fixture.write("worker/wrangler.toml", b"name = \"w\"\n");
    fixture.file("worker/.wrangler/state/d1/db.sqlite", 4096);

    let scan = fixture.scan();

    let zig = detection_for(&scan, "zig-app/.zig-cache").expect(".zig-cache must be reachable");
    assert_eq!(zig.technology, Some(Technology::Zig));
    assert_eq!(zig.confidence, Confidence::High);

    let wrangler = detection_for(&scan, "worker/.wrangler").expect(".wrangler must be reachable");
    assert_eq!(
        wrangler.cleanup,
        CleanupSafety::ProbablySafe,
        "local dev state must never be Safe"
    );
}

#[test]
fn unreadable_stub_directories_are_marked_truncated() {
    // The doctor's empty-directory finding filters on `truncated`, so a stub
    // for an unreadable directory must never look like a verified-empty one.
    // Cross-platform proxy: the TooDeep stub takes the same path.
    let fixture = Fixture::new();
    let depth = usize::from(bloatrail::scanner::MAX_TRAVERSAL_DEPTH) + 5;
    let mut relative = String::from("deep");
    for _ in 0..depth {
        relative.push_str("/d");
    }
    fixture.file(&format!("{relative}/leaf.bin"), 64);

    let scan = fixture.scan();
    let stubs = scan
        .tree
        .iter()
        .filter(|(_, node)| node.total.files == 0 && node.children.is_empty())
        .count();
    let untruncated_stubs = scan
        .tree
        .iter()
        .filter(|(_, node)| node.total.files == 0 && node.children.is_empty() && !node.truncated)
        .count();
    assert!(stubs > 0, "the depth cap should have produced a stub");
    assert_eq!(
        untruncated_stubs, 0,
        "a zero-file leaf the walker did not fully read must carry `truncated`"
    );
}

#[test]
fn category_totals_add_up_to_the_scanned_total() {
    let fixture = Fixture::new();
    fixture.rust_project("a", 4096);
    fixture.node_project("b", 8192);
    fixture.file("media/clip.mp4", 2048);
    fixture.file("docs/report.pdf", 1024);

    let scan = fixture.scan();
    assert_eq!(
        scan.categories.total_bytes(),
        scan.totals.bytes,
        "every byte must be attributed to exactly one category"
    );
    assert!(scan.categories.bytes(bloatrail::analysis::Category::Video) >= 2048);
}
