//! Safety behaviour of the cleanup engine.
//!
//! These are the most important tests in the project. A disk cleaner that is
//! occasionally wrong about which directory is disposable is worse than no disk
//! cleaner at all, so every claim the safety layer makes is asserted against a
//! real filesystem here.

mod support;

use std::path::PathBuf;

use bloatrail::analysis::{Category, Classifier, CleanupSafety};
use bloatrail::cleanup::executor::{ExecutionOptions, Executor, RemovalMethod};
use bloatrail::cleanup::planner::{CleanupPlan, CleanupTarget, TargetKind};
use bloatrail::platform::KnownPaths;
use support::Fixture;

fn plan_for(fixture: &Fixture) -> CleanupPlan {
    CleanupPlan::from_scan(&fixture.scan())
}

fn executor<'a>(
    root: &'a std::path::Path,
    known: &'a KnownPaths,
    classifier: &'a Classifier,
    dry_run: bool,
    limit: CleanupSafety,
) -> Executor<'a> {
    Executor::new(
        root,
        known,
        classifier,
        ExecutionOptions {
            dry_run,
            permanent: true,
            limit,
            excludes: bloatrail::pattern::ExcludeSet::default(),
        },
    )
}

#[test]
fn a_dry_run_touches_nothing_at_all() {
    let fixture = Fixture::new();
    fixture.rust_project("api", 4096);
    fixture.node_project("web", 8192);

    let plan = plan_for(&fixture);
    assert!(!plan.is_empty(), "the plan should have found something");

    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();
    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        true,
        CleanupSafety::Review,
    )
    .run(plan.selectable());

    assert!(report.dry_run);
    assert!(!report.removed.is_empty());
    assert!(report
        .removed
        .iter()
        .all(|removal| removal.method == RemovalMethod::Simulated));

    // Every single path the dry run "removed" must still be there.
    for removal in &report.removed {
        assert!(
            removal.path.exists(),
            "dry run removed `{}`",
            removal.path.display()
        );
    }
    assert!(fixture.join("api/target/debug/app").exists());
    assert!(fixture.join("web/node_modules/left-pad/index.js").exists());
}

#[test]
fn real_cleanup_removes_build_output_and_leaves_everything_else() {
    let fixture = Fixture::new();
    fixture.rust_project("api", 4096);
    fixture.write("api/.git/HEAD", b"ref: refs/heads/main\n");
    fixture.dir("api/.git/refs");
    fixture.file("api/.git/objects/pack/p.pack", 2048);
    fixture.file("docs/report.pdf", 1024);
    fixture.decoy_target("marketing", 2048);

    let plan = plan_for(&fixture);
    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();

    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        false,
        CleanupSafety::Safe,
    )
    .run(
        plan.selectable()
            .filter(|g| g.safety == CleanupSafety::Safe),
    );

    assert!(
        report.failures.is_empty(),
        "unexpected failures: {:?}",
        report.failures
    );
    assert!(!fixture.join("api/target").exists(), "build output goes");

    assert!(fixture.join("api/src/main.rs").exists(), "source stays");
    assert!(fixture.join("api/Cargo.toml").exists(), "manifest stays");
    assert!(fixture.join("api/.git").exists(), "git data stays");
    assert!(fixture.join("docs/report.pdf").exists(), "documents stay");
    assert!(
        fixture.join("marketing/target").exists(),
        "an unexplained `target` stays"
    );
}

#[test]
fn git_data_never_appears_in_a_plan() {
    let fixture = Fixture::new();
    fixture.rust_project("api", 1024);
    fixture.write("api/.git/HEAD", b"ref: refs/heads/main\n");
    fixture.dir("api/.git/refs");
    fixture.file("api/.git/objects/pack/p.pack", 16_384);

    let plan = plan_for(&fixture);

    for group in &plan.groups {
        assert_ne!(
            group.category,
            Category::GitData,
            "git data must never be offered for removal"
        );
    }
    assert!(
        plan.protected
            .iter()
            .any(|row| row.label == "Git repositories"),
        "git data should still be reported as protected"
    );
}

#[test]
fn a_target_outside_the_scan_root_is_refused() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    outside.rust_project("elsewhere", 1024);
    let stray = &outside;

    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();

    let mut group = bloatrail::cleanup::planner::CleanupGroup {
        index: Some(1),
        title: "Rust build artifacts".to_string(),
        safety: CleanupSafety::Safe,
        category: Category::BuildArtifact,
        technology: None,
        evidence: Vec::new(),
        regenerated_by: None,
        targets: Vec::new(),
        bytes: 1024,
        external: false,
    };
    group.targets.push(CleanupTarget {
        path: stray.join("elsewhere/target"),
        bytes: 1024,
        files: 1,
        kind: TargetKind::Directory,
        confidence: bloatrail::analysis::Confidence::High,
        detection: bloatrail::analysis::Detection::new(
            Category::BuildArtifact,
            bloatrail::analysis::Confidence::High,
            CleanupSafety::Safe,
            "Rust build artifacts",
        ),
    });

    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        false,
        CleanupSafety::Review,
    )
    .run([&group]);

    assert_eq!(report.refused_count(), 1);
    assert!(report.removed.is_empty());
    assert!(stray.join("elsewhere/target").exists());
}

#[test]
fn re_verification_stops_a_stale_plan_from_deleting_the_wrong_thing() {
    let fixture = Fixture::new();
    fixture.rust_project("api", 4096);

    let plan = plan_for(&fixture);
    assert!(!plan.is_empty());

    // Between planning and executing, the project stops being a Rust project —
    // exactly the situation the re-verification step exists for.
    std::fs::remove_file(fixture.join("api/Cargo.toml")).unwrap();
    std::fs::remove_file(fixture.join("api/Cargo.lock")).unwrap();

    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();
    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        false,
        CleanupSafety::Safe,
    )
    .run(plan.selectable());

    assert!(
        report.removed.is_empty(),
        "nothing should have been removed"
    );
    assert!(report.refused_count() >= 1);
    assert!(fixture.join("api/target/debug/app").exists());
}

#[test]
fn a_safety_limit_blocks_more_disruptive_groups() {
    let fixture = Fixture::new();
    fixture.write("py/pyproject.toml", b"[project]\nname='p'\n");
    fixture.write("py/.venv/pyvenv.cfg", b"home = /usr\n");
    fixture.file("py/.venv/lib/dep.py", 4096);
    fixture.file("py/__pycache__/m.pyc", 1024);

    let plan = plan_for(&fixture);
    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();

    // Running with a `Safe` limit must not remove the `ProbablySafe` virtualenv,
    // even though it was explicitly selected.
    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        false,
        CleanupSafety::Safe,
    )
    .run(plan.selectable());

    assert!(
        fixture.join("py/.venv/pyvenv.cfg").exists(),
        "a ProbablySafe group must be refused under a Safe limit"
    );
    assert!(
        !fixture.join("py/__pycache__").exists(),
        "the safe group went"
    );
    assert!(report.refused_count() >= 1);
}

#[test]
fn credential_directories_are_refused_even_when_asked_for_directly() {
    let fixture = Fixture::new();
    fixture.write(".ssh/id_ed25519", b"PRIVATE KEY\n");
    fixture.file(".ssh/target/junk.bin", 1024);

    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();

    let group = bloatrail::cleanup::planner::CleanupGroup {
        index: Some(1),
        title: "Rust build artifacts".to_string(),
        safety: CleanupSafety::Safe,
        category: Category::BuildArtifact,
        technology: None,
        evidence: Vec::new(),
        regenerated_by: None,
        targets: vec![CleanupTarget {
            path: fixture.join(".ssh/target"),
            bytes: 1024,
            files: 1,
            kind: TargetKind::Directory,
            confidence: bloatrail::analysis::Confidence::High,
            detection: bloatrail::analysis::Detection::new(
                Category::BuildArtifact,
                bloatrail::analysis::Confidence::High,
                CleanupSafety::Safe,
                "Rust build artifacts",
            ),
        }],
        bytes: 1024,
        external: false,
    };

    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        false,
        CleanupSafety::Review,
    )
    .run([&group]);

    assert_eq!(report.refused_count(), 1);
    assert!(fixture.join(".ssh/target").exists());
    assert!(fixture.join(".ssh/id_ed25519").exists());
}

#[test]
fn low_confidence_targets_are_refused_when_they_contain_secrets() {
    let fixture = Fixture::new();
    // A generic `cache` directory: Review-level confidence, so the contents are
    // inspected before anything happens to it.
    fixture.file("app/cache/blob.bin", 2048);
    fixture.write("app/cache/service-account.json", b"{\"key\":\"x\"}");

    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();

    let group = bloatrail::cleanup::planner::CleanupGroup {
        index: Some(1),
        title: "Cache directory".to_string(),
        safety: CleanupSafety::Review,
        category: Category::Cache,
        technology: None,
        evidence: Vec::new(),
        regenerated_by: None,
        targets: vec![CleanupTarget {
            path: fixture.join("app/cache"),
            bytes: 2048,
            files: 2,
            kind: TargetKind::Directory,
            confidence: bloatrail::analysis::Confidence::Medium,
            detection: bloatrail::analysis::Detection::new(
                Category::Cache,
                bloatrail::analysis::Confidence::Medium,
                CleanupSafety::Review,
                "Cache directory",
            ),
        }],
        bytes: 2048,
        external: false,
    };

    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        false,
        CleanupSafety::Review,
    )
    .run([&group]);

    assert_eq!(report.refused_count(), 1);
    assert!(fixture.join("app/cache/service-account.json").exists());
}

#[test]
fn nothing_is_selectable_in_a_directory_with_no_developer_storage() {
    let fixture = Fixture::new();
    fixture.file("photos/a.jpg", 4096);
    fixture.file("notes/b.txt", 512);

    let plan = plan_for(&fixture);
    assert!(plan.is_empty());
    assert_eq!(plan.automatically_safe(), bloatrail::ByteSize::ZERO);
}

#[test]
fn plan_totals_match_the_sum_of_their_groups() {
    let fixture = Fixture::new();
    fixture.rust_project("a", 4096);
    fixture.node_project("b", 8192);
    fixture.write("py/pyproject.toml", b"[project]\nname='p'\n");
    fixture.file("py/__pycache__/m.pyc", 1024);

    let plan = plan_for(&fixture);
    let summed: u64 = plan
        .groups
        .iter()
        .filter(|g| g.safety.is_deletable())
        .map(|g| g.bytes)
        .sum();
    assert_eq!(plan.recoverable().as_u64(), summed);
    assert!(plan.automatically_safe() <= plan.recoverable());
}

#[test]
fn every_selectable_group_has_a_unique_number() {
    let fixture = Fixture::new();
    fixture.rust_project("a", 4096);
    fixture.node_project("b", 8192);

    let plan = plan_for(&fixture);
    let mut seen: Vec<usize> = plan.selectable().filter_map(|g| g.index).collect();
    let count = seen.len();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), count, "selection numbers must be unique");
    assert_eq!(seen.first().copied(), Some(1), "numbering starts at 1");

    for index in &seen {
        assert!(plan.group_by_index(*index).is_some());
    }
    assert!(plan.group_by_index(9_999).is_none());
}

#[test]
fn unselectable_groups_are_never_executed_even_if_passed_in() {
    let fixture = Fixture::new();
    fixture.rust_project("api", 4096);

    let mut plan = plan_for(&fixture);
    for group in &mut plan.groups {
        group.index = None;
    }

    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();
    let report = executor(
        fixture.path(),
        &known,
        &classifier,
        false,
        CleanupSafety::Review,
    )
    .run(plan.groups.iter());

    assert!(report.removed.is_empty());
    assert!(fixture.join("api/target").exists());
}

#[test]
fn relative_and_traversal_paths_are_refused() {
    let fixture = Fixture::new();
    let known = KnownPaths::empty();
    let classifier = Classifier::with_default_detectors();

    for path in [
        PathBuf::from("relative/target"),
        fixture.join("a/../../target"),
    ] {
        let group = bloatrail::cleanup::planner::CleanupGroup {
            index: Some(1),
            title: "Rust build artifacts".to_string(),
            safety: CleanupSafety::Safe,
            category: Category::BuildArtifact,
            technology: None,
            evidence: Vec::new(),
            regenerated_by: None,
            targets: vec![CleanupTarget {
                path: path.clone(),
                bytes: 1,
                files: 1,
                kind: TargetKind::Directory,
                confidence: bloatrail::analysis::Confidence::High,
                detection: bloatrail::analysis::Detection::new(
                    Category::BuildArtifact,
                    bloatrail::analysis::Confidence::High,
                    CleanupSafety::Safe,
                    "Rust build artifacts",
                ),
            }],
            bytes: 1,
            external: false,
        };

        let report = executor(
            fixture.path(),
            &known,
            &classifier,
            false,
            CleanupSafety::Review,
        )
        .run([&group]);
        assert_eq!(
            report.refused_count(),
            1,
            "`{}` should have been refused",
            path.display()
        );
    }
}
