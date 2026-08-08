//! Traversal correctness against a real filesystem.

mod support;

use bloatrail::pattern::ExcludeSet;
use support::{node_named, Fixture};

#[test]
fn sizes_and_counts_aggregate_up_the_tree() {
    let fixture = Fixture::new();
    fixture.file("a/one.bin", 1000);
    fixture.file("a/two.bin", 2000);
    fixture.file("a/nested/three.bin", 3000);
    fixture.file("b/four.bin", 4000);

    let scan = fixture.scan();

    assert_eq!(scan.totals.bytes, 10_000);
    assert_eq!(scan.totals.files, 4);
    // root + a + a/nested + b
    assert_eq!(scan.totals.dirs, 4);

    let a = node_named(&scan, "a").expect("a");
    assert_eq!(a.total.bytes, 6_000);
    assert_eq!(a.own.bytes, 3_000, "own counts only direct children");
}

#[test]
fn children_are_ordered_largest_first() {
    let fixture = Fixture::new();
    fixture.file("small/x.bin", 10);
    fixture.file("large/x.bin", 10_000);
    fixture.file("medium/x.bin", 500);

    let scan = fixture.scan();
    let root = scan.tree.node(scan.tree.root());
    let names: Vec<&str> = root
        .children
        .iter()
        .map(|id| &*scan.tree.node(*id).name)
        .collect();
    assert_eq!(names, vec!["large", "medium", "small"]);
}

#[test]
fn exclusion_by_name_removes_a_directory_from_the_totals() {
    let fixture = Fixture::new();
    fixture.file("keep/a.bin", 1000);
    fixture.file("skipme/b.bin", 5000);

    let scan = fixture.scan_with(|options| {
        options.excludes = ExcludeSet::new(["skipme"]);
    });

    assert_eq!(scan.totals.bytes, 1000);
    assert!(node_named(&scan, "skipme").is_none());
}

#[test]
fn exclusion_by_path_removes_only_the_named_location() {
    let fixture = Fixture::new();
    fixture.file("one/target/a.bin", 1000);
    fixture.file("two/target/b.bin", 2000);

    let excluded = fixture.join("one/target");
    let scan = fixture.scan_with(|options| {
        options.excludes = ExcludeSet::new([excluded.to_string_lossy().to_string()]);
    });

    assert_eq!(scan.totals.bytes, 2000);
    assert!(node_named(&scan, "two/target").is_some());
}

#[test]
fn exclusion_patterns_also_apply_to_files() {
    let fixture = Fixture::new();
    fixture.file("data/keep.bin", 1000);
    fixture.file("data/skip.iso", 9000);

    let scan = fixture.scan_with(|options| {
        options.excludes = ExcludeSet::new(["*.iso"]);
    });
    assert_eq!(scan.totals.bytes, 1000);
}

#[test]
fn ordinary_dot_directories_are_skipped_unless_asked_for() {
    let fixture = Fixture::new();
    fixture.file("visible/a.bin", 1000);
    fixture.file(".private/secret.bin", 5000);

    let default = fixture.scan();
    assert_eq!(default.totals.bytes, 1000);

    let all = fixture.scan_with(|options| options.include_hidden = true);
    assert_eq!(all.totals.bytes, 6000);
}

#[test]
fn hidden_files_are_always_counted() {
    let fixture = Fixture::new();
    fixture.file("visible.bin", 1000);
    fixture.file(".hidden-but-huge.bin", 5000);

    // `--include-hidden` governs directories. A dot-file still occupies disk,
    // and silently omitting it would make the totals wrong.
    let scan = fixture.scan();
    assert_eq!(scan.totals.bytes, 6000);
    assert_eq!(scan.totals.files, 2);
}

#[test]
fn very_deep_trees_are_bounded_rather_than_fatal() {
    let fixture = Fixture::new();

    // Deeper than the traversal limit. Without a cap this recursion would
    // overflow the stack and abort the process instead of returning a result.
    let depth = usize::from(bloatrail::scanner::MAX_TRAVERSAL_DEPTH) + 40;
    let mut relative = String::from("deep");
    for _ in 0..depth {
        relative.push_str("/d");
    }
    fixture.file(&format!("{relative}/leaf.bin"), 256);
    fixture.file("shallow.bin", 1000);

    let scan = fixture.scan();
    assert!(
        scan.totals.bytes >= 1000,
        "the shallow part must be counted"
    );
    assert!(
        scan.skipped
            .iter()
            .any(|s| s.reason == bloatrail::scanner::SkipReason::TooDeep),
        "exceeding the depth limit must be reported, not silently ignored"
    );
}

#[test]
fn developer_dot_directories_are_always_traversed() {
    let fixture = Fixture::new();
    fixture.write("app/package.json", b"{}");
    fixture.file("app/.next/cache/chunk.pack", 4096);
    fixture.file("app/src/index.js", 100);

    let scan = fixture.scan();
    assert!(
        node_named(&scan, "app/.next").is_some(),
        "`.next` must be found without --include-hidden"
    );
    // 4096 (.next) + 100 (index.js) + 2 (package.json)
    assert_eq!(scan.totals.bytes, 4198);
}

#[test]
fn depth_limiting_reduces_retained_nodes_but_not_the_totals() {
    let fixture = Fixture::new();
    fixture.file("a/b/c/d/deep.bin", 4096);

    let full = fixture.scan();
    let shallow = fixture.scan_with(|options| options.max_depth = Some(2));

    assert_eq!(full.totals.bytes, shallow.totals.bytes);
    assert_eq!(full.totals.files, shallow.totals.files);
    assert!(
        shallow.tree.len() < full.tree.len(),
        "a depth limit must retain fewer nodes"
    );
    assert!(node_named(&shallow, "a/b").expect("a/b").truncated);
}

#[test]
fn the_largest_files_list_is_bounded_and_ordered() {
    let fixture = Fixture::new();
    for index in 0..20 {
        fixture.file(&format!("f{index}.bin"), (index + 1) * 100);
    }

    let scan = fixture.scan_with(|options| options.top_files = 5);
    assert_eq!(scan.largest_files.len(), 5);
    assert_eq!(scan.largest_files[0].size, 2000);
    assert!(scan
        .largest_files
        .windows(2)
        .all(|pair| pair[0].size >= pair[1].size));
}

#[test]
fn an_empty_directory_scans_cleanly() {
    let fixture = Fixture::new();
    let scan = fixture.scan();
    assert_eq!(scan.totals.bytes, 0);
    assert_eq!(scan.totals.files, 0);
    assert_eq!(scan.totals.dirs, 1);
    assert_eq!(scan.skipped_count, 0);
}

#[test]
fn scanning_a_file_rather_than_a_directory_is_an_error() {
    let fixture = Fixture::new();
    let file = fixture.file("a.bin", 10);

    let classifier = bloatrail::analysis::Classifier::with_default_detectors();
    let known = bloatrail::platform::KnownPaths::empty();
    let options = bloatrail::scanner::ScanOptions::new(file);
    let error = bloatrail::scanner::scan(&options, &classifier, &known).unwrap_err();
    assert!(matches!(error, bloatrail::Error::NotADirectory(_)));
}

#[test]
fn a_missing_root_is_reported_rather_than_panicking() {
    let fixture = Fixture::new();
    let missing = fixture.join("nope/not/here");

    let classifier = bloatrail::analysis::Classifier::with_default_detectors();
    let known = bloatrail::platform::KnownPaths::empty();
    let options = bloatrail::scanner::ScanOptions::new(missing);
    let error = bloatrail::scanner::scan(&options, &classifier, &known).unwrap_err();
    assert!(matches!(error, bloatrail::Error::NotFound(_)));
}

#[test]
fn thread_count_does_not_change_the_result() {
    let fixture = Fixture::new();
    for index in 0..8 {
        fixture.file(&format!("d{index}/a/b/file.bin"), 512 * (index + 1));
    }

    let single = fixture.scan_with(|options| options.threads = Some(1));
    let many = fixture.scan_with(|options| options.threads = Some(8));

    assert_eq!(single.totals.bytes, many.totals.bytes);
    assert_eq!(single.totals.files, many.totals.files);
    assert_eq!(single.totals.dirs, many.totals.dirs);
    assert_eq!(single.tree.len(), many.tree.len());
}

#[cfg(unix)]
mod unix_only {
    use super::*;

    #[test]
    fn broken_symlinks_do_not_abort_the_scan() {
        let fixture = Fixture::new();
        fixture.file("real.bin", 1000);
        std::os::unix::fs::symlink(fixture.join("gone.bin"), fixture.join("dangling")).unwrap();

        let scan = fixture.scan();
        assert_eq!(scan.totals.files, 2, "the link itself is still an entry");
        assert!(scan.totals.bytes >= 1000);
    }

    #[test]
    fn symlinked_directories_are_not_followed_by_default() {
        let fixture = Fixture::new();
        fixture.file("real/data.bin", 4096);
        std::os::unix::fs::symlink(fixture.join("real"), fixture.join("alias")).unwrap();

        let scan = fixture.scan();

        // The link itself is counted, and a symlink's own size is the length of
        // the path it stores, so the total is 4096 plus a few dozen bytes. What
        // must not happen is the target being counted twice.
        assert!(
            scan.totals.bytes >= 4096,
            "the real data should still be counted"
        );
        assert!(
            scan.totals.bytes < 2 * 4096,
            "following the link would double-count the data, got {}",
            scan.totals.bytes
        );
        assert!(
            node_named(&scan, "alias").is_none(),
            "a symlinked directory must not become a node in the tree"
        );
    }

    #[test]
    fn symlink_loops_terminate_when_following_is_enabled() {
        let fixture = Fixture::new();
        fixture.file("a/data.bin", 1024);
        std::os::unix::fs::symlink(fixture.path(), fixture.join("a/loop")).unwrap();

        let scan = fixture.scan_with(|options| options.follow_symlinks = true);
        assert!(scan.totals.bytes >= 1024);
        assert!(scan.tree.len() < 1000, "the loop must be broken");
    }

    #[test]
    fn hard_links_are_counted_once() {
        let fixture = Fixture::new();
        let original = fixture.file("original.bin", 8192);
        std::fs::hard_link(&original, fixture.join("linked.bin")).unwrap();

        let scan = fixture.scan();
        assert_eq!(
            scan.totals.bytes, 8192,
            "a hard link is the same bytes under another name"
        );
    }

    #[test]
    fn unreadable_directories_are_skipped_and_reported() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        fixture.file("open/a.bin", 1000);
        let locked = fixture.dir("locked");
        fixture.file("locked/secret.bin", 5000);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let scan = fixture.scan();

        // Restore permissions so the fixture can clean itself up.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(scan.totals.bytes, 1000, "the readable part still counted");
        assert!(scan.skipped_count >= 1, "the skip must be reported");
        assert!(scan
            .skipped
            .iter()
            .any(|s| s.reason == bloatrail::scanner::SkipReason::PermissionDenied));
    }
}
