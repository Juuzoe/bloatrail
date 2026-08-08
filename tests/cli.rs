//! End-to-end tests that run the real `bloatrail` binary.
//!
//! These check the parts no library test can: exit codes, stdout shape,
//! `--json` being machine-readable, and — most importantly — that a `clean`
//! invocation from a non-interactive shell cannot delete anything.

mod support;

use std::path::Path;
use std::process::{Command, Output};

use support::Fixture;

/// Run the binary with a private state directory so tests never touch the
/// developer's real scan history or configuration.
fn run(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bloatrail"))
        .args(args)
        .env("BLOATRAIL_HOME", state)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run bloatrail")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn sample(fixture: &Fixture) {
    fixture.rust_project("api", 4096);
    fixture.node_project("web", 8192);
    fixture.file("media/clip.mp4", 2048);
    fixture.write("api/.git/HEAD", b"ref: refs/heads/main\n");
    fixture.dir("api/.git/refs");
    fixture.file("api/.git/objects/pack/p.pack", 1024);
}

#[test]
fn version_and_help_are_available() {
    let state = Fixture::new();

    let version = run(state.path(), &["--version"]);
    assert!(version.status.success());
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));

    let help = run(state.path(), &["--help"]);
    assert!(help.status.success());
    let text = stdout(&help);
    for command in [
        "scan",
        "tree",
        "clean",
        "explain",
        "largest",
        "duplicates",
        "doctor",
        "diff",
    ] {
        assert!(
            text.contains(command),
            "`{command}` should appear in --help"
        );
    }
}

#[test]
fn running_with_no_arguments_prints_help_and_fails() {
    let state = Fixture::new();
    let output = run(state.path(), &[]);
    assert!(!output.status.success());
}

#[test]
fn scan_reports_the_developer_categories() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &["scan", &fixture.path().to_string_lossy(), "--no-progress"],
    );
    assert!(output.status.success());

    let text = stdout(&output);
    assert!(text.contains("BLOATRAIL"));
    assert!(text.contains("Storage breakdown"));
    assert!(text.contains("Build artifacts"));
    assert!(text.contains("Developer dependencies"));
    assert!(text.contains("Git repositories"));
}

#[test]
fn no_color_output_contains_no_escape_sequences() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "scan",
            &fixture.path().to_string_lossy(),
            "--no-color",
            "--no-progress",
        ],
    );
    assert!(!stdout(&output).contains('\u{1b}'));
}

#[test]
fn scan_json_is_machine_readable() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &["scan", &fixture.path().to_string_lossy(), "--json"],
    );
    assert!(output.status.success());

    let document: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("output should be valid JSON");

    assert_eq!(document["schema_version"], 1);
    assert!(document["totals"]["bytes"].as_u64().unwrap() > 0);
    assert!(document["categories"].as_array().unwrap().len() > 1);
    assert!(document["tree"]["path"].is_string());
}

#[test]
fn json_output_carries_no_progress_or_colour() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &["scan", &fixture.path().to_string_lossy(), "--json"],
    );
    let text = stdout(&output);
    assert!(!text.contains('\u{1b}'));
    assert!(text.starts_with('{'));
}

#[test]
fn clean_from_a_non_interactive_shell_cannot_delete_anything() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    // No --yes, no selection, stdin is not a terminal: this must be a dry run.
    let output = run(
        state.path(),
        &["clean", &fixture.path().to_string_lossy(), "--no-progress"],
    );
    assert!(output.status.success());

    let text = stdout(&output);
    assert!(text.contains("Potential cleanup"));
    assert!(text.contains("Dry run"));

    assert!(fixture.join("api/target/debug/app").exists());
    assert!(fixture.join("web/node_modules/left-pad/index.js").exists());
    assert!(fixture.join("api/src/main.rs").exists());
}

#[test]
fn clean_dry_run_is_explicit_about_changing_nothing() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "clean",
            &fixture.path().to_string_lossy(),
            "--dry-run",
            "--all",
            "--no-progress",
        ],
    );
    assert!(output.status.success());
    assert!(stdout(&output).contains("nothing was modified"));
    assert!(fixture.join("api/target").exists());
    assert!(fixture.join("web/node_modules").exists());
}

#[test]
fn clean_removes_only_what_was_selected() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "clean",
            &fixture.path().to_string_lossy(),
            "--yes",
            "--safe",
            "--permanent",
            "--no-progress",
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(!fixture.join("api/target").exists());
    assert!(!fixture.join("web/node_modules").exists());
    assert!(fixture.join("api/src/main.rs").exists());
    assert!(fixture.join("api/.git/objects/pack/p.pack").exists());
    assert!(fixture.join("media/clip.mp4").exists());
}

#[test]
fn an_unparseable_selection_is_an_error_not_a_silent_fallback() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "clean",
            &fixture.path().to_string_lossy(),
            "--select",
            "banana",
            "--yes",
            "--permanent",
            "--no-progress",
        ],
    );

    assert!(!output.status.success(), "a typo must not be interpreted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--select"), "stderr was: {stderr}");

    // And nothing was touched.
    assert!(fixture.join("api/target").exists());
    assert!(fixture.join("web/node_modules").exists());
}

#[test]
fn explain_names_the_evidence_it_used() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let target = fixture.join("api/target");
    let output = run(
        state.path(),
        &["explain", &target.to_string_lossy(), "--no-progress"],
    );
    assert!(output.status.success());

    let text = stdout(&output);
    assert!(text.contains("Rust build artifacts"));
    assert!(text.contains("Cargo.toml"));
    assert!(text.contains("SAFE"));
    assert!(text.contains("cargo build"));
}

#[test]
fn explain_is_cautious_about_a_directory_it_cannot_identify() {
    let fixture = Fixture::new();
    fixture.decoy_target("marketing", 2048);
    let state = Fixture::new();

    let target = fixture.join("marketing/target");
    let output = run(
        state.path(),
        &["explain", &target.to_string_lossy(), "--no-progress"],
    );
    assert!(output.status.success());

    let text = stdout(&output);
    assert!(text.contains("no project context"));
    assert!(text.contains("REVIEW"));
    assert!(
        !text.contains("Remove it with"),
        "Bloatrail must not suggest removing something it could not identify"
    );
}

#[test]
fn explain_protects_sensitive_files() {
    let fixture = Fixture::new();
    let key = fixture.write("id_ed25519", b"PRIVATE KEY\n");
    let state = Fixture::new();

    let output = run(state.path(), &["explain", &key.to_string_lossy()]);
    assert!(output.status.success());

    let text = stdout(&output);
    assert!(text.contains("private key"));
    assert!(text.contains("DO NOT AUTO DELETE"));
}

#[test]
fn largest_ranks_directories_and_files() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "largest",
            &fixture.path().to_string_lossy(),
            "--no-progress",
            "-n",
            "5",
        ],
    );
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Largest directories"));
    assert!(text.contains("Largest files"));

    let files_only = run(
        state.path(),
        &[
            "largest",
            &fixture.path().to_string_lossy(),
            "--files",
            "--no-progress",
        ],
    );
    let text = stdout(&files_only);
    assert!(text.contains("Largest files"));
    assert!(!text.contains("Largest directories"));
}

#[test]
fn duplicates_finds_identical_files_and_refuses_to_act() {
    let fixture = Fixture::new();
    let payload = vec![7u8; 64 * 1024];
    fixture.write("a/one.bin", &payload);
    fixture.write("b/two.bin", &payload);
    fixture.file("c/unique.bin", 64 * 1024 - 1);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "duplicates",
            &fixture.path().to_string_lossy(),
            "--min-file-size",
            "1KB",
            "--no-progress",
        ],
    );
    assert!(output.status.success());

    let text = stdout(&output);
    assert!(text.contains("Group 1"));
    assert!(text.contains("one.bin"));
    assert!(text.contains("two.bin"));
    assert!(!text.contains("unique.bin"));
    assert!(text.contains("never deletes duplicates automatically"));
}

#[test]
fn doctor_runs_without_changing_anything() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let before = fixture.scan().totals.bytes;
    let output = run(
        state.path(),
        &[
            "doctor",
            &fixture.path().to_string_lossy(),
            "--no-docker",
            "--no-progress",
        ],
    );
    assert!(output.status.success());
    assert!(stdout(&output).contains("Bloatrail Doctor"));
    assert_eq!(fixture.scan().totals.bytes, before);
}

#[test]
fn diff_needs_a_previous_scan_and_then_reports_growth() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();
    let root = fixture.path().to_string_lossy().into_owned();

    let first = run(state.path(), &["diff", &root, "--no-progress"]);
    assert!(
        !first.status.success(),
        "there is nothing to compare against yet"
    );

    run(state.path(), &["scan", &root, "--no-progress"]);
    fixture.file("api/target/debug/extra.bin", 100_000);

    let second = run(state.path(), &["diff", &root, "--no-progress"]);
    assert!(second.status.success());
    let text = stdout(&second);
    assert!(text.contains("Disk change since last scan"));
    assert!(text.contains("Net change"));
    assert!(text.contains('+'));
}

#[test]
fn tree_annotates_what_it_finds() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "tree",
            &fixture.path().to_string_lossy(),
            "--depth",
            "3",
            "--no-progress",
        ],
    );
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("node_modules"));
    assert!(text.contains("npm dependencies"));
    assert!(text.contains("Rust build artifacts"));
}

#[test]
fn ascii_mode_avoids_box_drawing_characters() {
    let fixture = Fixture::new();
    sample(&fixture);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "tree",
            &fixture.path().to_string_lossy(),
            "--ascii",
            "--no-progress",
        ],
    );
    let text = stdout(&output);
    assert!(!text.contains('├'));
    assert!(!text.contains('└'));
    assert!(text.contains("|-- ") || text.contains("`-- "));
}

#[test]
fn a_missing_path_fails_with_a_readable_message() {
    let state = Fixture::new();
    let output = run(state.path(), &["scan", "/definitely/not/a/real/path/xyzzy"]);
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bloatrail:"));
    assert!(stderr.contains("does not exist"));
}

#[test]
fn exclusions_reach_the_scanner_from_the_command_line() {
    let fixture = Fixture::new();
    fixture.file("keep/a.bin", 1000);
    fixture.file("drop/b.bin", 100_000);
    let state = Fixture::new();

    let output = run(
        state.path(),
        &[
            "scan",
            &fixture.path().to_string_lossy(),
            "--exclude",
            "drop",
            "--json",
        ],
    );
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(document["totals"]["bytes"].as_u64().unwrap(), 1000);
}

#[test]
fn config_example_is_printed_and_describes_the_real_path() {
    let state = Fixture::new();

    let output = run(state.path(), &["config", "--example"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("min_size"));

    let path = run(state.path(), &["config", "--path"]);
    assert!(path.status.success());
    assert!(stdout(&path).contains("config.toml"));
}
