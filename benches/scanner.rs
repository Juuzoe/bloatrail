//! Scanner throughput benchmarks.
//!
//! These build a synthetic project tree in a temporary directory and measure the
//! full pipeline: traversal, classification, aggregation and the largest-files
//! heap. The tree is deliberately shaped like a developer machine — a handful of
//! projects, each with a `node_modules` and a `target` — because that is the
//! workload the collapse optimisation is designed for.
//!
//! Run with:
//!
//! ```text
//! cargo bench --bench scanner
//! ```
//!
//! Numbers are machine-specific and are not quoted anywhere in the
//! documentation. To record your own, see `docs/BENCHMARKS.md`.

use std::fs;
use std::path::Path;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use bloatrail::analysis::Classifier;
use bloatrail::platform::KnownPaths;
use bloatrail::scanner::{self, ScanOptions};

/// Shape of the synthetic tree.
struct Shape {
    projects: usize,
    files_per_dir: usize,
    dirs_per_project: usize,
    file_size: usize,
}

const SMALL: Shape = Shape {
    projects: 4,
    files_per_dir: 8,
    dirs_per_project: 6,
    file_size: 512,
};

const LARGE: Shape = Shape {
    projects: 12,
    files_per_dir: 16,
    dirs_per_project: 12,
    file_size: 512,
};

/// Build a tree that looks like a developer's project directory.
fn build_tree(root: &Path, shape: &Shape) -> u64 {
    let payload = vec![b'x'; shape.file_size];
    let mut bytes = 0u64;

    for project in 0..shape.projects {
        let project_dir = root.join(format!("project-{project}"));
        fs::create_dir_all(&project_dir).unwrap();

        // Alternate between Rust and JavaScript project fingerprints.
        if project % 2 == 0 {
            fs::write(project_dir.join("Cargo.toml"), b"[package]\nname = \"p\"\n").unwrap();
            fs::write(project_dir.join("Cargo.lock"), b"# lock\n").unwrap();
        } else {
            fs::write(project_dir.join("package.json"), b"{\"name\":\"p\"}").unwrap();
            fs::write(project_dir.join("package-lock.json"), b"{}").unwrap();
        }

        for area in [
            "src",
            "tests",
            if project % 2 == 0 {
                "target"
            } else {
                "node_modules"
            },
        ] {
            for index in 0..shape.dirs_per_project {
                let dir = project_dir.join(area).join(format!("d{index}"));
                fs::create_dir_all(&dir).unwrap();
                for file in 0..shape.files_per_dir {
                    let path = dir.join(format!("f{file}.dat"));
                    fs::write(&path, &payload).unwrap();
                    bytes += payload.len() as u64;
                }
            }
        }
    }
    bytes
}

fn scan_once(root: &Path, threads: Option<usize>) {
    let classifier = Classifier::with_default_detectors();
    let known = KnownPaths::empty();
    let options = ScanOptions {
        threads,
        show_progress: false,
        ..ScanOptions::new(root)
    };
    let result = scanner::scan(&options, &classifier, &known).expect("scan");
    criterion::black_box(result.totals.bytes);
}

fn bench_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan");

    for (name, shape) in [("small", &SMALL), ("large", &LARGE)] {
        let temp = tempfile::tempdir().expect("temp dir");
        let bytes = build_tree(temp.path(), shape);
        group.throughput(Throughput::Bytes(bytes));

        group.bench_function(name, |b| {
            b.iter_batched(
                || temp.path().to_path_buf(),
                |root| scan_once(&root, None),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// How much parallelism actually helps on this machine.
fn bench_threads(c: &mut Criterion) {
    let temp = tempfile::tempdir().expect("temp dir");
    let bytes = build_tree(temp.path(), &LARGE);

    let mut group = c.benchmark_group("scan_threads");
    group.throughput(Throughput::Bytes(bytes));

    for threads in [1usize, 2, 4, 8] {
        group.bench_function(format!("{threads}"), |b| {
            b.iter_batched(
                || temp.path().to_path_buf(),
                |root| scan_once(&root, Some(threads)),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_scan, bench_threads);
criterion_main!(benches);
