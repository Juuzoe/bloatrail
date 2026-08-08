//! Classification and formatting microbenchmarks.
//!
//! The classifier runs once per directory, so its per-call cost is multiplied by
//! hundreds of thousands on a real scan. These benchmarks isolate it from disk
//! I/O so a regression in the dispatch table shows up clearly.
//!
//! Run with:
//!
//! ```text
//! cargo bench --bench classification
//! ```

use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};

use bloatrail::analysis::categorize::categorize_file;
use bloatrail::analysis::context::{DirContext, Markers};
use bloatrail::analysis::Classifier;
use bloatrail::platform::KnownPaths;
use bloatrail::units::ByteSize;

fn context<'a>(
    name: &'a str,
    path: &'a Path,
    parent_markers: Markers,
    env: &'a KnownPaths,
) -> DirContext<'a> {
    DirContext {
        path,
        name,
        name_lower: name,
        parent_name: Some("project"),
        markers: Markers::empty(),
        parent_markers,
        grandparent_markers: Markers::empty(),
        depth: 2,
        subdir_count: 4,
        file_count: 12,
        env,
    }
}

fn bench_classify(c: &mut Criterion) {
    let classifier = Classifier::with_default_detectors();
    let env = KnownPaths::empty();

    let mut group = c.benchmark_group("classify");

    // The overwhelmingly common case: a directory no rule cares about. This is
    // the number that dominates a real scan.
    let miss_path = Path::new("/projects/api/src/handlers");
    group.bench_function("miss", |b| {
        b.iter(|| {
            let ctx = context("handlers", miss_path, Markers::empty(), &env);
            criterion::black_box(classifier.classify(&ctx))
        });
    });

    // A hit that needs project context to resolve.
    let target_path = Path::new("/projects/api/target");
    group.bench_function("rust_target", |b| {
        b.iter(|| {
            let ctx = context("target", target_path, Markers::CARGO_TOML, &env);
            criterion::black_box(classifier.classify(&ctx))
        });
    });

    // A name that several detectors compete over.
    let build_path = Path::new("/projects/api/build");
    group.bench_function("contested_build", |b| {
        b.iter(|| {
            let ctx = context(
                "build",
                build_path,
                Markers::GRADLE_BUILD | Markers::CMAKELISTS | Markers::PYPROJECT,
                &env,
            );
            criterion::black_box(classifier.classify(&ctx))
        });
    });

    group.finish();
}

fn bench_categorize(c: &mut Criterion) {
    let names = [
        "main.rs",
        "holiday-video.MP4",
        "archive.tar.gz",
        "ubuntu-vm.qcow2",
        "some-unremarkable-file",
        "index.d.ts",
    ];

    c.bench_function("categorize_file", |b| {
        b.iter(|| {
            for name in &names {
                criterion::black_box(categorize_file(name));
            }
        });
    });
}

fn bench_format(c: &mut Criterion) {
    let sizes = [0u64, 999, 1536, 431 * 1024 * 1024, 88_451_223_552];
    c.bench_function("format_bytes", |b| {
        b.iter(|| {
            for size in &sizes {
                criterion::black_box(ByteSize(*size).to_string());
            }
        });
    });
}

criterion_group!(benches, bench_classify, bench_categorize, bench_format);
criterion_main!(benches);
