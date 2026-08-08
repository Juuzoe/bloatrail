# Benchmarking Bloatrail

This document explains how to measure Bloatrail's performance and how to record
the results.

**No performance figures are published in this repository.** Numbers from an
unknown machine, an unknown filesystem and an unknown cache state are worse than
no numbers at all, so the tooling is provided and the table below is left for
you to fill in on hardware you can describe.

## What is measured

Two Criterion benchmark suites, in [`benches/`](../benches):

| Suite | What it measures |
| --- | --- |
| `scanner` | End-to-end traversal of a synthetic project tree: `read_dir`, metadata, classification, aggregation and the largest-files heap. Reports throughput in bytes per second. |
| `classification` | Per-directory classification in isolation from disk I/O, plus file categorisation and byte formatting. |

The `scanner` suite builds a tree shaped like a developer machine — several
projects, each with a `node_modules` or a `target` — because that is the
workload the collapse optimisation exists for. It also sweeps the thread count
(1, 2, 4, 8) so you can see where parallelism stops helping on your hardware.

## Running them

```bash
cargo bench                            # everything
cargo bench --bench scanner            # traversal only
cargo bench --bench classification     # classification only
cargo bench -- --test                  # one iteration each, for CI
```

Criterion writes HTML reports to `target/criterion/report/index.html` and
compares each run against the previous one, so a regression shows up as a
percentage rather than a number you have to interpret.

To compare a change against `main`:

```bash
git switch main && cargo bench --bench scanner   # records the baseline
git switch my-branch && cargo bench --bench scanner
```

## Measuring a real scan

The benchmarks use synthetic trees. For a figure that means something, time the
binary against a real directory:

```bash
cargo build --release

# Warm the page cache first, then measure. A cold-cache number measures your
# disk; a warm-cache number measures Bloatrail.
./target/release/bloatrail scan ~ --no-progress > /dev/null
time ./target/release/bloatrail scan ~ --no-progress
```

`bloatrail scan` prints its own summary line, which is usually enough:

```
<N> files, <N> directories in <T>s (<R>/s)
```

Note what that rate actually measures: bytes of *apparent file size* accounted
for per second of wall clock. It is a measure of how fast the analyser gets
through a tree, not of disk bandwidth, and on a warm page cache it will exceed
any figure your storage could sustain. Quote it as "analysed at", never as
"read at".

### Things that will mislead you

- **Page cache.** The first scan of a directory is dominated by disk reads. Run
  twice and quote the second.
- **Antivirus.** On Windows, real-time scanning intercepts every file open.
  Excluding the scanned tree changes results substantially, so say which you
  measured.
- **Network filesystems.** SMB and NFS latency dominates everything; parallelism
  helps far more there than on local NVMe.
- **`--progress`.** Rendering is throttled to ten frames per second and the hot
  path only does relaxed atomic increments, but on a very short scan the
  fixed setup cost is visible. Use `--no-progress` when timing.
- **Debug builds.** Always measure `--release`. The difference is roughly an
  order of magnitude.

## Profiling

The `profiling` profile is a release build that keeps symbols:

```bash
cargo build --profile profiling

# Linux
perf record -g ./target/profiling/bloatrail scan ~ --no-progress
perf report

# macOS
xcrun xctrace record --template 'Time Profiler' --launch ./target/profiling/bloatrail scan ~

# Cross-platform, via cargo-flamegraph
cargo flamegraph --profile profiling -- scan ~ --no-progress
```

## Recording results

Fill this in for your own machine and keep the description honest — the setup
matters more than the number.

| Date | Machine | Filesystem | Files | Directories | Size | Wall time | Throughput |
| --- | --- | --- | --- | --- | --- | --- | --- |
| | | | | | | | |

Suggested description format:

> 2026-08-08 · MacBook Pro M3 Max, 36 GB RAM · APFS on internal NVMe ·
> warm cache · `bloatrail scan ~ --no-progress` · release build

## Where the time goes

For anyone reading a profile for the first time, the shape is usually:

1. **`read_dir` and metadata** — the majority of the wall time on any real
   filesystem. Bloatrail issues one `read_dir` per directory and one metadata
   call per entry; on Windows the metadata comes back with the directory
   enumeration, so it is effectively free there.
2. **Path construction** — one `PathBuf` join per subdirectory. Files do not get
   a path built unless they make the largest-files list.
3. **Classification** — a hash lookup per directory, then the handful of
   detectors that the name actually triggers.
4. **Aggregation** — arithmetic on the way back up the recursion.

If a profile shows anything else near the top, that is worth an issue.
