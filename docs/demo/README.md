# Demo and screenshot kit

Everything shown in the README — the scan breakdown, the two `target`
directories, the cleanup plan, the growth report — comes from a synthetic tree
this directory builds. No screenshot in this repository is of a real machine,
and this kit is committed so that claim is checkable rather than merely stated.

## Build the tree

```bash
python docs/demo/fixture.py ~/Projects
```

That writes 42 files across five projects — Rust, pnpm/Next.js, Python,
Gradle, and a marketing folder that is deliberately *not* a project — plus a
`.git` directory, logs, media and one stray duplicate.

The tree reports about 9 GB and occupies about 2 MB. Files are created sparse:
extended to their full length without their bytes ever being written.
Bloatrail reports apparent sizes (see *Known limits* in the README), so it
measures the tree exactly as though the bytes were there. Sparse files need
NTFS, ext4, XFS, btrfs or APFS; where they are unavailable the script says so
and falls back to real bytes at 1/1000 scale rather than filling the disk.

The two directories named `target` are the point of the fixture. One sits
beside a `Cargo.toml`; the other sits in `marketing/`. Any tool can see they
share a name — the demo exists to show the verdicts diverge.

## Record the GIFs

With [VHS](https://github.com/charmbracelet/vhs) installed and `bloatrail` on
your `PATH`:

```bash
vhs docs/demo/hero.tape      # the pitch: scan, explain, explain, clean --dry-run
vhs docs/demo/growth.tape    # the trajectory and the projected date
```

`growth.tape` needs a recorded past, because the report is a change over time
and a tree built five seconds ago correctly has nothing to compare against:

```bash
python docs/demo/seed-history.py ~/Projects
```

That runs one real scan and then back-dates five synthetic snapshots derived
from it, so the present is genuine and only the past is fabricated. It refuses
to run against any directory without the `.bloatrail-fixture` marker, so it
cannot write invented history for a real project.

## Clean up

```bash
rm -rf ~/Projects
```

The seeded history lives in Bloatrail's data directory
(`%APPDATA%\bloatrail`, `~/Library/Application Support/bloatrail`, or
`$XDG_DATA_HOME/bloatrail`) and is pruned to the newest 20 snapshots per
directory on its own. Setting `BLOATRAIL_HOME` to a scratch directory before
recording keeps it out of your real store entirely:

```bash
BLOATRAIL_HOME=$(mktemp -d) vhs docs/demo/growth.tape
```

## The desktop app

The app screenshots come from the app driving itself, not from this kit:

```bash
cargo build --release --features screenshots
BLOATRAIL_SHOT_DIR=docs/screenshots BLOATRAIL_SHOT_SCAN=~/Projects \
  ./target/release/bloatrail-gui
```

It walks every view, captures a PNG of each, and exits. The harness sits behind
its own feature so the shipped app carries no PNG encoder.
