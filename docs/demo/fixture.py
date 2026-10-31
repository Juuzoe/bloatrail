#!/usr/bin/env python3
"""Build the synthetic project tree used by Bloatrail's screenshots and demos.

Every screenshot and sample output in the README comes from a tree this script
builds. None of it is a real machine, which is why the repository quotes no
benchmark figures — and why this script is committed: the claim is checkable by
anyone who runs it.

The tree is realistic in *shape*, not in bytes. Files are created sparse, so a
tree that reports ~14 GB occupies a few hundred kilobytes on disk. Bloatrail
reports apparent sizes (see "Known limits" in the README), so it measures the
tree exactly as if the bytes were there, and the demo costs nothing to build.

    python docs/demo/fixture.py /tmp/Projects
    python docs/demo/fixture.py /tmp/Projects --real      # actually allocate
    python docs/demo/fixture.py /tmp/Projects --force     # overwrite existing

Sparse files need a filesystem that supports them: NTFS, ext4, XFS, btrfs and
APFS all do. Where they are unavailable the script says so and falls back to
`--real` with scaled-down sizes rather than filling the disk.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

KB = 1024
MB = 1024 * KB
GB = 1024 * MB

# The tree from the README. Sizes are what Bloatrail will report.
#
# Two directories are deliberately named `target`: one beside a Cargo.toml and
# one in a marketing folder. That pair is the whole pitch — the classifier has
# to reach opposite verdicts about identically named directories — so it is
# part of the fixture rather than something a demo sets up by hand.
FILES: list[tuple[str, int]] = [
    # backend-api — a Rust project with a large build tree and real Git data.
    ("backend-api/Cargo.toml", 2 * KB),
    ("backend-api/Cargo.lock", 48 * KB),
    ("backend-api/src/main.rs", 12 * KB),
    ("backend-api/src/routes/mod.rs", 340 * KB),
    ("backend-api/src/routes/handlers.rs", 369 * KB),
    ("backend-api/target/debug/deps/libcore.rlib", 1200 * MB),
    ("backend-api/target/debug/backend-api", 890 * MB),
    ("backend-api/target/debug/incremental/api-1a2b/dep-graph.bin", 760 * MB),
    ("backend-api/target/release/backend-api", 620 * MB),
    ("backend-api/target/.rustc_info.json", 4 * KB),
    ("backend-api/.git/HEAD", 41),
    ("backend-api/.git/config", 320),
    ("backend-api/.git/objects/pack/pack-9f3c.pack", 880 * MB),
    ("backend-api/.git/objects/pack/pack-9f3c.idx", 30 * MB),
    ("backend-api/logs/app.log", 210 * MB),
    ("backend-api/logs/access.log", 173 * MB),
    # dashboard — a pnpm/Next.js project.
    ("dashboard/package.json", 3 * KB),
    ("dashboard/pnpm-lock.yaml", 512 * KB),
    ("dashboard/src/app/page.tsx", 340 * KB),
    ("dashboard/src/components/Chart.tsx", 524 * KB),
    ("dashboard/node_modules/.pnpm/react@18/index.js", 420 * MB),
    ("dashboard/node_modules/next/dist/compiled.js", 604 * MB),
    ("dashboard/.next/cache/webpack/client.pack", 700 * MB),
    ("dashboard/.next/static/chunks/main.js", 400 * MB),
    ("dashboard/dist/bundle.js", 40 * MB),
    ("dashboard/public/hero.png", 421 * MB),
    ("dashboard/public/promo.mp4", 212 * MB),
    # ml-pipeline — a Python project with a virtualenv and tool caches.
    ("ml-pipeline/pyproject.toml", 2 * KB),
    ("ml-pipeline/requirements.txt", 900),
    ("ml-pipeline/train.py", 28 * KB),
    ("ml-pipeline/.venv/pyvenv.cfg", 180),
    ("ml-pipeline/.venv/lib/site-packages/torch/_C.so", 807 * MB),
    ("ml-pipeline/.mypy_cache/3.12/builtins.data.json", 17 * MB),
    ("ml-pipeline/__pycache__/train.cpython-312.pyc", 11 * MB),
    # android-client — Gradle.
    ("android-client/build.gradle.kts", 4 * KB),
    ("android-client/gradlew", 6 * KB),
    ("android-client/build/outputs/apk/app-debug.apk", 467 * MB),
    ("android-client/.gradle/caches/modules-2/files.bin", 342 * MB),
    # marketing — NOT a project. Its `target` directory must survive.
    ("marketing/campaign-brief.docx", 2 * MB),
    ("marketing/target/q4-audience.csv", 2 * MB),
    ("marketing/assets/logo.png", 1 * MB),
    # A stray duplicate, so `bloatrail duplicates` has something to find.
    ("backups/bundle-copy.js", 40 * MB),
]

# Directories that must exist even when no file inside them is listed.
EMPTY_DIRS = ["backend-api/.git/refs/heads", "dashboard/node_modules/.bin"]

# Files given an old modification time, in days. Bloatrail offers logs only
# above its staleness threshold (90 days by default) and says so in the group
# title, so without an aged file the cleanup plan never shows its REVIEW tier
# and the demo understates what the tool actually reasons about.
AGED: list[tuple[str, int]] = [
    ("backend-api/logs/access.log", 210),
    ("backend-api/logs/app.log", 120),
    ("backups/bundle-copy.js", 400),
]


def _fsutil(*command: str) -> bool:
    """Run an fsutil subcommand, reporting whether it succeeded."""
    result = subprocess.run(["fsutil", *command], capture_output=True, check=False)
    return result.returncode == 0


def _extend(path: Path, size: int) -> None:
    """Grow `path` to `size` apparent bytes without writing them.

    On Unix `ftruncate` leaves a hole. On Windows it must NOT be Python's
    `truncate()`: that calls the CRT's `_chsize_s`, which zero-*fills* the
    extension, so a "sparse" file ends up fully allocated — a 9 GB fixture that
    really costs 9 GB. `fsutil file setEOF` moves the end of file without
    writing anything, which is what the sparse flag needs to take effect.
    """
    if sys.platform == "win32":
        if _fsutil("file", "setEOF", str(path), str(size)):
            return
        # Fall back to the allocating path rather than producing a short file.
        with open(path, "r+b") as handle:
            handle.truncate(size)
        return
    with open(path, "r+b") as handle:
        handle.truncate(size)


def _allocated(path: Path) -> int | None:
    """Bytes `path` actually occupies, where the platform will say."""
    stat = path.stat()
    blocks = getattr(stat, "st_blocks", None)
    return None if blocks is None else blocks * 512


def supports_sparse(root: Path) -> bool:
    """Whether sparse files work here — measured, never assumed."""
    probe = root / ".sparse-probe"
    try:
        with open(probe, "wb") as handle:
            handle.write(b"probe")
        if sys.platform == "win32" and not _fsutil("sparse", "setflag", str(probe)):
            return False
        _extend(probe, 64 * MB)

        occupied = _allocated(probe)
        if occupied is not None:
            return occupied < 8 * MB
        # Windows exposes no block count through stat(). Confirm with the
        # filesystem that the flag survived the extend, rather than assuming
        # it did — assuming is how this script allocated 9 GB the first time
        # it ran. A sparse-flagged file extended via setEOF holds no data.
        if probe.stat().st_size != 64 * MB:
            return False
        return _fsutil("sparse", "queryflag", str(probe))
    except OSError:
        return False
    finally:
        probe.unlink(missing_ok=True)


def write(path: Path, size: int, sparse: bool) -> None:
    """Create one file of `size` apparent bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not sparse:
        # Real bytes, written in chunks so a large file does not need a large
        # buffer. Content is not zeros: `duplicates` hashes contents, and a
        # tree of identical zero-filled files would make every file a match.
        chunk = (path.name.encode() * 512)[: 64 * KB] or b"\0" * (64 * KB)
        with open(path, "wb") as handle:
            written = 0
            while written < size:
                handle.write(chunk[: min(len(chunk), size - written)])
                written += len(chunk)
        return

    # A few real bytes at the head keep every file's contents distinct, so
    # `duplicates` sees a realistic tree rather than one giant match group.
    with open(path, "wb") as handle:
        handle.write(path.name.encode()[:64] or b"x")
    if sys.platform == "win32":
        _fsutil("sparse", "setflag", str(path))
    _extend(path, size)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", type=Path, help="directory to build the tree in")
    parser.add_argument("--real", action="store_true", help="allocate real bytes instead of sparse files")
    parser.add_argument("--force", action="store_true", help="replace the directory if it exists")
    parser.add_argument(
        "--scale",
        type=float,
        default=1.0,
        help="multiply every size (use with --real, e.g. --scale 0.001)",
    )
    args = parser.parse_args()

    root: Path = args.root.expanduser().resolve()

    if root.exists():
        if not args.force:
            print(f"{root} already exists. Pass --force to replace it.", file=sys.stderr)
            return 1
        # Only ever remove a directory this script could have produced.
        if not (root / ".bloatrail-fixture").exists():
            print(
                f"{root} exists but was not built by this script "
                "(no .bloatrail-fixture marker). Refusing to delete it.",
                file=sys.stderr,
            )
            return 1
        shutil.rmtree(root)

    root.mkdir(parents=True)
    (root / ".bloatrail-fixture").write_text("Generated by docs/demo/fixture.py\n", encoding="utf-8")

    sparse = not args.real
    if sparse and not supports_sparse(root):
        print("Sparse files are unavailable here; falling back to real bytes at 1/1000 scale.", file=sys.stderr)
        sparse = False
        args.scale = min(args.scale, 0.001)

    total = 0
    for relative, size in FILES:
        scaled = max(1, int(size * args.scale))
        write(root / relative, scaled, sparse)
        total += scaled
    for relative in EMPTY_DIRS:
        (root / relative).mkdir(parents=True, exist_ok=True)

    # Age must be applied last: writing a file resets its modification time.
    # `time.time()` is the one clock reading here, and it only moves mtimes
    # backwards relative to now, so the tree ages correctly whenever it is run.
    now = time.time()
    for relative, days in AGED:
        target = root / relative
        if target.exists():
            stamp = now - days * 86_400
            os.utime(target, (stamp, stamp))

    print(f"Built {len(FILES)} files ({total / GB:.1f} GB apparent) in {root}")
    if sparse:
        print("Files are sparse: the tree reports its full size but occupies almost no disk.")
    print(f"\n  bloatrail scan {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
