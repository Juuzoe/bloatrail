#!/usr/bin/env python3
"""Give a fixture tree a plausible past, so `bloatrail growth` has a trajectory.

`growth` reports a change over time, so on a tree built five seconds ago it
correctly reports that there is nothing to compare yet. This writes the scan
snapshots that a month of ordinary use would have left behind, so the command
can be demonstrated without waiting a month.

    python docs/demo/fixture.py ~/Projects
    python docs/demo/seed-history.py ~/Projects
    bloatrail growth ~/Projects

The snapshots are back-dated and scaled down from a real scan of the tree, so
the present is genuine and only the past is synthetic. This is a documentation
tool: it writes into Bloatrail's own history store, and refuses to touch a
store entry it did not create for a fixture directory.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

DAY = 86_400
GB = 1024 ** 3

# Weeks back, and the fraction of today's size the tree had then. Free space
# falls faster than the tree grows, because everything else on a real machine
# is growing too — which is what makes the projected date interesting.
TIMELINE = [
    (28, 0.62, 3.1),
    (21, 0.71, 2.6),
    (14, 0.82, 1.9),
    (7, 0.91, 1.1),
    (3, 0.96, 0.6),
]


def store_root() -> Path | None:
    """Where Bloatrail keeps scan history on this machine."""
    if home := os.environ.get("BLOATRAIL_HOME"):
        return Path(home) / "history"
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        return Path(base) / "bloatrail" / "history" if base else None
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "bloatrail" / "history"
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else Path.home() / ".local" / "share") / "bloatrail" / "history"


def find_entry(history: Path, root: Path) -> tuple[Path, dict] | None:
    """Locate the store directory holding snapshots of `root`.

    The directory name is a hash Bloatrail computes internally. Rather than
    reimplement it here — and drift from it the next time it changes — this
    reads each entry and matches on the root recorded inside.
    """
    wanted = str(root).rstrip("/\\")
    if sys.platform == "win32":
        wanted = wanted.replace("/", "\\").lower()

    for entry in sorted(history.iterdir()) if history.is_dir() else []:
        if not entry.is_dir():
            continue
        for snapshot_file in sorted(entry.glob("*.json")):
            try:
                snapshot = json.loads(snapshot_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            recorded = str(snapshot.get("root", "")).rstrip("/\\")
            if sys.platform == "win32":
                recorded = recorded.replace("/", "\\").lower()
            if recorded == wanted:
                return entry, snapshot
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", type=Path, help="the fixture tree to give a past")
    parser.add_argument("--bloatrail", default="bloatrail", help="path to the bloatrail binary")
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    if not (root / ".bloatrail-fixture").exists():
        print(
            f"{root} was not built by docs/demo/fixture.py (no .bloatrail-fixture marker).\n"
            "Refusing to write synthetic history for a real directory.",
            file=sys.stderr,
        )
        return 1

    history = store_root()
    if history is None:
        print("Could not determine Bloatrail's data directory.", file=sys.stderr)
        return 1

    # Scan for real first: it creates the store entry and gives us a genuine
    # present to scale the synthetic past down from.
    print(f"Scanning {root} to establish the present…")
    scan = subprocess.run(
        [args.bloatrail, "scan", str(root), "--no-progress", "--json"],
        capture_output=True,
        check=False,
        text=True,
    )
    if scan.returncode != 0:
        print(f"`{args.bloatrail} scan` failed:\n{scan.stderr}", file=sys.stderr)
        return 1

    found = find_entry(history, root)
    if found is None:
        print(f"No history entry for {root} under {history}.", file=sys.stderr)
        return 1
    entry, present = found

    now = int(present["timestamp"])
    free_now = present.get("disk_available")
    if free_now is None:
        print(
            "The recorded snapshot has no disk figures, so this Bloatrail is older than\n"
            "the `growth` command. Rebuild it before seeding history.",
            file=sys.stderr,
        )
        return 1

    written = 0
    for days_ago, size_fraction, extra_free_gb in TIMELINE:
        past = dict(present)
        past["timestamp"] = now - days_ago * DAY
        past["bytes"] = int(present["bytes"] * size_fraction)
        past["files"] = max(1, int(present["files"] * size_fraction))
        past["categories"] = {
            key: int(value * size_fraction) for key, value in present.get("categories", {}).items()
        }
        past["largest"] = [[name, int(size * size_fraction)] for name, size in present.get("largest", [])]
        past["disk_available"] = int(free_now + extra_free_gb * GB)
        past["reclaimable"] = int(present.get("reclaimable", 0) * size_fraction)

        target = entry / f"{past['timestamp']:020d}.json"
        target.write_text(json.dumps(past, indent=2), encoding="utf-8")
        written += 1

    print(f"Wrote {written} back-dated snapshots into {entry}")
    print(f"\n  bloatrail growth {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
