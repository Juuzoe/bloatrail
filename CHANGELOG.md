# Changelog

Notable changes to Bloatrail. Versions follow [semantic versioning](https://semver.org).

## Unreleased

### `bloatrail growth`: what grew, and when the volume runs out

Every disk analyser answers "what is large today?". On the day the disk fills
up that answer has not changed in months; the useful questions are what has
been *growing* and how long is left. Monitoring tools can plot a trend but
cannot name a culprit; cleaners can name directories but have no memory.
`growth` is both halves: it reads every recorded scan of a directory as one
trajectory.

- One table of every recorded scan — size, proportion bar, and the volume's
  free space at the time. Attribution compares the first scan against the last,
  and each grown directory is annotated with its live classification and the
  command that recreates it.
- A projected exhaustion date, under rules that keep it honest: it is a trend
  extended forward and always "around"; a record shorter than 48 hours projects
  nothing; scans from before a capacity change are excluded, so a replaced disk
  does not fake a trend; a date more than a year out is reported as exactly
  that instead of a day.
- The rate is a least-squares fit across every point, not the difference
  between the first and the last. Because `clean` frees space, a window
  containing a cleanup ends with more free space than it started with, and
  endpoint differencing would read that as "not shrinking" and withhold the
  projection — going quiet for the people using the tool most.
- Reading a trend does not change it: `growth` records nothing unless given
  `--record`. Snapshots are thinned by age rather than a flat count —
  everything from the last week, one a day for a month, one a week for a year —
  so one busy afternoon cannot evict the months that make a trend meaningful.
- The first run is a starting line, not an error: growth is measured between
  scans, and the report says so.
- `--json` emits the full series, the attribution and the trend under the
  existing schema-versioned contract.

### `bloatrail explain --why-not`

Answers the question a person actually asks before trusting a deleter: not what
something is, but what would have been done to it. It runs the real safety
guard against a real cleanup target and prints the verdict, so the explanation
is the behaviour rather than a second account of it that can drift out of
agreement.

### Cleanup safety

Age-limited removal — the `Reclaim::OlderThan` path used for `logs/`, `tmp/`,
`cache/` and `~/Downloads` — is the one target kind whose deletions are not the
path the safety guard verified: the guard clears the container, and the
executor then walks it live. That walk trusted only a list of eight credential
directory names, so anything else old enough inside a swept directory was
removed.

- The sweep now re-checks every subdirectory on its own account and stops at
  any it may not enter: version-control metadata by name (`.git`, `.hg`,
  `.svn`, `.jj`, `_darcs`, `CVS`), credential stores, anything a detector
  classifies as not deletable, and anything that looks like a project root. A
  repository or source tree unpacked under `~/Downloads` is no longer pruned
  file by file.
- The sweep now follows the scan's hidden-directory policy. It previously
  descended into dot-directories the scan had skipped, deleting bytes that were
  in no total and on no screen the user had seen.
- Subtrees it declines to enter are reported with a reason, so what was
  preserved is visible rather than silently passed over. Files that fail to
  delete are reported too, instead of a wholly failed sweep looking like a
  sweep that had nothing to do.
- `sensitive::is_protected_directory` matches case-insensitively, like
  `classify` already did. On Windows and macOS `.SSH` is the same directory as
  `.ssh` and now gets the same answer.

### Reliability

- `--select 1-99999999999` expanded the range before validating it, allocating
  until the process died. Selections are bounded first.
- Directories whose names are not valid UTF-8 had their child paths rebuilt
  from a lossy string, producing a path that does not exist: the whole subtree
  was counted as zero bytes and reported as "no longer exists". Traversal now
  carries the real name and reserves the lossy copy for display.
- On Windows, every reparse tag was treated as a link. OneDrive and other cloud
  placeholders set that attribute without being links, so on a stock Windows 11
  machine — where OneDrive backs Desktop, Documents and Pictures — those trees
  were silently dropped from every total. Only name-surrogate tags (symlinks
  and junctions) count as links now.
- A directory crossing the edge of the recorded top-25 list was reported by
  `growth` and `diff` as created or deleted at its full size. Its absence is
  now bounded by the list's floor, so the reported change is the smallest the
  data supports rather than an invention.
- Two scans recorded within the same second no longer overwrite each other.

### Snapshots

- Snapshots record the volume's capacity and free space and the recoverable
  estimate at scan time. The fields are additive: snapshots written by earlier
  versions still load, and older binaries ignore the new fields.
- `scan`, `diff` and `growth` build their snapshots through one path, so the
  record cannot depend on which command wrote it.

### Reports

- Directory change lists (in `growth` and `diff`) no longer repeat a parent
  directory whose change is already explained by a listed child; a parent
  survives only when something else inside it moved.
- `growth` hides changes smaller than a thousandth of the biggest mover behind
  a counted "… and N smaller changes" line rather than listing them.

### Documentation and CI

- `docs/demo/` builds the synthetic tree behind every screenshot, with VHS
  tapes for the CLI recordings. The tree reports about 9 GB and occupies about
  2 MB, because its files are sparse — which makes the README's claim that no
  screenshot comes from a real machine checkable by running one script.
- CI runs `cargo audit`, exercises `install.sh` and `install.ps1` end to end on
  all three platforms — the front door had no test at all — and rebuilds the
  demo fixture so the documentation cannot quietly stop being reproducible.

### A pnpm `node_modules` measured as empty

Hidden directories are only traversed by default when their name is on an
allowlist. `.pnpm-store` — the global store — was on it, but `node_modules/.pnpm`
was not, and that is the per-project virtual store holding the packages
themselves; everything beside it in `node_modules` is a symlink pointing back
into it. A pnpm project's `node_modules` therefore measured 0 B, which is the
one directory the tool exists to find.

- `.pnpm` is traversed by default, so `node_modules` reports the space it
  occupies.
- `.nx` joins it: Nx keeps its build cache there and it grows to gigabytes on a
  monorepo.

### Tests

- The unreadable-directory test probes the directory it locked instead of
  assuming the mode took effect. Root ignores a `0o000` directory, so the
  assertion failed inside a container or devcontainer for a reason unrelated to
  the scanner.

## 0.3.0

### Duplicate detection understands hardlinks

Two hardlinked paths are one file under two names, so reporting them as a
duplicate pair claimed space that deleting a name would never free. Developer
trees are full of exactly this: pnpm links every package from its store into
each project's `node_modules`, and Cargo links binaries inside `target`.

- A fold stage now sits between size grouping and hashing. Paths sharing a
  storage identity collapse into one copy, so reclaim figures count bodies
  rather than names, and each copy is read at most once. On a tree with 2,000
  pnpm-style links, the claimed reclaimable space dropped from a fictional
  ~500 MB to the true 2.5 MB, and none of those links reached the hash stages.
- Copies with names the search could not see — outside the scanned root,
  excluded, hidden, or unmatchable because the filesystem's file IDs cannot be
  trusted — are marked and left out of the reclaim figure. Deleting their
  listed names frees nothing. A snapshot tree pinned entirely from outside now
  reports zero rather than a figure no deletion could realise.
- Where file identity is unavailable, the result degrades toward underclaiming
  rather than counting space that is not there.
- Concurrent mutation resolves toward silence rather than wrong answers: a name
  unlinked mid-scan is dropped while its siblings carry on, and a name another
  file was renamed over is recognised and skipped instead of having the
  impostor's bytes attributed to names that were never read.
- Copy-on-write clones share storage without hardlinks. Bloatrail cannot see
  that from metadata and counts them as ordinary copies; the README says so.

### Output

- `duplicates` groups paths by storage and labels every name with what deleting
  it would actually free.
- `--json` keeps its flat `paths` list and adds `copies`, each with a
  `linked_elsewhere` flag, plus a `hardlinks` count of folded paths.

### Platform

- New internal primitive for file identity: device and inode on Unix, volume
  serial and file ID through `GetFileInformationByHandle` on Windows.

## 0.2.0

- Native desktop app (`bloatrail-gui`), built on egui, shipping as a single
  executable with no runtime dependencies.
- Scan history and `bloatrail diff`, which reports what grew since last time.
- `bloatrail doctor` reads Docker's own disk usage through the CLI and never
  touches its files.
- Detectors for Rust, JavaScript, Python, Go, the JVM, .NET, C and C++, IDEs
  and system package managers, each deciding from project context rather than
  directory names alone.
- Cleanup pipeline with four independent axes: what a directory is, how
  confident the identification is, whether it can be removed, and what would
  come back. Removals go to the recycle bin unless `--permanent` is passed, and
  `--dry-run` returns before reaching any code that can write.

## 0.1.0

- First release: parallel scanner, annotated tree, and the classification model.
