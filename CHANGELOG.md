# Changelog

Notable changes to Bloatrail. Versions follow [semantic versioning](https://semver.org).

## 0.4.0

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

### Desktop app

- A Growth view: every recorded scan of the folder with its size and the
  volume's free space at the time, what grew between the first scan and the
  last (each grown directory labelled with its classification from the current
  scan), the volume's trend and projected date under the same rules as
  `bloatrail growth`, and the recoverable amount with a way into Cleanup. A
  folder with one recorded scan shows a starting line instead.
- The app now records each finished scan in the scan history, as `bloatrail
  scan` does, so its scans and the CLI's build one record. A scan stopped early
  is not recorded. History is read and written on the scan worker, never the
  UI thread.
- Snapshots are built by one library function, `Snapshot::capture`, for the
  CLI and the app alike, and both list the same changes above the same noise
  floor.

### Coverage

A dot-directory missing from the traversal allowlist is counted nowhere, and a
shared store missing from the registry of well-known locations is categorised
file by file. Both gaps are smaller now, and because closing a gap changes what
a scan counts, every recorded scan says what it covered.

- Every snapshot records a coverage stamp: a short digest of the
  always-traversed list, the hidden-directory, symlink, filesystem and exclude
  settings, and the well-known location rules. Rules are hashed as anchor and
  relative path (`~/.cargo/registry`, `%LOCALAPPDATA%/npm-cache`), never as a
  resolved path, so the stamp is the same on every run and on every machine of
  one platform with the same settings.
- `growth` measures attribution, the scan table and the net change from the
  first scan recorded under the newest scan's coverage, and says where that was
  and how many earlier scans it left out. Before, an upgrade that started
  walking a directory, or one scan with `--include-hidden`, showed up as growth
  that never happened on disk. The free-space trend still uses every scan: it
  reads the volume, which the scanner's rules do not change.
- `diff` across a coverage change still reports the figures, but says the two
  scans were counted under different rules and marks the net change as
  including it.
- Scans recorded before coverage was tracked count as different coverage from
  stamped ones. A record with no stamps at all, or one stamp throughout,
  behaves exactly as before.
- JSON: `diff` gains `coverage_changed`; `growth` gains `coverage_changed_at`
  (absent when coverage never changed) and `earlier_scans`, and its `points`
  hold only the comparable scans. All additive, so `schema_version` stays 1.
- Walked by default now: `.pub-cache`, `.ivy2`, `.sbt`, `.stack`, `.ghcup`,
  `.elan`, `.opam`, `.julia`, `.hex`, `.conan`, `.conan2`, `.volta`,
  `.terraform.d`, `.vagrant.d`, `.platformio`, `.espressif` and `.arduino15`.
  `~/.terraform.d/plugin-cache` was registered before, but its parent was never
  walked, so it was never seen. `.lima`, `.colima` and `.minikube` stay behind
  `--include-hidden`: they keep SSH keys and cluster certificates beside the
  VM disks.
- New well-known locations offered as safe, because the owning tool refills
  them on demand: pre-commit's hook environments, the Hex, opam, nvm,
  SDKMAN!, GHCup, Volta, ESP-IDF, Arduino and PlatformIO download caches,
  Julia's precompilation cache, Bazelisk's downloads and node-gyp's headers.
- Probably safe, because they come back at a cost or need a step before
  projects build again: Dart's pub cache, Coursier, Ivy, sbt's launcher
  downloads, Stack's package index and snapshot builds, Conan 1 and 2 package
  caches (locally built packages take hours to rebuild), Julia packages and
  artifacts, PlatformIO toolchains, ESP-IDF tools and Python environments,
  minikube's download cache and Electron's binary cache.
- Held for review and reclaimed through the tool that owns them, because they
  are choices or state: Node.js versions under nvm and Volta, pyenv versions
  (which can be pyenv-virtualenv environments), SDKMAN! candidates, elan
  toolchains, GHCup and Stack compilers, Arduino board cores, Vagrant boxes,
  minikube machines, Lima and Colima VMs, and Bazel's output root, which is
  cleared with `bazel clean --expunge`: deleting files under a running Bazel
  server is not safe, and Bazel marks its outputs read-only.
- Stores that move between platforms are registered where each platform puts
  them: `~/.cache` on Linux, `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on
  Windows (Coursier, Bazelisk, Electron, node-gyp, Cypress, Playwright, pub,
  Volta, Arduino), and Bazel's `_bazel_<user>` output root on each.

### New ecosystems, from contributors

- Dart and Flutter `build/` output, recognised by a `pubspec.yaml` beside it
  and held at medium confidence until a `pubspec.lock` confirms the project
  (#6, @QIU-Guanzong).
- Nx's `.nx` task cache, only when an `nx.json` sits beside it (#7,
  @QIU-Guanzong).
- Unreal Engine's `Intermediate/`, `Binaries/` and `DerivedDataCache/`, with
  `Saved/` held for review because it carries autosaves and local settings
  (#8, @Visio-Vanitas).
- Bazel's `bazel-out`, `bazel-bin`, `bazel-testlogs` and execution-root links
  in a workspace (#9, @Visio-Vanitas). The execution-root rule matches only
  `bazel-<workspace directory>`, so a hand-made `bazel-configs/` in the same
  repository is never offered, and the output names with no workspace file
  beside them are reported for review rather than as safe.
- Contributions arriving on separate branches each picked "the next free"
  marker bit and two of them collided, which would have made a
  `pubspec.lock` count as an Unreal project. A test now fails whenever two
  markers share a bit.

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

### Output

- `--ascii` now produces ASCII. The glyph set covered tree lines and bars,
  while the prose around them still carried dashes, ellipses and arrows;
  report text is folded to ASCII before it is written, and elided paths end
  in `...` with the width budget adjusted so columns still line up. JSON is
  left as serialised.
- Scan speed is reported in files a second instead of bytes. Sizes come from
  metadata without reading file contents, so `118 GB/s` described the files
  rather than the scan.
- The scan progress block measures its lines in display columns. A path with
  CJK characters used to wrap a line, and every redraw then left a stale row
  behind.
- `largest --json` applies `--min-size`, as the table always did.
- `diff` counts the changes past its ten-row limit in a closing line, the way
  `growth` does, instead of dropping them without a word.
- The reclaimable column pads the plain figure and colours it afterwards,
  rather than relying on how the width library counts escape bytes.

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

### Platforms

- A static ARM64 Linux build (`aarch64-unknown-linux-musl`), built and run on
  an ARM runner, and preferred by the install script, so Alpine on a
  Raspberry Pi or a Graviton container no longer needs glibc. Asking an older
  release for it falls back to the glibc build. Both ARM Linux builds are now
  native rather than cross-compiled, so each gets the same "does it run"
  check as x86.
- CI runs the test suite on ARM64 Linux as well as x86 Linux, macOS and
  Windows.
- The install scripts read the newest tag from the `releases/latest`
  redirect instead of the REST API, which answers 403 once a shared address
  (an office NAT, a pool of CI runners) has spent its 60 anonymous requests an
  hour. The API remains as the fallback.
- `cargo binstall bloatrail` fetches the prebuilt archive instead of
  compiling, once the crate is on crates.io.

### Documentation and CI

- `docs/demo/` builds the synthetic tree behind every screenshot, with VHS
  tapes for the CLI recordings. The tree reports about 9 GB and occupies about
  2 MB, because its files are sparse — which makes the README's claim that no
  screenshot comes from a real machine checkable by running one script.
- CI runs `cargo audit`, exercises `install.sh` and `install.ps1` end to end on
  all three platforms — the front door had no test at all — and rebuilds the
  demo fixture so the documentation cannot quietly stop being reproducible.

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
