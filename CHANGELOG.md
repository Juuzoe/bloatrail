# Changelog

Notable changes to Bloatrail. Versions follow [semantic versioning](https://semver.org).

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
