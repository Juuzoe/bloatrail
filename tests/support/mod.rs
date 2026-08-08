//! Shared helpers for the integration tests.
//!
//! Every test builds a real directory tree in a temporary location and runs the
//! real scanner over it. Nothing here mocks the filesystem: the point of these
//! tests is to prove the behaviour on an actual one.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use bloatrail::analysis::Classifier;
use bloatrail::platform::KnownPaths;
use bloatrail::scanner::{self, ScanOptions, ScanResult};

/// A temporary directory tree that cleans itself up.
pub struct Fixture {
    /// Kept alive so the directory is removed on drop.
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    /// Create an empty fixture.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary directory");
        // The scanner canonicalises its root, so every path a test compares
        // against has to be canonical too. This matters wherever the system
        // temp directory is not already in canonical form: macOS reaches it
        // through the `/var` -> `/private/var` symlink, and Windows CI runners
        // expose it under an 8.3 short name (`RUNNER~1`). Without this, a test
        // that builds an exclusion pattern or compares a path passes locally
        // and fails there.
        let root = scanner::canonical_root(dir.path()).expect("canonical fixture root");
        Fixture { _dir: dir, root }
    }

    /// The fixture root, in the same canonical form the scanner reports.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Absolute path of a fixture-relative location.
    pub fn join(&self, relative: &str) -> PathBuf {
        let mut path = self.root.clone();
        for part in relative.split('/') {
            path.push(part);
        }
        path
    }

    /// Create a directory, including parents.
    pub fn dir(&self, relative: &str) -> PathBuf {
        let path = self.join(relative);
        std::fs::create_dir_all(&path).expect("create directory");
        path
    }

    /// Write a file of `size` bytes, creating parent directories.
    pub fn file(&self, relative: &str, size: usize) -> PathBuf {
        let path = self.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, vec![b'x'; size]).expect("write file");
        path
    }

    /// Write a file with specific contents.
    pub fn write(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let path = self.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, contents).expect("write file");
        path
    }

    /// A Rust project: manifest, source and build output.
    pub fn rust_project(&self, name: &str, target_bytes: usize) -> PathBuf {
        self.write(&format!("{name}/Cargo.toml"), b"[package]\nname = \"p\"\n");
        self.write(&format!("{name}/Cargo.lock"), b"# lock\n");
        self.file(&format!("{name}/src/main.rs"), 256);
        self.file(&format!("{name}/target/debug/app"), target_bytes);
        self.join(name)
    }

    /// A JavaScript project with `node_modules`.
    pub fn node_project(&self, name: &str, modules_bytes: usize) -> PathBuf {
        self.write(&format!("{name}/package.json"), b"{\"name\":\"p\"}");
        self.write(&format!("{name}/package-lock.json"), b"{}");
        self.file(&format!("{name}/src/index.js"), 128);
        self.file(
            &format!("{name}/node_modules/left-pad/index.js"),
            modules_bytes,
        );
        self.join(name)
    }

    /// A directory that merely *looks* like build output.
    pub fn decoy_target(&self, name: &str, bytes: usize) -> PathBuf {
        self.file(&format!("{name}/target/notes.docx"), bytes);
        self.join(&format!("{name}/target"))
    }

    /// Scan the fixture with default options.
    pub fn scan(&self) -> ScanResult {
        self.scan_with(|_| {})
    }

    /// Scan a subdirectory of the fixture.
    pub fn scan_path(&self, relative: &str) -> ScanResult {
        let root = self.join(relative);
        run_scan(ScanOptions::new(root))
    }

    /// Scan with customised options.
    pub fn scan_with(&self, configure: impl FnOnce(&mut ScanOptions)) -> ScanResult {
        let mut options = ScanOptions::new(&self.root);
        configure(&mut options);
        run_scan(options)
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

fn run_scan(mut options: ScanOptions) -> ScanResult {
    options.show_progress = false;
    let classifier = Classifier::with_default_detectors();
    // An empty registry keeps results identical on every developer's machine:
    // otherwise a fixture created inside someone's real `~/Downloads` would be
    // classified differently.
    let known = KnownPaths::empty();
    scanner::scan(&options, &classifier, &known).expect("scan should succeed")
}

/// Find a node by its path suffix, e.g. `"backend/target"`.
pub fn node_named<'a>(
    scan: &'a ScanResult,
    suffix: &str,
) -> Option<&'a bloatrail::scanner::tree::DirNode> {
    let needle: PathBuf = suffix.split('/').collect();
    scan.tree
        .iter()
        .find_map(|(id, node)| scan.tree.path_of(id).ends_with(&needle).then_some(node))
}

/// The detection attached to a node, if any.
pub fn detection_for<'a>(
    scan: &'a ScanResult,
    suffix: &str,
) -> Option<&'a bloatrail::analysis::Detection> {
    node_named(scan, suffix).and_then(|node| node.detection.as_ref())
}
