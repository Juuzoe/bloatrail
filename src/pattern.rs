//! A small, predictable glob matcher for exclusion patterns.
//!
//! Bloatrail deliberately implements this rather than pulling in a full glob
//! engine: exclusion rules are checked once per directory in the hot path, the
//! required semantics fit in a page of code, and users benefit from rules that
//! behave the same on every platform.
//!
//! Two shapes of pattern are supported:
//!
//! * **Name patterns** (`node_modules`, `*.tmp`) match any path component.
//! * **Path patterns** (`~/VMs`, `/mnt/archive`, `**/fixtures`) match from the
//!   start of the path, and also match everything beneath a matched directory.
//!
//! Within a segment, `*` matches any run of characters and `?` matches one. A
//! whole segment of `**` matches zero or more path components.

use std::path::{Component, Path, PathBuf};

/// A compiled exclusion pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// The pattern as written, for diagnostics.
    original: String,
    segments: Vec<String>,
    anchored: bool,
    /// `true` when the pattern names a location from the filesystem root, in
    /// which case it must match starting at the first path component.
    absolute: bool,
}

impl Pattern {
    /// Compile a pattern, expanding a leading `~` to the user's home directory.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        let original = pattern.to_string();
        let expanded = expand_home(pattern);
        let normalised = expanded.replace('\\', "/");
        let anchored = normalised.contains('/');
        let absolute = normalised.starts_with('/') || has_drive_prefix(&normalised);

        let segments: Vec<String> = normalised
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .map(normalise)
            .collect();

        Pattern {
            original,
            segments,
            anchored,
            absolute,
        }
    }

    /// The pattern text as the user wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Whether this pattern is matched against whole paths rather than names.
    #[must_use]
    pub fn is_anchored(&self) -> bool {
        self.anchored
    }

    /// Match against a bare path component. Always `false` for anchored
    /// patterns, which need the full path to be meaningful.
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        if self.anchored || self.segments.is_empty() {
            return false;
        }
        segment_matches(&self.segments[0], &normalise(name))
    }

    /// Whether `path` (whose final component is `name`) is excluded.
    #[must_use]
    pub fn matches(&self, path: &Path, name: &str) -> bool {
        if self.segments.is_empty() {
            return false;
        }
        if !self.anchored {
            return segment_matches(&self.segments[0], &normalise(name));
        }

        let components = path_components(path);
        if self.absolute {
            return match_segments(&self.segments, &components);
        }
        // A relative multi-segment pattern such as `projects/*/target` may match
        // at any depth, so try every starting position.
        (0..=components.len()).any(|start| match_segments(&self.segments, &components[start..]))
    }
}

/// Split a path into comparable components.
///
/// The root marker is dropped (it carries no name) but a Windows drive prefix is
/// kept, because `C:\x` and `D:\x` are genuinely different locations.
fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::Prefix(prefix) => prefix.as_os_str().to_str().map(normalise),
            Component::ParentDir => Some("..".to_string()),
            Component::Normal(part) => part.to_str().map(normalise),
        })
        .collect()
}

/// Whether a normalised pattern begins with a Windows drive letter.
fn has_drive_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn normalise(text: &str) -> String {
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text.to_string()
    }
}

fn expand_home(pattern: &str) -> String {
    if pattern == "~" {
        return dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| pattern.to_string());
    }
    if let Some(rest) = pattern
        .strip_prefix("~/")
        .or_else(|| pattern.strip_prefix("~\\"))
    {
        if let Some(home) = dirs::home_dir() {
            let mut path: PathBuf = home;
            for part in rest.split(['/', '\\']) {
                path.push(part);
            }
            return path.to_string_lossy().into_owned();
        }
    }
    pattern.to_string()
}

/// Match pattern segments against a *prefix* of the path components.
///
/// Matching a prefix rather than the whole path is what makes `--exclude
/// /mnt/archive` exclude the directory and everything under it.
fn match_segments(pattern: &[String], components: &[String]) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if pattern[0] == "**" {
        // Zero components consumed, or one or more.
        if match_segments(&pattern[1..], components) {
            return true;
        }
        for index in 1..=components.len() {
            if match_segments(&pattern[1..], &components[index..]) {
                return true;
            }
        }
        return false;
    }
    let Some(first) = components.first() else {
        return false;
    };
    if !segment_matches(&pattern[0], first) {
        return false;
    }
    match_segments(&pattern[1..], &components[1..])
}

/// Wildcard match for a single path component.
///
/// Iterative with backtracking: linear in the common case, and immune to the
/// pathological blow-up a naive recursive matcher shows on inputs like
/// `a*a*a*a*b`.
fn segment_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();

    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// A set of exclusion patterns.
///
/// Name patterns and path patterns are kept apart so the scanner's hot path can
/// test a file name without building the joined `PathBuf` that anchored
/// patterns require.
#[derive(Debug, Clone, Default)]
pub struct ExcludeSet {
    names: Vec<Pattern>,
    paths: Vec<Pattern>,
}

impl ExcludeSet {
    /// Compile a set from raw pattern strings.
    #[must_use]
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = ExcludeSet::default();
        for raw in patterns {
            let pattern = Pattern::new(raw.as_ref());
            if pattern.is_anchored() {
                set.paths.push(pattern);
            } else {
                set.names.push(pattern);
            }
        }
        set
    }

    /// Whether any pattern excludes this path.
    #[must_use]
    pub fn excludes(&self, path: &Path, name: &str) -> bool {
        self.excludes_name(name) || self.paths.iter().any(|p| p.matches(path, name))
    }

    /// Whether any *name* pattern excludes this component. Allocation-free.
    #[must_use]
    pub fn excludes_name(&self, name: &str) -> bool {
        self.names.iter().any(|p| p.matches_name(name))
    }

    /// Whether any anchored pattern is configured, i.e. whether callers need to
    /// build a full path before testing.
    #[must_use]
    pub fn has_path_patterns(&self) -> bool {
        !self.paths.is_empty()
    }

    /// Whether the set contains no patterns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.paths.is_empty()
    }

    /// Number of patterns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len() + self.paths.len()
    }

    /// The patterns as written.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.names
            .iter()
            .chain(self.paths.iter())
            .map(Pattern::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_patterns_match_any_component() {
        let pattern = Pattern::new("node_modules");
        assert!(pattern.matches(Path::new("/a/b/node_modules"), "node_modules"));
        assert!(!pattern.matches(Path::new("/a/b/src"), "src"));
    }

    #[test]
    fn wildcards_work_inside_a_segment() {
        let pattern = Pattern::new("*.tmp");
        assert!(pattern.matches(Path::new("/a/scratch.tmp"), "scratch.tmp"));
        assert!(!pattern.matches(Path::new("/a/scratch.txt"), "scratch.txt"));

        let question = Pattern::new("log?");
        assert!(question.matches(Path::new("/a/log1"), "log1"));
        assert!(!question.matches(Path::new("/a/log12"), "log12"));
    }

    #[test]
    fn path_patterns_exclude_the_whole_subtree() {
        let pattern = Pattern::new("/mnt/archive");
        assert!(pattern.matches(Path::new("/mnt/archive"), "archive"));
        assert!(pattern.matches(Path::new("/mnt/archive/2024/photos"), "photos"));
        assert!(!pattern.matches(Path::new("/mnt/other"), "other"));
    }

    #[test]
    fn double_star_crosses_components() {
        let pattern = Pattern::new("/projects/**/fixtures");
        assert!(pattern.matches(Path::new("/projects/a/b/fixtures"), "fixtures"));
        assert!(pattern.matches(Path::new("/projects/fixtures"), "fixtures"));
        assert!(!pattern.matches(Path::new("/other/fixtures"), "fixtures"));
    }

    #[test]
    fn star_does_not_cross_components() {
        let pattern = Pattern::new("/projects/*/target");
        assert!(pattern.matches(Path::new("/projects/api/target"), "target"));
        assert!(!pattern.matches(Path::new("/projects/api/sub/target"), "target"));
    }

    #[test]
    fn pathological_patterns_terminate_quickly() {
        // A naive recursive matcher takes exponential time on this input.
        let pattern = Pattern::new("a*a*a*a*a*a*a*b");
        let text = "a".repeat(64);
        assert!(!pattern.matches(Path::new(&text), &text));
    }

    #[test]
    fn exclude_set_reports_membership() {
        let set = ExcludeSet::new(["node_modules", "*.iso"]);
        assert_eq!(set.len(), 2);
        assert!(set.excludes(Path::new("/a/node_modules"), "node_modules"));
        assert!(set.excludes(Path::new("/a/ubuntu.iso"), "ubuntu.iso"));
        assert!(!set.excludes(Path::new("/a/src"), "src"));
        assert!(ExcludeSet::default().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn windows_matching_is_case_insensitive() {
        let pattern = Pattern::new("Node_Modules");
        assert!(pattern.matches(Path::new(r"C:\a\node_modules"), "node_modules"));
    }
}
