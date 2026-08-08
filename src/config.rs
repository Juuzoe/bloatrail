//! Optional configuration file support.
//!
//! Precedence is the conventional one — **defaults < config file < command
//! line** — and it is implemented in one place so it cannot drift between
//! commands. Every setting has a defensible default, so the file is genuinely
//! optional: most users will never create one.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::units::ByteSize;

/// File name looked for inside the platform config directory.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Directory name used under the platform config and data directories.
pub const APP_DIR: &str = "bloatrail";

/// Environment variable that overrides where Bloatrail keeps its state.
pub const HOME_ENV: &str = "BLOATRAIL_HOME";

/// The on-disk configuration schema.
///
/// Every field is optional; absent fields fall through to the defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ConfigFile {
    /// Patterns never to descend into.
    pub exclude: Option<Vec<String>>,
    /// Hide entries below this size, e.g. `"10MB"`.
    pub min_size: Option<String>,
    /// Worker thread count.
    pub threads: Option<usize>,
    /// Follow symbolic links.
    pub follow_symlinks: Option<bool>,
    /// Traverse dot-directories.
    pub include_hidden: Option<bool>,
    /// Stay on one filesystem.
    pub same_filesystem: Option<bool>,
    /// Default tree depth.
    pub depth: Option<usize>,
    /// Default number of rows in ranked output.
    pub top: Option<usize>,
    /// Restrict output to ASCII.
    pub ascii: Option<bool>,
    /// Age in days above which a file counts as stale.
    pub stale_days: Option<u32>,
}

/// Command-line values that override the config file.
///
/// `None` means "not specified on the command line", which is what makes the
/// precedence rule expressible without sentinel values.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    /// Additional exclusion patterns.
    pub exclude: Vec<String>,
    /// Minimum displayed size.
    pub min_size: Option<ByteSize>,
    /// Worker thread count.
    pub threads: Option<usize>,
    /// Follow symbolic links.
    pub follow_symlinks: Option<bool>,
    /// Traverse dot-directories.
    pub include_hidden: Option<bool>,
    /// Stay on one filesystem.
    pub same_filesystem: Option<bool>,
    /// Tree depth.
    pub depth: Option<usize>,
    /// Rows in ranked output.
    pub top: Option<usize>,
    /// Restrict output to ASCII.
    pub ascii: Option<bool>,
}

/// Fully resolved settings.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Exclusion patterns from every source, in order.
    pub exclude: Vec<String>,
    /// Hide entries below this size.
    pub min_size: ByteSize,
    /// Worker threads, or `None` for "decide automatically".
    pub threads: Option<usize>,
    /// Follow symbolic links.
    pub follow_symlinks: bool,
    /// Traverse dot-directories that are not on the always-traverse list.
    pub include_hidden: bool,
    /// Stay on the scan root's filesystem.
    pub same_filesystem: bool,
    /// Tree depth.
    pub depth: usize,
    /// Rows in ranked output.
    pub top: usize,
    /// Restrict output to ASCII.
    pub ascii: bool,
    /// Age in days above which a file counts as stale.
    pub stale_days: u32,
    /// The config file that was loaded, if any.
    pub source: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            exclude: Vec::new(),
            min_size: ByteSize::ZERO,
            threads: None,
            follow_symlinks: false,
            include_hidden: false,
            same_filesystem: false,
            depth: 2,
            top: 10,
            ascii: false,
            stale_days: crate::scanner::DEFAULT_STALE_DAYS,
            source: None,
        }
    }
}

impl Settings {
    /// Apply a parsed config file on top of the defaults.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `min_size` cannot be parsed.
    pub fn apply_file(mut self, file: ConfigFile, path: &Path) -> Result<Self> {
        if let Some(exclude) = file.exclude {
            self.exclude.extend(exclude);
        }
        if let Some(raw) = file.min_size {
            self.min_size = raw.parse::<ByteSize>().map_err(|error| Error::Config {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
        }
        if let Some(threads) = file.threads {
            self.threads = Some(threads);
        }
        if let Some(value) = file.follow_symlinks {
            self.follow_symlinks = value;
        }
        if let Some(value) = file.include_hidden {
            self.include_hidden = value;
        }
        if let Some(value) = file.same_filesystem {
            self.same_filesystem = value;
        }
        if let Some(depth) = file.depth {
            self.depth = depth;
        }
        if let Some(top) = file.top {
            self.top = top;
        }
        if let Some(ascii) = file.ascii {
            self.ascii = ascii;
        }
        if let Some(days) = file.stale_days {
            self.stale_days = days;
        }
        self.source = Some(path.to_path_buf());
        Ok(self)
    }

    /// Apply command-line overrides, which win over everything.
    #[must_use]
    pub fn apply_overrides(mut self, overrides: &Overrides) -> Self {
        self.exclude.extend(overrides.exclude.iter().cloned());
        if let Some(min_size) = overrides.min_size {
            self.min_size = min_size;
        }
        if let Some(threads) = overrides.threads {
            self.threads = Some(threads);
        }
        if let Some(value) = overrides.follow_symlinks {
            self.follow_symlinks = value;
        }
        if let Some(value) = overrides.include_hidden {
            self.include_hidden = value;
        }
        if let Some(value) = overrides.same_filesystem {
            self.same_filesystem = value;
        }
        if let Some(depth) = overrides.depth {
            self.depth = depth;
        }
        if let Some(top) = overrides.top {
            self.top = top;
        }
        if let Some(ascii) = overrides.ascii {
            self.ascii = ascii;
        }
        self
    }
}

/// Load configuration.
///
/// `explicit` comes from `--config`; when it is given, a missing file is an
/// error rather than a silent fallback.
///
/// # Errors
///
/// Returns [`Error::Config`] for unreadable or malformed files.
pub fn load(explicit: Option<&Path>, overrides: &Overrides) -> Result<Settings> {
    let settings = Settings::default();

    let path = match explicit {
        Some(path) => Some(path.to_path_buf()),
        None => default_config_path().filter(|p| p.exists()),
    };

    let settings = match path {
        Some(path) => {
            let text = std::fs::read_to_string(&path).map_err(|error| Error::Config {
                path: path.clone(),
                message: error.to_string(),
            })?;
            let file: ConfigFile = toml::from_str(&text).map_err(|error| Error::Config {
                path: path.clone(),
                message: error.to_string(),
            })?;
            settings.apply_file(file, &path)?
        }
        None => settings,
    };

    Ok(settings.apply_overrides(overrides))
}

/// The conventional configuration path for this platform.
///
/// * Linux: `~/.config/bloatrail/config.toml`
/// * macOS: `~/Library/Application Support/bloatrail/config.toml`
/// * Windows: `%APPDATA%\bloatrail\config.toml`
#[must_use]
pub fn default_config_path() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os(HOME_ENV) {
        return Some(PathBuf::from(home).join(CONFIG_FILE_NAME));
    }
    dirs::config_dir().map(|dir| dir.join(APP_DIR).join(CONFIG_FILE_NAME))
}

/// Where Bloatrail stores scan history.
#[must_use]
pub fn data_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os(HOME_ENV) {
        return Some(PathBuf::from(home));
    }
    dirs::data_dir().map(|dir| dir.join(APP_DIR))
}

/// A commented starter configuration, printed by `bloatrail config --example`.
#[must_use]
pub fn example() -> String {
    format!(
        r#"# Bloatrail configuration
# Location: {}
#
# Every setting is optional. Command-line flags override anything set here.

# Never descend into these. Bare names match any directory; anything with a
# separator is matched against the whole path. `*`, `?` and `**` are supported.
exclude = [
    # "/mnt/archive",
    # "~/VMs",
    # "*.iso",
]

# Hide entries smaller than this in `tree` and `largest` output, and use it as a
# floor for `duplicates`. It never affects the totals, only what is displayed.
min_size = "1MB"

# Worker threads. Omit to use one per available core.
# threads = 8

# Follow symbolic links and Windows junctions. Off by default because it makes
# double-counting and loops possible.
follow_symlinks = false

# Traverse dot-directories that are not on the built-in always-traverse list.
include_hidden = false

# Refuse to cross filesystem boundaries.
same_filesystem = false

# Default depth for `bloatrail tree`.
depth = 2

# Default number of rows in `bloatrail largest`.
top = 10

# Use ASCII box drawing instead of Unicode.
ascii = false

# Age, in days, above which a file counts towards the "stale" figures used for
# Downloads and temporary-file suggestions.
stale_days = 90
"#,
        default_config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_usable_without_a_file() {
        let settings = Settings::default();
        assert!(settings.exclude.is_empty());
        assert_eq!(settings.min_size, ByteSize::ZERO);
        assert!(!settings.follow_symlinks);
        assert_eq!(settings.depth, 2);
        assert!(settings.source.is_none());
    }

    #[test]
    fn a_config_file_overrides_defaults() {
        let file: ConfigFile = toml::from_str(
            r#"
            exclude = ["/mnt/archive"]
            min_size = "10MB"
            threads = 4
            follow_symlinks = true
            depth = 5
            "#,
        )
        .expect("valid toml");

        let settings = Settings::default()
            .apply_file(file, Path::new("/tmp/config.toml"))
            .expect("apply");
        assert_eq!(settings.exclude, vec!["/mnt/archive".to_string()]);
        assert_eq!(settings.min_size, ByteSize(10 * 1024 * 1024));
        assert_eq!(settings.threads, Some(4));
        assert!(settings.follow_symlinks);
        assert_eq!(settings.depth, 5);
        assert_eq!(
            settings.source.as_deref(),
            Some(Path::new("/tmp/config.toml"))
        );
    }

    #[test]
    fn command_line_overrides_beat_the_config_file() {
        let file: ConfigFile = toml::from_str(
            r#"
            min_size = "10MB"
            threads = 4
            depth = 5
            "#,
        )
        .expect("valid toml");

        let overrides = Overrides {
            min_size: Some(ByteSize(1024)),
            threads: Some(16),
            depth: Some(1),
            ..Overrides::default()
        };

        let settings = Settings::default()
            .apply_file(file, Path::new("/tmp/config.toml"))
            .expect("apply")
            .apply_overrides(&overrides);

        assert_eq!(settings.min_size, ByteSize(1024));
        assert_eq!(settings.threads, Some(16));
        assert_eq!(settings.depth, 1);
    }

    #[test]
    fn exclusions_from_both_sources_are_combined() {
        let file: ConfigFile = toml::from_str(r#"exclude = ["a"]"#).expect("valid toml");
        let overrides = Overrides {
            exclude: vec!["b".to_string()],
            ..Overrides::default()
        };
        let settings = Settings::default()
            .apply_file(file, Path::new("/tmp/c.toml"))
            .expect("apply")
            .apply_overrides(&overrides);
        assert_eq!(settings.exclude, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn an_invalid_size_names_the_config_file() {
        let file = ConfigFile {
            min_size: Some("banana".to_string()),
            ..ConfigFile::default()
        };
        let error = Settings::default()
            .apply_file(file, Path::new("/tmp/config.toml"))
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("config.toml"), "got: {message}");
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_ignored() {
        let result: std::result::Result<ConfigFile, _> = toml::from_str(r#"mn_size = "10MB""#);
        assert!(result.is_err(), "a typo should not be silently ignored");
    }

    #[test]
    fn the_example_config_parses() {
        let text = example();
        let parsed: std::result::Result<ConfigFile, _> = toml::from_str(&text);
        assert!(parsed.is_ok(), "example config must be valid: {parsed:?}");
    }
}
