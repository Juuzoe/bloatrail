//! Library error types.
//!
//! The split is deliberate: this module holds the *domain* errors the library
//! can produce, each with enough structure for a caller to act on. The binary
//! adds human context on top with `anyhow`, so a user sees
//! "failed to read config file: permission denied" while a library consumer
//! still gets a matchable [`Error`] variant.

use std::path::PathBuf;

/// Errors produced by the Bloatrail library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The path does not exist.
    #[error("`{}` does not exist", .0.display())]
    NotFound(PathBuf),

    /// The path exists but is not a directory.
    #[error("`{}` is not a directory", .0.display())]
    NotADirectory(PathBuf),

    /// The path could not be read.
    #[error("permission denied reading `{}`", .0.display())]
    PermissionDenied(PathBuf),

    /// A filesystem operation failed.
    #[error("{path}: {source}")]
    Io {
        /// The path being operated on.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configuration file could not be parsed.
    #[error("invalid configuration in `{}`: {message}", .path.display())]
    Config {
        /// Path of the offending file.
        path: PathBuf,
        /// What was wrong with it.
        message: String,
    },

    /// A size string could not be parsed.
    #[error(transparent)]
    ParseSize(#[from] crate::units::ParseByteSizeError),

    /// The Rayon thread pool could not be created.
    #[error("could not create the worker thread pool: {0}")]
    ThreadPool(String),

    /// A refusal from the cleanup safety layer.
    ///
    /// This is not an unexpected failure: it is Bloatrail declining to do
    /// something dangerous, and the message explains why.
    #[error("refusing to delete `{}`: {reason}", .path.display())]
    RefusedDeletion {
        /// The path that was not deleted.
        path: PathBuf,
        /// Why it was refused.
        reason: String,
    },

    /// Moving an item to the trash failed.
    #[error("could not move `{}` to the trash: {message}", .path.display())]
    Trash {
        /// The path that could not be trashed.
        path: PathBuf,
        /// The underlying reason.
        message: String,
    },

    /// Serialisation of a result failed.
    #[error("could not serialise output: {0}")]
    Serialize(#[from] serde_json::Error),

    /// No previous scan is stored for a path.
    #[error("no previous scan recorded for `{}`", .0.display())]
    NoHistory(PathBuf),
}

/// Convenience alias for library results.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build an [`Error::Io`] for `path`.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    /// Build an [`Error::RefusedDeletion`].
    pub fn refused(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Error::RefusedDeletion {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_name_the_path() {
        let error = Error::NotFound(PathBuf::from("/tmp/missing"));
        assert!(error.to_string().contains("missing"));
    }

    #[test]
    fn refusals_explain_themselves() {
        let error = Error::refused("/home/dev/.ssh", "credential directory");
        let message = error.to_string();
        assert!(message.contains("refusing to delete"));
        assert!(message.contains("credential directory"));
    }

    #[test]
    fn io_errors_keep_their_source() {
        let error = Error::io(
            "/tmp/x",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope"),
        );
        assert!(std::error::Error::source(&error).is_some());
    }
}
