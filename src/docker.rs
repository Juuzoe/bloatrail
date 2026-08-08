//! Docker integration.
//!
//! Docker routinely accounts for tens of gigabytes on a developer machine, and
//! almost none of it can be recovered safely by deleting files: the engine keeps
//! its own metadata, and removing layers behind its back corrupts it.
//!
//! Bloatrail therefore *reports* Docker usage by asking the Docker CLI, and
//! recommends the official prune commands. It never touches Docker's storage
//! directly. If Docker is not installed, not running, or slow to answer, the
//! integration reports "unavailable" and every other command carries on.

use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde::Deserialize;

use crate::units::ByteSize;

/// How long to wait for the Docker CLI before giving up.
///
/// A stopped Docker Desktop can block for a long time; no disk report is worth
/// hanging a terminal over.
const TIMEOUT: Duration = Duration::from_secs(5);

/// One row of `docker system df`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerUsage {
    /// `Images`, `Containers`, `Local Volumes` or `Build Cache`.
    pub kind: DockerResource,
    /// Total space used.
    pub size: ByteSize,
    /// Space Docker reports as reclaimable.
    pub reclaimable: ByteSize,
    /// Number of items.
    pub count: u64,
}

/// The kinds of storage Docker reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerResource {
    /// Image layers.
    Images,
    /// Container writable layers.
    Containers,
    /// Named and anonymous volumes.
    Volumes,
    /// BuildKit cache.
    BuildCache,
}

impl DockerResource {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            DockerResource::Images => "Images",
            DockerResource::Containers => "Containers",
            DockerResource::Volumes => "Volumes",
            DockerResource::BuildCache => "Build cache",
        }
    }

    /// The command that reclaims this kind of storage.
    #[must_use]
    pub const fn prune_command(self) -> &'static str {
        match self {
            DockerResource::Images => "docker image prune -a",
            DockerResource::Containers => "docker container prune",
            DockerResource::Volumes => "docker volume prune",
            DockerResource::BuildCache => "docker builder prune",
        }
    }

    /// Whether removing this can destroy data that exists nowhere else.
    ///
    /// Volumes are the dangerous one: a pruned volume takes your local database
    /// with it.
    #[must_use]
    pub const fn holds_persistent_data(self) -> bool {
        matches!(self, DockerResource::Volumes)
    }

    fn from_type(value: &str) -> Option<Self> {
        match value {
            "Images" => Some(DockerResource::Images),
            "Containers" => Some(DockerResource::Containers),
            "Local Volumes" => Some(DockerResource::Volumes),
            "Build Cache" => Some(DockerResource::BuildCache),
            _ => None,
        }
    }
}

/// What Bloatrail could learn about Docker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerStatus {
    /// Docker answered.
    Available {
        /// One entry per resource kind.
        usage: Vec<DockerUsage>,
    },
    /// The `docker` executable was not found.
    NotInstalled,
    /// Docker is installed but did not answer.
    NotRunning {
        /// What it said, when it said anything.
        detail: String,
    },
    /// Bloatrail was asked not to look.
    ///
    /// Distinct from [`DockerStatus::NotInstalled`] so that `--no-docker` never
    /// makes a machine that has Docker look like one that does not.
    NotChecked,
}

impl DockerStatus {
    /// Total reclaimable space across all resource kinds.
    #[must_use]
    pub fn reclaimable(&self) -> ByteSize {
        match self {
            DockerStatus::Available { usage } => {
                usage.iter().map(|u| u.reclaimable).sum::<ByteSize>()
            }
            _ => ByteSize::ZERO,
        }
    }

    /// Total space Docker occupies.
    #[must_use]
    pub fn total(&self) -> ByteSize {
        match self {
            DockerStatus::Available { usage } => usage.iter().map(|u| u.size).sum::<ByteSize>(),
            _ => ByteSize::ZERO,
        }
    }

    /// Whether Docker reported anything.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, DockerStatus::Available { .. })
    }
}

/// The shape of one `docker system df --format '{{json .}}'` line.
#[derive(Debug, Deserialize)]
struct DfRow {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Size")]
    size: String,
    #[serde(rename = "Reclaimable")]
    reclaimable: String,
    #[serde(rename = "TotalCount", default)]
    total_count: String,
}

/// Query Docker for its disk usage.
///
/// Never fails: everything that can go wrong is represented in [`DockerStatus`].
#[must_use]
pub fn status() -> DockerStatus {
    match run_docker_df() {
        Ok(output) => DockerStatus::Available {
            usage: parse_df(&output),
        },
        Err(DockerError::NotInstalled) => DockerStatus::NotInstalled,
        Err(DockerError::Failed(detail)) => DockerStatus::NotRunning { detail },
    }
}

enum DockerError {
    NotInstalled,
    Failed(String),
}

fn run_docker_df() -> std::result::Result<String, DockerError> {
    let (sender, receiver) = mpsc::channel();

    // `Command::output` has no timeout, so the wait happens on its own thread
    // and the caller gives up after `TIMEOUT` regardless.
    std::thread::spawn(move || {
        let result = Command::new("docker")
            .args(["system", "df", "--format", "{{json .}}"])
            .stdin(Stdio::null())
            .output();
        let _ = sender.send(result);
    });

    match receiver.recv_timeout(TIMEOUT) {
        Ok(Ok(output)) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(Ok(output)) => Err(DockerError::Failed(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("docker returned a non-zero exit status")
                .to_string(),
        )),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(DockerError::NotInstalled)
        }
        Ok(Err(error)) => Err(DockerError::Failed(error.to_string())),
        Err(_) => Err(DockerError::Failed(
            "docker did not respond within 5 seconds".to_string(),
        )),
    }
}

/// Parse the newline-delimited JSON emitted by `docker system df`.
fn parse_df(output: &str) -> Vec<DockerUsage> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(row) = serde_json::from_str::<DfRow>(line) else {
            continue;
        };
        let Some(kind) = DockerResource::from_type(&row.kind) else {
            continue;
        };
        rows.push(DockerUsage {
            kind,
            size: ByteSize(parse_docker_size(&row.size)),
            reclaimable: ByteSize(parse_docker_size(&row.reclaimable)),
            count: row.total_count.trim().parse().unwrap_or(0),
        });
    }
    rows
}

/// Parse Docker's own size strings: `8.4GB`, `1.2 MB`, `0B`, `3.1GB (100%)`.
///
/// Docker uses decimal units here, so this is not [`crate::units::ByteSize`]'s
/// parser: reusing it would silently inflate every figure by 7%.
fn parse_docker_size(text: &str) -> u64 {
    let text = text.trim();
    let text = text.split('(').next().unwrap_or(text).trim();
    if text.is_empty() {
        return 0;
    }

    let split = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (number, suffix) = text.split_at(split);
    let Ok(value) = number.parse::<f64>() else {
        return 0;
    };

    let multiplier: f64 = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "kb" | "k" => 1e3,
        "mb" | "m" => 1e6,
        "gb" | "g" => 1e9,
        "tb" | "t" => 1e12,
        "kib" => 1024.0,
        "mib" => 1024.0f64.powi(2),
        "gib" => 1024.0f64.powi(3),
        "tib" => 1024.0f64.powi(4),
        _ => return 0,
    };

    (value * multiplier).max(0.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_decimal_sizes() {
        assert_eq!(parse_docker_size("0B"), 0);
        assert_eq!(parse_docker_size("8.4GB"), 8_400_000_000);
        assert_eq!(parse_docker_size("1.2 MB"), 1_200_000);
        assert_eq!(parse_docker_size("750kB"), 750_000);
    }

    #[test]
    fn strips_the_percentage_docker_appends_to_reclaimable() {
        assert_eq!(parse_docker_size("3.1GB (100%)"), 3_100_000_000);
        assert_eq!(parse_docker_size("0B (0%)"), 0);
    }

    #[test]
    fn unparseable_sizes_become_zero_rather_than_panicking() {
        assert_eq!(parse_docker_size(""), 0);
        assert_eq!(parse_docker_size("N/A"), 0);
        assert_eq!(parse_docker_size("12 bananas"), 0);
    }

    #[test]
    fn parses_a_realistic_df_payload() {
        let output = r#"
{"Type":"Images","TotalCount":"12","Active":"3","Size":"8.4GB","Reclaimable":"5.1GB (60%)"}
{"Type":"Containers","TotalCount":"4","Active":"1","Size":"750MB","Reclaimable":"600MB (80%)"}
{"Type":"Local Volumes","TotalCount":"7","Active":"2","Size":"9.2GB","Reclaimable":"1.1GB (11%)"}
{"Type":"Build Cache","TotalCount":"40","Active":"0","Size":"3.1GB","Reclaimable":"3.1GB (100%)"}
"#;
        let rows = parse_df(output);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].kind, DockerResource::Images);
        assert_eq!(rows[0].size, ByteSize(8_400_000_000));
        assert_eq!(rows[0].count, 12);
        assert_eq!(rows[2].kind, DockerResource::Volumes);
        assert!(rows[2].kind.holds_persistent_data());
        assert!(!rows[0].kind.holds_persistent_data());

        let status = DockerStatus::Available { usage: rows };
        assert_eq!(
            status.reclaimable(),
            ByteSize(5_100_000_000 + 600_000_000 + 1_100_000_000 + 3_100_000_000)
        );
        assert!(status.is_available());
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let output = "not json\n{\"Type\":\"Images\",\"Size\":\"1GB\",\"Reclaimable\":\"1GB\",\"TotalCount\":\"1\"}\n";
        let rows = parse_df(output);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn unavailable_docker_reports_nothing_reclaimable() {
        assert_eq!(DockerStatus::NotInstalled.reclaimable(), ByteSize::ZERO);
        assert_eq!(DockerStatus::NotInstalled.total(), ByteSize::ZERO);
        assert!(!DockerStatus::NotInstalled.is_available());
    }

    #[test]
    fn prune_commands_are_specific_to_the_resource() {
        assert_eq!(
            DockerResource::Volumes.prune_command(),
            "docker volume prune"
        );
        assert_eq!(
            DockerResource::BuildCache.prune_command(),
            "docker builder prune"
        );
    }
}
