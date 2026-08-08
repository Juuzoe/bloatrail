//! Reclaimability scoring.
//!
//! Sorting directories by size answers "what is big". Reclaimability answers the
//! more useful question: "how much of this could I actually get back, and how
//! sure is Bloatrail about that?"

use crate::analysis::domain::{CleanupSafety, Confidence, Detection, Reclaim};
use crate::scanner::tree::Totals;
use crate::units::ByteSize;

/// How much of a location is recoverable, and how confident that estimate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reclaimable {
    /// Bytes Bloatrail believes can be recovered.
    pub bytes: ByteSize,
    /// Confidence in that figure.
    pub confidence: Confidence,
    /// Whether recovery needs an external tool rather than a file deletion.
    pub external: bool,
}

impl Reclaimable {
    /// Nothing recoverable.
    pub const NONE: Reclaimable = Reclaimable {
        bytes: ByteSize::ZERO,
        confidence: Confidence::Low,
        external: false,
    };

    /// Whether this contributes to the headline "recoverable" figure.
    #[must_use]
    pub fn is_some(self) -> bool {
        !self.bytes.is_zero()
    }
}

/// Estimate how much of a classified directory can be recovered.
///
/// `totals` must be the subtree totals for the directory, including the
/// `stale_bytes` figure the scanner accumulated for files older than the
/// configured age threshold.
#[must_use]
pub fn estimate(detection: Option<&Detection>, totals: &Totals) -> Reclaimable {
    let Some(detection) = detection else {
        return Reclaimable::NONE;
    };

    match detection.reclaim {
        Reclaim::None => Reclaimable::NONE,
        Reclaim::All => {
            if detection.cleanup.is_deletable() {
                Reclaimable {
                    bytes: ByteSize(totals.bytes),
                    confidence: detection.confidence,
                    external: false,
                }
            } else {
                Reclaimable::NONE
            }
        }
        Reclaim::OlderThan { .. } => Reclaimable {
            bytes: ByteSize(totals.stale_bytes),
            // An age-based estimate is never better than a judgement call.
            confidence: detection.confidence.min(Confidence::Medium),
            external: false,
        },
        Reclaim::External => Reclaimable {
            bytes: ByteSize(totals.bytes),
            confidence: detection.confidence.min(Confidence::Medium),
            external: true,
        },
    }
}

/// The label shown in the reclaimability column.
#[must_use]
pub fn confidence_label(detection: Option<&Detection>, reclaimable: Reclaimable) -> &'static str {
    match detection {
        Some(d) if d.cleanup == CleanupSafety::NeverDelete => "NEVER",
        _ if !reclaimable.is_some() => "—",
        _ => reclaimable.confidence.label(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::{Category, Technology};

    fn totals(bytes: u64, stale: u64) -> Totals {
        Totals {
            bytes,
            files: 1,
            dirs: 0,
            stale_bytes: stale,
        }
    }

    #[test]
    fn unclassified_directories_reclaim_nothing() {
        assert_eq!(estimate(None, &totals(1000, 500)), Reclaimable::NONE);
    }

    #[test]
    fn fully_reclaimable_build_output_returns_the_whole_size() {
        let detection = Detection::new(
            Category::BuildArtifact,
            Confidence::High,
            CleanupSafety::Safe,
            "target",
        )
        .with_technology(Technology::Rust);
        let estimate = estimate(Some(&detection), &totals(8_000, 0));
        assert_eq!(estimate.bytes, ByteSize(8_000));
        assert_eq!(estimate.confidence, Confidence::High);
        assert!(!estimate.external);
    }

    #[test]
    fn never_delete_locations_reclaim_nothing_even_when_marked_all() {
        let detection = Detection::new(
            Category::GitData,
            Confidence::Certain,
            CleanupSafety::NeverDelete,
            ".git",
        )
        .with_reclaim(Reclaim::All);
        assert_eq!(
            estimate(Some(&detection), &totals(9_000, 0)).bytes,
            ByteSize::ZERO
        );
    }

    #[test]
    fn age_based_estimates_use_only_the_stale_portion() {
        let detection = Detection::new(
            Category::Download,
            Confidence::High,
            CleanupSafety::Review,
            "Downloads",
        )
        .with_reclaim(Reclaim::OlderThan { days: 90 });
        let estimate = estimate(Some(&detection), &totals(14_000, 6_000));
        assert_eq!(estimate.bytes, ByteSize(6_000));
        assert_eq!(
            estimate.confidence,
            Confidence::Medium,
            "an age heuristic must not claim high confidence"
        );
    }

    #[test]
    fn external_reclaim_is_flagged_for_the_renderer() {
        let detection = Detection::new(
            Category::ContainerData,
            Confidence::High,
            CleanupSafety::Review,
            "Docker",
        )
        .with_reclaim(Reclaim::External);
        let estimate = estimate(Some(&detection), &totals(12_000, 0));
        assert!(estimate.external);
        assert_eq!(estimate.bytes, ByteSize(12_000));
    }

    #[test]
    fn never_delete_shows_a_never_label() {
        let detection = Detection::new(
            Category::GitData,
            Confidence::Certain,
            CleanupSafety::NeverDelete,
            ".git",
        );
        assert_eq!(
            confidence_label(Some(&detection), Reclaimable::NONE),
            "NEVER"
        );
    }
}
