//! Strongly typed byte quantities plus the human-readable formatting used
//! throughout Bloatrail's terminal output.
//!
//! Sizes are rendered with binary multiples (1 KB = 1024 bytes), matching the
//! convention used by `du -h`, `dust` and most developer tooling. The suffix
//! labels stay short (`KB`/`MB`/`GB`) because they are what people read
//! fastest in a dense terminal table.

use std::fmt;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Sub};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Multiplier between two adjacent size units.
pub const UNIT: u64 = 1024;

const SUFFIXES: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];

/// A number of bytes.
///
/// Wrapping the raw `u64` keeps byte counts from being accidentally mixed with
/// file counts, durations or percentages, and gives every size a single
/// canonical rendering.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Zero bytes.
    pub const ZERO: ByteSize = ByteSize(0);

    /// Construct from a raw byte count.
    #[inline]
    #[must_use]
    pub const fn new(bytes: u64) -> Self {
        ByteSize(bytes)
    }

    /// The underlying byte count.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// `true` when this size is exactly zero.
    #[inline]
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// This size as a fraction of `total`, clamped to `0.0..=1.0`.
    ///
    /// Returns `0.0` when `total` is zero so callers never have to guard
    /// against division by zero when drawing bars.
    #[must_use]
    pub fn fraction_of(self, total: ByteSize) -> f64 {
        if total.0 == 0 {
            return 0.0;
        }
        (self.0 as f64 / total.0 as f64).clamp(0.0, 1.0)
    }

    /// Saturating subtraction; disk deltas should never wrap around.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, other: ByteSize) -> ByteSize {
        ByteSize(self.0.saturating_sub(other.0))
    }
}

/// Human-readable rendering, e.g. `82.4 GB`, `431 MB`, `12 B`.
///
/// The number of decimals is chosen per unit so that columns stay narrow while
/// large values keep enough precision to be meaningful.
impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (mut value, mut index) = scale(self.0);
        let mut decimals = decimals_for(index, value);

        // Rounding can push a value up to a whole unit: 1 048 575 bytes scales
        // to 1023.999 KB, which at zero decimals would print as "1024 KB".
        // Promote instead, so the boundary reads as "1.0 MB".
        if round_to(value, decimals) >= UNIT as f64 && index + 1 < SUFFIXES.len() {
            value /= UNIT as f64;
            index += 1;
            decimals = decimals_for(index, value);
        }

        write!(f, "{value:.decimals$} {}", SUFFIXES[index])
    }
}

/// Round `value` the same way `{:.decimals$}` will.
fn round_to(value: f64, decimals: usize) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (value * factor).round() / factor
}

/// Reduce a raw byte count to `(value, suffix_index)`.
fn scale(bytes: u64) -> (f64, usize) {
    if bytes < UNIT {
        return (bytes as f64, 0);
    }
    let mut value = bytes as f64;
    let mut index = 0usize;
    while value >= UNIT as f64 && index + 1 < SUFFIXES.len() {
        value /= UNIT as f64;
        index += 1;
    }
    (value, index)
}

/// Decimal places to show for a scaled value in the unit at `index`.
///
/// Bytes and kilobytes are noisy with decimals; gigabytes and above always keep
/// one so that a 289.6 GB directory does not collapse to `290 GB`.
fn decimals_for(index: usize, value: f64) -> usize {
    match index {
        0 => 0,
        1 | 2 if value >= 10.0 => 0,
        1 | 2 => 1,
        _ => 1,
    }
}

/// Format a byte count without constructing a [`ByteSize`] first.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    ByteSize(bytes).to_string()
}

/// Format an integer with thousands separators, e.g. `1,284,219`.
#[must_use]
pub fn format_count(value: u64) -> String {
    let digits = value.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*byte as char);
    }
    out
}

/// Format a throughput figure such as `2.8 GB/s`.
#[must_use]
pub fn format_rate(bytes: u64, seconds: f64) -> String {
    if seconds <= 0.0 {
        return "-".to_string();
    }
    let per_second = (bytes as f64 / seconds).round() as u64;
    format!("{}/s", ByteSize(per_second))
}

/// Error returned when a size string cannot be understood.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid size `{input}`: expected something like `10MB`, `1.5GiB` or `512`")]
pub struct ParseByteSizeError {
    /// The rejected input.
    pub input: String,
}

impl FromStr for ByteSize {
    type Err = ParseByteSizeError;

    /// Parse sizes such as `512`, `10MB`, `1.5 GiB`, `2g`.
    ///
    /// Both `MB` and `MiB` mean 1024-based units; Bloatrail is consistent
    /// rather than pedantic here, and the README says so.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let err = || ParseByteSizeError {
            input: s.to_string(),
        };
        if trimmed.is_empty() {
            return Err(err());
        }

        let split = trimmed
            .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '_'))
            .unwrap_or(trimmed.len());
        let (digits, suffix) = trimmed.split_at(split);
        let digits = digits.replace('_', "");
        let number: f64 = digits.parse().map_err(|_| err())?;
        if !number.is_finite() || number < 0.0 {
            return Err(err());
        }

        let suffix = suffix.trim().to_ascii_lowercase();
        let multiplier: u64 = match suffix.as_str() {
            "" | "b" => 1,
            "k" | "kb" | "kib" => UNIT,
            "m" | "mb" | "mib" => UNIT.pow(2),
            "g" | "gb" | "gib" => UNIT.pow(3),
            "t" | "tb" | "tib" => UNIT.pow(4),
            "p" | "pb" | "pib" => UNIT.pow(5),
            _ => return Err(err()),
        };

        let scaled = number * multiplier as f64;
        if scaled > u64::MAX as f64 {
            return Err(err());
        }
        Ok(ByteSize(scaled as u64))
    }
}

impl From<u64> for ByteSize {
    fn from(value: u64) -> Self {
        ByteSize(value)
    }
}

impl From<ByteSize> for u64 {
    fn from(value: ByteSize) -> Self {
        value.0
    }
}

impl Add for ByteSize {
    type Output = ByteSize;
    fn add(self, rhs: ByteSize) -> ByteSize {
        ByteSize(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for ByteSize {
    fn add_assign(&mut self, rhs: ByteSize) {
        self.0 = self.0.saturating_add(rhs.0);
    }
}

impl Sub for ByteSize {
    type Output = ByteSize;
    fn sub(self, rhs: ByteSize) -> ByteSize {
        ByteSize(self.0.saturating_sub(rhs.0))
    }
}

impl Sum for ByteSize {
    fn sum<I: Iterator<Item = ByteSize>>(iter: I) -> ByteSize {
        iter.fold(ByteSize::ZERO, |a, b| a + b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_small_values_without_decimals() {
        assert_eq!(ByteSize(0).to_string(), "0 B");
        assert_eq!(ByteSize(999).to_string(), "999 B");
    }

    #[test]
    fn formats_kilobytes_and_megabytes() {
        assert_eq!(ByteSize(1536).to_string(), "1.5 KB");
        assert_eq!(ByteSize(100 * UNIT).to_string(), "100 KB");
        assert_eq!(ByteSize(431 * UNIT.pow(2)).to_string(), "431 MB");
    }

    #[test]
    fn gigabytes_always_keep_one_decimal() {
        let bytes = (82.4 * UNIT.pow(3) as f64) as u64;
        assert_eq!(ByteSize(bytes).to_string(), "82.4 GB");
        let big = (289.6 * UNIT.pow(3) as f64) as u64;
        assert_eq!(ByteSize(big).to_string(), "289.6 GB");
    }

    #[test]
    fn values_just_below_a_boundary_promote_to_the_next_unit() {
        // 1023.999 KB must not print as "1024 KB".
        assert_eq!(ByteSize(UNIT.pow(2) - 1).to_string(), "1.0 MB");
        assert_eq!(ByteSize(UNIT.pow(3) - 1).to_string(), "1.0 GB");
        assert_eq!(ByteSize(UNIT - 1).to_string(), "1023 B");
        // And an exact boundary is unaffected.
        assert_eq!(ByteSize(UNIT.pow(2)).to_string(), "1.0 MB");
    }

    #[test]
    fn no_rendered_size_ever_shows_a_full_unit_of_the_smaller_suffix() {
        for exponent in 0..5u32 {
            for delta in [0i64, -1, 1, -2] {
                let raw = (UNIT.pow(exponent) as i64 + delta).max(0) as u64;
                let text = ByteSize(raw).to_string();
                assert!(
                    !text.starts_with("1024 ") && !text.starts_with("1024."),
                    "{raw} rendered as `{text}`"
                );
            }
        }
    }

    #[test]
    fn parses_common_size_spellings() {
        assert_eq!("512".parse::<ByteSize>().unwrap(), ByteSize(512));
        assert_eq!(
            "10MB".parse::<ByteSize>().unwrap(),
            ByteSize(10 * UNIT.pow(2))
        );
        assert_eq!(
            "10 mib".parse::<ByteSize>().unwrap(),
            ByteSize(10 * UNIT.pow(2))
        );
        assert_eq!(
            "1.5GiB".parse::<ByteSize>().unwrap(),
            ByteSize(UNIT.pow(3) + UNIT.pow(3) / 2)
        );
        assert_eq!("2g".parse::<ByteSize>().unwrap(), ByteSize(2 * UNIT.pow(3)));
    }

    #[test]
    fn rejects_nonsense_sizes() {
        for input in ["", "abc", "10 bananas", "-5MB", "1.2.3MB"] {
            assert!(
                input.parse::<ByteSize>().is_err(),
                "{input} should not parse"
            );
        }
    }

    #[test]
    fn counts_are_grouped_in_threes() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1,000");
        assert_eq!(format_count(1_284_219), "1,284,219");
    }

    #[test]
    fn fraction_of_zero_total_is_zero() {
        assert_eq!(ByteSize(10).fraction_of(ByteSize::ZERO), 0.0);
        assert_eq!(ByteSize(5).fraction_of(ByteSize(10)), 0.5);
    }

    #[test]
    fn arithmetic_saturates_instead_of_wrapping() {
        assert_eq!(ByteSize(3) - ByteSize(10), ByteSize::ZERO);
        assert_eq!(ByteSize(u64::MAX) + ByteSize(10), ByteSize(u64::MAX));
    }

    #[test]
    fn rate_formatting_handles_zero_duration() {
        assert_eq!(format_rate(100, 0.0), "-");
        assert_eq!(format_rate(2 * UNIT.pow(3), 1.0), "2.0 GB/s");
    }
}
