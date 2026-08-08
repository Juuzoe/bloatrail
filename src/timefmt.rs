//! Minimal date and duration formatting.
//!
//! Bloatrail needs exactly two things from a calendar — "when was this scan"
//! and "how long ago" — which is not enough to justify a date-time dependency.
//! The civil-date conversion below is the standard days-from-epoch algorithm and
//! is exercised by the tests at the bottom of this file.

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM` in UTC.
#[must_use]
pub fn format_timestamp(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let time_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hours = time_of_day / 3_600;
    let minutes = (time_of_day % 3_600) / 60;
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02} UTC")
}

/// Describe how long ago `seconds` was, relative to `now`.
#[must_use]
pub fn humanize_age(seconds: u64, now: u64) -> String {
    let elapsed = now.saturating_sub(seconds);
    match elapsed {
        0..=59 => "just now".to_string(),
        60..=3_599 => plural(elapsed / 60, "minute"),
        3_600..=86_399 => plural(elapsed / 3_600, "hour"),
        86_400..=2_591_999 => plural(elapsed / 86_400, "day"),
        2_592_000..=31_535_999 => plural(elapsed / 2_592_000, "month"),
        _ => plural(elapsed / 31_536_000, "year"),
    }
}

fn plural(value: u64, unit: &str) -> String {
    if value == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{value} {unit}s ago")
    }
}

/// Seconds since the Unix epoch, or `0` if the clock is before 1970.
#[must_use]
pub fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convert days since the Unix epoch to a civil `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, which is exact for the whole range of
/// dates a filesystem can produce and needs no lookup tables.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_correctly() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn known_timestamps_round_trip() {
        // 2024-02-29T12:34:00Z — a leap day, which is where naive
        // implementations break.
        assert_eq!(format_timestamp(1_709_210_040), "2024-02-29 12:34 UTC");
        // 2000-03-01T00:00:00Z — the century leap year.
        assert_eq!(format_timestamp(951_868_800), "2000-03-01 00:00 UTC");
        // 2026-08-08T09:05:00Z
        assert_eq!(format_timestamp(1_786_179_900), "2026-08-08 09:05 UTC");
    }

    #[test]
    fn ages_are_described_in_the_largest_sensible_unit() {
        let now = 1_000_000_000;
        assert_eq!(humanize_age(now, now), "just now");
        assert_eq!(humanize_age(now - 60, now), "1 minute ago");
        assert_eq!(humanize_age(now - 7_200, now), "2 hours ago");
        assert_eq!(humanize_age(now - 86_400, now), "1 day ago");
        assert_eq!(humanize_age(now - 86_400 * 45, now), "1 month ago");
        assert_eq!(humanize_age(now - 86_400 * 400, now), "1 year ago");
    }

    #[test]
    fn future_timestamps_do_not_underflow() {
        assert_eq!(humanize_age(2_000, 1_000), "just now");
    }
}
