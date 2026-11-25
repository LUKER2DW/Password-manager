//! Minimal ISO-8601 parsing (`YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]`) to Unix seconds.

/// Returns `None` for anything that does not look like an ISO-8601 timestamp.
pub(crate) fn iso8601_to_unix(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, time) = text.split_once(['T', ' '])?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    // The file says what it likes: years that fit the calculation below only.
    if date_parts.next().is_some()
        || !(0..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }

    // Split off the timezone suffix.
    let (clock, offset_seconds) = if let Some(clock) = time.strip_suffix(['Z', 'z']) {
        (clock, 0)
    } else if let Some(position) = time.rfind(['+', '-']).filter(|&p| p >= 8) {
        let (clock, zone) = time.split_at(position);
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let (hours, minutes) = zone[1..].split_once(':').unwrap_or((zone.get(1..3)?, "0"));
        let (hours, minutes) = (hours.parse::<i64>().ok()?, minutes.parse::<i64>().ok()?);
        if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
            return None;
        }
        (clock, sign * (hours * 3600 + minutes * 60))
    } else {
        (time, 0)
    };
    let clock = clock.split('.').next()?;
    let mut clock_parts = clock.split(':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next().unwrap_or("0").parse().ok()?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=60).contains(&second) {
        return None;
    }

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps() {
        assert_eq!(iso8601_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            iso8601_to_unix("2023-11-14T22:13:20.000Z"),
            Some(1_700_000_000)
        );
        assert_eq!(
            iso8601_to_unix("2023-11-14T22:13:20.123456Z"),
            Some(1_700_000_000)
        );
        assert_eq!(
            iso8601_to_unix("2023-11-15T00:13:20+02:00"),
            Some(1_700_000_000)
        );
        assert_eq!(iso8601_to_unix("2000-02-29 12:00:00"), Some(951_825_600));
    }

    #[test]
    fn a_date_made_to_break_the_reader_is_only_unreadable() {
        for text in [
            "9223372036854775807-01-01T00:00:00Z",
            "-9223372036854775808-01-01T00:00:00Z",
            "2023-11-14T22:13:20+9223372036854775807:00",
            "2023-11-14T22:13:20+00:9223372036854775807",
            "2023-11-14T-9223372036854775808:00:00Z",
            "2023-11-14T22:13:20+€",
            "2023-11-14T22:13:20+",
            "2023-11-14T22:13:20+1",
        ] {
            assert_eq!(iso8601_to_unix(text), None, "{text}");
        }
        assert_eq!(
            iso8601_to_unix("2023-11-15T00:13:20+02"),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(iso8601_to_unix(""), None);
        assert_eq!(iso8601_to_unix("yesterday"), None);
        assert_eq!(iso8601_to_unix("2023-13-01T00:00:00Z"), None);
    }
}
