//! Minimal timestamp formatting for exports (no date crate needed for this much).

/// Real-world UTC offsets stay within +-14 hours.
pub const MAX_OFFSET_MINUTES: i32 = 14 * 60;

struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

/// Unix time in ms, shifted by `offset_minutes`, as calendar date and time.
fn civil(ms: u64, offset_minutes: i32) -> Civil {
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX / 2) + i64::from(offset_minutes) * 60;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: (rem % 3600 / 60) as u32,
        second: (rem % 60) as u32,
    }
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian calendar
/// (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `+01:00`, `-05:30`, or `Z` for UTC.
fn offset_suffix(offset_minutes: i32) -> String {
    if offset_minutes == 0 {
        return "Z".into();
    }
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let abs = offset_minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", abs / 60, abs % 60)
}

/// RFC 3339, e.g. `2026-11-14T19:30:05+01:00`.
pub fn rfc3339(ms: u64, offset_minutes: i32) -> String {
    let c = civil(ms, offset_minutes);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        offset_suffix(offset_minutes)
    )
}

/// `2026-11-14 19:30:05 (UTC+01:00)` for reports.
pub fn readable(ms: u64, offset_minutes: i32) -> String {
    let c = civil(ms, offset_minutes);
    let zone = match offset_suffix(offset_minutes).as_str() {
        "Z" => "UTC".to_owned(),
        suffix => format!("UTC{suffix}"),
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} ({zone})",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// `20261114-1930` for default file names.
pub fn file_stamp(ms: u64, offset_minutes: i32) -> String {
    let c = civil(ms, offset_minutes);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}",
        c.year, c.month, c.day, c.hour, c.minute
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_utc_instants() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000_000, 0), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339(1_234_567_890_999, 0), "2009-02-13T23:31:30Z");
        // Leap days, including the 400-year rule.
        assert_eq!(rfc3339(951_782_400_000, 0), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_709_164_800_000, 0), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(4_107_542_399_000, 0), "2100-02-28T23:59:59Z");
        assert_eq!(rfc3339(4_107_542_400_000, 0), "2100-03-01T00:00:00Z");
    }

    #[test]
    fn offsets_shift_the_local_time() {
        let ms = 1_763_145_000_000; // 2025-11-14T18:30:00Z
        assert_eq!(rfc3339(ms, 0), "2025-11-14T18:30:00Z");
        assert_eq!(rfc3339(ms, 60), "2025-11-14T19:30:00+01:00");
        assert_eq!(rfc3339(ms, -330), "2025-11-14T13:00:00-05:30");
        // Crossing midnight and the year boundary.
        assert_eq!(rfc3339(ms, MAX_OFFSET_MINUTES), "2025-11-15T08:30:00+14:00");
        assert_eq!(rfc3339(0, -60), "1969-12-31T23:00:00-01:00");
    }

    #[test]
    fn readable_and_file_names() {
        let ms = 1_763_145_005_000;
        assert_eq!(readable(ms, 60), "2025-11-14 19:30:05 (UTC+01:00)");
        assert_eq!(readable(ms, 0), "2025-11-14 18:30:05 (UTC)");
        assert_eq!(file_stamp(ms, 60), "20251114-1930");
    }
}
