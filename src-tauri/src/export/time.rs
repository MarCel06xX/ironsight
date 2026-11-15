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

/// Days since 1970-01-01 of a proleptic Gregorian date (inverse of [`civil_from_days`]).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)` into Unix milliseconds.
/// Anything else (or a time before 1970) yields `None`.
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = |from: usize, to: usize| -> Option<u32> {
        let part = text.get(from..to)?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let separator =
        |at: usize, allowed: &[u8]| text.as_bytes().get(at).is_some_and(|b| allowed.contains(b));
    if !(separator(4, b"-")
        && separator(7, b"-")
        && separator(10, b"Tt ")
        && separator(13, b":")
        && separator(16, b":"))
    {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    let (hour, minute, second) = (digits(11, 13)?, digits(14, 16)?, digits(17, 19)?);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = text.get(19..)?;
    let mut millis = 0u64;
    if let Some(fraction) = rest.strip_prefix('.') {
        let count = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if count == 0 {
            return None;
        }
        let padded = format!("{:0<3}", &fraction[..count.min(3)]);
        millis = padded.parse().ok()?;
        rest = &fraction[count..];
    }
    let offset_minutes: i64 = match rest {
        "Z" | "z" => 0,
        _ => {
            let bytes = rest.as_bytes();
            if bytes.len() != 6 || bytes[3] != b':' {
                return None;
            }
            let sign = match bytes[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let hours: i64 = rest.get(1..3)?.parse().ok()?;
            let mins: i64 = rest.get(4..6)?.parse().ok()?;
            if hours > 23 || mins > 59 {
                return None;
            }
            sign * (hours * 60 + mins)
        }
    };
    let secs = days_from_civil(i64::from(year), month, day) * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second.min(59))
        - offset_minutes * 60;
    u64::try_from(secs).ok().map(|s| s * 1000 + millis)
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
    fn parses_what_it_writes() {
        for ms in [
            0,
            951_782_400_000,
            1_709_164_800_000,
            1_763_145_005_000,
            4_107_542_400_000,
        ] {
            for offset in [0, 60, -330, MAX_OFFSET_MINUTES] {
                assert_eq!(
                    parse_rfc3339(&rfc3339(ms, offset)),
                    Some(ms),
                    "{ms} {offset}"
                );
            }
        }
    }

    #[test]
    fn parses_fractions_and_rejects_garbage() {
        assert_eq!(
            parse_rfc3339("2025-11-14T18:30:00.5Z"),
            Some(1_763_145_000_500)
        );
        assert_eq!(
            parse_rfc3339("2025-11-14t18:30:00.123456z"),
            Some(1_763_145_000_123)
        );
        assert_eq!(
            parse_rfc3339(" 2025-11-14 19:30:00+01:00 "),
            Some(1_763_145_000_000)
        );
        for bad in [
            "",
            "2025-11-14",
            "2025-11-14T18:30:00",
            "2025-13-01T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2025-11-14T24:00:00Z",
            "2025-11-14T18:30:00+1:00",
            "2025-11-14T18:30:00.Z",
            "1969-12-31T23:59:59Z",
            "2025-11-14T18:30:00Zjunk",
            "２０２５-11-14T18:30:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
        assert_eq!(
            parse_rfc3339("2024-02-29T00:00:00Z"),
            Some(1_709_164_800_000)
        );
    }

    #[test]
    fn readable_and_file_names() {
        let ms = 1_763_145_005_000;
        assert_eq!(readable(ms, 60), "2025-11-14 19:30:05 (UTC+01:00)");
        assert_eq!(readable(ms, 0), "2025-11-14 18:30:05 (UTC)");
        assert_eq!(file_stamp(ms, 60), "20251114-1930");
    }
}
