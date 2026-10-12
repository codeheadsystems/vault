//! UTC time stamps: the clock in ms, the UTC day, and the `2026-10-12T15:04:05Z` text form that
//! `tokens.json`, revision metadata, and `GET /v1/revisions` use.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds in a day.
pub(crate) const DAY_MS: u64 = 86_400_000;

/// The current time in ms since the Unix epoch, or `0` for a clock before it.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Formats a time as `YYYY-MM-DDTHH:MM:SSZ`, dropping the milliseconds.
pub(crate) fn format(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Parses the form [`format`] writes. Anything else, including an impossible date, is `None`.
pub(crate) fn parse(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20 || &b[4..5] != b"-" || &b[7..8] != b"-" || &b[10..11] != b"T" {
        return None;
    }
    if &b[13..14] != b":" || &b[16..17] != b":" || &b[19..20] != b"Z" {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        let part = &s[r];
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if y < 1970 || !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 {
        return None;
    }
    if sec > 59 {
        return None;
    }
    let days = days_from_civil(y as i64, mo as u32, d as u32);
    let ms = (days as u64 * 86_400 + h * 3600 + mi * 60 + sec) * 1000;
    // An impossible day such as 02-30 does not survive the round trip.
    (format(ms) == s).then_some(ms)
}

/// The civil date of a day count since 1970-01-01, after Howard Hinnant's `civil_from_days`.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_and_parse() {
        assert_eq!(format(0), "1970-01-01T00:00:00Z");
        assert_eq!(format(1_760_281_445_999), "2025-10-12T15:04:05Z");
        assert_eq!(format(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(parse("2025-10-12T15:04:05Z"), Some(1_760_281_445_000));
        assert_eq!(parse("2000-02-29T00:00:00Z"), Some(951_782_400_000));
        for bad in [
            "2001-02-29T00:00:00Z",
            "2025-10-12 15:04:05Z",
            "2025-10-12T15:04:05",
            "2025-13-01T00:00:00Z",
            "2025-10-12T24:00:00Z",
            "+025-10-12T15:04:05Z",
            "1969-12-31T23:59:59Z",
            "",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        for day in [0, 1, 59, 365, 10_957, 20_000, 2_932_896] {
            let ms = day * DAY_MS + 3_723_000;
            assert_eq!(parse(&format(ms)), Some(ms));
        }
    }
}
