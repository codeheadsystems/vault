//! RFC 3339 times, as Bitwarden writes them (`2024-03-14T15:09:26.535Z`), to and from ms.

const DAY_MS: i64 = 86_400_000;
/// 9999-12-31T23:59:59.999Z, the last time with a four-digit year.
pub(crate) const MAX_MS: u64 = 253_402_300_799_999;

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day count since 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn num(s: &[u8]) -> Option<i64> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0, |n, &c| n * 10 + i64::from(c - b'0')))
}

/// Parses an RFC 3339 time with a four-digit year, any number of fraction digits (truncated to
/// ms), and `Z` or a `±hh:mm` offset. A time before 1970 is `Some(0)`; text that is not such a
/// time is `None`.
pub(crate) fn parse_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if !matches!(b[10], b'T' | b't') {
        return None;
    }
    let (y, mo, d) = (num(&b[0..4])?, num(&b[5..7])?, num(&b[8..10])?);
    let (h, mi, sec) = (num(&b[11..13])?, num(&b[14..16])?, num(&b[17..19])?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    // A leap second (`:60`) is accepted and counts as the next second.
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &b[19..];
    let mut ms = 0;
    if let Some(frac) = rest.strip_prefix(b".") {
        let n = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        let mut digits = [b'0'; 3];
        for (i, &c) in frac[..n.min(3)].iter().enumerate() {
            digits[i] = c;
        }
        ms = num(&digits)?;
        rest = &frac[n..];
    }
    let offset_min = match rest {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), oh1, oh2, b':', om1, om2] => {
            let (oh, om) = (num(&[*oh1, *oh2])?, num(&[*om1, *om2])?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 60 + om;
            if *sign == b'-' { -o } else { o }
        }
        _ => return None,
    };
    let t =
        days_from_civil(y, mo, d) * DAY_MS + ((h * 60 + mi - offset_min) * 60 + sec) * 1000 + ms;
    Some(u64::try_from(t).unwrap_or(0))
}

/// Formats ms as `YYYY-MM-DDTHH:MM:SS.mmmZ`. A time after year 9999 is written as
/// [`MAX_MS`], the last one RFC 3339 can express.
pub(crate) fn format_ms(ms: u64) -> String {
    let ms = ms.min(MAX_MS) as i64;
    let (days, rem) = (ms.div_euclid(DAY_MS), ms.rem_euclid(DAY_MS));
    let (y, m, d) = civil_from_days(days);
    let (s, milli) = (rem / 1000, rem % 1000);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        for (text, ms) in [
            ("1970-01-01T00:00:00.000Z", 0),
            ("2024-03-14T15:09:26.535Z", 1_710_428_966_535),
            ("2000-02-29T23:59:59.999Z", 951_868_799_999),
            ("9999-12-31T23:59:59.999Z", MAX_MS),
        ] {
            assert_eq!(parse_ms(text), Some(ms), "{text}");
            assert_eq!(format_ms(ms), text);
        }
        assert_eq!(parse_ms("2024-03-14T15:09:26Z"), Some(1_710_428_966_000));
        assert_eq!(
            parse_ms("2024-03-14T15:09:26.5359999Z"),
            Some(1_710_428_966_535)
        );
        assert_eq!(
            parse_ms("2024-03-14t16:09:26.535+01:00"),
            Some(1_710_428_966_535)
        );
        assert_eq!(
            parse_ms("2024-03-14T14:39:26.535-00:30"),
            Some(1_710_428_966_535)
        );
        assert_eq!(
            parse_ms("1969-12-31T23:59:59.999Z"),
            Some(0),
            "pre-1970 is 0"
        );
        assert_eq!(parse_ms("0001-01-01T00:00:00Z"), Some(0));
        assert_eq!(format_ms(u64::MAX >> 11), format_ms(MAX_MS));
    }

    #[test]
    fn refusals() {
        for bad in [
            "",
            "2024-03-14",
            "2024-03-14 15:09:26Z",
            "2024-13-01T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2024-03-14T24:00:00Z",
            "2024-03-14T15:09:26.Z",
            "2024-03-14T15:09:26",
            "2024-03-14T15:09:26+0100",
            "+2024-03-14T15:09:26Z",
            "2024-03-14T15:09:26.535Zx",
        ] {
            assert_eq!(parse_ms(bad), None, "{bad}");
        }
    }
}
