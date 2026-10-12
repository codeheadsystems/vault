//! The clock checks a client runs before it edits, merges, or pushes.

use crate::error::{Error, Result};
use crate::merge::DAY;

/// The build time in ms: `SOURCE_DATE_EPOCH` (seconds) when the build sets it, and otherwise
/// 2026-10-12T00:00:00Z.
pub const BUILD_TIME_MS: u64 = match option_env!("SOURCE_DATE_EPOCH") {
    Some(s) => match parse_decimal(s.as_bytes()) {
        Some(secs) => secs * 1000,
        None => panic!("SOURCE_DATE_EPOCH is not a decimal number of seconds"),
    },
    None => 1_791_763_200_000,
};

const fn parse_decimal(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 12 {
        return None;
    }
    let mut v = 0u64;
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            return None;
        }
        v = v * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    Some(v)
}

/// Checks the local clock before an edit, a merge, or a push. `now` is the local clock in ms,
/// `build_time` is normally [`BUILD_TIME_MS`], and `server_date` is the `Date` header of the
/// server's most recent response in ms, or `None` offline.
///
/// Refuses a clock earlier than the build time, and a clock that differs from the server's by
/// more than a day.
pub fn check_clock(now: u64, build_time: u64, server_date: Option<u64>) -> Result<()> {
    if now < build_time {
        return Err(Error::ClockBeforeBuildTime);
    }
    if let Some(date) = server_date
        && now.abs_diff(date) > DAY
    {
        return Err(Error::ClockSkew);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: u64 = 1_791_763_200_000;

    #[test]
    fn build_time() {
        if option_env!("SOURCE_DATE_EPOCH").is_none() {
            assert_eq!(BUILD_TIME_MS, BUILD);
        }
        assert_eq!(check_clock(BUILD, BUILD, None), Ok(()));
        assert_eq!(
            check_clock(BUILD - 1, BUILD, None),
            Err(Error::ClockBeforeBuildTime)
        );
        assert_eq!(
            check_clock(0, BUILD, None),
            Err(Error::ClockBeforeBuildTime)
        );
        assert_eq!(
            check_clock(0, BUILD, Some(0)),
            Err(Error::ClockBeforeBuildTime),
            "a server that agrees with a 1970 clock does not help"
        );
    }

    #[test]
    fn server_date_skew() {
        let now = BUILD + 10 * DAY;
        assert_eq!(check_clock(now, BUILD, Some(now)), Ok(()));
        assert_eq!(check_clock(now, BUILD, Some(now + DAY)), Ok(()));
        assert_eq!(check_clock(now, BUILD, Some(now - DAY)), Ok(()));
        assert_eq!(
            check_clock(now, BUILD, Some(now + DAY + 1)),
            Err(Error::ClockSkew)
        );
        assert_eq!(
            check_clock(now, BUILD, Some(now - DAY - 1)),
            Err(Error::ClockSkew)
        );
        assert_eq!(check_clock(now, BUILD, Some(0)), Err(Error::ClockSkew));
        assert_eq!(check_clock(u64::MAX, BUILD, Some(0)), Err(Error::ClockSkew));
    }

    #[test]
    fn decimal() {
        assert_eq!(parse_decimal(b"1791763200"), Some(1_791_763_200));
        assert_eq!(parse_decimal(b""), None);
        assert_eq!(parse_decimal(b"-1"), None);
        assert_eq!(parse_decimal(b"1e9"), None);
    }
}
