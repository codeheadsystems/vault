//! Output: item content and server strings escaped for display, the JSON result and error
//! objects, and small builders for JSON values.

use crate::error::CliError;
use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use vault_core::json::{self, Map, Value};
use zeroize::Zeroizing;

/// Where text goes, and whether standard error is a terminal, for the status line.
#[derive(Debug, Clone, Copy)]
pub struct Out {
    /// `--json`: text output is suppressed and one JSON object goes to standard output.
    pub json: bool,
    /// Standard error is a terminal.
    pub stderr_tty: bool,
}

impl Out {
    /// Detects whether standard error is a terminal.
    pub fn new(json: bool) -> Out {
        Out {
            json,
            stderr_tty: std::io::stderr().is_terminal(),
        }
    }

    /// Prints a line on standard output, unless `--json` is given, with the characters
    /// [`escape`] names escaped: text output is for display, also through a pipe.
    pub fn line(&self, text: &str) {
        if !self.json {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{}", escape(text));
        }
    }

    /// Prints a line on standard error, escaped as by [`escape`], also with `--json`.
    pub fn err(&self, text: &str) {
        let mut e = std::io::stderr().lock();
        let _ = writeln!(e, "{}", escape(text));
    }

    /// Prints a warning on standard error.
    pub fn warn(&self, text: &str) {
        self.err(&format!("vault: warning: {text}"));
    }
}

/// Escapes control characters other than newline and tab, and the format characters, as
/// `\u{..}`, so item content and server strings can neither drive a terminal nor hide or reorder
/// text.
pub fn escape(text: &str) -> Cow<'_, str> {
    if !text.chars().any(needs_escape) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if needs_escape(c) {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Control characters other than newline and tab; the line and paragraph separators; and the
/// format characters (Unicode category Cf), which include the bidirectional controls that can
/// make text display in an order other than its own.
fn needs_escape(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(
            c as u32,
            0x00AD
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
        )
}

/// A JSON object from key and value pairs.
pub fn obj<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Map>(),
    )
}

/// A JSON string.
pub fn s(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

/// A JSON number, or `null`.
pub fn n(v: Option<u64>) -> Value {
    v.map_or(Value::Null, Value::Number)
}

/// A JSON result: a value, or JSON text already serialised (for a number that is not an
/// integer, which [`Value`] cannot hold).
pub enum JsonResult {
    /// A value.
    Value(Value),
    /// Serialised JSON.
    Raw(Zeroizing<Vec<u8>>),
}

impl From<Value> for JsonResult {
    fn from(v: Value) -> Self {
        JsonResult::Value(v)
    }
}

/// Prints `{"v": 1, "result": ...}` and a newline on standard output.
pub fn print_result(result: &JsonResult) {
    let body = match result {
        JsonResult::Value(v) => json::to_vec(v),
        JsonResult::Raw(r) => r.clone(),
    };
    let mut line = Zeroizing::new(Vec::with_capacity(body.len() + 24));
    line.extend_from_slice(b"{\"v\":1,\"result\":");
    line.extend_from_slice(&body);
    line.extend_from_slice(b"}\n");
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(&line);
    let _ = o.flush();
}

/// Prints `{"v": 1, "error": {"exit", "code", "message"}}` and a newline on standard output.
pub fn print_error(e: &CliError) {
    let err = obj([
        ("exit", Value::Number(e.exit() as u64)),
        ("code", s(e.code())),
        ("message", s(e.message())),
    ]);
    let mut line = b"{\"v\":1,\"error\":".to_vec();
    line.extend_from_slice(&json::to_vec(&err));
    line.extend_from_slice(b"}\n");
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(&line);
    let _ = o.flush();
}

/// Formats ms as `2026-10-12T15:04:05Z`.
pub fn format_time(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

fn civil_from_days(z: u64) -> (u64, u64, u64) {
    let z = z + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_controls_only() {
        assert_eq!(escape("plain\ttext\n"), "plain\ttext\n");
        assert_eq!(escape("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(escape("\r\u{7f}\u{9b}"), "\\u{d}\\u{7f}\\u{9b}");
        assert_eq!(escape("é ✓"), "é ✓");
        assert_eq!(escape("a\u{202e}b\u{2066}c"), "a\\u{202e}b\\u{2066}c");
        assert_eq!(
            escape("\u{200b}\u{feff}\u{2028}"),
            "\\u{200b}\\u{feff}\\u{2028}"
        );
        assert_eq!(escape("\u{e0041}"), "\\u{e0041}");
    }

    #[test]
    fn times() {
        assert_eq!(format_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_time(1_791_817_445_999), "2026-10-12T15:04:05Z");
        assert_eq!(format_time(951_782_400_000), "2000-02-29T00:00:00Z");
    }
}
