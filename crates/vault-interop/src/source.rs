//! The JSON of a Bitwarden export, parsed as written: objects keep their keys in source order and
//! numbers keep their source text, so the import can list card fields in Bitwarden's order and
//! turn a number the body cannot hold into a string of its source text. The export is written
//! from the same type, so its keys come out in the order it builds them.
//!
//! The parser takes RFC 8259 JSON. It refuses a duplicate key, nesting deeper than [`MAX_DEPTH`],
//! which bounds its recursion, and more values than [`node_limit`] allows, which bounds its memory.
//! A lone surrogate escape decodes as U+FFFD. [`Json`] has no `Debug` and zeroizes its strings,
//! number texts, and keys when dropped, as the parser does with what it has built when it fails.

use crate::error::{Error, Result};
use vault_core::json::{Map, NUMBER_LIMIT, Value};
use zeroize::{Zeroize, Zeroizing};

/// The deepest nesting the parser accepts. An item nested deeper than the body allows is skipped
/// by the import; one nested deeper than this refuses the whole file.
pub(crate) const MAX_DEPTH: usize = 128;

/// A JSON value as the export writes it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    /// The number's source text.
    Number(String),
    String(String),
    Array(Vec<Json>),
    /// Keys in source order, each at most once.
    Object(Vec<(String, Json)>),
}

impl Drop for Json {
    fn drop(&mut self) {
        match self {
            Json::Number(s) | Json::String(s) => s.zeroize(),
            Json::Object(m) => {
                for (k, _) in m.iter_mut() {
                    k.zeroize();
                }
            }
            _ => {}
        }
    }
}

impl Json {
    /// The value of `key` when this is an object holding it.
    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    pub(crate) fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }

    /// The value as an integer in `[0, 2^53)`, the body's number rule.
    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(t) => body_number(t),
            _ => None,
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// The value under the body's JSON rules: a number outside them becomes a string of its
    /// source text. Nesting is not checked here; the body encoder checks it.
    pub(crate) fn to_value(&self) -> Value {
        match self {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(*b),
            Json::Number(t) => match body_number(t) {
                Some(n) => Value::Number(n),
                None => Value::String(t.clone()),
            },
            Json::String(s) => Value::String(s.clone()),
            Json::Array(a) => Value::Array(a.iter().map(Json::to_value).collect()),
            Json::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), v.to_value()))
                    .collect::<Map>(),
            ),
        }
    }
}

/// A number text that the body accepts as written: digits only, no leading zero, below `2^53`.
fn body_number(t: &str) -> Option<u64> {
    let digits = !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    if !digits || (t.len() > 1 && t.starts_with('0')) {
        return None;
    }
    t.parse::<u64>().ok().filter(|&n| n < NUMBER_LIMIT)
}

impl From<&Value> for Json {
    /// A body value as export JSON; object keys come out in byte order.
    fn from(v: &Value) -> Json {
        match v {
            Value::Null => Json::Null,
            Value::Bool(b) => Json::Bool(*b),
            Value::Number(n) => Json::Number(n.to_string()),
            Value::String(s) => Json::String(s.clone()),
            Value::Array(a) => Json::Array(a.iter().map(Json::from).collect()),
            Value::Object(m) => {
                Json::Object(m.iter().map(|(k, v)| (k.clone(), v.into())).collect())
            }
        }
    }
}

/// Where the writer puts bytes: a counter for the first pass, the buffer for the second.
trait Sink {
    fn put(&mut self, b: &[u8]);
}

impl Sink for usize {
    fn put(&mut self, b: &[u8]) {
        *self += b.len();
    }
}

impl Sink for Vec<u8> {
    fn put(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
}

/// Writes `v` as JSON indented by two spaces, as Bitwarden writes its exports, into a buffer sized
/// once, so no reallocation leaves a partial copy behind.
pub(crate) fn to_pretty(v: &Json) -> Zeroizing<Vec<u8>> {
    let mut len = 0usize;
    write(v, 0, &mut len);
    let mut out = Zeroizing::new(Vec::with_capacity(len + 1));
    write(v, 0, &mut *out);
    out.push(b'\n');
    out
}

fn newline(depth: usize, out: &mut dyn Sink) {
    out.put(b"\n");
    for _ in 0..depth {
        out.put(b"  ");
    }
}

fn write_str(s: &str, out: &mut dyn Sink) {
    out.put(b"\"");
    let mut start = 0;
    for (i, b) in s.bytes().enumerate() {
        let esc: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x08 => b"\\b",
            0x0c => b"\\f",
            0x00..=0x1f => b"",
            _ => continue,
        };
        out.put(&s.as_bytes()[start..i]);
        if esc.is_empty() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.put(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[usize::from(b >> 4)],
                HEX[usize::from(b & 15)],
            ]);
        } else {
            out.put(esc);
        }
        start = i + 1;
    }
    out.put(&s.as_bytes()[start..]);
    out.put(b"\"");
}

fn write(v: &Json, depth: usize, out: &mut dyn Sink) {
    match v {
        Json::Null => out.put(b"null"),
        Json::Bool(true) => out.put(b"true"),
        Json::Bool(false) => out.put(b"false"),
        Json::Number(t) => out.put(t.as_bytes()),
        Json::String(s) => write_str(s, out),
        Json::Array(a) if a.is_empty() => out.put(b"[]"),
        Json::Object(m) if m.is_empty() => out.put(b"{}"),
        Json::Array(a) => {
            out.put(b"[");
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.put(b",");
                }
                newline(depth + 1, out);
                write(x, depth + 1, out);
            }
            newline(depth, out);
            out.put(b"]");
        }
        Json::Object(m) => {
            out.put(b"{");
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.put(b",");
                }
                newline(depth + 1, out);
                write_str(k, out);
                out.put(b": ");
                write(x, depth + 1, out);
            }
            newline(depth, out);
            out.put(b"}");
        }
    }
}

/// The most values and object keys a parse of `len` bytes builds. Each costs some 32 to 64 bytes
/// of memory however short its text, so the limit keeps a hostile file such as `[0,0,0,...]`
/// from needing many times its size; a real export spends far more than 4 bytes per value.
pub(crate) fn node_limit(len: usize) -> usize {
    len / 4 + 1024
}

/// Parses `bytes` as one JSON value. A UTF-8 byte order mark is skipped.
pub(crate) fn parse(bytes: &[u8]) -> Result<Json> {
    parse_limited(bytes, node_limit(bytes.len()))
}

fn parse_limited(bytes: &[u8], max_nodes: usize) -> Result<Json> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut p = Parser {
        b: bytes,
        pos: 0,
        nodes_left: max_nodes,
    };
    p.ws();
    let v = p.value(1)?;
    p.ws();
    if p.pos != p.b.len() {
        return Err(Error::Json);
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    nodes_left: usize,
}

/// An object's entries while it is parsed. Values zeroize themselves; this zeroizes the keys when
/// a parse error drops the entries.
struct Entries(Vec<(String, Json)>);

impl Drop for Entries {
    fn drop(&mut self) {
        for (k, _) in &mut self.0 {
            k.zeroize();
        }
    }
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<()> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(Error::Json)
        }
    }

    /// Counts one value or key against the limit.
    fn node(&mut self) -> Result<()> {
        self.nodes_left = self.nodes_left.checked_sub(1).ok_or(Error::Json)?;
        Ok(())
    }

    fn literal(&mut self, word: &[u8], v: Json) -> Result<Json> {
        if self.b[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(Error::Json)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json> {
        self.node()?;
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(Error::Json),
        }
    }

    fn container(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::Json);
        }
        self.pos += 1;
        self.ws();
        Ok(())
    }

    fn array(&mut self, depth: usize) -> Result<Json> {
        self.container(depth)?;
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(out));
        }
        loop {
            out.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.ws();
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(out));
                }
                _ => return Err(Error::Json),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json> {
        self.container(depth)?;
        let mut out = Entries(Vec::new());
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(Vec::new()));
        }
        loop {
            self.node()?;
            let mut k = Zeroizing::new(self.string()?);
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value(depth + 1)?;
            out.0.push((core::mem::take(&mut *k), v));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.ws();
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(Error::Json),
            }
        }
        // Sorting references keeps the check at O(n log n) without copying a key.
        let mut keys: Vec<&str> = out.0.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::Json);
        }
        Ok(Json::Object(core::mem::take(&mut out.0)))
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(Error::Json),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.require_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.require_digits()?;
        }
        // The slice is ASCII, so it is valid UTF-8.
        let text = core::str::from_utf8(&self.b[start..self.pos]).map_err(|_| Error::Json)?;
        Ok(Json::Number(text.to_owned()))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn require_digits(&mut self) -> Result<()> {
        let start = self.pos;
        self.digits();
        if self.pos == start {
            Err(Error::Json)
        } else {
            Ok(())
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        let h = self.b.get(self.pos..self.pos + 4).ok_or(Error::Json)?;
        let mut n = 0u32;
        for &c in h {
            n = n * 16 + (c as char).to_digit(16).ok_or(Error::Json)?;
        }
        self.pos += 4;
        Ok(n)
    }

    /// The length of the raw string text from the current position (after the opening quote) to
    /// the closing quote, or `None` when the string is not terminated.
    fn raw_len(&self) -> Option<usize> {
        let mut i = self.pos;
        loop {
            match *self.b.get(i)? {
                b'"' => return Some(i - self.pos),
                b'\\' => i += 2,
                _ => i += 1,
            }
        }
    }

    fn string(&mut self) -> Result<String> {
        self.eat(b'"')?;
        // Decoding never lengthens the text, so a buffer of the raw length never reallocates and
        // leaves no partial copy behind.
        let mut out = Zeroizing::new(Vec::with_capacity(self.raw_len().ok_or(Error::Json)?));
        loop {
            let c = self.peek().ok_or(Error::Json)?;
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or(Error::Json)?;
                    self.pos += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => return Err(Error::Json),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1f => return Err(Error::Json),
                _ => out.push(c),
            }
        }
        let bytes = core::mem::take(&mut *out);
        String::from_utf8(bytes).map_err(|e| {
            e.into_bytes().zeroize();
            Error::Json
        })
    }

    /// A `\u` escape. A surrogate that is not half of a pair decodes as U+FFFD, as a JavaScript
    /// string can hold one but a Rust string cannot.
    fn unicode_escape(&mut self) -> Result<char> {
        let hi = self.hex4()?;
        if (0xdc00..=0xdfff).contains(&hi) {
            return Ok(char::REPLACEMENT_CHARACTER);
        }
        if !(0xd800..=0xdbff).contains(&hi) {
            return char::from_u32(hi).ok_or(Error::Json);
        }
        let save = self.pos;
        if self.b[self.pos..].starts_with(b"\\u") {
            self.pos += 2;
            let lo = self.hex4()?;
            if (0xdc00..=0xdfff).contains(&lo) {
                let code = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                return char::from_u32(code).ok_or(Error::Json);
            }
        }
        // Not a pair: the next escape, if any, is read on its own.
        self.pos = save;
        Ok(char::REPLACEMENT_CHARACTER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Json {
        parse(s.as_bytes()).unwrap_or_else(|_| panic!("{s} should parse"))
    }

    #[test]
    fn values_and_order() {
        let v = ok(r#" {"b": [1, -2.5e3, true, null], "a": "xé😀\n"} "#);
        let m = v.as_object().unwrap();
        assert_eq!(m[0].0, "b");
        assert_eq!(m[1].0, "a");
        assert_eq!(v.get("a").unwrap().as_str(), Some("xé😀\n"));
        let a = v.get("b").unwrap().as_array().unwrap();
        assert_eq!(a[0].as_u64(), Some(1));
        assert!(a[1] == Json::Number("-2.5e3".into()));
        assert!(a[2] == Json::Bool(true));
        assert!(a[3].is_null());
        assert!(ok("\u{feff}{}").as_object().unwrap().is_empty());
    }

    #[test]
    fn body_numbers() {
        for (t, n) in [("0", Some(0)), ("9007199254740991", Some((1 << 53) - 1))] {
            assert_eq!(body_number(t), n);
        }
        for t in ["9007199254740992", "-0", "-1", "1.0", "1e3", "01", ""] {
            assert_eq!(body_number(t), None, "{t}");
        }
        let v = ok(r#"[-1, 1.5, 1E2, 9007199254740992, 7]"#).to_value();
        let Value::Array(a) = &v else { panic!() };
        let texts: Vec<String> = a
            .iter()
            .map(|x| match x {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => panic!(),
            })
            .collect();
        assert_eq!(texts, ["-1", "1.5", "1E2", "9007199254740992", "7"]);
        assert!(matches!(a[4], Value::Number(7)));
    }

    #[test]
    fn writer_round_trips() {
        let text = r#"{"b":[1,-2.5e3,true,null,[],{}],"a":"q\"\\\n\u0001\u001f\té/"}"#;
        let v = ok(text);
        let out = to_pretty(&v);
        let s = core::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("{\n  \"b\": [\n    1,\n    -2.5e3,"), "{s}");
        assert!(s.contains(r#""a": "q\"\\\n\u0001\u001f\té/""#), "{s}");
        assert!(s.contains("[],\n    {}\n  ]"), "{s}");
        assert!(parse(&out).unwrap() == v);
    }

    #[test]
    fn lone_surrogates_become_replacement_characters() {
        for (text, want) in [
            (r#""\ud800""#, "\u{fffd}"),
            (r#""\udc00x""#, "\u{fffd}x"),
            (r#""\ud800\u0041""#, "\u{fffd}A"),
            (r#""\ud800\ud800""#, "\u{fffd}\u{fffd}"),
            (r#""\ud83d\ude00""#, "😀"),
        ] {
            assert_eq!(ok(text).as_str(), Some(want), "{text}");
        }
    }

    #[test]
    fn node_limit() {
        // `[0,0,0]` is four values; `{"a":1}` is an object, a key, and a value.
        assert!(parse_limited(b"[0,0,0]", 4).is_ok());
        assert_eq!(parse_limited(b"[0,0,0]", 3).err(), Some(Error::Json));
        assert!(parse_limited(br#"{"a":1}"#, 3).is_ok());
        assert_eq!(parse_limited(br#"{"a":1}"#, 2).err(), Some(Error::Json));
        assert_eq!(super::node_limit(4096), 2048);
    }

    #[test]
    fn refusals() {
        for bad in [
            "",
            "{",
            r#"{"a":1,"a":2}"#,
            "\"a\u{1}\"",
            r#""\x""#,
            "01",
            "1.",
            "-",
            "1e",
            "[1,]",
            "{} x",
            "tru",
            "\"\u{80}",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(parse(b"\"\xff\"").is_err());
        let deep = |n: usize| "[".repeat(n) + &"]".repeat(n);
        assert!(parse(deep(MAX_DEPTH).as_bytes()).is_ok());
        assert!(parse(deep(MAX_DEPTH + 1).as_bytes()).is_err());
    }
}
