//! Strict JSON for the body: a value type that keeps every key, a parser that enforces the body's
//! JSON rules, and a deterministic writer.
//!
//! The parser rejects a byte order mark, a duplicate key in any object, nesting deeper than 32
//! levels, and any number that is not an integer in `[0, 2^53)` written without a fraction or
//! exponent. The writer emits compact JSON with object keys in byte order, so equal values always
//! produce equal bytes, and escapes every control character (U+0000 to U+001F, DEL, and U+0080 to
//! U+009F) and U+2028 and U+2029, so its output is safe to print to a terminal.
//!
//! [`Value`] has no `Debug`, because a body value holds passwords, and it zeroizes its strings and
//! object keys when dropped.

use crate::error::{Error, IntegrityKind as K, Result};
use core::cell::Cell;
use core::fmt;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// The deepest nesting of arrays and objects a body may have. The outermost object is level 1.
pub const MAX_DEPTH: usize = 32;
/// The bound on JSON integers, exclusive: `2^53`.
pub const NUMBER_LIMIT: u64 = 1 << 53;

/// A JSON object with its keys in byte order.
pub type Map = BTreeMap<String, Value>;

/// A JSON value under the body rules.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer in `[0, 2^53)`.
    Number(u64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Map),
}

impl Value {
    /// Moves the string out, leaving an empty one, or `None` for another kind of value.
    pub fn take_string(&mut self) -> Option<String> {
        match self {
            Value::String(s) => Some(core::mem::take(s)),
            _ => None,
        }
    }

    /// Moves the array out, leaving an empty one, or `None` for another kind of value.
    pub fn take_array(&mut self) -> Option<Vec<Value>> {
        match self {
            Value::Array(a) => Some(core::mem::take(a)),
            _ => None,
        }
    }

    /// Moves the object out, leaving an empty one, or `None` for another kind of value.
    pub fn take_object(&mut self) -> Option<Map> {
        match self {
            Value::Object(m) => Some(core::mem::take(m)),
            _ => None,
        }
    }
}

impl Drop for Value {
    /// Zeroizes the string, or the keys of the object; nested values zeroize themselves.
    fn drop(&mut self) {
        match self {
            Value::String(s) => s.zeroize(),
            Value::Object(m) => wipe_keys(m),
            _ => {}
        }
    }
}

/// Zeroizes the keys of a map and drops its values, which zeroize themselves.
pub(crate) fn wipe_keys(m: &mut Map) {
    for (mut k, v) in core::mem::take(m) {
        k.zeroize();
        drop(v);
    }
}

/// Parses `bytes` as one JSON value under the body's JSON rules.
pub fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Error::Integrity(K::Bom));
    }
    let fail = Cell::new(None);
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = Seed {
        depth: 0,
        fail: &fail,
    }
    .deserialize(&mut de)
    .and_then(|v| de.end().map(|()| v));
    v.map_err(|_| Error::Integrity(fail.get().unwrap_or(K::Json)))
}

// Each array or object is one level and the outer object is level 1, so 32 nested containers
// parse and 33 do not.
struct Seed<'a> {
    depth: usize,
    fail: &'a Cell<Option<K>>,
}

impl Seed<'_> {
    fn reject<E: de::Error>(&self, k: K) -> core::result::Result<Value, E> {
        self.fail.set(Some(k));
        Err(E::custom("body JSON rule"))
    }

    fn child(&self) -> Option<Seed<'_>> {
        (self.depth < MAX_DEPTH).then_some(Seed {
            depth: self.depth + 1,
            fail: self.fail,
        })
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> core::result::Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> core::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> core::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> core::result::Result<Value, E> {
        if v < NUMBER_LIMIT {
            Ok(Value::Number(v))
        } else {
            self.reject(K::Number)
        }
    }

    // serde_json reports negative integers here, and `-0` and every number with a fraction,
    // an exponent, or more digits than a u64 holds through `visit_f64`.
    fn visit_i64<E: de::Error>(self, _: i64) -> core::result::Result<Value, E> {
        self.reject(K::Number)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> core::result::Result<Value, E> {
        self.reject(K::Number)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> core::result::Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> core::result::Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> core::result::Result<Value, A::Error> {
        let Some(child) = self.child() else {
            return self.reject(K::Nesting);
        };
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Seed { ..child })? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> core::result::Result<Value, A::Error> {
        let Some(child) = self.child() else {
            return self.reject(K::Nesting);
        };
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            let v = map.next_value_seed(Seed { ..child })?;
            if out.insert(k, v).is_some() {
                return self.reject(K::DuplicateKey);
            }
        }
        Ok(Value::Object(out))
    }
}

/// Writes `v` as compact JSON with object keys in byte order, into a buffer sized exactly once,
/// so no partial copy of the text is left behind by a reallocation.
pub fn to_vec(v: &Value) -> Zeroizing<Vec<u8>> {
    let len = encoded_len(v);
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    write(v, &mut out);
    debug_assert_eq!(out.len(), len);
    out
}

fn encoded_len(v: &Value) -> usize {
    match v {
        Value::Null | Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(n) => n.checked_ilog10().unwrap_or(0) as usize + 1,
        Value::String(s) => str_len(s),
        Value::Array(a) => 2 + a.len().saturating_sub(1) + a.iter().map(encoded_len).sum::<usize>(),
        Value::Object(m) => {
            2 + m.len().saturating_sub(1)
                + m.iter()
                    .map(|(k, x)| str_len(k) + 1 + encoded_len(x))
                    .sum::<usize>()
        }
    }
}

/// How the writer spells one character of a string.
enum Escape {
    /// A two-character escape: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, or `\t`.
    Short(&'static [u8]),
    /// `\uXXXX` with lowercase hex.
    Unicode(u32),
    /// The character itself, as UTF-8.
    Literal,
}

/// The escape for a character. Besides what JSON requires (`"`, `\`, and U+0000 to U+001F), the
/// writer escapes DEL and the C1 controls (U+007F to U+009F) and U+2028 and U+2029, so that JSON
/// printed to a terminal carries no raw control character.
fn escape(c: char) -> Escape {
    match c {
        '"' => Escape::Short(b"\\\""),
        '\\' => Escape::Short(b"\\\\"),
        '\u{8}' => Escape::Short(b"\\b"),
        '\u{c}' => Escape::Short(b"\\f"),
        '\n' => Escape::Short(b"\\n"),
        '\r' => Escape::Short(b"\\r"),
        '\t' => Escape::Short(b"\\t"),
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}' => {
            Escape::Unicode(c as u32)
        }
        _ => Escape::Literal,
    }
}

fn str_len(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match escape(c) {
            Escape::Short(e) => e.len(),
            Escape::Unicode(_) => 6,
            Escape::Literal => c.len_utf8(),
        })
        .sum::<usize>()
}

fn write(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            use std::io::Write;
            write!(out, "{n}").expect("writing to a Vec cannot fail");
        }
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(x, out);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            out.push(b'{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(k, out);
                out.push(b':');
                write(x, out);
            }
            out.push(b'}');
        }
    }
}

fn write_str(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for c in s.chars() {
        match escape(c) {
            Escape::Short(e) => out.extend_from_slice(e),
            Escape::Unicode(u) => {
                out.extend_from_slice(b"\\u");
                for shift in [12, 8, 4, 0] {
                    out.push(HEX[((u >> shift) & 15) as usize]);
                }
            }
            Escape::Literal => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn text(v: &Value) -> String {
        String::from_utf8(to_vec(v).to_vec()).unwrap()
    }

    fn err(s: &str) -> Option<K> {
        match parse(s.as_bytes()) {
            Err(Error::Integrity(k)) => Some(k),
            Err(_) => panic!("not an integrity error"),
            Ok(_) => None,
        }
    }

    #[test]
    fn round_trip_sorts_keys() {
        let v = parse(br#" {"b": [1, true, null, "x\n\u00e9"], "a": {}, "": 0} "#).unwrap();
        assert_eq!(text(&v), r#"{"":0,"a":{},"b":[1,true,null,"x\né"]}"#);
        assert!(parse(text(&v).as_bytes()).unwrap() == v);
    }

    #[test]
    fn numbers() {
        assert_eq!(err("0"), None);
        assert_eq!(err("9007199254740991"), None);
        assert_eq!(err("9007199254740992"), Some(K::Number), "2^53");
        assert_eq!(err("18446744073709551616"), Some(K::Number));
        assert_eq!(err("-1"), Some(K::Number));
        assert_eq!(err("-0"), Some(K::Number));
        assert_eq!(err("1.0"), Some(K::Number));
        assert_eq!(err("1e2"), Some(K::Number));
        assert_eq!(err("1E2"), Some(K::Number));
        assert_eq!(
            err(r#"{"a":{"b":[0.5]}}"#),
            Some(K::Number),
            "unknown fields too"
        );
        assert_eq!(err("01"), Some(K::Json));
    }

    #[test]
    fn duplicate_keys() {
        assert_eq!(err(r#"{"a":1,"a":1}"#), Some(K::DuplicateKey));
        assert_eq!(err(r#"{"x":[{"a":1,"b":2,"a":3}]}"#), Some(K::DuplicateKey));
        // Escapes are decoded before comparison.
        assert_eq!(err(r#"{"a":1,"a":1}"#), Some(K::DuplicateKey));
        assert_eq!(err(r#"{"a":1,"A":1}"#), None);
    }

    #[test]
    fn nesting() {
        let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(err(&nest(32)), None);
        assert_eq!(err(&nest(33)), Some(K::Nesting));
        let objects = |n: usize| format!("{}0{}", r#"{"a":"#.repeat(n), "}".repeat(n));
        assert_eq!(err(&objects(32)), None);
        assert_eq!(err(&objects(33)), Some(K::Nesting));
        assert_eq!(err(&nest(200)), Some(K::Nesting));
    }

    #[test]
    fn syntax() {
        assert_eq!(err("\u{feff}{}"), Some(K::Bom));
        assert_eq!(err("{} x"), Some(K::Json), "trailing content");
        assert_eq!(err("{,}"), Some(K::Json));
        assert_eq!(err(r#"{"a":1,}"#), Some(K::Json));
        assert_eq!(err(r#""\ud800""#), Some(K::Json), "lone surrogate");
        assert_eq!(err("\"\u{1}\""), Some(K::Json), "raw control character");
        assert_eq!(err(""), Some(K::Json));
        assert!(matches!(parse(b"\"\xff\""), Err(Error::Integrity(K::Json))));
    }

    #[test]
    fn writer_escapes() {
        let v = Value::String("\"\\\u{1}/".into());
        assert_eq!(text(&v), r#""\"\\\u0001/""#);
        // DEL, the C1 controls, and U+2028 and U+2029 are escaped; U+00A0 and other text is not.
        let v = Value::String("a\u{7f}\u{80}\u{9f}\u{a0}\u{2028}\u{2029}\u{e9}\u{1f600}".into());
        assert_eq!(
            text(&v),
            "\"a\\u007f\\u0080\\u009f\u{a0}\\u2028\\u2029\u{e9}\u{1f600}\""
        );
        // The length is exact, and the text reads back as the same value.
        assert_eq!(to_vec(&v).len(), encoded_len(&v));
        assert!(parse(&to_vec(&v)).unwrap() == v);
        let key = Value::Object(Map::from([("\u{85}".to_owned(), Value::Null)]));
        assert_eq!(text(&key), "{\"\\u0085\":null}");
    }
}
