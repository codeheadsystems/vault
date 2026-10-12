//! `tokens.json`: the token names, hashes, and creation times; the commands that edit it; and the
//! server's view of it, re-read when the file changes.

use crate::datadir::{self, DataDir, TOKENS};
use crate::error::{Context, Error, Result, invalid};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Mutex;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use vault_core::secret::Token;

/// The contents of `tokens.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokensFile {
    pub(crate) tokens: Vec<TokenEntry>,
}

/// One token: its name, the lowercase hex SHA-256 of its bytes, and its creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenEntry {
    pub(crate) name: String,
    pub(crate) hash: String,
    pub(crate) created: String,
}

/// Whether a token name is 1 to 32 characters from `a`-`z`, `0`-`9`, `-`, and `_`.
pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl TokensFile {
    /// Parses and checks `tokens.json`: valid names, no name twice, 64 lowercase hex characters
    /// per hash, and well-formed creation times.
    pub(crate) fn parse(bytes: &[u8]) -> Option<TokensFile> {
        let file: TokensFile = serde_json::from_slice(bytes).ok()?;
        let mut names = std::collections::BTreeSet::new();
        for t in &file.tokens {
            let hash_ok = t.hash.len() == 64
                && t.hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !valid_name(&t.name) || !hash_ok || crate::time::parse(&t.created).is_none() {
                return None;
            }
            if !names.insert(t.name.as_str()) {
                return None;
            }
        }
        Some(file)
    }

    /// Reads `tokens.json` for a command. A missing file is an empty list.
    pub(crate) fn load(data: &DataDir) -> Result<TokensFile> {
        let path = data.path(TOKENS);
        match datadir::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(TokensFile::default()),
            r => {
                let bytes = r.context(|| format!("reading {}", path.display()))?;
                TokensFile::parse(&bytes).ok_or_else(|| {
                    Error::Invalid(format!("{} is not a valid token list", path.display()))
                })
            }
        }
    }

    /// Writes `tokens.json` through a temporary file and a rename. The caller holds the writer
    /// lock.
    pub(crate) fn store(&self, data: &DataDir) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(self).expect("a token list serialises");
        json.push(b'\n');
        datadir::write_atomic(&data.path(TOKENS), &json)
    }
}

/// A token as `token ls` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    /// The token's name.
    pub name: String,
    /// When `token add` created it, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub created: String,
    /// The ID and creation time of the newest retained revision it pushed.
    pub last_push: Option<(u64, String)>,
}

/// What identifies one version of `tokens.json`: a rename gives a new inode, and an edit in place
/// changes the modification time or the size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileId {
    fn of(m: &fs::Metadata) -> FileId {
        FileId {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}

/// The names and stored hashes of `tokens.json`, or `None` when it cannot be read or parsed.
type Table = Option<Vec<(String, [u8; 32])>>;

/// The server's view of `tokens.json`. It never writes the file.
pub(crate) struct TokenTable {
    path: PathBuf,
    cache: Mutex<Option<(FileId, Table)>>,
}

impl TokenTable {
    pub(crate) fn new(data: &DataDir) -> TokenTable {
        TokenTable {
            path: data.path(TOKENS),
            cache: Mutex::new(None),
        }
    }

    /// The name of the token that `Authorization: Bearer <token>` carries, or `None` for a
    /// missing, malformed, unknown, or revoked token, and while `tokens.json` cannot be read or
    /// parsed.
    pub(crate) fn authenticate(&self, authorization: Option<&[u8]>) -> Option<String> {
        let token = parse_bearer(authorization?)?;
        let hash = vault_core::token::stored_hash(&token);
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let current = fs::symlink_metadata(&self.path)
            .ok()
            .map(|m| FileId::of(&m));
        let fresh = matches!((&*cache, current), (Some((id, _)), Some(c)) if *id == c);
        if !fresh {
            *cache = self.reload();
        }
        let entries = cache.as_ref()?.1.as_ref()?;
        // Every stored hash is compared, in constant time, whichever matches.
        let mut found = subtle::Choice::from(0);
        let mut index = 0u32;
        for (i, (_, stored)) in entries.iter().enumerate() {
            let eq = stored.ct_eq(&hash);
            index = u32::conditional_select(&index, &(i as u32), eq);
            found |= eq;
        }
        bool::from(found).then(|| entries[index as usize].0.clone())
    }

    /// Reads the file. The result is cached under the identity of the file that was read, so a
    /// file that is replaced between the `lstat` and the `open` is read again next time.
    fn reload(&self) -> Option<(FileId, Table)> {
        let mut f = datadir::open_read(&self.path).ok()?;
        let meta = f.metadata().ok()?;
        let id = FileId::of(&meta);
        if datadir::check_open_file(&self.path, &f).is_err() {
            return Some((id, None));
        }
        let mut bytes = Vec::new();
        if f.read_to_end(&mut bytes).is_err() {
            return Some((id, None));
        }
        let parsed = TokensFile::parse(&bytes).map(|file| {
            file.tokens
                .into_iter()
                .map(|t| {
                    let mut h = [0u8; 32];
                    hex::decode_to_slice(&t.hash, &mut h).expect("checked by parse");
                    (t.name, h)
                })
                .collect()
        });
        Some((id, parsed))
    }
}

/// Parses `Bearer <token>`. The scheme is case-insensitive.
fn parse_bearer(value: &[u8]) -> Option<Token> {
    let value = std::str::from_utf8(value).ok()?;
    let (scheme, rest) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    vault_core::token::decode(rest.trim()).ok()
}

/// A random source for `vault-core` backed by the operating system.
pub(crate) struct OsRng;

impl vault_core::rng::Rng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        getrandom::getrandom(dest).map_err(|_| vault_core::Error::Rng)
    }
}

/// Adds a token under `name` and returns it. The caller holds the writer lock.
pub(crate) fn add(data: &DataDir, name: &str, now_ms: u64) -> Result<Token> {
    if !valid_name(name) {
        return invalid(format!(
            "token name {name:?} is not 1 to 32 characters from a-z, 0-9, -, and _"
        ));
    }
    let mut file = TokensFile::load(data)?;
    if file.tokens.iter().any(|t| t.name == name) {
        return invalid(format!("a token named {name:?} exists"));
    }
    let token = Token::generate(&mut OsRng).map_err(|e| Error::Io {
        context: "reading the operating system's random source".into(),
        source: io::Error::other(e),
    })?;
    file.tokens.push(TokenEntry {
        name: name.to_owned(),
        hash: hex::encode(vault_core::token::stored_hash(&token)),
        created: crate::time::format(now_ms),
    });
    file.store(data)?;
    Ok(token)
}

/// Removes the token named `name`. The caller holds the writer lock.
pub(crate) fn remove(data: &DataDir, name: &str) -> Result<()> {
    let mut file = TokensFile::load(data)?;
    let before = file.tokens.len();
    file.tokens.retain(|t| t.name != name);
    if file.tokens.len() == before {
        return invalid(format!("no token named {name:?}"));
    }
    file.store(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("laptop"));
        assert!(valid_name("a"));
        assert!(valid_name("phone-2_x"));
        assert!(valid_name(&"a".repeat(32)));
        for bad in ["", "Laptop", "a b", "a.b", "é", &"a".repeat(33)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn bearer() {
        let t = Token::from_bytes([7; 20]);
        let text = vault_core::token::encode(&t);
        for v in [
            format!("Bearer {}", text.as_str()),
            format!("bearer {}", text.to_ascii_lowercase()),
            format!("BEARER  {} ", text.as_str()),
        ] {
            assert_eq!(
                parse_bearer(v.as_bytes()).unwrap().expose(),
                t.expose(),
                "{v}"
            );
        }
        assert!(parse_bearer(text.as_bytes()).is_none());
        assert!(parse_bearer(format!("Basic {}", text.as_str()).as_bytes()).is_none());
        assert!(parse_bearer(b"Bearer short").is_none());
        assert!(parse_bearer(b"Bearer \xff").is_none());
    }

    #[test]
    fn file_rules() {
        let h = "ab".repeat(32);
        let ok = format!(
            r#"{{"tokens":[{{"name":"a","hash":"{h}","created":"2026-10-12T15:04:05Z"}}]}}"#
        );
        assert_eq!(TokensFile::parse(ok.as_bytes()).unwrap().tokens.len(), 1);
        let dup = format!(
            r#"{{"tokens":[{{"name":"a","hash":"{h}","created":"2026-10-12T15:04:05Z"}},{{"name":"a","hash":"{h}","created":"2026-10-12T15:04:05Z"}}]}}"#
        );
        assert!(TokensFile::parse(dup.as_bytes()).is_none());
        let upper = ok.replace(&h, &"AB".repeat(32));
        assert!(TokensFile::parse(upper.as_bytes()).is_none());
        assert!(TokensFile::parse(b"{}").is_none());
        assert!(TokensFile::parse(b"not json").is_none());
    }
}
