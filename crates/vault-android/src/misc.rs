//! Setup text, secret key text, the revision list, password generation, and the pin check.

use crate::error::Result;
use crate::host::{OsRng, secret_key};
use vault_core::generate::{self, Classes};

/// Parsed setup text.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SetupText {
    /// The server URL.
    pub url: String,
    /// The token's text form, for `Authorization: Bearer <token>`.
    pub token: String,
    /// The certificate pin, 64 lowercase hex characters, or `None`.
    pub fp: Option<String>,
    /// Whether the URL is plain `http` to a loopback address.
    pub loopback_http: bool,
}

/// Parses setup text.
#[uniffi::export]
pub fn parse_setup_text(text: String) -> Result<SetupText> {
    let s = vault_core::setup::parse_setup(&text)?;
    let server = vault_core::setup::check_server_url(&s.url)?;
    let token = vault_core::token::encode(&s.token);
    Ok(SetupText {
        url: s.url,
        token: token.as_str().to_owned(),
        fp: s.fp.map(hex::encode),
        loopback_http: server.loopback_http,
    })
}

/// Decodes a secret key's text form to its 16 bytes; a typo fails with `secret_key_typo` before
/// any derivation. The caller zeroes the array.
#[uniffi::export]
pub fn decode_secret_key(text: String) -> Result<Vec<u8>> {
    let sk = vault_core::secret_key_text::decode(&text)?;
    Ok(sk.expose().to_vec())
}

/// The secret key's text form, for the emergency kit.
#[uniffi::export]
pub fn encode_secret_key(key: Vec<u8>) -> Result<String> {
    let sk = secret_key(key)?;
    Ok(vault_core::secret_key_text::encode(&sk).as_str().to_owned())
}

/// A server revision, from `GET /v1/revisions`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevisionInfo {
    /// The revision ID.
    pub id: u64,
    /// Its `ETag`.
    pub etag: String,
    /// Its size in bytes.
    pub size: u64,
    /// When it was stored, as the server writes it.
    pub created: String,
    /// The token that stored it.
    pub token: String,
}

/// Parses a `GET /v1/revisions` body.
#[uniffi::export]
pub fn parse_revisions(body: Vec<u8>) -> Result<Vec<RevisionInfo>> {
    Ok(vault_client::revisions::parse_revisions(&body)?
        .into_iter()
        .map(|r| RevisionInfo {
            id: r.id,
            etag: r.etag,
            size: r.size,
            created: r.created,
            token: r.token,
        })
        .collect())
}

/// The character classes of a generated password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordOptions {
    /// The length in characters.
    pub length: u32,
    /// `A` to `Z`.
    pub upper: bool,
    /// `a` to `z`.
    pub lower: bool,
    /// `0` to `9`.
    pub digits: bool,
    /// Symbols.
    pub symbols: bool,
    /// Leaves out characters that look alike.
    pub avoid_ambiguous: bool,
}

/// A generated password or passphrase and its entropy in bits.
#[derive(uniffi::Record)]
pub struct Generated {
    /// The password or passphrase.
    pub value: String,
    /// Its entropy in bits.
    pub bits: f64,
}

/// A random password. Every selected class appears at least once.
#[uniffi::export]
pub fn generate_password(options: PasswordOptions) -> Result<Generated> {
    let classes = Classes {
        upper: options.upper,
        lower: options.lower,
        digits: options.digits,
        symbols: options.symbols,
        avoid_ambiguous: options.avoid_ambiguous,
    };
    let length = options.length as usize;
    let value = generate::password(&mut OsRng, length, &classes)?;
    let bits = generate::password_bits(length, &classes)?;
    Ok(Generated {
        value: value.as_str().to_owned(),
        bits,
    })
}

/// A random passphrase from the BIP-39 English list.
#[uniffi::export]
pub fn generate_passphrase(words: u32, separator: String) -> Result<Generated> {
    let value = generate::passphrase(&mut OsRng, words as usize, &separator)?;
    Ok(Generated {
        value: value.as_str().to_owned(),
        bits: generate::passphrase_bits(words as usize),
    })
}

/// Whether the SHA-256 of the leaf certificate's DER encoding equals the pin `fp` (64
/// lowercase hex characters); a malformed pin never matches. The chain, the name, and the dates
/// take no part.
#[uniffi::export]
pub fn pin_matches(fp: String, leaf_der: Vec<u8>) -> bool {
    vault_core::setup::parse_fingerprint(&fp)
        .is_ok_and(|fp| vault_core::setup::pin_matches(&fp, &leaf_der))
}
