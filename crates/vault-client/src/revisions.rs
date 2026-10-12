//! The `GET /v1/revisions` response.

use crate::error::ClientError;
use vault_core::json::{self, Map, Value};

/// One retained revision as the server lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionInfo {
    /// The revision ID, increasing with every stored revision.
    pub id: u64,
    /// The `ETag` of the revision's file, quoted.
    pub etag: String,
    /// The file size in bytes.
    pub size: u64,
    /// When the server stored it, as RFC 3339 text.
    pub created: String,
    /// The name of the token that pushed it.
    pub token: String,
}

/// Parses `{"revisions": [...]}`. Keys the spec does not define are ignored, so a server may add
/// fields.
pub fn parse_revisions(body: &[u8]) -> Result<Vec<RevisionInfo>, ClientError> {
    let bad = |_| ClientError::BadResponse;
    let mut top = json::parse(body)
        .map_err(bad)?
        .take_object()
        .ok_or(ClientError::BadResponse)?;
    let list = take(&mut top, "revisions")?
        .take_array()
        .ok_or(ClientError::BadResponse)?;
    list.into_iter()
        .map(|mut v| {
            let mut m = v.take_object().ok_or(ClientError::BadResponse)?;
            Ok(RevisionInfo {
                id: number(&mut m, "id")?,
                etag: string(&mut m, "etag")?,
                size: number(&mut m, "size")?,
                created: string(&mut m, "created")?,
                token: string(&mut m, "token")?,
            })
        })
        .collect()
}

fn take(m: &mut Map, k: &str) -> Result<Value, ClientError> {
    m.remove(k).ok_or(ClientError::BadResponse)
}

fn number(m: &mut Map, k: &str) -> Result<u64, ClientError> {
    match take(m, k)? {
        Value::Number(n) => Ok(n),
        _ => Err(ClientError::BadResponse),
    }
}

fn string(m: &mut Map, k: &str) -> Result<String, ClientError> {
    take(m, k)?.take_string().ok_or(ClientError::BadResponse)
}
