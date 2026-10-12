//! The client state that changes together with the local vault file, and its `local.json` form.
//! Secrets (the secret key and the vault key) are never part of it.

use crate::error::ClientError;
use core::fmt;
use vault_core::header::{Header, MAX_GENERATION};
use vault_core::json::{self, Map, Value};
use vault_core::sync::{Accepted, SyncState, file_hash};
use vault_core::{IntegrityKind, Result as CoreResult};

/// The version of the `local.json` form this crate reads and writes.
pub const STATE_VERSION: u64 = 1;

/// Where the secret key is stored, chosen at `vault init` or `vault setup` and never changed by a
/// fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKeyStore {
    /// The platform keyring (the Secret Service on Linux).
    Keyring,
    /// A file readable only by the user.
    File,
}

/// Why sync stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// An integrity error; `vault sync --recover` repairs it.
    Integrity,
    /// The server answered `401`; setup repairs it.
    Token,
    /// A credential change on another device, or a pending secret key, needs an interactive sync.
    Credentials,
}

/// A stopped sync: the reason, the error code, and the time in ms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stopped {
    /// Why sync stopped.
    pub reason: StopReason,
    /// The error code, such as `integrity.aead` or `server.token`.
    pub code: String,
    /// When sync stopped, in ms.
    pub at: u64,
}

/// A retired `wrap_nonce` and the ID of the server's revision at its retirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    /// The retired `wrap_nonce`.
    pub nonce: [u8; 24],
    /// The revision that carried the new wrap when this one was retired, or `None` when the
    /// revision list could not be read then. A restore refuses every revision under a nonce
    /// without one.
    pub revision: Option<u64>,
}

/// Everything a client stores outside the secret stores and the transport settings: the local
/// vault file and the sync state that changes with it in one atomic write.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientState {
    /// The vault ID.
    pub vault_id: [u8; 16],
    /// The generation and hash of the file last accepted from the server, or `None` before the
    /// first push of a new vault.
    pub accepted: Option<Accepted>,
    /// The current `wrap_nonce`.
    pub wrap_nonce: [u8; 24],
    /// Every retired `wrap_nonce`, oldest first.
    pub retired: Vec<Retired>,
    /// The `wrap_nonce` values whose wrap failed to open in the credential change on another
    /// device flow.
    pub refused: Vec<[u8; 24]>,
    /// Where the secret key is stored.
    pub secret_key_store: SecretKeyStore,
    /// Whether a new secret key waits for the outcome of a `--new-secret-key` push.
    pub pending_secret_key: bool,
    /// Why sync stopped, or `None` while it runs.
    pub stopped: Option<Stopped>,
    /// Names of local items a background sync dropped because they predate the purge horizon.
    pub dropped: Vec<String>,
    /// The time of the last successful sync, in ms.
    pub last_sync: Option<u64>,
    /// The local vault file.
    pub file: Vec<u8>,
}

impl fmt::Debug for ClientState {
    /// Leaves out the dropped item names, which are vault content, and the file bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientState")
            .field("vault_id", &hex::encode(self.vault_id))
            .field("accepted", &self.accepted)
            .field("wrap_nonce", &hex::encode(self.wrap_nonce))
            .field("retired", &self.retired)
            .field("refused", &self.refused.len())
            .field("secret_key_store", &self.secret_key_store)
            .field("pending_secret_key", &self.pending_secret_key)
            .field("stopped", &self.stopped)
            .field("dropped", &self.dropped.len())
            .field("last_sync", &self.last_sync)
            .field("file_len", &self.file.len())
            .finish()
    }
}

impl ClientState {
    /// A state from `vault-core`'s sync state and a local file, such as a new vault from
    /// `vault init` before its first push. Retired nonces from `sync` carry no revision ID.
    pub fn new(sync: SyncState, file: Vec<u8>, secret_key_store: SecretKeyStore) -> ClientState {
        ClientState {
            vault_id: sync.vault_id,
            accepted: sync.accepted,
            wrap_nonce: sync.wrap_nonce,
            retired: sync
                .retired_wrap_nonces
                .into_iter()
                .map(|nonce| Retired {
                    nonce,
                    revision: None,
                })
                .collect(),
            refused: Vec::new(),
            secret_key_store,
            pending_secret_key: false,
            stopped: None,
            dropped: Vec::new(),
            last_sync: None,
            file,
        }
    }

    /// The part of the state `vault-core`'s sync decisions read.
    pub fn sync_state(&self) -> SyncState {
        SyncState {
            vault_id: self.vault_id,
            accepted: self.accepted.clone(),
            wrap_nonce: self.wrap_nonce,
            retired_wrap_nonces: self.retired.iter().map(|r| r.nonce).collect(),
        }
    }

    /// The local file's header, not authenticated.
    pub fn header(&self) -> CoreResult<Header> {
        vault_core::file::read_header(&self.file)
    }

    /// Whether the local file holds changes not yet pushed: its hash differs from the accepted
    /// hash.
    pub fn unpushed(&self) -> bool {
        self.accepted
            .as_ref()
            .is_none_or(|a| a.file_hash != file_hash(&self.file))
    }

    /// Records a file the client adopted or pushed, as its local file and accepted file.
    pub fn accept(&mut self, generation: u64, file: Vec<u8>) {
        self.accepted = Some(Accepted {
            generation,
            file_hash: file_hash(&file),
        });
        self.file = file;
    }

    /// The retirement entry for `nonce`, when it is retired.
    pub fn retirement(&self, nonce: &[u8; 24]) -> Option<&Retired> {
        self.retired.iter().find(|r| r.nonce == *nonce)
    }

    /// After a credential change lands, here or on another device: retires the current
    /// `wrap_nonce` at `revision` and makes `new` current. A retired nonce never becomes current
    /// again, and `new` leaves the refused list.
    pub fn rotate_wrap_nonce(&mut self, new: [u8; 24], revision: Option<u64>) -> CoreResult<()> {
        if new == self.wrap_nonce {
            return Ok(());
        }
        if self.retirement(&new).is_some() {
            return Err(vault_core::Error::Integrity(
                IntegrityKind::RetiredWrapNonce,
            ));
        }
        self.retired.push(Retired {
            nonce: self.wrap_nonce,
            revision,
        });
        self.wrap_nonce = new;
        self.refused.retain(|n| *n != new);
        Ok(())
    }

    /// Adds `nonce` to the refused list once.
    pub fn refuse(&mut self, nonce: [u8; 24]) {
        if !self.refused.contains(&nonce) {
            self.refused.push(nonce);
        }
    }

    /// The `local.json` form: compact JSON with keys in byte order.
    pub fn to_json(&self) -> Vec<u8> {
        let mut m = Map::new();
        let s = |v: String| Value::String(v);
        m.insert("v".into(), Value::Number(STATE_VERSION));
        m.insert("vault_id".into(), s(hex::encode(self.vault_id)));
        m.insert(
            "accepted".into(),
            match &self.accepted {
                None => Value::Null,
                Some(a) => object([
                    ("generation", Value::Number(a.generation)),
                    ("hash", s(hex::encode(a.file_hash))),
                ]),
            },
        );
        m.insert("wrap_nonce".into(), s(hex::encode(self.wrap_nonce)));
        m.insert(
            "retired".into(),
            Value::Array(
                self.retired
                    .iter()
                    .map(|r| {
                        object([
                            ("nonce", s(hex::encode(r.nonce))),
                            ("revision", r.revision.map_or(Value::Null, Value::Number)),
                        ])
                    })
                    .collect(),
            ),
        );
        m.insert(
            "refused".into(),
            Value::Array(self.refused.iter().map(|n| s(hex::encode(n))).collect()),
        );
        m.insert(
            "secret_key_store".into(),
            s(match self.secret_key_store {
                SecretKeyStore::Keyring => "keyring",
                SecretKeyStore::File => "file",
            }
            .into()),
        );
        m.insert(
            "pending_secret_key".into(),
            Value::Bool(self.pending_secret_key),
        );
        m.insert(
            "stopped".into(),
            match &self.stopped {
                None => Value::Null,
                Some(st) => object([
                    (
                        "reason",
                        s(match st.reason {
                            StopReason::Integrity => "integrity",
                            StopReason::Token => "token",
                            StopReason::Credentials => "credentials",
                        }
                        .into()),
                    ),
                    ("code", s(st.code.clone())),
                    ("at", Value::Number(st.at)),
                ]),
            },
        );
        m.insert(
            "dropped".into(),
            Value::Array(self.dropped.iter().cloned().map(s).collect()),
        );
        m.insert(
            "last_sync".into(),
            self.last_sync.map_or(Value::Null, Value::Number),
        );
        m.insert("file".into(), s(hex::encode(&self.file)));
        json::to_vec(&Value::Object(m)).to_vec()
    }

    /// Parses the `local.json` form strictly: `v` is 1, every key is present and no other, hex
    /// values are lowercase with their exact lengths, and numbers are integers in `[0, 2^53)`.
    pub fn from_json(bytes: &[u8]) -> Result<ClientState, ClientError> {
        let mut m = take_object(json::parse(bytes).map_err(|_| ClientError::LocalState)?)?;
        if number(take(&mut m, "v")?)? != STATE_VERSION {
            return Err(ClientError::LocalState);
        }
        let vault_id = hex_array(take(&mut m, "vault_id")?)?;
        let accepted = match take(&mut m, "accepted")? {
            Value::Null => None,
            v => {
                let mut a = take_object(v)?;
                let generation = number(take(&mut a, "generation")?)?;
                if !(1..=MAX_GENERATION).contains(&generation) {
                    return Err(ClientError::LocalState);
                }
                let file_hash = hex_array(take(&mut a, "hash")?)?;
                no_more(&a)?;
                Some(Accepted {
                    generation,
                    file_hash,
                })
            }
        };
        let wrap_nonce = hex_array(take(&mut m, "wrap_nonce")?)?;
        let retired = array(take(&mut m, "retired")?)?
            .into_iter()
            .map(|v| {
                let mut r = take_object(v)?;
                let nonce = hex_array(take(&mut r, "nonce")?)?;
                let revision = match take(&mut r, "revision")? {
                    Value::Null => None,
                    v => Some(number(v)?),
                };
                no_more(&r)?;
                Ok(Retired { nonce, revision })
            })
            .collect::<Result<_, ClientError>>()?;
        let refused = array(take(&mut m, "refused")?)?
            .into_iter()
            .map(hex_array)
            .collect::<Result<_, _>>()?;
        let secret_key_store = match string(take(&mut m, "secret_key_store")?)?.as_str() {
            "keyring" => SecretKeyStore::Keyring,
            "file" => SecretKeyStore::File,
            _ => return Err(ClientError::LocalState),
        };
        let pending_secret_key = match take(&mut m, "pending_secret_key")? {
            Value::Bool(b) => b,
            _ => return Err(ClientError::LocalState),
        };
        let stopped = match take(&mut m, "stopped")? {
            Value::Null => None,
            v => {
                let mut st = take_object(v)?;
                let reason = match string(take(&mut st, "reason")?)?.as_str() {
                    "integrity" => StopReason::Integrity,
                    "token" => StopReason::Token,
                    "credentials" => StopReason::Credentials,
                    _ => return Err(ClientError::LocalState),
                };
                let code = string(take(&mut st, "code")?)?;
                if code.is_empty() {
                    return Err(ClientError::LocalState);
                }
                let at = number(take(&mut st, "at")?)?;
                no_more(&st)?;
                Some(Stopped { reason, code, at })
            }
        };
        let dropped = array(take(&mut m, "dropped")?)?
            .into_iter()
            .map(string)
            .collect::<Result<_, _>>()?;
        let last_sync = match take(&mut m, "last_sync")? {
            Value::Null => None,
            v => Some(number(v)?),
        };
        let file = hex_bytes(&string(take(&mut m, "file")?)?)?;
        no_more(&m)?;
        Ok(ClientState {
            vault_id,
            accepted,
            wrap_nonce,
            retired,
            refused,
            secret_key_store,
            pending_secret_key,
            stopped,
            dropped,
            last_sync,
            file,
        })
    }
}

fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn take(m: &mut Map, k: &str) -> Result<Value, ClientError> {
    m.remove(k).ok_or(ClientError::LocalState)
}

fn no_more(m: &Map) -> Result<(), ClientError> {
    if m.is_empty() {
        Ok(())
    } else {
        Err(ClientError::LocalState)
    }
}

fn take_object(mut v: Value) -> Result<Map, ClientError> {
    v.take_object().ok_or(ClientError::LocalState)
}

fn array(mut v: Value) -> Result<Vec<Value>, ClientError> {
    v.take_array().ok_or(ClientError::LocalState)
}

fn string(mut v: Value) -> Result<String, ClientError> {
    v.take_string().ok_or(ClientError::LocalState)
}

fn number(v: Value) -> Result<u64, ClientError> {
    match v {
        Value::Number(n) => Ok(n),
        _ => Err(ClientError::LocalState),
    }
}

/// Lowercase hex of any even length.
fn hex_bytes(s: &str) -> Result<Vec<u8>, ClientError> {
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(ClientError::LocalState);
    }
    hex::decode(s).map_err(|_| ClientError::LocalState)
}

fn hex_array<const N: usize>(v: Value) -> Result<[u8; N], ClientError> {
    hex_bytes(&string(v)?)?
        .try_into()
        .map_err(|_| ClientError::LocalState)
}
