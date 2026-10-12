//! The agent protocol of `docs/cli.md`: one request per connection, each message a big-endian
//! `u32` length of at most 64 KiB and that many bytes of JSON; and the start message a command
//! writes to a new agent's standard input.
//!
//! Messages that carry the vault key live in zeroizing buffers of exactly their size, so encoding
//! leaves no reallocated copy behind.

use super::AgentSettings;
use crate::harden::LockedBuf;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Write};
use std::time::Duration;
use vault_core::secret::VaultKey;
use zeroize::Zeroizing;

/// The protocol version.
pub const VERSION: u32 = 1;
/// The largest message body.
pub const FRAME_MAX: usize = 64 * 1024;
/// How long either end waits for the other to read or write a message.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The size of the start message.
pub const START_LEN: usize = 16 + 32 + 8 * 3 + 1;

/// A framing failure.
#[derive(Debug)]
pub enum FrameError {
    /// The length prefix exceeds [`FRAME_MAX`].
    TooLarge,
    /// The connection closed or failed mid-message.
    Io(std::io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge => f.write_str("an agent message is too large"),
            FrameError::Io(e) => write!(f, "the agent connection failed: {e}"),
        }
    }
}

/// A request.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    /// The protocol version.
    pub v: u32,
    /// `key`, `sync`, `status`, or `lock`.
    pub op: String,
}

/// An error response's body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// A stable code, such as `agent.bad_request`.
    pub code: String,
    /// A message that never contains key material.
    pub message: String,
}

/// An error response.
#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error.
    pub error: ErrorBody,
}

/// The `key` response. The key travels as hex, so the JSON parser never unescapes it into a
/// buffer it does not zeroise.
#[derive(Serialize, Deserialize)]
pub struct KeyResponse {
    /// The vault ID, hex.
    pub vault_id: String,
    /// The vault key, hex.
    pub vault_key: Zeroizing<String>,
}

/// The `status` response; times are ms since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    /// When the agent started with the key.
    pub unlocked_at: u64,
    /// When the agent ends unless a `key` request comes first.
    pub locks_at: u64,
    /// The last background sync that succeeded.
    pub last_sync: Option<u64>,
    /// The failure of the last background sync, cleared by a success.
    pub last_error: Option<ErrorBody>,
}

/// Counts the bytes a serialisation writes.
struct Count(usize);

impl Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len();
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `v` as a frame: the length prefix and the JSON, in a zeroizing buffer of exactly its size.
pub fn encode<T: Serialize>(v: &T) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let bad = |e: serde_json::Error| FrameError::Io(std::io::Error::other(e));
    let mut n = Count(0);
    serde_json::to_writer(&mut n, v).map_err(bad)?;
    if n.0 > FRAME_MAX {
        return Err(FrameError::TooLarge);
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(4 + n.0));
    buf.extend_from_slice(&(n.0 as u32).to_be_bytes());
    serde_json::to_writer(&mut *buf, v).map_err(bad)?;
    Ok(buf)
}

/// Writes a frame made by [`encode`].
pub fn write_frame(w: &mut impl Write, frame: &[u8]) -> Result<(), FrameError> {
    w.write_all(frame)
        .and_then(|()| w.flush())
        .map_err(FrameError::Io)
}

/// Reads one frame's JSON. A length over [`FRAME_MAX`] is refused before anything else is read.
pub fn read_frame(r: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).map_err(FrameError::Io)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > FRAME_MAX {
        return Err(FrameError::TooLarge);
    }
    let mut buf = Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut buf).map_err(FrameError::Io)?;
    Ok(buf)
}

/// What a new agent receives on standard input: the vault ID, the vault key, and its settings.
pub struct Start {
    /// The vault ID.
    pub vault_id: [u8; 16],
    /// The vault key, in a locked page.
    pub key: LockedBuf,
    /// The settings.
    pub settings: AgentSettings,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The start message: the vault ID, the key, `agent.idle`, `agent.max`, and `sync.interval` in
/// ms as big-endian `u64`s, and `sync.auto` as one byte.
pub fn encode_start(vault_id: &[u8; 16], key: &VaultKey, s: &AgentSettings) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(START_LEN));
    out.extend_from_slice(vault_id);
    out.extend_from_slice(key.expose());
    for d in [s.idle, s.max, s.sync_interval] {
        out.extend_from_slice(&millis(d).to_be_bytes());
    }
    out.push(u8::from(s.sync_auto));
    out
}

/// Parses a start message; the key goes into a locked page.
pub fn decode_start(b: &[u8]) -> Option<Start> {
    if b.len() != START_LEN {
        return None;
    }
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&b[..16]);
    let key = super::locked_key(&b[16..48]).ok()?;
    let ms = |i: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[48 + 8 * i..56 + 8 * i]);
        Duration::from_millis(u64::from_be_bytes(x))
    };
    let sync_auto = match b[72] {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some(Start {
        vault_id,
        key,
        settings: AgentSettings {
            idle: ms(0),
            max: ms(1),
            sync_interval: ms(2),
            sync_auto,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let f = encode(&Request {
            v: 1,
            op: "status".into(),
        })
        .unwrap();
        assert_eq!(&f[..4], &(f.len() as u32 - 4).to_be_bytes());
        assert_eq!(f.len(), f.capacity());
        let got = read_frame(&mut &f[..]).unwrap();
        let r: Request = serde_json::from_slice(&got).unwrap();
        assert_eq!((r.v, r.op.as_str()), (1, "status"));
    }

    #[test]
    fn the_size_limit_is_64_kib() {
        let mut at_limit = (FRAME_MAX as u32).to_be_bytes().to_vec();
        at_limit.extend(vec![b' '; FRAME_MAX]);
        assert_eq!(read_frame(&mut &at_limit[..]).unwrap().len(), FRAME_MAX);
        let over = (FRAME_MAX as u32 + 1).to_be_bytes();
        assert!(matches!(
            read_frame(&mut &over[..]),
            Err(FrameError::TooLarge)
        ));
        let big = "x".repeat(FRAME_MAX);
        assert!(matches!(encode(&big), Err(FrameError::TooLarge)));
    }

    #[test]
    fn truncated_frames_fail() {
        assert!(matches!(
            read_frame(&mut &[0u8, 0][..]),
            Err(FrameError::Io(_))
        ));
        let mut short = 10u32.to_be_bytes().to_vec();
        short.extend_from_slice(b"{}");
        assert!(matches!(
            read_frame(&mut &short[..]),
            Err(FrameError::Io(_))
        ));
    }

    #[test]
    fn start_messages_round_trip() {
        let settings = AgentSettings {
            idle: Duration::from_secs(900),
            max: Duration::from_secs(8 * 3600),
            sync_interval: Duration::from_millis(1500),
            sync_auto: true,
        };
        let key = VaultKey::from_bytes([7; 32]);
        let m = encode_start(&[9; 16], &key, &settings);
        assert_eq!(m.len(), START_LEN);
        let s = decode_start(&m).unwrap();
        assert_eq!(s.vault_id, [9; 16]);
        assert_eq!(&s.key[..], &[7; 32]);
        assert_eq!(s.settings, settings);
        let mut bad = m.clone();
        bad[START_LEN - 1] = 2;
        assert!(decode_start(&bad).is_none());
        assert!(decode_start(&m[1..]).is_none());
    }
}
