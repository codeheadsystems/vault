//! The storage and clocks Kotlin supplies, and the `CommitHost` that the commit sequence writes
//! through. Kotlin does raw file and key-slot I/O; the library parses and writes `local.json`.

use crate::error::{Result, VaultError};
use vault_client::commit::CommitHost;
use vault_client::{ClientState, SecretKeyStore};
use vault_core::secret::SecretKey;

/// A secret key slot in `noBackupFilesDir`, wrapped by the storage key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeySlot {
    /// The secret key.
    Current,
    /// A new secret key waiting for the outcome of its push.
    Pending,
}

/// The app's storage and clocks. The library calls these methods while it holds its state lock,
/// so an implementation never calls back into the library. A failure is a `VaultException`
/// whose code starts with `host.`, such as `host.io` or `host.device_locked`.
#[uniffi::export(with_foreign)]
pub trait Host: Send + Sync {
    /// The `local.json` bytes, or `None` before setup.
    fn read_state(&self) -> Result<Option<Vec<u8>>>;
    /// Writes the `local.json` bytes atomically: a temporary file, `fsync`, then a rename.
    fn write_state(&self, state: Vec<u8>) -> Result<()>;
    /// The unwrapped 16-byte secret key in `slot`, or `None` when the slot is empty. The
    /// implementation zeroes every other array it used to unwrap the key. The returned array
    /// itself cannot be zeroed after the return: it stays in the Java heap until collected, and
    /// UniFFI copies it into a buffer that is freed without zeroing. The library copies the key
    /// into memory it zeroes.
    fn read_key(&self, slot: KeySlot) -> Result<Option<Vec<u8>>>;
    /// Wraps `key` with the storage key and writes it to `slot` atomically. The implementation
    /// zeroes `key`, its own array, once the cipher has wrapped it; the buffer the key crossed in
    /// is freed without zeroing.
    fn write_key(&self, slot: KeySlot, key: Vec<u8>) -> Result<()>;
    /// Deletes `slot`; an empty slot is not an error.
    fn delete_key(&self, slot: KeySlot) -> Result<()>;
    /// Deletes the vault key wrapped by the biometric key; none stored is not an error.
    fn delete_biometric_wrap(&self) -> Result<()>;
    /// The 16-byte device ID from `noBackupFilesDir`, or `None` before the first edit.
    fn read_device_id(&self) -> Result<Option<Vec<u8>>>;
    /// Writes the device ID atomically.
    fn write_device_id(&self, id: Vec<u8>) -> Result<()>;
    /// `System.currentTimeMillis()`.
    fn now_ms(&self) -> u64;
    /// `SystemClock.elapsedRealtime()`, the clock of the idle lock.
    fn elapsed_realtime_ms(&self) -> u64;
}

/// The operating system CSPRNG.
pub(crate) struct OsRng;

impl vault_core::rng::Rng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) -> vault_core::Result<()> {
        getrandom::getrandom(dest).map_err(|_| vault_core::Error::Rng)
    }
}

/// The local state, or `None` before setup.
pub(crate) fn read_state(host: &dyn Host) -> Result<Option<ClientState>> {
    match host.read_state()? {
        None => Ok(None),
        Some(b) => Ok(Some(ClientState::from_json(&b)?)),
    }
}

/// The local state, failing before setup.
pub(crate) fn require_state(host: &dyn Host) -> Result<ClientState> {
    read_state(host)?.ok_or_else(|| VaultError::new("state.no_vault", "no vault is set up"))
}

/// The secret key in `slot`, checked for length.
pub(crate) fn read_key(host: &dyn Host, slot: KeySlot) -> Result<Option<SecretKey>> {
    match host.read_key(slot)? {
        None => Ok(None),
        Some(b) => secret_key(b).map(Some),
    }
}

/// A 16-byte secret key from bytes, which are zeroed.
pub(crate) fn secret_key(b: Vec<u8>) -> Result<SecretKey> {
    let b = zeroize::Zeroizing::new(b);
    let a: [u8; 16] = b
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::usage("a secret key is not 16 bytes"))?;
    Ok(SecretKey::from_bytes(a))
}

/// The device ID, created on first use.
pub(crate) fn device_id(host: &dyn Host) -> Result<[u8; 16]> {
    if let Some(b) = host.read_device_id()? {
        return b
            .try_into()
            .map_err(|_| VaultError::new("host.device_id", "the device ID is not 16 bytes"));
    }
    let mut id = [0u8; 16];
    vault_core::rng::Rng::fill(&mut OsRng, &mut id)?;
    host.write_device_id(id.to_vec())?;
    Ok(id)
}

/// Writes `state`, deleting the biometric wrap first when its `wrap_nonce` differs from the
/// state it replaces (docs/android.md, Unlock and locking).
pub(crate) fn write_state(
    host: &dyn Host,
    replaced: Option<&[u8; 24]>,
    state: &ClientState,
) -> Result<()> {
    if replaced != Some(&state.wrap_nonce) {
        host.delete_biometric_wrap()?;
    }
    host.write_state(state.to_json())
}

/// The commit sequence's storage over a [`Host`]. Android keeps one vault, so the slots ignore
/// the vault ID and the store.
pub(crate) struct Commits<'a> {
    pub(crate) host: &'a dyn Host,
    /// The `wrap_nonce` of the state on disk, `None` before setup.
    pub(crate) wrap_nonce: Option<[u8; 24]>,
    /// The last state written.
    pub(crate) written: Option<ClientState>,
}

impl<'a> Commits<'a> {
    pub(crate) fn new(host: &'a dyn Host, on_disk: Option<&ClientState>) -> Commits<'a> {
        Commits {
            host,
            wrap_nonce: on_disk.map(|s| s.wrap_nonce),
            written: None,
        }
    }
}

impl CommitHost for Commits<'_> {
    type Error = VaultError;

    fn store_current(&mut self, _: SecretKeyStore, _: &[u8; 16], key: &SecretKey) -> Result<()> {
        self.host.write_key(KeySlot::Current, key.expose().to_vec())
    }

    fn store_pending(&mut self, _: SecretKeyStore, _: &[u8; 16], key: &SecretKey) -> Result<()> {
        self.host.write_key(KeySlot::Pending, key.expose().to_vec())
    }

    fn copy_pending_to_current(&mut self, _: SecretKeyStore, _: &[u8; 16]) -> Result<()> {
        let k = read_key(self.host, KeySlot::Pending)?.ok_or_else(|| {
            VaultError::new(
                "secret_key.no_pending",
                "the pending secret key is missing from its slot",
            )
        })?;
        self.store_current(SecretKeyStore::File, &[0; 16], &k)
    }

    fn delete_pending(&mut self, _: SecretKeyStore, _: &[u8; 16]) -> Result<()> {
        self.host.delete_key(KeySlot::Pending)
    }

    fn write_state(&mut self, state: &ClientState) -> Result<()> {
        write_state(self.host, self.wrap_nonce.as_ref(), state)?;
        self.wrap_nonce = Some(state.wrap_nonce);
        self.written = Some(state.clone());
        Ok(())
    }
}
