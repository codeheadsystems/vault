//! Secret key storage: the Secret Service (GNOME Keyring or KWallet) or the `secret-key` file in
//! the data directory, each with the slots `current` and `pending` per vault ID.
//!
//! The store is chosen at `vault init` or `vault setup` and recorded in `local.json`. Nothing here
//! falls back from one store to the other: a Secret Service that cannot be reached is an error.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use vault_core::secret::SecretKey;
use zeroize::{Zeroize, Zeroizing};

/// The file store's name in the data directory.
pub const FILE_NAME: &str = "secret-key";

/// The largest `secret-key` file read.
const FILE_MAX: u64 = 64 * 1024;

/// A secret key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The secret key the vault opens with.
    Current,
    /// A new secret key during a credential change, until the change is confirmed.
    Pending,
}

impl Slot {
    /// The slot's name, as the `slot` attribute and the file store spell it.
    pub fn name(self) -> &'static str {
        match self {
            Slot::Current => "current",
            Slot::Pending => "pending",
        }
    }
}

/// Where the secret keys are stored, as `local.json` records it in `secret_key_store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    /// The Secret Service.
    Keyring,
    /// The `secret-key` file.
    File,
}

/// A failure of a secret key store. Messages never contain key material.
#[derive(Debug)]
pub enum SecretsError {
    /// The Secret Service cannot be reached.
    Unreachable,
    /// The Secret Service refused an operation, such as a dismissed unlock prompt.
    Keyring(&'static str),
    /// The `secret-key` file is not mode `0600`, not a regular file, or not this user's.
    UnsafeFile(PathBuf),
    /// A stored value does not parse.
    Corrupt,
    /// Reading or writing the `secret-key` file failed.
    Io(std::io::Error),
}

impl SecretsError {
    /// The exit code: always 1.
    pub fn exit_code(&self) -> u8 {
        1
    }
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretsError::Unreachable => f.write_str(
                "the Secret Service that holds the secret key cannot be reached; run the command \
                 in a desktop session with GNOME Keyring or KWallet",
            ),
            SecretsError::Keyring(what) => {
                write!(f, "the Secret Service refused to {what} the secret key")
            }
            SecretsError::UnsafeFile(p) => write!(
                f,
                "{} must be a regular file of this user with mode 0600",
                p.display()
            ),
            SecretsError::Corrupt => f.write_str("the stored secret key does not parse"),
            SecretsError::Io(e) => write!(f, "cannot use the secret key file: {e}"),
        }
    }
}

impl std::error::Error for SecretsError {}

/// A secret key store.
pub trait SecretStore {
    /// The key in `slot` for the vault, if stored.
    fn get(&self, vault_id: &[u8; 16], slot: Slot) -> Result<Option<SecretKey>, SecretsError>;
    /// Stores `key` in `slot`, replacing what the slot held.
    fn put(&self, vault_id: &[u8; 16], slot: Slot, key: &SecretKey) -> Result<(), SecretsError>;
    /// Empties `slot`; an empty slot is not an error.
    fn delete(&self, vault_id: &[u8; 16], slot: Slot) -> Result<(), SecretsError>;
}

/// The store of `kind`; `data_dir` is where the file store keeps `secret-key`.
pub fn open(kind: StoreKind, data_dir: &Path) -> Box<dyn SecretStore> {
    match kind {
        StoreKind::Keyring => Box::new(Keyring),
        StoreKind::File => Box::new(FileStore::new(data_dir)),
    }
}

/// Whether the Secret Service is reachable and has a default collection, for the choice of
/// store at `vault init` and `vault setup`.
pub fn keyring_available() -> bool {
    Keyring::connect().is_ok_and(|s| s.get_default_collection().is_ok())
}

fn decode_key(hex_text: &str) -> Result<SecretKey, SecretsError> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    hex::decode_to_slice(hex_text.trim(), &mut *bytes).map_err(|_| SecretsError::Corrupt)?;
    Ok(SecretKey::from_bytes(*bytes))
}

fn encode_key(key: &SecretKey) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(32));
    for b in key.expose() {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0xf)]));
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The Secret Service, with one item per vault and slot, found by the attributes
/// `application = vault`, `vault_id`, and `slot`.
struct Keyring;

mod keyring {
    use super::*;
    use secret_service::EncryptionType;
    use secret_service::blocking::SecretService;

    impl Keyring {
        pub(super) fn connect() -> Result<SecretService<'static>, SecretsError> {
            SecretService::connect(EncryptionType::Dh).map_err(|_| SecretsError::Unreachable)
        }
    }

    fn attributes(vault_hex: &str, slot: Slot) -> HashMap<&str, &str> {
        HashMap::from([
            ("application", "vault"),
            ("vault_id", vault_hex),
            ("slot", slot.name()),
        ])
    }

    impl SecretStore for Keyring {
        fn get(&self, vault_id: &[u8; 16], slot: Slot) -> Result<Option<SecretKey>, SecretsError> {
            let s = Keyring::connect()?;
            let vault_hex = hex::encode(vault_id);
            let found = s
                .search_items(attributes(&vault_hex, slot))
                .map_err(|_| SecretsError::Keyring("search for"))?;
            let item = match (found.unlocked.first(), found.locked.first()) {
                (Some(i), _) => i,
                (None, Some(i)) => {
                    i.unlock().map_err(|_| SecretsError::Keyring("unlock"))?;
                    i
                }
                (None, None) => return Ok(None),
            };
            let secret = Zeroizing::new(
                item.get_secret()
                    .map_err(|_| SecretsError::Keyring("read"))?,
            );
            let text = std::str::from_utf8(&secret).map_err(|_| SecretsError::Corrupt)?;
            decode_key(text).map(Some)
        }

        fn put(
            &self,
            vault_id: &[u8; 16],
            slot: Slot,
            key: &SecretKey,
        ) -> Result<(), SecretsError> {
            let s = Keyring::connect()?;
            let c = s
                .get_default_collection()
                .map_err(|_| SecretsError::Unreachable)?;
            c.ensure_unlocked()
                .map_err(|_| SecretsError::Keyring("unlock"))?;
            let vault_hex = hex::encode(vault_id);
            let label = match slot {
                Slot::Current => format!("vault secret key ({})", &vault_hex[..8]),
                Slot::Pending => format!("vault pending secret key ({})", &vault_hex[..8]),
            };
            let text = encode_key(key);
            c.create_item(
                &label,
                attributes(&vault_hex, slot),
                text.as_bytes(),
                true,
                "text/plain",
            )
            .map_err(|_| SecretsError::Keyring("store"))?;
            Ok(())
        }

        fn delete(&self, vault_id: &[u8; 16], slot: Slot) -> Result<(), SecretsError> {
            let s = Keyring::connect()?;
            let vault_hex = hex::encode(vault_id);
            let found = s
                .search_items(attributes(&vault_hex, slot))
                .map_err(|_| SecretsError::Keyring("search for"))?;
            for i in found.unlocked.iter().chain(found.locked.iter()) {
                i.delete().map_err(|_| SecretsError::Keyring("delete"))?;
            }
            Ok(())
        }
    }
}

/// The `secret-key` file: a JSON object from vault ID to slot to key, all lowercase hex. Callers
/// hold the data directory's `lock` while they change it.
struct FileStore {
    path: PathBuf,
}

/// The file's contents, with every key string zeroised when dropped.
type FileMap = BTreeMap<String, BTreeMap<String, Zeroizing<String>>>;

impl FileStore {
    fn new(data_dir: &Path) -> FileStore {
        FileStore {
            path: data_dir.join(FILE_NAME),
        }
    }

    /// The file's contents; a missing file is empty.
    fn load(&self) -> Result<FileMap, SecretsError> {
        let mut f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileMap::new()),
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
                return Err(SecretsError::UnsafeFile(self.path.clone()));
            }
            Err(e) => return Err(SecretsError::Io(e)),
        };
        let m = f.metadata().map_err(SecretsError::Io)?;
        if !m.is_file() || m.uid() != rustix::process::getuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err(SecretsError::UnsafeFile(self.path.clone()));
        }
        if m.len() > FILE_MAX {
            return Err(SecretsError::Corrupt);
        }
        let mut text = Zeroizing::new(Vec::with_capacity(FILE_MAX as usize + 1));
        Read::by_ref(&mut f)
            .take(FILE_MAX + 1)
            .read_to_end(&mut text)
            .map_err(SecretsError::Io)?;
        serde_json::from_slice(&text).map_err(|_| SecretsError::Corrupt)
    }

    /// Replaces the file: a temporary file of mode `0600` is written, synced, and renamed over
    /// it, and the directory is synced.
    fn save(&self, map: &FileMap) -> Result<(), SecretsError> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        let tmp = dir.join(format!("{FILE_NAME}.tmp"));
        let mut text = Zeroizing::new(Vec::with_capacity(FILE_MAX as usize));
        serde_json::to_writer(&mut *text, map).map_err(|_| SecretsError::Corrupt)?;
        text.push(b'\n');
        let _ = std::fs::remove_file(&tmp);
        let written = (|| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&tmp)?;
            f.write_all(&text)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            std::fs::File::open(dir)?.sync_all()
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written.map_err(SecretsError::Io)
    }
}

impl SecretStore for FileStore {
    fn get(&self, vault_id: &[u8; 16], slot: Slot) -> Result<Option<SecretKey>, SecretsError> {
        let map = self.load()?;
        match map
            .get(&hex::encode(vault_id))
            .and_then(|slots| slots.get(slot.name()))
        {
            Some(text) => decode_key(text).map(Some),
            None => Ok(None),
        }
    }

    fn put(&self, vault_id: &[u8; 16], slot: Slot, key: &SecretKey) -> Result<(), SecretsError> {
        let mut map = self.load()?;
        map.entry(hex::encode(vault_id))
            .or_default()
            .insert(slot.name().to_owned(), encode_key(key));
        self.save(&map)
    }

    fn delete(&self, vault_id: &[u8; 16], slot: Slot) -> Result<(), SecretsError> {
        let mut map = self.load()?;
        let id = hex::encode(vault_id);
        let Some(slots) = map.get_mut(&id) else {
            return Ok(());
        };
        if let Some(mut old) = slots.remove(slot.name()) {
            old.zeroize();
        } else {
            return Ok(());
        }
        if slots.is_empty() {
            map.remove(&id);
        }
        self.save(&map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_bytes([b; 16])
    }

    fn get(s: &dyn SecretStore, id: &[u8; 16], slot: Slot) -> Option<[u8; 16]> {
        s.get(id, slot).unwrap().map(|k| *k.expose())
    }

    #[test]
    fn file_store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(StoreKind::File, dir.path());
        let a = [1u8; 16];
        let b = [2u8; 16];
        assert_eq!(get(&*s, &a, Slot::Current), None);
        s.put(&a, Slot::Current, &key(0xaa)).unwrap();
        s.put(&b, Slot::Current, &key(0xbb)).unwrap();
        s.put(&a, Slot::Pending, &key(0xcc)).unwrap();
        assert_eq!(get(&*s, &a, Slot::Current), Some([0xaa; 16]));
        assert_eq!(get(&*s, &a, Slot::Pending), Some([0xcc; 16]));
        assert_eq!(get(&*s, &b, Slot::Current), Some([0xbb; 16]));
        assert_eq!(get(&*s, &b, Slot::Pending), None);

        let path = dir.path().join(FILE_NAME);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!dir.path().join("secret-key.tmp").exists());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&hex::encode(a)));
        assert!(text.contains(&"cc".repeat(16)));

        // Promotion as the commit does it: copy, then delete the pending slot.
        s.put(&a, Slot::Current, &key(0xcc)).unwrap();
        s.delete(&a, Slot::Pending).unwrap();
        assert_eq!(get(&*s, &a, Slot::Current), Some([0xcc; 16]));
        assert_eq!(get(&*s, &a, Slot::Pending), None);
        s.delete(&a, Slot::Pending).unwrap();

        s.delete(&a, Slot::Current).unwrap();
        s.delete(&a, Slot::Current).unwrap();
        assert_eq!(get(&*s, &a, Slot::Current), None);
        assert_eq!(get(&*s, &b, Slot::Current), Some([0xbb; 16]));
    }

    #[test]
    fn file_store_refuses_unsafe_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(StoreKind::File, dir.path());
        let id = [3u8; 16];
        s.put(&id, Slot::Current, &key(1)).unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            s.get(&id, Slot::Current),
            Err(SecretsError::UnsafeFile(_))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&path, dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), &path).unwrap();
        assert!(matches!(
            s.get(&id, Slot::Current),
            Err(SecretsError::UnsafeFile(_))
        ));
    }

    #[test]
    fn file_store_reports_corrupt_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let write = |text: &str| {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        };
        let s = open(StoreKind::File, dir.path());
        let id = [4u8; 16];
        write("not json");
        assert!(matches!(
            s.get(&id, Slot::Current),
            Err(SecretsError::Corrupt)
        ));
        write(&format!(
            r#"{{"{}": {{"current": "abcd"}}}}"#,
            hex::encode(id)
        ));
        assert!(matches!(
            s.get(&id, Slot::Current),
            Err(SecretsError::Corrupt)
        ));
    }

    #[test]
    fn store_kind_spelling() {
        assert_eq!(
            serde_json::to_string(&StoreKind::Keyring).unwrap(),
            "\"keyring\""
        );
        assert_eq!(
            serde_json::from_str::<StoreKind>("\"file\"").unwrap(),
            StoreKind::File
        );
    }

    /// Needs a desktop session with a Secret Service (GNOME Keyring or KWallet) and an unlocked
    /// default collection; it writes and deletes items for a random vault ID.
    #[test]
    #[ignore = "needs a Secret Service"]
    fn keyring_round_trip() {
        assert!(keyring_available());
        let s = open(StoreKind::Keyring, Path::new("/nonexistent"));
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).unwrap();
        s.put(&id, Slot::Current, &key(0x11)).unwrap();
        s.put(&id, Slot::Current, &key(0x12)).unwrap();
        s.put(&id, Slot::Pending, &key(0x13)).unwrap();
        assert_eq!(get(&*s, &id, Slot::Current), Some([0x12; 16]));
        s.put(&id, Slot::Current, &key(0x13)).unwrap();
        s.delete(&id, Slot::Pending).unwrap();
        assert_eq!(get(&*s, &id, Slot::Current), Some([0x13; 16]));
        assert_eq!(get(&*s, &id, Slot::Pending), None);
        s.delete(&id, Slot::Current).unwrap();
        assert_eq!(get(&*s, &id, Slot::Current), None);
    }
}
