//! Reading an export file: the size cap, the three kinds of export, and the decryption of a
//! password-protected one.

use crate::crypto::{self, EncString, Kdf, OpenError};
use crate::error::{Error, Result};
use crate::source::{self, Json};

/// The largest export file read, 64 MiB.
pub const MAX_EXPORT_SIZE: usize = 64 << 20;

/// A parsed export file.
pub enum Export {
    /// A plain export, ready to import.
    Plain(PlainExport),
    /// A password-protected export, which [`ProtectedExport::decrypt`] opens.
    Protected(ProtectedExport),
}

/// A plain export: the `folders` and `items` of the file, or of a password-protected export's
/// decrypted `data`. Its strings are zeroized on drop.
pub struct PlainExport {
    pub(crate) root: Json,
}

/// A password-protected export whose KDF parameters are inside the bounds.
pub struct ProtectedExport {
    salt: String,
    kdf: Kdf,
    validation: EncString,
    data: EncString,
}

/// Parses an export file. A file over [`MAX_EXPORT_SIZE`], an account-restricted export, and a
/// password-protected export with an unknown `kdfType` or parameters outside the bounds are
/// refused here, before any key derivation.
pub fn parse(bytes: &[u8]) -> Result<Export> {
    if bytes.len() > MAX_EXPORT_SIZE {
        return Err(Error::TooLarge);
    }
    let root = source::parse(bytes)?;
    match root.get("encrypted") {
        Some(Json::Bool(true)) => {}
        Some(Json::Bool(false)) | None => return plain(root).map(Export::Plain),
        Some(_) => return Err(Error::NotAnExport),
    }
    if !matches!(root.get("passwordProtected"), Some(Json::Bool(true))) {
        return Err(Error::AccountRestricted);
    }
    let text = |k: &str| root.get(k).and_then(Json::as_str).ok_or(Error::NotAnExport);
    let salt = text("salt")?;
    if salt.is_empty() {
        return Err(Error::NotAnExport);
    }
    let kdf = Kdf::from_export(&root)?;
    Ok(Export::Protected(ProtectedExport {
        salt: salt.to_owned(),
        kdf,
        validation: EncString::parse(text("encKeyValidation_DO_NOT_EDIT")?)?,
        data: EncString::parse(text("data")?)?,
    }))
}

/// Checks the shape of a plain export: an object with an `items` array, and `folders` an array
/// or null when present.
fn plain(root: Json) -> Result<PlainExport> {
    let items_ok = root.get("items").and_then(Json::as_array).is_some();
    let folders_ok = root
        .get("folders")
        .is_none_or(|f| f.is_null() || f.as_array().is_some());
    if !items_ok || !folders_ok {
        return Err(Error::NotAnExport);
    }
    Ok(PlainExport { root })
}

impl Export {
    /// Whether [`ProtectedExport::decrypt`] must open the export before it imports.
    pub fn needs_password(&self) -> bool {
        matches!(self, Export::Protected(_))
    }
}

impl ProtectedExport {
    /// The key derivation and its parameters, already checked against the bounds.
    pub fn kdf(&self) -> Kdf {
        self.kdf
    }

    /// Derives the keys from `password`, checks them against `encKeyValidation_DO_NOT_EDIT`, and
    /// decrypts `data` into a plain export. Each MAC is checked, in constant time, before its
    /// ciphertext is decrypted. A MAC failure on the validation string is a wrong password; a
    /// failure on `data` after it is a corrupt file.
    pub fn decrypt(&self, password: &str) -> Result<PlainExport> {
        let keys = crypto::derive(password, &self.salt, self.kdf)?;
        crypto::open(&keys, &self.validation).map_err(|e| match e {
            OpenError::Mac => Error::WrongPassword,
            OpenError::Padding => Error::Corrupt,
        })?;
        let data = crypto::open(&keys, &self.data).map_err(|_| Error::Corrupt)?;
        let root = source::parse(&data)?;
        if !matches!(root.get("encrypted"), Some(Json::Bool(false)) | None) {
            return Err(Error::NotAnExport);
        }
        plain(root)
    }
}

impl PlainExport {
    pub(crate) fn items(&self) -> &[Json] {
        self.root
            .get("items")
            .and_then(Json::as_array)
            .unwrap_or(&[])
    }

    pub(crate) fn folders(&self) -> &[Json] {
        self.root
            .get("folders")
            .and_then(Json::as_array)
            .unwrap_or(&[])
    }

    /// The number of entries in the export's `collections`, which the import skips.
    pub fn collections(&self) -> usize {
        self.root
            .get("collections")
            .and_then(Json::as_array)
            .map_or(0, <[Json]>::len)
    }
}
