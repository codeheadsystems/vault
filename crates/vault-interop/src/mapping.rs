//! What the import and the export share: the Bitwarden item types, the typed objects, the hidden
//! keys, and the URI match values.

/// Bitwarden `type` of a login.
pub(crate) const BW_LOGIN: u64 = 1;
/// Bitwarden `type` of a secure note.
pub(crate) const BW_NOTE: u64 = 2;

/// The key of the typed object that an item of a known `type` from 3 on carries.
pub(crate) fn object_key(bw_type: u64) -> Option<&'static str> {
    match bw_type {
        3 => Some("card"),
        4 => Some("identity"),
        5 => Some("sshKey"),
        6 => Some("bankAccount"),
        7 => Some("driversLicense"),
        8 => Some("passport"),
        _ => None,
    }
}

/// The item keys the import reads or the export writes itself, which are never a typed object.
pub(crate) const ITEM_KEYS: [&str; 16] = [
    "passwordHistory",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "id",
    "organizationId",
    "folderId",
    "type",
    "reprompt",
    "name",
    "notes",
    "favorite",
    "fields",
    "login",
    "secureNote",
    "collectionIds",
];

/// Typed-object keys whose custom fields are hidden.
pub(crate) const HIDDEN_KEYS: [&str; 11] = [
    "number",
    "code",
    "ssn",
    "passportNumber",
    "licenseNumber",
    "privateKey",
    "accountNumber",
    "routingNumber",
    "iban",
    "pin",
    "nationalIdentificationNumber",
];

/// Bitwarden URI `match` 4, a regular expression.
pub(crate) const MATCH_REGEX: u64 = 4;

/// The vault `match` for a Bitwarden one, with `None` for `null`.
pub(crate) fn match_to_vault(m: Option<u64>) -> &'static str {
    match m {
        None | Some(0) => "base_domain",
        Some(1) => "host",
        Some(2) => "starts_with",
        Some(3) => "exact",
        // A later value has no vault counterpart and is read as never.
        _ => "never",
    }
}

/// The Bitwarden `match` for a vault one; `regex` is whether the URI was imported with `match` 4.
pub(crate) fn match_to_bitwarden(m: &str, regex: bool) -> u64 {
    match m {
        "base_domain" => 0,
        "host" => 1,
        "starts_with" => 2,
        "exact" => 3,
        "never" if regex => MATCH_REGEX,
        _ => 5,
    }
}
