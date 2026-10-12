# Bitwarden import and export

The `vault-interop` crate reads and writes Bitwarden JSON exports. It does no I/O, so the CLI uses
it now and the Firefox extension can use it later; CI builds it for `wasm32-unknown-unknown`. Like
`vault-core`, it takes the current time and a random source as arguments. Imported items are local
edits (spec [Local edits](../spec/format.md#local-edits)): each gets `modified` set to the time of
the import and `created` from the export.

## Export files read

| `encrypted` | Other keys | Handling |
| --- | --- | --- |
| `false` | `folders`, `items` | Read directly |
| `true` | `passwordProtected: true`, `salt`, `kdfType`, KDF parameters, `encKeyValidation_DO_NOT_EDIT`, `data` | Decrypted with the export password, then read |
| `true` | No `passwordProtected` | Refused: an account-restricted export opens only in a Bitwarden account |

An export file over 64 MiB is refused. Items with a non-null `deletedDate`, and `collections`, are
skipped and counted in the result. Attachments are not part of a JSON export.

### Password-protected exports

1. Derive the master key from the export password and `salt` (as UTF-8 bytes):
   - `kdfType` 0: PBKDF2-HMAC-SHA256 with `kdfIterations`, 32 bytes.
   - `kdfType` 1: Argon2id with `kdfMemory` MiB, `kdfIterations`, `kdfParallelism`, and the
     SHA-256 of the salt as the salt, 32 bytes.
2. Derive the encryption key and the MAC key with HKDF-Expand (SHA-256) from the master key, with
   the info strings `enc` and `mac`, 32 bytes each.
3. Each encrypted string is `2.<iv>|<ciphertext>|<mac>` in base64: AES-256-CBC with PKCS#7
   padding, authenticated by HMAC-SHA256 over the IV and ciphertext. The MAC is checked in constant
   time before decryption.
4. A failure to decrypt `encKeyValidation_DO_NOT_EDIT` reports a wrong password. `data` decrypts to
   the plain export JSON.

The KDF parameters are checked before derivation:

| Parameter | Accepted |
| --- | --- |
| `kdfIterations` with PBKDF2 | 5,000 to 2,000,000 |
| `kdfMemory` with Argon2id | 16 to 256 MiB |
| `kdfIterations` with Argon2id | 2 to 10 |
| `kdfParallelism` with Argon2id | 1 to 16 |

Another `kdfType`, or a parameter outside these bounds, is refused before any derivation. The
memory and iteration limits are the spec's ceiling
([KDF parameters](../spec/format.md#kdf-parameters)); the lower bounds and the parallelism range
are Bitwarden's own.

## Item mapping

| Bitwarden | vault |
| --- | --- |
| `type` 1, login | Login |
| `type` 2, secure note | Note |
| `type` 3, card | Note with custom fields |
| `type` 4, identity | Note with custom fields |
| `type` 5, SSH key | Note with custom fields |
| `name` | `name`; `"Untitled"` when empty or null |
| `notes` | `notes`; `""` for null |
| `favorite` | `favourite` |
| `folderId` | `folder`: the folder's `name`, which holds nested folders as a `/` path |
| `creationDate` | `created`; the import time when absent |
| `fields`, `type` 0 or 1 | `fields`, with `hidden` true for `type` 1 |
| `fields`, `type` 2 | `fields`, with the value `"true"` or `"false"` |
| `fields`, `type` 3 (linked) | `origin` only |
| `login.username`, `login.password` | `login.username`, `login.password`; `""` for null |
| `login.uris` | `login.uris` (see below) |
| `login.totp` | `login.totp` |
| `login.fido2Credentials` | `login.passkeys`, each object verbatim |
| `passwordHistory` | `password_history`, with `retired` from `lastUsedDate`, then normalised |
| `id`, `revisionDate`, `reprompt`, `organizationId`, `collectionIds` | `origin` |

The card, identity, and SSH key objects become custom fields named after their Bitwarden keys, in
the order Bitwarden lists them, skipping null values. `number`, `code`, `ssn`, `passportNumber`,
`licenseNumber`, and `privateKey` are hidden fields.

| Bitwarden URI `match` | vault `match` |
| --- | --- |
| `null` or 0 (domain) | `base_domain` |
| 1 (host) | `host` |
| 2 (starts with) | `starts_with` |
| 3 (exact) | `exact` |
| 4 (regular expression) | `never`, with the original recorded in `origin` |
| 5 (never) | `never` |

### Origin data

Each imported item carries `origin.bitwarden`, an object holding what the item schema has no field
for:

| Key | Contents |
| --- | --- |
| `id` | The Bitwarden item ID |
| `type` | The Bitwarden item type |
| `item` | Every other item key the mapping does not use, such as `revisionDate`, `reprompt`, `organizationId`, and `collectionIds`, verbatim |
| `login` | Every `login` key the mapping does not use, such as `passwordRevisionDate`, verbatim |
| `boolean_fields` | Names of the custom fields that were `type` 2 |
| `linked_fields` | The `type` 3 fields, verbatim |
| `regex_uris` | URIs whose `match` was 4 |

Keys Bitwarden adds in later versions land in `item` or `login` without a code change.

### Values the body accepts

Every value copied verbatim (the `origin` data and `login.passkeys`) must satisfy the spec's body
JSON rules. Before import, a number outside `[0, 2^53)` or with a fraction or exponent becomes a
string of its source text, and a date before 1970 becomes `0`. An item that still breaks a rule,
for example by nesting deeper than 32 levels, is skipped and named in the result. The encoder in
`vault-core` checks the whole body before every seal, so a body that breaks the rules is never
written.

### Repeated imports

An item whose Bitwarden `id` equals `origin.bitwarden.id` on an existing item updates that item
through the same mapping, as a local edit, when any mapped value differs. A new password moves the
old one into the item's history. Items deleted in Bitwarden stay in the vault.

## Export mapping

Export reverses the import mapping:

- A login is `type` 1. A note whose `origin.bitwarden.type` is 3, 4, or 5 becomes that type again,
  with the custom fields named after its keys moved back into the card, identity, or SSH key
  object; other fields stay custom fields. Any other note is `type` 2 with `secureNote.type` 0.
- `id` is `origin.bitwarden.id` when present, otherwise the vault item ID. `creationDate` is
  `created` and `revisionDate` is `modified`, both as RFC 3339 times with milliseconds.
- A custom field named in `boolean_fields` with the value `"true"` or `"false"` is `type` 2. The
  `linked_fields` are appended.
- A URI listed in `regex_uris` whose `match` is still `never` is `match` 4.
- Each distinct `folder` becomes a folder with a new random ID.
- The keys in `origin.bitwarden.item` and `origin.bitwarden.login` are written back where they
  came from, unless the mapping already wrote that key.
- Empty `notes`, `username`, `password`, and `totp` are written as null.
- Without `origin.bitwarden.item`, `reprompt` is 0, and `organizationId` and `collectionIds` are
  null.
- Items of an unknown type are skipped and counted.

### Round trip

Importing a Bitwarden export and exporting it again gives the same items, compared by item ID, with
these differences: folder IDs, `revisionDate` (the time of the last import or edit), password
history beyond 10 entries or with duplicates (normalised away), number values turned into strings,
and the order of items and keys.
