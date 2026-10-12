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

An export file over 64 MiB is refused, and so is one holding more JSON values and object keys than
one per 4 bytes of the file, plus 1,024, which bounds the memory a hostile file can take. A `\u`
escape of a lone UTF-16 surrogate, which a JavaScript string can hold, is read as U+FFFD. Items
with a non-null `deletedDate`, and `collections`, are skipped and counted in the result.
Attachments are not part of a JSON export.

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
| Any other `type` with a typed object (see below) | Note with custom fields |
| `name` | `name`; `"Untitled"` when empty or null |
| `notes` | `notes`; `""` for null |
| `favorite` | `favourite` |
| `folderId` | `folder`: the folder's `name`, which holds nested folders as a `/` path; `""` for null or an ID that names no folder in the export |
| `creationDate` | `created`; the import time when absent or not an RFC 3339 time |
| `fields`, `type` 0 or 1 | `fields`, with `hidden` true for `type` 1 |
| `fields`, `type` 2 | `fields`, with the value `"true"`, or `"false"` for any other value or null |
| `fields`, `type` 3 (linked) | `origin` only |
| `fields`, `type` 4 or later | `fields`, as text |
| `login.username`, `login.password` | `login.username`, `login.password`; `""` for null |
| `login.uris` | `login.uris` (see below); an entry with a null `uri` is dropped |
| `login.totp` | `login.totp`; null for `""` |
| `login.fido2Credentials` | `login.passkeys`, each object verbatim |
| `passwordHistory` | `password_history`, with `retired` from `lastUsedDate` (0 when it is missing or not an RFC 3339 time), then normalised |
| `id`, `revisionDate`, `reprompt`, `organizationId`, `collectionIds` | `origin` |

With `--folder <prefix>`, each folder path becomes `<prefix>/<path>`, and an item without a folder
goes into `<prefix>` itself.

| Bitwarden URI `match` | vault `match` |
| --- | --- |
| `null` or 0 (domain) | `base_domain` |
| 1 (host) | `host` |
| 2 (starts with) | `starts_with` |
| 3 (exact) | `exact` |
| 4 (regular expression) | `never`, with the original recorded in `origin` |
| 5 (never) | `never` |
| 6 or later | `never` |

### Typed items

An item whose `type` is neither 1 nor 2 carries its data in a **typed object**: `card` for
`type` 3, `identity` for 4, `sshKey` for 5, `bankAccount` for 6, `driversLicense` for 7, and
`passport` for 8. For any other `type`, the typed object is the one item key whose value is an
object, among the keys other than those the mapping reads or writes itself (`id`, `type`, `name`,
`notes`, `favorite`, `folderId`, `fields`, `login`, `secureNote`, `passwordHistory`,
`creationDate`, `revisionDate`, `deletedDate`, `reprompt`, `organizationId`, and
`collectionIds`). An item with no typed object by this rule, or with
more than one candidate, is skipped and named in the result.

A typed item becomes a note. Each key of the typed object, in file order, becomes a custom field
named after the key when its value is a string or a number (a number as its source text). A null
value gives no field. A boolean, array, or object value is kept in
`origin.bitwarden.object_values`. The typed object's custom fields come before the item's own
custom fields.

These keys give hidden fields, whatever the type: `number`, `code`, `ssn`, `passportNumber`,
`licenseNumber`, `privateKey`, `accountNumber`, `routingNumber`, `iban`, `pin`, and
`nationalIdentificationNumber`.

### Origin data

Each imported item carries `origin.bitwarden`, an object holding what the item schema has no field
for:

| Key | Contents |
| --- | --- |
| `id` | The Bitwarden item ID |
| `type` | The Bitwarden item type, verbatim |
| `object` | The key of the typed object, on a typed item |
| `object_keys` | The keys of the typed object in file order, null values included, on a typed item |
| `object_values` | The typed object's boolean, array, and object values, by key |
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

- A repeated import overwrites edits made in the vault to mapped values with the export's values.
  Only a changed password is kept, in the history; an edited name, folder, or field is lost.
- An item deleted in the vault is added again, as a new item, by a later import of an export
  that holds it: a tombstone carries no `origin`.
- Several items with the same Bitwarden `id` in one export are each added. A later import pairs
  them in order: the first entry with that `id` updates the first vault item from it, in vault
  order, the second the second, and an entry beyond the vault items from that `id` is added.

## Export mapping

Export reverses the import mapping:

- A login is `type` 1. A note with `origin.bitwarden.object` becomes its `origin.bitwarden.type`
  again, with its typed object rebuilt from `object_keys` in their order: the first custom field
  named after a key gives that key's value as a string and leaves the custom fields; otherwise the
  value in `object_values`, or else null. The other fields stay custom fields. Any other note is
  `type` 2 with `secureNote.type` 0.
- `id` is `origin.bitwarden.id` when present, otherwise the vault item ID. `creationDate` is
  `created` and `revisionDate` is `modified`, both as RFC 3339 times with milliseconds.
- A custom field named in `boolean_fields` with the value `"true"` or `"false"` is `type` 2. The
  `linked_fields` are appended.
- A URI listed in `regex_uris` whose `match` is still `never` is `match` 4.
- Each distinct `folder` becomes a folder with a new random ID.
- The keys in `origin.bitwarden.item` and `origin.bitwarden.login` are written back where they
  came from, unless the mapping already wrote that key.
- Empty `notes`, `username`, `password`, and `totp` are written as null.
- Where `origin.bitwarden.item` does not hold them, `reprompt` is 0, and `organizationId` and
  `collectionIds` are null.
- `fields` and `passwordHistory` are always arrays, empty when the item has none.
- A URI `match` of `base_domain` is 0, `host` 1, `starts_with` 2, `exact` 3, and `never` or an
  unknown value 5.
- Vault items of a `type` the client does not know are skipped and counted.

### Round trip

Importing a Bitwarden export and exporting it again gives the same items, compared by item ID, with
these differences:

- Folder IDs, and `revisionDate`, which is the time of the last import or edit.
- Password history beyond 10 entries, with duplicates, with an empty password, or equal to the
  current password, which normalising removes. A missing `lastUsedDate`, or one before 1970, is
  written as `1970-01-01T00:00:00.000Z`.
- Number values turned into strings, including numbers in typed objects.
- A null URI `match` written as 0, and a null boolean field value written as `"false"`.
- Null `fields` and `passwordHistory` written as `[]`, an empty `totp` as null, and URI entries
  with a null `uri` left out.
- The order of items and keys.

The export matches fields and URIs by name and text, so an item with repeated names can change: a
text field with the value `"true"` or `"false"` named like a boolean field becomes a boolean
field, a URI equal to one whose `match` was 4 also gets `match` 4, and a custom field named like a
key of the typed object moves into the typed object.
