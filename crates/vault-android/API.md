# vault-android API

The Kotlin-facing API of `vault-android`, the UniFFI bindings that the Android app loads
(`docs/android.md`, Rust bindings). `uniffi-bindgen` generates the Kotlin into the package
`uniffi.vault_android`, loaded through JNA from `libvault_android.so`. The generator reads the
UniFFI metadata from an unstripped library, so it runs on the host build; the `android` profile
strips the shipped libraries, which have the same API checksums:

```sh
cargo build -p vault-android
cargo run --locked -p vault-android --features bindgen --bin uniffi-bindgen -- generate \
  --library target/debug/libvault_android.so --language kotlin --out-dir <dir>
cargo ndk -t arm64-v8a -t x86_64 -P 29 build -p vault-android --profile android
```

The shipped libraries are `target/aarch64-linux-android/android/libvault_android.so` and
`target/x86_64-linux-android/android/libvault_android.so`. The host build also serves the JVM
tests through JNA.

UniFFI turns `snake_case` into `camelCase`, a Rust `Option` into a nullable type, `Vec<u8>` into
`ByteArray`, a `u64` into `ULong`, and an enum with fields into a sealed class. No function is
`suspend`; the app calls the library from a background dispatcher.

No function takes a library object (`Vault` or `Procedure`) as an argument. UniFFI 0.32's
Kotlin checks that an object is still open only when it is the receiver of a call; an object
passed as an argument after `close()` crosses as a freed handle. A call on a closed object throws
`IllegalStateException`.

## Conventions

| Notation | Meaning |
| --- | --- |
| Times | `Host.nowMs` is `System.currentTimeMillis()`; `Host.elapsedRealtimeMs` is `SystemClock.elapsedRealtime()` |
| Keys | `ByteArray`; a vault key is 32 bytes, a secret key, a device ID, and a vault ID 16, a `wrap_nonce` 24 |
| Items | An item as JSON text, as the body schema defines it; an item list is a JSON array of them |
| Errors | `VaultException.Failed(code, detail)`, `code` being a stable string: a `vault-core` or `vault-client` code (such as `wrong_credentials`, `integrity.aead`, `sync.locked`), `usage` for an argument of the wrong shape, or a code of this library or of the host |

Randomness comes from the operating system inside the library. Every key argument is copied into
Rust memory, and the caller zeroes its `ByteArray` afterwards; every returned key is a new
`ByteArray` that the caller zeroes when done. A key or password that crosses the boundary passes
through a buffer that is freed without zeroing.

The library's own codes are `state.no_vault` (no vault is set up), `secret_key.missing` (the
current slot is empty), `secret_key.no_pending`, `biometric.stale`, `procedure.poisoned` (an
earlier call on the procedure panicked), and `host.unexpected` (a host method threw something other
than a `VaultException`).

## Host

The app's storage and clocks. The library calls these methods while it holds its state lock, so
an implementation never calls back into the library. A method fails by throwing
`VaultException.Failed` with a code that starts with `host.`, such as `host.io` or
`host.device_locked` when the storage key refuses on a locked device.

```kotlin
interface Host {
    fun readState(): ByteArray?                  // local.json, or null before setup
    fun writeState(state: ByteArray)             // atomically: a temporary file, fsync, a rename
    fun readKey(slot: KeySlot): ByteArray?       // unwrapped by the storage key; null when empty
    fun writeKey(slot: KeySlot, key: ByteArray)  // wrapped by the storage key, atomically
    fun deleteKey(slot: KeySlot)                 // an empty slot is not an error
    fun deleteBiometricWrap()                    // none stored is not an error
    fun readDeviceId(): ByteArray?               // noBackupFilesDir; null before the first edit
    fun writeDeviceId(id: ByteArray)
    fun nowMs(): ULong
    fun elapsedRealtimeMs(): ULong
}
enum class KeySlot { CURRENT, PENDING }
```

Kotlin never parses `local.json`. The library creates the device ID on the first edit. In
`readKey`, Kotlin zeroes every array it used to unwrap the key except the one it returns, which it
cannot zero after the return; in `writeKey`, it zeroes `key` once wrapped. The library copies a key
it reads into memory it zeroes; the UniFFI buffers a key crosses in are freed without zeroing. A commit
that changes `wrap_nonce` calls `deleteBiometricWrap` before it writes the state, so a wrap never
outlives the credentials it belongs to.

## Vault

The one vault of the process: the state lock, the unlocked session, and the idle lock. The app
holds one instance, `Vault(host)`, in its `Application`.

```kotlin
class Vault(host: Host) {
    fun stateSummary(): StateSummary?            // null before setup
    fun clearDropped()                           // after the dropped names were shown

    // Locking (docs/android.md, Unlock and locking and Idle lock)
    fun isUnlocked(): Boolean
    fun lock()                                   // zeroes the session and the vault key
    fun lockIfIdle(): Boolean                    // the entry-point check; true when it locked
    fun recordActivity()                         // an action in the app's own activities only
    fun setIdleTime(ms: ULong)                   // 5 minutes until set
    fun unlock(password: String)                 // the local file only; beginUnlock pulls first
    fun reopen(vaultKey: ByteArray, wrapNonce: ByteArray)   // after the biometric unwrap
    fun vaultKey(): VaultKeyExport               // for the biometric wrap only
    fun secretKeyText(password: String): String  // AND-8, after the master password

    // Items (no secrets in list entries)
    fun readOnly(): Boolean                      // the body's v is newer than this client writes
    fun list(folder: String?, text: String?): List<Entry>    // listing order
    fun folders(): List<String>
    fun item(id: String): String                 // JSON, secrets included
    fun credential(id: String): Credential       // for one fill or copy

    // Local edits: each reads the state, applies the change, and writes it under the state lock
    fun add(item: NewItem): String               // the new item's ID
    fun update(id: String, base: String, edited: String)
    fun remove(id: String)

    // Autofill (docs/android.md, Autofill), with the compiled-in Public Suffix List
    fun candidates(page: Page): List<Candidate>
    fun saveOffer(page: Page, username: String, password: String): SaveOffer
    fun applySaveOffer(offer: SaveOffer, username: String, password: String): String?
    fun recordAppFill(id: String, app: AppPage): Binding

    // Procedures (see Procedures)
    fun beginSync(mode: SyncMode): Procedure
    fun beginUnlock(): Procedure                 // pull first, then unlock or take over
    fun beginRecover(): Procedure
    fun beginPasswd(change: PasswdChange, kdfMemoryMib: UInt?): Procedure   // 64 by default
    fun beginSetup(): Procedure                  // refused with "usage" when a vault is set up
    fun beginRepairToken(): Procedure
    fun beginFetchRevision(id: ULong): Procedure
}

data class StateSummary(val vaultId: String, val generation: ULong?, val unpushed: Boolean,
    val stopped: Stopped?, val pendingSecretKey: Boolean, val lastSync: ULong?,
    val dropped: List<String>, val wrapNonce: ByteArray)
data class Stopped(val reason: String, val code: String, val at: ULong)  // integrity, token, credentials
data class VaultKeyExport(val vaultKey: ByteArray, val wrapNonce: ByteArray)
data class Entry(val id: String, val itemType: String, val name: String, val folder: String,
    val username: String, val uris: List<String>, val favourite: Boolean, val review: Boolean,
    val supported: Boolean, val modified: ULong)
data class NewItem(val itemType: String, val name: String, val folder: String,
    val favourite: Boolean, val notes: String, val username: String, val password: String,
    val uris: List<ItemUri>)                     // itemType: "login" or "note"
data class Credential(val username: String, val password: String)
data class RestoreSummary(val added: ULong, val changed: ULong, val removed: ULong)
enum class Binding { RECORDED, UNCHANGED, NOT_PULLED }
```

- Every method takes the state lock and runs the idle check first: when the idle time has passed
  since the last `recordActivity`, `unlock`, or `reopen`, it locks before doing anything else, and
  a call that needs the session then fails with `sync.locked`. Only `recordActivity` counts as
  activity; requests from other apps never call it.
- `unlock` and `secretKeyText` run the key derivation outside the state lock.
- `reopen` refuses a wrap stored for another `wrapNonce` with `biometric.stale`, and a key that
  does not open the file with its integrity code. The app stores the wrap with the `wrapNonce` that
  `vaultKey` returns, and zeroes `VaultKeyExport.vaultKey` once the cipher has wrapped it.
- `update` takes the item as `item(id)` returned it (`base`) and the user's edited copy (`edited`),
  and merges the changed keys onto the current item (`vault_client::items::apply_changes`), so a
  sync that landed during the edit is kept.
- A failed state write returns the session to the state on disk.
- `applySaveOffer` carries out the offer the user confirmed: `New` adds a login with the submitted
  username and password and the offer's URIs and app bindings; `Update` sets the item's password,
  which keeps the old one in its history. It returns the item's ID, or `null` for `None`.
- `recordAppFill` records a confirmed app fill as a local edit of `login.apps`: a `BIND` adds the
  current certificate, and a `REBIND` moves the association to it. It binds only after a pull has
  succeeded since the session was opened (a `sync`, `recover`, or `passwd` procedure, or an
  `unlock` procedure whose sync ran); otherwise it returns `NOT_PULLED` and the fill goes ahead
  unbound (docs/android.md, App matching). A fill whose kind records nothing (`FILL`,
  `SIGNATURE_CHANGED`, `UNVERIFIED`) returns `UNCHANGED` either way.

## Autofill

```kotlin
sealed class Page {
    data class AndroidWeb(val scheme: String, val host: String) : Page()  // webScheme, webDomain
    data class App(val app: AppPage) : Page()
}
data class AppPage(val packageName: String, val signers: List<String>, val history: List<String>,
    val multipleSigners: Boolean)
data class Candidate(val id: String, val name: String, val username: String,
    val outcome: Outcome, val appMatch: AppMatch?)  // appMatch on an app page only
enum class Outcome { FILL, CONFIRM }
enum class AppMatch { FILL, REBIND, SIGNATURE_CHANGED, BIND, UNVERIFIED }
sealed class SaveOffer {
    object None : SaveOffer()
    data class Update(val id: String) : SaveOffer()
    data class New(val name: String, val uris: List<ItemUri>, val apps: List<AppBinding>) : SaveOffer()
}
data class ItemUri(val uri: String, val matchValue: String)
data class AppBinding(val packageName: String, val certSha256: String)
data class WebPage(val scheme: String, val host: String, val origin: String)

fun androidWebPage(scheme: String, host: String): WebPage?
fun explicitChoiceAllowed(page: Page): Boolean
fun knownSuffix(host: String): String?
fun pageCandidates(page: Page, items: String, suffixes: KnownSuffix?): List<Candidate>
fun pageSaveOffer(page: Page, username: String, password: String, items: String,
                  suffixes: KnownSuffix?): SaveOffer
fun appsAfterFill(item: String, app: AppPage): List<AppBinding>?

interface KnownSuffix { fun knownSuffix(host: String): String? }
```

- `AppPage.signers` holds the current signing certificate digests, 64 lowercase hex characters
  each: one for one signer, several for more than one (`apkContentsSigners`), none when
  `getPackageInfo` failed. `history` is `signingCertificateHistory`, oldest first and ending with
  the current digest, for one signer, and empty otherwise. Signing information of any other shape
  counts as unread, so the page is `UNVERIFIED` (`vault_client::autofill::AppPage::new`); an empty
  `packageName` fails with `usage`.
- `androidWebPage` returns `null` for a scheme other than `http` or `https`, or a host with a port,
  a path, a query, a fragment, or user information; the app then treats the browser as not
  allowlisted and matches by the app rules. A `Page.AndroidWeb` that it refuses matches nothing.
- `explicitChoiceAllowed` says whether an item without an association may fill the page through
  "Choose another item" and a confirmation: always on an app page, and on an Android web page
  unless it is `http` and its host is not a local host.
- `knownSuffix` looks a host up in the compiled-in Public Suffix List (from `publicsuffix.org`,
  fetched on 2026-10-14, MPL-2.0; `src/psl.rs`). The free functions that take `items` need no
  vault, and use the compiled-in list when `suffixes` is `null`; the spec vectors run through them
  with the vectors' table as a Kotlin `KnownSuffix`. Only Kotlin implements `KnownSuffix`.

## Setup text, secret keys, and generation

```kotlin
fun parseSetupText(text: String): SetupText
fun decodeSecretKey(text: String): ByteArray     // code "secret_key_typo" before any derivation
fun encodeSecretKey(key: ByteArray): String      // VLT1-... text form
fun parseRevisions(body: ByteArray): List<RevisionInfo>
fun generatePassword(options: PasswordOptions): Generated
fun generatePassphrase(words: UInt, separator: String): Generated
fun pinMatches(fp: String, leafDer: ByteArray): Boolean

data class SetupText(val url: String, val token: String, val fp: String?, val loopbackHttp: Boolean)
data class RevisionInfo(val id: ULong, val etag: String, val size: ULong, val created: String,
    val token: String)
data class PasswordOptions(val length: UInt, val upper: Boolean, val lower: Boolean,
    val digits: Boolean, val symbols: Boolean, val avoidAmbiguous: Boolean)
data class Generated(val value: String, val bits: Double)
```

`token` is the text form to send as `Authorization: Bearer <token>`, and `fp` is 64 lowercase hex
characters. `pinMatches` compares the SHA-256 of the leaf certificate's DER encoding with `fp`; a
malformed `fp` never matches.

## Procedures

The `vault-client` machines, stepped from Kotlin. A procedure performs no I/O and holds no lock
while it runs: each step returns a request to make, a prompt to show, a save, or the end. The
vault's `begin` methods read the state and the stored secret keys under the state lock, with the
session's vault key when unlocked.

```kotlin
class Procedure {
    fun start(): Step
    fun step(input: Input): Step
    fun applySave()                                  // after a Save step
    fun apply(background: Boolean): Applied          // after Done or Failed

    // Restore, after a beginFetchRevision procedure ended, through its vault's session
    fun restorePreview(itemId: String?): RestoreSummary
    fun restore(itemId: String?): RestoreSummary
}

enum class SyncMode { BACKGROUND, INTERACTIVE, INTERACTIVE_ASK_AGAIN }
enum class PasswdChange { NEW_PASSWORD, REKEY, NEW_SECRET_KEY, NEW_SECRET_KEY_AND_PASSWORD }

sealed class Step {
    data class Request(val request: uniffi.vault_android.Request) : Step()
    data class Prompt(val prompt: uniffi.vault_android.Prompt) : Step()
    data class Save(val slot: KeySlot, val kit: String, val vaultId: String) : Step()
    data class Done(val report: Report) : Step()
    data class Failed(val error: ErrorInfo) : Step()
}
data class Request(val method: String, val path: String, val ifMatch: String?,
    val ifNoneMatch: String?, val body: ByteArray?)
data class ErrorInfo(val code: String, val message: String)

sealed class Prompt {
    data class MasterPassword(val purpose: Purpose, val failed: UInt) : Prompt()
    data class MasterPasswordAndSecretKey(val purpose: Purpose) : Prompt()
    data class OldMasterPassword(val failed: UInt) : Prompt()
    data class NewMasterPassword(val rejected: String?) : Prompt()   // the rule the last answer broke
    object SecretKey : Prompt()
    object KitVaultId : Prompt()
    data class Confirm(val confirmation: ConfirmKind, val description: String) : Prompt()
}
enum class Purpose { UNLOCK, CREDENTIALS_CHANGED, PENDING_SECRET_KEY, RECOVERY, REVISION }
enum class ConfirmKind { DISCARD_LOCAL_CHANGES, NO_CREDENTIAL_CHANGE }

sealed class Input {
    data class Response(val status: UShort, val body: ByteArray, val date: ULong?) : Input()
    object Unreachable : Input()
    data class Answer(val answer: uniffi.vault_android.Answer) : Input()
    object Saved : Input()
}
sealed class Answer {
    data class Password(val password: String) : Answer()
    data class PasswordAndSecretKey(val password: String, val secretKey: ByteArray) : Answer()
    data class SecretKey(val secretKey: ByteArray) : Answer()
    data class VaultId(val vaultId: ByteArray?) : Answer()
    data class Confirmed(val confirmed: Boolean) : Answer()
    object Declined : Answer()
}

sealed class Report {
    data class Sync(val sync: SyncResult) : Report()
    data class Unlock(val sync: SyncResult?, val syncError: ErrorInfo?) : Report()
    data class Recover(val generation: ULong, val revision: ULong?, val expired: List<String>,
        val credentialsChanged: Boolean, val pendingSecretKey: PendingKey?) : Report()
    data class Passwd(val generation: ULong, val retiredRevision: ULong?,
        val expired: List<String>) : Report()
    object Setup : Report()
    object RepairToken : Report()
    data class Revision(val id: ULong, val generation: ULong) : Report()
}
data class SyncResult(val outcome: SyncOutcome, val generation: ULong, val expired: List<String>,
    val credentialsChanged: Boolean, val pendingSecretKey: PendingKey?)
enum class SyncOutcome { UP_TO_DATE, ADOPTED, PUSHED }
enum class PendingKey { LANDED, NOT_LANDED }

data class Applied(val written: Boolean, val superseded: Boolean, val mergedLocalChanges: Boolean,
    val expired: List<String>, val pendingLeft: Boolean, val wrapChanged: Boolean,
    val unlocked: Boolean)
```

- Requests: `path` is `/v1/vault`, `/v1/revisions`, or `/v1/revisions/<id>`; a `PUT` carries
  `ifMatch`, or `ifNoneMatch` set to `*`, and a `body`. A transport failure or timeout is
  `Input.Unreachable`. `date` is the `Date` header in ms, from `getHeaderFieldDate`.
- Answers: `Password` for the password prompts, `PasswordAndSecretKey` for
  `MasterPasswordAndSecretKey`, `SecretKey` (from `decodeSecretKey`) for `SecretKey`, `VaultId`
  for `KitVaultId`, `Confirmed` for `Confirm`, and `Declined` for any of them.
- A `Save` step carries the secret key's text form for the kit. The app shows the kit, confirms it
  was kept, calls `applySave`, and answers `Input.Saved`. `applySave` runs the commit rule, stores
  the key in the named slot, and writes the state, under the state lock.
- `apply` runs `vault_client::commit::apply` through the host, under the state lock: the key
  the new state needs, then the state, then deleting the pending key. A `Failed` step can carry a
  state to commit too (such as `stopped`), so the app calls `apply` after every end.
  `superseded` means another sync committed first and nothing was written.
- After `apply`, the session follows the committed state. An unlocked session reopens it with
  the procedure's vault key, or locks when no key opens it. An `unlock` or `setup` procedure that
  started while locked unlocks the session. A procedure that started unlocked and was interrupted
  by a lock commits its result but does not unlock again. `unlocked` reports the session
  afterwards.
- `wrapChanged` means the commit changed `wrap_nonce`: the biometric wrap was deleted, and the app
  offers, outside the state lock, to wrap the new vault key.
- `setup` records the `file` secret key store in the state; the app's key slots play it. It ends
  with `Done` and no `Save` step, and `apply` writes the secret key to the current slot, then the
  state.
- `unlock` falls back to the local file when the pull is unreachable: it asks for the master
  password (up to three times, `failed` counting the wrong answers), and ends `Done` with
  `Report.Unlock.syncError` set.
