# vault-wasm API

The TypeScript-facing API of `vault-wasm`, the `wasm-bindgen` bindings that the Firefox extension
loads (`docs/firefox.md`, WASM bindings). The module is `wasm-bindgen`'s `web` output: call the
default export `init()` once per context before anything else.

## Conventions

| Notation | Meaning |
| --- | --- |
| `State` | The local state as `local.json` text (`vault-client` `ClientState`), as IndexedDB stores it |
| `Bytes` | `Uint8Array`; a vault key is 32 bytes, a secret key and a device ID 16 |
| `now` | `Date.now()`, in ms |
| `KnownSuffix` | `(host: string) => string \| null`, or a `Record<string, string \| null>` |
| Errors | Thrown `Error` objects with a string `code` (`vault-core` and `vault-client` codes, such as `wrong_credentials`, `integrity.aead`, `sync.stopped`) |

Randomness comes from `crypto.getRandomValues` inside the module. Every argument that is a key
is copied into WASM memory; the caller zeroes its `Uint8Array` afterwards. Every returned key is a
new `Uint8Array` that the caller zeroes when done.

`KnownSuffix` supplies `browser.publicSuffix.getKnownSuffix`. As a function, it is called
synchronously; a throw, a returned `Promise`, or any value that is neither a string nor `null`
counts as a failed answer, so the URI does not match. When the browser API is asynchronous, call
`suffixHosts` first, resolve each host, and pass the answers as a record; a host missing from the
record counts as a failed answer.

## Setup text, secret keys, and state

```ts
parseSetupText(text: string): { url: string; token: string; fp: string | null; loopbackHttp: boolean }
decodeSecretKey(text: string): Bytes                  // throws code "secret_key_typo"
encodeSecretKey(key: Bytes): string                   // VLT1-... text form, for the kit
stateSummary(state: State): {
  vaultId: string; generation: number | null; unpushed: boolean;
  stopped: { reason: "integrity" | "token" | "credentials"; code: string; at: number } | null;
  pendingSecretKey: boolean; lastSync: number | null; dropped: string[];
}
clearDropped(state: State): State                     // after the names were shown
parseRevisions(body: Bytes): { id: number; etag: string; size: number; created: string; token: string }[]
```

`fp` is 64 lowercase hex characters. `token` is the text form to send as `Authorization: Bearer
<token>`.

## Session

An unlocked vault. The unlocked body stays in WASM memory. Locking is `session.lock()`, which
zeroes the vault key and every string of the body in linear memory, followed by `session.free()`.
A wrong password throws `wrong_credentials`.

```ts
class Session {
  static unlock(state: State, secretKey: Bytes, password: string): Session   // local file only
  static reopen(state: State, vaultKey: Bytes): Session                       // ~1 ms
  vaultKey(): Bytes                      // for storage.session only
  reload(state: State): void             // after a commit by this or another context
  readOnly(): boolean                    // the body's v is newer than this client writes
  lock(): void                           // zeroes the key and the body; then call free()

  // Items (no secrets in list entries)
  list(filter?: { folder?: string; text?: string }): ItemEntry[]   // listing order
  folders(): string[]                                             // every folder path, sorted
  item(id: string): object               // the item as the body schema defines it, secrets included

  // Local edits: run under navigator.locks "vault-state" with `state` read under it. The result's
  // state (null when nothing changed) is written by the caller; the session already holds it.
  add(state: State, deviceId: Bytes, now: number, item: NewItem): { id: string; state: State | null }
  update(state: State, deviceId: Bytes, now: number, id: string, base: object, edited: object): { state: State | null }
  remove(state: State, deviceId: Bytes, now: number, id: string): { state: State | null }

  // Autofill (docs/firefox.md, Fill and Save offers)
  suffixHosts(pageUrl: string): string[]
  candidates(pageUrl: string, knownSuffix: KnownSuffix): Candidate[]
  credential(id: string): { username: string; password: string }   // for one fill or copy
  saveOffer(pageUrl: string, username: string, password: string, knownSuffix: KnownSuffix): SaveOffer

  // Restore, after a fetchRevision procedure ended
  restorePreview(revision: Procedure, itemId?: string): { added: number; changed: number; removed: number }
  restore(state: State, deviceId: Bytes, now: number, revision: Procedure, itemId?: string):
    { state: State; added: number; changed: number; removed: number }
}

type ItemEntry = { id: string; type: string; name: string; folder: string; username: string;
                   uris: string[]; favourite: boolean; review: boolean; supported: boolean;
                   modified: number }
type NewItem = { type: "login" | "note"; name: string; folder?: string; favourite?: boolean;
                 notes?: string; username?: string; password?: string;
                 uris?: { uri: string; match: string }[] }
type Candidate = { id: string; name: string; username: string; outcome: "fill" | "confirm" }
type SaveOffer = { action: "none" } | { action: "update"; id: string }
               | { action: "new"; name: string; uri: string; match: "base_domain" }
```

`update` takes the item as `item(id)` returned it (`base`) and the user's edited copy (`edited`),
and merges the changed keys onto the current item (`vault_client::items::apply_changes`), so a
sync that landed during the edit is kept. A `NewItem` becomes a login or note stamped with `now`
and `deviceId`.

## Free autofill functions

```ts
framesToFill(topUrl: string, frames: { frameId: number; url: string }[]): number[]
pageUrl(url: string): Prepared | null
prepareUri(uri: string): Prepared | null
registrableDomain(url: string, knownSuffix: KnownSuffix): string | null
matchUri(pageUrl: string, uri: string, match: string, knownSuffix: KnownSuffix): "fill" | "confirm" | "none"
type Prepared = { scheme: string; host: string; port: number | null; pathQuery: string; origin: string }
```

`framesToFill` takes `webNavigation.getAllFrames` results (top frame included) and the top frame's
URL from `tabs.get`.

## Password generation

```ts
generatePassword(o: { length: number; upper: boolean; lower: boolean; digits: boolean;
                      symbols: boolean; avoidAmbiguous: boolean }): { value: string; bits: number }
generatePassphrase(words: number, separator: string): { value: string; bits: number }
```

## Procedures

The `vault-client` machines, stepped from JavaScript. A procedure performs no I/O: each step
returns a request to make, a prompt to show, a state to save, or the end.

```ts
class Procedure {
  static sync(state: State, keys: Keys, mode: "background" | "interactive" | "interactive-ask-again"): Procedure
  static unlock(state: State, keys: Keys): Procedure          // pull first, then unlock or take over
  static recover(state: State, keys: Keys): Procedure
  static passwd(state: State, keys: Keys, change: "new-password" | "rekey" | "new-secret-key"
                | "new-secret-key-and-password", kdfMemoryMib?: 64 | 128 | 256): Procedure
  static setup(): Procedure
  static repairToken(state: State): Procedure
  static fetchRevision(state: State, keys: Keys, id: number): Procedure

  start(now: number): Step
  step(input: Input, now: number): Step

  // After a "save" step, inside one IndexedDB transaction:
  applySave(started: State, onDisk: State, now: number, host: CommitHost): void
  // After "done", inside one IndexedDB transaction:
  apply(started: State | null, onDisk: State | null, background: boolean, now: number,
        host: CommitHost): Applied           // null and null after setup only
  vaultKey(): Bytes | null                // after "done": the key for the committed state
}

type Keys = { vaultKey?: Bytes; secretKey?: Bytes; pendingSecretKey?: Bytes }

type Step =
  | { type: "request"; method: "GET" | "PUT"; path: string;
      ifMatch?: string; ifNoneMatch?: "*"; body?: Bytes }
  | { type: "prompt"; prompt: Prompt }
  | { type: "save"; state: State; slot: "current" | "pending"; kit: string; vaultId: string }
  | { type: "done"; ok: true; result: object }
  | { type: "done"; ok: false; error: { code: string; message: string } }

type Prompt =
  | { kind: "master_password"; purpose: Purpose; failed: number }
  | { kind: "master_password_and_secret_key"; purpose: Purpose }
  | { kind: "old_master_password"; failed: number }
  | { kind: "new_master_password"; rejected: string | null }     // the rule the last answer broke
  | { kind: "secret_key" }
  | { kind: "kit_vault_id" }
  | { kind: "confirm"; confirmation: "discard_local_changes" | "no_credential_change"; description: string }
type Purpose = "unlock" | "credentials_changed" | "pending_secret_key" | "recovery" | "revision"

type Input =
  | { type: "response"; status: number; body: Bytes; date?: number }   // date: the Date header in ms
  | { type: "unreachable" }
  | { type: "answer"; password?: string; secretKey?: Bytes; vaultId?: Bytes | null;
      confirmed?: boolean; declined?: boolean }
  | { type: "saved" }

interface CommitHost {                       // each method only queues IndexedDB requests
  storeCurrent(vaultId: string, key: Bytes): void
  storePending(vaultId: string, key: Bytes): void     // saves of --new-secret-key only
  deletePending(vaultId: string): void
  writeState(state: State): void
}
type Applied = { written: boolean; superseded: boolean; mergedLocalChanges: boolean;
                 expired: string[]; pendingLeft: boolean }
```

- Requests: `path` is `/v1/vault`, `/v1/revisions`, or `/v1/revisions/<id>`. A transport failure
  or timeout is `{ type: "unreachable" }`.
- Answers: `password` for the password prompts, `password` and `secretKey` together for
  `master_password_and_secret_key`, `secretKey` for `secret_key`, `vaultId` for `kit_vault_id`,
  `confirmed` for `confirm`, and `declined: true` to decline any of them.
- A `save` step carries the state and, for the kit, the secret key's text form. The caller shows
  the kit, confirms it was kept, runs `applySave`, and answers `{ type: "saved" }`. `applySave`
  runs the commit rule first, which writes nothing, then stores the key in the named slot, then
  writes the state.
- The host contract for `applySave` and `apply`: when either throws, the host discards every
  write it queued during the call, by aborting the IndexedDB transaction. A throw can follow a
  key write already queued, for example when `writeState` fails, so committing the transaction
  after a throw could store a key that no state names.
- `result` on success: `sync` gives `{ outcome: "up_to_date" | "adopted" | "pushed", generation,
  expired, credentialsChanged, pendingSecretKey: "landed" | "not_landed" | null }`; `unlock` gives
  `{ sync: <sync result> | { error } }`; `recover` gives `{ generation, revision, expired,
  credentialsChanged, pendingSecretKey }`; `passwd` gives `{ generation, retiredRevision,
  expired }`; `setup` and `repairToken` give `{}`; `fetchRevision` gives `{ id, generation }`, and
  the opened revision stays in the procedure for `restorePreview` and `restore`.
- `setup` records the `file` secret key store in the state; the extension's IndexedDB plays it.
- `apply` runs `vault_client::commit::apply` with `host`; `superseded: true` means another
  context committed first and nothing was written. A procedure's `done` can carry a state to
  commit on failure too (such as `stopped`), so call `apply` after every `done`.
- `vaultKey()` after `done` is the key for `storage.session` and `Session.reopen`.
- `setup` ends with `done` and no `save` step. With no earlier state, call `apply(null, null,
  ...)`: it writes the secret key with `storeCurrent`, then the state. A browser that already
  holds a state repairs its token with `repairToken`, so `apply(null, <state>)` throws.
- `unlock` falls back to the local file when the pull is `unreachable`: it asks for the master
  password (up to three times, `failed` counting the wrong answers), ends `ok` with `result.sync`
  holding the error, and `vaultKey()` opens the local state.
