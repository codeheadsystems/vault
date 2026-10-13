# Firefox extension

The Firefox extension is a standalone client. It runs `vault-core` and `vault-client` compiled to
WebAssembly, talks to `vault serve` directly, and needs no CLI. It follows the spec
[Sync](../spec/format.md#sync) and [Autofill matching](../spec/format.md#autofill-matching), and the
Firefox rules in [the requirements](requirements.md#autofill-matching). It needs Firefox 153 or
later, for `browser.publicSuffix`.

## Scope

Phase 3 builds the P0 and P1 requirements: FF-1 to FF-6, FF-8, and FF-9. PIN unlock (FF-7, P2)
comes later. Bitwarden import and export stay in the CLI; no Firefox requirement needs them.

| ID | Feature |
| --- | --- |
| FF-1 | WASM core, direct server access |
| FF-2 | Popup: search, view, copy username and password |
| FF-3 | Fill from a user action: popup, keyboard shortcut, or context menu |
| FF-4 | Lock after an idle time and on browser close |
| FF-5 | Add and edit items; generate a password into a field |
| FF-6 | Offer to save or update after a login form submits |
| FF-8 | Setup from the setup text, the certificate exception, the secret key, and the master password |
| FF-9 | Certificate exception or publicly trusted certificate; `http` only to loopback |

## Components

| Component | Path | Role |
| --- | --- | --- |
| `vault-wasm` | `crates/vault-wasm/` | `wasm-bindgen` bindings over `vault-core` and `vault-client` |
| Background script | `extension/src/background/` | The agent: holds the vault key, syncs in the background, runs the idle lock, and performs every fill |
| Popup | `extension/src/popup/` | Unlock, search, view, copy, fill, add, and quick edits |
| Vault page | `extension/src/page/` | A full-tab extension page for setup, credential change, recovery, restore, and turning on save offers |
| Fill script | `extension/src/fill/` | Injected on demand into one frame; writes one credential into a form |
| Save watcher | `extension/src/save/` | Optional content script that reports a submitted login form (FF-6) |

The split mirrors the CLI. The background script plays the agent, and the popup plays short
commands. Procedures that can wait minutes for prompts (setup, `passwd`, recovery, restore, and a
credential takeover) run in the vault page, because a popup closes when it loses focus and an idle
background script unloads.

The extension is TypeScript, bundled with esbuild, with no UI framework. `web-ext` lints, runs, and
signs it. Node dependencies are build and test tools only; none is bundled into the extension
except the generated `wasm-bindgen` glue. `package-lock.json` is committed, and a licence check
holds npm packages to the same licences as `deny.toml`. The shipped JavaScript is not minified, so
a reviewer can read it.

### WASM bindings

`vault-wasm` exposes coarse operations, so secrets cross the JavaScript boundary only where the UI
needs them:

- unlock, lock, and the state of the session;
- the `vault-client` machines, stepped from JavaScript, with requests and prompts as plain objects;
- item list entries without secrets, one item in full for viewing or editing, and edits;
- autofill matching, frame selection, and save offer decisions from `vault_client::autofill`;
- password generation.

The unlocked body stays inside WASM memory. The vault key crosses into JavaScript in two places:
storing it in `storage.session`, and reading it back when a new background instance starts. Code
that handles it holds it in a `Uint8Array` and zeroes the array when done. JavaScript receives a
password only for a view, an edit, a copy, or a fill, as a string that it does not store. Locking
discards the WASM instance, so its memory goes with it. Randomness comes from
`crypto.getRandomValues`, and the time from `Date.now()`.

Each context that needs the vault (the background script, the popup, and the vault page) runs its
own WASM instance. The module is built with the `wasm` Cargo profile, which inherits `release` and
sets `lto = "fat"`, `codegen-units = 1`, and `opt-level = 3`, with the `simd128` target feature and
`wasm-opt -O3`. It is loaded through `wasm-bindgen`'s `web` output as an ES module. The manifest's
content security policy for extension pages is `script-src 'self' 'wasm-unsafe-eval'`; the default
Manifest V3 policy refuses to compile WebAssembly.

| Measure (Firefox 157, Ryzen 7 7840U) | Value |
| --- | --- |
| Unlock at the floor KDF parameters | 127 ms |
| Unlock at the ceiling | 1.85 s |
| Module size, gzipped | 192 KB |
| WASM memory after a floor unlock | 65 MiB |

## Storage

| Data | Store |
| --- | --- |
| Local state (`local.json` contents, including the vault file) | IndexedDB |
| Server URL, token, fingerprint, and device ID | IndexedDB |
| Secret key, and a pending one | IndexedDB |
| Vault key while unlocked, last activity time | `storage.session` |
| Pending save offers, the hash of the last copied value | `storage.session` |
| Settings without secrets | `storage.local` |

The extension's content scripts can read `storage.local`, so it holds no secret and no credential.
IndexedDB in the extension's own origin is reachable only from the background script and extension
pages; a content script's `indexedDB` opens the page's origin. `storage.session` is not available to
content scripts at all, and Firefox clears it when the browser closes. Nothing is written to
`storage.sync`. The extension holds the `unlimitedStorage` permission, which grants persistent
storage at install, and calls `navigator.storage.persist()` from the background script, which then
resolves `true` with no prompt. Firefox therefore does not evict the local state under storage
pressure. Extension storage survives "Clear recent history" and "Clear Data" with every option
selected.

Every change to the local state runs inside `navigator.locks.request("vault-state")`, which plays
the CLI's file lock across the background script, the popup, and the vault page. Inside the lock, a
context reads the state, runs `vault-client`'s commit rule, and writes the result, including any
secret key change in the order `vault-client` gives, in one IndexedDB transaction. Other contexts
learn of a change from a `runtime` message and reload.

## Background script

Firefox runs a Manifest V3 background script as an event page (`background.scripts`), and unloads
it after about 30 seconds without events, discarding its memory. Each new instance reads the vault
key from `storage.session` and, when one is present, reopens the local vault file in WASM memory,
which takes about 1 ms. An unload therefore does not lock the vault, and WASM memory, which never
shrinks while an instance lives, is released.

The script registers every event listener synchronously at the top level, so an event that wakes
it is delivered. Work that must happen later runs from `alarms`, which wake a suspended background
script; `setTimeout` does not survive an unload.

- Idle lock (FF-4): only user actions count as activity: a popup or vault page request, and a fill
  or copy the user started. Messages from content scripts never count. Every request, and every
  start of a new instance, first compares the last activity time in `storage.session` with the idle
  time (default 15 minutes) and locks when it has passed, before doing anything else. An alarm
  also checks every minute, so a suspended machine locks on wake. Locking clears the vault key, the
  pending save offers, and the alarms, and discards the WASM instance.
- Browser close: Firefox clears `storage.session`, so the next session starts locked.
- Sync: on unlock (pull first, as the spec requires), after every local change, and from an alarm
  every 5 minutes while unlocked. One sync runs at a time; a request during a sync sets a flag that
  runs one more afterwards. Before a sync, `permissions.contains` checks the server's host
  permission, and a missing one is reported in the popup. A sync that needs a prompt records
  `stopped`, and the popup names the action that resolves it, which opens the vault page.

Requests to the server use `fetch` with `redirect: "error"`, `credentials: "omit"`, and
`cache: "no-store"`.

## Messages

The popup and the vault page send requests to the background script with `runtime.sendMessage`.
The background script accepts a request only when `sender.id` equals `runtime.id`, the sender has no
`tab`, and its URL is under the extension's own origin, and it validates each request's shape. The
manifest has no `externally_connectable` key and an empty `web_accessible_resources`, so no web
page can message the extension or load its pages. A content script can send only the save
watcher's one message type, and never receives anything but the credential of an explicit fill.

## Fill

A fill starts from a user action: the popup's fill button, the keyboard shortcut (`commands`,
default Ctrl+Shift+L), or the context menu. The shortcut and the context menu grant `activeTab`, so
filling needs no site permissions. The background script:

1. Takes the URL of the tab's top frame from `tabs.get`. It never takes a URL from page content or
   from a content script.
2. Finds the candidates with `vault_client::autofill`, supplying known suffixes from
   `browser.publicSuffix.getKnownSuffix` (the `publicSuffix` permission). It returns `null` when
   only the list's default rule applies, and throws on a host it cannot parse, which counts as a
   failed answer.
3. From the shortcut or the context menu, fills only when exactly one candidate has the outcome
   `fill`. Otherwise it sets a badge on the toolbar button showing the number of candidates, and the
   user picks one in the popup. Firefox 157 lets `action.openPopup()` run after the listener's
   asynchronous work only because `extensions.openPopupWithoutUserGesture.enabled` defaults to true;
   the extension does not depend on that preference. A fill started from the popup for an item that
   is not a candidate asks for confirmation first, naming the page's host.
4. Asks for confirmation for a candidate with the outcome `confirm`: an `https` item on an `http`
   page of a local host.
5. After the choice, reads the frames with `webNavigation.getAllFrames`, selects them with
   `vault_client::autofill`, and injects the fill script with `scripting.executeScript` into each
   selected frame, passing the credential and the top frame's origin. Under `activeTab` alone
   Firefox refuses every frame outside the top frame's origin, but with the all-sites permission
   that save offers request it injects into any frame, so the selection, not the browser, keeps the
   credential to the top frame's origin. A frame ID names the frame, not its document: a frame that
   navigates after the frames are read receives the fill script in its new document.

The fill script runs in the isolated world, as one synchronous function, so its origin check and its
writes apply to the same document. It writes nothing when `self.origin` differs from the origin it
was given. `self.origin` is used rather than `location.origin`, which is `"null"` in `about:blank`
and `srcdoc` frames that inherit the page's origin. It finds the visible username and password
fields, sets their values, dispatches `input` and `change` events, and keeps no reference to the
credential afterwards.

Generating a password into a field (FF-5) fills only a visible password field in a selected frame,
and records the generated password as a pending save offer for the page's origin, so a form that
fails to submit does not lose it.

## Save offers

Save offers (FF-6) need the save watcher in every page, and so the all-sites host permission, which
the extension requests only when the user turns save offers on in the vault page. When a form with
a password field submits in the top frame, the watcher sends the username and password to the
background script. The background script takes the page URL from the sender's tab and frame, as
the browser reports them, and ignores a message from any frame but the top frame. It answers every
message the same way, so a page learns nothing about the vault, and keeps at most one pending offer
per origin and ten in all, the newest replacing the oldest.

`vault_client::autofill` decides the offer. A pending offer sets a badge on the toolbar button, and
the popup offers to save or update. A new item stores only the page's origin, never its path or
query. Nothing is saved without the user's confirmation.

## Setup

Setup runs in the vault page.

1. Paste the setup text from `vault serve token add`. The extension checks it with `vault-core`
   and, in the same click, requests the host permission `<scheme>://<host>/*`, without the port.
2. For an `https` URL with `fp`, the extension first tests a request. When the request succeeds
   before any exception is accepted, the profile already trusts a certificate for the host, which
   may be an earlier exception that nobody compared; the extension warns that it cannot check the
   fingerprint and suggests removing the exception in Firefox's certificate manager. Otherwise it
   opens `/v1/vault` on the server in a new tab, which `vault serve` answers with an empty body, and
   shows the fingerprint in both forms in the vault page; nothing the tab displays is trusted. After
   the user accepts the exception, compares the fingerprints, and confirms, the extension closes the
   tab and tests a request again. The extension never offers to accept a new certificate on its own;
   a new certificate means new setup text. A loopback `http` URL skips this step.
3. Type or paste the secret key, and optionally the vault ID from the emergency kit.
4. Enter the master password. The extension runs the `vault-client` setup machine.

## Clipboard

Copying a username or password writes it with `navigator.clipboard.writeText` under the
`clipboardWrite` permission, and stores a SHA-256 hash of the value in `storage.session`. An alarm
45 seconds later wakes the background script, which reads the clipboard under the `clipboardRead`
permission and clears it when its hash matches. Both work from the background script with no
extension page open and the browser window unfocused. Firefox refuses custom clipboard types, so the
extension cannot offer `x-kde-passwordManagerHint`, and a clipboard manager may keep a copied
password.

## Private windows

The extension does not run in private windows unless the user allows it in Firefox's add-on
settings. Its state is the same in a private window; a fill or save offer there follows the same
rules.

## Build and tests

| Command | Purpose |
| --- | --- |
| `cargo build -p vault-wasm --target wasm32-unknown-unknown --profile wasm` | The WASM module |
| `npm run build` in `extension/` | `wasm-bindgen`, `wasm-opt`, esbuild, and the manifest |
| `npm test` in `extension/` | Unit tests for message validation, storage, and the fill script |
| `npm run e2e` in `extension/` | Headless Firefox against a real `vault serve` |
| `wasm-pack test --node crates/vault-wasm` | The spec vectors through the WASM bindings |

The spec vectors, `autofill.json` included, run through the WASM bindings in CI, and the release
gate runs against the shipped module, so a `test_kdf` header is refused in the build users install.
`vault-wasm` joins the CI WASM job.

Unit tests run in Node with the WASM module. The end-to-end tests drive Firefox through geckodriver
and cover setup, unlock, sync between the extension and the CLI, fills into same-origin,
same-site, and cross-origin frames, a frame that navigates before the fill, the `http` refusal and
the local-host confirmation, the idle lock after an unload, a readable `Date` header from the
server, and the transport behaviours in [the requirements](requirements.md#transport).

## Distribution

Firefox release builds load only signed extensions. The extension is signed as an unlisted add-on
through addons.mozilla.org with `web-ext sign --channel unlisted`, which needs an AMO account and
API key. A signed `.xpi` installs from a file.

The manifest fixes `browser_specific_settings.gecko.id` from the first build, because Firefox keys
the extension's storage by it and a change loses every device's local state, and sets
`strict_min_version` to `"153.0"`. Updates install from a new signed `.xpi`; an `update_url` that
serves signed updates is a later option.
