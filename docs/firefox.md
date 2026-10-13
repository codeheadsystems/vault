# Firefox extension

The Firefox extension is a standalone client. It runs `vault-core`, `vault-client`, and
`vault-interop` compiled to WebAssembly, talks to `vault serve` directly, and needs no CLI. It
follows the spec [Sync](../spec/format.md#sync) and the autofill matching rules in
[the requirements](requirements.md#autofill-matching). It needs Firefox 153 or later, for
`browser.publicSuffix`.

## Scope

Phase 3 builds the P0 and P1 requirements: FF-1 to FF-6, FF-8, and FF-9. PIN unlock (FF-7, P2)
comes later.

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
| `vault-wasm` | `crates/vault-wasm/` | `wasm-bindgen` bindings over `vault-core`, `vault-client`, and `vault-interop` |
| Background script | `extension/src/background/` | Holds the unlocked vault, drives sync, decides every fill |
| Popup | `extension/src/popup/` | Unlock, search, view, copy, add, edit, setup, and prompts |
| Fill script | `extension/src/fill/` | Injected on demand into one frame; writes one credential into a form |
| Save watcher | `extension/src/save/` | Optional content script that reports a submitted login form (FF-6) |

The extension is TypeScript, bundled with esbuild, with no UI framework. `web-ext` lints, runs, and
signs it. Node dependencies are build and test tools only; none is bundled into the extension
except the generated `wasm-bindgen` glue. `package-lock.json` is committed, and a licence check
holds npm packages to the same licences as `deny.toml`.

### WASM bindings

`vault-wasm` exposes coarse operations, so secrets cross the JavaScript boundary only where the UI
needs them:

- unlock, lock, and the state of the session;
- the `vault-client` machines, stepped from JavaScript, with requests and prompts as plain objects;
- item list entries without secrets, one item in full on request, and edits;
- password generation, Bitwarden import, and export.

The unlocked body and the vault key stay inside WASM memory. JavaScript receives a password only
for a copy or a fill, as a string that it does not store. Randomness comes from
`crypto.getRandomValues`, and the time from `Date.now()`.

The module is built with `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`, the `simd128` target
feature, and `wasm-opt -O3`, and loaded with `wasm-bindgen`'s `no-modules` output. The manifest's
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
| Settings without secrets | `storage.local` |

The extension's content scripts can read `storage.local`, so it holds no secret and no credential.
IndexedDB in the extension's own origin is reachable only from the background script and extension
pages; a content script's `indexedDB` opens the page's origin. `storage.session` is not available
to content scripts at all, and Firefox clears it when the browser closes. Nothing is written to
`storage.sync`.

All writes of the local state go through one function that serialises them, which gives the same
single-writer rule as the CLI's lock.

## Background script

Firefox runs a Manifest V3 background script as an event page (`background.scripts`), and unloads
it after about 30 seconds without events, discarding its memory. Each new instance reads the vault
key from `storage.session` and, when one is present, reopens the local vault file in WASM memory,
which takes about 1 ms. An unload therefore does not lock the vault, and WASM memory, which never
shrinks while an instance lives, is released.

Work that must happen later runs from `alarms`, which wake a suspended background script;
`setTimeout` does not survive an unload.

- Idle lock (FF-4): every request from the popup or a fill updates the last activity time in
  `storage.session`. An alarm checks it every minute and locks after the idle time (default 15
  minutes). Locking clears the vault key from `storage.session` and WASM memory.
- Browser close: Firefox clears `storage.session`, so the next session starts locked.
- Sync: on unlock (pull first, as the spec requires), after every local change, and from an alarm
  every 5 minutes while unlocked. A sync that needs a prompt records `stopped`, and the popup shows
  it with the action that resolves it.

## Messages

The popup sends requests to the background script with `runtime.sendMessage`. The background
script accepts a request only when the sender is an extension page of this extension (no `tab`, and
a URL under the extension's own origin), and validates each request's shape. A content script can
send only the save watcher's one message type, and never receives anything but the credential of
an explicit fill.

## Fill

A fill starts from a user action: the popup's fill button, the keyboard shortcut (`commands`,
default Ctrl+Shift+L), or the context menu. The shortcut and the context menu grant `activeTab`, so
filling needs no site permissions. The background script:

1. Takes the page URL from the browser: `tabs.get` for the tab, and `webNavigation.getAllFrames`
   for frame URLs. It never takes a URL from page content or from a content script.
2. Finds the matching items by the autofill matching rules. Base domain comes from
   `browser.publicSuffix`, which uses Firefox's own Public Suffix List. A host under a suffix the
   list does not know, such as `nas.lan`, is its own base domain, and an IP address matches only
   itself.
3. With several matches, asks in the popup which one; with one match, fills it.
4. Asks for confirmation before filling an `https` item into an `http` page.
5. Injects the fill script with `scripting.executeScript` into the top frame and into each frame
   whose origin matches the item, passing that one credential as an argument. The background
   script filters the frames itself: Firefox injects into a cross-origin frame whenever the
   extension holds permission for it.

The fill script finds the username and password fields, sets their values, dispatches `input` and
`change` events, and keeps no reference to the credential afterwards.

## Save offers

Save offers (FF-6) need the save watcher in every page, and so the all-sites host permission, which
the extension requests only when the user turns save offers on. When a form with a password field
submits, the watcher sends the form values to the background script, which checks the origin
against the sender's frame URL from the browser. When no item matches, or a matching item has a
different password, the extension sets a badge on its toolbar button, and the popup offers to save
or update. Nothing is saved without the user's confirmation.

## Setup

1. Paste the setup text from `vault serve token add`. The extension checks it with `vault-core`
   and, in the same click, requests the host permission `<scheme>://<host>/*`, without the port; a
   pattern with a port is granted but never matches.
2. For an `https` URL with `fp`, the extension opens the server URL in a tab and shows the
   fingerprint in both forms. After accepting the exception, comparing the fingerprints, and
   confirming, the extension tests a request. A loopback `http` URL skips this step.
3. Type or paste the secret key, and optionally the vault ID from the emergency kit.
4. Enter the master password. The extension runs the `vault-client` setup machine.

## Clipboard

Copying a username or password writes it with `navigator.clipboard.writeText` under the
`clipboardWrite` permission. An alarm 45 seconds later wakes the background script, which clears
the clipboard when it still holds the copied value. Firefox refuses custom clipboard types, so the
extension cannot offer `x-kde-passwordManagerHint`, and a clipboard manager may keep a copied
password.

## Build and tests

| Command | Purpose |
| --- | --- |
| `cargo build -p vault-wasm --target wasm32-unknown-unknown --profile wasm` | The WASM module |
| `npm run build` in `extension/` | `wasm-bindgen`, `wasm-opt`, esbuild, and the manifest |
| `npm test` in `extension/` | Unit tests for matching, message validation, and the fill script |
| `npm run e2e` in `extension/` | Headless Firefox against a real `vault serve` |

Unit tests run in Node with the WASM module. The end-to-end tests drive Firefox through geckodriver
and cover setup, unlock, sync between the extension and the CLI, fill into same-origin and
cross-origin frames, the `http` confirmation, idle lock, an unloaded background script, and the
transport behaviours in [the requirements](requirements.md#transport).

## Distribution

Firefox release builds load only signed extensions. The extension is signed as an unlisted add-on
through addons.mozilla.org with `web-ext sign --channel unlisted`, which needs an AMO account and
API key. A signed `.xpi` installs from a file.
