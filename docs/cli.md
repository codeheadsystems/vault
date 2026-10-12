# vault command-line client

The `vault` command is the Linux client. It keeps a full copy of the vault on the device, works
offline, and syncs with `vault serve` as the spec [Sync](../spec/format.md#sync) section describes.
The same binary runs the server ([vault serve](serve.md)).

The sync, recovery, and credential change procedures live in the `vault-client` crate as state
machines with no I/O: each step returns a request to make (a `GET`, a conditional `PUT`, a revision
list or fetch, or a prompt for credentials) and takes the response back. The CLI supplies the
HTTP transport, storage, prompts, agent, editor, and clipboard. The Firefox and Android clients
reuse the same crate.

## Commands

| Command | Effect |
| --- | --- |
| `vault init` | Creates a vault, prints the emergency kit, and pushes the vault to the server |
| `vault setup` | Adds this device to an existing vault, or replaces its server token |
| `vault key show [--qr]` | Prints the secret key text form, and its QR code with `--qr` |
| `vault unlock` | Unlocks the vault and starts the agent |
| `vault lock` | Ends the agent |
| `vault status` | Lock state, last sync, unpushed changes, and sync problems |
| `vault ls [<folder>]` | Lists items, with `--review` only those a merge flagged |
| `vault find <text>` | Searches names, folders, usernames, and URIs |
| `vault show <item>` | Prints an item |
| `vault add <name>` | Adds a login, or a note with `--note` |
| `vault edit <item>` | Edits an item in the editor |
| `vault rm <item>` | Deletes an item |
| `vault mv <item> <folder>` | Moves an item to a folder; `""` for none |
| `vault gen` | Generates a password or passphrase |
| `vault sync` | Syncs now; `--recover` repairs sync after an integrity error |
| `vault passwd` | Changes the master password, the vault key, or the secret key |
| `vault import bitwarden <file>` | Imports a Bitwarden JSON export |
| `vault export` | Exports the vault |
| `vault history` | Lists the server's revisions |
| `vault restore <revision>` | Restores the vault, or one item, from a revision |
| `vault completions <shell>` | Prints a completion script for `bash`, `zsh`, or `fish` |
| `vault serve` | The server commands ([vault serve](serve.md)) |

### Item selection

A command that takes `<item>` resolves it in this order, ignoring deleted items:

1. An item ID, or a prefix of at least 8 characters of one.
2. A name, compared without regard to case. `<folder>/<name>` names an item in a folder.
3. A part of a name, compared without regard to case.

The first step that matches exactly one item selects it. A step that matches several items ends
the search with exit code 3 and lists them. No match at all is also exit code 3.

An item of a type the client does not know is listed as unsupported. `show` prints only its `id`
and `type`, `edit` refuses it, and `rm` deletes it.

### Item text form

`show` and `edit` present an item as TOML. Read-only data appears as comments.

```toml
# vault item
# Lines that start with "#" are ignored.
# Save and quit to apply the changes; quit without saving to cancel.
#
#
# id: 3b0e5d2c-6f0a-4c1e-9d55-1b8f2a7c9e01
# type: login
# modified: 2026-10-12T15:04:05Z
# password history: 2 entries
name = "GitHub"
folder = "Work"
favourite = false
username = "ned"
password = "correct-horse-battery"
totp = ""
uris = [
  { uri = "https://github.com", match = "base_domain" },
]
notes = """
"""

[[fields]]
name = "recovery code"
value = "abcd-efgh"
hidden = true

#
#
#
#
# end of item
```

A note has no `username`, `password`, `totp`, or `uris`. `show` prints `password`, `totp`, and every
hidden field value as `********` unless `--reveal` is given. `show --field <name>` prints one value
with no decoration: `username`, `password`, `totp`, `notes`, `uri` (the first URI), or a custom
field name.

`edit` applies the changed keys through `vault-core` and keeps everything the text form does not
show: password history, Android app bindings, passkeys, `origin`, and unknown fields. A key the
form does not define, a value of the wrong type, or an empty `name` is reported, and the editor
opens again with the error as a comment at the top. An unchanged file saves nothing. The file
starts and ends with five fixed comment lines, so no item text falls in the first or last five
lines, where Vim looks for modelines.

### Adding items

`vault add <name>` creates a login. Options: `--note`, `--folder <folder>`, `--username <user>`,
`--uri <uri>` (repeatable), `--generate` with the [generator](#password-generation) options, and
`-e` to open the editor on the result before saving. Without `--generate`, the command reads the
password from the terminal twice without echo, or one line from standard input when it is not a
terminal.

### Clipboard

`show -c` copies the password, or the value `--field` names, and prints nothing. `gen -c` copies
the generated value. A helper process (`vault clip`, started by the command) owns the clipboard,
offers the `x-kde-passwordManagerHint` type with the value `secret`, and after
`clipboard.clear_after` (45 s) clears the clipboard if it still holds the copied value. The value
reaches the helper through a pipe, never through arguments or the environment. Both X11 and
Wayland compositors with the data control protocol are supported; other Wayland compositors use
the X11 clipboard through XWayland. A clipboard manager may keep its own copy regardless of the
hint.

### Password generation

`vault gen` prints a 20-character password from upper case, lower case, digits, and symbols,
without the ambiguous characters `0O1lI|`. Options: `--length <n>`, `--no-upper`, `--no-digits`,
`--no-symbols`, and `--ambiguous`. `--words <n>` prints a passphrase of `n` words (default 6) from
the BIP-39 English word list, separated by `--separator` (default `-`). The entropy in bits goes to
standard error, or into the JSON result.

### Device setup

`vault init`:

1. Reads the setup text from `vault serve token add`, without echo. A setup text that does not
   parse is reported without echoing it.
2. Checks that `GET /v1/vault` returns `404`, and refuses otherwise.
3. Reads a master password twice and refuses one shorter than 12 characters.
4. Generates the secret key, the device ID, and the vault, with `--kdf-memory 64`, `128`, or `256`
   MiB (default 64).
5. Prints the emergency kit: the secret key text form and its QR code, the server URL, and the
   vault ID. `--kit <file>` also writes it to a new mode `0600` file. The command then asks for the
   last group of the secret key, to confirm the kit was kept.
6. Stores the state and pushes generation 1 with `If-None-Match: *`.

`vault setup`:

1. Reads the setup text, without echo.
2. Pulls the vault. A `404` ends setup with the message that the server holds no vault.
3. Reads the secret key text form; a typo is reported before any key derivation. Then asks for the
   vault ID from the emergency kit, which may be left empty; when given, it must equal the remote
   `vault_id`.
4. Reads the master password and unlocks, allowing three attempts.
5. Generates the device ID and stores the state, recording which secret key store holds the key.

On a device that already has a vault, `vault setup` reads only the setup text, checks that the
server's vault has the same `vault_id`, and replaces the stored URL, token, and fingerprint. This
is the repair after a `401`.

`vault key show` asks for the master password every time, also while the agent is unlocked.

### Credential changes

`vault passwd`, `vault passwd --rekey`, and `vault passwd --new-secret-key` follow the spec
[Credential change](../spec/format.md#credential-change). With the agent unlocked, the command
asks only for the new master password, so a live agent session can replace a forgotten one (the
requirements' threat model accepts this). Without the agent, it asks for the current master
password first. It ends the agent on success. `--new-secret-key` prints the new emergency kit and
asks for its last group before it pushes.

### Import and export

`vault import bitwarden <file>` reads a plain or password-protected Bitwarden JSON export, asking
for the export password when needed. An item whose Bitwarden ID matches the `origin` of an
existing item updates that item as a local edit, so a changed password moves into its history; an
unchanged one is left alone; any other item is added. Items deleted in Bitwarden since an earlier
import are not deleted, and are counted. `--folder <prefix>` puts the imported folders under a
prefix, and `--dry-run` prints the counts without saving. The command prints the numbers of items
added, updated, unchanged, and skipped, and reminds the user to delete the source file. The
mapping is in [Bitwarden import and export](bitwarden.md).

`vault export --format <format>`:

| Format | Output |
| --- | --- |
| `vault` | The local vault file, which opens with the master password and secret key |
| `bitwarden` | A plain Bitwarden JSON export |
| `json` | The vault body as the spec defines it |

`bitwarden` and `json` are plaintext and need `--plaintext`. Output goes to standard output, or
with `-o <file>` to a new file created with mode `0600`; an existing file is refused. A plaintext
export prints a warning to standard error.

### History and restore

`vault history` lists the server's retained revisions: ID, time, pushing token, and size, marking
the current one. `vault restore <revision>` downloads the revision, checks its `vault_id`, opens
it (asking for that revision's credentials when its wrap differs from the current one), and
restores the whole vault (`vault-core` `restore_all`), or one item with `--item <item>`, selected
in the revision. A revision under a retired `wrap_nonce` with an ID above the one at which that
nonce was retired is refused: only a holder of the old credentials can have written it. The command
prints the revision's pushing token and the number of items added, changed, and removed, asks for
confirmation unless `-y` is given, saves, and syncs.

## Options for every command

| Option | Effect |
| --- | --- |
| `--json` | Prints one JSON object on standard output (see [JSON output](#json-output)) |
| `--offline` | Contacts no server; writes stay local until a later sync |
| `--password-fd <n>` | Reads the master password from file descriptor `n`, for scripts |

## Files

| Path | Contents |
| --- | --- |
| `$XDG_DATA_HOME/vault/` | Client data, mode `0700`; default `~/.local/share/vault/` |
| `local.json` | The local vault file and sync state |
| `server.json` | Server URL, token, and certificate fingerprint |
| `device-id` | The device ID, 32 lowercase hex characters |
| `secret-key` | The secret keys, only when the file store was chosen at setup |
| `lock` | Advisory lock held by every writer |
| `$XDG_CONFIG_HOME/vault/config.toml` | [Settings](#settings) |
| `$XDG_RUNTIME_DIR/vault/` | The agent socket and editor files, mode `0700` |

Every file is mode `0600`. A command refuses a data directory that another user owns, that the group
or others can access, or that is a symbolic link.

### Local state file

`local.json` holds everything the spec [Client state](../spec/format.md#client-state) requires to
change together. A write goes to a temporary file, which is synced with `fsync`, renamed over
`local.json`, and followed by an `fsync` of the directory:

```json
{
  "v": 1,
  "vault_id": "<32 hex>",
  "accepted": {"generation": 7, "hash": "<64 hex>"},
  "wrap_nonce": "<48 hex>",
  "retired": [{"nonce": "<48 hex>", "revision": 41}],
  "refused": ["<48 hex>"],
  "secret_key_store": "keyring",
  "pending_secret_key": false,
  "stopped": null,
  "dropped": [],
  "last_sync": 1760281445000,
  "file": "<hex of the local vault file>"
}
```

- `retired` records, with each retired `wrap_nonce`, the ID of the server's current revision when
  it was retired, read from `GET /v1/revisions` after the credential change. `vault restore` uses
  it.
- `refused` lists the `wrap_nonce` values whose wrap failed to open in the credential change on
  another device flow.
- `secret_key_store` is `keyring` or `file`, chosen at `vault init` or `vault setup` and never
  changed by a fallback.
- `stopped` is `null` while sync runs, or
  `{"reason": "integrity" | "token" | "credentials", "code": "<error code>", "at": <ms>}`.
- `dropped` lists the names of local items a background sync dropped because they predate the
  purge horizon; the next interactive command prints them and clears the list.
- Unpushed changes exist when the hash of `file` differs from `accepted.hash`.

### Secret key storage

With `secret_key_store = keyring`, the secret key is stored in the Secret Service (GNOME Keyring or
KWallet) as an item with the attributes `application = vault`, `vault_id = <hex>`, and
`slot = current` or `pending`. When the Secret Service is unreachable later, commands that need the
secret key fail with a message; they never fall back to the file. `vault init` and `vault setup`
choose `file` when no Secret Service is reachable or the `keyring` setting is `file`, store the key
in `secret-key`, and print a warning.

## Agent

The agent keeps the vault key in memory between commands. `vault unlock`, or the first command
that needs the vault key when no agent runs, reads the master password, unlocks the vault, and
starts the agent as a detached process (`vault agent`). The command passes the vault key to it
through an inherited pipe, never through arguments or the environment. Without an agent
(`agent.enabled = false`, `VAULT_NO_AGENT=1`, or no `$XDG_RUNTIME_DIR`), every command that needs
the vault key asks for the master password.

| Aspect | Behaviour |
| --- | --- |
| Holds | The vault ID and vault key; never the master password or the secret key |
| Socket | `$XDG_RUNTIME_DIR/vault/agent.sock`, mode `0600` |
| Peers | The agent accepts only connections whose `SO_PEERCRED` user is its own; the command checks the directory's owner and mode before connecting |
| Ending | After `agent.idle` (15 minutes) without a request, `agent.max` (8 hours) after the unlock, `vault lock`, a credential change, `SIGTERM`, or removal of the socket |
| Hardening | Not dumpable (no core files, no `ptrace` by other processes), and memory locked when the `RLIMIT_MEMLOCK` limit allows |
| Sync | Every `sync.interval` (5 minutes), and 2 s after a command reports a write |

Unlike `ssh-agent`, which signs on request and never releases its keys, this agent gives the vault
key to any process of the same user that asks. Its hardening protects the key in the agent's own
memory, not from a process of the same user.

The agent's sync never prompts. Anything that needs a prompt (credentials changed on another
device, a pending secret key to resolve, or an integrity error) sets `stopped` and waits for an
interactive `vault sync`.

### Agent protocol

One request per connection. A message is a big-endian `u32` length, at most 64 KiB, and that many
bytes of JSON. Requests carry `"v": 1` and an `op`:

| `op` | Response |
| --- | --- |
| `key` | `{"vault_id", "vault_key"}`, both hex; resets the idle timer |
| `sync` | `{}`; schedules a sync |
| `status` | `{"unlocked_at", "locks_at", "last_sync", "last_error"}` |
| `lock` | `{}`; the agent zeroes the key and exits |

An error response is `{"error": {"code", "message"}}`. A command that receives a key that does not
open the local file ends the agent and asks for the master password.

## Sync behaviour

- A command served by an unlocked agent reads the local file. `ls`, `find`, `show`, and `gen`
  never contact the server then.
- An unlock with a typed master password pulls first (spec
  [Opening a file](../spec/format.md#opening-a-file)), with a 5 s limit; when the server does not
  answer in time, the unlock uses the local file.
- A write saves the local file first. With an agent, the command then asks the agent to sync and
  exits. Without one, it syncs before exiting, with a 10 s limit; a failed sync prints a warning
  and the change stays local. The exit code is 0 either way.
- Sync holds `lock` only to read and to commit, never during network requests. At commit it
  compares the hash of the local file with the one it read. When a command changed the file
  meanwhile, it merges the current local body into the result under the new header, so the change
  stays local and unpushed, and the next sync pushes it.
- `vault sync` syncs in the foreground and asks for whatever the sync needs. It reports the
  outcome: up to date, adopted the server's file, or pushed a new generation.
- Before each sync the client checks its clock (spec [Sync](../spec/format.md#sync)) against the
  build time and the server's `Date` header.
- An integrity error, a `401`, or a credential change on another device sets `stopped`. Reads and
  writes go on locally; only sync stops, until `vault sync --recover`, `vault setup`, or
  `vault sync` respectively.
- Local items that a merge drops because they predate the server's purge horizon are listed by
  name on standard error, or recorded in `dropped` by a background sync.

When standard error is a terminal, a command prints at most one status line after its output, in
this order of priority: dropped items, sync stopped (with the command that repairs it), unpushed
changes older than one hour, and items flagged for review.

### Server connection

The client uses hyper's HTTP/1.1 client over rustls with the `ring` provider, the same stack as
the server. With `fp` in the setup text it accepts only a leaf certificate whose DER SHA-256 equals
`fp`, and still checks the handshake signature against that certificate's key. Without `fp` it
validates the chain against the `webpki-roots` set. A `localhost` URL connects to `127.0.0.1` or
`::1` without the system resolver.

- Connections time out after 5 s, requests after 30 s.
- A vault file response over 16 MiB, or a revision list over 1 MiB, is an error.
- Redirects are not followed, and proxy environment variables are ignored.
- Strings from the server, such as token names in `vault history`, are escaped like item content.

## Editor files

`edit` and `add -e` need `$XDG_RUNTIME_DIR` on a `tmpfs` file system. The command creates
`$XDG_RUNTIME_DIR/vault/` with mode `0700` if needed, checks with `lstat` that it is a directory the
user owns with that mode, creates a new mode `0700` directory in it, checks the file system type
with `fstatfs` on that directory, and creates `item.toml` inside with `O_CREAT`, `O_EXCL`, and
`O_NOFOLLOW`. The editor is `$VISUAL`, then `$EDITOR`, then `vi`, run as
`sh -c '$VISUAL "$1"' sh <path>`.

- Vi, Vim, and Neovim start with swap, backup, undo, and viminfo or ShaDa files and modelines
  turned off.
- Emacs starts with backup files, auto-save, lock files, and file-local variables turned off.
- Afterwards the file is overwritten with zeros and removed, and so is the directory, also when
  the editor fails.

Other editors may write backup or swap files of their own, inside or outside that directory. A
`tmpfs` can be written to swap.

## Output

Item content and server strings printed to a terminal have control characters other than newline
and tab escaped, on standard output and standard error. Output to a pipe or a file is unchanged.
Error messages never contain item content other than item names, key material, tokens, or setup
text.

### JSON output

With `--json`, a command prints one JSON object and a newline on standard output. Within
`"v": 1`, fields are only ever added.

```json
{"v": 1, "result": {}}
{"v": 1, "error": {"exit": 3, "code": "item.not_found", "message": "no item matches \"gh\""}}
```

| Command | `result` |
| --- | --- |
| `ls`, `find` | `{"items": [{"id", "type", "name", "folder", "username", "favourite", "review"}]}` |
| `show` | The item, as the body schema defines it; with `--reveal` only, the values of `login.password`, `login.totp`, hidden fields, `password_history`, and `login.passkeys`, which are otherwise `null` |
| `add`, `edit`, `rm`, `mv` | `{"id", "synced"}` |
| `gen` | `{"value", "bits"}` |
| `sync` | `{"outcome": "up_to_date" \| "adopted" \| "pushed", "generation", "dropped": [names]}` |
| `status` | `{"unlocked", "last_sync", "unpushed", "stopped", "review"}` |
| `history` | `{"revisions": [...]}`, as `GET /v1/revisions` returns them |
| `key show` | `{"secret_key"}` |
| `import` | `{"added", "updated", "unchanged", "skipped"}` |

`code` is a `vault-core` error code such as `integrity.bad_magic`, or one of the client's own:
`item.not_found`, `item.ambiguous`, `auth.wrong_password`, `server.unreachable`,
`server.status`, `server.token`, `sync.stopped`, and `usage`. These codes, including those of
`vault-core`, are part of the JSON interface: a code is never renamed, and new ones are only
added.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, including a write saved locally whose sync failed |
| 1 | Other error |
| 2 | Usage error |
| 3 | No item matches, or more than one does |
| 4 | Wrong master password or secret key, or no terminal to ask for one |
| 5 | Integrity error; sync stopped until `vault sync --recover` |
| 6 | Server unreachable, or an unexpected HTTP status |
| 7 | The server refused the token; run `vault setup` |
| 8 | Credentials changed on another device; run `vault sync` |

## Settings

`$XDG_CONFIG_HOME/vault/config.toml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `agent.enabled` | `true` | Commands use the agent |
| `agent.idle` | `15m` | The agent ends after this long without a request |
| `agent.max` | `8h` | The agent ends this long after the unlock |
| `sync.auto` | `true` | Sync after writes and from the agent |
| `sync.interval` | `5m` | Time between the agent's syncs |
| `clipboard.clear_after` | `45s` | Time before a copied value is cleared |
| `keyring` | `auto` | `auto` uses the Secret Service when reachable; `file` uses `secret-key` |

Durations are a number with `s`, `m`, or `h`.

## Environment variables

| Variable | Use |
| --- | --- |
| `VAULT_NO_AGENT` | `1` makes commands open the vault themselves |
| `VISUAL`, `EDITOR` | The editor |
| `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_RUNTIME_DIR`, `HOME` | Where the client keeps its data, settings, socket, and editor files |
