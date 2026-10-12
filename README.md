# vault

vault is a single-user, zero-knowledge password manager for Linux, Firefox, and Android. It replaces
a hosted service such as Bitwarden for one person who runs their own small server. Every client
keeps a full encrypted copy of the vault and works offline; `vault serve` stores the encrypted file
and its recent revisions, and never holds a key.

## Status

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Format spec, `vault-core`, and test vectors | Done |
| 2 | `vault serve` and the command-line client, with Bitwarden import and export | Done; in trial use |
| 3 | Firefox extension | In design |
| 4 | Android app | Not started |
| 5 | TOTP (v1.1), then WebAuthn passkeys (v1.2) | Not started |

The format is not yet frozen for a release. Bitwarden stays the primary password manager until
v1.0.

## Design

- One vault is one encrypted file. Clients sync it through `vault serve` with `GET` and a
  conditional `PUT`, and merge concurrent edits item by item, keeping a losing password in the
  item's history.
- The vault key is wrapped under a key derived from the master password (Argon2id) and a 128-bit
  secret key. The secret key never reaches the server, so a leaked server copy cannot be attacked
  by guessing the master password alone.
- The file uses XChaCha20-Poly1305 and HKDF-SHA-256, with the whole header authenticated. A
  generation number in the header lets every client detect a server that serves an older revision.
- The server stores bytes, revision metadata, and hashed per-device tokens, and never decrypts
  or merges anything. It keeps recent revisions and refuses pushes past its quota instead of
  deleting history, so a stolen token can stop sync but cannot erase the vault.
- A new device needs the server's setup text (URL and token), the secret key from an existing
  device or the emergency kit, and the master password.

## Repository

| Path | Contents |
| --- | --- |
| `crates/vault-core/` | Keys, vault file, item schema, merge rule, and sync decisions; no I/O, builds for WASM |
| `crates/vault-client/` | The sync, recovery, credential change, setup, and restore procedures as state machines; no I/O |
| `crates/vault-interop/` | Bitwarden JSON import and export, including password-protected exports |
| `crates/vault-server/` | `vault serve` |
| `crates/vault-cli/` | The `vault` binary: the command-line client, its agent, and `vault serve` |
| `spec/` | The normative format spec and known-answer test vectors |
| `tools/` | An independent Python check of the test vectors, and a Bitwarden fixture generator |
| `docs/` | Requirements, design documents, and the documentation style guide |

## Building

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.96.0).

```sh
cargo build --release -p vault-cli
cargo test --workspace
```

The binary is `target/release/vault`. A server-only binary builds with
`cargo build --release -p vault-cli --no-default-features --features serve`.

## Use

On the machine that runs the server:

```sh
vault serve init --url https://nas.lan:8443
vault serve token add desktop
vault serve
```

On a client, with the setup text that `token add` printed:

```sh
vault init                                  # first device: creates the vault and the emergency kit
vault setup                                 # any later device
vault import bitwarden bitwarden-export.json
vault add github --username me --generate
vault show github -c                        # copies the password, cleared after 45 seconds
vault sync
```

[vault serve](docs/serve.md) covers running the server as a system service, and
[the CLI](docs/cli.md) covers every command, the agent, and the files the client keeps.

## Documents

| Document | Contents |
| --- | --- |
| [Requirements](docs/requirements.md) | Goals, threat model, functional requirements, and decisions |
| [Format spec](spec/format.md) | Vault file, keys, item schema, merge rule, sync, and server API |
| [vault serve](docs/serve.md) | Server commands, data directory, request handling, and retention |
| [CLI](docs/cli.md) | Commands, local state, agent, sync behaviour, and output |
| [Bitwarden](docs/bitwarden.md) | Import and export mapping |

## Licence

MIT; see [LICENSE](LICENSE).
