# vault

vault is a single-user, zero-knowledge password manager with a CLI, a Firefox extension, and an
Android app. Clients share one encrypted vault file through `vault serve`, a server that stores
bytes and never holds a key. The project is MIT licensed.

## Documents

| Path | Contents |
| --- | --- |
| `docs/requirements.md` | Requirements, threat model, releases, and decisions |
| `docs/style.md` | Documentation style for every document in the repository |
| `spec/format.md` | Vault file, keys, item schema, merge rule, rollback protection, and server API |
| `spec/vectors/` | Known-answer test vectors that every client checks |
| `docs/serve.md` | `vault serve`: commands, data directory, request handling, retention |
| `docs/cli.md` | The CLI: commands, local state, agent, sync behaviour, output |
| `docs/bitwarden.md` | Bitwarden import and export mapping |
| `docs/firefox.md` | The Firefox extension: components, storage, fill, save offers, and setup |
| `docs/phase-2-trial.md` | The checklist for the phase 2 trial of the CLI |

The spec is normative. Where code and spec disagree, the code is wrong until a spec change is
proposed and approved. Every format change updates the spec and the test vectors in the same commit.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/vault-core/` | Keys, vault file, body schema, merge rule, and sync decisions; no I/O, builds for WASM |
| `crates/vault-core/tests/` | Vector checks, merge property tests, and the release gate |
| `crates/vault-core/examples/gen_vectors.rs` | The generator of `spec/vectors/` |
| `crates/vault-client/` | Client state and the sync, recovery, credential change, setup, and restore procedures as state machines; no I/O, builds for WASM |
| `crates/vault-interop/` | Bitwarden JSON import and export; no I/O, builds for WASM |
| `extension/` | The Firefox extension: TypeScript sources, unit and end-to-end tests, and the build, pack, source, and sign scripts |
| `crates/vault-wasm/` | `wasm-bindgen` bindings over `vault-core` and `vault-client` for the Firefox extension; `API.md` is its TypeScript-facing API |
| `crates/vault-server/` | `vault serve`: the server, its data directory, and its commands |
| `crates/vault-cli/` | The `vault` binary: the CLI, the agent, and the embedded `vault serve` |
| `tools/bitwarden-fixtures/` | Python generator of the password-protected Bitwarden test fixtures |
| `tools/vectors-check/` | Independent Python check of `spec/vectors/` against the spec |
| `.github/workflows/ci.yml` | Format, lint, test, WASM build, vectors, `cargo-deny`, and `cargo-audit`; manual runs only until v1 |
| `deny.toml` | Allowed licences and sources for `cargo-deny` |
| `.cargo/config.toml` | The SIMD128 target feature for WASM builds, and the `wasm-bindgen` test runner |
| `rust-toolchain.toml` | Rust 1.96.0 with the `wasm32-unknown-unknown` target |

`vault-core`, `vault-client`, and `vault-interop` read no clock and no operating system randomness:
the caller passes `now` in ms and an `Rng`. Code that departs from a literal reading of the spec, or
reads an ambiguous passage one way, carries a `// SPEC-QUESTION:` comment.

## Commands

| Command | Purpose |
| --- | --- |
| `cargo fmt --all --check` | Formatting |
| `cargo clippy --workspace --all-targets -- -D warnings` | Lints |
| `cargo test --workspace` | Unit, vector, property, and release gate tests |
| `VAULT_EXPECT_TEST_KDF=1 cargo test -p <crate> --features insecure-test-kdf` | Tests with the test KDF parameters accepted, for `vault-core`, `vault-client`, and `vault-cli` |
| `cargo clippy -p vault-cli --no-default-features --features serve -- -D warnings` | Server-only build |
| `cargo test -p vault-core --release --test release_gate` | Release build refuses `test_kdf` headers |
| `cargo build -p vault-core -p vault-client -p vault-interop --target wasm32-unknown-unknown --release` | WASM build |
| `cargo build -p vault-wasm --target wasm32-unknown-unknown --profile wasm` | The Firefox extension's module |
| `cargo test -p vault-wasm --target wasm32-unknown-unknown` | The spec vectors through the WASM bindings, under Node, after `cargo install --locked wasm-bindgen-cli` at the pinned version |
| `cargo test -p vault-wasm --target wasm32-unknown-unknown --profile wasm --test release_gate` | The module built with the `wasm` profile refuses `test_kdf` headers |
| `npm test` in `extension/` | The licence check, `npm audit --omit=dev`, and the extension's unit tests |
| `npm run e2e` in `extension/` | Headless Firefox against a real `vault serve` and CLI; needs `GECKODRIVER`, `WASM_BINDGEN`, and Firefox |
| `cargo deny check` | Licences, advisories, and sources |
| `cargo run -p vault-core --example gen-vectors --features insecure-test-kdf` | Regenerate `spec/vectors/` |
| `python3 -I tools/vectors-check/check.py` | Check the vectors in Python, after `pip install -r tools/vectors-check/requirements.txt` |

The `insecure-test-kdf` feature accepts the test KDF parameters; `vault-client` and `vault-cli` pass
it through to `vault-core`, and their tests that need it declare `required-features`. A build
without `debug_assertions` fails to compile with it, and no crate enables it through a
dev-dependency. `tests/release_gate.rs` fails when the feature is on unless
`VAULT_EXPECT_TEST_KDF=1` is set, so a leak through feature unification fails `cargo test
--workspace`. Proptest failure seeds in `crates/vault-core/tests/merge_props.proptest-regressions`
are committed.

## Phasing

1. Format spec and `vault-core`.
2. `vault serve` and the CLI, including Bitwarden import and export.
3. Firefox extension.
4. Android app.

## Complexity guardrails

`docs/requirements.md` lists what stays out: per-item objects, cloud-provider storage, per-device
keys in the vault file, a server that understands the vault, client-maintained history, and
public-key or post-quantum cryptography. Adding one needs a written reason in the requirements.

## Style

Every document except `docs/requirements.md` follows `docs/style.md`: third person, present
tense, bold only for a defined term's first use, noun-phrase headings, no em dashes, serial comma,
British spelling in prose, and prose wrapped at 100 columns.
