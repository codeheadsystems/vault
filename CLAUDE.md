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

The spec is normative. Where code and spec disagree, the code is wrong until a spec change is
proposed and approved. Every format change updates the spec and the test vectors in the same commit.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/vault-core/` | Keys, vault file, body schema, merge rule, and sync decisions; no I/O, builds for WASM |
| `crates/vault-core/tests/` | Vector checks, merge property tests, and the release gate |
| `crates/vault-core/examples/gen_vectors.rs` | The generator of `spec/vectors/` |
| `tools/vectors-check/` | Independent Python check of `spec/vectors/` against the spec |
| `.github/workflows/ci.yml` | Format, lint, test, WASM build, vectors, `cargo-deny`, and `cargo-audit`; manual runs only until v1 |
| `deny.toml` | Allowed licences and sources for `cargo-deny` |
| `rust-toolchain.toml` | Rust 1.96.0 with the `wasm32-unknown-unknown` target |

`vault-core` reads no clock and no operating system randomness: the caller passes `now` in ms and
an `Rng`. Code that departs from a literal reading of the spec, or reads an ambiguous passage one
way, carries a `// SPEC-QUESTION:` comment.

## Commands

| Command | Purpose |
| --- | --- |
| `cargo fmt --all --check` | Formatting |
| `cargo clippy --workspace --all-targets -- -D warnings` | Lints |
| `cargo test --workspace` | Unit, vector, property, and release gate tests |
| `VAULT_EXPECT_TEST_KDF=1 cargo test -p vault-core --features insecure-test-kdf` | Tests with the test KDF parameters accepted |
| `cargo test -p vault-core --release --test release_gate` | Release build refuses `test_kdf` headers |
| `cargo build -p vault-core --target wasm32-unknown-unknown --release` | WASM build |
| `cargo deny check` | Licences, advisories, and sources |
| `cargo run -p vault-core --example gen-vectors --features insecure-test-kdf` | Regenerate `spec/vectors/` |
| `python3 -I tools/vectors-check/check.py` | Check the vectors in Python, after `pip install -r tools/vectors-check/requirements.txt` |

The `insecure-test-kdf` feature accepts the test KDF parameters. A build without
`debug_assertions` fails to compile with it, and no crate enables it through a dev-dependency.
`tests/release_gate.rs` fails when the feature is on unless `VAULT_EXPECT_TEST_KDF=1` is set, so a
leak through feature unification fails `cargo test --workspace`. Proptest failure seeds in
`crates/vault-core/tests/merge_props.proptest-regressions` are committed.

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
