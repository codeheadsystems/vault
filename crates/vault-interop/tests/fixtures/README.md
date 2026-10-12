# Bitwarden export fixtures

The export files the `vault-interop` tests read, and their sources.

| File | Source |
| --- | --- |
| `full.json` | Written by hand in the format of Bitwarden's plain JSON export: a login with every URI `match` value, every custom field type, a passkey, and a password history; a secure note; a card; an identity; an SSH key; an item in the trash; a passport (type 8); and a collection |
| `protected-pbkdf2.json` | `full.json` encrypted by `tools/bitwarden-fixtures/generate.py` with PBKDF2 (5,000 iterations) |
| `protected-argon2id.json` | `full.json` encrypted by `tools/bitwarden-fixtures/generate.py` with Argon2id (16 MiB, 2 iterations, parallelism 2) |

The password of the two `protected-` files is `correct horse battery staple`. The generator is an
independent Python implementation of Bitwarden's export encryption, so the tests check the Rust
decryption against a second implementation. It writes the same bytes on every run:

```sh
pip install -r tools/bitwarden-fixtures/requirements.txt
python3 -I tools/bitwarden-fixtures/generate.py crates/vault-interop/tests/fixtures
```
