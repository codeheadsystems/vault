# Test vectors

Known-answer vectors for `spec/format.md`. Each file is generated from fixed inputs by
`crates/vault-core/examples/gen_vectors.rs`, checked by `crates/vault-core/tests/vectors.rs`, and
checked independently by `tools/vectors-check/check.py`, which derives every value from the spec
text with argon2-cffi, PyNaCl, and the Python standard library.

## File layout

Each file is one JSON object with a `description`, any inputs that every case shares, and a
`cases` array. Each case has a `name`, usually an `op` that names the operation, its inputs, and
either its expected outputs or an expected error.

| Convention | Meaning |
| --- | --- |
| Binary values | Lowercase hex strings |
| `password_hex` | A password as the hex of its UTF-8 bytes, so that NFKC input is unambiguous |
| `params` | KDF parameters as `{"m_kib", "t", "p"}` |
| `now`, `modified`, `retired`, `horizon` | Integers in ms |
| `result` | `"ok"`, an error code, or the operation's output |
| `error` | The error code the operation returns |
| `draws` | The random bytes a client draws, in the order it draws them |

Every random input (secret keys, vault IDs, vault keys, salts, nonces, item IDs, and device IDs)
and every `now` is an explicit input.

## Test and release builds

Cases that use the test KDF parameters expect a test build. A build that refuses the test
parameters expects the case's `release_error` instead, or, in `tamper.json`, the
`release_error_open` and `release_error_unlock` fields. In `kdf.json`, `check_params` cases give
both `test_build` and `release_build` results.

Files in `sync.json` and `malformed.json`, and the file in `etag.json`, use the floor parameters
and a fixed KEK that no password derives; they open with the given vault key and need no
Argon2id run.

## Comparison rules

Merge and edit results compare `items`, `tombstones`, and `expired` as sets keyed by `id`, with
each value compared as JSON. Every other top-level key compares as JSON. Body JSON in
`vault-file.json` is compact, with object keys in byte order, which is the form the generator's
client writes; the format does not require that form.

## Error codes

An error code names the rule a case breaks. The `integrity.` codes are integrity errors and the
`input.` codes are refused caller input.

| Code | Rule |
| --- | --- |
| `integrity.size_limit` | The file is larger than 16 MiB |
| `integrity.truncated` | The input is shorter than its structure requires |
| `integrity.trailing_bytes` | The input is longer than its structure allows |
| `integrity.bad_magic` | The header magic is not `"VAULT"` |
| `integrity.format_version` | An unknown `format_version` |
| `integrity.unknown_flags` | A flag bit other than `test_kdf` |
| `integrity.generation` | A `generation` outside `[1, 2^48]` |
| `integrity.kdf_params` | KDF parameters outside the bounds |
| `integrity.test_kdf_in_release` | `test_kdf` in a build that refuses the test parameters |
| `integrity.padded_size` | A plaintext length that is not a positive multiple of 4,096 |
| `integrity.length` | A JSON length past the end of the plaintext |
| `integrity.padding` | A non-zero padding byte |
| `integrity.aead` | The body ciphertext fails authentication |
| `integrity.json` | Not UTF-8 JSON, or a lone surrogate |
| `integrity.bom` | A byte order mark |
| `integrity.duplicate_key` | A duplicate key in an object |
| `integrity.nesting` | Nesting deeper than 32 levels |
| `integrity.number` | A number that is not an integer in `[0, 2^53)` without a sign, fraction, or exponent |
| `integrity.missing_key` | A required key is missing |
| `integrity.wrong_type` | A defined key has the wrong JSON type, such as an `origin` that is not an object on a login or a note (an item of unknown `type` keeps any `origin` unchecked) |
| `integrity.bad_value` | A value outside its stated bounds |
| `integrity.duplicate_id` | An `id` twice among items and tombstones |
| `integrity.vault_id_mismatch` | A remote file with another `vault_id` |
| `integrity.generation_rollback` | A remote `generation` below the accepted one |
| `integrity.generation_fork` | The accepted `generation` with a different SHA-256 |
| `integrity.retired_wrap_nonce` | A remote file under a retired `wrap_nonce` |
| `wrong_credentials` | The vault key wrap does not open |
| `secret_key_typo` | A secret key text form with a wrong shape or check value |
| `input.password_too_short` | A new password under 12 scalar values after NFKC |
| `input.password_too_long` | A password over 4,096 bytes of UTF-8 |
| `input.password_unassigned` | A new password with an unassigned code point |
| `input.kdf_params` | KDF parameters for writing outside the bounds |
| `input.not_found` | No item with that `id` |
| `input.unsupported_item` | An edit of an item of unknown `type` |
| `input.setup_text` | Malformed setup text |
| `input.server_url` | A server URL that breaks the setup rules |
| `input.token` | A token text form with a wrong shape |
| `input.fingerprint` | An `fp` that is not 64 lowercase hex characters |
| `clock_before_build_time` | The clock reads earlier than the build time |
| `clock_skew` | The clock differs from the server's `Date` by more than a day |

When several rules are broken, the header rules apply in the order the table lists them, before
the body rules. Each vector breaks one rule, apart from the release expectations above.

## Regeneration

```text
cargo run -p vault-core --example gen-vectors --features insecure-test-kdf
python3 -I tools/vectors-check/check.py
```

The generator writes identical bytes on every run. A format change updates the spec, the
generator, and these files in the same commit.
