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
