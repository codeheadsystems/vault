# vault serve

`vault serve` stores the vault file for every client and serves it over HTTPS, over HTTP on a
loopback address, or both. It stores bytes, revision metadata, and token hashes. It never unlocks,
decrypts, or merges the vault. The request and response rules are those of the spec
[Server API](../spec/format.md#server-api); this document covers the commands, the data
directory, and the operation of the process.

## Commands

| Command | Effect |
| --- | --- |
| `vault serve init --url <URL>` | Creates the data directory, `serve.toml`, and a self-signed certificate |
| `vault serve` | Runs the server in the foreground |
| `vault serve token add <name>` | Creates a token and prints the setup text and its QR code |
| `vault serve token ls` | Lists token names, creation times, and each token's last retained push |
| `vault serve token rm <name>` | Revokes a token |
| `vault serve revisions ls` | Lists retained revisions, newest first |
| `vault serve revisions prune --before <id>` | Deletes every revision with a lower ID, except the current one |
| `vault serve revisions rm --token <name> [--after <id>]` | Deletes the revisions a token pushed, optionally only those after a revision, except the current one |

Every command takes `--data <dir>`. The default is `$VAULT_SERVE_DATA`, then
`$XDG_DATA_HOME/vault-serve`, then `~/.local/share/vault-serve`.

The commands other than `vault serve` edit the data directory directly and work while the server
runs. There is no administration over the network. `revisions rm` is the repair after a stolen
token pushed garbage: it removes that token's revisions, newest included, after `token rm`.

### Initialisation

`vault serve init --url <URL>` takes these options:

| Option | Default | Effect |
| --- | --- | --- |
| `--url <URL>` | Required | The URL clients use, printed in the setup text |
| `--listen <addr>` | `0.0.0.0:8443` | The HTTPS address and port |
| `--http-listen <addr>` | None | A plain HTTP address and port, loopback only |
| `--cert <file> --key <file>` | None | PEM certificate chain and private key to serve instead of a generated pair |
| `--no-tls` | Off | No HTTPS listener; needs `--http-listen` |
| `--quota <size>` | `2GiB` | Storage quota, with a `MiB` or `GiB` suffix |

Without `--cert` or `--no-tls`, `init` generates an ECDSA P-256 certificate valid for ten years,
with the URL's host as its subject alternative name, into `tls/`. It prints the certificate's
SHA-256 fingerprint as lowercase hex and in the colon-separated upper-case form Firefox shows. A
URL whose scheme is `http` needs a loopback host and `--http-listen`; any other URL needs `https`.
`init` refuses a data directory that already holds `serve.toml`.

The HTTP listener serves two cases: a Firefox profile on the same machine, which uses
`http://localhost` without a certificate exception, and a TLS reverse proxy on the same machine.
A proxy passes `Authorization`, `If-Match`, and `If-None-Match` unchanged, accepts request bodies
up to 16 MiB, does not cache, and does not follow redirects. Plain HTTP on loopback suits a host
with one user: another local user who binds the port while the server is down receives the token
of any client that connects.

### Tokens

`vault serve token add <name>` creates a 20-byte token from the operating system's random source,
stores the SHA-256 of its bytes under `<name>`, and prints the setup text (spec
[Setup text](../spec/format.md#setup-text)) as text and as a QR code, followed by the certificate
fingerprint in both forms. The QR code draws light modules as blocks, for a terminal with a dark
background. The token appears only in that output. The name is 1 to 32 characters
from `a`-`z`, `0`-`9`, `-`, and `_`, and a name in use is refused.

| Option | Effect |
| --- | --- |
| `--url <URL>` | A URL other than the one in `serve.toml` |
| `--fp <hex>` | The fingerprint to put in the setup text |
| `--no-fp` | Leaves `fp` out, for a certificate that clients validate through WebPKI |

The default fingerprint is that of the certificate `serve.toml` names. An `https` URL with no
HTTPS listener (a reverse proxy) needs `--fp` or `--no-fp`. A loopback `http` URL never carries
`fp`.

`vault serve token rm <name>` takes effect on the server's next request. Revisions pushed with the
token keep its name. `token ls` derives each token's last push from the retained revisions.

## Data directory

| Path | Contents |
| --- | --- |
| `serve.toml` | Settings |
| `tokens.json` | `{"tokens": [{"name", "hash", "created"}]}`: per token, its name, the lowercase hex SHA-256 of its bytes, and its creation time |
| `server.lock` | Held by the running server for its lifetime |
| `lock` | Held by every writer while it writes |
| `tls/cert.pem`, `tls/key.pem` | The generated certificate and key, when `init` made them |
| `revisions/<id>.vault` | A revision's bytes |
| `revisions/<id>.json` | `{"etag", "size", "created", "token"}`: a revision's `ETag`, size in bytes, creation time, and token name |

The directory and `revisions/` are mode `0700` and every file is mode `0600`, all owned by the
user running the command. The server and every command refuse to start when any of them is owned
by another user, is accessible to the group or to others, or is a symbolic link. Files are opened
with `O_NOFOLLOW`. A copy of the data directory includes the TLS private key; a certificate from
`--cert` and `--key` can live outside it.

`serve.toml`:

```toml
url = "https://nas.lan:8443"
quota = "2GiB"

[https]
listen = "0.0.0.0:8443"
cert = "tls/cert.pem"
key = "tls/key.pem"

[http]
listen = "127.0.0.1:8080"
```

At least one of `[https]` and `[http]` is present, and `[http]` listens on a loopback address only.
Relative paths are relative to the data directory. Times in `tokens.json` and the metadata files
take the form `2026-10-12T15:04:05Z`.

### Writes and crash safety

A second `vault serve` on the same data directory fails to take `server.lock` and exits.

A revision is stored in this order: the metadata to a temporary file and a rename, then the bytes
to a temporary file, `fsync`, and a rename to `<id>.vault`, then an `fsync` of `revisions/`. A
revision exists when its `.vault` file exists. At start, the server removes temporary files
(`*.tmp`) in `revisions/` and in the top of the data directory, and metadata files without a
`.vault` file. The current revision is the one with the highest ID.
Revision file names are built from the ID as a decimal `u64`.

Every writer holds an exclusive `flock` on `lock`: the server while it stores or deletes a
revision, and `token`, `revisions prune`, and `revisions rm` while they edit. Writes to
`tokens.json` use a temporary file and a rename. The server never writes `tokens.json`. It re-reads
the file when its inode, modification time, or size changes, and answers every request with `401`
while the file cannot be read or parsed, or while it is a symbolic link or is accessible to the
group or to others.

The server keeps the current revision's `ETag` in memory and re-reads the current revision after
`revisions rm` or `prune` changes it. It computes the `ETag` from the file's bytes, so a metadata
file that disagrees with its revision does not stop clients from pushing. A revision whose metadata
file is missing or unreadable is still listed, with the `ETag` and size of its bytes, the
modification time of its `.vault` file as `created`, and an empty `token`.

## Request handling

- HTTP/1.1 only. TLS 1.2 and 1.3 through rustls with the `ring` provider.
- A request whose token matches no stored hash receives `401` with `WWW-Authenticate: Bearer`.
  Hashes are compared in constant time. The token is checked before the path and the method, so
  every request without a valid token receives `401`, whatever its path.
- A request path is matched exactly. A revision ID in `/v1/revisions/<id>` is a decimal `u64`
  without leading zeros; anything else receives `404`, whatever the method. A valid ID with a
  method other than `GET` receives `405`.
- An unknown path receives `404`. A known path with another method receives `405` with `Allow`.
- Revision bodies are `application/octet-stream`; `GET /v1/revisions` is `application/json`.
- Limits: 10 s for the TLS handshake and the request headers together, 60 s for the whole request,
  and 32 connections at a time. A request that runs past 60 s while it waits for the PUT lock or
  its body receives `408`; a store under way always completes. A response body still being sent
  at 60 s, or a write that waits 60 s for a client that stopped reading, closes the connection.
- `SIGTERM` and `SIGINT` stop accepting connections and end the process once requests in progress
  finish, or after 10 s.

### PUT processing

The server handles `PUT /v1/vault` in this order, reading the body only at step 5:

1. Check the token (`401`) and the presence of `If-Match` or `If-None-Match` (`428`).
2. Take the PUT lock. PUTs are serialised, so of two PUTs with the same `If-Match`, one stores a
   revision and the other receives `412`.
3. Check the condition. `If-Match` holds only when its value is exactly the current `ETag`; a list
   of values, `*`, or a weak validator does not hold (`412`). `If-None-Match` holds only when its
   value is exactly `*` and no revision exists; any other value receives `412`. `If-Match` on a
   server with no revision receives `412`. With both headers, both conditions must hold, so the
   request receives `412`.
4. Check a `Content-Length` over 16 MiB (`413`) and the quota (`507`). Without `Content-Length`,
   the quota check counts the body as 4,269 bytes, the smallest vault file, and step 7 checks the
   quota again for the size received.
5. Stream the body to a temporary file in `revisions/`, refusing it with `413` when it grows past
   16 MiB.
6. Check the shape of a vault file (`400`): it starts with `VAULT`, and its size is 4,269 bytes or
   more, with `size - 173` a multiple of 4,096. This check uses no key.
7. Store the revision and apply retention.

Every response to a PUT other than `200` carries `Connection: close`, because its body may be
unread.

### Retention and quota

After it stores a revision, the server keeps:

- the newest 100 revisions;
- within the 90 UTC days ending today, today included, the newest revision of each token on each
  UTC day;
- the newest revision of each token, whatever its age;
- the current revision.

It deletes every other revision. Each revision counts against the quota as its size rounded up to
4,096 bytes, plus 4,096 bytes for its metadata. A PUT that would take the total above the quota,
or the number of retained revisions above 10,000, receives `507`, and nothing is deleted to make
room.

### Logging

The server writes one line per request to standard error: the time, the peer address, the method,
the path, the status, the token name, and the body size. The path is cut to 200 characters and
control characters in it are escaped. The server never logs the `Authorization` header, a token,
or a request or response body.

## Running as a service

On a machine shared with the CLI, `vault serve` runs as its own system user, so a fault in the
server cannot reach the client's secret key, local vault file, or agent socket:

```sh
sudo useradd --system --home-dir /var/lib/vault-serve --create-home vault-serve
sudo -u vault-serve vault serve init --data /var/lib/vault-serve --url https://nas.lan:8443
sudo -u vault-serve vault serve token add laptop --data /var/lib/vault-serve
```

`/etc/systemd/system/vault-serve.service`:

```ini
[Unit]
Description=vault serve
After=network-online.target

[Service]
User=vault-serve
ExecStart=/usr/local/bin/vault serve --data /var/lib/vault-serve
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/vault-serve

[Install]
WantedBy=multi-user.target
```

`vault serve` prints a warning at start when the user running it has a client data directory or
an agent socket.

## Server-only build

`cargo build -p vault-cli --release --no-default-features --features serve` builds a `vault`
binary with only the `serve` commands. The server code calls only the token, setup text, and
`ETag` functions of `vault-core`; the crate still links `vault-core` and its dependencies.
