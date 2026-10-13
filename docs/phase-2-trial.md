# Phase 2 trial

The phase 2 exit criterion is two weeks of daily CLI use alongside Bitwarden. This checklist sets up
`vault serve` and the CLI, imports the Bitwarden vault, and lists the behaviours that the automated
tests cannot reach: the Secret Service, the clipboard, real terminal prompts, and editors.

Bitwarden stays the primary password manager during the trial. A problem is recorded with the
command, its exit code, and its message; error messages never contain item content.

## Installation

1. Build and install the binary on every machine in the trial:

   ```sh
   cargo build --release -p vault-cli
   sudo install -m 0755 target/release/vault /usr/local/bin/vault
   ```

## Server

On the machine that stays on. When Firefox will later run on the same machine, add
`--http-listen 127.0.0.1:8080`.

2. Create the service user and the data directory:

   ```sh
   sudo useradd --system --home-dir /var/lib/vault-serve --create-home vault-serve
   sudo -u vault-serve vault serve init --data /var/lib/vault-serve --url https://<host>:8443
   ```

   Keep the printed fingerprint.

3. Install the system unit from [vault serve](serve.md#running-as-a-service) and start it:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now vault-serve
   journalctl -u vault-serve -f
   ```

4. Create one token per device:

   ```sh
   sudo -u vault-serve vault serve token add desktop --data /var/lib/vault-serve
   ```

   The output holds the token; it is shown once.

## First device

5. Generate a master password candidate if wanted: `vault gen --words 7`.
6. Run `vault init --kit /dev/shm/vault-kit.txt`. Paste the setup text from step 4, choose the
   master password, and confirm the last group of the secret key.
7. Print or copy the emergency kit to offline storage, then remove the file:
   `shred -u /dev/shm/vault-kit.txt`.
8. Check the state: `vault status`. In `~/.local/share/vault/local.json`, `secret_key_store` is
   `keyring` on a desktop with GNOME Keyring or KWallet. Seahorse or KWalletManager shows an item
   with `application = vault`.

## Import

9. In Bitwarden, export the vault as plain JSON to `/dev/shm/bitwarden.json`. `/dev/shm` is a
   memory file system, so the plaintext never reaches the disk.
10. Run `vault import bitwarden --dry-run /dev/shm/bitwarden.json` and compare the counts with
    Bitwarden's item count. Then run it without `--dry-run`.
11. Export again for comparison, keeping plaintext on `tmpfs` only:

    ```sh
    vault export --format bitwarden --plaintext -o /dev/shm/roundtrip.json
    ```

12. Compare the two files item by item; [Round trip](bitwarden.md#round-trip) lists the expected
    differences.

    ```sh
    norm='.items | map(del(.revisionDate, .folderId)) | sort_by(.id)'
    diff <(jq -S "$norm" /dev/shm/bitwarden.json) <(jq -S "$norm" /dev/shm/roundtrip.json)
    ```

13. Remove both files: `shred -u /dev/shm/bitwarden.json /dev/shm/roundtrip.json`. A later test of
    the password-protected path uses Bitwarden's password-protected export with the same command.

## Second device

14. On the server, create a token for the device (step 4).
15. On the first device, run `vault key show` (or `vault key show --qr`).
16. On the second device, run `vault setup`: paste the setup text, type the secret key, leave the
    vault ID empty or give the one from the kit, and enter the master password.

## Behaviours to check by hand

| Area | Check |
| --- | --- |
| Keyring | After a reboot, `vault ls` asks only for the master password, not the secret key |
| Agent | `vault unlock`, then `vault ls` answers without a prompt; after 15 minutes idle it asks again; `vault lock` ends it at once |
| Clipboard | `vault show -c <item>` pastes in another application; the clipboard manager (Klipper, GPaste, cliphist) does not record it; it is cleared after 45 s |
| Clipboard | On Wayland and on X11, if both are in use |
| Prompts | Ctrl-C at the master password prompt leaves the terminal echoing; Ctrl-Z at the prompt, then `fg`, prompts again without echo |
| Editor | `vault edit <item>` with the usual `$EDITOR`; no swap, backup, or undo file appears in the editor's usual directories afterwards |
| Sync | An edit on one device appears on the other after `vault sync`, or within 5 minutes with the agent unlocked |
| Offline | With the server stopped, `vault add` succeeds; after the server restarts, the next sync pushes it |
| Conflict | The same item edited on both devices before a sync: the newer edit wins and the other password is in its history (`vault show --reveal`) |
| History | `vault history` lists revisions; `vault restore <id> --item <item>` brings back an older version |
| Status line | After a problem, the next command prints one status line naming the repair command |

## Exit

The trial ends when two weeks of daily use have passed with no lost item or password and no
unexplained round-trip difference. Phase 3 (the Firefox extension) then becomes the daily path.
