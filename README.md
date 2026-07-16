# credman

Local credential manager for the terminal. Credentials are encrypted at rest with AES-256-GCM and unlocked with a BIP39 seed phrase (Argon2id key derivation). No network access.

## Install

```bash
cargo install --path .
```

Or build a release binary:

```bash
cargo build --release
./target/release/credman --help
```

## Quick start

```bash
# Create a vault (shows a 12-word seed once — write it down)
credman init

# On another device: copy the encrypted vault file, then verify your seed
credman restore

# Add / list / get credentials (prompts for seed each time)
credman add
credman list
credman get github

# Interactive TUI (default when no subcommand is given)
credman
# or
credman tui
```

Seed prompts are masked by default and show progress toward 12 words. Press `Ctrl+R` to temporarily reveal or hide the phrase; failed TUI unlocks keep the masked input so you can correct it.

`credman add --generate` accepts lengths from 8 through 128 characters, offers to copy the generated password, then offers an explicit terminal reveal if copying is declined or unavailable. Name lookup prefers an exact match; ambiguous partial matches list candidates so you can rerun the command with an exact name or ID.

## Vault location

Default path: `~/.credman/vault`

Override with `--vault /path/to/vault` or `CREDMAN_VAULT`.

To use the same vault on another device, copy the encrypted vault file to that path (or point `--vault` / `CREDMAN_VAULT` at it), then run `credman restore` and enter your seed phrase. The seed alone cannot recreate vault contents — the file stores a random salt required for decryption.

## Commands

| Command | Description |
|---------|-------------|
| `credman init` | Create vault; display and confirm 12-word seed phrase |
| `credman status` | Show vault path and whether it exists (no unlock) |
| `credman backup <dir>` | Copy encrypted vault to a timestamped file in `<dir>` |
| `credman restore` | Verify a copied vault with your seed, or create an empty vault from an existing seed |
| `credman restore --force` | Overwrite an existing vault with a new empty vault using a provided seed |
| `credman add` | Add an entry (interactive prompts) |
| `credman add --generate [--length 8..128]` | Add with a generated password (default length: 24) |
| `credman get <name\|id>` | Show an entry |
| `credman get <q> --password-only` | Print only the password |
| `credman get <q> --clipboard` | Copy password; clear it after 30 seconds if unchanged |
| `credman list` | List entries (no secrets) |
| `credman list --secrets` | Include passwords |
| `credman edit <name\|id>` | Edit an entry |
| `credman rm <name\|id>` | Delete an entry |
| `credman tui` | Open the TUI |

Global flags: `--vault <path>`, `--seed <phrase>` (scripting only — may appear in shell history).

After `init` / `restore`, you can optionally write down a short seed fingerprint (not stored; for offline verification later).

## TUI keys

On the unlock screen, a **Forgot seed?** note reminds you that credman cannot recover a lost phrase.

After unlock:

| Key | Action |
|-----|--------|
| `/` | Filter list (fuzzy) |
| `:` | Command palette (fuzzy actions) |
| `?` | Show keyboard shortcuts |
| `j` / `k` or arrows | Move selection |
| `a` | Add entry |
| `e` | Edit entry |
| `d` | Delete entry |
| `c` | Copy password |
| `r` or Space | Reveal / hide password |
| `q` / Esc | Quit (vault re-locked) |

Form passwords remain masked while typing. Delete confirmation names the selected entry, and the list distinguishes an empty vault from a filter with no matches. After copying, the status line shows the remaining clipboard lifetime; quitting the TUI clears a still-matching copied password immediately.

## Concurrency and lock files

credman permits one process at a time to hold an unlocked session for a vault. A second CLI command or TUI fails immediately with `vault is in use` rather than waiting or risking a last-writer-wins overwrite.

The advisory lock is stored next to the vault as `<vault>.lock` and is held for the complete unlocked session. The file can remain after credman exits; the operating system lock, not file existence, indicates active use. Do not delete or replace the lock file while credman is running.

## Clipboard behavior

CLI and TUI password copies expire after 30 seconds. Before clearing, credman compares the current clipboard text with the secret it copied. If you copied something else, credman leaves the newer value untouched.

CLI commands start a small hidden helper process so the command can return immediately. The secret is sent to that helper over piped standard input, never in command-line arguments or environment variables. Clipboard clearing is best effort: desktop clipboard managers may retain history, and headless or restricted display sessions may prevent later access. The TUI performs the same comparison in-process and displays a countdown.

## Data limits

Limits are checked on input, before save, and after decrypting a vault. Oversized files are rejected before being read into memory.

| Data | Limit |
|------|-------|
| Generated password | 8–128 characters |
| Entries per vault | 10,000 |
| Name | 256 characters; required |
| Username | 256 characters |
| Password | 4,096 characters |
| URL | 2,048 characters |
| Notes | 8,192 characters |
| Tags per entry | 32 |
| Tag | 64 characters |
| Decrypted vault JSON | 16 MiB |
| Encrypted vault file | 32 MiB |

## Security model

```
seed phrase → Argon2id(salt) → AES-256-GCM key → encrypted vault file
```

- **Seed phrase** is a BIP39 12-word mnemonic — the only unlock secret. It is never stored by credman.
- **Salt** and **nonce** live in the vault header; ciphertext is authenticated (GCM).
- Wrong seed or tampered file → decryption failure.
- Key material is wrapped with `zeroize` and dropped when the process exits.
- On Unix, new vault directories use `0700`, the default `~/.credman` directory is hardened to `0700`, and vault files use `0600`.
- A private advisory lock prevents concurrent credman sessions from silently overwriting changes.
- Clipboard values are cleared after 30 seconds only when they still match the copied password.
- Each CLI command unlocks for that process only (no background agent in v1).

### Threat model (honest)

| Threat | Status |
|--------|--------|
| Attacker steals vault file without seed | Cannot decrypt |
| Attacker has seed + vault file | Full access (by design) |
| Malware in your user session while unlocked | Can scrape memory / terminal — OS compromise wins |
| Lost seed phrase | Vault is unrecoverable |

**Backup**: keep an offline copy of the seed phrase. Use `credman backup <dir>` to copy the encrypted vault to a timestamped file (no unlock required) — without the seed it is useless to an attacker; with the seed it restores everything. On a new device, copy the vault file and run `credman restore`.

See [SECURITY.md](SECURITY.md) for trust boundaries, operational details, limitations, and recovery guidance.

## Development

```bash
cargo test
cargo run -- --help
```
