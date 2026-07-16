# Security model

credman is a single-user, local credential manager. It has no network service, synchronization service, browser extension, or background unlock agent. Its security boundary is the local operating-system user account.

## Protected assets

- The 12-word BIP39 seed phrase is the root secret and is never stored by credman.
- Vault entries are plaintext only while a credman process is unlocked.
- The encrypted vault, its salt, nonce, format metadata, and advisory lock file are stored on disk.
- A copied password temporarily crosses into the desktop clipboard service.

The seed phrase and an encrypted vault together provide full access. Losing the seed makes the vault unrecoverable.

## Encryption at rest

credman derives a 256-bit key from the normalized seed phrase and a random 16-byte salt using Argon2id. Vault JSON is encrypted and authenticated with AES-256-GCM using a fresh 12-byte nonce on every save. The salt, nonce, Argon2 parameter metadata, and ciphertext are stored in the vault file.

Authenticated decryption rejects an incorrect seed and modified ciphertext. The current format uses compile-time Argon2 parameters even though those values are recorded in the header.

Sensitive key, seed, clipboard, and entry buffers use `zeroize` where practical. This reduces remnants after normal drops; it does not guarantee protection from process inspection, swap, crash dumps, or a compromised operating system.

## Files and permissions

The default paths are:

```text
~/.credman/vault
~/.credman/vault.lock
```

On Unix:

- newly created vault directories use mode `0700`;
- the managed default `~/.credman` directory is corrected to `0700`;
- vault, temporary, and lock files use mode `0600`;
- an existing parent of a custom `--vault` path is not chmodded because it may be intentionally shared.

Each save writes a private temporary file, calls `sync_all`, and atomically renames it over the vault. Backups should copy the completed `vault` file, not `vault.tmp` or `vault.lock`.

## Concurrent access

credman takes a non-blocking exclusive advisory lock on `<vault>.lock` before reading or replacing a vault and holds it for the complete unlocked session. This includes read-only commands because every command decrypts the whole vault and the simple single-session rule avoids inconsistent behavior.

If another credman process owns the lock, the new process fails immediately with `vault is in use by another credman process`. It does not wait and does not overwrite the active session's eventual save.

The lock is released by the operating system when the process exits or crashes. The lock file itself may remain and is not evidence of an active process. Do not delete it while credman is running: replacing the path could allow two processes to lock different files.

Advisory lock guarantees depend on the filesystem. A local filesystem is recommended; network filesystems may provide weaker or implementation-specific locking.

## Seed and terminal exposure

Unlock prompts mask each seed word and show progress toward 12 words. `Ctrl+R` temporarily reveals or hides the phrase. The TUI preserves failed input for correction but returns it to the masked state. Seed buffers are zeroized after successful use and when the TUI exits.

After `init` / `restore` confirmation you may optionally write down a **seed fingerprint** (first 4 hex characters of SHA-256 over the normalized phrase). This is advisory only — credman never stores the seed or the fingerprint. It helps you later check that you still have the same phrase without comparing all 12 words from memory.

`--seed <phrase>` is available for scripting. It may appear in shell history and process listings; prefer interactive entry for real secrets.

Initialization must display the generated seed once. Terminal emulators, screen sharing, recording, and scrollback can retain that display. Initialize in a private terminal, write the seed down offline, and close or clear the terminal according to the terminal emulator's behavior.

Commands that print passwords, including `get --password-only` and `list --secrets`, intentionally expose them to standard output. Avoid shell tracing, terminal recording, shared sessions, and untrusted log collectors.

## Clipboard lifecycle

Copied passwords have a 30-second lifetime:

1. credman writes the password to the system clipboard.
2. CLI commands start a hidden helper process and pass the expected password over piped standard input. The value is not placed in process arguments or environment variables.
3. The TUI tracks the expected password and shows the remaining lifetime in its status line.
4. At expiration, credman reads the clipboard and clears it only if it exactly matches the expected password.
5. If the user copied another value, credman leaves that newer value untouched.

Quitting the TUI attempts an immediate compare-and-clear. A new TUI copy replaces the previous timer.

Clearing is best effort. Clipboard history managers may retain old entries, another process in the same desktop session may read the value before expiration, and a headless or restricted display session may prevent the helper from reconnecting. Disable clipboard history for sensitive workflows or use direct password entry when that risk is unacceptable.

## Input and vault limits

Validation runs when CLI or TUI data is saved, before serialization, after decryption, and before oversized vault files are read.

| Data | Limit |
|------|-------|
| Generated password | 8–128 characters |
| Entries | 10,000 |
| Name | 256 characters and nonblank |
| Username | 256 characters |
| Password | 4,096 characters |
| URL | 2,048 characters |
| Notes | 8,192 characters |
| Tags | 32 per entry |
| Tag | 64 characters |
| Decrypted vault JSON | 16 MiB |
| Encrypted vault file | 32 MiB |

Text limits count Unicode characters. Vault-size limits count bytes. The TUI stops accepting form characters at its field limit; all paths still perform authoritative validation before persistence.

These bounds prevent accidental or crafted local files from causing unbounded allocations. They are not a substitute for operating-system storage quotas.

## Threat boundaries

credman is designed to protect against:

- theft of the encrypted vault without the seed;
- accidental concurrent credman sessions overwriting each other;
- routine shoulder surfing when masked input is used;
- indefinite clipboard persistence when the desktop permits compare-and-clear;
- oversized or malformed vault data exceeding documented bounds.

credman does not protect against:

- malware, debuggers, or another process with equivalent user privileges while the vault is unlocked;
- keyloggers, compromised terminal emulators, or clipboard managers that retain history;
- an attacker who has both the seed and vault;
- a replaced or malicious credman binary;
- physical coercion or disclosure of the offline seed;
- deletion, rollback, or corruption of the vault file.

## Backup and recovery

Keep the seed phrase offline and separate from encrypted vault backups. Test restoration with a copied vault before relying on a backup process.

To restore:

1. place the encrypted backup at the intended vault path;
2. ensure no credman process is using that vault;
3. run `credman restore` (or `credman --vault /path/to/vault restore`);
4. enter the matching seed phrase to verify decryption.

If no vault file is present, `credman restore` can create a new empty vault from an existing seed. That does not recover previous entries — the encrypted vault backup is required for that. `credman restore --force` overwrites an existing vault with a new empty one.

Do not edit the binary vault, lock, or temporary files manually. There is no seed recovery or reset flow.

## Reporting a security issue

Do not include seed phrases, passwords, vault files, or other credentials in a public report. Provide a minimal reproduction using generated test data and describe the operating system, filesystem, terminal, and clipboard environment involved.
