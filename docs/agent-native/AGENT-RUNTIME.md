# Runtime reference

Credman runs on Linux as one durable vault owner with authenticated Unix-socket admission and MCP stdio frontends. A trusted supervisor supplies the unlock material, configuration, and private human administration channel.

## Commands and bootstrap

```text
credman serve --directory DIRECTORY --seed-fd SEED_FD --config-fd CONFIG_FD --admin-fd ADMIN_FD [--create] [--bridge-socket PATH]
credman mcp --session-file PATH
```

`DIRECTORY` is an existing absolute directory, owned by the effective user with mode `0700`. `--create` initializes a store without replacing state. A seed is a 12-word English BIP39 mnemonic supplied through a private descriptor. The descriptor arguments identify resources already opened by the supervisor; they do not contain secret values.

Seed, configuration, and administration descriptors must be distinct and above stdin, stdout, and stderr. Administration and workload sockets cannot alias. Input descriptors close after reading, unlisted descriptors close, and retained descriptors are close-on-exec.

The configuration descriptor contains a JSON object with these fields:

| Field | Content |
|-------|---------|
| `owner` | User-selected owner identity |
| `workspace` | Scope shared by this store's tasks and records |
| `admin_principal` | Identity assigned to the private human channel |
| `peers` | Preconnected workload sockets, each with `fd` and `principal` |
| `destinations` | Optional list of fixed HTTPS consumers, defaulting to empty |

An empty `peers` list requires `--bridge-socket`. At most 16 preconnected peers and 16 destinations are accepted. A bridge socket resides under an owned mode-`0700` directory.

Each destination has `id`, `service`, `origin`, `path`, `auth`, and optional `ca_file`. `auth` is `basic` or `bearer`. The HTTPS origin and service must match the task approval. The optional CA file requires an absolute nonsymlinked path whose file and ancestors have trusted ownership and no group or world write permissions.

The owner serializes human control before workload processing. It stops admitting requests after 300 seconds. An in-flight operation and its bounded reply may finish afterward.

## Human administration channel

Administration uses a connected private Unix socket, separate from agent connections. Messages contain a four-byte big-endian length followed by a JSON payload, with a maximum payload of 65,536 bytes.

| Operation | Arguments | Effect |
|-----------|-----------|--------|
| `status` | None | Check owner availability |
| `approve` | `approval` | Persist a task approval |
| `revoke_task` | `task` | Revoke task authority and dependent grants |
| `issue_session` | `principal`, `tasks`, `expires_at` | Issue a private one-use attachment credential |
| `revoke_session` | `session` | Invalidate attachment or active session authority |
| `import_secret` | `task`, `request`, `kind`, `values` | Import credentials under an approved task |
| `read_secret` | `task`, `record`, `fields` | Return authorized values with `permission: secret.read` |
| `mutate` | `task`, `request`, `mutation` | Apply a scoped mutation; human `Share` may include `SecretRead` |
| `audit` | Optional `offset` | Return up to 100 safe events, plus `total` and `has_more` |
| `shutdown` | None | Acknowledge and stop the owner |

A task approval contains `id`, `owner`, `principal`, `workspace`, `service`, `origin`, `fields`, `permissions`, `destinations`, `expires_at`, and optional `share`. Sharing bounds specify permitted recipients, fields, permissions, destinations, and expiry. Unlocking and session issuance create no task authority.

The human channel can also submit `generate`, `metadata`, and `use` under approved human-task scope. Human identity is established by the supervisor's channel binding. JSON labels do not authenticate an arbitrary host process.

## Sessions and MCP

`issue_session` returns a private `session` object with `id`, `socket`, `token`, and `expires_at`. It requires a nonempty task UUID allowlist, a principal distinct from the administrator, and a future expiry within the owner lifetime. At most 32 sessions are retained.

The supervisor writes the object into a new owned mode-`0600` regular single-link file under an owned mode-`0700` directory. The token must stay outside harness configuration, argv, environment variables, chat, and logs.

The frontend validates the session file and owner endpoint, then attaches using the token. The owner consumes the token once and binds the connection to its server-held principal, scope, task allowlist, and deadline. Disconnect, restart, expiry, and revocation require fresh issuance. MCP `clientInfo` and tool arguments cannot select identity.

The frontend implements newline-delimited JSON-RPC for `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`. Supported negotiated protocol versions are `2024-11-05` and `2025-11-25`. Stdout carries protocol messages only.

## Agent requests

Agent channels use the same bounded length-prefixed JSON framing as administration. Duplicate keys, unknown fields, malformed data, excessive nesting, invalid lengths, and transport deadline violations are rejected. MCP maps its four tools to these operations:

| MCP tool | Native operation | Arguments |
|----------|------------------|-----------|
| `credman_generate` | `generate` | `task`, `request`, `kind`, optional `username` |
| `credman_mutate` | `mutate` | `task`, `request`, `mutation` |
| `credman_metadata` | `metadata` | `task`, `record`, `fields` |
| `credman_use` | `use` | `task`, `usage` |

`generate` accepts kind `Login` with a public username or `ApiKey` without a username. The owner generates a private 32-character value and returns a record receipt. Reusing the same request UUID and specification returns the same receipt under current authority; changed specifications conflict.

Agent mutations are externally tagged `Patch`, `Delete`, `Share`, `Revoke`, or `ReportOutcome` objects. Record mutations use expected revisions. Patches accept metadata only. Agent-created read grants, plaintext creation, and secret patches are rejected. Outcome reports are untrusted and cannot establish a verified login.

`metadata` accepts approved `Label`, `Username`, and `Notes` fields. Agent requests have no plaintext secret-read operation. Explicit human reads use the administration channel.

`usage` contains `request`, `record`, `fields`, `destination`, and `action`. Only action `Use` is supported. Basic destinations require exactly `Username` and `Password`; Bearer destinations require exactly `ApiKey`.

The owner prepares `/usr/bin/curl` before final authorization, then supplies credentials through private stdin for a fixed verified-HTTPS GET. Agents cannot choose the URL, headers, CA file, or command. Redirects, ambient curl configuration, proxies, and automatic retries are disabled. Response bodies, headers, and curl stderr are discarded. A receipt contains an attempt ID and delivery status, without secret values.

Task, grant, and attached-session authority are checked immediately before delivery, after durable intent publication. Expiry at that boundary cancels dispatch. Cached responses also require current authority. `Accepted` describes HTTP delivery, without proving registration or a verified login. An uncertain outcome is not automatically redispatched.

## Offline administration

```text
credman admin --directory DIRECTORY --seed-fd SEED_FD --identity-fd IDENTITY_FD backup --secret-fd SECRET_FD [--passphrase] --output-fd OUTPUT_FD
credman admin --directory DIRECTORY --seed-fd SEED_FD --identity-fd IDENTITY_FD restore --secret-fd SECRET_FD [--passphrase] --backup-fd BACKUP_FD
credman admin --directory DIRECTORY --seed-fd SEED_FD --identity-fd IDENTITY_FD recover
```

The identity descriptor contains trusted `owner`, `principal`, and `workspace` values. Inputs are distinct transferred resources. Backup output requires an empty private regular file or private pipe and cannot alias an input. Ordinary admin stdout contains no backup or plaintext bytes. Seed and backup-secret text inputs are capped at 4096 bytes, identity at 64 KiB, and encrypted backup input at 32 MiB. Passphrases require at least 16 characters.

Backups use either a seed or a separate passphrase. A destination store can use a different seed. Restore validates the complete backup and creates a fresh store without overwriting state. It preserves records and request receipts while revoking retained tasks and grants.

After restore or recovery, approve fresh human and recipient tasks. Use the human task to grant access to an existing record before reading or using it. Recovery requires matching human scope, the seed, and valid retained encrypted evidence. It settles unfinished delivery conservatively and revokes authority.

## Storage

The store retains `state.v2`, `owner.lock`, and publication or recovery evidence such as `pending.v2` and `recovery.v2`. One owner holds the exclusive advisory lock throughout its session. Publication uses private unique temporary files, file sync, atomic publication, and directory sync.

Ambiguous publication freezes access for explicit recovery. Never delete lock or recovery evidence to force access. See [security](../../SECURITY.md) for filesystem assumptions, key custody, and recovery limits.
