# Security model

Credman is a user-owned credential vault for agent tasks. A trusted supervisor unlocks the store, binds private channels to principals, and supplies human approval separately. The current Linux runtime is a bounded local owner with authenticated Unix-socket admission and stdio MCP frontends, not a production provider installation.

## Protected assets and trusted components

The root seed, derived keys, credential fields, and sensitive metadata require protection. Records, task approvals, grants, revisions, retry state, delivery attempts, and audit events are persisted together inside encrypted state.

The supervisor, operating-system account, kernel, binary, toolchain, and configured destination remain trusted. Knowing both the seed and encrypted store permits offline access. Losing the seed without another usable backup secret makes that encrypted copy unrecoverable.

Host-capable agents running under the human's Unix UID are not isolated principals. Role names, JSON identity fields, and role-specific bridge sockets do not authenticate a hostile host process. A production integration must enforce the intended worker boundary in its actual launch path.

## Encryption and private resources

The shared crypto implementation uses Argon2id, a random 16-byte salt, a 256-bit key, and AES-256-GCM with a fresh 12-byte nonce for each encrypted image. Header values and lengths are bounded before expensive processing. Backup envelopes authenticate their version, secret kind, KDF parameters, and salt inside encrypted plaintext.

The seed and supervisor configuration enter through distinct inherited descriptors above stdin, stdout, and stderr. Workload and administration sockets cannot alias. Transferred descriptors are close-on-exec, and unlisted descriptors are closed. Unlock material stays outside command arguments and environment variables.

Keys and sensitive buffers use zeroization where practical. This does not prove that copies cannot remain in process memory, swap, crash dumps, or another trusted component.

## Files, ownership, and durability

A store uses an explicit absolute directory, owned by the effective Unix user with mode `0700`. Directory traversal rejects symlinks. Anchored file access requires owned regular single-link files with mode `0600` and refuses final symlinks.

The agent-store files include `state.v2`, `owner.lock`, and retained publication or recovery evidence such as `pending.v2` and `recovery.v2`. An exclusive advisory lock is held for the complete owner session. Do not replace or delete lock or evidence files to bypass access checks.

Publication uses unique private temporary files, file sync, atomic publication, and directory sync. A definite prepublication failure differs from an ambiguous publication result. Ambiguity freezes access for explicit human recovery instead of reusing stale in-memory authority. Filesystem guarantees remain platform-dependent; this is local-filesystem behavior, not a power-loss or network-filesystem proof.

## Client attachment and MCP identity

Only the private human administration channel issues or revokes client sessions. A separately generated random token authenticates attachment; record, task, grant, and session UUIDs do not. The owner consumes the token once and binds the connection to a human-selected principal, owner/workspace scope, task allowlist, and expiry. Issuance does not approve a task. Restart, disconnect, expiry, and revocation do not create reconnect authority.

The session document is an owned mode-`0600` regular single-link file under a private mode-`0700` directory. The proxy refuses unsafe or symlinked paths and verifies the private owner endpoint. Harness configuration contains a file path, never the seed or attachment token. A host-capable same-UID process can still steal a readable token; this is not OS isolation.

MCP initialization labels and tool arguments cannot choose principal or administration authority. A client that reuses one MCP process across conversations shares that configured session identity. Per-conversation authentication is not inferred. Configuration merging and diagnostic startup can launch a client earlier than expected; a probe must use its own issued attachment.

## Agent authority and secret disclosure

Unlocking creates no task authority. Each request is bound to the context established by its private channel, not an identity chosen in request JSON.

Tasks restrict owner, principal, workspace, service, origin, fields, permissions, destinations, and expiry. Grants cannot widen the issuer's approved delegation. Grants pin secret-value versions, and cached requests recheck current authority before returning their retained result.

`SecretUse` sends authorized values to an approved fixed HTTPS destination and returns only delivery status and references. The destination receives the authorized secret by design. `SecretRead` does not authorize MCP disclosure: the MCP catalog has no read tool, and the owner rejects raw reads from workload peers. A trusted human can import or read secrets and issue scoped read grants through the private administration channel when the task permits it. Workload peers cannot issue read grants. Revocation blocks future vault access; it cannot recall a value already sent to a destination or rotate an upstream password.

Private use performs only a fixed verified-HTTPS GET with Basic or Bearer authentication. Destination service and origin must match the approved task. The broker prepares the child before final authorization. The handoff callback supplies the private configuration after authorization; a cached attempt does not dispatch again. Response body, headers, and curl stderr are discarded, not scanned. Delivery status does not prove login, registration, or account creation. Unknown outcomes are not automatically redispatched. An untrusted agent report is not verified login evidence. There is no portable private injection guarantee across the harnesses.

## Input and output boundaries

Workload transport uses bounded length-prefixed JSON with duplicate-key, depth, schema, and deadline checks. Identity-widening request fields are rejected. Oversized generated responses return a bounded error; malformed or poisoned channels close.

State and backup decoding enforce strict schemas, bounds, and cross-record invariants. Unsupported schemas and unknown fields are rejected.

Offline backup writes only to a validated, empty private regular file or private pipe through an explicit descriptor. Output cannot alias an input resource. Offline administration stdout is not a backup or plaintext-export channel. MCP stdout carries only protocol messages and approved nonsecret metadata; it never returns credential secret fields. Authorized human secret reads use the separate private administration channel. Invalid JSON, unsupported methods, and errors must not echo credential or attachment input. Seed and backup-secret text inputs are capped at 4096 bytes, identity at 64 KiB, and encrypted backup input at 32 MiB.

## Backup and recovery

Encrypted backups support a seed or a separate passphrase. The destination store seed can differ from the backup secret. Restore validates the entire backup before publication, refuses an existing destination image, revokes previous tasks and grants, and requires fresh approval.

Explicit recovery requires human context, matching scope, the seed, and valid retained encrypted evidence. Recovery revokes authority and resolves unfinished delivery outcomes conservatively. Tests with crafted journals and injected publication failures do not reproduce arbitrary disk failure or power loss.

Keep encrypted backups and their secrets separate. An administrative recovery command does not recover a lost seed or authenticate the human who supplied JSON identity labels. Those responsibilities remain with the trusted integration.

## Remaining limits

The worker launcher checks a reviewed sandbox path, not arbitrary host-capable agents. Memory, PID, CPU, and tmpfs quotas are not enforced per worker. The runtime does not protect against a compromised host account or kernel, a replaced binary, storage deletion or rollback, or copies made after authorized disclosure. Audit events are bounded records, not a tamper-evident log.

Verification uses synthetic credentials, isolated homes, and private loopback HTTPS endpoints. Installed-client diagnostics establish connection and discovery only; they do not establish model-driven credential workflows or production-provider integration.

## Reporting a security issue

Do not include seeds, passwords, vault images, or other credentials in a public report. Provide a minimal reproduction with synthetic data and identify the operating system, filesystem, supervisor, worker boundary, and affected request path.
