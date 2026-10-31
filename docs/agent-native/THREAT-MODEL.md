# Threat model

Credman protects user-owned credentials while supervised agents share scoped access and use approved HTTPS consumers. This model covers the Linux owner, Unix-socket sessions, MCP frontends, encrypted storage, and private human administration.

## Assets

Protected assets include the root seed, derived keys, credential values, sensitive metadata, session tokens, task approvals, grants, revisions, retry receipts, delivery journals, and audit events.

## Trusted components

The supervisor controls task approval, principal assignment, destination configuration, and private human channels. The host account, kernel, executable, toolchain, and approved consumer are trusted. Seed possession together with encrypted state permits offline access. An approved consumer receives authorized credential values by design.

A host-capable agent sharing the human's Unix UID is a trusted host operator. The runtime does not isolate such an agent from readable session files, process memory, or administration resources. Deployments requiring hostile-worker isolation must enforce that boundary in their launcher.

## Agent capabilities and controls

| Attempt | Enforced control |
|---------|------------------|
| Guess a record or task ID | IDs convey no authority; requests use the authenticated channel context |
| Forge a principal, owner, workspace, or administrator claim | Request schemas reject identity fields; the owner binds context before requests |
| Read an unshared record | Task permissions and current field-scoped grants are required |
| Extract credentials through MCP | Tools return metadata, references, and receipts; plaintext reads are confined to private human administration |
| Widen a share or re-share without approval | Issuer sharing bounds constrain recipient, fields, permissions, destinations, and expiry |
| Reuse a revoked, expired, or changed credential grant | Current authority and pinned value versions are checked, including cached requests |
| Reuse an attachment credential | Tokens attach once, expire within the owner lifetime, and are revocable |
| Redirect a secret to another consumer | The supervisor configures the fixed HTTPS URL and authentication scheme; redirects and proxies are disabled |
| Smuggle commands or headers through credential values | Values are validated and escaped for a fixed curl invocation using private stdin |
| Replay an uncertain delivery | Durable attempt journals retain outcomes without automatic redispatch |
| Submit malformed or oversized data | Bounded strict decoding rejects duplicate keys, unknown fields, invalid lengths, and excessive depth |
| Exploit ambiguous storage publication | The owner freezes access and requires explicit human recovery |
| Restore stale task authority | Restore and recovery revoke retained approvals and grants |

## Persistence and disclosure boundaries

Records and access-control state are persisted together inside authenticated encrypted snapshots. Unique private temporary files, file sync, atomic publication, and directory sync define the local-filesystem commit boundary. Header version 3 authenticates the store header as associated data. A clock-only advance under 60 seconds can remain unpersisted; after a restart, detection of that high-water is coarse by up to 60 seconds. Receipts and completed deliveries older than 24 hours may be compacted. A retried request ID then runs as new work and still requires current authorization. Recovery uses validated retained evidence and does not silently reuse stale in-memory authority.

Private use rechecks task, grant, and attached-session expiry immediately before the delivery callback, after durable intent publication. Revocation orders subsequent access through the single owner. It cannot recall values already delivered or undo an external action.

An explicit human `SecretRead` is disclosure. The authorized recipient can copy the value. Audit entries exclude credential content but are bounded and are not tamper-evident against host administrators.

## Validation requirements

- Unshared records, forged identities, widened grants, stale revisions, revoked tasks, expired sessions, and pinned-version mismatches fail.
- Generated credentials remain absent from MCP responses, errors, audit entries, and persisted plaintext files.
- Basic and Bearer delivery reach only the configured verified-TLS endpoint. Invalid certificates and redirects do not disclose credentials to another endpoint.
- Cached successful requests require current authority. That cache is idempotent for 24 hours. After compaction, the same request ID is new work and still requires current authorization. Uncertain delivery and lost replies do not cause automatic redispatch.
- Corrupt snapshots and backups fail closed. Publication faults preserve recovery evidence, and human recovery settles incomplete attempts conservatively.
- Restored records remain accessible only after fresh task approval and grants. Offline administration closes unrelated inherited descriptors.

The [verification commands](../../README.md#verify) exercise these paths with synthetic data. They do not prove hostile-host safety, cryptographic correctness, storage rollback resistance, power-loss behavior, or per-worker resource limits. See [security](../../SECURITY.md) for operational constraints.
