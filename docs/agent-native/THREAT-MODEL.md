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
| Reuse a revoked, expired, or changed credential grant | Current authority is rechecked, including cached requests. Pinned grants match one secret version; `follow_active` grants allow later versions. Metadata edits do not rotate the secret version |
| Reuse an attachment credential | Tokens attach once, expire within the owner lifetime, and are revocable |
| Redirect a secret to another consumer | The supervisor configures the fixed HTTPS URL and authentication scheme; redirects and proxies are disabled |
| Smuggle commands or headers through credential values | Values are validated and escaped for a fixed curl invocation using private stdin |
| Replay an uncertain delivery | Durable attempt journals retain outcomes without automatic redispatch |
| Submit malformed or oversized data | Bounded strict decoding rejects duplicate keys, unknown fields, invalid lengths, and excessive depth |
| Exploit ambiguous storage publication | The owner freezes access and requires explicit human recovery |
| Restore stale task authority | Restore and recovery revoke retained approvals and grants |

## Persistence and disclosure boundaries

Records and access-control state are persisted together inside authenticated encrypted snapshots. Unique private temporary files, file sync, atomic publication, and directory sync define the local-filesystem commit boundary. Recovery uses validated retained evidence and does not silently reuse stale in-memory authority.

Private use rechecks task, grant, and attached-session expiry immediately before the delivery callback, after durable intent publication. Revocation orders subsequent access through the single owner. It cannot recall values already delivered or undo an external action.

An explicit human `SecretRead` is disclosure. The authorized recipient can copy the value. Audit entries record the acting principal and time, exclude credential content, and are bounded rather than tamper-evident against host administrators.

## Validation requirements

- Unshared records, forged identities, widened grants, stale revisions, revoked tasks, expired sessions, and secret-version mismatches on pinned grants fail. `follow_active` grants survive secret rotation and still honor recipient, field, permission, destination, and expiry bounds.
- Generated credentials remain absent from MCP responses, errors, audit entries, and persisted plaintext files.
- Basic, Bearer, header, and query delivery reach only the configured verified-TLS endpoint. Invalid certificates and redirects do not disclose credentials to another endpoint. Query parameters are part of that destination URL and are not placed in process arguments.
- Cached successful requests require current authority. Uncertain delivery and lost replies do not cause automatic redispatch.
- Corrupt snapshots and backups fail closed. Publication faults preserve recovery evidence, and human recovery settles incomplete attempts conservatively.
- Restored records remain accessible only after fresh task approval and grants. Offline administration closes unrelated inherited descriptors.

The [verification commands](../../README.md#verify) exercise these paths with synthetic data. They do not prove hostile-host safety, cryptographic correctness, storage rollback resistance, power-loss behavior, or per-worker resource limits. See [security](../../SECURITY.md) for operational constraints.
