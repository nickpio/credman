# Threat model for the agent credential vault

Status: design threat model and proposed acceptance criteria, not blanket implemented guarantees. The [current runtime reference](AGENT-RUNTIME.md) identifies tested synthetic boundaries and unimplemented production protections. The [first storage slice](IMPLEMENTATION-STATUS.md) is historical evidence limited to its original source and checks. Neither document certifies power-loss durability, hostile same-UID isolation, or production migration safety.

## What is protected

Credential values, sensitive account metadata, user ownership, and record access grants are protected assets. A malicious or compromised agent, prompt injection, an unrelated local process, or an accidental log must not gain broader access than the user authorized.

The vault process is trusted with unlocked material. A compromised vault service, privileged host, or administration identity defeats this local policy boundary. The design does not protect a credential from a website that legitimately receives it, or from an authorized consumer after plaintext disclosure.

## Identity and permissions

Authenticate the consumer through an enforced workload/runtime boundary. An `agent_name` or credential reference in a message is not proof of identity or permission. Linux peer credentials identify the connected process, not a model persona.[5] Current agents sharing the human's login need a real isolation change before per-agent policy can be claimed.

Separate user administration from agent access. Human unlock is not an all-agents grant. An agent cannot approve its own sharing escalation or claim user intent merely by describing a task. Bound create/write/use rights to the authorized task, workspace and service. Grants have explicit recipients, fields, permissions, expiry, and delegation limits. A delegate cannot amplify rights or re-share by default.

## Sharing and secret delivery

Share references and grants, not plaintext chat messages or duplicate secret exports. Metadata listing is also access-controlled. Secret field changes must not modify approved origins or widen recipient permissions implicitly.

Private tool/browser injection is preferred, but requires a real adapter outside ordinary model-visible tool responses. MCP's stdio transport is not a sandbox and its local peers share a trust domain.[1] Its authorization specification covers HTTP-based transports; it does not establish per-record permissions or secret-safe delivery for this application.[7]

An explicit `secret.read` permission is a disclosure boundary. A recipient can copy the value. Vault grant expiry/revocation stops future retrieval, not use of a copied static password. Vault's lease documentation likewise distinguishes leased credentials from arbitrary key-value secrets, which do not issue leases.[3] Upstream invalidation needs actual rotation/revocation; local deletion is not account deletion.

## Signup lifecycle and data integrity

The account-creation tool is separate from the vault. Persist generated credentials before submitting a signup when supported. If the external outcome is uncertain, retain the credential and mark the outcome unknown. Do not lose the only password, invent a verified login status, or create duplicate accounts automatically. Human email/MFA steps remain explicit.

Serialize record/grant mutations through one owner, use expected revisions for updates, and make credential creation idempotent within a scoped task/request ID. A metadata update cannot overwrite a newer secret or expand an ACL. Secret and permission commits need defined failure behavior; never publish a successful share before persistence succeeds.

Keep encrypted fields and sensitive metadata out of plaintext policy sidecars, logs, debug output and ordinary agent responses. Audit actor, opaque record/grant ID, action, decision and safe outcome only. Do not log request bodies or secret values. Ciphertext, temporary files, service storage and migration backups retain private permissions and crash-safe writes.

## Required negative checks before release

- Agent B cannot discover/read/use Agent A's unshared record, including with a guessed reference or forged name.
- A scoped grant reveals/delivers only its permitted fields and destination; B cannot re-share or expand it.
- Expired/revoked grants and stale revisions fail. Concurrent access cannot bypass a committed revocation or overwrite a newer record.
- Synthetic secrets do not appear in use-path model responses, chat, errors, audit or debug output. An explicitly authorized plaintext-read path is tested as disclosure, not mislabeled hidden injection.
- A malformed/failed tool handoff does not fall back to printing secrets. Untrusted site text cannot authorize broader storage, sharing or signup.
- Failed/ambiguous signup preserves recoverable credentials and honest lifecycle status.
- Old binaries cannot silently save over a richer schema. Interrupted migration and storage failures preserve the last usable vault.
- Actual isolated agent identities cannot read service files/process memory or use the administration channel. Same-user unit tests do not prove this isolation.

The [specialist review](SPECIALIST-REVIEW.md) adds source-checked persistence/import risks and the implementation order. Specify the clock and authorization/handoff point for expiry/revocation, including queued/in-flight uses and descendant grants. A cache hit or matching import ID must not bypass current authority. These are required policy definitions, not new runtime guarantees.

Revocation cannot recall already delivered material or undo an external action. Audit is not tamper-proof against host administrators merely because the vault wrote it. All integration/isolation/schema claims still require implementation evidence.

## Sources

[1] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security
[3] https://developer.hashicorp.com/vault/docs/concepts/lease
[5] https://man7.org/linux/man-pages/man7/unix.7.html
[7] https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
