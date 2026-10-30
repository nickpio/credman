# Threat model for the proposed local credential broker

Status: design requirements, not implemented or verified guarantees. The scope is approved credential use by isolated local agent workloads. Raw secret retrieval, remote hosting, and deployment are outside this phase.

## Trust boundaries

The design has separate roles for the human administrator, agent workloads, the broker, and credential recipients. Running the broker under a different account addresses only part of that separation. Agents must not inherit the human administrator's authority or be able to alter broker policy, replace its binary, or use its approval interface.

Existing same-login Hermes profiles are not distinct authenticated security principals. The deployment design must supply a real workload boundary before it can claim isolation between an agent and the human. A self-reported `agent_name`, tool description, model instruction, or profile path is not authority.

The broker is trusted with plaintext credential material while unlocked. Compromise of the broker, its administrator, or the host's privileged control remains outside the proposed agent-policy boundary. Encryption at rest does not protect an unlocked process from an actor that can inspect or replace that process.

An approved provider receives the credential or a credential-derived proof as required by its protocol. The promise is not that credentials never leave the broker. The design aims to keep raw credentials out of agent-facing APIs, tool transcripts, and logs while restricting where and how they are used.

## Protocol and credential-lifetime boundaries

Linux `SO_PEERCRED` reports the credentials of the connected peer process.[5] The broker must map that authenticated OS boundary to a principal. An agent persona label does not create a different OS identity.

MCP's local-server guidance states that a client and stdio server share a trust domain and that stdio is not a sandbox.[1] The authorization specification defines the authorization flow for HTTP-based transports.[7] An MCP adapter can carry requests, but it is not the workload isolation or application-grant policy described here.

A local expiry timer cannot make an already disclosed static password disappear from the recipient. Vault's lease documentation distinguishes leased secrets from arbitrary key-value storage, which does not issue leases.[3] If a later design releases credentials to tools, expiry/revocation claims must name the upstream mechanism rather than imply that a local grant revokes a copied secret.

## Required controls and evidence

| Threat | Required control | Evidence needed before release |
|---|---|---|
| Agent invents an identity or copies another profile label | Derive the principal from an authenticated workload channel, not request metadata. Bind grants to that principal. | A request with a forged name still has the original principal and cannot use another principal's grant. |
| Agent acts as the approving human | Separate agent and administrator identities and control channels. Approval authority cannot be available through the agent's ordinary user privileges. | An agent workload cannot open the administration channel, approve a request, or alter approval policy. |
| Agent reads vault or policy files directly | Broker-owned private storage, protected service code and configuration, and isolated workload permissions. | Negative file-access and process-inspection tests from an actual agent identity. Same-user unit tests are insufficient. |
| Prompt injection requests broader access | Default-deny authorization outside the model. Neither source text nor a provider response can modify a grant. | Malicious repository text and tool output do not change allowed operations, resources, or expiry. |
| Authorized operation is turned into credential forwarding | Broker-owned provider binding and request construction. No caller-selected authenticated destination, auth header, arbitrary shell, or unrestricted proxy. | Cross-origin redirects, path/host substitutions, header injection, and unapproved internal destinations fail before credential use. |
| Response or error reflects credential material | Operation-specific safe output schema. Do not forward raw headers, bodies, or exception objects by default. Treat the provider as a credential recipient, not proof that its response is safe. | A synthetic provider that echoes credentials cannot place them in agent-visible success/error output or audit records. Document the limits of such filtering. |
| Agent retains an obsolete authorization | Expiry, principal binding, bounded uses, revocation, and an authorization check at execution time. | Expired/revoked grants and grants from a previous unlock session cannot start a new operation. |
| Race allows too many uses or bypasses revocation | One owner for mutable grant/session state and atomic authorization/reservation. Define the instant after which an in-flight request cannot be recalled. | Concurrent use and revoke tests enforce the documented policy without promising cancellation of an action already accepted upstream. |
| Retry repeats a side effect | Correlate normalized requests and outcomes. Reject reuse of an ID with different input. Record uncertain outcomes rather than automatically retrying them. | Timeout/crash tests distinguish denied, failed-before-send, complete, and outcome-unknown actions. Exactly-once remote execution is not assumed. |
| Audit becomes another secret store | Record actor, operation, resource reference, approval/grant identifiers, decision, and outcome. Exclude credential values and raw request/response content. | Sentinel secrets are absent from agent output, logs, audit, traces, and panic diagnostics. Do not claim generic redaction can recognize every transformed secret. |
| Concurrent human client overwrites broker state | One vault owner while the service is active. Preserve the existing advisory-lock rule until a reviewed replacement exists. | Concurrent CLI/TUI/service tests cannot silently save over one another. |
| Migration loses recovery or weakens encryption | Preserve existing vault bytes and recovery semantics until compatibility is proven with disposable copies. No automatic destructive conversion. | Round-trip, old-header/KDF, corruption, interruption, rollback, and backup/restore tests. |

## Approval semantics to specify

An approval must identify the effective actor, credential reference, operation, resource constraints, and expiry. If the request has arguments that affect the action, the approval must bind those arguments or explicit allowed bounds. Approving a displayed description is not permission to execute a different request.

The human must see the effective operation after normalization and policy checks, not an agent-supplied summary alone. Decide separately whether an approval permits one operation or a bounded standing grant. Denial, expiry, cancellation, and a locked broker are normal protocol results, not reasons to bypass checks or ask a model to provide the seed.

## Honest limits

- The design does not stop a permitted agent from abusing the business authority of an overly broad approved operation. Operation and resource scope still matter.
- An upstream service or broker compromise may disclose credentials. No claim of universal non-disclosure is made.
- A human or agent with host-administrator powers can defeat ordinary local service isolation. Do not deploy under a privilege arrangement that makes an agent that administrator.
- Audit records are not tamper-proof against a privileged host actor merely because the broker writes them. Stronger integrity and rollback protection need a separately defined trust anchor.
- No exploit, sandbox, authorization, concurrency, or migration test has been executed in this design-only phase.

## Sources

[1] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security
[3] https://developer.hashicorp.com/vault/docs/concepts/lease
[5] https://man7.org/linux/man-pages/man7/unix.7.html
[7] https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
