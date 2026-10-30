# Agent-native Credman design

Status: proposal for review. This phase changes documentation only. No toolchain, broker, account, service, adapter, or vault migration has been installed or implemented.

The user selected brokered credential use, an isolated local service identity, and a design-only phase. [Scope and source findings](DECISIONS.md) record those decisions. [Threat model](THREAT-MODEL.md) defines the required boundary. [Implementation plan](IMPLEMENTATION-PLAN.md) defines the release gates, not completed work.

## Recommendation: expose approved operations, not credentials

Use a local broker that owns the unlocked vault and executes typed operations on behalf of authenticated agent workloads. Start with one provider and a read-only operation. Keep the existing vault encoding during the first extraction.

The agent asks to perform a named operation against an approved resource. It does not supply a password, vault seed, provider URL, HTTP method, authentication header, or shell command. The broker checks authority outside the model, constructs the provider request, and returns a bounded safe result.

Unlocking and approval are separate. A human unlock makes credential material available to the broker. It does not authorize an agent to use it.

## Caller experience

The following is illustrative protocol pseudocode, not an existing command or stable wire specification:

```text
agent.submit({
	protocol_version: 1,
	request_id: opaque_request_id,
	operation: "repository.read_metadata.v1",
	resource: "approved-repository"
})
→ ApprovalRequired { request_id, broker_derived_summary }

human_admin.approve(request_id, single_use_bounds)
→ Approved { approval_id, expiry }

agent.result(request_id)
→ Completed { repository_id, visibility, default_branch }
```

An operator binds `approved-repository` to a credential entry UUID, fixed provider, endpoint, and provider resource. The example does not select GitHub, Forgejo, or another service for implementation. That product decision is still open.

`agent.result` is authenticated and authorized too. Knowing another principal's request ID is not permission to read its result. Unlock, enrollment, approvals, reveal/export, backup, restore, and USB setup do not appear in the workload operation registry.

## Agent-first contract

The client is noninteractive and schema-driven. Expose the operations that the authenticated principal may request, not a credential inventory. Use exact operation/resource IDs and versions, never fuzzy credential lookup on the machine path.

Return structured states such as `locked`, `approval_required`, `queued`, `running`, `completed`, `failed_before_dispatch`, and `outcome_unknown`, with stable bounded error codes. The client must not start a TUI, prompt for a seed, print a credential, or report queued work as complete. Separate request/receipt retrieval from permission to execute again.

Result access needs a current principal/ownership check and an explicit receipt-read policy, including expiry/revocation behavior. A consumed single-use execution approval must not cause a status query to execute the operation a second time.

Safe result schemas limit data shape and disclosure. Provider-supplied strings remain untrusted content and cannot authorize another operation, widen a grant, or supply instructions to the control plane.

## The architecture comparison

Two independently developed candidates were compared against the existing code and selected trust boundary.

| Criterion | A: declarative HTTP broker | B: compiled typed-operation broker |
|---|---|---|
| Authority definition | Reviewed request templates, argument constraints, credential injection, and response projections | Reviewed operation input/result types and provider adapter code |
| Extension cost | Add a declarative operation after policy review | Add adapter code and operation-specific tests |
| Central risk | Template compiler and transformation language become security-critical | Adapter code and its approved business authority become security-critical |
| Safe client surface | Operation IDs only; no raw authenticated HTTP | Operation IDs only; no raw authenticated HTTP |
| Initial scope | Requires careful URL, path, query, body, and transformation rules even for one service | Can support one narrow action without a general transformation language |
| Decision | Do not build a generic request DSL for v1 | Recommended first implementation |

Both candidates need the same identity, approval, ownership, and audit boundary. An unrestricted authenticated HTTP proxy is rejected, not offered as a shortcut. A future declarative format may be considered only after repeated adapter requirements justify it and its compiler can be tested as a security boundary.

Provider-scoped short-lived credential delivery is a different alternative. It improves compatibility with existing tools but gives recipients material they can copy. It is not the selected v1 default. A local lease cannot revoke an exported static password without an upstream revocation mechanism. The [threat model](THREAT-MODEL.md) records the primary-source evidence and limits.

## Identities and local transport

Propose Linux-first local Unix sockets with separate workload and administration endpoints. Their exact installation paths and account names remain deployment decisions.

- The broker runs under a protected service identity that owns the authoritative vault, policy, and journal.
- Agents run in enforced workload boundaries separate from that broker and from the human administrator.
- The human administration channel is unavailable to agent workloads. A second socket or interactive prompt is not enough if the agent has the same authority as the human.
- The server derives the principal from authenticated transport credentials and a protected enrollment record. It never trusts a request's `agent_name` or PID as an independent persona identity.
- In an initial UID-based design, the isolated workload UID is the security principal. Two processes with that UID share authority. Enrollment revision and broker session epoch bind grants; claimed run IDs do not create isolation. A UID must not be reused without retiring its enrollment and grants.

Current same-login Hermes profiles do not satisfy the selected isolation goal. Moving only the broker to a different account protects some storage, but does not stop an agent from using a human administration channel available to their shared login. Deployment must resolve this before the service can claim hostile-agent isolation.

A versioned, bounded JSON client interface can support an agent-agnostic CLI. An optional Hermes/MCP adapter is a thin client of the broker, not another vault owner or policy engine. Adapter authentication material is not a provider credential and must never be forwarded upstream. MCP does not replace OS isolation or application authorization. Remote HTTP hosting and a custom OAuth service are outside v1.

## Authority types

Illustrative types explain ownership and invariants. They are not implemented Rust APIs:

```text
Principal = verified workload identity + enrollment revision

OperationSpec<Input, SafeOutput> =
	operation ID + version + input schema + resource rules + adapter

Binding =
	opaque resource ID + provider resource + fixed endpoint + credential UUID

Grant =
	principal + operation revision + binding revision + argument bounds
	+ expiry + maximum uses + policy generation + unlock epoch

Approval =
	verified human + principal + normalized request digest
	+ exact grant revision + expiry + single-use decision

AuthorizedExecution = broker-private committed permit

submit(AuthenticatedPeer, OperationRequest) -> RequestState
approve(AuthenticatedAdmin, RequestId, Bounds) -> ApprovalReceipt
revoke(AuthenticatedAdmin, GrantId) -> RevocationReceipt
result(AuthenticatedPeer, RequestId) -> SafeResult
```

Use one compiled registry to derive operation schemas, dispatch, policy descriptors, and safe result validation. Reject unknown fields and unsupported versions. An agent cannot define or replace operation specifications, bindings, credential destinations, or grant bounds.

Start with explicit single-use approval. Bounded standing grants are a separately reviewed extension. Every grant/session needs an expiry; no default unlimited unlock or authority. The precise timeout policy is still an operator/product decision.

## One owner for mutable state

One broker state owner serializes vault mutations and authorization transitions. It owns the `UnlockedVault`, session epoch, enrollment/binding revisions, grant reservations, approvals, and request journal. Do not split write authority across a policy manager, UI, and transport handler.

Provider execution happens outside the state owner's network-duration critical section. A bounded internal worker receives only the material needed for an already committed operation and returns a typed outcome to the owner. It does not update grants, reopen the vault, or make its own authorization decisions. Credential copies and HTTP-library buffers remain inside the trusted broker process and have bounded lifetimes. Zeroization is best effort, not protection from broker compromise.

Proposed module map:

```text
src/lib.rs                    narrow application/client exports
src/crypto.rs                 existing crypto, private to vault boundary
src/vault.rs                  private file/session primitives
src/model.rs                  private stored records, not wire DTOs
src/validation.rs             existing data validation
src/broker/state.rs           sole mutable-state and transaction owner
src/broker/operations.rs      compiled operation registry and DTOs
src/broker/providers/          fixed provider request/response adapters
src/broker/executor.rs        bounded execution; no policy/state writes
src/broker/protocol.rs        versioned workload messages and safe errors
src/broker/local.rs           peer authentication and endpoint dispatch
src/broker/store.rs           private transactional policy/request journal
src/bin/credmand.rs           proposed locked-by-default service entry
src/cli.rs, src/tui/           human presentation and administration clients
```

The application API must hide vault keys, raw `Entry` values, and `AuthorizedExecution` construction from ordinary clients. Rust module privacy reduces accidental misuse; OS authorization is still the security control against a client that supplies its own executable.

A transactional local store for policy, use reservations, and the request journal is preferable to hand-maintained JSON counters. SQLite is the proposed store, subject to dependency review when implementation is authorized. It contains private metadata, not upstream credential values. The encrypted vault format, policy-store schema, and execution protocol have independent versions.

## Operation lifecycle

1. Authenticate the workload, parse a bounded request, and resolve the exact operation and binding revisions.
2. Normalize arguments and evaluate policy. Return a safe denial, locked state, or approval-required state without prompting the model for a seed.
3. Obtain a matching human approval through the separate control path.
4. Atomically reserve the permitted use and persist a dispatch-intent record before releasing an internal execution permit. If the required journal/audit write fails, do not dispatch.
5. Construct and send the fixed provider request. Disable redirects and environment-proxy inheritance by default. Enforce reviewed endpoint, egress, time, response-size, and concurrency bounds.
6. Validate and project the result. Never forward arbitrary provider bodies, headers, cookies, debug objects, or error strings to the agent.
7. Persist a safe outcome. If dispatch may have reached the provider but completion is uncertain, record `OutcomeUnknown`. Do not refund the use or blindly replay the action.

Deduplication binds a request ID to principal, operation/binding revisions, and normalized input. Reusing an ID with changed input fails. Use provider idempotency only where the provider actually supports it. Keep deduplication tombstones for a defined retention period; do not promise exactly-once upstream execution.

Revocation blocks future dispatch commits and uncommitted queued work. An operation becomes in flight at its dispatch-commit checkpoint; a later revoke cannot promise to recall it, even if network transmission has not completed. Best-effort cancellation is additional behavior, not a stronger guarantee.

A lock request stops new dispatch and invalidates grants. Report `Locking` while bounded in-flight work releases credential buffers; report `Locked` only after the session owner and managed execution material have been released. Do not promise that an already accepted remote action is undone or that every library/OS memory copy is instantly erased.

## Human migration and exclusions

Preserve existing encrypted vault bytes and recovery semantics first. While the service is active, CLI/TUI clients cooperate through the one vault owner. Do not add a fallback that silently opens a second writable copy when broker access fails.

Offline human maintenance requires a stopped/quiesced broker and the existing exclusive lock. Credential reveal/export remains a human-only administrative action. Existing USB preparation/launch helpers are not workload authentication and must not expose the broker's authoritative vault or privileged executable to agents.

Defer raw-secret export to agents, arbitrary authenticated HTTP, arbitrary command execution with secret environment variables, unconstrained signing, provider-side credential issuance/rotation, browser login automation, remote hosting, and unattended unlock. None is needed to prove one approved credential-backed operation.

## Verification status

Completed in this phase: repository/source inspection, comparison of two architecture candidates, and independent retrieval/quote checks for the cited security boundary sources. Changes are confined to this design folder and a link from the root README.

Not completed: Rust build/test baseline, broker execution, agent isolation, approval enforcement, migration, secret-sentinel tests, or deployment. Rust/Cargo are unavailable in this session and the user explicitly declined installation for this phase. The [implementation plan](IMPLEMENTATION-PLAN.md) keeps those gates open.
