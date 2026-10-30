# Implementation gates for the agent-native broker

Status: plan only. The user authorized design work, not installation, implementation, provisioning, or migration. None of the tests below has run. Passing source/citation checks is not a substitute for these gates.

## Gate 0: approve the product and trust boundary

Before implementation, select:

- The first provider and one read-only credential-backed operation. `repository.read_metadata.v1` is an illustrative candidate, not a chosen provider integration.
- The Linux workload isolation and enrollment mechanism, including a human administration identity that agents cannot impersonate.
- Human unlock and approval UX, session/approval expiry policy, and the result-retention policy.
- Existing-vault and CLI/TUI compatibility requirements.

Reject a deployment that merely assigns different bot names to processes under the approving human's login. Reject a first slice that requires an arbitrary URL, raw credential read, generic shell, or unconstrained signing operation.

Deliverable: an approved operation/binding contract and deployable identity model. No real credentials are needed for this decision.

## Gate 1: establish a safe baseline

Only after the user authorizes a build environment:

1. Provision the selected Rust toolchain without changing unrelated Hermes dependencies.
2. Inspect all tests for home-directory, terminal, clipboard, USB, and relative-path side effects.
3. Run the existing suite against an isolated source/work directory and disposable vault data. Prevent fallback to a real home vault or inherited credential environment. Do not assume that changing the command's working directory alone changes Cargo's test working directory.
4. Record exact toolchain/dependency versions, commands, results, and any environment-specific tests that cannot run.
5. Add failure-reproduction tests for storage extraction risks before changing their behavior. In particular, replacing a disposable vault must preserve the previous file if validation, derivation, or persistence fails.

Deliverable: a real baseline, not a guessed test count. Rust/Cargo were unavailable and no installation was allowed in the design phase, so this gate is currently open.

## Gate 2: extract one application owner without changing crypto

Keep the current encrypted envelope, stored KDF parameters, normalized mnemonic derivation, and recovery semantics. Make raw vault/session/key fields private. Separate stored-record serialization from agent-visible DTOs and redact secret-bearing debug paths.

Move entry validation, mutation, and commit behavior behind one application boundary. Migrate one human caller at a time and delete duplicate mutation paths after callers move. Define failure/rollback semantics explicitly rather than inheriting the current differences between CLI and TUI.

Required evidence:

- Existing vault and backup round trips still pass using synthetic fixtures, including non-default valid header KDF parameters.
- Wrong-key, corrupt/truncated/oversized data, unsupported-version behavior, and private-file permissions are covered.
- Concurrent sessions cannot bypass the lock or silently overwrite one another.
- Mutation failures preserve the documented file and in-memory state.
- Agent DTOs cannot serialize stored entries or keys. Secret sentinels do not appear in their errors or debug output.
- Human reveal/clipboard behavior is tested separately; it is intentionally not an agent API.

Deliverable: a verified internal boundary with no new agent authority or network behavior yet.

## Gate 3: implement the locked local service and control planes

Implement the proposed service under a protected identity. Start locked. Separate workload and administration endpoint dispatch, with bounded parsing and authenticated context construction outside payload deserialization.

Keep one owner for session/vault state and transactional authorization/journal updates. Treat the policy store, operation registry, and vault format as separately versioned components. Never store the unlock seed for unattended restart.

Required evidence from actual isolated workloads:

- An agent cannot read vault/key/policy files, inspect broker secrets, alter broker code/configuration, or connect to the administration channel.
- A forged agent name/PID is not another principal. Two same-UID processes are deliberately treated as the same OS principal, not falsely isolated personas.
- Human unlock does not create agent authority. Wrong-role, malformed, oversized, and unknown-version messages fail safely.
- A restart begins locked and invalidates session-bound authority. Lock/revoke behavior follows the documented dispatch checkpoint.
- Revocation/expiry/use-limit updates survive concurrent requests without counter races. Network execution does not hold the state owner's global lock for the request duration.

Deliverable: a tested containment and authorization boundary. A systemd unit file or passing in-process unit test alone does not meet this gate.

## Gate 4: prove one typed operation with synthetic credentials

Implement a fixed provider binding and compiled operation schema. No generic authenticated HTTP or arbitrary-command escape hatch is permitted. Approvals bind the effective principal, normalized arguments, operation/binding revisions, and grant/session epoch.

Use a disposable mock provider and a synthetic secret sentinel before any real account:

- One approved operation succeeds and returns only its safe schema.
- Unapproved resources, changed arguments, expired/revoked approvals, reused IDs with changed input, and stale binding revisions are denied before credential use.
- Redirects, environment proxies, DNS/address changes, unauthorized ports/origins, path/query ambiguity, header injection, and response-size/time limits cannot redirect authority.
- Provider bodies, headers, cookies, errors, or malformed responses that echo the sentinel do not enter agent-visible output or audit. Record the limits of this check rather than claiming a universal secret detector.
- Audit/journal failure before dispatch prevents execution. A failure after possible provider acceptance is not reported as proof that no action happened.
- Concurrent use cannot exceed the grant. A lost/ambiguous response produces `OutcomeUnknown`, not an automatic replay or refunded use.
- Result retrieval requires its own current ownership/policy check and cannot restart execution. Define how expiry/revocation affects receipt access.

Deliverable: an actual disposable end-to-end operation, including negative and crash/timeout cases.

## Gate 5: migrate human clients and vault ownership

First test against copied synthetic vaults. Require a maintenance window for an explicitly approved real migration later. Retain an encrypted backup and verify it before changing authoritative ownership or location.

While the broker owns the vault, human CLI/TUI commands use its administration boundary. An unavailable broker does not trigger a second writable-file fallback. Offline maintenance requires the broker to stop/quiesce, the correct privileged human context, and the existing lock.

Required evidence:

- CLI, TUI, and service cannot become parallel writers.
- Interrupted migration/restore cannot remove the last usable vault or backup.
- Original vault/recovery compatibility remains documented and tested. Any necessary format change has an explicit versioned migration and rollback plan.
- Reveal/export and USB setup remain human administration. Agents cannot use a portable USB binary, old direct-access path, or backup endpoint to bypass broker policy.

Deliverable: a tested migration plan. No real vault is read or migrated automatically by this design document.

## Gate 6: add client adapters, then review release authority

Add the noninteractive JSON client and, if useful, a thin Hermes/MCP adapter over the proven broker. Neither adapter gets credential values or becomes a second authorization owner. Do not create a remote OAuth/network service as incidental scope.

Before a release or push, require:

- Stable bounded request/result/error contracts, safe defaults, and no TTY prompts on the agent path.
- End-to-end checks through the real adapter from the intended isolated workload identity.
- Adversarial security review and QA on the exact changes, with failures and unverified cases visible.
- Updated security/recovery/operations documentation that distinguishes implemented guarantees from proposals and OS-compromise limits.
- Separate user approval for installation, account provisioning, service activation, real credential use, and real migration.

A raw-secret API, successful demo under one shared UID, or mock-only MCP test does not satisfy the selected product goal.
