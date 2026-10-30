# Specialist review of the vault-first design

Status: both read-only reviews received and source-checked against baseline `510c2a0`, before the first implementation slice. The [implementation status](IMPLEMENTATION-STATUS.md) records subsequent fixes and tests. This reviewed proposal is not an implemented agent vault or a security certification; no repository execution occurred in the design-review phase.

## Conclusion

Keep the credential-vault product direction. Build records, user ownership and scoped sharing, rather than a provider-operation execution framework. The first implementation must establish safe persistence and schema compatibility before exposing an agent API.

Backend Engineer reviewed storage/API/type boundaries. Security Engineer independently reviewed identity, authorization, delivery and lifecycle risks. The caller read both reports, checked that their source/design inputs were unchanged, and inspected the principal persistence/import findings directly.

## Confirmed source observations

These are properties of the then-current terminal prototype at `510c2a0`, not the refactored application. The source paths below are historical citations; those prototype modules are now removed. The earlier import-compatibility recommendation is superseded by the [agent-first decisions](DECISIONS.md). Missing functionality was a readiness gap, not proof of a vulnerability in a deployed service.

| Finding | Source evidence | Required change before agent exposure |
|---|---|---|
| Replacement removes the existing vault before deriving/saving its successor. Failure can leave no prior vault at that path. | `src/vault.rs`:277–302 | Stage and commit replacement without deleting the last usable vault first; test failures before and after replacement. |
| Normal save syncs its temporary file and renames it, with no parent-directory sync in that function. Power-loss durability is not established by the rename alone. | `src/vault.rs`:217–232 | Define target-platform durability, recovery and ambiguous post-replacement outcomes. Do not blindly restore old in-memory state after an uncertain durable commit. |
| Mutation and success semantics differ between clients. CLI prints update success before persist; TUI deletion stays removed in memory after failed persist, and dirty state is retried on exit. | `src/cli.rs`:810–812; `src/tui/app.rs`:539–545; `src/tui/mod.rs`:62–65 | One staged commit boundary, with success only after the required persistence step and explicit recovery on failure. |
| Inner schema validation does not reject a new data version. Vault and backup formats have separate outer-version rejection paths. | `src/validation.rs`:77–109; `src/vault.rs`:172–175; `src/backup.rs`:147–159 | Guard both vault and backup formats when introducing richer fields. Preserve v1 import/recovery through reviewed copy migration, not writable legacy compatibility. |
| Existing imports replace the payload wholesale or overwrite entries with matching IDs. Public mutable vault state bypasses a future application boundary. | `src/cli.rs`:959–964; `src/backup.rs`:216–224; `src/vault.rs`:261–268 | Route every writer, including import/restore and CLI/TUI, through record/revision/permission invariants. Never merge new ACLs using a legacy entry overwrite. |

Plaintext-bearing `Entry` Debug/serialization and intentional human password output must also stay separate from agent DTOs and logs. This is a boundary requirement, not a claim that an existing service log was observed leaking secrets.

## Application contract to carry forward

- **Create:** authenticate the principal and its user-authorized task/workspace/service scope. Commit the record and scoped request/result association together. Repeating an identical create ID returns its committed result; reusing it with changed input conflicts.
- **Update:** use an exact record ID and expected revision with a typed field patch. Secret writes cannot change user ownership, service origin, destinations or grants. Reported account outcomes remain distinct from verified ones.
- **Share:** bind recipient, record, field subset, access mode, expiry, destination and active-version policy. Require user authority. Delegation is off by default; choose parent/descendant grant semantics before enabling it.
- **Use/read:** filter metadata before presentation; `secret.use` returns only a verified private-adapter receipt. An unsupported private path requires interaction, never implicit plaintext fallback. `secret.read` is an explicitly approved disclosure mode.
- **Revoke:** commit before acknowledging success and serialize new access authorization against revocation. Define the authorization/handoff point and treatment of queued/in-flight work. Already dispatched/delivered material cannot be recalled; unknown outcomes cannot be blindly replayed.

Keep records, grants and create-deduplication results in one application-owned commit for the first local payload design. Secret-bearing internal types are not public responses. Stage candidate state, validate it, persist it, then publish successful memory/results; handle uncertain durability separately from a confirmed pre-commit failure.

## Unresolved security decisions

1. Enforced workload isolation and authenticated enrollment, distinct from same-login bot names and the human administration channel.
2. Trusted user/task approval provenance, including precisely who can approve sharing and plaintext reads.
3. Destination integrity for the first adapter, including approved-origin interpretation, redirects/frames and unsupported-delivery behavior. No existing private adapter capability is assumed.
4. Revocation/expiry linearization, clock behavior, child-grant dependency, active versus historical secret versions and in-flight delivery policy.
5. Durable signup status, cancellation/retention and reconciliation, including human email/MFA steps and preservation of credentials after unknown external outcomes.

These remain design choices. The reviews do not authorize provisioning or silently choose the user's isolation model.

## Revised implementation order

1. After implementation/toolchain authorization, establish an isolated Rust test baseline with synthetic vaults only.
2. Fix and fault-test replacement, rollback, post-commit acknowledgements and recovery.
3. Add outer vault/backup schema guards and explicit copy migration tests.
4. Extract the application owner; add records, grants, revisions and durable scoped idempotency. Route all writers through it.
5. Prove two-principal create/deny/share/use-or-read/revoke behavior, expiry, stale/concurrent updates, scope-widening denial and restart handling.
6. Prove the first private adapter and mocked signup outcomes, including redaction and unknown-result reconciliation.
7. Verify actual workload/admin separation before exposing the service to real agents or credentials.

Provider-action brokering, remote sync and OAuth/session automation remain separate future scope.

## Evidence and limits

Full reports are retained privately outside the project and setup Git:

- Backend: `/home/nick/.hermes/profiles/backend-engineer/engineering/credman-vault-design-20261024-v1/review.md`, task `credman-vault-design-20261024-backend-v1`.
- Security: `/home/nick/.hermes/profiles/security-engineer/engineering/credman-vault-design-20261024-v1/review.md`, task `credman-vault-design-20261024-security-v1`.

The [review verification receipt](specialist-review-verification.json) binds both exact artifacts and input hashes. The earlier synthetic bot acceptance checks establish that the specialists executed their fixtures; they do not prove the real storage, crypto, grants, private delivery or OS boundary. Public-source evidence from the original design remains separate and was not re-fetched by these reviews.
