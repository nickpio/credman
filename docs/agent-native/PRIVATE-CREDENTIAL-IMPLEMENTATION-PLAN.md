# Private credential implementation plan

## Outcome

Agent A generates or receives a privately imported credential, grants Agent B scoped use, and gives B only its record reference. B authenticates to a human-approved HTTPS endpoint without receiving the secret in model context, messages, tool results, errors, or audit output.

Preserve the existing single durable owner, encrypted records, task approvals, version-pinned grants, revocation, sessions, backup, restore, and recovery. Do not replace the vault with a provider-action broker. Existing OpenCode runtime-discovery uncertainty is separate work.

## Delegation policy

Plan each part before dispatch. Each handoff names its data contract, owned files, dependencies, permitted actions, acceptance checks, and configured model route. Use a strong coding/reasoning route for secret handling and an independent strong route for security review. Use a lighter capable route for bounded fixture or documentation work only when that configured route is suitable. Never invent provider/model IDs or silently fall back to the parent while claiming model selection.

Advanced Delegation is installed and enabled in the default Hermes profile. The user selected named model routes. The following routes were validated with the plugin and saved through its supported configuration writer, then read back with `hermes delegation config --show`:

| Route | Provider | Model | Reasoning | Assignment |
|---|---|---|---|---|
| `implementation` | `openai-codex` | `gpt-6.1-sol` | high | Core generation, HTTPS consumer, integration |
| `security-review` | `openai-codex` | `gpt-6-astra` | high | Independent trust-boundary review |
| `qa` | `openai-codex` | `gpt-6.1-terra` | high | Independent acceptance and test fixtures |
| `routine` | `openai-codex` | `gpt-6-luna` | low | Bounded documentation and mechanical edits |

The backend is `model_map`, with `implementation` as the default. These models appeared in the installed Hermes provider/model picker inventory. Assignments reflect task complexity, not measured model benchmarks.

The user also authorized persistent bot-model assignments. Saved defaults were updated through the live `profiles.configure` API and verified with `profiles.describe`:

| Bot | Model |
|---|---|
| Backend Engineer | `gpt-6.1-sol` |
| Security Engineer | `gpt-6-astra` |
| QA Engineer | `gpt-6.1-terra` |
| Researcher | `gpt-6-astra` |
| Analyst | `gpt-6.1-terra` |
| Editor | `gpt-6-luna` |

All use `openai-codex`. Persona, toolsets, skills, MCP settings, other model settings, credentials, and workspace paths were not changed. The main profile's model is unchanged. Configuration readback is not a claim that every existing conversation has replaced a cached runtime override.

The running chat now exposes the per-task `option` selector. Implementation and QA dispatches explicitly select their configured routes. Verify actual route metadata on each completion; an accepted dispatch or saved route is not proof that its model execution succeeded.

The two completed read-only design candidates remain available. Do not repeat that design fan-out. Core generation and the private HTTPS consumer are assigned to separate implementation workers with disjoint source ownership. QA owns the isolated HTTPS fixture and private-flow acceptance source. Integration starts after their API contracts are checked.

## Part 1: Private generation and import (complete)

Owner: Backend core subagent. Model: `implementation` route.

Owned files: `src/agent/mod.rs`, scoped storage APIs, and directly affected snapshot validation or core tests. No unrelated storage-format or cryptography rewrite.

Contract:

- Represent generation as a stable nonsecret request specification, such as credential kind and optional username.
- Authorize and check the existing request cache before drawing OS randomness. Atomically persist the credential and its receipt through the current transaction path.
- Identical requests return the same reference after retry and restart. Changed input with the same UUID conflicts. Cached receipts still require current authority.
- Generated Password or ApiKey values never appear in receipts. Preserve metadata classification explicitly; a supplied username is not treated as a generated secret.
- Private human import must validate administration authority and target task scope. Do not create a model-selected principal or general impersonation API.

Acceptance: private generation returns references only; retries and restart do not create another record or regenerate a cached credential; revoked authority cannot use a cached receipt. Reuse unchanged backup/recovery evidence where valid.

## Part 2: Restricted HTTPS consumer (complete)

Owner: Backend consumer subagent. Model: `implementation` route.

Owned files: one private HTTPS-consumer module and module-local focused checks. Integration declarations belong to Part 3, avoiding concurrent writes.

Preferred first implementation: the installed `/usr/bin/curl` as a fixed private subprocess. Existing Cargo caches have no Rust HTTPS dependency closure. Do not download dependencies or add hand-written libcurl FFI merely to avoid a subprocess.

Contract:

- Human configuration binds a destination ID to a service, exact HTTPS origin and fixed path, Basic or Bearer authentication, and optional explicitly trusted CA material.
- Agent inputs cannot select a URL, command, header, proxy, arbitrary request body, CA file, or redirect target.
- Support a bounded fixed GET operation first. Do not infer registration or verified-login success from a generic HTTP status.
- Prepare the child and private pipes before `use_secret` performs final authorization. The prepared child waits without URL or credentials; the handoff callback supplies the private configuration immediately.
- Use no shell. Put no secret in argv or environment. Disable ambient curl configuration, proxies, redirects, retries, and TLS key logging. Always verify certificate and hostname.
- Check configuration escaping, inherited descriptors, bounded private writes, transfer deadlines, and kill/reap behavior. Discard response body and stderr. Return only strictly parsed, mapped status, never raw library or subprocess diagnostics.
- Preserve unknown delivery outcomes and existing recovery/idempotency behavior. Never blindly resend a possibly dispatched request.

Acceptance: real TLS fixture checks Basic and Bearer authentication; wrong CA or hostname and unapproved destinations cannot disclose credentials; a response that reflects a credential cannot enter model-facing output.

## Part 3: Private agent-facing interface and integration (complete)

Owner: Backend integration subagent, dispatched after Parts 1 and 2 agree on exact APIs. Model: `implementation` route.

Owned files: `src/agent_broker.rs`, `src/agent_mcp.rs`, `src/main.rs`, and necessary CLI/configuration seams.

Contract:

- Expose private generation, bounded mutations/delegation, metadata, and private use through MCP.
- Remove plaintext read from discovery and dispatch. Enforce the prohibition at the owner boundary for every non-admin peer, not only in tool descriptions.
- Reject agent plaintext-secret Create/Patch input. Keep any permitted metadata edits clearly separate from private import.
- Retain authenticated session identity and typed workload validation. Do not accept principal, owner, administration authority, or destination bindings from model arguments.
- Reuse `DurableVault::use_secret`, current task/grant checks, and the strict handoff ordering. Bind consumer service/origin to approved task/record scope.
- Keep transport uncertainty distinct from policy denial and unsupported private delivery.

Acceptance: two independent client sessions complete generation, SecretUse sharing and real private HTTPS use. Raw reads, forged authority and secret-bearing mutation bypasses fail.

## Part 4: Independent functional and privacy acceptance (complete)

Owner: QA subagent. Model: `qa` route, independent of implementation contexts.

Owned files: synthetic HTTPS fixture, private bridge acceptance cases, and only required isolated-runner changes. Do not edit production Rust to make tests pass.

Minimum checks:

1. A generates a credential and delegates use to B. B authenticates against a local TLS fixture. The fixture privately establishes that the same credential was used; it never emits the credential into test output.
2. An unrelated client and wrong task/destination are denied. Grant and task revocation block both cached and fresh uses while the task remains otherwise live. Exercise relevant expiry and retry boundaries without repeating unrelated suites.
3. Scan every recorded model-facing request/result, error, audit result, and native stdout/stderr against the actual synthetic secret and applicable encodings. Make the fixture return a secret-bearing body to prove it is discarded. Separate this test oracle from the agent interface.

Use only synthetic state, an isolated network namespace with local TLS, and task-owned certificate material. No real provider calls, accounts, live harness settings, dependency downloads, or claims of model-agent execution from scripted clients.

## Part 5: Independent security review and completion (source review and focused verification complete)

Security owner: Security subagent on the `security-review` route. Review changed authority, TLS/destination, child-process/FD, generation/retry, import, and output boundaries. Source-only findings are separate from QA's executed checks.

Coordinator owner: reconcile API contracts, verify exact source/artifact hashes and actual acceptance output, and apply only bounded repairs to concrete findings. Give each file and each check one owner. Do not re-run unchanged full suites or restart design merely because a phase ended.

Documentation owner: `routine` route (`gpt-6-luna`). The implementation, source review, and focused acceptance evidence are recorded in [private credential verification](private-credential-verification.json). The source-bound final report is `/home/nick/.local/share/credman-private/20261029T174025Z/qa-final.json` (SHA-256 `99951dbb7486b205f137932d4a9a83c5c3c12866bd5404b6c838bf2785aa8004`). The security closure is `/home/nick/.local/share/credman-private/20261029T174025Z/security-closure.json` (SHA-256 `f0ab87a5913dc86b71305fef71b7c159d8aeaa40e2488cf77fe1bb2855ac0566`). These private reports are source evidence, not public artifacts.

The historical baseline checks include cargo check, 25 focused Rust checks, and three native cases against that baseline binary. The later [session-expiry follow-up](session-expiry-verification.json) records the owner-authorization repair; the baseline checks were not rerun for that patch. They are not a full test suite, benchmark, live LLM harness run, or production security audit. Native output canary scans cover recorded model-facing and process output; HTTP response bodies, headers, and curl stderr are discarded, not scanned. The trusted endpoint receives authorized secrets by design.

Keep the same-UID trusted-host limitation explicit. This feature protects the model-facing workflow; it does not create hostile-process isolation. Preserve all bot/workspace directories, source, reusable tests, and historical evidence. Retire only proven task-disposable artifacts after useful results are retained.
