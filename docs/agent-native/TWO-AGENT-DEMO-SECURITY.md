# Two-real-agent demo bridge security review

Disposition: source review CLOSED for the bounded trusted-operator synthetic demonstration, including the narrow teardown repair below. No new source security blocker identified. The live-clean authorization workflow ran on the prior hash; the teardown repair is source-reviewed but not yet exercised. Both bot sessions are stopped; this review does not authorize repeating them.

File: /home/nick/credman/examples/two_agent_demo.py
Latest reviewed SHA-256: 645bb4b6bb3f9e45dc7f62f14f10a1f272c5eb1fe1d02b51a070acb89bd862df
Authorization-workflow source SHA-256: 5227457aea3ccdc83743e63ba5dc8eaed82f05b084625d0b4774d1ca4cf9a462

## Narrow lifecycle delta review

Inspected only close() at lines 702-741 and computed the current file hash. After the shutdown request, an exact {'ok': True} acknowledgment now triggers broker.wait(timeout=2) before the existing termination fallback. TimeoutExpired joins the existing fixed/suppressed error path. Thus a cleanly exiting broker gets a bounded grace period instead of immediate SIGTERM; missing/bad acknowledgment, timeout or I/O failure still reaches owned-process termination. The required broker.returncode == 0 completion gate remains intact (723-724). No identity, grant, secret-delivery or request-policy code is changed by this reviewed delta, per the parent's declared three-line scope. No new blocker identified. This is one scoped source review, not a fresh full-file audit or execution result.

Evidence separation: I directly executed B's live-clean pregrant login/read denials, granted login Accepted, and post-revoke cached/fresh denials. All denials were exit1, Accepted exit0; cached request matched the successful request and the fresh request differed. Parent reports all16 named checks true, actual application1/1, and the8-step workflow in109s on hash5227457. Parent also reports final clean-exit failure broker_exit=-15 due to immediate post-ACK termination. Those aggregate/lifecycle facts are supplied parent evidence, not independently reread receipts in this narrow review. Do not describe that prior run as cleanly finalized.

The fix on hash645bb4 remains UNEXERCISED here. Parent will run only a separate fresh native startup + parent finish lifecycle check in its approved pinned sandbox, preserving the prior unchanged authorization evidence. No bot workflow, probes or client commands were rerun for this review. Both source hashes and separate evidence must appear in any final verified account.

Historical source review details follow; line references identify their stated earlier revisions.
Previous closed revisions: 7d9db59af51628bb7cc84948093b5f98e75b1e55cef903537bd8d4eab95ca963; 1a804780b77d8be952fca24791c77ac6fc0dd1f6e3f2aadfc33b7944fa216b24

Final scoped delta closure: inspected the new retry/fresh-ID comparisons (638-646), required native clean exit in final evidence (721-740) and server return (873-876), corrected DEVNULL documentation (87-92), and current client validation/printing (745-822,891-892). Original required serve flags remain at 844-850. No new source security blocker identified. Child output is suppressed, not measured. The source is 909 lines; the detailed findings below retain line references from the immediately preceding 901-line review where not updated, with equivalent controls preserved. This is scoped source closure, not executed demo evidence.

The source changed after the previous closure. Its changed sections were inspected after the preceding full-file review, and the current file was rehashed; the review does not silently reuse the old hash. Parent/Backend must freeze the staged source and match its invocation before launch.

## Findings closed in current source

1. Host-client response disclosure. client_response validates exact operation-specific schemas, strict scalar types/bounds, canonical UUIDs/expected record, fixed errors/statuses and named check/count consistency, then reconstructs output (738-815). It runs before printing (883-884). Extra credential/echo fields are refused rather than printed. Negative acceptance remains unexecuted: unexpected fields/values must yield only fixed refusal.

2. Parent control and real application counts. Separate listeners and role command sets isolate workflow operations (124-126,506-511,531-542). Supervisor queries and validates real fake-app account/registration counts (306-327); these are distinct from named check totals. Control results are provisional final:false. Teardown writes final:true stop evidence and final.json with checks, actual counters and child exit codes (697-735). Parent must require successful controller exit and complete final evidence, not finish acknowledgment alone.

3. Record scope/authority. All record-bearing commands require this run's retained record (525-530). Native identity/task/destination choices originate from trusted supervisor configuration and separate preconnected endpoints (468-505), never arbitrary workload JSON. Share fixes B, fields, SecretUse-only mode, destination and expiry (573-579). Socket-basename checks (874-876) are routing checks, not authentication. Negative checks for other UUIDs, extra identity/admin/task fields and wrong-role operations remain unexecuted.

4. Native malformed response handling. Native UUID failures are wrapped (209-213), status is string-checked before enum membership (406-410), and malformed native replies stop with fixed summaries (681-687). Events project fixed fields (345-359). revoked:true follows successful native mutation receipt (585-589). Unexpected read success is withheld and stops the run (591-597). No automatic registration retry is implemented.

## Current runtime/evidence contract

Required non-status order is A create/register, B login denial, B read denial, A share, B accepted login, A acknowledged revoke, B cached-request denial, B fresh-request denial. Ordered observations and expiry exclusion are at 610-653. The successful request ID is retained and checked for the cached retry; the fresh login generates a new ID. Do not insert additional non-status probes into the strict run.

The bridge does not script the two bots. Actual A/B tool/message records must corroborate who acted; role labels in JSONL alone are not proof. Exchange only the opaque record reference. Password generation is internal; the public synthetic seed enters by FD. Neither password nor native/admin request JSON is a bot command input.

Canary checks now cover serialized responses/events/ready, selected encrypted images and app verifier state (277-343). Child stdout/stderr are DEVNULL (461-462,488-491), NOT measured/scanned for canary absence. The check is honestly named child_output_suppressed; final.json labels this suppressed_devnull_not_measured (732). The top-level docstring still describes an older drain/EOF implementation and must not be repeated as runtime evidence. This documentation mismatch is not a new credential-leak source path.

Literal-canary checks prove at most the checked literal marker claim after execution, not encoded/partial/side-channel absence, cryptographic correctness, full memory erasure or recall of disclosed copies. Report actual final results, not assumed passing values from source.

## Launch preconditions and limits

Current serve parser requires --synthetic-only, --binary, --binary-sha256, --fake-app and --state-dir, with --session-seconds for duration (837-846). Earlier --root/--seconds aliases are absent. Parent must match its controller invocation to this revision. Hash comparison is enforced by the required argument; preserve verified artifact staging. HOME/TMPDIR labels remain accidental-launch guards, not sandbox proof. Only the thin client may run on the host.

Same-UID host bots, supervisor and host remain trusted operators able to discover/access same-user paths. The separate control socket is workflow separation, not host-bot authentication/isolation. This review does not certify resource quotas, kernel security, hostile unsandboxed same-user containment, real providers or full native integration.

Only the bridge was inspected in this task; SHA-256 was computed read-only. No server, fixture, client or tests ran during review. No Backend source was edited. Only this report was written. No real credentials/auth/history, profile change, deployment or folder deletion/relocation occurred.

Skills: pstack:poteto-mode, principle-boundary-discipline and unslop. All previously reported source security findings remain closed against the latest hash. Later changes require scoped reinspection; actual demonstration evidence remains pending parent launch.
