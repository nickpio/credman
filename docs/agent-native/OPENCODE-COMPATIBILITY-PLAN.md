# Resolve OpenCode compatibility

**Status: incomplete and deferred by user request.** The unfinished authenticated probe is disabled for the main merge. Its source and investigation evidence remain in the private task archive. This task does not authorize resuming the pending authentication experiment.

## Outcome and acceptance

Resolve the installed OpenCode client's empty MCP listing without changing vault authority or weakening secret handling. Verify the installed version in an isolated synthetic home.

Minimum acceptance:

- Reproduce the current empty-listing failure and identify its cause with runtime evidence.
- The installed native OpenCode client connects to the current source-pinned Credman binary and discovers exactly `credman_generate`, `credman_mutate`, `credman_metadata`, and `credman_use`.
- Complete an approved nonsecret-result tool invocation through OpenCode's actual MCP machinery, not a replacement MCP client. Do not use provider credentials or a model prompt. Report a missing supported invocation path as a limit rather than inventing proof.
- Preserve task/session identity, one-use attachment handling, unknown transport outcomes, and secret-safe output. Probes use fresh sessions.
- Independent QA verifies the fixed path. Review changed trust/process/configuration boundaries and update current documentation without rewriting historical evidence.

## Parts and owners

1. **Version-specific evidence. Researcher, GPT-6 Astra.** Reuse the existing exact-tag loader trace. Investigate only plugin activation/readiness and the supported discovery/invocation API. Read-only research, no repository or live configuration edits.
2. **Reproduction and implementation. Backend, GPT-6.1 Sol.** Own `tests/harness_clients.py`, `scripts/check-harnesses.py`, and `examples/harness_config.py` only as required by a proven cause. Add targeted OpenCode selection instead of rerunning unrelated clients. No Rust or installed OpenCode binary changes without a separately scoped finding.
3. **Independent acceptance. QA, GPT-6.1 Terra.** Execute the final targeted native probe against immutable source and binary hashes. Reuse current unchanged vault/private-HTTPS evidence. No source fixes or weakened assertions during acceptance.
4. **Changed-boundary review. Security, GPT-6 Astra.** Read-only review of the actual delta, especially configuration selection, private child lifecycle, session consumption, local API authentication, output and sandbox boundaries.
5. **Closeout. Coordinator.** Verify reports and exact external effects. Update current compatibility claims and save source-bound evidence. Use GPT-6 Luna only for bounded documentation if useful.

## Baseline and constraints

Source baseline: `/home/nick/.local/share/credman-opencode/20261029T233914Z/before.tar.gz`, SHA-256 `def7742ae5531b4fdb6baa18a7f1678160e7e4ebbe9a47a2db59ad71f680247e`. The manifest records 49 scoped files. Git HEAD is not the feature baseline; preserve the dirty worktree and index.

Installed OpenCode candidate: `/home/nick/.opencode/bin/opencode`, SHA-256 `4452778e23fbda075eb2f83c2574b1d7452af8e347c52b8d9e016838b9c530d9`. Verify its current version inside the sandbox. Shell PATH discovery alone does not find this installation.

The earlier 2.1.4 probe selected the native `mcp.servers.credman` configuration but returned an empty list. The native schema is supported by existing exact-tag research. Config-plugin activation/readiness, serving-instance lifecycle, and probe observation are hypotheses, not established causes.

## Current findings

The first targeted runtime reproduced the empty native MCP listing on installed **OpenCode v2.2.2**, with the binary digest above. The document-selection check succeeded. The older v2.1.4 source trace remains historical and is not version-matched proof.

A persistent server inside the private loopback namespace returned HTTP 401 before authenticated discovery. The next synthetic-authentication edit/execution was stopped by a tool approval request and did not run. Source is not a working fix. The saved `reproduction.json` and `readiness-observation.json` record the failed observations.

Version-matched r3 research now covers v2.2.2. Foreground `serve` generates a random local API password unless supplied with a fixture-only `OPENCODE_PASSWORD`; unauthenticated HTTP 401 is expected and does not diagnose MCP activation. The native API command performs authenticated health checking before custom request headers, so an Authorization header alone cannot fix that earlier check. Any approved experiment must keep the same private server, synthetic authentication, and location across MCP status, model catalogue readiness, and plugin inventory requests. No authentication experiment has executed yet.

The v2.2.2 source investigation found no supported stock model-free tools-list plus tools-call endpoint. Connected status follows initial tool discovery, but is not proof of an actual tool invocation. Keep this acceptance distinction explicit. Research artifacts are in `/home/nick/.hermes/profiles/researcher/research/credman-opencode-runtime-r3-v2.2.2/`; source guidance neither approves execution nor establishes runtime success.

Security preflight found three concrete diagnostic gaps that must be repaired before treating an authenticated probe as safely verified: incomplete final-output/encoding screening, unbounded captures and incomplete response deadlines, and process-group cleanup that can skip scanning or miss descendants. The report is `/home/nick/.local/share/credman-opencode/20261029T233914Z/security-preflight.json`, SHA-256 `c699593d1dd06ec0be7f4206a2cd08e559affe516a4cc4f92bd170adc8b1a30d`. Its source hashes and mode `0600` were verified. No disclosure or host escape was demonstrated, and no runtime checks or repairs were performed by Security. This review does not clear the pending execution approval.

Keep provider egress disabled, use private network namespaces and synthetic HOME/XDG roots, and never mount real auth/config/history. No dependency installation, upgrades, real credentials, live harness configuration changes, commits, pushes, or workspace deletion. Preserve all bot directories and ancestors, reusable caches/source/tests, and historical verification records. Stop after a verified scoped fix or a concrete blocker.
