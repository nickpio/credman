# Harness bridge decisions

The user requested removing the fake application adapter and exposing the credential vault across Codex, Claude Code, Hermes, Grok Build, and OpenCode. Official sources document local MCP support in all five. Current scope is local harness integration, not cloud-host access or an agent messaging bus.

## Chosen structure

Keep one durable owner and use authenticated private Unix-socket admission with thin MCP stdio frontends. Ordinary harnesses can launch the frontend without preserving extra descriptors. The root seed and human administration channel never move into harness configuration. The frontend does not reopen encrypted storage.

A local HTTP MCP service was considered. It would add an HTTP runtime, loopback exposure, Host/Origin validation, bearer-header setup, and more lifecycle machinery without a demonstrated client need. Standard stdio is the smaller common interface. No five SDKs, public embedding library, generic execution framework, or database is added.

## Authority and disclosure

Issue a random one-use attachment credential through the private human channel. Bind the resulting connection to principal, owner/workspace, task allowlist, expiry, and current owner lifetime. A session UUID or a credential reference is not the authentication secret. MCP clientInfo, cwd, harness labels, and tool arguments cannot select identity or approve tasks.

MCP can be shared across conversations by a harness. Independent chat identity is not inferred. Same-UID host-capable agents remain trusted host operators who can steal readable files; token custody does not create OS isolation.

Remove the fake-login route rather than rename it as provider support. Generate secrets inside the durable owner and share record references with scoped `SecretUse` authority. The fixed HTTPS GET consumer supplies authorized values privately to a human-configured Basic or Bearer endpoint and returns only a delivery receipt. It cannot prove registration or verified login. Raw agent reads and secret-bearing writes are blocked at the owner boundary; human import/read uses the separate private channel. This does not promise universal browser injection, hostile-host isolation, or recall of a value already delivered.

## Evidence

The [private credential baseline](private-credential-verification.json) and [session-expiry follow-up](session-expiry-verification.json) record separate source revisions and check scopes. Earlier installed-client diagnostics remain in [historical bridge verification](harness-bridge-verification.json); they predate this tool catalogue. OpenCode runtime connection remains unresolved. Hash-check unchanged core/storage before reusing earlier functional/recovery evidence. Distinguish configured, connected/discovered, actual tool-called, and model-workflow-tested states. No real credentials, provider calls, live harness edits, installation, commit, or push is implied.
