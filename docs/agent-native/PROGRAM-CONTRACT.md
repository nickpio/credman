# Agent-vault and harness bridge contract

Credman stores user-owned credentials and controls scoped access across local agent harnesses. It is not a provider-action service, a general agent bus, or a maintained terminal password manager.

## One owner, multiple frontends

`serve` is the only durable application owner. It accepts trusted preconnected peers and optional private Unix-socket attachment. `mcp --session-file PATH` is a thin stdio frontend that authenticates and forwards workload requests without opening storage. Offline `admin` retains backup, restore, and recovery. No public HTTP listener, daemon installation, or harness SDK is added.

The human administration descriptor remains separate. Only that channel can approve tasks, issue/revoke sessions, inspect audit, or stop the owner. Human identity/configuration remains trusted supervisor input, not proof against an arbitrary same-UID host process.

Session credentials bind principal, workspace/owner, task allowlist, expiry, and the current owner instance. Random one-use attachment authentication is separate from record/task/session identifiers. Attachment never creates task approval. MCP client labels, paths, and request fields cannot select identity or widen authority.

## Stable policy and storage

- Records belong to the user. Creator, originating task, service, origin, and restored-registration guards remain immutable through ordinary patches.
- Metadata, private use, plaintext read, write, grants, and deletion remain separate permissions.
- Delegation cannot widen fields, recipients, permissions, destinations, or expiry. Grants pin credential-value versions.
- Recheck task/grant/session authority and expiry on requests, including cached mutation retries.
- For attached sessions, recheck the server-held session deadline at final owner authorization immediately before the private callback, after durable intent publication. Expiry cancels dispatch with a resolved non-dispatched intent. Remote receipt/completion before expiry and recall after handoff are not guaranteed.
- Preserve one durable commit boundary, revision checks, request deduplication, conservative unknown outcomes, and explicit recovery after ambiguous publication.
- Preserve strict encrypted state/backup decoding, input bounds, unique ownership, file protection, restore no-overwrite, task/grant revocation, clock constraints, and restored registration blocking.

The fake-login adapter and executable fake-app demo are removed. The current consumer performs a fixed verified-HTTPS GET to a human-configured Basic or Bearer destination. Service, exact origin, fields, action, and current authority are checked before delivery. Only action `Use` is supported; unsupported actions and unknown destinations fail before durable delivery preparation. Unknown outcomes are not automatically redispatched. HTTP acceptance is not verified login or account creation.

The MCP catalogue contains `credman_generate`, `credman_mutate`, `credman_metadata`, and `credman_use`. Agents exchange references and scoped `SecretUse` authority, not plaintext. The owner rejects raw reads, secret-bearing Create/Patch input, and agent-issued `SecretRead` grants even if a frontend bypasses MCP. Explicit task-scoped human import/read stays on the private administration channel. There is no universal browser or harness-private injection guarantee.

## Compatibility and acceptance

Use the common MCP stdio subset and inert, source-verified configuration generation for Codex, Claude Code, Hermes, Grok Build, and OpenCode. Support actual protocol negotiation; do not advertise unsupported revisions or treat a client label as authentication. Do not install or overwrite live harness settings as a side effect of source integration.

Verify actual two-client generate/deny/share/use/revoke against one encrypted owner, private human import/read boundaries, task/session binding, attachment replay/expiry/revocation/restart, safe error output, and unsupported-use non-dispatch. Test the Cargo-produced binary, not a guessed cache executable. Distinguish real harness discovery from actual tool calls, generic protocol tests, and documentation-supported configuration.

Reuse unchanged domain/storage evidence after checking exact source hashes. Do not repeat historical signup tests or full suites merely because a transport changed. See the [private credential baseline](private-credential-verification.json) and [session-expiry follow-up](session-expiry-verification.json) for their separate execution and review scopes, [historical bridge verification](harness-bridge-verification.json) for earlier client diagnostics, [harness integration](HARNESS-BRIDGE.md) for setup, and [security](../../SECURITY.md) for remaining trust limits.

Preserve historical records and every bot-chat workspace/ancestor. No real vault, account, service deployment, global harness setting, commit, or push is implied.
