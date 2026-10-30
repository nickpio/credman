# credman

## OpenCode usage is incomplete

OpenCode is not supported for credential use in this revision. The installed v2.2.2 client selected its configuration but did not establish MCP discovery or tool invocation. The unfinished authenticated API experiment is disabled, and the probe reports `status: incomplete` with `connected: false`. No authentication experiment or live configuration change is part of this merge. Earlier v2.1.4 records remain historical.

An agent-first credential vault and local MCP bridge. Multiple agent harnesses access the same scoped vault operations while one owner holds the encrypted store.

The user owns credentials. A harness name, model claim, record reference, or MCP client label grants no authority. A trusted supervisor binds each client session to a principal, workspace, task allowlist, and expiry.

## Current scope

The fake-login application adapter is removed. The bridge generates local credentials, supports scoped sharing and private use through an approved HTTPS destination, reads authorized metadata, and accepts private human imports. Encrypted backup, restore safeguards, and human recovery remain in the core.

MCP exposes `credman_generate`, `credman_mutate`, `credman_metadata`, and `credman_use`. It does not expose `credman_read`, even when a task has `SecretRead`. Agents receive references and use authority, not plaintext. A trusted human can import or read secrets through the private administration channel, subject to approved task scope.

`credman_generate` creates local credentials, not online accounts. Login generation requires a public username and creates a private password; API-key generation creates a private token. For approved HTTPS destinations, `credman_use` performs a fixed verified-HTTPS GET with Basic or Bearer authentication. Its `Accepted`, `Rejected`, `Unknown`, and `HumanRequired` statuses describe delivery, not verified login or registration. The agent cannot choose the URL, headers, CA file, or command. Unknown delivery is not retried automatically.

This remains a local Linux prototype, not a production provider installation or an agent messaging bus.

## How agents share credentials

1. A trusted human supervisor unlocks one store and approves separate tasks for Agent A and Agent B.
2. The supervisor issues each agent a one-use attachment credential through its private administration channel. The credential goes into a private session file, not the harness configuration or a chat.
3. Each harness launches `credman mcp --session-file PATH`. The frontend authenticates to the existing owner; it never opens the vault or receives the root seed.
4. Agent A calls `credman_generate` and receives an opaque record reference and revision. The reference alone grants no access.
5. Within its approved delegation limits, A grants B `SecretUse` for specific fields and destination IDs, then sends B the record reference. Agent-issued `SecretRead` grants are forbidden.
6. B calls `credman_use` through its own task and bound session. The owner supplies the secret privately to the approved HTTPS consumer and returns a receipt. Revocation and expiry block later access, including cached retries.

Revoking access cannot recall a value already sent to a trusted destination or rotate an upstream credential.

For attached sessions, the owner rechecks session expiry at final authorization immediately before the private delivery callback, after durable intent publication. Expiry at that boundary cancels dispatch. This does not require remote receipt or completion before expiry, or recall credentials already handed off.

## Harness integration

All five target harnesses document local MCP support. They use different configuration shapes, not different vault backends. The installed-client results below predate private generation and the current tool catalogue. They were not rerun for this feature.

| Harness | Local MCP configuration | Historical installed-client check |
|---------|-------------------------|------------------------|
| Codex | TOML `mcp_servers.credman`, command and args | 0.164.0 discovers all four tools |
| Claude Code | JSON `mcpServers.credman`, stdio command and args | 2.1.310 reports connected |
| Hermes | Profile YAML `mcp_servers.credman`, command and args | Native MCP probe connects and discovers all four tools |
| Grok Build | TOML `mcp_servers.credman`, command and args | 1.0.70 reports healthy and discovers four tools |
| OpenCode | JSON `mcp.servers.credman`, local command array (OpenCode v2) | 2.1.4 loads the exact configuration, but its MCP listing remains empty. Runtime compatibility is unverified. |

The [harness guide](docs/agent-native/HARNESS-BRIDGE.md) covers provisioning, configuration, actual compatibility checks, and lifecycle limits. Generate a configuration fragment without touching live settings:

```bash
python examples/harness_config.py codex \
	--binary /absolute/path/to/credman \
	--session-file /private/credman/session-agent-a.json
```

Use `claude-code`, `hermes`, `grok-build`, or `opencode` for the other formats. The fragment contains only an executable and session-file path, never a seed or token.

## Native interfaces

```text
credman serve --directory DIRECTORY --seed-fd SEED_FD --config-fd CONFIG_FD --admin-fd ADMIN_FD [--create] [--bridge-socket PATH]
credman mcp --session-file PATH
credman admin --directory DIRECTORY --seed-fd SEED_FD --identity-fd IDENTITY_FD {backup,restore,recover} ...
```

The seed enters through a private descriptor, not argv or an environment variable. The human administration channel remains separate from MCP. The owner is bounded to 300 seconds in this prototype; it installs no daemon. Sessions expire no later than the owner and require fresh issuance after disconnect, restart, or a consumed attachment.

See the [runtime reference](docs/agent-native/AGENT-RUNTIME.md) and [security model](SECURITY.md). There is no interactive credential CLI, TUI, clipboard helper, USB watcher, or old-format migration surface.

## Build and verification

```bash
cargo build --release --locked
python scripts/check-isolated.py --work-dir /absolute/path/to/prepared-cache --agent-program-tests
```

The isolated controller builds offline, hides the host home and external network, and enables loopback only inside its private network namespace. It tests the Cargo-produced executable against synthetic state. [Historical private credential verification](docs/agent-native/private-credential-verification.json) records the baseline 25 focused Rust checks and three native private-flow cases. The [session-expiry follow-up](docs/agent-native/session-expiry-verification.json) records the later authorization repair and its targeted independent checks. The earlier [bridge verification](docs/agent-native/harness-bridge-verification.json) records historical client connection diagnostics, not current private-use proof.

Earlier [agent-first refactor checks](docs/agent-native/agent-first-verification.json) and [two-real-bot playback](docs/agent-native/demo/two-agent-demo.html) remain historical evidence. The old fake-application launcher is retired; playback is not a live run of the bridge.

## Limits

- Same-UID host-capable agents are trusted host operators, not isolated principals. Someone who can read another session file can steal its attachment authority.
- MCP clients can share a process/connection across conversations. One configured session is one principal, not automatically a separately authenticated identity per chat.
- Per-worker memory, PID, CPU, and tmpfs quotas remain absent. Tests do not establish hostile-host safety, storage rollback resistance, cryptographic correctness, or power-loss behavior.
- Real website signup, password rotation, and proof of remote account creation are not implemented. HTTPS delivery is tested with synthetic local fixtures; no real credentials, global harness configuration, deployment, commit, or push are part of validation.
