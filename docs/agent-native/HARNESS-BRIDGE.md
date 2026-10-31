# Connect agent harnesses

Each agent harness launches a Credman MCP stdio frontend using its own supervisor-issued session file. All frontends connect to one owner. The frontend authenticates and forwards requests without opening encrypted storage or receiving the root seed.

## Provision tasks and sessions

1. Start the owner with an owned mode-`0700` store directory, private seed and configuration descriptors, a human administration socket, and a private bridge socket.
2. Through the human channel, approve each agent's task with explicit fields, permissions, service, origin, destination IDs, sharing bounds, and expiry.
3. Call `issue_session` with the agent principal, task UUID allowlist, and expiry. Each task must already be an unexpired, unrevoked approval for that principal. The private response contains a `session` object. The human channel can also list tasks, records, grants, and sessions; those pages contain no secret values, metadata values, or attachment tokens.
4. Write that object directly to a new owned mode-`0600` regular single-link file under an owned mode-`0700` directory.
5. Configure the harness to launch `credman mcp --session-file PATH` with an absolute executable path.

The [runtime reference](AGENT-RUNTIME.md) specifies descriptors and message schemas. The [synthetic supervisor fixture](../../tests/bridge_support.py) demonstrates the launch mechanics using public test data.

A session binds the entire connection to one principal. A record reference, harness name, model claim, working directory, or MCP `clientInfo` label grants no authority. A harness that reuses one MCP process across conversations also reuses its configured session identity.

## Generate configuration

```bash
python3 examples/harness_config.py codex \
	--binary /absolute/path/to/credman \
	--session-file /private/credman/agent-a.json
```

The generator prints a configuration fragment. It does not change live settings or read the token. Its implemented output shapes are:

| Harness argument | Output |
|------------------|--------|
| `codex` | TOML `mcp_servers.credman` with `command` and `args` |
| `claude-code` | JSON `mcpServers.credman` with stdio `command` and `args` |
| `hermes` | YAML `mcp_servers.credman` with `command`, `args`, and sampling disabled |
| `grok-build` | TOML `mcp_servers.credman` with `command` and `args` |
| `opencode` | JSON `mcp.servers.credman` with a local command array |

Apply the fragment through the harness's supported configuration mechanism. Preserve unrelated settings and check which configuration scope the client selects. Configuration generation alone does not establish connection or tool-call compatibility.

OpenCode credential use is unsupported. Its connection, exact tool discovery, and invocation are unverified; the diagnostic reports `status: incomplete` and `connected: false`.

## Handle sessions

Attachment consumes the token once. Do not share one session file across client launches. Disconnect, revocation, restart, and consumed-token reconnects require fresh issuance. Session expiry cannot exceed the owner's request-admission window. That window is 300 seconds unless `max_lifetime_secs` sets another value from 60 through 86400. An optional `idle_timeout_secs` in that same range, and no longer than the admission window, stops the owner after a quiet period with no administration or peer request. The MCP frontend reads until the session `expires_at`, bounded by 86400 seconds. A failed owner or frontend prints `credman COMMAND: KIND` and uses the exit codes in the [runtime reference](AGENT-RUNTIME.md#exit-codes). The kind is not a secret and the process does not print configuration contents.

Connection diagnostics can consume tokens. Provision a separate session for a probe, then issue a fresh session for the agent. Use the human `revoke_session` operation to invalidate attachment or active session authority. Task and grant revocation also remain effective after attachment.

Keep session tokens outside configuration text, command arguments, environment variables, chat, and logs. The session file contains authentication material; its path alone belongs in harness configuration.

## Use credentials

The MCP frontend exposes `credman_generate`, `credman_mutate`, `credman_metadata`, and `credman_use`. Agent tool results contain references, authorized metadata, and delivery receipts. A metadata result includes the record revision and signup state with the approved nonsecret fields. Secret values are available only to approved HTTPS consumers or explicitly authorized human reads through the private administration channel.

Configure destinations in the owner configuration before approving private use. Each destination specifies `id`, `service`, `origin`, `path`, `auth`, and optional `ca_file` and `timeouts`. The task must approve the matching service, exact origin, and destination ID. Basic authentication requires `Username` and `Password`. Bearer, header, and query authentication require `ApiKey`. Header names and query parameter names are fixed in the destination. The [runtime reference](AGENT-RUNTIME.md) gives the bounds, IPv6 origins, and the single-threaded timeout limit.

Private use performs a fixed verified-HTTPS GET. Agents cannot choose its URL, headers, CA file, or command. Delivery acceptance does not prove account creation or verified login.

If a mutation reply is lost, its durable outcome can be unknown. Reconnect with a newly issued session and reconcile or retry the original request UUID under current task authority. A new request UUID can repeat a mutation.

## Diagnose clients

The installed-client checker stages executables and source in a synthetic namespace with provider egress disabled. It requires Bubblewrap and the selected installed harness clients. For Hermes, run it with the Python environment containing its installed dependencies and supply `--hermes-source` when needed.

```bash
python3 scripts/check-harnesses.py \
	--binary /absolute/path/to/credman \
	--binary-sha256 SHA256 \
	--harness codex
```

Repeat `--harness` to select clients. Omitting it selects the full matrix, including unsupported OpenCode, so the matrix cannot report all clients connected. Source hashes, executable hashes, connection status, and source drift appear in the result. Client diagnostics do not establish model-driven workflows.

## Trust boundary

The supervisor, host account, kernel, executable, session custody, and configured HTTPS destinations remain trusted. Host-capable agents under the human's Unix UID can steal readable tokens or inspect processes. Private paths and principal labels do not enforce OS isolation. The separate sandbox-worker test helper does not provide isolation in the MCP launch path.

See the [security model](../../SECURITY.md) and [threat model](THREAT-MODEL.md) for the supported boundaries.
