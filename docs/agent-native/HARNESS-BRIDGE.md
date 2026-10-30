# Connect agent harnesses to one credential vault

## OpenCode usage is incomplete

OpenCode is not supported for credential use in this revision. The installed v2.2.2 client selected its configuration but did not establish MCP discovery or tool invocation. The unfinished authenticated API experiment is disabled, and the probe reports `status: incomplete` with `connected: false`. No authentication experiment or live configuration change is part of this merge. Earlier v2.1.4 records remain historical.

Codex, Claude Code, Hermes, Grok Build, and OpenCode have primary-documented MCP stdio support. Credman uses that common interface rather than five SDKs or a general agent messaging protocol.

## Trust and data flow

```text
Human supervisor + private seed/admin descriptors
                       |
                 One vault owner
          policy + encrypted durable state
                       |
       Private Unix socket, attachment authentication
              /                    \
       MCP stdio frontend A    MCP stdio frontend B
              |                    |
       Codex/Claude/...         Hermes/Grok/OpenCode/...
```

The frontend does not reopen storage. The owner binds context before handling requests and serializes mutations, sharing, revocation, and reads. Identity comes from a human-issued attachment credential, never `clientInfo`, a tool argument, a working directory, a harness name, or record possession.

One store retains one owner/workspace scope. Different workspace scopes require separately provisioned stores. A harness's working directory cannot silently select another scope.

## Provision the owner and tasks

A trusted supervisor supplies these private resources to `serve`:

- An existing absolute private store directory, owned by the user with mode `0700`.
- A seed descriptor, separate trusted configuration descriptor, and connected human administration descriptor, all above standard input/output/error.
- A private bridge socket path under an owned `0700` directory.

The trusted configuration has `owner`, `workspace`, `admin_principal`, `peers`, and an optional `destinations` list. `peers` can be empty when a bridge socket is supplied. Destinations default to empty, so private use requires explicit human configuration.

At most 16 unique destinations are accepted. Each has `id`, `service`, `origin`, `path`, `auth` (`basic` or `bearer`), and optional `ca_file`. The task must approve the matching service, exact HTTPS origin, and destination ID. Basic use requires exactly `Username` and `Password`; Bearer use requires exactly `ApiKey`. Only action `Use` is supported. `/usr/bin/curl` is required. A custom CA file must have an absolute, nonsymlinked path whose file and ancestors have trusted ownership and are not group- or world-writable.

The command contract is:

```text
credman serve --directory DIRECTORY --seed-fd SEED_FD --config-fd CONFIG_FD --admin-fd ADMIN_FD --bridge-socket PATH [--create]
```

Descriptor placeholders are not a ready-to-run shell command. The supervisor creates and transfers the actual pipes/sockets. The [acceptance fixture](../../tests/bridge_support.py) provides a synthetic executable supervisor example; its public test seed is not a seed for a real store.

Through the separate human channel, approve exact `TaskApproval` records with the existing `approve` operation. Task approval sets principal, service, origin, fields, permissions, destinations, sharing bounds, and expiry. Unlocking or issuing a session does not approve a task.

## Issue an agent session

The human administration operation is:

```text
{"op":"issue_session","principal":"agent-a","tasks":["TASK_UUID"],"expires_at":EXPIRY_UNIX_SECONDS}
```

`EXPIRY_UNIX_SECONDS` denotes an integer selected by the trusted supervisor, not literal JSON syntax. It must be in the future and within the owner's bounded lifetime. A session has a nonempty task allowlist. The principal cannot be the administration principal.

The successful private reply includes a `session` object containing `id`, `socket`, `token`, and `expires_at`. Write that object directly into a new mode-`0600` regular session file under a private mode-`0700` directory. Do not log the reply, paste its token into chat, include it in a repository, or put it in harness args or environment variables. The UUID is a reference; the separate random token authenticates attachment.

The proxy validates file and socket ownership, permissions, and paths. The owner consumes the attachment token once and binds the connection to the issued context and task allowlist. It independently enforces the actual task and record/grant policies.

Use `revoke_session` with the session UUID through the human channel to invalidate attachment or active-session authority. Task/grant revocation also remains authoritative after attachment.

## Generate a harness configuration

Use a pinned absolute executable and the private session-file path:

```bash
python examples/harness_config.py HARNESS \
	--binary /absolute/path/to/credman \
	--session-file /private/credman/session-agent-a.json
```

`HARNESS` is one of `codex`, `claude-code`, `hermes`, `grok-build`, or `opencode`. The generator prints a fragment; it does not edit live settings or copy token contents.

| Harness | Documented destination and shape | Source |
|---------|----------------------------------|--------|
| Codex | `~/.codex/config.toml` or trusted project config; `mcp_servers.credman` with command/args | [Codex MCP](https://developers.openai.com/codex/mcp) |
| Claude Code | `.mcp.json`/supported user or local scope; `mcpServers.credman` with stdio command/args. Session-only `--mcp-config` plus `--strict-mcp-config` is available. | [Claude MCP](https://code.claude.com/docs/en/mcp) |
| Hermes | Active-profile `mcp_servers.credman` command/args. Use the supported MCP connection workflow, not a hand edit of live profile configuration. | [Hermes config reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference) |
| Grok Build | `$GROK_HOME/config.toml` or supported project scope; `mcp_servers.credman` command/args | [Grok Build MCP](https://docs.x.ai/build/features/mcp-servers) |
| OpenCode | `opencode.json`/supported config scope; `mcp.servers.credman` local command array with `disabled: false` and legacy protocol (OpenCode v2.1.4) | [OpenCode MCP](https://opencode.ai/docs/mcp-servers/) |

Use each harness's approval/configuration mechanism. Do not overwrite unrelated settings. Grok and other clients may merge compatibility/project configurations, so verify which server entry is actually selected.

## Tools and disclosure

The MCP frontend exposes four tools:

| Tool | Arguments | Result boundary |
|------|-----------|-----------------|
| `credman_generate` | `task`, `request`, generation specification | Reference and revision; generated secret is not returned |
| `credman_mutate` | `task`, `request`, typed `mutation` | Metadata-only patch, share, revoke, delete, or outcome reporting |
| `credman_metadata` | `task`, `record`, `fields` | Authorized non-secret fields only |
| `credman_use` | `task`, `usage` | Delivery status and reference; no plaintext |

The owner derives principal/owner/workspace from attachment, not these arguments. A task ID is not a bearer capability. A client cannot approve tasks, issue sessions, revoke another session, or access offline administrative operations through MCP.

Owner-channel transport failure is not an authorization denial. If a mutation reply is lost, its durable outcome can be unknown. Do not issue a new mutation UUID as a blind retry. Reconnect with a freshly provisioned session and reconcile or retry the original request UUID under still-valid task authority.

MCP has no raw-read tool, and the owner rejects raw reads from workload peers. Human import and read operations use the private administration channel and approved task scope. Login generation requires a public username; API-key generation does not. Both generate private values. Generated credentials are local records, not remote accounts.

`credman_use` supports a configured fixed HTTPS GET with Basic or Bearer authentication. Destinations bind service, origin, path, and optional CA file. The model cannot select a URL, header, CA file, or command. Only delivery status is returned. `Accepted` does not prove login or registration. Response bodies, headers, and curl stderr are discarded, not scanned. A trusted endpoint receives the authorized secret by design, and an unknown outcome is not automatically redispatched.

## Lifecycle and compatibility checks

The current owner has a 300-second deadline. Session expiry cannot extend it. A successful attachment consumes its token. Disconnect, revocation, or owner restart requires fresh session issuance. Do not share one session file across harness launches.

**Connection diagnostics can consume the one-use token.** Provision a separate session for a probe, then issue a fresh session before the real harness launch. A stale attachment must not be silently replayed during automatic MCP reconnects.

Hermes and other harnesses can reuse one MCP process across conversations. If independent principals are required, provision separate sessions and supported client/profile scopes. A per-chat authenticated identity is not inferred from labels or headers.

MCP uses newline-delimited JSON-RPC on stdio. Credman implements the bounded initialize/initialized, ping, tools/list, and tools/call subset. Modern clients can negotiate a supported legacy protocol generation; no unsupported protocol version or optional server feature is advertised.

The [private credential baseline](private-credential-verification.json) records earlier source-bound checks. The [session-expiry follow-up](session-expiry-verification.json) records the later owner-authorization repair. The separate [harness bridge verification](harness-bridge-verification.json) is historical: its four-tool connection diagnostics predate the current private-use catalog and were not rerun. They do not prove current private workflow compatibility. The installed OpenCode 2.1.4 empty MCP listing remains unresolved. These scripted-client checks are not live LLM agent runs.

## Historical harness compatibility

In the earlier diagnostic run, installed Codex, Claude Code, Hermes, and Grok Build clients connected to that run's source-bound executable in isolated synthetic homes. Codex, Hermes, and Grok Build reported four then-current tools. Claude Code reported a successful connection. These diagnostics predate the current private-use catalogue and are not model-driven agent runs.

OpenCode 2.1.4 loads the exact generated native-v2 document. Its `debug config` output includes the expected file path and decoded `mcp.servers.credman`. Its native `mcp list` still returns `No MCP servers configured`, including with an explicit private config directory and a standalone-child service setting. This does not establish a Credman protocol failure or runtime compatibility. Serving-instance and configuration-plugin activation remain unresolved. Do not change the accepted schema merely to hide the empty listing.

The isolated probe disables package lazy installs and provider egress. It never changes your live harness settings. Probe failure remains a nonzero exit even when four clients succeed.

## Remaining limits

The supervisor, host account, kernel, executable, and session-file custody remain trusted. Same-UID host-capable agents can steal readable files or inspect processes; role labels and private socket paths do not create OS isolation. Resource quotas remain a separate production gap.

The retired fake-application demonstration is available in Git history. No fake-application runtime is required by the bridge.
