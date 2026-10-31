# Credman

Credman is an agent-native credential vault for sharing access to sensitive credentials across supervised agents. Agents exchange record references and scoped permissions. Credential values stay inside the vault and its approved HTTPS consumers, outside model-visible tool responses and chat.

One vault owner holds the encrypted store. A trusted supervisor approves tasks, assigns agent identities, configures destinations, and issues private sessions. Agents connect through MCP stdio frontends without receiving the vault seed.

## Capabilities

- Generate login passwords and API-key values inside the vault. Login generation takes a public username; generated secrets never appear in the response.
- Share access with a named agent, limited by fields, permissions, destination IDs, and expiry. A pinned grant matches one secret version. A `follow_active` grant stays valid for later secret versions. Metadata patches do not rotate that version. The MCP share schema still submits pinned grants.
- Use credentials through a fixed HTTPS GET with Basic or Bearer authentication. The supervisor selects the endpoint, path, and optional CA certificate.
- Read authorized metadata, patch metadata, revoke grants, delete records, and report task outcomes through MCP.
- Import existing credentials and perform explicitly authorized secret reads through a separate human administration channel.
- Create encrypted backups, restore into a fresh store, and recover from ambiguous storage publication with human authorization.
- Persist encrypted records, approvals, grants, request receipts, delivery attempts, and bounded audit events together. Revision checks prevent stale updates, and request IDs support retries without repeating completed work.

Credential generation creates vault records. It does not create remote accounts or issue provider credentials. A generated API-key value must be provisioned with its intended service separately.

## How sharing works

1. The supervisor starts a vault owner and approves separate tasks for Agent A and Agent B. Each approval specifies identity, workspace, service, origin, fields, permissions, destinations, and expiry.
2. The supervisor issues each agent a one-use attachment token through the private human channel and writes it into a private session file.
3. Each agent harness launches `credman mcp --session-file PATH`. The owner authenticates the attachment and binds the connection to its assigned principal and task allowlist.
4. A calls `credman_generate` and receives an opaque record ID and revision.
5. Within its approved sharing bounds, A grants B `SecretUse` for the required fields and destination. A sends B the record reference through their existing communication channel.
6. B calls `credman_use`. The owner checks current task, session, and grant authority, supplies credentials privately to the configured HTTPS consumer, and returns a delivery receipt.
7. Revocation or expiry blocks subsequent access, including retries of successful requests.

A record ID conveys no authority by itself. Agents cannot approve tasks, change their session identity, or grant plaintext read access. The vault provides access control and private delivery; agents use their own communication channel to exchange references.

## MCP tools

| Tool | Purpose | Returned data |
|------|---------|---------------|
| `credman_generate` | Generate a login password or API-key value | Record ID and revision |
| `credman_mutate` | Patch metadata, share, revoke, delete, or report an outcome | Record revision and optional grant ID |
| `credman_metadata` | Read approved `Label`, `Username`, or `Notes` fields | Revision, signup state, and those field values |
| `credman_use` | Authenticate a configured HTTPS GET | Attempt ID and delivery status |

Basic authentication requires exactly `Username` and `Password`; Bearer authentication requires exactly `ApiKey`. Agents select an approved destination ID, while the supervisor controls its URL and authentication scheme. Redirects and automatic HTTP retries are disabled. HTTP response bodies, headers, and curl diagnostics are discarded.

Delivery receipts use `Accepted`, `Rejected`, `Unknown`, or `HumanRequired`. An accepted HTTP response does not prove account registration or a verified login. Uncertain delivery is retained without automatic redispatch.

## Build

The runtime requires Linux, a Rust toolchain with Cargo, and `/usr/bin/curl` for private HTTPS use.

```bash
cargo build --release --locked
./target/release/credman --help
```

The executable has three commands:

| Command | Responsibility |
|---------|----------------|
| `serve` | Own the unlocked store and handle supervisor and agent requests |
| `mcp` | Authenticate a session and expose the four tools over stdio |
| `admin` | Perform offline encrypted backup, restore, or recovery |

## Connect agents

A trusted supervisor must provision the store, tasks, and session files before launching clients. The store directory must be owned by the effective Unix user with mode `0700`. The seed and supervisor configuration enter through private inherited file descriptors.

```text
credman serve --directory DIRECTORY --seed-fd SEED_FD --config-fd CONFIG_FD --admin-fd ADMIN_FD --bridge-socket PATH [--create]
```

This is the supervisor invocation contract. The supervisor must open and transfer the descriptors, including a connected administration socket. The [runtime reference](docs/agent-native/AGENT-RUNTIME.md) describes their contents and protocol. [The synthetic supervisor fixture](tests/bridge_support.py) demonstrates descriptor transfer using public test data.

Generate a harness configuration fragment after the supervisor has issued a session:

```bash
python3 examples/harness_config.py codex \
	--binary /absolute/path/to/credman \
	--session-file /private/credman/agent-a.json
```

The generator supports `codex`, `claude-code`, `hermes`, `grok-build`, and `opencode` configuration shapes. It prints executable arguments and a session-file path without reading the token or changing live settings. OpenCode credential use is unsupported until its connection, tool discovery, and invocation are verified. Configuration generation alone does not establish client compatibility.

The [harness guide](docs/agent-native/HARNESS-BRIDGE.md) covers provisioning, configuration, and session lifecycle. Each independent principal needs its own session. A harness that shares one MCP process across conversations shares that session's identity.

## Verify

The isolated controller requires Python 3, Bubblewrap, rustup, and OpenSSL. Use a dedicated cache outside the repository. The fetch step downloads locked dependencies; subsequent builds and tests run offline with a synthetic home and private loopback network.

```bash
python3 scripts/check-isolated.py --work-dir /absolute/path/to/credman-checks --fetch
python3 scripts/check-isolated.py --work-dir /absolute/path/to/credman-checks test --release
python3 scripts/check-isolated.py --work-dir /absolute/path/to/credman-checks clippy --all-targets -- -D warnings
python3 scripts/check-isolated.py --work-dir /absolute/path/to/credman-checks --agent-program-tests
python3 scripts/check-isolated.py --work-dir /absolute/path/to/credman-checks --workload-tests
python3 -B tests/check_isolated_runner.py
python3 -B scripts/check-docs.py
```

Executable acceptance checks exercise real MCP subprocesses against one durable owner and synthetic HTTPS endpoints. They cover generation, sharing, revocation, session boundaries, TLS validation, uncertain delivery, backup, restore, and human reauthorization. The controller records source hashes and the executable digest with each run.

## Security boundaries and limits

Credman encrypts persisted state with Argon2id-derived keys and AES-256-GCM. It uses private filesystem resources, one-use session authentication, task approvals, bounded delegation, strict request decoding, and authorization checks immediately before private delivery.

The supervisor, host account, kernel, executable, and configured HTTPS consumer are trusted. Host-capable agents under the same Unix UID can steal readable session files or inspect processes. Session identity does not provide OS isolation. An approved consumer receives the credential by design, and revocation cannot recall a delivered value or rotate a remote password.

The owner stops admitting requests after 300 seconds. An in-flight operation and its bounded reply may finish afterward. Sessions require fresh issuance after disconnect, restart, or token consumption. There is no installed background service, remote vault API, website signup automation, or upstream credential rotation. Per-worker resource quotas, rollback resistance, and power-loss durability are not established.

See the [security model](SECURITY.md), [threat model](docs/agent-native/THREAT-MODEL.md), and [runtime reference](docs/agent-native/AGENT-RUNTIME.md) for the enforced boundaries and operational details.
