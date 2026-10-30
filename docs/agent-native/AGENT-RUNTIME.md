# Agent broker and MCP runtime reference

## OpenCode usage is incomplete

OpenCode is not supported for credential use in this revision. The installed v2.2.2 client selected its configuration but did not establish MCP discovery or tool invocation. The unfinished authenticated API experiment is disabled, and the probe reports `status: incomplete` with `connected: false`. No authentication experiment or live configuration change is part of this merge. Earlier v2.1.4 records remain historical.

Status: local Linux harness bridge. The fake application adapter is removed. The [private credential baseline](private-credential-verification.json) is historical. The [session-expiry follow-up](session-expiry-verification.json) covers the later authorization repair. [Bridge verification](harness-bridge-verification.json) and [agent-first verification](agent-first-verification.json) describe older source. No production provider or hostile-host isolation is claimed.

## Native entrypoint

```text
credman serve --directory DIRECTORY --seed-fd SEED_FD --config-fd CONFIG_FD --admin-fd ADMIN_FD [--create] [--bridge-socket PATH]
credman mcp --session-file PATH
```

`DIRECTORY` is an existing dedicated absolute directory, owned by the current user with mode `0700`. `--create` never replaces existing state. The seed and trusted configuration enter through distinct private descriptors above standard IO. Administration and workload sockets cannot alias. Seed/configuration descriptors close after reading, unlisted descriptors close, and retained descriptors are close-on-exec.

The trusted configuration contains `owner`, `workspace`, `admin_principal`, and `peers`, each peer having `fd` and `principal`. Empty peers require a bridge socket. An optional `destinations` list defaults to empty and accepts at most 16 unique fixed HTTPS destinations. Each has `id`, `service`, `origin`, `path`, `auth` (`basic` or `bearer`), and optional `ca_file`. The old fake-destination registry is removed. The owner stops admitting requests after a 300-second deadline and serializes human control before workload processing. An in-flight operation and its bounded reply may finish afterward. It installs no daemon.

## Attachment and MCP

The private human channel supports `status`, `approve`, `revoke_task`, `audit`, `shutdown`, `issue_session`, and `revoke_session`. It also supports task-scoped `import_secret` (`task`, `request`, `kind`, `values`) and `read_secret` (`task`, `record`, `fields`). Only an authorized private human read can return `permission: secret.read` and secret fields. The human channel also accepts `mutate` with `Share`, including task-scoped `SecretRead` grants. After restore or recovery revokes old authority, approve a fresh human task and recipient task, then issue a new grant before reading an existing record.

`issue_session` takes `principal`, a nonempty `tasks` UUID allowlist, and `expires_at`. The private reply carries `session` with `id`, `socket`, `token`, and `expires_at`. The supervisor writes that document to an owned private regular single-link `0600` file under a `0700` directory. The token is not a record reference or root seed and must not enter config, argv, environment, chat, or logs.

`mcp` validates the file/endpoint and authenticates with the owner before a successful protocol initialization. The token attaches once. The owner binds principal, scope, task allowlist, and expiry independently of `clientInfo` or request arguments. `revoke_session` takes `session`, the UUID reference; only the human channel can call it. Disconnect/restart or consumed attachment requires fresh issuance.

The frontend implements bounded newline-delimited JSON-RPC with initialize/initialized, ping, tools/list, and tools/call. MCP stdout contains protocol only. The four tools map to workload operations:

| Tool | Arguments | Native op |
|------|-----------|-----------|
| `credman_generate` | task, request, kind, optional username | generate |
| `credman_mutate` | task, request, mutation | mutate |
| `credman_metadata` | task, record, fields | metadata |
| `credman_use` | task, usage | use |

The [harness guide](HARNESS-BRIDGE.md) has five configuration formats, lifecycle warnings, and source references. Harness type is compatibility metadata, not a new access-control role. One MCP connection can serve several conversations; that does not create several authenticated principals.

## Workload protocol

Native private channels use a four-byte big-endian length followed by bounded UTF-8 JSON. The decoder rejects duplicate keys, malformed/deep data, invalid lengths, and transport deadline violations. Workload identity belongs to the bound channel.

`generate` carries `task`, `request`, `kind`, and optional `username`. Login generation requires a public username and creates a private 32-character password. ApiKey generation forbids a supplied username and creates a private 32-character token. The same request UUID and specification returns the original receipt after restart; changed specifications conflict.

`mutate` carries `task`, `request`, and an externally tagged `Mutation`. Agent variants are metadata-only `Patch`, `Delete`, `Share`, `Revoke`, and untrusted `ReportOutcome`. The owner rejects raw `Create`, embedded `Generate`, secret-bearing `Patch`, and agent-issued `SecretRead` grants. Successful mutations return references and revisions, not secret values.

`metadata` carries `task`, `record`, and `fields`. Only approved `Label`, `Username`, and `Notes` fields are accepted. There is no MCP read tool. The owner rejects legacy workload `read` even when the task has `SecretRead`; human reads use the explicit private `read_secret` operation.

`use` carries `task` and `usage` (`PrivateUse`): `request`, `record`, `fields`, `destination`, and `action`. Only action `Use` is supported. The configured destination service and exact origin must match the approved task. Fields must exactly match Basic (`Username`, `Password`) or Bearer (`ApiKey`) authentication.

The owner prepares a fixed `/usr/bin/curl` HTTPS GET before final authorization, then supplies authorized values through private stdin. The model cannot choose a URL, header, CA file, or command. Responses return a receipt with delivery status, not credential fields or HTTP bodies. Redirects and automatic retries are disabled. Unknown outcomes are retained without redispatch, and HTTP acceptance is not verified login or registration. Unsupported actions and unknown destinations fail before durable delivery preparation.

Task approvals and grants restrict scope, fields, permissions, recipients, destinations, expiry, and pinned value versions. Cached mutations recheck current authority. References and request IDs are not bearer authority. Session allowlists do not replace domain authorization.

`audit` pages safe events using optional `offset`, returning `total` and `has_more`. It is bounded, not tamper-evident. Issuance replies are private authentication material and are not audit/model output.

## Offline human administration

```text
credman admin --directory DIRECTORY --seed-fd SEED_FD --identity-fd IDENTITY_FD backup --secret-fd SECRET_FD [--passphrase] --output-fd OUTPUT_FD
credman admin --directory DIRECTORY --seed-fd SEED_FD --identity-fd IDENTITY_FD restore --secret-fd SECRET_FD [--passphrase] --backup-fd BACKUP_FD
credman admin --directory DIRECTORY --seed-fd SEED_FD --identity-fd IDENTITY_FD recover
```

`IDENTITY_FD` contains trusted `owner`, `principal`, and `workspace`, not self-authentication. Inputs are distinct transferred resources. Backup output requires an empty private file/pipe and cannot alias an input. Secrets are capped at 4096 bytes, identity at 64 KiB, and backup input at 32 MiB. No backup/plaintext bytes are printed to ordinary admin stdout.

Backups are authenticated and encrypted using a seed or passphrase. Restore creates a new store without overwriting state, preserves records/history, revokes prior authority, and requires new approval. Restored records cannot register again. Recovery requires human scope and valid encrypted evidence and revokes authority. Never delete `pending.v2` or a recovery gate to force access.

## Executed synthetic acceptance

```bash
python scripts/check-isolated.py --work-dir /absolute/path/to/prepared-cache --agent-program-tests
```

The controller uses an offline namespace, synthetic home, exact current Cargo artifact, source hashes, and synthetic credentials. The credential-flow acceptance cases use real MCP subprocesses, one durable owner, and verified loopback TLS Basic/Bearer endpoints without a fake application or model/provider call. [Private credential verification](private-credential-verification.json) records their outcomes and source review. Prior installed-client diagnostics remain historical, and OpenCode runtime connection remains unverified.

The sandboxed-worker launcher remains separate reusable evidence. It is not proof that host-capable harnesses sharing the human's UID are isolated. Per-worker memory, PID, CPU, and tmpfs quotas remain absent. No real vault, provider, production deployment, or global configuration is part of validation. Existing bot-chat directories and ancestors are never cleanup targets.
