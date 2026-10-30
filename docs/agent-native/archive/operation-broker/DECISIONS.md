# Agent-native Credman: scope and decisions

Status: design phase. No runtime implementation, toolchain installation, account provisioning, service deployment, or vault migration is authorized in this phase.

## Confirmed product direction

The user selected these requirements:

- Broker approved credential use. Do not return raw secrets by default.
- Run an isolated local broker under a service identity separate from agent workloads.
- Keep the current phase design-only. Do not install Rust or any other dependency.

The design must make credential use an explicit authorized operation. A machine-readable wrapper around `get --password-only` does not meet the selected goal.

## Existing project

Discovery started from clean `main` at commit `510c2a0`.

- Credman is a Rust binary. `src/main.rs` routes into `cli::run`; no separate service or library entry point is present.
- `README.md` and `SECURITY.md` describe a single-user, offline CLI and TUI, human BIP39 unlock, Argon2id key derivation, and AES-256-GCM vault encryption.
- `src/vault.rs` owns the file format and an exclusive advisory lock held across an unlocked session. This ownership rule constrains a future service and concurrent human clients.
- `src/model.rs::Entry` contains plaintext credential fields while unlocked and derives `Serialize` and `Debug`. Do not reuse this type as an agent response or audit record.
- `src/cli.rs::Cli` accepts `--seed`, and human commands can deliberately reveal passwords. Those human interfaces are not an acceptable default agent transport.
- `SECURITY.md` explicitly excludes compromise by another process with equivalent OS-user privileges. Adding an agent name field cannot change that boundary.

These observations concern source code and documentation only. No real vault, seed, stored credential, authentication file, or personal credential directory was opened. Rust and Cargo are unavailable on the current command path and in the checked standard user-local locations. No build or test baseline has been run, and no installation is attempted.

## Design constraints

1. The broker owns credential material. Agent-facing messages contain operation requests and safe results, not vault keys, seeds, or credential records.
2. Workload identity must come from an authenticated execution boundary. A caller-supplied bot name is metadata, not proof of identity.
3. Separate agent access from human administration and approval. Current same-login Hermes profiles do not provide this separation by themselves.
4. Model content, repository files, provider responses, and tool descriptions cannot grant permission, change policy, or select an arbitrary credential destination.
5. Preserve a single owner for mutable vault, grant, and audit state. Keep failed, denied, pending, successful, and outcome-unknown operations distinct.
6. A design proposal is not a security guarantee. Isolation, non-disclosure, revocation, durability, and migration claims need explicit implementation tests before release.

## Source-level extraction risks

Read-only tracing identified these behaviors to cover before the service is implemented:

- `UnlockedVault` owns the key, plaintext data, and session lock, but exposes mutable fields (`src/vault.rs:261–268`). Keep that state behind the service's ownership boundary.
- `UnlockedVault::replace` removes an existing vault before deriving and validating the new key (`src/vault.rs:277–303`). Existing CLI flows perform prior confirmation and validation, but the storage API is not failure-atomic. Do not expose replacement as an agent operation. Add failure-preservation tests before any refactor reuses it differently.
- CLI and TUI combine prompts, mutation, persistence, and presentation. TUI form-save restores the previous state on persistence failure, while deletion retains a dirty changed state for a later retry (`src/tui/app.rs:499–545`). Define one application-level commit contract before adding a machine client.
- Human `get` prints password and notes by default; `list --secrets` also exposes passwords (`src/cli.rs:694–747`). A new agent API must use separate safe response types, not adapt these output paths.
- Vault envelope version, plaintext data version, and protocol version are separate concepts. Preserve the existing outer format and stored KDF parameters during an initial extraction. Review unknown plaintext-version behavior before introducing new schema versions.
- Existing vault disk tests use disposable directories. Some TUI tests construct a relative `vault` path and inspect its existence. A future test run needs an isolated working directory and explicit synthetic vault paths. No tests have been run in this phase.

These are source-based design risks, not reproduced exploit claims or a full security audit. No runtime fixes are included in this design phase.

## Provisional compatibility direction

Retain the current encrypted vault format and human recovery flow unless a demonstrated requirement forces a reviewed migration. Keep the CLI and TUI useful as human administration clients. A future agent service must not silently migrate or overwrite an existing vault.

Compatibility is a proposal, not a completed migration. The design comparison must decide how human clients cooperate with a service that owns the vault lock.

## Decisions still needed before implementation

- The first real provider and credential-backed operation to support.
- The supported workload isolation mechanism and authenticated principal mapping on the target host.
- How the human unlocks and approves grants through a control path unavailable to agents.
- Whether any future raw-secret escape hatch is acceptable. The selected default is no agent secret-read operation.
- Which existing human commands remain unchanged, and which become broker clients while a service is active.

No installation or implementation begins merely because this document lists those decisions. The architecture proposal, threat model, migration sequence, and acceptance gates must be reviewed first.
