# First storage-hardening slice

Historical execution record for the removed terminal prototype. Commands and source paths below refer to that earlier code, not the current executable. Use the [runtime reference](AGENT-RUNTIME.md) for current commands. This record covers the initial v1 fixes. Current synthetic v2 implementation and limits are documented in the [runtime reference](AGENT-RUNTIME.md) and [program verification](program-verification.json). Counts and lint comparisons below apply only to this earlier slice.

## Scope and result

The user approved Rust/Cargo installation and the first storage fixes using synthetic vaults only. Work is on `agent-native/storage-foundation`.

Implemented:

- Keep the old encrypted vault until the current temp-write/sync/rename path publishes its replacement. Creation still rejects an existing vault under the lock.
- Restore a failed TUI deletion at its original index, preserving the prior dirty flag and coherent filter/error state.
- Announce CLI edit success only after persistence succeeds.

Each defect was reproduced by a failing regression before its fix. The CLI checks drive the actual executable through a synthetic PTY and explicitly decline clipboard copy and password display.

No format, KDF, encryption primitive or public CLI flag changed. No record/grant schema, agent API/service, principal provisioning, site signup, real credential access or real-vault migration was introduced. Nothing was pushed or deployed.

## Executed verification

| Check | Actual result |
|---|---|
| Original `510c2a0` Rust baseline | 64 passed; no failures |
| Replacement before/after fix | Reproduced removal of the original vault; fixed test preserves encrypted bytes and the old unlock after a blocked write |
| TUI deletion before/after fix | Reproduced missing in-memory entry; fixed test preserves entry order, both prior dirty states, filtered index, error state and disk bytes |
| Actual CLI edit before fix | Failure case printed success despite a write error; positive case passed |
| Actual CLI edit after fix | Both checks passed, including reopened metadata and no success message on failed persistence |
| Final Rust unit suite | 66 passed; no failures |
| Runner guard/controller suite | 8 passed |
| Real fetch-only check | One locked fetch command; no build/test command queued |
| Strict Clippy, all targets | Fails on baseline and current tree; normalized diagnostics match with no new group |
| Rustfmt check | Fails on both trees with the same 25 existing formatting hunks and no new hunk |

The [storage verification receipt](storage-verification.json) records commands, outcomes, hashes and limitations. The security source review found no new runtime regression in the three fixes. It identified two medium runner findings, both reproduced and fixed. Fetch-only no longer queues execution, and CLI checks reject custom Cargo arguments instead of risking a stale binary. An independent source-only closure review of the runner fixes passed with no findings. That review did not rerun the tests or reassess the unchanged runtime code.

The fetch command-planning unit check stubs the Cargo boundary. A separate real fetch-only invocation verified the single fetch receipt. Rust and CLI results above came from real execution, not that stub.

## Build environment and repeatable checks

User-local tools were installed from the official rustup distribution after checking its published SHA-256:

```text
rustc 1.99.1 (58cf8f9c3 2026-10-13)
cargo 1.99.1 (5f94df478 2026-08-27)
```

Rustfmt and Clippy are installed. The initializer required the basename `rustup-init`; the renamed multicall binary was rejected before installation and retried under the proper name. `--no-modify-path` left shell startup configuration unchanged. Tools are under `/home/nick/.cargo/bin/`; the runner resolves the installed compiler through rustup without requiring a PATH edit.

On Linux with Bubblewrap/user namespaces, Python 3, Git, a C linker and the user-local Rust toolchain, run from the repository:

```sh
# Fetch locked crates only. This command does not build or test.
python scripts/check-isolated.py --fetch

# Reuse a dedicated cache with --work-dir PATH if desired.
python scripts/check-isolated.py
python scripts/check-isolated.py --cli-regressions
python -B tests/check_isolated_runner.py

# Reproduce known baseline quality-gate failures without changing checkout.
python scripts/check-isolated.py --revision 510c2a0 clippy --all-targets -- -D warnings
python scripts/check-isolated.py fmt -- --check
```

The default cache is beneath TMPDIR, or `~/.cache` when TMPDIR is absent. Nonempty unmarked caches, mismatched repository markers and symlinked cache directories are refused. Each run gets a private source snapshot, avoiding shared staging-file races; snapshots are removed on normal exit. Cargo/target caches and execution receipts remain in the dedicated task cache.

The runner clears the environment, closes inherited stdin, hides the host home and user runtime/desktop sockets, uses a synthetic home, exposes source/toolchain read-only, and limits build/test concurrency to two. Its probe checks those boundaries and an empty network route table. Only locked crate fetch is network-enabled; compilation and tests are offline in a new network namespace. No actual clipboard, USB device or systemd user service is exposed.

CLI-check mode builds the `credman` target and reads its Cargo `compiler-artifact` record. It copies that executable into the private read-only source snapshot and records its SHA-256 before execution. The check does not execute a fixed shared-cache path. Fetch, probe, and CLI-check modes reject Cargo arguments and cannot be combined.

This isolates project test execution, not the coordinator/specialist bots. It is not the future authenticated agent/vault boundary, a full resource/cgroup sandbox, or a portable runner. The eight guard/controller cases do not exhaust every malicious filesystem race. No cryptographic or power-loss security proof is claimed.

## Remaining gates

The inherited writer still has a fixed-name temp file, generic errors and no parent-directory sync or explicit ambiguous-publication state. Tests inject definite pre-publication write failure; they do not simulate power loss, rename EIO or network-filesystem ambiguity. See [durability notes](STORAGE-DURABILITY-NOTES.md).

Before the credential/grant service, implement the richer commit/recovery contract, secure temp creation and vault/backup schema guards, followed by the shared application owner, records/grants, private adapters and authenticated workload isolation. Those features are not complete in this slice.
