# Agent-first refactor scope

This refactor removes the unused terminal prototype rather than preserving compatibility. The [implementation contract](PROGRAM-CONTRACT.md) and [runtime reference](AGENT-RUNTIME.md) describe the supported application.

## Source preservation

Preserve the current uncommitted source before deleting prototype files. Do not stash, reset, relocate chat workspaces, or modify actual vault data. Historical verification records remain evidence, not a second supported product.

## Application changes

1. Replace the interactive command tree with `serve` and offline `admin {backup,restore,recover}`. Remove aliases and global seed or vault options.
2. Remove the TUI, clipboard, USB, v1 vault and backup formats, importer, receipts, legacy attachments, and unused dependencies. Retain shared crypto and the agent-only state owner.
3. Preserve restore authority revocation and immutable registration-blocking provenance. Keep bounded decoding, descriptor checks, publication gates, and explicit human recovery.
4. Move test setup off the importer onto native records. Delete only prototype-specific tests, not backup, corruption, authorization, recovery, or data-loss assertions.
5. Update the runner registry, native callers, demo launch, and current documentation. Keep the recorded real-bot evidence labelled historical.

## Acceptance

Run the affected controller guards, agent Rust checks, and native executable cases against synthetic state with no host credentials or network. Bind execution to the Cargo artifact and record exact hashes. Review the changed trust and persistence boundaries independently once; expand checks only for a concrete uncovered risk.

The [verification record](agent-first-verification.json) contains actual outcomes and remaining limits. No commit, push, service installation, real-provider signup, or real-vault migration is included.
