# Agent credential vault and harness bridge

The [repository README](../../README.md) describes the current product. One encrypted owner serves scoped agent clients through MCP stdio frontends. The terminal prototype and fake application adapter are removed.

## Current references

- [Harness integration](HARNESS-BRIDGE.md): session provisioning, five supported configuration shapes, and lifecycle/disclosure limits.
- [Runtime and protocol](AGENT-RUNTIME.md): native supervisor bootstrap, authenticated attachment, MCP tools, and offline administration.
- [Implementation contract](PROGRAM-CONTRACT.md): ownership, policy, persistence, and verification boundaries.
- [Security model](../../SECURITY.md): trusted components, session custody, disclosure, and remaining gaps.
- [Bridge verification](harness-bridge-verification.json): historical source/binary/client checks and independent review; these predate private generation.

## Historical evidence

[Agent-only refactor verification](agent-first-verification.json), the [earlier program record](program-verification.json), and the [first storage slice](IMPLEMENTATION-STATUS.md) remain execution history. They are not current compatibility, provider integration, or production claims. Retired fake-application demos and superseded operation-broker designs are available in Git history.
