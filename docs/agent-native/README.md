# Agent credential vault and harness bridge

The [repository README](../../README.md) describes the current product. One encrypted owner serves scoped agent clients through MCP stdio frontends. The terminal prototype and fake application adapter are removed.

## Current references

- [Harness integration](HARNESS-BRIDGE.md): session provisioning, five supported configuration shapes, and lifecycle/disclosure limits.
- [Runtime and protocol](AGENT-RUNTIME.md): native supervisor bootstrap, authenticated attachment, MCP tools, and offline administration.
- [Implementation contract](PROGRAM-CONTRACT.md): ownership, policy, persistence, and verification boundaries.
- [Security model](../../SECURITY.md): trusted components, session custody, disclosure, and remaining gaps.
- [Bridge verification](harness-bridge-verification.json): exact current source/binary/client checks and independent review.

## Historical evidence

[Agent-only refactor verification](agent-first-verification.json), the [earlier program record](program-verification.json), the [first storage slice](IMPLEMENTATION-STATUS.md), and [two-real-bot evidence](demo/evidence.json) remain execution history. They are not current compatibility, private-provider integration, or production claims. The [playback guide](TWO-AGENT-DEMO.md) identifies the retired fake application launch and its recorded failures.
