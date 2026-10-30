# Historical two-real-agent demonstration

This is execution history for the earlier fake-application prototype, not a launch guide for the current harness bridge. The fake adapter, fake application, and executable demo helper are retired. Use the [harness guide](HARNESS-BRIDGE.md) and [current verification](harness-bridge-verification.json) for the supported interface.

The [recorded playback](demo/two-agent-demo.html) and [evidence JSON](demo/evidence.json) are preserved unchanged. Backend Engineer and Security Engineer performed eight real actions. All 16 functional/privacy checks passed, including before-grant and post-revocation denials. The session then failed during shutdown.

- The actual workflow used helper `5227457aea3ccdc83743e63ba5dc8eaed82f05b084625d0b4774d1ca4cf9a462`. Immediate post-ACK termination produced broker exit -15 and controller exit 1. Its `complete:false` is not relabelled.
- The bounded-wait helper `645bb4b6bb3f9e45dc7f62f14f10a1f272c5eb1fe1d02b51a070acb89bd862df` was verified by a separate lifecycle-only native check with broker exit 0. The real-agent authorization workflow was not repeated.
- The later entrypoint-only helper change to `serve` had hash `ac22a9a93ebb5b322434cb2ad0fcb1ad3435de245e9be3c921623289d6969ff2`. It did not create a new real-bot workflow result.
- The executable used for the original workflow/lifecycle evidence was `a84dc7014b546e16c7f3e35f6bc249808dab743cb59c445454318222aa8ad968`. New bridge source and binaries require their own evidence.

The two host-capable bots were trusted operators under the same Unix account, not isolated authenticated workloads. Their bridge sockets were routing, not a hostile-host security boundary. Passwords were generated inside the trusted helper and shared as record references. Child output was suppressed, not measured empty.

The viewer remains recorded playback with real event/tool lineage and explicit failure notes. Re-rendering it does not execute the old application. Preserve its evidence and all bot-chat working directories and ancestors.
