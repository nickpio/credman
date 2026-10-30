# Durability boundary for the first storage slice

The initial fix targets deterministic failures **before publication**. It does not establish crash/power-loss durability, general network-filesystem semantics, or a complete publish-state API.

The current writer syncs the temporary file and then calls rename. It has no fallible operation after a successful rename. Therefore this slice must not casually add parent-directory sync followed by ordinary rollback-on-error: directory-sync failure would happen after the new file is already visible.

There is a further caveat. A rename error is not universally proof that nothing changed. POSIX excludes EIO from its usual destination-unchanged error guarantee, and network filesystems have additional ambiguity. The current generic error API does not classify these outcomes. Existing and newly tested pre-write failure rollback must not be advertised as handling every rename/I/O failure.

Before the future credential/grant service can rely on commits, define explicit outcomes such as not-published, published-durable, published-durability-unknown and publication-unknown. On uncertain publication/durability, freeze/reconcile instead of automatically restoring stale memory or rewriting the old image. Rekey/replacement recovery must retain the necessary unlock material until the outcome is reconciled.

The fuller writer also needs a unique securely created sibling temporary file, explicit create-only versus replace semantics, private-directory guarantees, and parent-directory synchronization. Existing fixed-name temp and cooperative lock behavior are not upgraded by this first minimal patch. The lock is already on a separate `.lock` file, not the inode being replaced.

Researcher proposed synthetic fault injection before rename and after a real rename at directory sync. Those are next-stage tests, not executed crash experiments. The current task's tmp-path obstruction exercises a definite pre-publication write failure only. The scratch filesystem was observed as Btrfs; that observation does not prove durability.

## Verified primary references

The caller independently retrieved these pages and checked the relevant quote in each. The private receipt is `/home/nick/.hermes/cache/scratch/credman-storage-20261024/research-verification.json`.

- Rust rename behavior: https://doc.rust-lang.org/std/fs/fn.rename.html
- Linux fsync and the separate directory-sync requirement: https://man7.org/linux/man-pages/man2/fsync.2.html
- POSIX rename error guarantees, including the EIO exception: https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html

The complete research is retained under Researcher's `credman-rust-storage-durability-20261024-v1` packet. Documentation findings are not filesystem execution proof, and the suggested richer API is not implemented in this slice.
