# Crash-safety invariants

These are the properties the destructive consumer (plan phase 3) and the legacy ZIP consumer (phase 4) must hold at every instant, including immediately after a crash at any point. Each has a named check in the crash harness (`trunc-testkit`, phase 3). A change that weakens one needs an ADR.

## Ordering rule

For every batch of blocks, in this order:

1. **Verify.** Read the footer at end of file and check it against the manifest. Check the payload hash.
2. **Decode** and check the decoded hash.
3. **Preallocate** the outputs for the batch. If this fails for lack of space, pause; nothing has been destroyed.
4. **Write** the outputs into the staging directory.
5. **Flush data** of every output touched (`FlushFileBuffers` / `fdatasync`).
6. **Flush directories** that gained entries (`fsync(dirfd)`; directory-handle flush on Windows).
7. **Truncate** the archive past the batch, retrying while another process has it memory-mapped.

No step may be reordered past a later one. In particular, truncation never happens before steps 5 and 6 have completed for every block in the batch.

## Invariants

| Id | Invariant | Harness check |
|---|---|---|
| I1 | At every crash point, every content byte is recoverable from (remaining archive) ∪ (durable staging output). | `inv_no_byte_lost` |
| I2 | Occupied space never exceeds `SpaceBound::consume_peak` for the batch size in use. | `inv_peak_within_bound` |
| I3 | Recovery is idempotent: running it twice gives the same state as running it once. | `inv_recovery_idempotent` |
| I4 | In native mode, no output byte is ever read back as decoder input (blocks are independent). | `inv_block_independence` |
| I5 | Nothing is written outside the staging directory before the rename phase, and no rename targets a path outside the destination. | `inv_writes_confined` |

## Recovery (native format)

Recovery needs no journal for block progress:

1. Open the archive. Its length gives `k`, the number of blocks consumed (format spec section 10). A length off a block boundary is a hard error. It cannot result from the ordering rule on a journaled filesystem.
2. Blocks `< k` were durable before they were truncated, so there is nothing to do for them.
3. For block `k`: hash the staging bytes its runs cover. If they match `blake3_u`, the block was written but not released, so truncate. Otherwise redo it from step 1 of the ordering rule.
4. Continue.

The journal (`journal-v1.md`) is used only for the final staging-to-destination rename phase and to record a pause for lack of space.

## What these invariants do not cover

- **Filesystems without a journal** (FAT32, exFAT): a crash during truncation can leave the size and cluster chain inconsistent. Destructive mode on them is opt-in (`--allow-unjournaled`).
- **Storage that ignores flush commands:** no software ordering can make it durable.
- **Snapshots** (VSS, APFS local snapshots, btrfs/ZFS): truncation frees nothing while a snapshot holds the blocks. I2 is about logical occupancy, and the CLI warns when snapshots are detected.
