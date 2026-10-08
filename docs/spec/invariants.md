# Crash-safety invariants

These are the properties the destructive consumer (`trunc-engine::consume`, plan phase 3) holds at every instant, including immediately after a crash at any point. The legacy ZIP consumer (phase 4) will hold them too. Each one is checked by the crash sweep in `crates/trunc-engine/tests/consume.rs`, which crashes a consume at **every** operation index under three crash models (write-through, lose-unflushed, random subset of unflushed operations), with double crashes and torn writes. A change that weakens an invariant needs an ADR.

## Ordering rule

For every batch of blocks, in this order:

1. **Verify.** Read each block's footer and check it against the manifest. Check the payload hash.
2. **Decode** and check the decoded hash.
3. **Preallocate** each output up to the end of what this batch writes to it. If the destination is full, pause: nothing has been destroyed, and the archive is still a valid shorter `.trnc`.
4. **Write** the outputs into the staging directory `<dest>/.trunc-stage-<archive id>/`.
5. **Flush data** of every output written in this batch (`FlushFileBuffers` / `fdatasync`).
6. **Flush directories** that gained entries in this batch.
7. **Truncate** the archive past the batch, retrying while another process has it memory-mapped. On Windows the allocation size is set as well, so the space is returned immediately rather than when the handle closes.
8. **Flush the archive.** Without this, a crash could resurrect blocks whose outputs already exist, and occupancy would exceed the bound. The sweep caught exactly this when the step was removed.

No step may be reordered past a later one.

The sweep is itself tested by mutation. Removing step 5, 6 or 8 makes it fail: steps 5 and 6 by losing data, step 8 by exceeding the space bound.

## Invariants

| Id | Invariant | Checked by |
|---|---|---|
| I1 | At every crash point, every content byte is recoverable from (remaining archive) ∪ (durable staging output). | Every sweep: after each crash and reboot, the resumed consume must produce a byte-identical tree. Blocks already truncated are never redone, so any lost byte would show. |
| I2 | Occupied space never exceeds `SpaceBound::consume_peak` for the batch size in use. | `FaultFs::peak()` compared to the bound after every sweep run. |
| I3 | Recovery is idempotent. | `crash_sweep_write_through_with_double_crashes` crashes again during recovery. Calling consume after completion is a no-op. |
| I4 | No output byte is ever read back as decoder input (blocks are independent). | By construction: the consumer never opens staging files for reading (ADR-0001). |
| I5 | Nothing is written outside the staging directory, the destination's top-level targets, or the archive's own files (`.trncr` note, `.receipt`). | `check_crash_state` lists every path after each crash. |

## Recovery (native format)

There is no journal. Every phase is recoverable from what is on disk:

| On disk after a crash | Meaning | What a rerun does |
|---|---|---|
| Archive length on block boundary `k` | Blocks `0..k` are durable at the destination | Continues from block `k`, redoing the interrupted batch |
| Staging directory exists | Extraction or renaming in progress | Recreates missing directories (skipping top-level items already moved), consumes the rest, renames what remains |
| No staging directory, archive fully consumed, resume note matches, all top-level items present | Renames are done | Turns the archive into a receipt and removes the note |
| Archive gone, note present | Only the note removal was interrupted | Removes the note |
| Archive gone, receipt present, contents in place | Already complete | No-op success |
| Archive partially consumed, no staging directory at this destination | Wrong destination | Refuses, naming the destination recorded in the resume note |

The resume note (`<archive>.trncr`) records the archive id and the destination. It is written durably before anything else and removed last. Correctness never depends on it: it only lets `trunc resume` find the destination and lets the error above name it.

An interrupted batch is always redone rather than verified and skipped. Its blocks are still in the archive, and redoing it costs at most one batch.

## Measured (10 GiB, NTFS)

`--consume` of a 10 GiB dataset compressed to a 5.81 GiB archive (lz4):

| | Predicted bound | Measured |
|---|---|---|
| Peak extra space | 4.39 GiB | 4.32 GiB |
| Normal extract, for comparison | 10.07 GiB | 10.00 GiB |

All 40 output files were identical to the source. `--consume` took 53 s; a normal extract took 60 s.

## ZIP archives (ADR-0008)

The same invariants hold for ZIP consumption, with these differences:

- **Order:** entries are processed in descending order of where their bytes end. After each entry, the archive is truncated to the furthest region end among entries still to do, then flushed.
- **Journal:** the journal (layout, identity, destination) is created atomically before the first truncation.
- **Punch mode:** within an entry, the order is: flush output → journal the inflate checkpoint → deallocate consumed input. The entry's CRC is verified before anything in it is deallocated.
- **Sweeps:** `crates/trunc-engine/tests/zipconsume.rs` crashes entry mode and punch mode at every operation under all three crash models, and with torn writes.
- **Mutation checks:** removing the output flush is caught by data loss. Deallocating before the checkpoint is journaled is caught by a corrupt stream on resume.

## What these invariants do not cover

- **Filesystems without a journal** (FAT32, exFAT): a crash during truncation can leave the size and cluster chain inconsistent. Destructive mode on them is opt-in (`--allow-unjournaled`).
- **Storage that ignores flush commands:** no software ordering can make it durable.
- **Snapshots** (VSS, APFS local snapshots, btrfs/ZFS): truncation frees nothing while a snapshot holds the blocks. I2 is about logical occupancy. `trunc plan` reports when snapshots could not be checked.
- **Process death vs power loss:** `tests/cli.rs::killed_consume_resumes` kills real `trunc` processes mid-consume on NTFS. Lost unflushed writes (power loss) are covered only by the FaultFs models.
