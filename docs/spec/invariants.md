# Crash-safety invariants

These are the properties every destructive consumer holds at every instant, including immediately after a crash at any point: the native consumer (`trunc-engine::consume`), the ZIP consumer (`zipconsume`, which ISO 9660 images also use) and the compressed-stream consumer (`streamconsume`). The ordering rule and recovery table below are the native consumer's; the sections after them give how the others differ. Each invariant is checked by the crash sweeps in `crates/trunc-engine/tests/consume.rs` (and `zipconsume.rs`, `isoconsume.rs` and `streamconsume.rs` for the others), which crash a consume at **every** operation index under three crash models (write-through, lose-unflushed, random subset of unflushed operations), with double crashes and torn writes. A change that weakens an invariant needs an ADR.

## Ordering rule

For every batch of blocks, in this order:

1. **Verify.** Read each block's footer and check it against the manifest. Check the payload hash.
2. **Decode** and check the decoded hash.
3. **Preallocate** each output up to the end of what this batch writes to it. If the destination is full, pause: nothing has been destroyed, and the archive is still a valid shorter `.trnc`.
4. **Write** the outputs into the staging folder `<dest>/.trunc-stage-<archive id>/`.
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
| I2 | Occupied space never exceeds `SpaceBound::consume_peak` for the batch size in use. | `FaultFs::peak()` compared to the bound after every sweep run. The planners are also property-tested on random inputs against a replay of each consume loop: `trnc_planner_never_underestimates_the_consume_peak`, `trnc_planner_holds_for_one_block_batches` and `trnc_bound_covers_a_file_released_half_written` in `tests/space_plan.rs`; `zip_planner_never_underestimates_the_consume_peak` and `zip_planner_holds_in_punch_mode` in `zipconsume`; `stream_planner_never_underestimates_the_consume_peak` in `streamconsume`. |
| I3 | Recovery is idempotent. | `crash_sweep_write_through_with_double_crashes` crashes again during recovery. Calling consume after completion is a no-op. |
| I4 | No output byte is ever read back as decoder input (blocks are independent). | By construction: the native consumer never opens staging files for reading (ADR-0001). The exception is a resumed xz or zstd stream consume, whose decoder window is read back from the staged output and the gap log and must match the CRC journaled with the checkpoint (`stream::restore_window`, ADR-0012). |
| I5 | Nothing is written outside the staging folder, the destination's top-level targets, or the archive's own files (`.trncr` note, `.receipt`; for the other consumers, the journal `.trncj` and the gap log `.trncg`). | `check_crash_state` lists every path after each crash. |

## Recovery (native format)

There is no journal. Every phase is recoverable from what is on disk:

| On disk after a crash | Meaning | What a rerun does |
|---|---|---|
| Archive length on block boundary `k` | Blocks `0..k` are durable at the destination | Continues from block `k`, redoing the interrupted batch |
| Staging folder exists | Extraction or renaming in progress | Recreates missing directories (skipping top-level items already moved), consumes the rest, renames what remains |
| No staging folder, archive fully consumed, resume note matches, all top-level items present | Renames are done | Turns the archive into a receipt and removes the note |
| Archive gone, note present | Only the note removal was interrupted | Removes the note |
| Archive gone, receipt present, contents in place | Already complete | No-op success |
| Archive partially consumed, no staging folder at this destination | Wrong destination | Refuses, naming the destination recorded in the resume note |

The resume note (`<archive>.trncr`) records the archive id and the destination. It is written durably before anything else and removed last. Correctness never depends on it: it only lets `trunc resume` find the destination and lets the error above name it.

An interrupted batch is always redone rather than verified and skipped. Its blocks are still in the archive, and redoing it costs at most one batch.

## Measured (10 GiB, NTFS)

`--consume` of a 10 GiB dataset compressed to a 5.81 GiB archive (lz4):

| | Predicted bound | Measured |
|---|---|---|
| Peak extra space | 4.39 GiB | 4.32 GiB |
| Normal extract, for comparison | 10.07 GiB | 10.00 GiB |

All 40 output files were identical to the source. `--consume` took 53 s; a normal extract took 60 s.

## ZIP archives and ISO images (ADR-0008, ADR-0015)

The same invariants hold for ZIP consumption, with these differences. I2's bound is `zip_space`'s `consume_peak_guaranteed`.

- **Order:** entries are processed in descending order of where their bytes end. After each entry, the archive is truncated to the furthest region end among entries still to do, then flushed.
- **Journal:** the journal (layout, identity, destination) is created atomically before the first truncation.
- **Punch mode:** within an entry, the order is: flush output → journal the inflate checkpoint → deallocate consumed input. The entry's CRC is verified before anything in it is deallocated.
- **Sweeps:** `crates/trunc-engine/tests/zipconsume.rs` crashes entry mode and punch mode at every operation under all three crash models, and with torn writes.
- **Mutation checks:** removing the output flush is caught by data loss. Deallocating before the checkpoint is journaled is caught by a corrupt stream on resume.
- **ISO 9660 images** are consumed by the same code, as a layout of stored entries. ISO 9660 has no checksums, so every file's CRC-32 is computed before the journal is created and stored in its layout; the check before release then compares against the image as it was when the consume started (`a_file_changed_before_extraction_is_caught_before_release`). The journal magic differs (`TIJP1`, against ZIP's `TZJP1`), so neither consumer resumes the other's journal. `crates/trunc-engine/tests/isoconsume.rs` sweeps entry mode and punch mode at every operation.

## Compressed tarballs and files (ADR-0011, ADR-0012, ADR-0013)

The same invariants hold, with these differences:

- **Order:** a read-only scan decodes everything first and records the checkpoint table, with a BLAKE3 hash of the content between consecutive checkpoints; the journal is then created. At each checkpoint: flush the outputs (and the gap log, for xz and zstd tarballs) → check that the content since the previous checkpoint hashes as it did in the scan → journal the decoder state → deallocate the compressed bytes before the checkpoint. The archive keeps its length until every output is durable, then is truncated to zero. A split archive loses whole parts instead, once a checkpoint passes their end.
- **Checkpoints depend only on the file and the interval**, never on the thread count, so the scan, the consume and any resume meet the same ones. A unit decoded ahead on a worker thread is used only at the position the sequential decoder has reached (`parallel_decoding_matches_sequential`).
- **Sweeps:** `crates/trunc-engine/tests/streamconsume.rs` (`crash_sweep`, `crash_sweep_every_codec`, `crash_sweep_single_file`, `crash_sweep_independent_units`, `crash_sweep_split_archive` and others) crashes at every operation and checks occupancy against the bound after each crash.

## What these invariants do not cover

- **Filesystems without a journal** (FAT32, exFAT): a crash during truncation can leave the size and cluster chain inconsistent. Destructive mode on them is opt-in (`--allow-unjournaled`).
- **Storage that ignores flush commands:** no software ordering can make it durable.
- **Snapshots** (VSS, APFS local snapshots, btrfs/ZFS): truncation frees nothing while a snapshot holds the blocks. I2 is about logical occupancy. `trunc plan` reports when snapshots could not be checked.
- **Process death vs power loss:** `killed_consume_resumes`, `killed_zip_consume_resumes`, `killed_iso_consume_resumes`, `killed_tgz_consume_resumes` and `killed_xz_and_zstd_consumes_resume` in `tests/cli.rs` kill real `trunc` processes mid-consume on the real filesystem. Lost unflushed writes (power loss) are covered only by the FaultFs models.
