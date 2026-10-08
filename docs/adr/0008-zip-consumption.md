# ADR-0008: Destructive ZIP extraction

Status: accepted (2026-10-08)

## Context
ZIP stores entries front to back and puts its index (the central directory) at the end, so it cannot be consumed by plain end-truncation the way `.trnc` is. Two problems follow:
- the index is the first thing truncation would destroy;
- a single huge entry would need its whole output written before any of its input could be released.

## Decisions

**Order and truncation rule.** Entries are processed in descending order of the end of their byte region: local header to end of data, plus any data descriptor. After each entry is extracted and flushed, the file is truncated to the furthest region end among the entries still to do. This one rule handles gaps, self-extractor prefixes and overlapping entries alike: it never cuts bytes another entry still needs. Overlapping archives are still refused unless `--allow-overlap` is given, because overlap is a zip-bomb technique.

**Journal.** Before the first truncation, the parsed layout, the archive's file identity and size, and the destination are stored in `<archive>.trncj`: an immutable preamble plus two alternating checkpoint slots. The journal is written under a temporary name and renamed into place. The crash sweep found that a crash midway through creating it in place left an unreadable journal. As with `.trnc`, the archive's length determines which entries are done (ADR-0007); the journal supplies what the truncated central directory no longer can.

**Punch mode.** For entries with a compressed size of at least `--punch-min` (default 256 MiB), on filesystems that can deallocate ranges and with no overlaps, space is freed inside the entry as it decompresses. After each checkpoint (default every 64 MiB of output) the order is:
1. flush the output;
2. write the inflate state (bit position, 32 KiB window, CRC) to the journal;
3. deallocate the compressed bytes already consumed.

Steps 2 and 3 must not swap. The punch-mode sweep under the write-through crash model fails when they do: resuming from the older checkpoint reads zeroed input.

Before punching starts, the whole entry is decoded once without writing, to check its CRC. Without this, a corrupt entry would be discovered only after part of it was destroyed.

**Own DEFLATE decoder.** Library inflaters keep their state private, so it cannot be persisted. `trunc-legacy::inflate` checkpoints at block boundaries, where the state is just bit position + window + CRC. It is tested against flate2 at every compression level and fuzzed.

**No receipt.** After the last entry, the file is truncated to zero and removed; then the journal is removed.

## Consequences
- Other ZIP tools cannot open the file after the first step. The confirmation prompt says so.
- The guaranteed space bound gives no credit for punching, since that depends on how compression is spread through an entry. `trunc plan` shows the expected figure, assuming compression is spread evenly, alongside the guaranteed one. If punching frees less than expected, consumption pauses safely when the disk fills.
- Supported: Stored and Deflate, Zip64, data descriptors, CP437/UTF-8/Info-ZIP Unicode names, Unix modes. Refused: encryption, other methods, multi-disk archives. Symlink entries are never created.
- Running consume again after a ZIP job has fully finished reports the archive as not found. Nothing of it remains to prove the job completed, which is the point of destructive extraction.
