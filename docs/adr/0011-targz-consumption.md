# ADR-0011: Consuming .tar.gz archives

Status: accepted (2026-10-09)

## Context
Most large downloads on Linux are `.tar.gz`, not ZIP. A gzip stream has no index and can only be
decoded from the start. ZIP's approach (process entries from the end, truncate after each) does
not apply, and a gzip file records no sizes, so the space a run needs is unknown until it has been
decoded.

## Decision
- **Consume from the front.** Decode forward and deallocate (punch) the compressed bytes already
  used, keeping the file length. Truncate to zero only when every output is durable, then delete.
  This reuses ZIP punch mode's checkpointing DEFLATE decoder and the journal (ADR-0008).
- **Scan first.** A read-only pass decodes everything once: it checks every gzip member's CRC-32
  and size, parses and validates every tar header and name, and records the checkpoint table.
  Nothing is written, so a corrupt or hostile archive is refused while it is still whole. The
  scan also yields the exact sizes the space planner needs.
- **Checkpoints are deterministic.** A checkpoint falls at the first DEFLATE block boundary after
  `checkpoint_every` bytes of output, or at a gzip member boundary once that much has been
  produced since the last one. The positions depend only on the archive and the interval, so the
  consuming pass, and any resumed pass, meets exactly the checkpoints the scan recorded.
- **Hash each interval.** For every checkpoint, the scan stores the BLAKE3 of the file content
  between it and the previous one. Before a checkpoint is journaled and its bytes freed, the
  consuming pass must have produced the same hash. If the archive changed between the passes, or
  a read went wrong, consumption stops before freeing anything it did not verify.
- **Journal per checkpoint:** decoder state (bit position, 32 KiB window, member offsets) and the
  free-below offset. Resuming restarts from it, truncates the file being written at that point,
  and rewrites any later output.
- **Refuse what cannot be represented safely.** Hard links (they would need copies or links
  created outside the staging protocol), GNU sparse files, multi-volume archives, data after the
  end-of-archive marker, and unknown entry types are refused. Symlinks and device entries are
  skipped, as for ZIP. (Hard links and sparse files are extracted since ADR-0015.)

## Consequences
- A `.tar.gz` is decoded twice when consumed, and `plan`, `inspect` and `verify` each decode it
  once. On filesystems that cannot deallocate ranges, `--consume` saves nothing but still works.
- Peak extra space is about *output − archive*, plus one checkpoint interval of compressed data.
- The journal preamble grows with the number of entries and checkpoints (about 48 bytes per
  64 MiB of output plus about 50 bytes per entry), and is capped by the tar reader's entry limit.
