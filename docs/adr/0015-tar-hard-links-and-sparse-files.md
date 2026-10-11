# ADR-0015: Hard links and sparse files in tarballs

Status: accepted (2026-10-11). Amends ADR-0011, which refused both.

## Context
ADR-0011 refused hard links ("they would need copies or links created outside the staging
protocol") and GNU sparse files. Both are common in real tarballs: toolchains, Git and Python
installs hard-link identical files, and disk images, databases and VM images are archived
sparse (`tar -S`). Refusing them sends users back to `tar`, which needs the archive and the
output on disk at the same time.

## Decision
- **Parsing.** Type `1` entries are hard links; the target comes from the header, a GNU `K`
  entry or a PAX `linkpath`. The target is validated like an entry name and must be an earlier
  regular file of the same archive (a link to a link leads to its file). Sparse files are read
  in the old GNU format (type `S`, map in the header and extension headers) and in the PAX
  formats 0.0, 0.1 and 1.0 (`GNU.sparse.*` records; for 1.0 the map is at the start of the
  data and counts as tar metadata, not content). A map must be sorted, non-overlapping, inside
  the real size and cover exactly the stored bytes. An archive may hold at most 2^20 map
  segments in all (24 bytes each in memory and in the journal); a larger PAX 1.0 count is
  refused when read. The entry list in the journal gains two entry kinds with extra fields, so
  journals without links or sparse files are encoded as before.
- **Sparse files.** The decoded stream holds only the data segments, so the content map,
  checkpoints and interval hashes are unchanged. The router writes each piece of stored content
  at its offset in the file. A new output is first deallocated beyond its current end: this
  marks it sparse where the filesystem needs that (NTFS), so writing past the end and the final
  `set_len` to the real size leave holes instead of allocating (or writing) zeros. On resume the
  file is cut back to where its first unconfirmed byte goes. Window restore and media
  verification read stored content back through the same map. A sparse file with no data is
  created at its real size as a hole.
- **Hard links.** Links are made after everything is decoded and durable (for a single
  archive, after it is truncated to zero) and before anything is renamed into place, inside the
  staging directory, from the staged target. `FsBackend::hard_link_beneath` confines both paths
  (Linux: `linkat` between directories opened with `openat2`; elsewhere: checks first), and the
  engine then opens the new name confined and requires the target's file id, removing it
  otherwise. Where the filesystem refuses (FAT, exFAT, too many links) the link becomes a copy;
  a copy of a sparse file copies only its segments. Links and copies are flushed with their
  directories before renaming starts. A resumed run that finds renaming begun knows the links
  were made; otherwise it keeps an existing name that is the target's file, keeps a copy that
  matches the target, and redoes any other copy. A link takes the target's mode.
- **Space.** Sparse files count their stored data (rounded to clusters per segment). Hard links
  cost nothing where the destination filesystem has them; on FAT and exFAT each costs a copy of
  its target, at the end, when the archive is gone but the gap log still exists.

## Consequences
- An NTFS sparse file allocates in 64 KiB compression units, so a map of many small segments
  can take more space than the plan's cluster rounding says; the safety margin absorbs small
  cases.
- On Windows, linking is checked after the fact rather than confined atomically, as for every
  other confined operation there (ADR-0010 describes the Linux side).
- Multi-volume archives stay refused.
