# ADR-0015: ISO 9660 images

Status: accepted (2026-10-11).

## Context
Disc images (`.iso`) are large, uncompressed containers: a 4-50 GB image extracts to almost
exactly its own size, so extracting one next to itself needs the whole image's size again in
free space. Like a ZIP of stored entries, each file is one contiguous byte range of the image,
and the directory records that describe them are small. The format comes from optical media and
was never designed for hostile input: directory extents can point anywhere, including at an
ancestor directory.

## Decision
- **Files become stored ZIP entries.** `trunc_legacy::iso` parses the image into a
  `zip::Layout` whose file entries are `Stored`, with region = data. Directories, symlinks and
  empty files get empty regions at offset 0 (an empty file's extent is meaningless and often
  points into other data). Extraction, planning and consumption are the ZIP code
  (ADR-0008) unchanged: same ordering by region end, same truncation rule, same journal with its
  two checkpoint slots, same punch mode for large files. `zipconsume::Format` supplies only the
  scan, the journal magic (`TIJP1`; ZIP's is `TZJP1`, so neither consumer resumes the other's
  journal) and the overlap message.
- **CRCs are computed before consuming.** ISO 9660 has no checksums, but the ZIP consumer checks
  a CRC-32 before releasing any entry. On a fresh start every file is read once and its CRC
  stored in the journal's layout. A file whose bytes change between the scan and its extraction
  (or a resume) is refused before its source is released, and `--verify-media` has something to
  compare against. Plain extraction skips this pass; `verify` checks structure only.
- **Names.** The tree is walked from the root directory record, never the path table. Rock
  Ridge (`NM`, with `CE` continuation areas) is used when the root's `.` record carries the
  SUSP indicator and Rock Ridge fields; else a Joliet supplementary volume (escape sequences
  `%/@`, `%/C`, `%/E`; names decoded as UTF-16); else plain names with the `;N` version and the
  extension-less trailing dot stripped. Every path then goes through NFC and `validate_host`,
  with the same duplicate (host case rules) check as ZIP and tar. Rock Ridge modes (`PX`) are
  kept; symlinks (`SL` or a link mode) are skipped like every other format's; devices, FIFOs
  and sockets are skipped; relocated directories (`CL`/`RE`) are listed where they belong.
  Hidden files are extracted; associated files (resource forks) are skipped.
- **Multi-extent files** (consecutive records of one name with the multi-extent flag) are joined
  when each section but the last is whole sectors and the sections are contiguous, which is what
  authoring tools write. Non-contiguous sections are refused as unsupported: a ZIP entry is one
  byte range.
- **Shared and overlapping data.** Files whose extent is exactly another file's are hard links
  (`genisoimage` caches inodes by default; `xorriso` can deduplicate). Plain extraction copies
  each one in full. Consuming them, like any overlap, needs `--allow-overlap`; the ZIP
  consumer's truncation rule then handles them correctly (punch mode is off when anything
  overlaps). Partial overlaps are never written by real tools: `verify` fails and extraction
  refuses them unless `--allow-overlap`.
- **Hostile images are bounded.** A directory extent visited twice (a loop or two directories
  sharing records), overlapping directory extents, file data overlapping directory records and
  extents past the end of the file are refused. So are more than 2^21 entries, 512 MiB of
  directory records, 256 levels, 16 chained continuation areas or 64 KiB of system-use data per
  record. A random-corruption test parses thousands of damaged images without a panic.
- **What is refused.** UDF-only images (a UDF recognition sequence and no ISO 9660
  descriptors) get a clear "UDF is not supported" message; hybrid ISO/UDF images use the ISO
  9660 side. Also refused: logical blocks other than 2048 bytes, multi-volume sets and
  interleaved files.

## Consequences
- Consuming reads every file twice (scan, then extraction) and large punch-mode files three
  times, since the ZIP consumer verifies them before punching. The extra reads buy the
  "unchanged since the scan" check that ISO 9660 cannot provide itself.
- Consuming an image with hard links needs `--allow-overlap`, and the image then cannot use
  punch mode; peak extra space is the largest group of files instead of one checkpoint interval.
- El Torito boot images and HFS/APM hybrid partitions are not extracted as such; only the files
  in the ISO 9660 tree (which normally include the boot image and catalog) are.
