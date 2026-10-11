# Journal format, version 1 (`<archive>.trncj`)

Status: implemented in `trunc-journal`. Used by ZIP consumption (ADR-0008), ISO 9660 image consumption (ADR-0015) and consumption of compressed tarballs and files (ADR-0011, ADR-0012, ADR-0013). Native `.trnc` consumption needs no journal (ADR-0007).

The journal holds one immutable **preamble** and a **latest checkpoint**. An append-only log was considered (the earlier draft) and rejected: punch mode writes a ~33 KiB checkpoint every 64 MiB of output, so a log would grow without bound on large entries.

## Layout (little-endian)

```text
HEADER 64     magic "TRNCJ\0\x01\0" | version u16 | slot_cap u32 | preamble_len u64 |
              preamble_blake3 [32] | reserved [6] | crc32c u32 over bytes 0..60
PREAMBLE      preamble_len bytes
SLOT A        generation u64 | len u32 | crc32c u32 (over generation, len, payload) | payload [slot_cap]
SLOT B        same
```

## Protocol

- **Create:** write the whole file to `<path>.tmp`, flush it, rename it to `<path>`, flush the directory. A crash during creation never leaves a partial journal at `<path>`. A leftover `.tmp` is discarded on the next start.
- **Write:** put the next generation into the slot holding the older one, then flush. A torn write damages only that slot.
- **Open:** check the header CRC and the preamble's BLAKE3; the valid slot with the highest generation is the latest checkpoint. Generation 0 means empty.

## Contents for ZIP consumption

- **Preamble:** `"TZJP1"` | archive id [16] | original length u64 | file id (volume u64, file u128) | destination (u32 length + UTF-8) | serialized ZIP layout.
- **Slot:** entry index u32 | inflate checkpoint (bit position u64, output total u64, CRC u32, window length u32, window).
- **ISO 9660 images** use the same contents with the magic `"TIJP1"`. Their layout holds stored entries whose CRC-32s were computed from the image before the journal was created. Each consumer refuses a journal with the other's magic, so a ZIP journal is never resumed as an ISO one or the other way round.

## Contents for compressed tarballs and files

- **Preamble:** `"TSJP1"` | archive id [16] | file id (volume u64, file u128) | destination (u32 length + UTF-8) | part count u32, then per part of a split archive: name length u16, name, size u64, file id (volume u64, file u128) | codec u8 (1 gzip, 2 bzip2, 3 xz, 4 zstd) | mode u8 (0 tar, 1 single file) | file length u64 | units u64 (members, streams or frames) | decoded length u64 | checkpoint interval u64 | tail hash [32] | checkpoint count u64 | per checkpoint: free-below offset u64, decoded offset u64, BLAKE3 of the file content since the previous checkpoint [32] | entry list (count u64, then per entry: name length u32, name, kind u8, size u64, data offset u64, mode u32 or `u32::MAX`, mtime seconds i64, mtime nanoseconds u32). A single file has one entry.
- **Slot:** checkpoints passed u32 | free-below offset u64 | decoded offset u64 | decoder cursor (codec-specific, see `trunc_legacy::stream`). For a split archive, a slot with checkpoints passed = `u32::MAX` is the end record: everything is decoded and durable, and the remaining parts may be deleted.
- **Slot capacity** is the codec's largest cursor plus 64 bytes: about 32 KiB for gzip (the DEFLATE window) and xz (LZMA probabilities), 4 KiB for zstd, 64 bytes for bzip2.
- **Gap log** `<archive>.trncg` (xz and zstd tarballs only): every decoded byte that is not file content (tar headers, PAX records, padding, end blocks), in stream order, flushed with the outputs before each checkpoint is journaled. On resume it is cut back to the checkpoint, and together with the staged files it gives back the decoder's window. It is removed before the journal.
- A single archive keeps its length while it is consumed (only ranges below the free-below offset are deallocated). It is truncated to zero once every output is durable, so a zero-length archive with a journal means "only the rename phase and cleanup remain". A split archive loses whole parts instead, once a checkpoint passes their end.

## Contents for .tar.gz consumption by v0.1.0

- **Preamble:** `"TGJP1"` | archive id [16] | file id (volume u64, file u128) | destination (u32 length + UTF-8) | the layout as above without the codec, mode and part table.
- **Slot:** checkpoints passed u32 | member data offset u64 | member output base u64 | free-below offset u64 | inflate checkpoint.
- Later versions still resume these journals, writing slots in the same layout.
