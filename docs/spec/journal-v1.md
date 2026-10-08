# Journal format, version 1 (`<archive>.trncj`)

Status: implemented in `trunc-journal`. Used by ZIP consumption (ADR-0008) and `.tar.gz` consumption (ADR-0011). Native `.trnc` consumption needs no journal (ADR-0007).

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

## Contents for .tar.gz consumption

- **Preamble:** `"TGJP1"` | archive id [16] | file id (volume u64, file u128) | destination (u32 length + UTF-8) | file length u64 | gzip members u64 | tar stream length u64 | checkpoint interval u64 | tail hash [32] | checkpoint count u64 | per checkpoint: free-below offset u64, tar offset u64, BLAKE3 of the file content since the previous checkpoint [32] | entry list (count u64, then per entry: name length u32, name, kind u8, size u64, data offset u64, mode u32 or `u32::MAX`, mtime seconds i64, mtime nanoseconds u32).
- **Slot:** checkpoints passed u32 | member data offset u64 | member output base u64 | free-below offset u64 | inflate checkpoint.
- The archive keeps its length while it is consumed (only ranges below the free-below offset are deallocated). It is truncated to zero once every output is durable, so a zero-length archive with a journal means "only the rename phase and cleanup remain".
