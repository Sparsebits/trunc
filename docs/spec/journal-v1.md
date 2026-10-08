# Journal format, version 1 (`<archive>.trncj`)

Status: **draft**, implemented in plan phase 4.2. Only legacy ZIP consumption uses it, recording every state transition. Native-format consumption needs no journal (ADR-0007).

## Layout

```text
[SUPERBLOCK A 4096][SUPERBLOCK B 4096][RECORD][RECORD]...
```

Superblock: `magic "TRNCJSB\0"` | `generation u64` | `log_committed_len u64` | `last_seq u64` | `archive_identity [32]` | zero padding | `crc32c u32` (final 4 bytes, over the preceding 4092).

Record: `len u32` (length of the payload) | `seq u64` | `type u16` | `payload (CBOR, len bytes)` | `crc32c u32` (over len, seq, type and payload).

## Commit protocol

1. Append records to the log.
2. Flush the log file's data.
3. Write the superblock with the *lower* generation, now holding `generation = max + 1` and the new `log_committed_len`.
4. Flush again.

## Open protocol

1. Read both superblocks. Use the one with the highest generation whose CRC is valid.
2. Replay records up to `log_committed_len`. Each record's CRC and `seq` (strictly increasing by 1) are checked.
3. Ignore anything after `log_committed_len`. It is a torn tail from an uncommitted append.
4. Compare `archive_identity` (BLAKE3 of: archive file ID, archive size at BEGIN, manifest or central-directory hash) with the file on disk. Refuse on mismatch, because the archive was replaced.

## Record types

| Type | Name | Payload |
|---|---|---|
| 1 | BEGIN | archive file ID, size, manifest/CD hash, mode, destination, staging dir |
| 2 | CD_COPY | legacy: raw central directory bytes, so the archive tail can be freed |
| 3 | ENTRY | entry id, state (`Started`, `Done`) |
| 4 | CKPT | legacy: entry id, inflate checkpoint, output offset, CRC state |
| 5 | RELEASE | byte range of the archive released (truncated or punched) |
| 6 | PAUSED | reason (`NoSpace { needed }`, `Mapped`) |
| 7 | RENAME_BEGIN | list of top-level staging entries and their targets |
| 8 | RENAME_ITEM | index of an item renamed |
| 9 | RENAME_DONE | — |
| 10 | END | — |
