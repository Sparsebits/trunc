# ADR-0001: Blocks are independently decodable

Status: accepted (2026-10-08)

## Context
Destructive consumption truncates each block's compressed bytes once its output is durable. If decoding block `k` needed decoder state from earlier blocks (an LZ history window, entropy tables), then a crash after those blocks were truncated would leave block `k` undecodable. The only way out would be checkpointing decoder state in a journal, which is the complexity the native format exists to avoid.

## Decision
Every block is one complete zstd frame, one complete lz4 block, or stored bytes. No block reads another block's data or any already-written output during decoding. To recover most of the compression lost by not sharing history, a single optional zstd dictionary is stored once, between the manifest and the blocks. It is never truncated until consumption ends.

## Consequences
- Crash recovery needs only the file length and the footer at end of file.
- Output files are never decoder inputs (invariant I4), so users or other programs touching outputs mid-extraction cannot corrupt later blocks.
- Compression ratio is somewhat lower than solid compression, depending on block size. A "group mode" (truncate per group, history shared inside a group) is a phase 7 spike to measure whether the extra ratio is worth a larger peak.
