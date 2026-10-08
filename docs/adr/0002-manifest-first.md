# ADR-0002: Manifest at the front, blocks reversed, manifest hash in the header

Status: accepted (2026-10-08)

## Context
A consumer must read the full index before destroying anything, and the index must survive every truncation. Putting the index at the end (as ZIP does) would make it the first thing truncated.

## Decision
- Header, then manifest, then optional dictionary, then blocks from last to first. Block 0 sits at end of file.
- Block offsets are computed from block sizes, not stored. The manifest's length therefore doesn't depend on its own position.
- The header stores BLAKE3 of the manifest region. An early implementation had no manifest checksum, and a test flipping a byte in an unsigned manifest showed the corruption went undetected. The header grew from 64 to 96 bytes to hold the hash.

## Consequences
- The producer must know every block's size before writing the first block, so it compresses to a temporary spool and then writes the final file. Producing an archive cannot be streamed to a pipe in v1.
- After full consumption, header + manifest remain as a small signed receipt of what was extracted.
