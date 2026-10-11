# ADR-0017: 7z archives

Status: accepted (2026-10-11).

## Context
7z is the other archive people download besides ZIP and tarballs. A 7z file is a 32-byte
signature header, the packed streams, and a header at the end (usually itself LZMA-compressed)
that describes *folders*: one packed stream decoded by a chain of coders into the contents of
one or more files back to back (*solid* when several). Most archives use LZMA2 (7-Zip's
default), LZMA (older archives, and the compressed header), sometimes behind the BCJ x86 or
Delta filter. trunc already has a resumable LZMA2 decoder for xz (ADR-0012).

## Decision
- **Supported coders: Copy, LZMA, LZMA2, BCJ x86 and Delta**, in any linear chain of up to four.
  Everything else is refused before anything is written, naming the method: PPMd, BZip2,
  Deflate, BCJ2 (four input streams), ARM/ARM64/PowerPC/SPARC/IA-64/RISC-V filters, and the
  Zstandard/Brotli/LZ4 coders of 7-Zip forks. AES is reported as "the archive is encrypted".
- **LZMA1 lives next to LZMA2.** Raw LZMA (5 property bytes, known size, optional end marker)
  is a separate struct at the end of `lzma.rs` that reuses the range coder and the
  length/distance/copy code but has its own symbol loop, so the LZMA2 hot path is untouched. It
  is fed input in pieces with 64 bytes of lookahead (one symbol never reads more), so memory is
  the dictionary plus small buffers however large the folder. Dictionaries above `--max-window`
  are refused, as for xz and zstd.
- **The header is validated whole before extraction.** Every count is bounded by the header
  bytes that could hold it, headers (stored or decoded) are capped at 256 MiB, packed streams
  must lie between the signature header and the header, the coder graph must be one chain from
  the packed stream to the single output (cycles and unused coders are refused), substream sizes
  must fit their folder, every file must map to exactly one stream, and names follow the ZIP and
  tar rules (`validate_host`, NFC, no duplicates on this host, nothing under a file). Each coder
  must produce exactly its declared size; every file CRC and folder CRC is checked.
- **Entry policy follows ZIP.** Unix modes (p7zip's high-16-bit extension) are applied; Windows
  attributes other than the directory bit are ignored; symlinks are skipped; anti-items
  (deletion markers) are skipped and counted.
- **Extraction stages, then moves.** Folders decode (in parallel where the backend allows) into
  `.trunc-stage-<id>` inside the destination; files move into place only after every CRC
  matched. A damaged archive leaves the destination as it was. Conflicts are checked before
  anything is written; `--overwrite` replaces existing files one by one.
- **`--consume` is refused** for now, with a message.

## Why not consume yet
Packed streams sit front to back with the header at the end, so a 7z could be consumed from
the front like a tarball (ADR-0011): free each folder's packed bytes once its files are durable.
That is only a win when a folder is small compared with the archive; a solid archive is usually
one folder, and freeing it only at its end saves nothing. Real savings need freeing *inside* a
folder while it decodes, which needs safe points:
- LZMA2 has them at chunk boundaries (a fresh range coder), and the xz decoder already
  journals a cursor there and reads its window back from the output (ADR-0012). A 7z LZMA2
  folder could reuse that, with the output split across files and the window read back from
  the staged files.
- LZMA1 has no boundaries: its range coder runs from the first byte to the last, so the cursor
  would include the range coder state and the input position, and every checkpoint would have
  to land mid-stream. Possible, but it is new crash-safety surface.
- BCJ and Delta carry a few bytes of state, which a cursor can hold.
- The header at the end must survive (or be journaled) until the end, as ZIP's central
  directory is.
The simple alternative, "extract everything, flush, then delete the archive", frees nothing
while running, which is what `--consume` promises; we would rather refuse than mislabel it.
The plan is: journal the parsed layout, consume folder by folder from the front, and add
in-folder checkpoints for LZMA2 folders first, with FaultFs crash sweeps as for tarballs.

## Consequences
- `x`, `inspect`, `verify` and `plan` work for 7z, including split `.7z.001` sets (ADR-0013
  said those were refused; they are now read like other split archives, and still not consumed).
- Self-extracting 7z executables are not recognised (the signature must be at offset 0).
- The test writer in `trunc-testkit` produces Copy/LZMA/LZMA2/BCJ/Delta archives through
  liblzma's raw encoders; a dozen small archives written by 7-Zip (from bodgit/sevenzip's
  BSD-licensed test data) are checked in to cover real headers and LZMA without an end marker.
