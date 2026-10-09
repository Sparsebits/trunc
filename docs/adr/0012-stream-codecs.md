# ADR-0012: bzip2, xz and zstd, and single compressed files

Status: accepted (2026-10-09). Extends ADR-0011.

## Context
ADR-0011 consumes `.tar.gz` by decoding forward with a DEFLATE decoder that can save its state
at a block boundary, and freeing the compressed bytes behind each checkpoint. Large downloads
also come as `.tar.zst`, `.tar.xz` and `.tar.bz2`, and as single compressed files (disk images,
database dumps, model weights). The C libraries for these formats keep their decoder state
private, so they can only restart at frame, block or stream boundaries. Most `.tar.zst` and
`.tar.xz` files are written single-threaded as one frame or block: with those libraries,
consuming them would free nothing until the end.

## Decision
- **Own decoders.** trunc has pure-Rust decoders for bzip2, xz (LZMA2 only) and zstd (RFC 8878,
  no dictionaries), alongside the DEFLATE one, behind one interface (`trunc_legacy::stream`).
  Each hands out a *safe point* at the first codec boundary after `checkpoint_every` bytes of
  output: a DEFLATE block, a bzip2 block, an LZMA2 chunk, or a zstd block, and frame, stream
  and member boundaries. Positions depend only on the input and the interval, so the rest of
  ADR-0011 (scan, interval hashes, journal, punching from the front) applies unchanged.
- **Small cursors.** A safe point's state is what the next unit needs and nothing more:
  - bzip2: the bit position, output total and stream CRC (blocks are independent);
  - xz: the LZMA probabilities (at most about 28 KB), state and repeat distances, the block's
    check state, and a running hash of the index records;
  - zstd: the repeat offsets, the Huffman weights and FSE normalized counts the next block may
    reuse, and the XXH64 state.

  CRC-64, SHA-256 and XXH64 are implemented in trunc so their running state can be saved.
  Journal slots are sized per codec (about 32 KiB for gzip and xz, 4 KiB for zstd, 64 bytes for
  bzip2).
- **The window comes back from the output.** xz and zstd decoders refer back up to 8–128 MiB
  of output. Rather than journaling that at every checkpoint, the cursor records its length
  and a CRC-32, and on resume the decoder reads it back from what was already written:
  - file content from the staged output files;
  - everything else in the decoded stream (tar headers, PAX records, padding) from a **gap
    log**, `<archive>.trncg`, an append-only sidecar written alongside the outputs and flushed
    with them before each checkpoint is journaled. The scan's entry table maps any stream
    offset to a file or a gap-log position.

  A mismatching CRC refuses to resume. Interval hashes and codec checksums would also catch it.
- **Bounded memory.** Windows larger than `--max-window` (default 256 MiB, enough for
  `xz -9` and `zstd --long=27`) are refused before anything is written.
- **Single compressed files.** When the first 512 decoded bytes are not a tar header, the
  output is one file named after the archive without its suffix (`disk.img.xz` → `disk.img`,
  `backup.tgz` → `backup.tar`, anything else gets `.out`). `--raw` forces this for tarballs, so
  `trunc x big.tar.zst --raw --consume` turns the archive into `big.tar` in place.
- **Journal `TSJP1`.** The preamble adds the codec and mode to ADR-0011's layout. Journals
  written by v0.1.0 (`TGJP1`, gzip only) are still read, and resume with their old slot format.

## Consequences
- Four decoders to keep correct. They are tested against the reference encoders and decoders
  at many levels, resumed from every safe point with the input before it zeroed, and fuzzed
  differentially (anything trunc accepts, the reference decoder must accept with the same
  output).
- Decoding speed on one core: gzip and bzip2 match or beat `gzip -t` and `bzip2 -t`, xz is
  about 25% slower than liblzma, and zstd reaches about 300 MB/s, slower than libzstd.
- A tarball consume of an xz or zstd archive writes the tar metadata twice: once into the gap
  log, which is removed at the end. The space planner counts it.
- BCJ and delta xz filters, zstd dictionaries and the obsolete randomized bzip2 blocks are
  refused.
