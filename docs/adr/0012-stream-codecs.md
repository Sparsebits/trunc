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
- **Independent units decode in parallel.** Some units need nothing from the ones before them,
  so worker threads decode them ahead while the decoding loop takes them in order:
  - bzip2 blocks. Block starts are found by searching for the 48-bit block magic at every bit
    offset. Workers decode each candidate, and the loop uses only the one that starts exactly
    where the previous block ended, so a false match inside compressed data is ignored. Safe
    points are unchanged (they were already between blocks).
  - Blocks of xz streams with two or more blocks (what `xz -T` writes). The stream's index,
    read from the end of the file, gives every block's position and sizes without decoding.
    In such streams, as long as no block produces more than 256 MiB, safe points are between
    blocks only, so a block is always decoded whole and no window needs restoring.
  - zstd frames that declare their size (up to 128 MiB) and are followed by more of the file
    (`pzstd`, `zstd:chunked`). Their only safe point is at the end.
  - BGZF gzip members (`bgzip`, samtools, htslib): each header gives the member's size, so the
    members are found by reading one trailer and the next header per member, and workers
    decode them in batches of about 2 MiB of output. A BGZF member has no safe points inside
    the size its header gives (one whose data runs past it does from there on), and a
    member-boundary cursor points at a BGZF member's header so a resume knows it is one. A
    member that does not match its header is decoded by the loop as ordinary gzip.

  Which units are decoded whole depends only on the file, never on the thread count, so the
  scan, the consume pass and a resume see the same safe points. Tests check that one thread
  and eight give the same output and safe points. Blocks decoded ahead and not yet taken hold
  at most about 512 MiB. Both passes of `--consume` benefit, so keeping the scan (refuse
  before destroying anything) costs far less on multi-block files.
- **Journal `TSJP1`.** The preamble adds the codec and mode to ADR-0011's layout. Journals
  written by v0.1.0 (`TGJP1`, gzip only) are still read, and resume with their old slot format.

## Consequences
- Four decoders to keep correct. They are tested against the reference encoders and decoders
  at many levels, resumed from every safe point with the input before it zeroed, and fuzzed
  differentially (anything trunc accepts, the reference decoder must accept with the same
  output).
- Decoding speed on one core: gzip at about 500 MB/s and bzip2 match or beat `gzip -t` and
  `bzip2 -t`, xz is about 25% slower than liblzma, and zstd decodes at about 600-680 MB/s,
  roughly 60% of libzstd (`cargo run --release -p trunc-legacy --example decode -- <file>`
  times a decoder alone; `TRUNC_THREADS=1` keeps it to one core). bzip2, multi-block xz and
  multi-frame zstd scale with cores: a 437 MiB `.tar.xz` from `xz -T0` verifies in 0.65 s
  instead of 4.1 s.
- Multi-block xz streams free space a block at a time rather than an LZMA2 chunk at a time
  (`xz -T0` blocks are 3x the dictionary, 24 MiB at the default level). The space planner
  works from the scan's safe points, so its numbers include this.
- A tarball consume of an xz or zstd archive writes the tar metadata twice: once into the gap
  log, which is removed at the end. The space planner counts it.
- BCJ and delta xz filters, zstd dictionaries and the obsolete randomized bzip2 blocks are
  refused.
