# In-Place Decompression and Self-Consuming Archive Design

**Conversation date:** October 8, 2026  
**Topic:** Destructive extraction, crash-safe archive managers, in-place codecs, reverse-order archive formats, and prior art.

> This document packages the conversation in chronological order. Text is preserved in substance, including technical proposals and caveats. Some earlier response formatting and diagrams are normalized for Markdown readability.

## 1. In-place decompression

**User:** In-place decompression

**Assistant:**

In-place decompression means decompressing compressed data into memory that overlaps with the compressed input buffer, rather than allocating a separate full-size output buffer.

The tricky part is avoiding overwriting compressed bytes that haven’t been read yet. Common approaches are to decompress backwards, arrange the compressed stream so input is consumed before output reaches it, use a small scratch buffer, or design the format specifically for safe in-place expansion.

For example, instead of:

`compressed buffer -> separate decompressed buffer`

you do:

```text
[compressed data ........ free space]
→ expand within that same allocation
→ [fully decompressed data ........]
```

It’s useful when memory is tight, especially in bootloaders, embedded systems, game assets, and large model/data loading. It is not automatically supported by normal compression formats or libraries, because decompression usually expands data faster than the input pointer advances.

## 2. Destructive extraction on disk

**User:** No like a zip file is decompressed as a new thing and the zip stays intact, so the space taken is 1.8x what if we made a decompressor that decompresses in place so less space is taken

**Assistant:**

Yes. What you mean is **destructive extraction on disk**, not ordinary “in-place decompression” in RAM.

Say you have:

- `archive.zip` = 10 GB
- extracted contents = 18 GB

Normal unzip needs a peak around **28 GB** because the 10 GB ZIP stays there until extraction finishes.

What you're proposing is:

> As compressed parts of the ZIP are consumed, immediately give those disk blocks back to the filesystem so the extracted files can reuse them.

Then theoretically you'd need closer to **18 GB total occupied space**, rather than 28 GB.

The interesting part is that this is absolutely possible in principle, but a normal ZIP is awkward for it.

A destructive extractor could work roughly like this:

1. Read the ZIP's directory/index into RAM.
2. Start extracting entries.
3. Once a compressed region is guaranteed never to be needed again, reclaim its disk blocks.
4. Let the filesystem reuse those blocks for extracted data.
5. Eventually the ZIP itself disappears completely.

```text
START
[========= compressed ZIP: 10 GB =========]

MIDWAY
[=== unread ZIP ===][freed]
                    ↓ blocks reused
                    [========= extracted files =========]

END
[================ extracted files: 18 GB ================]
```

The clever part isn't really the decompression algorithm. It's **incrementally freeing the archive's physical disk space**.

On Linux, you could potentially do this with things like `fallocate(..., FALLOC_FL_PUNCH_HOLE, ...)` to punch holes in already-consumed portions of the archive. Once you've decompressed bytes 0–500 MB, for example, those blocks can be deallocated while keeping the rest of the ZIP file intact.

ZIP creates complications because compressed streams generally decode **forwards**. If you destroy bytes too early, corrupt data, crash, or discover CRC failure, you can't recover. You'd therefore want to process entries in an order where you can safely reclaim their regions. ZIP's central directory also lives near the end, so you'd first load all the metadata you'll need before destroying anything.

There's also a fundamental space constraint. Suppose:

\[
C = \text{compressed size},\quad U = \text{uncompressed size}
\]

A normal extractor needs approximately \(C+U\) occupied at peak.

A destructive extractor could approach \(U+\epsilon\), where \(\epsilon\) is buffers, metadata, temporary blocks, etc.

If you already possess the archive, the **additional free disk space** you'd need could approach only \(U-C\), rather than \(U\).

So a **100 GB ZIP → 180 GB extracted dataset** might theoretically extract with only roughly **80 GB of free disk**, rather than needing another 180 GB free.

There's a useful product idea here:

```bash
destructive-unzip huge.zip
```

The hard engineering problem is **crash safety and ordering entries so peak temporary disk usage is minimized**.

## 3. A WinRAR alternative with crash resistance

**User:** I want to make a winrar alternative that does exactly this. Use things like sha etc to ensure crash resistance lookup useful algorithms that might be relevant etc etc

**Assistant:**

Build it around one feature that WinRAR/7-Zip do not optimize for: **crash-safe destructive extraction**, progressively reclaiming archive blocks.

The core technology is **filesystem sparse-range deallocation + resumable decoder checkpoints + transactional metadata + integrity verification**.

Linux proofs of concept include `punch-extract` and `peel`, but a Windows-first implementation with a GUI, broad format support, transactional recovery and space guarantees would be a larger product.

### Architecture

```text
                 archive.zip
                     │
              ┌──────▼───────┐
              │ Archive index │
              └──────┬───────┘
                     │
          compressed-range dependency graph
                     │
              ┌──────▼───────┐
              │   Scheduler   │
              └──────┬───────┘
                     │
             read compressed chunk
                     │
              ┌──────▼───────┐
              │  Decompress   │
              └──────┬───────┘
                     │
               write output
                     │
              FlushFileBuffers
                     │
             persist checkpoint
                     │
              FlushFileBuffers
                     │
       FSCTL_SET_ZERO_DATA(source range)
                     │
                space reclaimed
```

On Windows, `FSCTL_SET_SPARSE` and `FSCTL_SET_ZERO_DATA` can make ranges of NTFS sparse files unallocated; `FSCTL_QUERY_ALLOCATED_RANGES` can inspect allocated ranges. The file may remain logically large while its physical disk usage shrinks.

### Key crash-safety invariant

> Never destroy compressed bytes until you have durably stored both the resulting output and enough decoder state to continue without those bytes.

Hashing alone does not provide crash safety. Correct write ordering does.

A safe transaction:

1. Decode source `[A, B)`.
2. Write resulting output.
3. Flush output.
4. Save decoder checkpoint at `B`.
5. Save output/hash state.
6. Flush checkpoint journal.
7. Deallocate source `[A, B)`.

Crash before step 3: source remains, so retry. Crash after output flush but before checkpoint commit: source remains, so retry. Crash after committed checkpoint but before deallocation: reclaim later. Crash during/after deallocation: resume from the durable checkpoint.

This resembles database write-ahead logging, especially SQLite's treatment of durable commit order.

### Append-only journal

Use `archive.zip.reclaimlog` instead of one mutable JSON file.

```text
HEADER
CHECKPOINT seq=1 ...
CHECKPOINT seq=2 ...
CHECKPOINT seq=3 ...
```

A record may contain:

```text
sequence_number
archive_file_id
archive_size
archive_metadata_hash
format
entry_id
compressed_offset
compressed_bit_offset
output_file_id
output_offset
decoder_state_blob
archive_crc_state
source_hash_state
output_hash_state
reclaimable_start
reclaimable_end
record_crc32c
record_blake3
```

Recovery locates the newest valid checkpoint, checks file identity and persisted output, and resumes. On Windows, `FILE_ID_INFO` can identify source files more robustly than name and timestamp alone.

### Hashing roles

- **CRC32C:** Fast detection of corrupted/torn journal records.
- **BLAKE3:** Fast incremental cryptographic hashes and chunk/Merkle verification.
- **SHA-256:** Interoperability with published external archive checksums.

At 4 MiB per source chunk, 100 GB contains about 25,600 hashes, needing ~800 KiB if each hash occupies 32 bytes.

Possible modes:

- Fast: archive-provided checksums.
- Safe: BLAKE3 fingerprinting during extraction.
- Paranoid: hash the whole archive before reclaiming its first block.

Hashing a damaged input merely fingerprints that damaged input unless a trusted reference hash exists.

### DEFLATE checkpoints

DEFLATE has a 32 KiB sliding history window. zlib's `zran` random-access technique saves compressed offset, bit alignment, output offset and history window; `inflateCopy()` can capture decoder state. This makes intra-entry checkpointing possible even for a gigantic single ZIP member.

### Zstandard and framed compression

Zstandard's seekable format divides data into independently decompressible frames, making frame-level verified extraction and reclaim attractive. For a native format, consider Zstd frames, BLAKE3 tree hashes, an index and recovery metadata rather than inventing a new compressor.

### ZIP as MVP

Read and persist the central directory and per-entry compressed extents before destructively extracting. Individual entries can be scheduled in an order that minimizes free-space requirements.

Model entry `i` as compressed size \(c_i\) and output size \(u_i\). Once complete, net disk increase is \(u_i-c_i\). An entry-completion-only strategy may temporarily need \(u_i\) free before releasing \(c_i\). A space-aware scheduler can use reclaimed storage as capacity for subsequent entries.

More general formats can be represented with a **compressed-extent dependency graph**: reclaim an extent only when every possible future consumer has durable state that no longer needs it. This resembles garbage collection of archived bytes.

### Encryption caveat

Authenticated encryption may only be verifiable after the full encrypted entry is processed. Destructively removing ciphertext before end-of-entry authentication is unsafe. Initially treat encrypted entries as atomic: decrypt, authenticate, flush, checkpoint and only then reclaim.

### 7z and RAR

7z's solid compression ties multiple logical files into one stream. Begin with solid-folder boundaries, and add LZMA/LZMA2 decoder checkpoints later. RAR extraction can use an appropriately licensed library such as libarchive; RAR creation has separate proprietary/licensing constraints and is not essential initially.

### Implementation stack

Rust engine with archive parser, codec adapters, checkpoint/WAL engine, space-aware scheduler, extent reclamation, integrity checker and Windows NTFS backend. A native Windows or Tauri GUI could come later.

Suggested journal states:

```text
DISCOVERED
    ↓
OUTPUT_WRITTEN
    ↓
OUTPUT_DURABLE
    ↓
CHECKPOINT_DURABLE
    ↓
SOURCE_RECLAIMED
```

Never transition to `SOURCE_RECLAIMED` before the checkpoint is durable.

### Crash testing

Inject process termination and simulated storage failures after every write/flush/state transition. Include short writes, torn records, corrupt WAL, out-of-space failures, renamed/replaced inputs, truncated outputs and interrupted reclamation. Resume and compare against conventional extraction byte-for-byte.

Checkpoints should balance flush overhead against redo cost (e.g. start experimenting with 32–256 MiB intervals). Two alternating superblocks can store the latest committed WAL generation with checksums.

### MVP scope

Windows 10/11, NTFS, same-volume extraction, ZIP Stored/Deflate/Zip64, normal directory trees, CRC verification, DEFLATE intra-file checkpoints, crash recovery, progressive sparse deallocation and accurate preflight space estimates. Make destructive mode opt-in.

Example:

```bash
reclaim x archive.zip
reclaim x archive.zip --destructive
reclaim x archive.zip --destructive --verify
reclaim inspect archive.zip
```

Future expansion: integrate destructive extraction with downloads so compressed chunks are consumed and reclaimed as they arrive, avoiding a complete downloaded archive plus full output side by side.

### References discussed

- [Microsoft: sparse-file operations](https://learn.microsoft.com/en-us/windows/win32/fileio/sparse-file-operations)
- [Microsoft: FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)
- [Microsoft: FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [SQLite: atomic commit](https://www.sqlite.org/atomiccommit.html)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3)
- [zlib source/API](https://github.com/madler/zlib)
- [Zstd seekable format](https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md)
- [7-Zip SDK](https://www.7-zip.org/sdk.html)
- [libarchive](https://github.com/libarchive/libarchive)
- [RARLAB license](https://www.rarlab.com/license.htm)
- [punch-extract](https://github.com/tomsync775/punch-extract)
- [peel](https://github.com/agouin/peel)

## 4. Designing the archive itself for in-place expansion

**User:** That's cool, one more idea what if instead of using file system hacks the file was compressed in such a way that the bytes are decompressed around the existing zip bytes that's how the file is compressed in the first place

**Assistant:**

If you control the format, this may be better than retrofitting ZIP. The proposed archive is **self-consuming**: it is arranged so its compressed representation is progressively overwritten or replaced as output materializes.

### Variant A: one big file, overlapping decompression

A 100 GB compressed file expands to 180 GB. Grow the same file, move input toward the end, and decode forward into earlier space without overwriting unread input:

```text
START
[ CCCCCCCCCCCCCCCCCCCC ]                100 GB

GROW
[ free........................ | CCCCCCCCCCCCCCCCCC ]
                                             180 GB

DECODE
[ UUUUUUUUUU......... | CCCCCCCCCCCC ]

END
[ UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU ]  180 GB
```

The result transforms the same file instead of needing both file copies. In-memory overlap is an established codec feature in LZ4, LZO and other packers. Multi-file output is harder because logical files need distinct filesystem allocations.

### Variant B: reverse-order blocks, consumed from EOF

For a purpose-built **multi-file** format, store encoded blocks in reverse logical order:

```text
HEADER / INDEX

[block4][block3][block2][block1]
                              ↑ EOF
```

Extract the final block at EOF, write and verify its destination bytes, flush, and truncate the archived tail. Repeat until the archive has disappeared.

```text
[block4][block3][block2][block1]
                         ↓ extract block1, truncate
[block4][block3][block2]
                    ↓ extract block2, truncate
[block4][block3]
...
[header]
```

No sparse-file ranges or hole punching are needed; normal reads, writes, flushes and truncation suffice on a filesystem that supports those operations.

### Space bound

Let initial archive size be \(C\), each compressed block size \(c_i\), and its decoded output size \(u_i\).

After processing block 1, occupied storage is approximately \(C-c_1+u_1\); after block 2 it is \(C-c_1-c_2+u_1+u_2\), eventually reaching final output \(U\).

Because the safe sequence writes the new output before truncating the compressed block, the transient peak is roughly:

\[
U+c_{\max}+J
\]

in the expanding-data case, where \(J\) represents recovery metadata and scratch overhead. Small independently reclaimable blocks reduce this temporary margin.

For a 100 GB archive expanding to 180 GB in 8 MiB compressed blocks, this can approach **180 GB + one chunk + journal**, instead of 280 GB.

### Forward decoding, reverse physical storage

Logical blocks still decode in forward order:

```text
A → B → C → D
```

They are simply stored in reverse order:

```text
[D][C][B][A]
             ↑ EOF
```

This preserves ordinary forward LZ dictionary dependencies as long as later blocks reference already decoded output, or explicit restart/checkpoint structures are provided.

### Self-describing footer per block

```text
[compressed payload]
[footer:
   magic
   block_id
   compressed_len
   uncompressed_len
   destination_file_id
   destination_offset
   BLAKE3(compressed)
   BLAKE3(uncompressed)
   CRC32C
]
                    ↑ EOF
```

A tail footer tells the extractor where the preceding compressed block starts, its output location and expected hashes. Once the block is safely extracted, shortening the file reveals the previous block's footer at the new EOF.

### Transactional extraction

1. Read tail block.
2. Verify compressed hash.
3. Decompress and write output.
4. Verify output hash.
5. Flush output.
6. Persist and flush committed-block journal state.
7. Truncate source archive.
8. Make truncation durable where supported.

A crash before source truncation preserves source data. A crash after durable checkpoint permits safe continuation. Alternating superblocks and a WAL provide stronger recovery bookkeeping.

### Codec and chunk design

Experiment with 4, 8, 16 or 32 MiB chunks. LZ4 and LZO support overlapping/in-place variants. A higher-ratio Zstd design can divide data into independently restartable groups, possibly allowing dictionary dependencies within each group while retaining random access across groups.

The compressor could jointly optimize compressed bytes and decompression overlap/scratch:

\[
J = compressed\_size + \lambda\,peak\_decompression\_slack
\]

This trades slight compression-ratio loss for lower extraction working space.

### Two product modes

- **Existing ZIP/7z/RAR:** use the filesystem-aware destructive extraction strategy.
- **Native format** (placeholder extension `.arcx`): reverse-ordered chunk blocks, BLAKE3 checks, transactional metadata, and self-consuming extraction without hole punching.

Core promise: **roughly the difference between compressed and uncompressed size is needed as additional free disk space**, plus bounded overhead.

Core invariant: the next compressed block is at EOF; once its output is durable, EOF moves backward past it.

### References discussed

- [LZ4 API](https://github.com/lz4/lz4/blob/dev/lib/lz4.h)
- [LZ4 manual](https://github.com/lz4/lz4/blob/dev/doc/lz4_manual.html)
- [LZO documentation](https://github.com/nemequ/lzo/blob/master/doc/LZO.TXT)
- [UPX packer source](https://github.com/upx/upx/blob/devel/src/packer.cpp)

## 5. Prior-art check: does it already exist?

**User:** Does this already exist

**Assistant:**

**The core idea already exists, but the exact general-purpose archive format being proposed does not appear to exist in mainstream use.** This is not a claim of proven novelty or patentability.

For a single compressed blob, in-place decompression is established prior art. LZ4 explicitly permits a compressed input toward the end of a buffer and output expansion at the beginning. A newer codec, ZXC, describes a similar layout with peak memory near expanded size rather than compressed-plus-expanded.

Other relatives include UPX self-unpacking executables, Imploder's in-place executable/data decompression, Exomizer's forward/backward crunch and decrunch modes, and Linux EROFS compressed pages laid out to permit in-place decompression.

For on-disk destructive extraction of existing archive formats, `punch-extract` and `peel` use Linux hole punching. `peel` includes crash-resumable checkpoints.

What was **not found in the searched results**: a mainstream, general-purpose, multi-file archive format explicitly designed as a transactional, reverse-order EOF stack that destructively extracts by progressively truncating its own archive.

| Concept | Prior art found? |
|---|---|
| In-place decompression in RAM | Yes, well established |
| Backward decompression | Yes |
| Executables overwriting their compressed representation during unpacking | Yes |
| Compressed filesystem data decompressed in place | Yes |
| Existing archive files progressively reclaimed via hole punching | Yes |
| Mainstream multi-file self-consuming disk archive format | Not found in this search |
| Crash-safe desktop manager built around that purpose-made format | Not found in this search |

The differentiated proposal is not simply “in-place decompression,” but:

> **A transactional self-reclaiming archive container whose physical ordering guarantees bounded additional storage during destructive extraction.**

Or, more product-oriented:

> **A filesystem-independent self-consuming archive format with transactional extraction and near-zero temporary-space amplification.**

Its idealized peak occupied space approaches:

\[
U+B+J
\]

instead of:

\[
U+C
\]

where \(U\) is decompressed output size, \(B\) is a bounded compressed block/scratch allowance, and \(J\) is recovery metadata.

A patentability/publication claim would require a much deeper prior-art search, including patents and academic literature. Not finding an existing product on the web does not prove the mechanism is novel.

### Further references discussed

- [ZXC](https://github.com/hellobertrand/zxc)
- [UPX documentation](https://github.com/upx/upx/blob/devel/doc/upx-doc.html)
- [Imploder](https://github.com/hitchhikr/imploder)
- [Exomizer information](https://github.com/bitshifters/exomizer/blob/master/exomizer2/exo20info.txt)
- [EROFS kernel discussion](https://lkml.rescloud.iu.edu/1908.1/04948.html)
- [punch-extract](https://github.com/tomsync775/punch-extract)
- [peel](https://github.com/agouin/peel)

---

## Consolidated takeaways

1. **Feature:** Minimize extraction's additional free-space requirement by consuming the source archive as output is materialized.
2. **Compatibility engine:** For existing archives, use sparse/hole-punch deallocation, checkpoints, a WAL, and dependency-aware reclamation.
3. **Native format:** Reverse physical chunk order so extraction always consumes the archive tail, safely truncating after output becomes durable.
4. **Safety:** Correct write/flush/commit/truncate ordering is primary; CRC32C/BLAKE3/SHA-256 serve distinct integrity roles.
5. **Engineering challenge:** Decoder resumability, output consistency, allocation guarantees, metadata durability, encrypted/solid archives, and crash injection tests.
6. **Prior art:** The building blocks exist; an exact broad consumer product combining these properties was not found in this search.

**Caveat:** Mathematical space bounds above are conceptual/idealized. Real systems must account for allocation granularity, journal/filesystem metadata, destination filesystem behavior, decoder scratch, compression blocks, and cases where the decoded data is not larger than its archive.
