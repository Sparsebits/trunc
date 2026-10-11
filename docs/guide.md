# trunc user guide

`trunc` extracts archives while consuming them: as each piece is safely extracted, the archive shrinks by that piece. You need about *output size − archive size* of free space instead of the full output size. It works with its own `.trnc` format and with existing ZIP files, tarballs compressed with gzip, bzip2, xz or zstd, single compressed files, and archives split into parts.

## Quick start

```sh
trunc plan big.trnc -C D:\out                 # how much space each mode needs, and any warnings
trunc x big.trnc -C D:\out --consume          # extract, destroying the archive as it goes
trunc resume big.trnc                          # after a crash, power cut, kill or pause
```

`trunc x` without `--consume` is an ordinary extraction that leaves the archive alone.

## Supported formats

| Format | Extract | `--consume` | When space comes back | Resume reads |
|---|---|---|---|---|
| `.trnc` | yes | yes | From the end, after each batch of blocks (`--batch`, default 256 MiB of output) | the archive's length |
| ZIP: Stored, Deflate, Zip64 | yes | yes | From the end, after each group of entries. Entries of 256 MiB or more (`--punch-min`) also every 64 MiB while they decompress | `<archive>.trncj` and the archive's length |
| `.tar.gz`, `.tgz`, `.gz` | yes | yes | From the front, every 64 MiB of output (`--checkpoint-every`), at the next Deflate block | `<archive>.trncj` |
| `.tar.bz2`, `.bz2` | yes | yes | From the front, every 64 MiB, at the next bzip2 block | `<archive>.trncj` |
| `.tar.xz`, `.xz` | yes | yes | From the front, every 64 MiB, at the next LZMA2 chunk. Files with several blocks per stream (`xz -T0`): at the next block | `<archive>.trncj`, plus the decoder window read back from the output |
| `.tar.zst`, `.zst` | yes | yes | From the front, every 64 MiB, at the next zstd block. Frames that declare their size, in files of several frames (`pzstd`): at the end of the frame | `<archive>.trncj`, plus the decoder window read back from the output |
| Compressed tarball or file split into `.001` or `.aa` parts | yes | yes | As above, and each part is deleted once its data is safely extracted | `<archive>.trncj` |
| ZIP or `.trnc` split into parts | yes | no | | |

Freeing from the end shrinks the file, which works on every filesystem. Freeing from the front, and punch mode inside ZIP entries, release space inside a file, which needs NTFS, ext4, XFS, btrfs or ZFS. On other filesystems, compressed archives still consume safely but give their space back only at the end, and a large ZIP entry only once it is finished. Deleting split parts works everywhere.

Every format resumes with `trunc resume <archive>` or by running the same command again.

## Creating archives

```sh
trunc create data.trnc ./folder ./file.txt    # zstd level 9, 8 MiB blocks
trunc create data.trnc ./folder --codec lz4   # faster, larger
trunc create data.trnc ./folder --dict train  # helps with many small similar files
trunc key gen me.key                           # once
trunc create data.trnc ./folder --sign me.key  # recipients can check it came from you
```

Smaller blocks (`--block-size 4M`) mean less extra space during `--consume`; larger blocks compress slightly better.

## What `--consume` promises

- **Nothing is lost if it is interrupted.** Every byte is always either still in the archive or safely written at the destination. Run the same command again, or `trunc resume <archive>`, to continue. This is tested by crashing it at every single filesystem operation, under models where unflushed writes are lost or survive in any order.
- **Nothing is destroyed until it has been verified and made durable.** Each piece's hash (or ZIP CRC) is checked before its source is released; compressed tarballs and files are decompressed and checked in full before anything is written. The output is flushed to disk, and only then is the source released.
- **Files appear all at once at the end.** Output goes into a hidden `.trunc-stage-…` folder inside the destination and is moved into place when everything is done. Existing files at the destination are never overwritten. `--consume` refuses to start if a top-level name already exists.
- **It stops safely when it can't continue.** If the disk fills up, or another program keeps the archive open, it pauses (exit code 75). Free some space or close the program, then resume.
- **It tells you before risky situations.** It refuses to run on an archive inside a cloud-synced folder (the sync client could upload every truncation and replace your cloud copy), on FAT32/exFAT, which have no journal, or on a filesystem it cannot identify (network shares, FUSE, WSL's view of Windows drives). Override with `--allow-sync` or `--allow-unjournaled` if you are sure.

## What it does not promise

- **The archive is gone afterwards.** For `.trnc`, a small `<archive>.receipt` (header and signed manifest) is kept unless you pass `--no-receipt`. For ZIP and compressed archives, nothing remains, and other tools cannot open the file once the first step has run.
- **Space figures are upper bounds, not exact predictions.** Other programs writing to the same disk, filesystem compression and quotas are outside its view.
- **Snapshots defeat it.** With System Restore / Volume Shadow Copies, Time Machine local snapshots, or btrfs/ZFS snapshots, truncated data stays allocated and no space is freed. `trunc plan` says when it could not check.
- **Drives that ignore flush commands** (some cheap USB sticks and SD cards) can lose data on power loss no matter what software does. `--verify-media` reads extracted data back from disk, bypassing the OS cache, before releasing the source. It catches many such problems, at the cost of one extra read.
- **It is designed for one machine and one user.** Don't extract destructively into a folder that other people can write to.

## ZIP files

`trunc x file.zip -C out --consume` handles Stored and Deflate entries, Zip64, self-extracting archives and names in UTF-8 or the old DOS code page. Encrypted archives, other compression methods and spanned archives (`.z01`, `.z02`, …) are refused; parts cut by `split` or 7-Zip (`.001`) are read as one file (see [Split archives](#split-archives)).

For ZIPs containing a few very large files, **punch mode** frees space *inside* each large entry as it decompresses, on NTFS and other filesystems that support sparse files. It applies to entries whose compressed size is at least `--punch-min` (default 256 MiB). Each such entry is fully verified once before any of it is freed. `--no-punch` turns it off.

## Compressed tarballs and files

`trunc x file.tar.gz -C out --consume` handles tar archives compressed with gzip, bzip2, xz or zstd (`.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`), from GNU tar, bsdtar, Python and most other writers: ustar, GNU long names, PAX headers, files over 8 GiB, several gzip members, bzip2 streams, xz streams or zstd frames back to back, and xz streams of many blocks (files from `pigz`, `pbzip2`, `pzstd`, `xz -T0` and `zstd --long` all work). The format is recognised from the content, not the name. Symlinks and device entries are skipped. Hard links, sparse files and multi-volume archives are refused for now.

A compressed file that is not a tar archive (`disk.img.xz`, `dump.sql.gz`) is decompressed into one file named without the suffix, in the destination: `trunc x disk.img.xz --consume` leaves `disk.img`. `.tgz`, `.txz` and the other short forms become `.tar`; a name without a known suffix gets `.out` added. `--raw` does the same for a tarball, so `trunc x big.tar.zst --raw --consume` turns it into `big.tar` in place.

A compressed stream can only be decoded from the start, so trunc frees space from the front of the archive. It first decompresses the whole archive once to check every checksum and tar header, without writing anything. Then it extracts, and every 64 MiB of output (`--checkpoint-every`) it confirms the output matches that first pass, saves its position in a small journal, and frees the compressed bytes already used. The file keeps its size, but those bytes stop taking up disk space. That needs a filesystem that can free space inside a file (NTFS, ext4, XFS, btrfs, ZFS). Elsewhere `--consume` still works, but needs as much space as a normal extraction.

xz and zstd decoders look back up to 8-128 MiB. When a consume resumes, trunc reads that window back from the files it has already written, plus a small sidecar (`<archive>.trncg`) holding the tar headers, so the journal stays small. `--max-window` (default 256M) refuses archives that would need more memory than that.

The scan means the archive is decompressed twice. `trunc plan`, `inspect` and `verify` scan it too, since compressed streams record no reliable sizes. Both passes use every core where the file allows it (see [Parallel decoding](#parallel-decoding)).

Signatures apply only to `.trnc` archives: `--require-signed` and `--trust-key` are refused for ZIP and compressed files rather than ignored.

## Split archives

Pass the first part of a split archive (`big.tar.zst.001` or `big.tar.zst.aa`) and trunc reads the parts as one file: `x`, `inspect`, `verify` and `plan` work for every format. Naming a later part is an error that points at the first.

With `--consume`, compressed tarballs and files delete each part as soon as its data is safely extracted. This frees space on any filesystem, FAT32 and exFAT included (which still need `--allow-unjournaled`). Split ZIP and `.trnc` archives can be extracted but not consumed yet.

## Names on Linux and macOS

`.trnc` archives only hold names that work on Windows, macOS and Linux. Archives from other tools often don't: Linux tarballs contain names with backslashes or colons, and source trees have files that differ only in case (`Makefile` and `makefile`). For tar, ZIP and single compressed files, trunc follows the computer it runs on:

- On Linux and macOS, names that only Windows forbids are accepted: `\`, `:`, `<>"|?*`, trailing dots or spaces, and device names like `CON`.
- On Linux, names that differ only in case are separate files. macOS compares names without case, like Windows, so there the second one is refused.
- On Windows, the portable rules apply.

A name the computer cannot hold is refused before anything is written. Names that could reach outside the destination (`..`, absolute paths, `C:` prefixes, control characters) are refused everywhere.

## Parallel decoding

`.trnc` blocks are independent, so `trunc x` (with or without `--consume`), `resume` and `verify` decode them on every core. `--threads N` limits that, and `create --threads N` limits compression.

A compressed stream is usually one long chain, where each part needs the one before it, so it decodes on one core. Some files are made of parts that need nothing from the ones before them, and trunc decodes those parts on every core:

- **bzip2**: every file of 2 MiB or more. Each block stands alone.
- **xz**: streams with two or more blocks, which is what `xz -T0` writes. The stream's index, at the end of the file, gives every block's position.
- **zstd**: files of several frames that declare their size (up to 128 MiB each), as `pzstd` writes.

gzip, single-block xz and single-frame zstd files decode on one core. Compressed archives always use every core they can; `--threads` applies only to `.trnc`.

Both passes of a consume run in parallel, and so do `plan`, `inspect` and `verify`. A 437 MiB `.tar.xz` from `xz -T0` verifies in 0.65 s instead of 4.1 s. If you make the archive yourself and want it to extract fast, compress with `xz -T0`, `pzstd` or bzip2.

What this means for space and memory:

- **Space comes back a whole block or frame at a time.** An xz block or zstd frame decoded in parallel is decoded whole, so checkpoints fall only between them, and one larger than 64 MiB gives its space back only when it ends. `xz -T0` blocks are three times the dictionary size: 24 MiB at the default level, 192 MiB at `-9`. zstd frames are at most 128 MiB. If any block in an xz stream produces more than 256 MiB, that stream decodes on one core in the usual 64 MiB steps. `trunc plan` already counts all of this.
- **Up to about 512 MiB of memory** holds parts decoded ahead and not yet written.
- **The core count changes nothing else.** Which parts are decoded whole depends only on the file, so the scan, the consume and a resume on another computer stop at the same checkpoints.

## Performance and profiling

`--profile FILE` (any command, or `TRUNC_PROFILE=FILE`) records where a run spends its time. When the command finishes, trunc prints a summary to stderr and writes a Chrome trace to `FILE`. `--profile -` prints the summary without writing a file. Profiling is off unless asked for; each span then costs one atomic read.

```console
$ trunc --profile run.json x big.tar.zst -C out --consume --yes
...
profile: 3.71 s wall, 15279 spans on 79 threads
      self      total     calls       mean       bytes       MB/s  span
    4.62 s     4.62 s       492     9.4 ms                         fs.flush
    2.42 s     2.42 s      3278   739.8 us                         zstd.sequences
  358.6 ms   358.8 ms       487   736.8 us                         fs.open
  351.7 ms   356.3 ms         5    71.3 ms                         fs.flush_all
  191.4 ms   191.4 ms       690   277.4 us   201.8 MiB     1105.3  fs.write
  180.9 ms   180.9 ms         3    60.3 ms    62.4 MiB      361.7  fs.deallocate
  ...
   11.6 ms     3.70 s         1     3.70 s                         stream.consume
  898.8 us     1.28 s         1     1.28 s    65.5 MiB       53.7  stream.scan
  ...
hot paths (self time by call path):
    4.62 s       487  fs.flush
    1.29 s      1625  cli.extract > stream.consume > decode.zstd > zstd.block > zstd.sequences
    1.13 s      1639  cli.extract > stream.consume > stream.scan > decode.zstd > zstd.block > zstd.sequences
  350.5 ms       479  fs.open
  275.7 ms         3  cli.extract > stream.consume > decode.zstd > stream.checkpoint > stream.flush_outputs > fs.flush_all
  ...
(self: time not spent in nested spans on the same thread; parallel threads add up)
trace written to run.json (open it in https://ui.perfetto.dev or chrome://tracing)
```

The first line gives the wall time from the first span to the last, and how many spans and threads were recorded. Each row of the table is one span name, sorted by self time. The table shows the top 30:

| Column | Meaning |
|---|---|
| `self` | time inside the span, minus the spans nested in it on the same thread |
| `total` | time inside the span, nested spans included |
| `calls` | how many times it ran |
| `mean` | `total` divided by `calls` |
| `bytes` | data the span handled, for spans that count it (reads, writes, decoders, punching) |
| `MB/s` | `bytes` divided by `total`, in millions of bytes per second |

Self time is where the time went; total time is what a phase cost. In the example, `stream.scan` has a total of 1.28 s: that is the read-only first pass. `stream.consume` covers nearly the whole run but has almost no self time, because the work happens in the spans inside it.

Self times on different threads add up, so they can exceed the wall time. Flushes run on many threads at once: `fs.flush` shows 4.62 s of self time in a 3.71 s run, and the main thread's wait for them is the 356 ms total of `fs.flush_all`. Decoders working ahead (see [Parallel decoding](#parallel-decoding)), `.trnc` decoding and `create` also run on worker threads.

*Hot paths* list the 15 call paths with the most self time, which shows who made the slow calls. The two `zstd.sequences` paths above split the decoder's time between the scan and the consume pass. A path starts at the outermost span on its own thread, so work done on worker threads has no parent: `fs.flush` here, and `fs.open`, because outputs are opened ahead of their data.

Some patterns to look for:

- Most self time in `decode.*`, `inflate.*`, `bzip2.*`, `xz.*` or `zstd.*`: decoding is the limit. Unless the file decodes in parallel, that is one core per pass.
- Most in `fs.flush` or `fs.flush_all`: the disk is the limit. A larger `--checkpoint-every` or `--batch` flushes less often, but needs more free space.
- Large `fs.deallocate` or `fs.set_len`: freeing archive space is slow on this filesystem.
- Many short `fs.open`, `fs.set_modified` and `fs.close` calls: the archive has many small files.

To see every thread on a timeline, open the trace file in <https://ui.perfetto.dev> (Open trace file, or drag the file onto the page), `chrome://tracing` (Load), or <https://www.speedscope.app>. Threads are named `main` and `worker N`; spans that count bytes carry the count as an argument. At most 5 million spans are kept; the first line of the summary says how many more were dropped.

Spans are named by layer:

| Span | What it measures |
|---|---|
| `cli.create`, `cli.extract`, `cli.resume`, `cli.inspect`, `cli.verify`, `cli.plan`, `cli.key` | the whole command |
| `fs.open`, `fs.read`, `fs.write`, `fs.close` | opening, reading, writing and closing files |
| `fs.flush`, `fs.flush_dir`, `fs.flush_all` | making file data and directory entries durable; `flush_all` flushes a set of files and directories in parallel |
| `fs.read_back` | `--verify-media` reading output back from the disk, not the cache |
| `fs.deallocate`, `fs.allocated_ranges` | releasing space inside a file (punching), and listing what is still allocated |
| `fs.set_len`, `fs.preallocate` | setting a file's length (shrinking the archive), and reserving space |
| `fs.create_dir`, `fs.read_dir`, `fs.remove`, `fs.rename`, `fs.metadata`, `fs.set_mode`, `fs.set_modified` | other filesystem calls |
| `fs.probe_volume` | identifying the filesystem, its free space and its features |
| `hash.blake3` | BLAKE3 hashing |
| `journal.create`, `journal.write` | creating the journal, and writing a checkpoint to it |
| `decode.gzip`, `decode.bzip2`, `decode.xz`, `decode.zstd` | one decoder run over a compressed stream (once per pass) |
| `inflate.block` | one Deflate block (gzip and ZIP) |
| `bzip2.find_blocks` | searching the file for block starts, so blocks can decode in parallel |
| `bzip2.block`, `bzip2.huffman`, `bzip2.bwt`, `bzip2.rle_crc` | one bzip2 block, and its phases: Huffman and move-to-front decoding, the inverse Burrows-Wheeler transform, and the last run-length step with the CRC |
| `xz.index_scan` | reading stream indexes from the end of the file, to find blocks that can decode in parallel |
| `xz.chunk`, `xz.check` | one LZMA2 chunk; the block's CRC or SHA-256 check |
| `zstd.frame_scan` | finding frames that declare their size, so they can decode in parallel |
| `zstd.block`, `zstd.literals`, `zstd.sequences`, `zstd.checksum` | one zstd block, its literals and sequences sections, and the frame's XXH64 checksum |
| `tar.parse` | reading tar headers during the scan |
| `stream.scan` | the read-only first pass over a compressed tarball or file |
| `stream.consume` | a whole consume of a compressed tarball or file, scan included |
| `stream.extract` | a whole extraction without `--consume`, scan included |
| `stream.route` | splitting decoded output into files |
| `stream.checkpoint` | one checkpoint: `stream.flush_outputs` (flush the outputs and the gap log), `stream.verify_interval` (compare the content hash with the scan's), then `stream.free` (release compressed bytes, or delete finished parts) |
| `stream.restore_window` | reading the decoder window back from the output on resume |
| `stream.finish` | removing the archive, journal and gap log at the end |
| `stage.build`, `stage.rename` | building the staging tree, and moving it into place |
| `trnc.block`, `trnc.decompress` | one `.trnc` block (hash, decompress, hash again), and its decompression |
| `consume.batch` | one `.trnc` consume batch, with its phases `consume.decode`, `consume.write`, `consume.flush`, `consume.verify_media` and `consume.release` |
| `extract.create_files`, `extract.create` | creating every output file up front, and one of them |
| `extract.decode`, `extract.apply`, `extract.write`, `extract.finish` | decoding a round of `.trnc` blocks, writing one block's data, one write, and finishing a file |
| `create.walk`, `create.read_inputs`, `create.compress`, `create.spool`, `create.sync`, `create.assemble` | `trunc create`: listing inputs, reading them, compressing blocks in parallel, writing them to a spool file, flushing, and writing the archive |
| `zip.group`, `zip.entry`, `zip.decode_entry`, `zip.release` | a group of ZIP entries flushed together, one entry, decoding and checking one entry, and releasing its bytes |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (for `plan`: both modes fit) |
| 1 | Error or refusal; nothing unsafe was done |
| 2 | `plan`: only `--consume` fits |
| 3 | `plan`: neither fits |
| 75 | `--consume` paused safely; resume later |
