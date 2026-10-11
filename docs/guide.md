# trunc user guide

trunc extracts an archive and gives its disk space back as it goes. Each piece of the archive is released as soon as the files it holds are verified and flushed to disk, so you need about *output size − archive size* of free space instead of the full output size. It works with the archives you already have: ZIP files, tarballs compressed with gzip, bzip2, xz or zstd, single compressed files, ISO 9660 disc images and archives split into parts. It also extracts container images to their root filesystem, and has its own `.trnc` format built for this.

The first part of this guide explains what consuming does and what it promises. The second part walks through each kind of archive. The [commands and options](#commands-and-options) and [exit codes](#exit-codes) are at the end.

**Contents**

- Concepts: [quick start](#quick-start), [what `--consume` does](#what---consume-does), [supported formats](#supported-formats), [what `--consume` promises](#what---consume-promises), [what it does not promise](#what-it-does-not-promise)
- Tasks: [planning](#checking-the-space-first), [resuming](#resuming-after-an-interruption), [ZIP files](#zip-files), [compressed tarballs and files](#compressed-tarballs-and-files), [ISO images](#iso-images), [split archives](#split-archives), [container images](#container-images), [creating `.trnc` archives](#creating-archives), [names on Linux and macOS](#names-on-linux-and-macos), [parallel decoding](#parallel-decoding), [performance and profiling](#performance-and-profiling)
- Reference: [commands and options](#commands-and-options), [exit codes](#exit-codes)

## Quick start

```sh
trunc plan big.zip -C ./out              # how much space each mode needs, and any warnings
trunc x big.zip -C ./out --consume       # extract, destroying the archive as it goes
trunc resume big.zip                     # after a crash, power cut, kill or pause
```

`trunc x` without `--consume` is an ordinary extraction that leaves the archive alone. The same commands work for every format below; trunc recognizes the format from the file's content, not its name.

## What `--consume` does

An ordinary extractor reads the archive and writes the files next to it, so at its peak the disk holds both: the archive and everything in it. `--consume` removes that overlap. trunc works through the archive in steps, and after each step, once the files it wrote are verified and flushed, it releases the part of the archive they came from. The disk holds the output plus whatever part of the archive has not been extracted yet, plus one step's worth of working room.

How a part is released depends on the format:

- **From the end.** `.trnc`, ZIP and ISO archives are extracted from the end of the file towards the start, and the file is shortened after each step. Shortening a file works on every filesystem.
- **From the front.** A compressed stream can only be decoded from the start, so trunc frees the bytes it has already decoded while the file keeps its size. This needs a filesystem that can free space inside a file (NTFS, ext4, XFS, btrfs, ZFS). ZIP and ISO use the same technique, called punch mode, inside single large files.
- **Part by part.** Split archives lose each part file once its data is safely extracted. This works on every filesystem.

Output goes to a hidden staging folder inside the destination and is moved into place at the end, so you never see half-written files. When it finishes, the archive is gone; for `.trnc`, a small receipt holding the archive's manifest is kept. If it is interrupted, nothing is lost: run the same command again, or `trunc resume`.

## Supported formats

| Format | Extract | `--consume` | When space comes back | Resume reads |
|---|---|---|---|---|
| ZIP: Stored, Deflate, Zip64 | yes | yes | From the end, after each group of entries. Entries of 256 MiB or more (`--punch-min`) also every 64 MiB while they decompress | `<archive>.trncj` and the archive's length |
| `.tar.gz`, `.tgz`, `.gz` | yes | yes | From the front, every 64 MiB of output (`--checkpoint-every`), at the next Deflate block. BGZF files (`bgzip`): between members | `<archive>.trncj` |
| `.tar.bz2`, `.bz2` | yes | yes | From the front, every 64 MiB, at the next bzip2 block | `<archive>.trncj` |
| `.tar.xz`, `.xz` | yes | yes | From the front, every 64 MiB, at the next LZMA2 chunk. Files with several blocks per stream (`xz -T0`): at the next block | `<archive>.trncj`, plus the decoder window read back from the output |
| `.tar.zst`, `.zst` | yes | yes | From the front, every 64 MiB, at the next zstd block. Frames that declare their size, in files of several frames (`pzstd`): at the end of the frame | `<archive>.trncj`, plus the decoder window read back from the output |
| ISO 9660 images (`.iso`), with Rock Ridge or Joliet names | yes | yes | As for ZIP: from the end after each group of files, and every 64 MiB inside files of 256 MiB or more | `<archive>.trncj` and the archive's length |
| Compressed tarball or file split into `.001` or `.aa` parts | yes | yes | As above, and each part is deleted once its data is safely extracted | `<archive>.trncj` |
| ZIP, ISO or `.trnc` split into parts | yes | no | — | — |
| Container images: `docker save` and OCI archives, plain or compressed | yes | no | — | — |
| `.trnc` | yes | yes | From the end, after each batch of blocks (`--batch`, default 256 MiB of output) | the archive's length |

On filesystems that cannot free space inside a file, compressed archives still consume safely but give their space back only at the end, and a large ZIP entry or ISO file only once it is finished. Deleting split parts works everywhere.

Every format that can be consumed resumes with `trunc resume <archive>` or by running the same command again.

## What `--consume` promises

- **Nothing is lost if it is interrupted.** Every byte is always either still in the archive or safely written at the destination. Run the same command again, or `trunc resume <archive>`, to continue. This is tested by crashing it at every single filesystem operation, under models where unflushed writes are lost or survive in any order.
- **Nothing is destroyed until it has been verified and made durable.** Each piece's hash (or ZIP CRC) is checked before its source is released; compressed tarballs and files are decompressed and checked in full before anything is written. The output is flushed to disk, and only then is the source released.
- **Files appear all at once at the end.** Output goes into a hidden staging folder, `.trunc-stage-…`, inside the destination and is moved into place when everything is done. Existing files at the destination are never overwritten: `--consume` refuses to start if a top-level name already exists.
- **It stops safely when it can't continue.** If the disk fills up, or another program keeps the archive open, it pauses (exit code 75). Free some space or close the program, then resume.
- **It warns you about risky situations.** It refuses to run on an archive inside a cloud-synced folder (the sync client could upload every truncation and replace your cloud copy), on FAT32 or exFAT, which have no journal, or on a filesystem it cannot identify (network shares, FUSE, WSL's view of Windows drives). Override with `--allow-sync` or `--allow-unjournaled` if you are sure.

## What it does not promise

- **The archive is gone afterwards.** For `.trnc`, a small `<archive>.receipt` (header and signed manifest) is kept unless you pass `--no-receipt`. For ZIP, ISO and compressed archives, nothing remains, and other tools cannot open the file once the first step has run.
- **Space figures are upper bounds, not exact predictions.** Other programs writing to the same disk, filesystem compression and quotas are outside its view.
- **Snapshots defeat it.** With System Restore (Volume Shadow Copies), Time Machine local snapshots, or btrfs and ZFS snapshots, truncated data stays allocated and no space is freed. `trunc plan` says when it could not check.
- **Drives that ignore flush commands** (some cheap USB sticks and SD cards) can lose data on power loss no matter what software does. `--verify-media` reads extracted data back from disk, bypassing the OS cache, before releasing the source. It catches many such problems, at the cost of one extra read.
- **It is designed for one machine and one user.** Don't consume an archive into a folder that other people can write to.

## Checking the space first

`trunc plan` reads the archive, looks at the destination's filesystem, and prints the free space each mode needs. It changes nothing.

```sh
trunc plan big.tar.zst -C ./out
```

It also warns about cloud-sync folders, snapshots and filesystems where consuming is unsafe. Its exit code says what fits: 0 if both modes fit, 2 if only `--consume` fits, 3 if neither does (see [Exit codes](#exit-codes)). For compressed tarballs it decompresses the archive once to find the sizes, since compressed streams record no reliable sizes. `trunc plan` does not support container images yet; `trunc inspect` shows their layer sizes.

`trunc x` also checks the free space before it starts and refuses if the output will not fit. `--ignore-space` starts anyway.

## Resuming after an interruption

If a consume stops for any reason (a crash, a power cut, Ctrl-C, a full disk, another program holding the archive open), continue it with either of:

```sh
trunc resume big.zip              # uses the destination recorded when the consume started
trunc x big.zip -C ./out --consume
```

For `.trnc` the archive's length records the progress. For the other formats, a small journal next to the archive (`<archive>.trncj`) does. Leave the journal where it is until the consume finishes; trunc removes it at the end. `trunc inspect` shows when an archive is partly consumed.

## ZIP files

`trunc x file.zip -C out --consume` handles Stored and Deflate entries, Zip64, data descriptors, self-extracting archives, and names in UTF-8 or the old DOS code page. Encrypted archives, other compression methods and spanned archives (`.z01`, `.z02`, …) are refused; parts cut by `split` or 7-Zip (`.001`) are read as one file (see [Split archives](#split-archives)).

ZIP files weren't designed to be taken apart from the end, so trunc does more work before it deletes anything:

1. It reads the ZIP's index and checks every entry against it. It refuses archives whose entries overlap, a trick used by zip bombs, unless you pass `--allow-overlap`.
2. It decompresses every entry once and checks its CRC.
3. It saves the ZIP's layout to a small journal next to the archive (`<archive>.trncj`). The index lives at the end of the ZIP, so it is the first thing to go.
4. It extracts entries from the end of the file to the start, shrinking the archive after each group of entries.

From the first deletion on, other tools can no longer open the ZIP. trunc tells you this before it starts.

### Punch mode

A single 50 GB entry would normally need 50 GB of headroom, because the archive can't shrink until that entry is finished. **Punch mode** avoids this by freeing space *inside* the entry while it decompresses. It applies to entries whose compressed size is at least `--punch-min` (default 256 MiB). trunc decompresses such an entry with its own Deflate decoder, which can save its position: every 64 MiB of output, it saves its position in the journal and releases the compressed bytes it has already read. The file keeps its size, but those bytes stop taking up disk space.

Each punched entry is fully verified once before any of it is freed. Punch mode needs a filesystem that supports sparse files (NTFS, ext4, XFS, btrfs, ZFS). `--no-punch` turns it off.

## Compressed tarballs and files

`trunc x file.tar.gz -C out --consume` handles tar archives compressed with gzip, bzip2, xz or zstd (`.tar.gz` or `.tgz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`), from GNU tar, bsdtar, Python and most other writers: ustar, GNU long names, PAX headers, files over 8 GiB, several gzip members, bzip2 streams, xz streams or zstd frames back to back, and xz streams of many blocks (files from `pigz`, `bgzip`, `pbzip2`, `pzstd`, `xz -T0` and `zstd --long` all work). The format is recognized from the content, not the name. Symlinks and device entries are skipped. Hard links, sparse files and multi-volume archives are refused for now.

A compressed stream can only be decoded from the start, so trunc frees space from the front of the archive, in two passes:

1. It decompresses the whole archive once, writing nothing (the *scan*). This checks every checksum and tar header, validates every file name, and records a hash of each 64 MiB stretch of output.
2. It decompresses again, this time writing files. Every 64 MiB of output (`--checkpoint-every`), it flushes the files, checks that the stretch it just wrote hashes the same as in the first pass, saves its position in a small journal, and releases the compressed bytes it has used.

The file keeps its size, but the released bytes stop taking up disk space. That needs a filesystem that can free space inside a file (NTFS, ext4, XFS, btrfs, ZFS). Elsewhere `--consume` still works, but needs as much space as a normal extraction.

Saving a position means saving the decompressor's state, which off-the-shelf libraries don't allow, so trunc has its own decoders for all four formats. They are tested and fuzzed against the reference implementations.

xz and zstd decoders look back up to 8–128 MiB. When a consume resumes, trunc reads that window back from the files it has already written, plus a small gap log (`<archive>.trncg`) holding the tar headers, so the journal stays small. `--max-window` (default 256M) refuses archives that would need more memory than that.

The first pass means the archive is decompressed twice. `trunc plan`, `inspect` and `verify` make the same pass, since compressed streams record no reliable sizes. Both passes use every core where the file allows it (see [Parallel decoding](#parallel-decoding)).

A compressed file that is not a tar archive (`disk.img.xz`, `dump.sql.gz`) is decompressed into one file named without the suffix, in the destination: `trunc x disk.img.xz --consume` leaves `disk.img`. `.tgz`, `.txz` and the other short forms become `.tar`; a name without a known suffix gets `.out` added. `--raw` does the same for a tarball, so `trunc x big.tar.zst --raw --consume` turns it into `big.tar` in place.

Signatures apply only to `.trnc` archives: `--require-signed` and `--trust-key` are refused for ZIP, ISO and compressed files rather than ignored.

## ISO images

```sh
trunc plan disc.iso -C ./disc              # space needed, and any shared or overlapping files
trunc x disc.iso -C ./disc --consume       # extract, shrinking the image as it goes
trunc inspect disc.iso --entries           # volume name, name scheme and the file list
trunc verify disc.iso                      # check the structure; ISO 9660 has no checksums
```

A disc image is not compressed, so its files take up about as much space as the image itself, and extracting it next to itself normally needs the image's size again. Each file in an ISO 9660 image is one contiguous stretch of the image, like a stored ZIP entry, and trunc consumes it the same way: from the end of the image to the start, shrinking the image after each group of files, with [punch mode](#punch-mode) inside files of 256 MiB or more. The flags are the ZIP ones: `--punch-min`, `--no-punch` and `--allow-overlap`.

- **Every file is read before anything is freed.** ISO 9660 stores no checksums, so on a fresh start trunc reads every file once and records a CRC-32 for it in the journal (`<archive>.trncj`). A file whose bytes change between that pass and its extraction, or a resume, is refused before its part of the image is released. Plain extraction skips this pass, and `trunc verify` checks only the structure: every extent in bounds, no loops and no overlaps.
- **Names.** trunc uses Rock Ridge names when the image has them, else the Joliet names, else the plain ISO 9660 names with the `;1` version suffix removed. Hidden files are extracted. Symlinks, devices, FIFOs and resource forks are skipped. Names then follow the same rules as other formats (see [Names on Linux and macOS](#names-on-linux-and-macos)).
- **Hard links.** Some authoring tools store one copy of identical files and point several names at it. Plain extraction writes each name in full. Consuming such an image needs `--allow-overlap`, and turns punch mode off, so the working room is the largest group of files instead of 64 MiB.
- **What is refused.** UDF-only images (hybrid ISO/UDF images use their ISO 9660 side), block sizes other than 2048 bytes, multi-volume sets, interleaved files, and damaged or crafted images with loops, overlapping directories or extents past the end of the file. Boot images and HFS or APM partitions are not extracted as such; only the files in the ISO 9660 tree are.

## Split archives

Pass the first part of a split archive (`big.tar.zst.001` or `big.tar.zst.aa`) and trunc reads the parts as one file: `x`, `inspect`, `verify` and `plan` work for every format. Naming a later part is an error that points at the first.

With `--consume`, compressed tarballs and files delete each part as soon as its data is safely extracted. This frees space on any filesystem, even on a USB stick formatted FAT32 or exFAT (which still needs `--allow-unjournaled`). Split ZIP, ISO and `.trnc` archives can be extracted but not consumed yet.

## Container images

```sh
trunc x image.tar -C ./rootfs                                    # docker save, or skopeo copy … oci-archive:
trunc x images.tar.zst -C ./rootfs --image app:1.4 --platform linux/arm64
trunc inspect image.tar --entries                                # layers and their sizes, and the merged files
trunc verify image.tar                                           # check every blob and layer digest
```

A tarball written by `docker save` or by `skopeo copy … oci-archive:` holds the image's metadata and one blob per layer. Extracting it as an ordinary tarball would give you those blobs; `trunc x` gives you the image's root filesystem instead: the layers applied in order, the files `docker export` of a container would give, without a container runtime. The outer tar may be plain or compressed with gzip, bzip2, xz or zstd, and layers may be plain or compressed with gzip or zstd. trunc recognizes an image from its content. `--raw` turns this off, so a compressed image can still be decompressed into its outer `.tar`.

- **Choosing an image.** When the archive holds several images or platforms, `--image NAME` picks one by tag (`name:tag`) or OCI reference name, and `--platform OS/ARCH[/VARIANT]` by platform. Otherwise trunc uses the only one, or the one for this computer's architecture; anything still ambiguous is refused with a list of what is there.
- **Everything is checked by digest.** Metadata and layer blobs are checked against the digests recorded for them, and every decoded layer against the image config's `diff_ids`, once while merging and again while writing. Only `sha256` digests are accepted, and encrypted layers are refused.
- **Nothing is written twice or deleted.** trunc decodes every layer once to merge them, resolving deletions (whiteouts) and replacements in memory, and then again to write only the files that survive into a staging folder, which is moved into place at the end. A file that a later layer deletes or replaces is never written.
- **The result is not a complete runtime root.** As for tarballs, symlinks, device nodes and FIFOs are not created (they are counted and reported), so images with a merged `/usr` lose `/bin`, `/lib` and the like. Ownership, directory modes and directory times are not applied, and hard links are refused. On Windows, Linux names that Windows cannot hold make the image refused (see [Names on Linux and macOS](#names-on-linux-and-macos)).
- **Space.** You need room for the merged root filesystem. A compressed image is first decompressed into a temporary file (in the destination for `x`, next to the archive for `inspect` and `verify`), which is removed afterwards.

`--consume` is refused for images. A later layer can delete or replace anything an earlier one added, so no layer can be freed until every layer after it is applied, and consuming would save no space over extracting and then deleting the archive. `--overwrite`, `--allow-symlinks`, `--require-signed` and `--trust-key` are refused too. `trunc plan` does not support images yet; `trunc inspect` shows the layer sizes.

## Creating archives

When you make the archive yourself, trunc's own `.trnc` format consumes with the least work: it stores its blocks back to front, so extraction always takes the block at the end of the file, and the archive's length is the only progress record it needs. Its blocks are independent, so they decompress on every core, and each one is hashed; archives can be signed.

```sh
trunc create data.trnc ./folder ./file.txt      # zstd level 9, 8 MiB blocks
trunc create data.trnc ./folder --codec lz4     # faster, larger
trunc create data.trnc ./folder --dict train    # helps with many small similar files
trunc key gen me.key                            # once
trunc create data.trnc ./folder --sign me.key   # recipients can check it came from you
trunc x data.trnc -C ./out --require-signed --trust-key <public key>
```

`--codec` takes `store`, `lz4`, `zstd` or `zstd:LEVEL` (from -7 to 22). `--dict` takes `train`, to train a zstd dictionary from the inputs, or the path of a dictionary file. `--force` replaces an existing output file.

Smaller blocks (`--block-size 4M`) mean less extra space during `--consume`; larger blocks compress slightly better.

## Names on Linux and macOS

`.trnc` archives only hold names that work on Windows, macOS and Linux. Archives from other tools often don't: Linux tarballs contain names with backslashes or colons, and source trees have files that differ only in case (`Makefile` and `makefile`). For tar, ZIP, ISO, single compressed files and container images, trunc follows the computer it runs on:

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
- **gzip**: BGZF files, as written by `bgzip`, samtools and htslib. Each member is at most 64 KiB and its header gives its size, so the members can be found without decoding them.

Other gzip files, single-block xz and single-frame zstd files decode on one core. Compressed archives always use every core they can; `--threads` applies only to `.trnc`.

Both passes of a consume run in parallel, and so do `plan`, `inspect` and `verify`. A 437 MiB `.tar.xz` from `xz -T0` verifies in 0.65 s instead of 4.1 s. If you make the archive yourself and want it to extract fast, compress with `xz -T0`, `pzstd`, `bgzip` or bzip2.

What this means for space and memory:

- **Space comes back a whole block or frame at a time.** An xz block or zstd frame decoded in parallel is decoded whole, so checkpoints fall only between them, and one larger than 64 MiB gives its space back only when it ends. `xz -T0` blocks are three times the dictionary size: 24 MiB at the default level, 192 MiB at `-9`. zstd frames are at most 128 MiB. BGZF members are small, so they change nothing here. If any block in an xz stream produces more than 256 MiB, that stream decodes on one core in the usual 64 MiB steps. `trunc plan` already counts all of this.
- **Up to about 512 MiB of memory** holds parts decoded ahead and not yet written.
- **The core count changes nothing else.** Which parts are decoded whole depends only on the file, so the first pass, the consume and a resume on another computer stop at the same checkpoints.

## Performance and profiling

`--profile FILE` (any command, or `TRUNC_PROFILE=FILE`) records where a run spends its time. When the command finishes, trunc prints a summary to stderr and writes a Chrome trace to `FILE`. `--profile -` prints the summary without writing a file. Profiling is off unless you ask for it; each span then costs one atomic read.

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

*Hot paths* lists the 15 call paths with the most self time, which shows who made the slow calls. The two `zstd.sequences` paths above split the decoder's time between the first pass and the consume pass. A path starts at the outermost span on its own thread, so work done on worker threads has no parent: `fs.flush` here, and `fs.open`, because outputs are opened ahead of their data.

Some patterns to look for:

- Most self time in `decode.*`, `inflate.*`, `bzip2.*`, `xz.*` or `zstd.*`: decoding is the limit. Unless the file decodes in parallel, that is one core per pass.
- Most in `fs.flush` or `fs.flush_all`: the disk is the limit. A larger `--checkpoint-every` or `--batch` flushes less often, but needs more free space.
- Large `fs.deallocate` or `fs.set_len`: freeing archive space is slow on this filesystem.
- Many short `fs.open`, `fs.set_modified` and `fs.close` calls: the archive has many small files.

To see every thread on a timeline, open the trace file in <https://ui.perfetto.dev> (Open trace file, or drag the file onto the page), `chrome://tracing` (Load), or <https://www.speedscope.app>. Threads are named `main` and `worker N`; spans that count bytes carry the count as an argument. At most 5 million spans are kept; the first line of the summary says how many more were dropped.

<details>
<summary><b>Span names</b></summary>

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
| `tar.parse` | reading tar headers during the first pass |
| `stream.scan` | the read-only first pass over a compressed tarball or file |
| `stream.consume` | a whole consume of a compressed tarball or file, first pass included |
| `stream.extract` | a whole extraction without `--consume`, first pass included |
| `stream.route` | splitting decoded output into files |
| `stream.checkpoint` | one checkpoint: `stream.flush_outputs` (flush the outputs and the gap log), `stream.verify_interval` (compare the content hash with the first pass's), then `stream.free` (release compressed bytes, or delete finished parts) |
| `stream.restore_window` | reading the decoder window back from the output on resume |
| `stream.finish` | removing the archive, journal and gap log at the end |
| `stage.build`, `stage.rename` | building the staging tree, and moving it into place |
| `trnc.block`, `trnc.decompress` | one `.trnc` block (hash, decompress, hash again), and its decompression |
| `consume.batch` | one `.trnc` consume batch, with its phases `consume.decode`, `consume.write`, `consume.flush`, `consume.verify_media` and `consume.release` |
| `extract.create_files`, `extract.create` | creating every output file up front, and one of them |
| `extract.decode`, `extract.apply`, `extract.write`, `extract.finish` | decoding a round of `.trnc` blocks, writing one block's data, one write, and finishing a file |
| `create.walk`, `create.read_inputs`, `create.compress`, `create.spool`, `create.sync`, `create.assemble` | `trunc create`: listing inputs, reading them, compressing blocks in parallel, writing them to a spool file, flushing, and writing the archive |
| `zip.group`, `zip.entry`, `zip.decode_entry`, `zip.release` | a group of ZIP entries flushed together, one entry, decoding and checking one entry, and releasing its bytes |

</details>

## Commands and options

| Command | What it does |
|---|---|
| `trunc extract ARCHIVE`, or `trunc x` | Extract an archive; destructive only with `--consume` |
| `trunc plan ARCHIVE` | Report how much free space extracting and consuming need |
| `trunc resume ARCHIVE` | Continue an interrupted or paused consume |
| `trunc inspect ARCHIVE` | Show the header, a summary of the contents and the space needed; `--entries` and `--blocks` list them |
| `trunc verify ARCHIVE` | Check every hash without extracting |
| `trunc create OUT INPUT...` | Pack files and directories into a `.trnc` archive |
| `trunc key gen FILE` | Generate a signing key and print its public key |
| `trunc key show FILE` | Print the public key of a secret key file |

Options for `trunc x`. `resume` takes the same options for consuming, `plan` takes `-C`, `--batch`, `--raw` and `--max-window`, and `verify` takes the trust, stream, image and `--threads` options.

| Option | Default | Meaning |
|---|---|---|
| `-C`, `--dest DIR` | `.` | Destination folder. For `resume`, the one recorded when the consume started |
| `--consume` | | Free the archive as files are extracted. The archive is gone afterwards |
| `-y`, `--yes` | | Don't ask for confirmation before destroying the archive |
| `--verify-media` | | Read extracted data back from the disk, bypassing the OS cache, before releasing the source |
| `--batch SIZE` | `256M` | `.trnc`: output per batch, one flush and one truncation each. Smaller needs less space and flushes more often |
| `--checkpoint-every SIZE` | `64M` | ZIP and compressed archives: output between checkpoints that free compressed data |
| `--punch-min SIZE` | `256M` | ZIP and ISO: stored size from which entries are punched while they are extracted |
| `--no-punch` | | ZIP and ISO: never free space inside an entry |
| `--allow-overlap` | | ZIP and ISO: accept archives whose entries overlap, or ISO files that share data (hard links) |
| `--allow-sync` | | Consume an archive inside a cloud-synced folder |
| `--allow-unjournaled` | | Consume on a filesystem without a journal (FAT32, exFAT) or one trunc cannot identify |
| `--ignore-space` | | Start even if the free-space check says it will not fit |
| `--no-receipt` | | `.trnc`: delete the archive at the end instead of keeping `<archive>.receipt` |
| `--raw` | | Compressed tarballs: decompress into one `.tar` file instead of unpacking it |
| `--max-window SIZE` | `256M` | xz and zstd: refuse streams whose decoder would need more memory than this |
| `--image NAME` | | Container images: which image to use, by tag or reference name |
| `--platform OS/ARCH` | | Container images: which platform to use, as `OS/ARCH` or `OS/ARCH/VARIANT` |
| `--overwrite` | | Replace existing files at the destination. Not with `--consume` |
| `--allow-symlinks` | | `.trnc`: create symlink entries that resolve inside the destination. Not with `--consume` |
| `--require-signed` | | `.trnc`: refuse unsigned archives |
| `--trust-key HEX` | | `.trnc`: accept only archives signed by this public key. Repeatable |
| `--threads N` | `0` (all cores) | `.trnc`: decode threads |
| `--profile FILE` | | Any command: record where the time goes (see [Performance and profiling](#performance-and-profiling)) |

Sizes take a suffix such as `4M` or `1G`. Run `trunc <command> --help` for the full list.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (for `plan`: both modes fit) |
| 1 | Error or refusal; nothing unsafe was done |
| 2 | `plan`: only `--consume` fits |
| 3 | `plan`: neither fits |
| 75 | `--consume` paused safely; resume later |
