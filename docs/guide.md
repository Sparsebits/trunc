# trunc user guide

`trunc` extracts archives while consuming them: as each piece is safely extracted, the archive shrinks by that piece. You need about *output size − archive size* of free space instead of the full output size. It works with its own `.trnc` format and with existing ZIP and `.tar.gz` files.

## Quick start

```sh
trunc plan big.trnc -C D:\out                 # how much space each mode needs, and any warnings
trunc x big.trnc -C D:\out --consume          # extract, destroying the archive as it goes
trunc resume big.trnc                          # after a crash, power cut, kill or pause
```

`trunc x` without `--consume` is an ordinary extraction that leaves the archive alone.

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
- **Nothing is destroyed until it has been verified and made durable.** Each piece's hash (or ZIP CRC) is checked before its source is released; `.tar.gz` archives are checked in full before anything is written. The output is flushed to disk, and only then is the source released.
- **Files appear all at once at the end.** Output goes into a hidden `.trunc-stage-…` folder inside the destination and is moved into place when everything is done. Existing files at the destination are never overwritten. `--consume` refuses to start if a top-level name already exists.
- **It stops safely when it can't continue.** If the disk fills up, or another program keeps the archive open, it pauses (exit code 75). Free some space or close the program, then resume.
- **It tells you before risky situations.** It refuses to run on an archive inside a cloud-synced folder (the sync client could upload every truncation and replace your cloud copy), on FAT32/exFAT, which have no journal, or on a filesystem it cannot identify (network shares, FUSE, WSL's view of Windows drives). Override with `--allow-sync` or `--allow-unjournaled` if you are sure.

## What it does not promise

- **The archive is gone afterwards.** For `.trnc`, a small `<archive>.receipt` (header and signed manifest) is kept unless you pass `--no-receipt`. For ZIP and `.tar.gz`, nothing remains, and other tools cannot open the file once the first step has run.
- **Space figures are upper bounds, not exact predictions.** Other programs writing to the same disk, filesystem compression and quotas are outside its view.
- **Snapshots defeat it.** With System Restore / Volume Shadow Copies, Time Machine local snapshots, or btrfs/ZFS snapshots, truncated data stays allocated and no space is freed. `trunc plan` says when it could not check.
- **Drives that ignore flush commands** (some cheap USB sticks and SD cards) can lose data on power loss no matter what software does. `--verify-media` reads extracted data back from disk, bypassing the OS cache, before releasing the source. It catches many such problems, at the cost of one extra read.
- **It is designed for one machine and one user.** Don't extract destructively into a folder that other people can write to.

## ZIP files

`trunc x file.zip -C out --consume` handles Stored and Deflate entries, Zip64, self-extracting archives and names in UTF-8 or the old DOS code page. Encrypted archives, other compression methods and spanned archives (`.z01`, `.z02`, …) are refused; parts cut by `split` or 7-Zip (`.001`) are read as one file (see [Split archives](#split-archives)).

For ZIPs containing a few very large files, **punch mode** frees space *inside* each large entry as it decompresses, on NTFS and other filesystems that support sparse files. It applies to entries whose compressed size is at least `--punch-min` (default 256 MiB). Each such entry is fully verified once before any of it is freed. `--no-punch` turns it off.

## Compressed tarballs and files

`trunc x file.tar.gz -C out --consume` handles tar archives compressed with gzip, bzip2, xz or zstd (`.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`), from GNU tar, bsdtar, Python and most other writers: ustar, GNU long names, PAX headers, files over 8 GiB, and several gzip members, bzip2 streams, xz streams or zstd frames back to back (as `pigz`, `pbzip2`, `xz -T0` and `pzstd` write them). The format is recognised from the content, not the name. Symlinks and device entries are skipped. Hard links, sparse files and multi-volume archives are refused for now.

A compressed file that is not a tar archive (`disk.img.xz`, `dump.sql.gz`) is decompressed into one file named without the suffix, in the destination: `trunc x disk.img.xz --consume` leaves `disk.img`. `--raw` does the same for a tarball, so `trunc x big.tar.zst --raw --consume` turns it into `big.tar` in place.

A compressed stream can only be decoded from the start, so trunc frees space from the front of the archive. It first decompresses the whole archive once to check every checksum and tar header, without writing anything. Then it extracts, and every 64 MiB of output (`--checkpoint-every`) it confirms the output matches that first pass, saves its position in a small journal, and frees the compressed bytes already used. The file keeps its size, but those bytes stop taking up disk space. That needs a filesystem that can free space inside a file (NTFS, ext4, XFS, btrfs, ZFS). Elsewhere `--consume` still works, but needs as much space as a normal extraction.

xz and zstd decoders look back up to 8-128 MiB. When a consume resumes, trunc reads that window back from the files it has already written, plus a small sidecar (`<archive>.trncg`) holding the tar headers, so the journal stays small. `--max-window` (default 256M) refuses archives that would need more memory than that.

The scan means the archive is decompressed twice. `trunc plan`, `inspect` and `verify` scan it too, since compressed streams record no reliable sizes.

Signatures apply only to `.trnc` archives: `--require-signed` and `--trust-key` are refused for ZIP and compressed files rather than ignored.

## Split archives

Pass the first part of a split archive (`big.tar.zst.001` or `big.tar.zst.aa`) and trunc reads the parts as one file: `x`, `inspect`, `verify` and `plan` work for every format. Naming a later part is an error that points at the first.

With `--consume`, compressed tarballs and files delete each part as soon as its data is safely extracted. This frees space on any filesystem, FAT32 and exFAT included (which still need `--allow-unjournaled`). Split ZIP and `.trnc` archives can be extracted but not consumed yet.

## Names on Linux and macOS

`.trnc` archives only hold names that work on Windows, macOS and Linux. Archives from other tools often don't: Linux tarballs contain names with backslashes or colons, and source trees have files that differ only in case (`Makefile` and `makefile`). On Linux and macOS, trunc accepts the names the system can hold; on Windows it refuses them before writing anything. Names that could reach outside the destination (`..`, absolute paths, `C:` prefixes) are refused everywhere.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (for `plan`: both modes fit) |
| 1 | Error or refusal; nothing unsafe was done |
| 2 | `plan`: only `--consume` fits |
| 3 | `plan`: neither fits |
| 75 | `--consume` paused safely; resume later |
