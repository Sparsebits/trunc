# trunc user guide

`trunc` extracts archives while consuming them: as each piece is safely extracted, the archive shrinks by that piece. You need about *output size − archive size* of free space instead of the full output size. It works with its own `.trnc` format and with existing ZIP files.

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
- **Nothing is destroyed until it has been verified and made durable.** Each piece's hash (or ZIP CRC) is checked before anything is written. The output is flushed to disk, and only then is the source released.
- **Files appear all at once at the end.** Output goes into a hidden `.trunc-stage-…` folder inside the destination and is moved into place when everything is done. Existing files at the destination are never overwritten. `--consume` refuses to start if a top-level name already exists.
- **It stops safely when it can't continue.** If the disk fills up, or another program keeps the archive open, it pauses (exit code 75). Free some space or close the program, then resume.
- **It tells you before risky situations.** It refuses to run on an archive inside a cloud-synced folder (the sync client could upload every truncation and replace your cloud copy) or on FAT32/exFAT, which have no journal. Override with `--allow-sync` or `--allow-unjournaled` if you are sure.

## What it does not promise

- **The archive is gone afterwards.** For `.trnc`, a small `<archive>.receipt` (header and signed manifest) is kept unless you pass `--no-receipt`. For ZIP, nothing remains, and other ZIP tools cannot open the file once the first step has run.
- **Space figures are upper bounds, not exact predictions.** Other programs writing to the same disk, filesystem compression and quotas are outside its view.
- **Snapshots defeat it.** With System Restore / Volume Shadow Copies, Time Machine local snapshots, or btrfs/ZFS snapshots, truncated data stays allocated and no space is freed. `trunc plan` says when it could not check.
- **Drives that ignore flush commands** (some cheap USB sticks and SD cards) can lose data on power loss no matter what software does. `--verify-media` reads extracted data back from disk, bypassing the OS cache, before releasing the source. It catches many such problems, at the cost of one extra read.
- **It is designed for one machine and one user.** Don't extract destructively into a folder that other people can write to.

## ZIP files

`trunc x file.zip -C out --consume` handles Stored and Deflate entries, Zip64, self-extracting archives and names in UTF-8 or the old DOS code page. Encrypted archives, other compression methods and multi-part archives are refused.

For ZIPs containing a few very large files, **punch mode** frees space *inside* each large entry as it decompresses, on NTFS and other filesystems that support sparse files. It applies to entries whose compressed size is at least `--punch-min` (default 256 MiB). Each such entry is fully verified once before any of it is freed. `--no-punch` turns it off.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (for `plan`: both modes fit) |
| 1 | Error or refusal; nothing unsafe was done |
| 2 | `plan`: only `--consume` fits |
| 3 | `plan`: neither fits |
| 75 | `--consume` paused safely; resume later |
