# weightdrop

**Unpack model weights and datasets on GPU boxes with small disks.**

You rented a GPU box with a 400 GB NVMe. Your dataset is 300 GB of `.tar.zst` shards, and it
unpacks to 320 GB. A plain `tar -x` needs 620 GB at once: the archives plus everything inside.
It doesn't fit, so you start deleting shards by hand, or you pay for a bigger disk.

weightdrop unpacks the set one shard at a time and frees each archive's space *while* it is
being decoded. On that box it needs the archives plus about one shard's worth of slack, roughly
320 GB in total, and it checks the numbers before it touches anything.

```console
$ weightdrop plan ./shards -C /data
shard                     archive      content    own peak+     set peak
train-000000.tar.zst      3.00 GB      3.20 GB      0.30 GB    300.30 GB
...
peak on disk  320.10 GB (while unpacking train-000099.tar.zst)
free space needed at /data:
  plain extract (--keep)       320.00 GB   DOES NOT FIT
  weightdrop unpack             20.10 GB   fits
  saving                       299.90 GB

$ weightdrop unpack ./shards -C /data
[37/100] 118.40 GB / 320.00 GB  ETA 14m02s
```

Kill it, lose power, run out of space: run the same command again and it picks up where it
stopped. Nothing is lost.

Built on [trunc](../../../README.md), which does the crash-safe, resumable "extract while
freeing the archive" work for each shard.

## Install

From this repository:

```sh
cargo install --path crates/flavors/weightdrop
```

## Usage

```sh
weightdrop plan   <shards...> [-C <dest>]
weightdrop unpack <shards...> [-C <dest>] [--keep] [--flatten] [--ignore-space]
```

`<shards...>` can be shard files, a directory of shards, or a glob in the file name
(`'data/train-*.tar.zst'`, quoted so the shell leaves it alone on Windows).

What weightdrop recognises as a shard set:

| Naming                                   | Example                                  |
| ---------------------------------------- | ---------------------------------------- |
| WebDataset                               | `train-000000.tar.zst`, `shard_0001.tgz` |
| `-of-N` (Hugging Face and friends)       | `train-00000-of-00042.tar.gz`            |
| split parts of one archive               | `weights.tar.zst.001`, `weights.tar.zst.aa` |
| a lone archive                           | `checkpoint.tar.xz`                      |

Shards are ordered by number, not by name. Codecs can be mixed inside a set (`.tar.gz`,
`.tar.zst`, `.tar.xz`, `.tar.bz2`, `.tgz`, ...), and the codec is checked from the content, not
the name. Several sets in one directory (`train-*`, `val-*`) are unpacked one after another.
Files that aren't archives (`README.md`, `dataset_info.json`) are listed and skipped.

Refused up front, before any archive is touched:

- **gaps in the numbering** (`train-000003` missing, or `-of-00042` with only 41 shards). An
  incomplete download is usually a mistake, so weightdrop names the missing numbers.
- duplicate numbers (`x-000001.tar.gz` and `x-000001.tar.zst`)
- **name collisions** between shards (see layout below), and outputs that already exist
- a set that does not fit in the free space (`--ignore-space` overrides this)

### Output layout

By default every shard unpacks straight into `-C <dest>`, which is what WebDataset-style shards
of flat sample files want. If two shards would create the same top-level name, weightdrop
notices that during planning and gives each shard its own folder (`<dest>/train-000000/`, ...)
instead. With `--flatten`, a collision is an error and nothing is changed.

### `--keep`

Plain extraction. The archives stay, so you need room for everything. Use it when the archives
live on storage you don't want changed.

### Resuming

weightdrop keeps a small state file, `<dest>/.weightdrop-state`, that records the shard list,
the layout it chose and which shards are finished. A shard that was interrupted halfway is
continued by trunc from its own journal (`<shard>.trncj` next to the shard). Run the same
`unpack` command again to continue. The state file is removed when the set is finished.

## Honest limits (v0)

- **Compressed tarballs only.** Uncompressed `.tar` shards (common for Hugging Face WebDataset
  repos) are recognised but refused: trunc cannot consume a plain tar yet. ZIP and `.safetensors`
  files are not handled by weightdrop. For a single ZIP, use `trunc x --consume`.
- **Everything is decoded twice.** Compressed tarballs record no sizes, so the plan scans every
  remaining shard read-only before anything is consumed, then trunc decodes each shard again
  as it consumes it. Expect about twice the decode time of a plain extract. That is the price
  of refusing before anything is destroyed.
- **Saving needs a filesystem that can free space inside a file** (ext4, XFS, btrfs, ZFS,
  NTFS). Elsewhere only whole shards are freed, one at a time, and `plan` says so. Archives on
  another volume than the destination free nothing there.
- The flat layout merges shards by **top-level name**. Two shards that both contain a `train/`
  folder go into per-shard folders (or are refused with `--flatten`). They are never merged
  into one folder.
- Symlinks and device entries inside shards are skipped, as in `trunc x --consume`.
- The progress line shows bytes written in this run. A shard resumed from its journal is
  reported per shard only.
- The plan is an estimate built from trunc's per-shard planner plus a safety margin.
  `--ignore-space` exists for when you know better.
