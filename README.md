<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.png">
    <img alt="trunc: extract huge archives without the free space" src="docs/assets/banner-light.png" width="100%">
  </picture>
</p>

<p align="center"><b>Unpack archives that are bigger than your free space.</b></p>

<p align="center">
  <a href="https://github.com/Sparsebits/trunc/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Sparsebits/trunc/actions/workflows/ci.yml/badge.svg"></a>
  <a href="#license"><img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-ff5b35"></a>
  <img alt="Rust 1.85+" src="https://img.shields.io/badge/rust-1.85%2B-121212">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-121212">
</p>

<p align="center">
  <a href="#installation">Installation</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#supported-formats">Formats</a> ·
  <a href="#faq">FAQ</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="docs/guide.md">User guide</a>
</p>

---

You downloaded a 60 GB dataset as a ZIP, and your laptop has 40 GB free. Every extractor you
have will stop partway: it writes the 60 GB of contents next to the 60 GB archive, which stays
until you delete it. trunc deletes the archive while it extracts. Each piece goes as
soon as the files it held are verified and flushed to disk, so the job needs room for what the
contents add over the archive, not for both. If the power goes out halfway, run the same
command again and it carries on.

<p align="center">
  <img alt="Disk space over time while extracting a 2.76 GiB ZIP into 4.25 GiB of files: tar -xf peaks at 7.00 GiB, trunc x --consume at 4.50 GiB" src="docs/assets/disk-usage.svg" width="100%">
</p>

<p align="center"><sub>
Extracting a 2.76 GiB ZIP (702 files, 4.25 GiB: a 1 GiB video, photos, a 1 GiB CSV and logs).
Grey: Windows' built-in <code>tar -xf</code>. Orange: <code>trunc x --consume</code>. The line is the
space allocated to the archive and the extracted files, read every 100 ms with
<code>GetCompressedFileSizeW</code> (freed parts of the archive count as free). One run each,
NTFS on a Samsung NVMe SSD, AMD Ryzen 7 5800H. Reading 700 files every 100 ms slowed both
runs, so the time axis is longer than an unobserved run.
</sub></p>

```console
$ trunc x dataset.zip -C dataset --consume --yes
all entries consumed; moving files into place
extracted 702 files, 5 directories, 4.25 GiB into dataset
archive   consumed and removed
time      65.54s (12 steps)
```

Leave off `--yes` and trunc asks before it starts. Leave off `--consume` and it is an ordinary
extractor that keeps the archive.

## Highlights

- **Works on the archives you have.** ZIP (including Zip64), `.tar.gz`, `.tar.bz2`, `.tar.xz`,
  `.tar.zst`, single compressed files such as `disk.img.xz`, ISO disc images and split archives
  all give space back while they extract. No repacking, no special format.
- **Less space.** You need about *output size minus archive size* free, not the full output size.
  Inside big files too: a single 50 GB entry gives its space back every 64 MiB.
- **Safe to interrupt.** A part of the archive is released only after the files it produced are
  verified and flushed to disk. `trunc resume` continues after a crash, a kill or a full disk.
- **Plans first.** `trunc plan` tells you how much space each mode needs, and warns about
  cloud-sync folders, snapshots and filesystems where consuming an archive is unsafe.
- **Checks everything.** Every piece is checked against its hash, CRC or codec checksum before
  the archive bytes it came from are freed.
- **Windows and Linux.** Every feature on NTFS, ext4, XFS, btrfs and ZFS. The Linux builds are
  static and run on any distribution.
- **Container images too.** `docker save` and OCI archives extract to their merged root
  filesystem, without a container runtime.
- **Its own format, if you make the archive.** `.trnc` archives decompress in parallel at over
  1 GiB/s and can be signed.

## Installation

On Linux (x86-64 or ARM64, any distribution):

```sh
curl -LsSf https://raw.githubusercontent.com/Sparsebits/trunc/main/install.sh | sh
```

On Windows:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/Sparsebits/trunc/main/install.ps1 | iex"
```

Both scripts download the latest release, check its SHA-256, and install `trunc` to `~/.local/bin`
or `%LOCALAPPDATA%\Programs	runc`. Set `TRUNC_VERSION=v0.1.0` to pin a version, or
`TRUNC_INSTALL_DIR` to install somewhere else. If the [GitHub CLI](https://cli.github.com) is
installed, they also check the release's signed build provenance (see
[Verifying downloads](docs/security.md#verifying-downloads)).

You can also download the archives yourself from
[Releases](https://github.com/Sparsebits/trunc/releases), or build from source with Rust 1.85 or
newer:

```sh
cargo install --git https://github.com/Sparsebits/trunc trunc-cli
```

## Usage

Ask first what it will cost. `trunc plan` changes nothing:

```console
$ trunc plan dataset.zip -C dataset
archive       dataset.zip (ZIP, 2.76 GiB)
content       4.25 GiB to write
destination   dataset (NTFS), 50.25 GiB free

free space needed at the destination:
  extract (keeps archive)       4.29 GiB   fits
  consume (--consume)           1.78 GiB   fits
  (punch mode frees space inside large entries; without it consuming needs up to 2.53 GiB)
```

Then extract, giving the archive's space back as you go:

```sh
trunc x dataset.zip -C dataset --consume       # a ZIP
trunc x big.tar.zst -C ./out --consume         # a compressed tarball
trunc x disk.img.xz --consume                  # a single compressed file: leaves disk.img
trunc x disc.iso -C ./disc --consume           # an ISO image
trunc x big.tar.zst.001 -C ./out --consume     # a split archive: each part goes once it is done
trunc resume dataset.zip                       # continue after a crash, a kill or a full disk
```

Other things it does:

```sh
trunc x image.tar -C ./rootfs                               # a docker save image's root filesystem
trunc inspect big.zip --entries                             # what's inside
trunc verify big.tar.zst                                    # check every checksum, write nothing
trunc x big.zip -C ./out --consume --verify-media           # re-read files from disk before deleting

trunc create data.trnc ./data                               # pack a folder as .trnc
trunc create data.trnc ./data --codec lz4 --block-size 4M   # faster, larger archive
trunc key gen me.key                                        # sign archives
trunc create data.trnc ./data --sign me.key
trunc x data.trnc -C ./out --require-signed --trust-key <public key>
```

Run `trunc <command> --help` for every flag, or see the
[commands and options](docs/guide.md#commands-and-options) in the user guide.

## Supported formats

| Format | Extract | `--consume` | Space comes back |
|---|---|---|---|
| ZIP (Stored, Deflate, Zip64) | yes | yes | from the end, after each group of entries, and every 64 MiB inside entries of 256 MiB or more |
| `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst` | yes | yes | from the front, every 64 MiB of output, or after each block or frame decoded in parallel |
| Single files: `.gz`, `.bz2`, `.xz`, `.zst` | yes | yes | the same as tarballs |
| ISO 9660 images (`.iso`) | yes | yes | as for ZIP |
| Compressed tarballs and files split into `.001` or `.aa` parts | yes | yes | as above, and each part is deleted once its data is safe |
| ZIP, ISO and `.trnc` split into parts | yes | not yet | — |
| Container images (`docker save`, OCI archives) | yes | no | — |
| `.trnc` | yes | yes | from the end, after each batch of blocks |

Every format that can be consumed resumes after a crash with `trunc resume`. The
[user guide](docs/guide.md#supported-formats) has the details for each format.

## How it works

Most archive formats put the first file at the start. A `.trnc` archive stores its content
backwards: the first block sits at the very end of the file. Extraction always works on the
block at the end:

1. Read the last block, check its hash, and decompress it.
2. Write its files and flush them to disk.
3. Shrink the archive so that block is gone.

```text
 archive                                                 output
┌────────┬──────────┬─────────┬─────────┬─────────┐
│ header │ manifest │ block 3 │ block 2 │ block 1 │  ──►  files from block 1
└────────┴──────────┴─────────┴─────────┴─────────┘
                                          ▲
                              cut here once those files are on disk
```

Every filesystem can shrink a file from the end instantly, and the space comes back right away.
Because a block is cut only after step 2, each byte of your data is always in one of two places:
still in the archive, or already on disk.

The archive's length is the progress marker. After a crash, `trunc resume` looks at how long the
archive is, works out which blocks are gone, and continues with the next one. There is no
separate state file to lose.

ZIP files, ISO images and compressed tarballs weren't designed to be taken apart like this, so trunc does
more work for them. It checks the whole archive before deleting anything, records its progress in
a small journal next to the archive, and uses its own resumable decoders so that it can free
space every 64 MiB inside large files. The user guide explains how this
works for [ZIP files](docs/guide.md#zip-files), [compressed tarballs](docs/guide.md#compressed-tarballs-and-files),
[ISO images](docs/guide.md#iso-images) and [split archives](docs/guide.md#split-archives).

## Safety

- **Nothing is released before it is verified and on disk.** Every piece is checked against its
  hash, CRC or codec checksum, and its output is flushed, before the archive bytes it came from
  are freed.
- **Crashes are tested, not hoped about.** The test suite crashes an extraction at every single
  filesystem operation, and simulates torn writes, full disks, and drives that claim to have saved
  data when they haven't. After each one, it checks that recovery produces exactly the right files.
- **Files appear all at once.** Output goes to a hidden staging folder inside the destination and
  is moved into place at the end, so a crash never leaves half-written files where you expect
  finished ones. `--consume` never overwrites existing files.
- **Hostile archives can't escape the destination.** trunc rejects absolute paths, `..` and drive
  letters everywhere, and on Windows also device names like `CON` and alternate data streams. It
  never follows symlinks or junctions when writing, and creates symlink entries only from `.trnc`
  archives, only with `--allow-symlinks`, and only if they point inside the destination.
- **Risky setups are refused.** trunc won't consume an archive in a cloud-synced folder, on a
  filesystem without a journal, or on one it can't identify, unless you say so.

The [security checklist](docs/security.md) lists each rule with the code and test that enforce
it, and the user guide spells out [what `--consume` promises](docs/guide.md#what---consume-promises)
and [what it doesn't](docs/guide.md#what-it-does-not-promise).

## When not to use it

- **You want to keep the archive.** Leave off `--consume`.
- **The archive is in OneDrive, Dropbox, Google Drive or iCloud.** The sync client would upload
  every change. trunc refuses unless you pass `--allow-sync`.
- **Your disk keeps snapshots**, such as System Restore points or btrfs and ZFS snapshots. A
  snapshot holds on to the space trunc frees, so you save nothing.
- **The drive is FAT32 or exFAT.** These filesystems can lose their own records in a crash.
  trunc refuses unless you pass `--allow-unjournaled`.

## FAQ

### How much free space do I need?

Run `trunc plan <archive> -C <destination>`. It prints the free space a normal extraction and a
consume need, from the archive's own sizes and your filesystem, and errs on the high side.

### Can I keep the archive?

Yes: leave off `--consume`, and `trunc x` is an ordinary extractor. With `--consume`, the archive
is gone at the end, and other tools can no longer open a ZIP, ISO or compressed tarball once the
first step has run. trunc says so before it starts.

### What happens if my computer crashes halfway?

Run `trunc resume <archive>`, or the same command again. The files it had finished were flushed to
disk before their part of the archive was deleted, and everything else is still in the archive.

### What if the disk fills up anyway?

trunc reserves space for each batch of files before it writes them. If the reservation fails,
it stops cleanly with exit code 75, leaving a valid, shorter archive. Free some space and run
`trunc resume`.

### Why not delete each file from the archive once it's extracted?

That frees nothing until a whole file is done, and does nothing for an archive that holds one
huge file. A `.trnc` archive is made of 8 MiB blocks by default, and trunc frees space after each
batch of blocks, including from the middle of a single large file.

### Why can't I consume a container image?

A later layer can delete or replace anything an earlier layer added, so no layer can be freed
until every layer after it has been applied. Consuming would save no space, so trunc extracts the
image's root filesystem and leaves the archive for you to delete.

## Performance

A 10 GiB folder was packed with `trunc create --codec lz4` into a 5.81 GiB archive, then
extracted twice on the same NTFS volume: once normally and once with `--consume`. Peak use is the
largest drop in the volume's free space, sampled every 50 ms. The machine has an AMD Ryzen 7 5800H
and a Samsung NVMe SSD.

| Command | Peak disk use | trunc's prediction | Time |
|---|---|---|---|
| `trunc x --consume` | **4.32 GiB** | 4.39 GiB | 53 s |
| `trunc x` | 10.00 GiB | 10.07 GiB | 60 s |

This is one run on one machine, and your results will depend on your data and disk. `trunc plan`
gives the figure for your own archive before you start, and it is meant to overestimate rather
than underestimate.

<details>
<summary><b>Codec speed</b> (1 GiB of test data, three quarters text-like and one quarter random)</summary>

| Codec | Archive size | Create | Extract | Verify |
|---|---|---|---|---|
| zstd:9 (default) | 36.2 % | 295 MiB/s | 1.18 GiB/s | — |
| zstd:3 | 37.6 % | 566 MiB/s | 1.11 GiB/s | 1.6 GiB/s |
| lz4 | 53.1 % | 590 MiB/s | 1.12 GiB/s | 1.6 GiB/s |

</details>

Compressed tarballs are decompressed twice: once to check everything, and once to write. Parts of
a file that need nothing from the parts before them decode on all cores, in both passes: bzip2
blocks, the blocks of an xz file made with `xz -T0`, zstd frames that declare their size, as
`pzstd` writes them, and BGZF gzip files from `bgzip`. A 437 MiB `.tar.xz` from `xz -T0` verifies
in 0.65 s instead of 4.1 s. Other gzip files, and xz and zstd files written as one block or frame,
decode on one core. The user guide
explains [what this means for space and memory](docs/guide.md#parallel-decoding).

To see where a run spends its time, add `--profile run.json` to any command. It prints a summary
and writes a trace for <https://ui.perfetto.dev>; the user guide explains
[how to read it](docs/guide.md#performance-and-profiling).

## Documentation

- [User guide](docs/guide.md): what `--consume` does and promises, supported formats, ZIP files,
  compressed tarballs, ISO images, split archives, container images, parallel decoding,
  profiling, and the full list of commands, options and exit codes
- [Security checklist](docs/security.md): how hostile archives are handled, known gaps, and how to
  verify downloads
- [Format spec](docs/spec/trnc-format-v1.md): the `.trnc` v1 file format
- [Crash-safety invariants](docs/spec/invariants.md): what must hold after any crash, and the test
  for each
- [Design decisions](docs/adr): why trunc works the way it does
- [Changelog](CHANGELOG.md)

## Platform support

Windows (NTFS) and Linux (ext4, XFS, btrfs, ZFS) get every feature, and both are tested on every
commit. Prebuilt binaries are available for Windows x64, Linux x64 and Linux ARM64; the Linux
builds are static and run on any distribution.

FAT32 and exFAT drives work with `--allow-unjournaled`. On filesystems that can't free space inside
a file, compressed tarballs still consume safely but give their space back only at the end, and a
large ZIP entry only once it is finished. macOS is untested.

## Contributing

Issues and pull requests are welcome. Before opening a PR, please run `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`. If you change
how archives are consumed, add a crash test; `crates/trunc-engine/tests/consume.rs` has examples.

To build, you need Rust 1.85 or newer, plus the MSVC build tools on Windows:

```sh
cargo build --release      # target/release/trunc
cargo test --workspace
```

The parsers are fuzzed with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). On Linux with
a nightly toolchain, run `cargo +nightly fuzz run zip` (the targets are `zip`, `tar`,
`inflate`, `bzip2`, `xz`, `zstd`, `manifest`, `header` and `footer`).

<details>
<summary><b>Repository layout</b></summary>

| Path | What |
|---|---|
| `crates/trunc-core` | File format types, path rules, space model. No I/O. |
| `crates/trunc-hash` | BLAKE3, CRC32C, SHA-256 |
| `crates/trunc-codec` | zstd, lz4 and uncompressed blocks |
| `crates/trunc-chunk` | Splitting content into blocks |
| `crates/trunc-fs` | Filesystem access: sparse files, file ids, volume checks, cloud-sync detection |
| `crates/trunc-journal` | The crash-safe journal used when consuming ZIP files and compressed archives |
| `crates/trunc-legacy` | ZIP and tar readers, split archives, and the resumable Deflate, bzip2, xz and zstd decoders |
| `crates/trunc-engine` | Creating, extracting, verifying and consuming archives |
| `crates/trunc-cli` | The `trunc` command |
| `crates/trunc-prof` | The span profiler behind `--profile` |
| `crates/trunc-testkit` | A simulated filesystem that can crash on demand, plus test fixtures |
| `fuzz/` | Fuzz targets |

</details>

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT),
at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion
in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

<p align="center"><sub>Made by <a href="https://github.com/Sparsebits">Sparsebits</a>.</sub></p>
