<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.png">
    <img alt="trunc: extract huge archives without the free space" src="docs/assets/banner-light.png" width="100%">
  </picture>
</p>

<p align="center">
  <b>Self-consuming archives.</b> trunc shrinks the archive while it extracts,<br>
  so unpacking needs about <i>output − archive</i> of free space instead of the whole output.
</p>

<p align="center">
  <a href="https://github.com/Sparsebits/trunc/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Sparsebits/trunc/actions/workflows/ci.yml/badge.svg"></a>
  <a href="#license"><img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-ff5b35"></a>
  <img alt="Rust 1.85+" src="https://img.shields.io/badge/rust-1.85%2B-121212">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-121212">
  <img alt="Status: pre-release" src="https://img.shields.io/badge/status-pre--release-c93a17">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#benchmarks">Benchmarks</a> ·
  <a href="#zip-files">ZIP files</a> ·
  <a href="docs/guide.md">User guide</a> ·
  <a href="docs/spec/trnc-format-v1.md">Format spec</a>
</p>

---

You have a 60 GB archive, 70 GB of free space, and 100 GB of content inside. Every extractor
keeps the archive until the end, so this doesn't fit. **trunc does:** each time a chunk of
output is safely on disk, it cuts that chunk off the archive.

- **About U − C of free space.** A 10 GiB extract from a 5.81 GiB archive peaked at **4.32 GiB**
  of extra disk use. A normal extractor needs 10.00 GiB.
- **Crash-safe.** Pull the plug at any moment, then run `trunc resume`. Every byte is either still in the
  archive or already durable in the output. The tests crash it at every filesystem operation
  and check that it recovers.
- **Works on ZIPs you already have.** Stored and Deflate, Zip64 included. Huge single entries are
  freed *while they decompress*, using a checkpointing DEFLATE decoder.
- **Tells you before it starts.** `trunc plan` checks the filesystem, free space, cloud-sync
  folders and snapshots, and gives a conservative upper bound for both modes.
- **Verified, optionally signed.** BLAKE3 per block plus a Merkle root, and Ed25519 manifest signatures.
  Nothing is truncated until its output has been verified.
- **Fast.** Independent zstd or lz4 blocks, decoded in parallel at more than 1 GiB/s.

## Quick start

```sh
cargo install --git https://github.com/Sparsebits/trunc trunc-cli    # binary: trunc
```

Pack something, see what extraction will need, then extract it destructively:

```console
$ trunc create data.trnc ./data
created   data.trnc
entries   12
blocks    96
size      768.00 MiB -> 256.08 MiB (33.3% of original)
time      2.67s (288.09 MiB/s)

$ trunc plan data.trnc -C ./out
destination   C:\ NTFS (journaled, cluster 4.00 KiB), 6.54 GiB free
archive now   256.08 MiB
content       768.00 MiB to write

free space needed at the destination:
  extract (keeps archive)     787.89 MiB   fits
  consume (--consume)         531.85 MiB   fits   (peak occupancy 787.93 MiB, 3 batches)
  consume saves 256.03 MiB (32.5%)

$ trunc x data.trnc -C ./out --consume
all blocks consumed; moving files into place
extracted 9 files, 3 directories, 768.00 MiB into ./out
archive   consumed; receipt kept at data.trnc.receipt
time      1.52s (3 batches)
```

The same command works on existing ZIP files:

```sh
trunc x big.zip -C ./out --consume
```

<details>
<summary><b>All commands</b></summary>

```sh
trunc create data.trnc ./data                       # zstd:9, 8 MiB blocks
trunc create data.trnc ./data --codec lz4 --block-size 4M --dict train
trunc inspect data.trnc --entries --blocks
trunc verify data.trnc                              # hash every block, extract nothing
trunc plan data.trnc -C ./out                       # filesystem, free space, warnings
trunc x data.trnc -C ./out                          # ordinary extract, archive kept
trunc x data.trnc -C ./out --consume                # destructive: frees the archive as it goes
trunc x data.trnc -C ./out --consume --verify-media # read outputs back from disk before freeing
trunc resume data.trnc                              # continue after a crash, kill or pause

trunc key gen me.key                                # signing
trunc create data.trnc ./data --sign me.key
trunc x data.trnc -C ./out --require-signed --trust-key <hex public key>
```

`trunc <command> --help` lists every flag.

</details>

## How it works

A `.trnc` archive stores its blocks **in reverse**: the first block of content sits at the end of
the file. Extraction decodes the block at EOF, makes its output durable, and truncates the file.
The archive gets shorter as the output grows.

```
 archive on disk                                       output (staging dir)
┌────────┬──────────┬─────────┬─────────┬─────────┐
│ header │ manifest │ block 3 │ block 2 │ block 1 │◄─ EOF
└────────┴──────────┴─────────┴─────────┴─────────┘
                                         │
                1. verify + decode ──────┴─────────►  write block 1's bytes
                2. flush output data and directories
                3. truncate the archive just before block 1
                                                       ...repeat until only the header
                                                       and manifest remain (kept as a receipt)
```

The order of those three steps is the whole safety argument. Nothing is released until the
bytes that replace it are durable. **The archive's length is the progress record**, so recovery
needs no journal: `trunc resume` reads the length, knows which blocks are gone, and continues.
Blocks are independent zstd or lz4 frames, so no block ever depends on data that has already
been freed.

Output goes to a hidden staging directory using exclusive handles, and is renamed into place
at the end. A crash never leaves half-extracted files at their final paths.

## Benchmarks

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/chart-dark.png">
    <img alt="Free disk space needed: trunc --consume 4.32 GiB, any extractor 10.00 GiB" src="docs/assets/chart-light.png" width="100%">
  </picture>
</p>

10 GiB dataset, 5.81 GiB lz4 archive, NTFS, AMD Ryzen 7 5800H, Samsung NVMe SSD. Peak measured by
sampling the volume's free space during the run.

| | Peak extra disk use | Predicted bound | Time |
|---|---|---|---|
| `trunc x --consume` | **4.32 GiB** | 4.39 GiB | 53 s |
| `trunc x` (keeps archive) | 10.00 GiB | 10.07 GiB | 60 s |

<details>
<summary><b>Codec throughput</b> (1 GiB synthetic: ¾ text-like, ¼ random)</summary>

| Codec | Size | Create | Extract | Verify |
|---|---|---|---|---|
| zstd:9 (default) | 36.2 % | 295 MiB/s | 1.18 GiB/s | — |
| zstd:3 | 37.6 % | 566 MiB/s | 1.11 GiB/s | 1.6 GiB/s |
| lz4 | 53.1 % | 590 MiB/s | 1.12 GiB/s | 1.6 GiB/s |

</details>

## ZIP files

ZIPs weren't designed for this, so trunc works backwards through them:

1. It parses the central directory and cross-checks every local header. Overlapping entries
   (a zip-bomb technique) are refused unless you pass `--allow-overlap`.
2. It verifies every entry's CRC **before** anything is destroyed.
3. It saves the archive's layout to a small journal (`<archive>.trncj`).
4. It extracts entries from the end of the file backwards, truncating after each one.
5. **Punch mode**, for entries of 256 MiB or more compressed: trunc decompresses with its own DEFLATE
   decoder, checkpoints every 64 MiB of output, and punches the consumed compressed bytes out of
   the file. A single 50 GB entry no longer needs 50 GB of headroom.

After the first truncation, the ZIP can no longer be opened by other tools. trunc says so
before it starts.

## When to use it

**Good fit:** downloads bigger than your free space, dataset or model drops, VM images, backups
restored onto the same disk, CI runners and containers with small disks.

**Not a fit:**
- You want to keep the archive. Use `trunc x` without `--consume`.
- The archive sits in a cloud-synced folder. trunc refuses by default, because a sync client
  would upload every truncation.
- The disk is snapshotted. Snapshots keep the freed blocks allocated, so you save nothing.
- The filesystem is FAT32 or exFAT. These have no metadata journal, so this needs
  `--allow-unjournaled` and an accepted risk.

The [user guide](docs/guide.md#what---consume-promises) spells out exactly what `--consume`
promises and what it doesn't.

## FAQ

<details>
<summary><b>What happens if my machine crashes halfway?</b></summary>

Run `trunc resume <archive>`. For `.trnc` files, the archive's length says exactly which blocks
are already consumed, and their output was flushed before they were cut. For ZIPs, the
journal holds the layout and the last checkpoint. The crash tests replay every filesystem operation
under three crash models (write-through, lose-unflushed, random subset) plus torn writes, full disks,
and drives that lie about flushing.

</details>

<details>
<summary><b>What if the disk fills up anyway?</b></summary>

Output space is preallocated per batch before anything is decoded. If that fails, trunc stops
with exit code 75, leaving a valid (shorter) archive. Free some space and run `trunc resume`.

</details>

<details>
<summary><b>Can a malicious archive write outside the destination?</b></summary>

No. Absolute paths, `..`, drive letters, Windows device names and alternate data streams are
rejected. Outputs never follow symlinks or junctions, and symlink entries are only created
with `--allow-symlinks`, pointing inside the destination. Decompression bombs are bounded by the
space check. The [security checklist](docs/security.md) maps each rule to the code and test that
enforce it. The parsers are fuzzed with cargo-fuzz.

</details>

<details>
<summary><b>Why not just delete each file from a tar after extracting it?</b></summary>

That only frees space once an entire file is done, and only when the files are separate. trunc frees space
block by block, 8 MiB at a time by default, and inside single huge files.

</details>

<details>
<summary><b>Which platforms are supported?</b></summary>

Windows on NTFS is the primary platform, with all features. Linux runs native consume and ZIP
consume at entry granularity. ZIP punch mode and no-replace renames on Linux arrive with the
Linux backend. macOS is untested.

</details>

## Documentation

| | |
|---|---|
| [User guide](docs/guide.md) | Creating archives, what `--consume` promises, ZIP behaviour, exit codes |
| [Format spec](docs/spec/trnc-format-v1.md) | The `.trnc` v1 wire format |
| [Crash-safety invariants](docs/spec/invariants.md) | Each invariant and the test that checks it |
| [Journal format](docs/spec/journal-v1.md) | The ZIP consume journal |
| [Security checklist](docs/security.md) | Hostile-input rules, trust model, known gaps |
| [Design decisions](docs/adr) | ADRs 0001–0009 |

## Building from source

Requires Rust 1.85+ (the repo pins `stable`). On Windows, you also need the MSVC build tools.

```sh
cargo build --release            # target/release/trunc(.exe)
cargo test --workspace
cargo +nightly fuzz run zip      # fuzzing (needs cargo-fuzz); targets: zip inflate manifest header footer
```

<details>
<summary><b>Repository layout</b></summary>

| Path | What |
|---|---|
| `crates/trunc-core` | Format types, encoders and decoders, path rules, space model. No I/O. |
| `crates/trunc-hash` | BLAKE3 (with a Merkle tree), CRC32C, SHA-256 |
| `crates/trunc-codec` | Store, lz4 and zstd block codecs, dictionary training |
| `crates/trunc-chunk` | Block boundary selection |
| `crates/trunc-fs` | Filesystem backend trait. OS backend: NTFS sparse files, file ids, volume probing. Cloud-sync detection. |
| `crates/trunc-journal` | Crash-safe two-slot checkpoint store used by ZIP consume |
| `crates/trunc-legacy` | ZIP parser (Zip64, data descriptors, CP437/UTF-8 names) and the checkpointing DEFLATE decoder |
| `crates/trunc-engine` | Producer, extractor, verifier, consume engines, preflight |
| `crates/trunc-cli` | The `trunc` binary |
| `crates/trunc-testkit` | `FaultFs` in-memory crash-injection filesystem, fixtures, ZIP builder |
| `fuzz/` | cargo-fuzz targets |

</details>

## Contributing

Issues and pull requests are welcome. Before you open a PR, run `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`. Changes to
the consume path need a crash-sweep test (see `crates/trunc-engine/tests/consume.rs`).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT),
at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion
in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

<p align="center"><sub>Built by <a href="https://github.com/Sparsebits">Sparsebits</a>.</sub></p>
