# trunc

Self-consuming archives. A `.trnc` archive stores its blocks in reverse order, so an extractor can decode the block at the end of the file, make its output durable, and truncate the archive past it. Extraction then needs roughly *output size − archive size* of free space instead of the full output size.

> **Status: early development (plan phases 0–3 done).** Create, inspect, verify, plan, extract, and destructive extraction (`--consume`) with crash recovery all work on Windows/NTFS. Linux runs everything except the volume probing and sparse-file features (phase 5).

## Build

Needs Rust 1.85+ (the repo pins `stable` via `rust-toolchain.toml`). On Windows, also the MSVC build tools.

```sh
cargo build --release          # binary: target/release/trunc(.exe)
cargo test --workspace
```

## Use

```sh
trunc create data.trnc ./data                  # zstd:9, 8 MiB blocks
trunc create data.trnc ./data --codec lz4 --block-size 4M --dict train
trunc inspect data.trnc --entries --blocks
trunc verify data.trnc
trunc plan data.trnc -C ./out                  # filesystem, free space, extract vs consume, warnings
trunc x data.trnc -C ./out                     # non-destructive extract
trunc x data.trnc -C ./out --consume           # destructive: frees the archive as it extracts
trunc resume data.trnc                         # continue after a crash, kill or pause

trunc key gen me.key                           # signing
trunc create data.trnc ./data --sign me.key
trunc verify data.trnc --trust-key <hex public key>
```

## Layout

| Path | What |
|---|---|
| `crates/trunc-core` | Format types, encoders/decoders, path rules, space model. No I/O. |
| `crates/trunc-hash` | BLAKE3 (incl. Merkle tree), CRC32C, SHA-256 |
| `crates/trunc-codec` | Store / lz4 / zstd block codecs, dictionary training |
| `crates/trunc-chunk` | Block boundary selection |
| `crates/trunc-engine` | Producer, archive reader, extractor, verifier, keys |
| `crates/trunc-cli` | The `trunc` binary |
| `crates/trunc-fs` | Filesystem backend trait; OS backend (NTFS sparse files, file ids, volume probing, no-replace rename); cloud-sync detection |
| `crates/trunc-testkit` | Deterministic fixtures, tree comparison, `FaultFs` in-memory crash-injection filesystem |
| `crates/trunc-journal`, `-legacy`, `-adapter` | Placeholders for phases 4 and 7 |
| `docs/spec` | Normative format spec, crash-safety invariants, journal draft |
| `docs/adr` | Design decisions |
| `fuzz/` | cargo-fuzz targets (needs nightly) |

## Measured

**Destructive extraction** (10 GiB dataset, 5.81 GiB lz4 archive, NTFS):

| | Peak extra free space used | Time |
|---|---|---|
| `trunc x --consume` | **4.32 GiB** (bound predicted 4.39 GiB) | 53 s |
| `trunc x` (keeps archive) | 10.00 GiB | 60 s |

**Codecs** (phase 1, Ryzen 7 5800H, NVMe, 1 GiB synthetic: ¾ text-like, ¼ random)

| Codec | Ratio | Create | Extract | Verify |
|---|---|---|---|---|
| zstd:9 (default) | 36.2 % | 295 MiB/s | 1.18 GiB/s | — |
| zstd:3 | 37.6 % | 566 MiB/s | 1.11 GiB/s | 1.6 GiB/s |
| lz4 | 53.1 % | 590 MiB/s | 1.12 GiB/s | 1.6 GiB/s |

`in_place_decompression_conversation.md` is the design conversation this project came from.
