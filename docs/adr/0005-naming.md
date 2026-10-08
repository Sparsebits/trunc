# ADR-0005: Name `trunc`, extension `.trnc`

Status: accepted (2026-10-08)

## Decision
The product and CLI are `trunc`, named for the mechanism: the archive is consumed by truncation. The file extension is `.trnc`, the file magic `TRNC\0\x01`, the footer magic `TRNCBLK\0`, and the journal extension `.trncj`.

## Why not `.trc`
`.trc` is widely used: SQL Server Profiler trace files (with Windows file associations on machines that have SQL Server tools), Oracle trace files, and oscilloscope trace data. As of 2026-10-08, fileinfo.com did not list `.trnc`.

## Organization
The GitHub organization is **Sparsebits** (`sparsebits`). It is home to the product family: `trunc` (core) and later variants in their own repos. The name nods to sparse files, a term systems developers know, which punch mode produces.

History (all on 2026-10-08):
- `trunc` was taken as a GitHub name.
- The repo briefly moved to **Headroom Labs** (`headroom-labs`). That was dropped hours later: an unrelated, widely used *compression* project already operates as Headroom Labs (headroomlabs.ai, 70k+ stars). Same name in the same space meant confusion and trademark risk.
- **Sparsebit** (singular) was rejected because sparsebit.com belongs to a data-analytics company and Megvii publishes a model-compression toolbox under that name.
- No company or product called **Sparsebits** was found, and its domains appeared unregistered at the time.

Lesson recorded for future names: check web presence and adjacent spellings, not just exact GitHub handles.

## Crate names
The crate name `trunc` on crates.io belongs to an unrelated crate (v0.1.0, last published 2015). Workspace crates use the `trunc-` prefix. The binary is built from `trunc-cli` and named `trunc`.
