# ADR-0005: Name `trunc`, extension `.trnc`

Status: accepted (2026-10-08)

## Decision
The product and CLI are `trunc`, named for the mechanism: the archive is consumed by truncation. The file extension is `.trnc`, the file magic `TRNC\0\x01`, the footer magic `TRNCBLK\0`, and the journal extension `.trncj`.

## Why not `.trc`
`.trc` is widely used: SQL Server Profiler trace files (with Windows file associations on machines that have SQL Server tools), Oracle trace files, and oscilloscope trace data. As of 2026-10-08, fileinfo.com did not list `.trnc`.

## Organization
The GitHub organization is **Headroom Labs** (`headroom-labs`), named for the benefit (room on the disk) rather than the mechanism, so it fits the product family: `trunc` (core) and later variants in their own repos. Chosen 2026-10-08; `trunc` was taken as a GitHub name.

## Crate names
The crate name `trunc` on crates.io belongs to an unrelated crate (v0.1.0, last published 2015). Workspace crates use the `trunc-` prefix. The binary is built from `trunc-cli` and named `trunc`.
