# ADR-0006: FaultFs is an in-memory filesystem, not a wrapper

Status: accepted (2026-10-08)

## Context
The plan described `FaultFs<B: FsBackend>` as a wrapper that injects faults around a real backend. A wrapper can stop operations at a chosen point, but it cannot model the failure that matters most: **data that was written but not flushed disappearing after a crash.** That data is already in the real OS cache, and nothing can take it back.

## Decision
`trunc_testkit::FaultFs` is an in-memory `FsBackend` that tracks a current view and a durable view of every file and directory entry.
- File contents and sizes become durable on `flush_data`.
- Directory entries become durable when every parent directory they touch has been flushed (POSIX rules, stricter than NTFS).
- Three crash models: `WriteThrough`, `LoseUnflushed`, and `RandomSubset { seed }`. The last keeps each unflushed operation independently, in order, which models write caches that persist work out of order.
- Faults are keyed by operation index: `CrashAt`, `TornWrite`, `NoSpaceAt`, `MappedAt`.
- It tracks allocated bytes and the peak, so the crash harness can check invariant I2 (occupancy within the space bound).

Real-filesystem behaviour that the in-memory model cannot reproduce (sharing violations, mapped-section truncation errors, sparse granularity, junctions) is covered by `crates/trunc-fs/tests/os.rs` against NTFS.

## Consequences
- The phase 3 engine must do all I/O, including reading the archive, through `FsBackend`, so it can run on FaultFs.
- Crash sweeps run in memory and are fast enough to cover every operation index of a consume in CI.
