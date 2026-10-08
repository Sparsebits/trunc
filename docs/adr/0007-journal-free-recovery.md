# ADR-0007: Native consumption recovers without a journal

Status: accepted (2026-10-08). Supersedes the journal use described for native archives in ADR-0003 and in the original plan.

## Context
The plan used a write-ahead journal for the native consumer's final rename phase and for space-exhaustion pauses. A journal is a second source of truth that must agree with the archive, the staging directory and the destination, and its own crash cases need testing.

## Decision
Native consumption keeps no journal. State is derived from what is on disk:
- the archive's length (blocks consumed);
- whether the staging directory exists and what it still contains (items not yet renamed);
- whether the destination's top-level items exist. They were checked to be absent before the first write, so if they exist now, we moved them.

A resume note next to the archive (`<archive>.trncr`) records the archive id and the destination. It is written first and removed last, and it is a hint only: it lets `trunc resume` find the destination and lets a wrong-destination error name the right one.

A pause (out of space, or the archive mapped by another process) is an ordinary error return: the archive is a valid shorter `.trnc`, so rerunning the command resumes.

An interrupted batch is always redone. Checking hashes to skip the redo would add a second code path to save at most one batch.

## Consequences
- `trunc-journal` is only needed for legacy ZIP consumption (phase 4).
- Every recovery path is the same function, `consume()`, run again. The crash sweep exercises all of it at every operation index.
- Consume is idempotent even after completion: if the receipt shows the job finished into this destination, running it again succeeds without doing anything.
