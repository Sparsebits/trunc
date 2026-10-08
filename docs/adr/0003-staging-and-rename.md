# ADR-0003: Extract into a staging directory, rename into place at the end

Status: accepted (2026-10-08); implemented in phase 3

## Context
During a destructive extraction, already-written output is the only copy of that data. If users, launchers, sync clients or antivirus software touched it mid-extraction, recovery by hash would fail and the data would be gone.

## Decision
Destructive extraction writes into `<dest>/.trunc-stage-<archive-id>/`, holding output handles with exclusive sharing on Windows. Top-level items are renamed into the destination only after the last block is consumed. That phase is recorded in the journal so it can resume.

## Consequences
- Outputs appear in the destination all at once, at the end.
- Linux has no mandatory locks: changes there are detected (hash mismatch on recovery), not prevented.
