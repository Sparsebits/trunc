# ADR-0009: Signatures are optional by default

Status: accepted (2026-10-08). Decides the open question in plan phase 6.2.

## Context
Destructive extraction is irreversible, so the question was whether `--consume` should refuse unsigned archives by default.

## Decision
- Signatures are **not required by default**. Most archives (and every ZIP) are unsigned, and integrity is already enforced for all of them: the header checksum, the manifest hash, per-block and per-entry hashes, and ZIP CRCs, all checked before any source byte is released.
- When an archive is unsigned, `trunc plan` and `--consume` print a note saying integrity is checked but not origin.
- `--require-signed` and `--trust-key` let users and scripts insist on authenticity. Distributors who sign should tell their users to pass `--trust-key <key>`.

## Consequences
- Requiring signatures would block ordinary use without adding integrity, which is already guaranteed. Authenticity, a separate property, stays opt-in.
- A future variant (for example VM image distribution) can turn `--require-signed` on by default in its own CLI.
