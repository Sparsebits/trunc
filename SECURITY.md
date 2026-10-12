# Security policy

trunc deletes its input as it extracts, so a bug can lose data or let a hostile archive write
outside the destination. Reports of that kind are especially welcome.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability** (<https://github.com/Sparsebits/trunc/security/advisories/new>).

Include what you can: the trunc version (`trunc --version`), the OS and filesystem, the command
you ran, and an archive or script that reproduces the problem. If the archive is large, describe
how to generate it instead.

We aim to acknowledge reports within a few days and to agree on a disclosure date with you once a
fix is ready. We credit reporters in the advisory unless you ask us not to.

## Supported versions

trunc is pre-1.0. Security fixes go into the latest release only.

## Scope

In scope: anything that makes trunc free archive bytes before their output is safely on disk,
write or delete outside the destination, follow a link when writing, exhaust memory or disk on
hostile input despite the documented limits, or accept a tampered or wrongly signed `.trnc`
archive. The [security checklist](docs/security.md) lists each rule and how it is enforced, and
explains how to verify release downloads.

Out of scope: the documented limits in that checklist, and running `--consume` with overrides
such as `--allow-sync`, `--allow-unjournaled` or `--allow-overlap` on archives you do not trust.
