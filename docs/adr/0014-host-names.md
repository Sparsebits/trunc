# ADR-0014: Entry names from other tools follow the host

Status: accepted (2026-10-09). Narrows ADR-0005 for formats trunc does not write.

## Context
`.trnc` entry names follow the intersection of what Windows, macOS and Linux accept, so an
archive made anywhere extracts the same everywhere. trunc applied the same rules to tar and
ZIP archives. Real Linux tarballs break them: systemd unit names contain backslashes
(`system-systemd\x2dcryptsetup.slice`), and the Linux kernel has headers that differ only in
case (`xt_CONNMARK.h` and `xt_connmark.h`). trunc refused both, everywhere.

## Decision
- For tar and ZIP entries (and single-file outputs), names are checked against what this
  computer can hold (`trunc_core::path::validate_host`):
  - On Windows, the portable rules apply, as before.
  - On Linux and macOS, characters and names that only Windows forbids (`\`, `:`, `<>"|?*`,
    trailing dots or spaces, device names like `CON`) are accepted.
- Duplicates are compared as the host compares names (`host_key`): case-insensitively on Windows
  and macOS, exactly on Linux.
- Everything that could escape the destination stays refused on every platform: absolute
  paths, `..`, empty components, control characters, NUL, and a Windows drive prefix (`C:`).
- `.trnc` archives keep the portable rules when created and extracted.

## Consequences
- The same tarball may extract on Linux and be refused on Windows. The refusal happens during
  the read-only scan, before anything is written or freed.
- A Linux destination can still be case-insensitive (ext4 or f2fs with `casefold`, a mounted
  NTFS, FAT, exFAT or SMB share, ZFS with `casesensitivity=insensitive`). Before the scan,
  trunc probes the destination (or its nearest existing ancestor) by creating
  `.trunc-stage-case-probe`, looking it up upper-cased and removing it. If the name resolves,
  duplicates are compared with the case-insensitive key for that run, for every format, so two
  entries that differ only in case are refused during the read-only scan, before anything is
  written or freed. Without the probe the clash would surface only when `--consume` created the
  second output, after earlier archive bytes were freed, and again on every resume. A resume
  reuses the names checked when its journal was created. Windows and macOS skip the probe:
  names there always compare case-insensitively.
