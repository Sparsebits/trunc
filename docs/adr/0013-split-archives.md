# ADR-0013: Split archives

Status: accepted (2026-10-09).

## Context
Large downloads are often split into parts: `name.001`, `name.002`, … (7-Zip, HJSplit,
`split -d`) or `name.aa`, `name.ab`, … (`split`). The parts are slices of one file. Joining
them first (`cat`, `copy /b`) needs the whole archive's size again in free space, which is the
problem trunc exists to avoid. Parts also make consuming possible where nothing else does:
deleting a finished part frees its space on any filesystem, FAT32 and exFAT included.

## Decision
- **One file, read through its parts.** Naming the first part of a set whose first two parts
  exist reads the set as one file (`trunc_engine::source::Parts`). Naming a later part is an
  error that points at the first. A lone `name.001` is an ordinary file. All of `x`, `inspect`,
  `verify` and `plan` work this way for every format.
- **Consuming from the front.** For compressed tarballs and files (ADR-0011, ADR-0012), a part is
  deleted once a journaled checkpoint passes its end: the deletion follows the journal write,
  as punching does. The part containing the checkpoint is punched where the filesystem can.
  When everything is decoded and durable, an explicit end record is journaled before the
  remaining parts are deleted, so "every part is gone" is never mistaken for "finished".
- **Resuming checks every part.** The journal records each part's name, size and file id. On
  resume, a present part must match, and a missing part must lie entirely before the last
  checkpoint (or the end record must be there). Anything else is refused.
- **ZIP and `.trnc` sets are read, not consumed.** Their progress is the archive length, and
  truncating across part files needs its own crash analysis. `--consume` refuses them with a
  message; extracting without it works.
- The journal and gap log are named after the first part (`name.001.trncj`).

## Consequences
- Peak extra space with parts and no hole punching is about one part plus one checkpoint
  interval, instead of the whole archive.
- An entry in the archive named like one of its own parts is refused when extracting next to
  the parts.
- `.7z.001` and `.partN.rar` sets are refused like any 7z or RAR archive.
