# ADR-0016: Container image tarballs

Status: accepted (2026-10-11). Builds on ADR-0003, ADR-0011 and ADR-0012.

## Context
`docker save` and `skopeo copy … oci-archive:` produce a tar of tars: metadata
(`manifest.json`, or `oci-layout` + `index.json`), an image config, and one blob per layer,
each a tar that may be gzip- or zstd-compressed. What people usually want from one is the
image's root filesystem, the layers applied in order: what `docker export` of a container
gives, without a container runtime. Extracting the outer tar as an ordinary tarball gives the
blobs, not the files.

Layers are not independent. A later layer can delete a path (`.wh.<name>`), hide everything
a directory held below it (`.wh..wh..opq`), or replace a file with a directory or the other
way round. Applying layers to disk one by one, as runtimes do, writes files that are deleted
again and needs deletes, which a crash can leave half done.

## Decision
- **Detection by content.** An uncompressed tar is an image if it has `manifest.json` or
  `index.json` at its root, found by reading its headers only (contents are skipped). A
  compressed one (gzip, bzip2, xz, zstd) is an image if its first 64 KiB, decoded, show image
  entries (`oci-layout`, `blobs/sha256/<hex>`, `<hex>/layer.tar`, `repositories`,
  `manifest.json`, `index.json`). `--raw` turns detection off, so the outer tar can still be
  decompressed as itself.
- **Metadata.** `manifest.json` is preferred when present (it carries the repository tags;
  newer Docker writes both). Otherwise `index.json` is followed, through nested indexes up to
  4 deep. Manifests whose blob is not in the archive (other platforms of a multi-platform
  index saved for one) and attestation manifests are left out. With several candidates,
  `--image NAME` picks by tag or reference name and `--platform OS/ARCH[/VARIANT]` by platform;
  otherwise the only one, or else the one for this computer's architecture
  (`<host os>/<arch>`, then `linux/<arch>`); anything still ambiguous is refused with the list.
  JSON is read by a small strict parser in the engine (no new dependency; duplicate keys are
  refused). Documents over 16 MiB are refused.
- **Digests everywhere.** Every JSON blob reached through a descriptor is checked against its
  digest and size. Every layer blob is hashed (its digest, when recorded) and its decoded tar
  hashed again and compared with the config's `diff_ids`. Only `sha256:<64 lowercase hex>`
  digests are accepted, and a blob path is always built from one (`blobs/sha256/<hex>`), so a
  manifest cannot name anything outside `blobs/`. `docker save` layer paths are looked up
  among the outer tar's validated entry names; anything else is "not in the archive". The
  declared layer media type must match the blob's actual compression; encrypted layers are
  refused.
- **Scan, merge, then write.** The scan decodes every layer with trunc's decoders, parses its
  headers with the tarball reader (same name validation, same refusals: hard links, sparse
  files), and merges the layers into the final tree: for each path, which entry of which layer
  wins. Within a layer, whiteouts and opaque markers apply first and only to lower layers, then
  the layer's entries are added: a directory over a directory keeps what is below it,
  anything else replaces the whole subtree, and a path through a lower non-directory turns it
  into a directory. Whiteout names that are empty, `.` or `..`, entries inside a whiteout, and
  whiteouts that are directories are refused; other `.wh..wh.` names (aufs bookkeeping) are
  ignored. Names that differ only in case on this computer are refused across layers as they
  are within one. Then only the winning entries are written, into a staging directory renamed
  into place (ADR-0003): a file a later layer deletes or replaces is never written, and nothing
  is ever deleted. Layer digests are checked again during this second decode.
- **Policy as for tarballs.** Symlinks, devices and FIFOs in the image are not created
  (counted and reported). A symlink still shadows what lower layers had at its path. Top-level
  names that already exist in the destination are refused; `--overwrite` is not supported.
- **Compressed outer tars** are decompressed into a temporary file (in the destination for
  `x`, next to the archive for `inspect` and `verify`) because layer blobs must be read by
  offset. It is removed afterwards.
- **No consuming.** A layer can be freed only once no later layer can change what it
  contributes, which in general is after all layers are applied, so consuming saves no peak
  space over extracting and deleting. `--consume` is refused with that explanation.

- **Review fixes (2026-10-11).** Detection confirms structure: a valid `manifest.json`
  (array of objects with `Config` and `Layers`) or `oci-layout` plus an `index.json` with a
  `manifests` list; for compressed archives these files are checked when among the first
  entries, else `blobs/sha256/<hex>` / `<hex>/layer.tar` names suffice and an archive that
  then has no structure falls back to ordinary tarball handling. Archives with a consume
  journal are never images (resume wins). JSON is strict (numbers per RFC 8259; duplicate
  keys found with a set). Index walks memoize blobs by digest, dedupe candidates and stop
  after 4096 descriptors. Candidates without a descriptor platform take it from their config
  before choosing. aufs bookkeeping (anything under a `.wh..wh.*` component other than the
  opaque marker file) is skipped whatever its type. Entries and whiteouts reached through a
  symlink in the merged tree (`lib/x` with `lib -> usr/lib`) are refused rather than merged
  wrongly; resolving them is future work. Whiteouts must match names exactly (case-only
  matches are refused on case-folding systems). The temporary copy of a compressed outer tar
  is space-checked (refused up front when the archive's size does not fit, stopped when the
  copy outgrows free space minus 64 MiB; `x --ignore-space` skips this), removed by a drop
  guard on errors and panics, placed in the system temp dir when the archive's folder is not
  writable (`inspect`/`verify`), and stale copies from crashed runs are removed when not in
  use (Windows/Linux) or reported.

## Consequences
- Peak extra space is the merged root filesystem (plus the decompressed outer tar when that
  is compressed).
- Every layer is decoded twice (scan and write), as for compressed tarballs.
- The root filesystem is not a faithful runtime root: no symlinks (merged-`/usr` images lose
  `/bin`, `/lib` and friends), no device nodes, no ownership, no hard links (refused until the
  tar reader supports them), and directory modes and times are not applied. On Windows, Linux
  names that are invalid there (`:` in Perl man pages, case-only twins in terminfo) make the
  image refused, as for any tarball.
- `plan` does not support images yet; `inspect` shows the layer sizes.
