# Security checklist

How each rule from the design (plan section 7) is enforced, and the test that shows it. Reviewed 2026-10-08 (plan phase 6.2). A rule without a test is listed as a gap.

## Hostile archive contents

| Rule | Enforced in | Tested by |
|---|---|---|
| Entry paths are relative, NFC, `/`-separated; no `..`, `.`, empty components, drive letters, control characters. `.trnc` names, and on Windows all names, also exclude `\`, `:`, Windows-reserved names and trailing dots/spaces (ADR-0014) | `trunc-core::path::validate` for every manifest entry; `trunc-core::path::validate_host` for ZIP, tar and single-file outputs | `trunc-core` path tests; `hostile_manifest_is_rejected_at_open`; `rejects_hostile_names`; `hostile_archives_are_refused_untouched` |
| No duplicate names (case-insensitive for `.trnc` and on Windows and macOS; exact on Linux) and nothing nested under a file; outputs are checked against the exact name the filesystem reports | `Manifest::validate`; `zip::parse`; `tar::Reader` (`host_key`); `check_exact_name` | `rejects_case_collisions_and_nesting_under_files`; `rejects_hostile_names`; `hostile_and_unsupported_archives_are_refused_untouched` |
| Names that the filesystem folds together anyway (8.3 short names like `LONGFI~1.TXT`, Unicode case variants) are never merged into one output | `stage::check_exact_name`: an output that already exists must be listed under its exact name | code review; covered by the crash sweeps for the legitimate resume case |
| Block table tiles the stream exactly; sizes bounded; footers match the manifest | `Manifest::validate`, `Footer::decode`, `Archive::read_footer` | manifest and footer unit tests; `decode_never_panics` property tests; fuzz targets `header`, `footer`, `manifest` |
| Every byte is hash-checked before use (payload before decompressing, decoded block, whole entry) | `Archive::decode_block`, extract/consume hashers | `tampered_payload_is_detected`; `tampered_block_stops_before_destroying_it` |
| tar.gz: the whole archive (gzip CRCs, tar headers, names) is checked before anything is written, and the content between checkpoints must hash as it did then before its compressed bytes are freed | `tgzconsume::scan`, `consume_tgz` | `corruption_is_found_before_anything_is_destroyed`; crash sweeps in `tgzconsume.rs` |
| ZIP punch mode: each checkpoint's running CRC must match the verification pass before its bytes are freed | `zipconsume::verify_checkpoints`, `extract_punching` | `crash_sweep_punch_mode` |
| Manifest corruption is detected even when unsigned | BLAKE3 of the manifest region in the header | `tampered_footer_and_manifest_are_detected` (flips every 5th byte of header and manifest) |
| ZIP: central directory entries match their local headers; data stays before the directory; descriptor CRCs agree | `zip::parse` | `rejects_unsupported_and_inconsistent_archives`; fuzz target `zip`; `tampered_archives_never_panic` |
| ZIP: overlapping entries (zip-bomb technique) refused unless `--allow-overlap` | `consume_zip`, `extract_zip` | `overlapping_entries_need_opt_in_and_then_extract_correctly` |
| Decompression bombs: output never exceeds declared sizes; declared sizes are checked against free space first | `Inflater` `max_out`; block decoder exact length; preflight in `consume`, `consume_zip`, and the CLI `x` path | `output_limit_and_overrun_are_errors`; `zip_bomb_is_refused_by_the_space_check`; `refuses_up_front_when_space_is_clearly_short` |
| Decoders never panic on garbage | all decoders return errors | property tests (`garbage_never_panics`, `corrupted_streams_never_panic`) and fuzz targets |
| Compressed streams: the scan decodes everything (checksums, tar headers, names) before anything is written; decoder memory is bounded by `--max-window`; a resumed decoder's window read back from disk must match the CRC journaled with it | `streamconsume::scan`; `Limits::max_window` in the xz and zstd decoders; `stream::restore_window` | `corruption_is_found_before_anything_is_destroyed`; `every_codec_on_structured_data`; fuzz targets `bzip2`, `xz`, `zstd` (differential against the reference decoders, with a resume from every safe point) |
| Split archives: a resumed consume accepts a missing part only if it lies wholly before the last checkpoint, and refuses parts whose size or file id changed | `source::Parts::reopen` | `split_archives_refuse_later_parts_and_replaced_parts`; `crash_sweep_split_archive` |

## Writing outputs

| Rule | Enforced in | Tested by |
|---|---|---|
| Never follow symlinks or junctions when opening outputs | `OsFs::open` (Windows: `FILE_FLAG_OPEN_REPARSE_POINT` + attribute check, junction detection on open failure; Linux: `O_NOFOLLOW`). Staged outputs and directories go through `open_beneath` / `create_dir_beneath`: on Linux `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS)`, so no component below the staging directory can be a link; on Windows the opened handle's real location (`GetFinalPathNameByHandleW` plus the volume serial) must lie inside the staging directory, so nothing is written through a junction anywhere on the path, and an item created through one is removed again | `junctions_are_never_followed`; `symlinks_are_never_followed` |
| Symlink entries are never created by `--consume`; non-destructive extraction creates them only with `--allow-symlinks` and only when they resolve inside the destination, without passing through another symlink entry | `stage::build_structure`; `extract::symlink_stays_inside` | `symlink_containment` |
| Writes go only into the staging directory until the rename phase; renames never replace existing paths | `consume`, `consume_zip`, `OsFs::rename` (Windows `MoveFileExW` without replace; Linux `renameat2(RENAME_NOREPLACE)`) | `check_crash_state` in every crash sweep; `rename_never_replaces`; `refuses_existing_targets_and_wrong_destinations` |
| An output is never the archive or its journal under another name | `stage::open_staged_output` compares file ids | `refuses_staged_files_that_are_the_archive`; `refuses_staged_files_that_are_the_zip` |
| setuid/setgid/sticky bits are never restored | `extract::apply_mode` (`mode & 0o777`); `OsFs::set_mode` | code review |
| Outputs cannot be modified by other processes during consumption | Windows: exclusive share mode (other handles may read only). Linux: advisory `flock`, which stops a second trunc but not other programs (see gaps) | `exclusive_open_blocks_other_handles`; `exclusive_open_stops_a_second_exclusive_open`; `exclusive_handles_and_create_semantics` |

## Trust

| Rule | Enforced in | Tested by |
|---|---|---|
| Signatures (Ed25519 over the manifest hash) are verified whenever present | `SignedManifest::open` | `signature_round_trip_and_tamper` |
| `--require-signed` refuses unsigned archives; `--trust-key` pins signers | `TrustPolicy::check` | `signatures_and_trust_policy`; `signing_flow` |
| Unsigned archives are reported | preflight `Finding::Unsigned` (`trunc plan`, `--consume`) | code review |
| `--require-signed` and `--trust-key` are refused (not ignored) for ZIP and tar.gz, which cannot be signed, so a ZIP renamed to `.trnc` cannot slip past them | CLI `refuse_trust_flags` | `signature_flags_are_refused_for_unsigned_formats` |
| Destructive mode refuses archives in cloud-synced folders, on unjournaled filesystems and on filesystems it cannot identify, unless overridden | preflight blockers | `blockers_for_unjournaled_and_synced_archives`; `unjournaled_volumes_need_consent` |

## Known gaps and accepted risks

- **Local attackers racing the staging directory (Windows, and Linux kernels before 5.6).** On Windows every opened output is checked where it really is, so data is never written through a junction; but a process with write access to the destination could swap a staged directory for a junction so that an empty file or directory is briefly created outside before trunc removes it. On Linux 5.6 and later, `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` prevents even that; where openat2 is unavailable a check-then-open fallback applies. Destructive extraction into a directory that untrusted local users can write to is not supported.
- **Linux advisory locking.** `flock` stops a second trunc, but other programs can still modify staged outputs, and such changes are not detected: a resumed run does not re-read output that was already made durable.
- **Integrity is not authenticity.** An unsigned archive can be replaced wholesale. Use signatures and `--trust-key` when the source matters.
- **Lying storage.** A drive that acknowledges flushes without persisting data defeats any ordering. `--verify-media` reads data back, bypassing the OS cache, before releasing source bytes; the drive's own cache may still answer.

## Verifying downloads

Every release lists the SHA-256 of each file in `SHA256SUMS` (and `<asset>.sha256`); `install.sh` and `install.ps1` always check it. Each target also has a CycloneDX SBOM, `trunc-<target>.cdx.json`, listing the crates compiled into that binary.

Releases built while the repository is public also carry signed build provenance (Sigstore, via GitHub artifact attestations), which ties each file to the commit and the `release.yml` run that built it. Check it with the [GitHub CLI](https://cli.github.com):

```sh
gh attestation verify trunc-x86_64-unknown-linux-musl.tar.gz --repo Sparsebits/trunc \
  --signer-workflow Sparsebits/trunc/.github/workflows/release.yml
# the SBOM bound to that archive:
gh attestation verify trunc-x86_64-unknown-linux-musl.tar.gz --repo Sparsebits/trunc \
  --predicate-type https://cyclonedx.org/bom
```

The install scripts run the first check themselves when `gh` is installed, warning (not failing) if it cannot verify, for example when gh is not logged in. Set `TRUNC_VERIFY_ATTESTATION=1` to make the check required, or `0` to skip it.
