# Security checklist

How each rule from the design (plan section 7) is enforced, and the test that shows it. Reviewed 2026-10-08 (plan phase 6.2). A rule without a test is listed as a gap.

## Hostile archive contents

| Rule | Enforced in | Tested by |
|---|---|---|
| Entry paths are relative, NFC, `/`-separated; no `..`, `.`, empty components, drive letters, `\`, `:`, control characters, Windows-reserved names or trailing dots/spaces | `trunc-core::path::validate`, applied to every manifest entry and every ZIP name | `trunc-core` path tests; `hostile_manifest_is_rejected_at_open`; `rejects_hostile_names`; `hostile_archives_are_refused_untouched` |
| No duplicate names (case-insensitive) and nothing nested under a file | `Manifest::validate`; `zip::parse` | `rejects_case_collisions_and_nesting_under_files`; `rejects_hostile_names` |
| Block table tiles the stream exactly; sizes bounded; footers match the manifest | `Manifest::validate`, `Footer::decode`, `Archive::read_footer` | manifest and footer unit tests; `decode_never_panics` property tests; fuzz targets `header`, `footer`, `manifest` |
| Every byte is hash-checked before use (payload before decompressing, decoded block, whole entry) | `Archive::decode_block`, extract/consume hashers | `tampered_payload_is_detected`; `tampered_block_stops_before_destroying_it` |
| Manifest corruption is detected even when unsigned | BLAKE3 of the manifest region in the header | `tampered_footer_and_manifest_are_detected` (flips every 5th byte of header and manifest) |
| ZIP: central directory entries match their local headers; data stays before the directory; descriptor CRCs agree | `zip::parse` | `rejects_unsupported_and_inconsistent_archives`; fuzz target `zip`; `tampered_archives_never_panic` |
| ZIP: overlapping entries (zip-bomb technique) refused unless `--allow-overlap` | `consume_zip`, `extract_zip` | `overlapping_entries_need_opt_in_and_then_extract_correctly` |
| Decompression bombs: output never exceeds declared sizes; declared sizes are checked against free space first | `Inflater` `max_out`; block decoder exact length; preflight in `consume`, `consume_zip`, and the CLI `x` path | `output_limit_and_overrun_are_errors`; `zip_bomb_is_refused_by_the_space_check`; `refuses_up_front_when_space_is_clearly_short` |
| Decoders never panic on garbage | all decoders return errors | property tests (`garbage_never_panics`, `corrupted_streams_never_panic`) and fuzz targets |

## Writing outputs

| Rule | Enforced in | Tested by |
|---|---|---|
| Never follow symlinks or junctions when opening outputs | `OsFs::open` (Windows: `FILE_FLAG_OPEN_REPARSE_POINT` + attribute check, junction detection on open failure; Linux: `O_NOFOLLOW`). Staged outputs and directories go through `open_beneath` / `create_dir_beneath`, which on Linux use `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS)` so no component below the staging directory can be a link | `junctions_are_never_followed`; `symlinks_are_never_followed` |
| Symlink entries are never created by `--consume`; non-destructive extraction creates them only with `--allow-symlinks` and only when they resolve inside the destination | `stage::build_structure`; `extract::symlink_stays_inside` | `symlink_containment` |
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
| Destructive mode refuses archives in cloud-synced folders and on unjournaled filesystems unless overridden | preflight blockers | `blockers_for_unjournaled_and_synced_archives` |

## Known gaps and accepted risks

- **Local attackers racing the staging directory (Windows, and Linux kernels before 5.6).** Intermediate directories are checked when created or reused, but a process with write access to the destination could swap a staged directory for a junction between the check and a later open. On Linux 5.6 and later, `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` closes this; where openat2 is unavailable the check-then-open fallback applies. Destructive extraction into a directory that untrusted local users can write to is not supported.
- **Linux advisory locking.** `flock` stops a second trunc, but other programs can still modify staged outputs. Changes are caught by hashes on resume, not prevented.
- **Integrity is not authenticity.** An unsigned archive can be replaced wholesale. Use signatures and `--trust-key` when the source matters.
- **Lying storage.** A drive that acknowledges flushes without persisting data defeats any ordering. `--verify-media` reads data back, bypassing the OS cache, before releasing source bytes; the drive's own cache may still answer.
