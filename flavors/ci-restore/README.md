# ci-restore

**Restore big CI caches and artifacts without doubling runner disk.**

A GitHub-hosted runner has about 14 GB of free disk. Restoring a cache or unpacking a download
keeps the archive on disk until the last file is out, so you need *archive + output* free:

| A 4 GB `.tar.zst` that unpacks to 11 GB | Peak disk | On a 14 GB runner |
|---|---|---|
| `actions/cache` restoring the tree, or download then `tar -x` | 4 + 11 = **15 GB** | No space left on device |
| `actions/cache` restoring one `cache.tar.zst`, then ci-restore | max(2 × 4, 11 + ε) = **about 11 GB** | fits |

The numbers are arithmetic, not a benchmark: tar keeps the whole archive until it finishes, and
trunc frees the compressed tarball from the front every 64 MiB of output, so the archive shrinks
as the tree grows (ε is one 64 MiB checkpoint). actions/cache needs its download plus the file it
restores (2 × 4 GB) before ci-restore starts. `trunc plan`, which the action prints first, gives
the figure for your own archive.

ci-restore installs [trunc](../../README.md) on the runner, checks it against the release's
`SHA256SUMS`, and runs `trunc x <archive> -C <path> --consume --yes`. If the job is killed
halfway, nothing is lost: the rest is still in the archive, and running it again continues.

Built on [trunc](../../README.md).

## GitHub Actions

```yaml
- uses: Sparsebits/trunc/flavors/ci-restore@main # pin a commit SHA in real use
  id: restore
  with:
    archive: cache.tar.zst # a path or an https:// URL
    path: deps
    # token: ${{ secrets.TRUNC_READ_TOKEN }}  # while Sparsebits/trunc is private, see below
- run: echo "${{ steps.restore.outputs.bytes-written }} bytes, saved ${{ steps.restore.outputs.space-saved }}"
```

| Input | Default | |
|---|---|---|
| `archive` | (required) | path or http(s) URL: `.tar.zst`, `.tar.gz`, `.tar.xz`, `.tar.bz2`, single compressed files, split tarballs, ZIP, ISO, `.trnc` |
| `path` | `.` | destination directory |
| `consume` | `true` | free the archive while extracting; `false` is an ordinary extract |
| `version` | `latest` | trunc release tag |
| `verify-checksum` | `true` | check the trunc download against `SHA256SUMS` |
| `token` | `github.token` | token for downloading trunc's release assets through the GitHub API |
| `sha256` | | expected SHA-256 of the archive, checked before extraction |
| `args` | | extra `trunc x` flags, e.g. `--verify-media` |
| `trunc-path` | | use this trunc binary instead of installing one |
| `repository` | `Sparsebits/trunc` | where to install trunc from |

Outputs: `bytes-written`, `space-saved` (archive bytes freed), `duration` (seconds),
`trunc-version`, `trunc-path`. trunc is also added to `PATH` for later steps, and a summary goes
to the job summary.

Runners: `ubuntu-latest`, `ubuntu-24.04-arm` and `windows-latest` (the steps use bash, which
Windows runners have). macOS runners fail with a "not supported yet" error: there is no macOS
trunc build.

The binary is cached in the runner tool cache (`$RUNNER_TOOL_CACHE/trunc/<version>/<arch>`),
which saves the download on self-hosted runners; hosted runners start fresh each job.

## Recipes

- [actions/cache](recipes/actions-cache.yml): cache one `cache.tar.zst` file instead of the tree.
  Restore it with `actions/cache/restore` (`path: cache.tar.zst`), unpack it with ci-restore,
  and on a miss pack it with `tar --zstd -cf cache.tar.zst -C deps .` and save it with
  `actions/cache/save`. The restore peaks at about the output size; the save still needs tree +
  archive, as actions/cache always does. actions/cache compresses the file again, which gains
  nothing on zstd data but costs little.
- [Large downloads](recipes/large-download.yml) (models, toolchains, datasets), replacing
  `curl | tar -x`: the archive is downloaded with retries and its `sha256` checked *before*
  anything is extracted, then freed as it unpacks. A pipe uses as little disk but cannot check
  the archive first and leaves a partial tree when the connection drops; download, check, extract
  then delete needs archive + output.
- [GitLab CI](recipes/gitlab-ci.yml), using the shell script.

## Any CI: `ci-restore.sh`

```sh
sh ci-restore.sh cache.tar.zst deps                       # install trunc, plan, consume
sh ci-restore.sh --sha256 "$SUM" https://example.com/m.tar.zst models
sh ci-restore.sh --no-consume cache.tar.zst deps -- --verify-media
TRUNC_BIN=/usr/local/bin/trunc sh ci-restore.sh a.tar.zst out   # use an existing trunc
sh ci-restore.sh install                                  # just install; prints the path
```

POSIX `sh`, `curl`, `tar` (or `unzip`/PowerShell on Windows) and `sha256sum` or `shasum`. Set
`CI_RESTORE_OUTPUT` to a file to get `key=value` results (a GitLab dotenv report works). The
header of the script lists every variable. Exit code 75 means trunc paused safely because the
disk is full: free some space and run it again.

## Limitations

- **Private repository.** The trunc repository is currently private, so release assets can only
  be downloaded through the GitHub API with a token that can read it. The action sends its
  `token` input (default `github.token`, which works only inside the trunc repository itself);
  elsewhere pass a fine-grained token with *Contents: read* on Sparsebits/trunc, e.g.
  `token: ${{ secrets.TRUNC_READ_TOKEN }}`. The script reads `TRUNC_TOKEN` (then `GITHUB_TOKEN`,
  `GH_TOKEN`). Once the repository is public, the public download URLs work with no token, and
  the script falls back to them when the API refuses.
- `version: latest` means the latest *published* release; drafts are not installable.
- `--consume` does not overwrite: the destination must not already contain the archive's files,
  and symlinks in the archive are skipped (trunc creates them only without `--consume`).
- The space comes back only on the same filesystem: keep the archive on the volume you extract
  to (`$GITHUB_WORKSPACE` and `$RUNNER_TEMP` share one on hosted runners; URL downloads go to
  `$RUNNER_TEMP`).
- No macOS build yet. On other systems, build trunc from source and set `TRUNC_BIN` /
  `trunc-path`.
