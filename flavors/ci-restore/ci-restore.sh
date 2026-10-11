#!/bin/sh
# ci-restore: restore a big CI cache or artifact without doubling the runner's disk use.
#
# Extracts ARCHIVE (a path or an http(s) URL) into DEST with trunc, which frees the archive's
# space while it extracts. Peak disk use is about the size of the extracted files, not the
# archive plus the files. Built on trunc: https://github.com/Sparsebits/trunc
#
#   ci-restore.sh [options] ARCHIVE DEST    restore ARCHIVE into DEST
#   ci-restore.sh install                   install trunc and print the binary's path
#
# Options:
#   --no-consume       keep the archive (an ordinary extract, which needs archive + output)
#   --sha256 HEX       check the archive's SHA-256 before extracting anything
#   --                 the rest of the arguments go to `trunc x` (e.g. --overwrite)
#
# Environment:
#   TRUNC_BIN                use this trunc binary instead of installing one
#   TRUNC_VERSION            release tag to install, e.g. v0.1.0 (default: latest)
#   TRUNC_REPO               GitHub repository to install from (default: Sparsebits/trunc)
#   TRUNC_TOKEN              GitHub token for downloading release assets through the API
#                            (needed while the repository is private; GITHUB_TOKEN and GH_TOKEN
#                            are used when TRUNC_TOKEN is unset)
#   TRUNC_VERIFY_CHECKSUM    1 (default) checks the download against the release's SHA256SUMS
#   TRUNC_CACHE_DIR          where installed binaries are kept between runs (default: the
#                            runner tool cache on GitHub Actions, else ~/.cache/ci-restore)
#   CI_RESTORE_CONSUME       0 is the same as --no-consume
#   CI_RESTORE_SHA256        the same as --sha256
#   CI_RESTORE_DOWNLOAD_DIR  where a URL archive is downloaded (default: next to DEST)
#   CI_RESTORE_OUTPUT        file to append key=value results to (the action passes
#                            $GITHUB_OUTPUT; a GitLab dotenv report file works too)
#
# Results (printed, and appended to CI_RESTORE_OUTPUT): bytes-written, space-saved (archive
# bytes freed during the restore), duration-seconds, trunc-version, trunc-path.
#
# Exit codes: trunc's own (75 = paused safely, out of space: free some and run it again), or 1.
set -eu

repo=${TRUNC_REPO:-Sparsebits/trunc}
version=${TRUNC_VERSION:-latest}
verify=${TRUNC_VERIFY_CHECKSUM:-1}
token=${TRUNC_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}
consume=${CI_RESTORE_CONSUME:-1}
sha256=${CI_RESTORE_SHA256:-}
out_file=${CI_RESTORE_OUTPUT:-}
api=${GITHUB_API_URL:-https://api.github.com}
web=${GITHUB_SERVER_URL:-https://github.com}

say() { printf 'ci-restore: %s\n' "$*" >&2; }
die() {
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        printf '::error title=ci-restore::%s\n' "$*"
    fi
    say "error: $*"
    exit 1
}
group() { [ "${GITHUB_ACTIONS:-}" = true ] && printf '::group::%s\n' "$*" || say "$*"; }
endgroup() { [ "${GITHUB_ACTIONS:-}" = true ] && printf '::endgroup::\n' || true; }
truthy() {
    case "$1" in 1 | true | TRUE | True | yes | on) return 0 ;; *) return 1 ;; esac
}
emit() {
    printf '%-17s %s\n' "$1" "$2"
    if [ -n "$out_file" ]; then printf '%s=%s\n' "$1" "$2" >>"$out_file"; fi
}

# --- platform -------------------------------------------------------------------------------

os=$(uname -s)
case "$os" in
Linux) os=linux ;;
MINGW* | MSYS* | CYGWIN* | Windows_NT) os=windows ;;
Darwin) os=macos ;;
*) die "unsupported system $os (trunc has Linux and Windows builds)" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=x86_64 ;;
aarch64 | arm64) arch=aarch64 ;;
*) die "unsupported CPU $(uname -m) (trunc has x86-64 and ARM64 builds)" ;;
esac
if [ "$os" = macos ]; then
    target=
    asset=
    exe=trunc
elif [ "$os" = windows ]; then
    # The x64 build also runs on Windows on ARM, under emulation.
    target=x86_64-pc-windows-msvc
    asset="trunc-$target.zip"
    exe=trunc.exe
else
    target="$arch-unknown-linux-musl"
    asset="trunc-$target.tar.gz"
    exe=trunc
fi

# Windows paths (C:\x) work in Git Bash, but find/du are happier with /c/x.
unixpath() {
    if [ "$os" = windows ] && command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s\n' "$1"; fi
}
nativepath() {
    if [ "$os" = windows ] && command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi
}

file_size() {
    stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null || wc -c <"$1" | tr -d ' '
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    else
        die "sha256sum or shasum is needed to check checksums"
    fi
}

# Apparent size of the regular files under $1, in bytes.
tree_bytes() {
    [ -d "$1" ] || {
        echo 0
        return
    }
    if find "$1" -maxdepth 0 -printf '' >/dev/null 2>&1; then
        find "$1" -type f -printf '%s\n' | awk '{ s += $1 } END { printf "%.0f\n", s }'
    else
        # BSD/busybox find: approximate with disk usage.
        du -sk "$1" | awk '{ printf "%.0f\n", $1 * 1024 }'
    fi
}

now() {
    t=$(date +%s%N 2>/dev/null || true)
    case "$t" in
    *[!0-9]* | "") echo "$(date +%s)000000000" ;;
    *) echo "$t" ;;
    esac
}

command -v curl >/dev/null 2>&1 || die "curl is required"
fetch() { curl --proto '=https,http,file' -fsSL --retry 3 "$@"; }

# --- install --------------------------------------------------------------------------------

# GET an API path with the token; prints the body.
api_get() {
    fetch -H "Authorization: Bearer $token" -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" "$api/repos/$repo/$1"
}

# The API URL of release asset $2 in the release JSON on stdin ($1 is unused, for clarity).
# Each asset object starts with its "url" (.../releases/assets/ID) and has a
# "browser_download_url" ending in its name; the uploader's "url" never matches.
asset_api_url() {
    tr ',{}' '\n\n\n' | awk -v name="$1" '
        /"url": *"[^"]*\/releases\/assets\/[0-9]+"/ { u = $0; sub(/.*"url": *"/, "", u); sub(/".*/, "", u) }
        /"browser_download_url": *"/ {
            b = $0; sub(/.*"browser_download_url": *"/, "", b); sub(/".*/, "", b)
            n = b; sub(/.*\//, "", n)
            if (n == name) { print u; exit }
        }'
}

resolve_version() {
    [ "$version" = latest ] || return 0
    if [ -n "$token" ] && json=$(api_get releases/latest 2>/dev/null); then
        version=$(printf '%s' "$json" | tr ',' '\n' | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
    else
        # Public repositories: the /releases/latest page redirects to /releases/tag/<tag>.
        final=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$web/$repo/releases/latest" 2>/dev/null || true)
        case "$final" in */releases/tag/*) version=${final##*/} ;; *) version= ;; esac
    fi
    [ -n "$version" ] || die "could not find the latest published release of $repo (drafts do not count). While the repository is private, pass a token that can read it (TRUNC_TOKEN, or the action's token input); otherwise set TRUNC_VERSION to a published tag."
}

# Download release asset $1 into file $2.
download_asset() {
    if [ -n "$token" ]; then
        if [ -z "${release_json:-}" ]; then
            release_json=$(api_get "releases/tags/$version" 2>/dev/null) || release_json=
        fi
        if [ -n "$release_json" ]; then
            url=$(printf '%s' "$release_json" | asset_api_url "$1")
            [ -n "$url" ] || die "release $version of $repo has no asset named $1"
            fetch -H "Authorization: Bearer $token" -H "Accept: application/octet-stream" "$url" -o "$2" &&
                return 0
        fi
        say "the API download failed; trying the public download URL"
    fi
    fetch "$web/$repo/releases/download/$version/$1" -o "$2" ||
        die "could not download $1 from release $version of $repo. If the repository is private, pass a token that can read it (TRUNC_TOKEN, or the action's token input)."
}

install_trunc() {
    [ "$os" != macos ] || die "macOS is not supported yet: trunc has no macOS release build. On macOS runners, restore with tar, or build trunc from source (cargo install --git $web/$repo trunc-cli) and point TRUNC_BIN at it."
    resolve_version
    case "$arch" in x86_64) tc_arch=x64 ;; *) tc_arch=arm64 ;; esac
    [ "$os" = windows ] && tc_arch=x64
    if [ -n "${TRUNC_CACHE_DIR:-}" ]; then
        cache_root=$TRUNC_CACHE_DIR
    elif [ -n "${RUNNER_TOOL_CACHE:-}" ]; then
        cache_root="$(unixpath "$RUNNER_TOOL_CACHE")/trunc"
    else
        cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/ci-restore"
    fi
    # The tool-cache layout used by actions/tool-cache: <tool>/<version>/<arch> + <arch>.complete
    vdir="$cache_root/${version#v}"
    bin="$vdir/$tc_arch/$exe"
    if [ -f "$vdir/$tc_arch.complete" ] && [ -x "$bin" ]; then
        say "using cached trunc $version at $bin"
        TRUNC_BIN=$bin
        return
    fi

    tmp=$(mktemp -d)
    say "downloading $asset from $repo $version"
    download_asset "$asset" "$tmp/$asset"
    if truthy "$verify"; then
        download_asset SHA256SUMS "$tmp/SHA256SUMS"
        expected=$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1; exit }' "$tmp/SHA256SUMS")
        [ -n "$expected" ] || die "SHA256SUMS of $version has no line for $asset"
        actual=$(sha256_of "$tmp/$asset")
        [ "$expected" = "$actual" ] || die "checksum mismatch for $asset: SHA256SUMS says $expected, the download is $actual"
        say "checksum ok: $asset matches SHA256SUMS"
    else
        say "warning: not checking the download against SHA256SUMS (verify-checksum is off)"
    fi

    if [ "$os" = windows ]; then
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "$tmp/$asset" -d "$tmp"
        else
            powershell.exe -NoProfile -NonInteractive -Command \
                "Expand-Archive -LiteralPath '$(cygpath -w "$tmp/$asset")' -DestinationPath '$(cygpath -w "$tmp")'"
        fi
    else
        tar -xzf "$tmp/$asset" -C "$tmp"
    fi
    mkdir -p "$vdir/$tc_arch"
    cp "$tmp/trunc-$target/$exe" "$bin"
    chmod 755 "$bin"
    : >"$vdir/$tc_arch.complete"
    rm -rf "$tmp"
    TRUNC_BIN=$bin
}

ensure_trunc() {
    if [ -n "${TRUNC_BIN:-}" ]; then
        TRUNC_BIN=$(unixpath "$TRUNC_BIN")
        [ -f "$TRUNC_BIN" ] || die "TRUNC_BIN=$TRUNC_BIN does not exist"
    else
        install_trunc
    fi
    trunc_version=$("$TRUNC_BIN" --version 2>/dev/null) || die "$TRUNC_BIN does not run"
}

# --- main -----------------------------------------------------------------------------------

if [ "${1:-}" = install ]; then
    ensure_trunc
    say "installed $trunc_version"
    emit trunc-version "$trunc_version"
    emit trunc-path "$(nativepath "$TRUNC_BIN")"
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
    --no-consume) consume=0 ;;
    --consume) consume=1 ;;
    --sha256)
        [ $# -ge 2 ] || die "--sha256 needs a value"
        sha256=$2
        shift
        ;;
    --) break ;;
    -h | --help)
        sed -n '2,/^set -eu/p' "$0" | sed '$d; s/^# \{0,1\}//'
        exit 0
        ;;
    -*) die "unknown option $1 (pass trunc's own flags after --)" ;;
    *)
        if [ -z "${archive:-}" ]; then
            archive=$1
        elif [ -z "${dest:-}" ]; then
            dest=$1
        else
            die "unexpected argument $1"
        fi
        ;;
    esac
    shift
done
if [ "${1:-}" = -- ]; then shift; fi
[ -n "${archive:-}" ] && [ -n "${dest:-}" ] || die "usage: ci-restore.sh [--no-consume] [--sha256 HEX] ARCHIVE DEST [-- TRUNC_FLAGS...]"

group "install trunc"
ensure_trunc
say "$trunc_version ($TRUNC_BIN)"
endgroup

dest=$(unixpath "$dest")
mkdir -p "$dest"

case "$archive" in
http://* | https://*)
    url=$archive
    name=${url%%[?#]*}
    name=${name##*/}
    [ -n "$name" ] || name=archive
    dl_dir=${CI_RESTORE_DOWNLOAD_DIR:-$(dirname "$dest")}
    dl_dir=$(unixpath "$dl_dir")
    mkdir -p "$dl_dir"
    archive="$dl_dir/$name"
    group "download $url"
    fetch "$url" -o "$archive" || die "download failed: $url"
    say "downloaded $(file_size "$archive") bytes to $archive"
    endgroup
    ;;
*) archive=$(unixpath "$archive") ;;
esac
[ -f "$archive" ] || die "archive not found: $archive"

if [ -n "$sha256" ]; then
    actual=$(sha256_of "$archive")
    expected=$(printf '%s' "$sha256" | tr 'A-F' 'a-f')
    [ "$expected" = "$actual" ] || die "checksum mismatch for $archive: expected $expected, got $actual"
    say "checksum ok: $archive"
fi

# The archive may sit inside DEST (e.g. `path: .`); its bytes are not output.
archive_dir=$(cd "$(dirname "$archive")" && pwd -P)
dest_abs=$(cd "$dest" && pwd -P)
case "$archive_dir/" in "$dest_abs"/*) inside=1 ;; *) inside=0 ;; esac

archive_before=$(file_size "$archive")
tree_before=$(tree_bytes "$dest")

group "trunc plan"
"$TRUNC_BIN" plan "$archive" -C "$dest" || say "warning: trunc plan failed; extracting anyway"
endgroup

if truthy "$consume"; then
    set -- x "$archive" -C "$dest" --consume --yes "$@"
else
    set -- x "$archive" -C "$dest" "$@"
fi
say "running: trunc $*"
start=$(now)
status=0
"$TRUNC_BIN" "$@" || status=$?
end=$(now)

if [ "$status" -ne 0 ]; then
    if [ "$status" -eq 75 ]; then
        die "trunc paused safely: the runner is out of disk space. Nothing is lost; free some space and run it again (or 'trunc resume $archive')."
    fi
    die "trunc exited with status $status"
fi

archive_after=0
[ -f "$archive" ] && archive_after=$(file_size "$archive")
receipt=0
[ -f "$archive.receipt" ] && receipt=$(file_size "$archive.receipt")
tree_after=$(tree_bytes "$dest")
written=$((tree_after - tree_before))
if [ "$inside" = 1 ]; then
    written=$((written + archive_before - archive_after - receipt))
fi
saved=$((archive_before - archive_after - receipt))
[ "$saved" -ge 0 ] || saved=0
duration=$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.2f\n", (e - s) / 1e9 }')

emit bytes-written "$written"
emit space-saved "$saved"
emit duration-seconds "$duration"
emit trunc-version "$trunc_version"
emit trunc-path "$(nativepath "$TRUNC_BIN")"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        printf '### ci-restore\n\n| | |\n|---|---|\n'
        printf '| archive | `%s` |\n| destination | `%s` |\n' "$archive" "$dest"
        printf '| bytes written | %s |\n| space saved | %s |\n| duration | %s s |\n' \
            "$written" "$saved" "$duration"
        printf '| trunc | %s |\n' "$trunc_version"
    } >>"$GITHUB_STEP_SUMMARY"
fi
