#!/bin/sh
# Install trunc from its GitHub releases (Linux, x86-64 and ARM64).
#
#   curl -LsSf https://raw.githubusercontent.com/Sparsebits/trunc/main/install.sh | sh
#
# Environment:
#   TRUNC_VERSION       release tag to install, e.g. v0.1.0 (default: the latest release)
#   TRUNC_INSTALL_DIR   where to put the binary (default: ~/.local/bin)
#   TRUNC_VERIFY_ATTESTATION
#                       check the download's signed build provenance with the GitHub CLI
#                       (`gh attestation verify`, see docs/security.md): 1 = required,
#                       0 = skip, auto (default) = only when gh is installed, and a warning
#                       rather than a failure when it cannot verify (e.g. gh is not logged in)
#
# The SHA-256 checksum is always verified.
set -eu

repo=Sparsebits/trunc
base=${TRUNC_DOWNLOAD_BASE:-https://github.com/$repo/releases}
version=${TRUNC_VERSION:-latest}
dir=${TRUNC_INSTALL_DIR:-$HOME/.local/bin}
attest=${TRUNC_VERIFY_ATTESTATION:-auto}

say() { printf 'trunc-install: %s\n' "$*"; }
die() {
    say "error: $*" >&2
    exit 1
}

case "$(uname -s)" in
Linux) ;;
Darwin) die "there is no macOS build yet; build from source: cargo install --git https://github.com/$repo trunc-cli" ;;
*) die "unsupported system $(uname -s) (on Windows, use install.ps1)" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=x86_64 ;;
aarch64 | arm64) arch=aarch64 ;;
*) die "unsupported CPU $(uname -m)" ;;
esac
case "$attest" in
0 | 1 | auto) ;;
*) die "TRUNC_VERIFY_ATTESTATION must be 0, 1 or auto, not '$attest'" ;;
esac

name="trunc-$arch-unknown-linux-musl"
asset="$name.tar.gz"
if [ "$version" = latest ]; then
    url="$base/latest/download/$asset"
else
    url="$base/download/$version/$asset"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl --proto '=https,file' -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q "$1" -O "$2"; }
else
    die "curl or wget is required"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "downloading $url"
fetch "$url" "$tmp/$asset" || die "download failed: $url"
fetch "$url.sha256" "$tmp/$asset.sha256" || die "download failed: $url.sha256"

expected=$(cut -d ' ' -f 1 <"$tmp/$asset.sha256")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$asset" | cut -d ' ' -f 1)
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/$asset" | cut -d ' ' -f 1)
else
    die "sha256sum or shasum is required to verify the download"
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset: expected $expected, got $actual"

# Build provenance: a Sigstore attestation from the release workflow, checked by the GitHub CLI.
if [ "$attest" != 0 ]; then
    if command -v gh >/dev/null 2>&1; then
        if out=$(gh attestation verify "$tmp/$asset" --repo "$repo" \
            --signer-workflow "$repo/.github/workflows/release.yml" 2>&1); then
            say "verified the build provenance of $asset"
        elif [ "$attest" = 1 ]; then
            printf '%s\n' "$out" >&2
            die "could not verify the build provenance of $asset"
        else
            say "warning: gh could not verify the build provenance of $asset (not logged in, or no attestation for this release); relying on the checksum. Set TRUNC_VERIFY_ATTESTATION=1 to require it." >&2
        fi
    elif [ "$attest" = 1 ]; then
        die "TRUNC_VERIFY_ATTESTATION=1 needs the GitHub CLI (gh): https://cli.github.com"
    fi
fi

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$dir"
cp "$tmp/$name/trunc" "$dir/trunc.new"
chmod 755 "$dir/trunc.new"
mv -f "$dir/trunc.new" "$dir/trunc"

say "installed $("$dir/trunc" --version) to $dir/trunc"
case ":$PATH:" in
*":$dir:"*) ;;
*) say "$dir is not on your PATH; add it with: export PATH=\"$dir:\$PATH\"" ;;
esac
