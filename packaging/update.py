"""Regenerate the package manifests for a release from its SHA256SUMS.

    python packaging/update.py 0.1.0                  # downloads SHA256SUMS with the GitHub CLI
    python packaging/update.py 0.1.0 path/SHA256SUMS  # or reads a local copy

Writes the Scoop manifest, the winget manifests and the AUR PKGBUILD and .SRCINFO.
"""

import json
import pathlib
import subprocess
import sys

REPO = "Sparsebits/trunc"
HOME = f"https://github.com/{REPO}"
DESC = "Extract archives bigger than your free space: trunc deletes the archive as it extracts."
HERE = pathlib.Path(__file__).resolve().parent


def sums(version, path):
    if path:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    else:
        text = subprocess.run(
            ["gh", "release", "download", f"v{version}", "-R", REPO, "-p", "SHA256SUMS", "-O", "-"],
            check=True, capture_output=True, text=True,
        ).stdout
    out = {}
    for line in text.splitlines():
        digest, name = line.split()
        out[name.lstrip("*")] = digest
    return out


def write(rel, text):
    p = HERE / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    print("wrote", p.relative_to(HERE.parent))


def url(version, target, ext):
    return f"{HOME}/releases/download/v{version}/trunc-{target}.{ext}"


def scoop(version, h):
    arch = {"64bit": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}
    manifest = {
        "version": version,
        "description": DESC,
        "homepage": HOME,
        "license": "MIT|Apache-2.0",
        "architecture": {
            a: {"url": url(version, t, "zip"), "hash": h[f"trunc-{t}.zip"], "extract_dir": f"trunc-{t}"}
            for a, t in arch.items()
        },
        "bin": "trunc.exe",
        "checkver": "github",
        "autoupdate": {
            "architecture": {
                a: {"url": url("$version", t, "zip"), "hash": {"url": "$url.sha256"},
                    "extract_dir": f"trunc-{t}"}
                for a, t in arch.items()
            }
        },
    }
    write("scoop/trunc.json", json.dumps(manifest, indent=4) + "\n")


def winget(version, h):
    pid = "Sparsebits.trunc"
    d = f"winget/manifests/s/Sparsebits/trunc/{version}"
    head = f"PackageIdentifier: {pid}\nPackageVersion: {version}\n"
    write(f"{d}/{pid}.yaml", f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.9.0.schema.json
{head}DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.9.0
""")
    installers = ""
    for arch, target in (("x64", "x86_64-pc-windows-msvc"), ("arm64", "aarch64-pc-windows-msvc")):
        installers += f"""- Architecture: {arch}
  InstallerUrl: {url(version, target, "zip")}
  InstallerSha256: {h[f"trunc-{target}.zip"].upper()}
  NestedInstallerFiles:
  - RelativeFilePath: trunc-{target}\\trunc.exe
    PortableCommandAlias: trunc
"""
    write(f"{d}/{pid}.installer.yaml", f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.9.0.schema.json
{head}InstallerType: zip
NestedInstallerType: portable
Commands:
- trunc
Installers:
{installers}ManifestType: installer
ManifestVersion: 1.9.0
""")
    write(f"{d}/{pid}.locale.en-US.yaml", f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.9.0.schema.json
{head}PackageLocale: en-US
Publisher: Sparsebits
PublisherUrl: https://github.com/Sparsebits
PackageName: trunc
PackageUrl: {HOME}
License: MIT OR Apache-2.0
LicenseUrl: {HOME}/blob/main/LICENSE-MIT
ShortDescription: {DESC}
Description: |-
  trunc extracts ZIP, tar, compressed tarballs, ISO images and container images while deleting the
  archive as it goes, so you only need free space for the extracted files. An interrupted run can
  be resumed.
Tags:
- archive
- extract
- unzip
- tar
- zip
- disk-space
ReleaseNotesUrl: {HOME}/releases/tag/v{version}
ManifestType: defaultLocale
ManifestVersion: 1.9.0
""")


def aur(version, h):
    x64 = h["trunc-x86_64-unknown-linux-musl.tar.gz"]
    arm = h["trunc-aarch64-unknown-linux-musl.tar.gz"]
    src = f"{HOME}/releases/download/v$pkgver/trunc-{{arch}}-unknown-linux-musl.tar.gz"
    write("aur/trunc-bin/PKGBUILD", f"""# Maintainer: Sparsebits <https://github.com/Sparsebits>
pkgname=trunc-bin
pkgver={version}
pkgrel=1
pkgdesc="{DESC}"
arch=('x86_64' 'aarch64')
url="{HOME}"
license=('MIT OR Apache-2.0')
provides=('trunc')
conflicts=('trunc')
source_x86_64=("trunc-$pkgver-x86_64.tar.gz::{src.format(arch="x86_64")}")
source_aarch64=("trunc-$pkgver-aarch64.tar.gz::{src.format(arch="aarch64")}")
sha256sums_x86_64=('{x64}')
sha256sums_aarch64=('{arm}')

package() {{
  cd "trunc-$CARCH-unknown-linux-musl"
  install -Dm755 trunc "$pkgdir/usr/bin/trunc"
  install -Dm644 LICENSE-MIT "$pkgdir/usr/share/licenses/$pkgname/LICENSE-MIT"
  install -Dm644 LICENSE-APACHE "$pkgdir/usr/share/licenses/$pkgname/LICENSE-APACHE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}}
""")
    s = lambda a: f"{HOME}/releases/download/v{version}/trunc-{a}-unknown-linux-musl.tar.gz"
    write("aur/trunc-bin/.SRCINFO", f"""pkgbase = trunc-bin
\tpkgdesc = {DESC}
\tpkgver = {version}
\tpkgrel = 1
\turl = {HOME}
\tarch = x86_64
\tarch = aarch64
\tlicense = MIT OR Apache-2.0
\tprovides = trunc
\tconflicts = trunc
\tsource_x86_64 = trunc-{version}-x86_64.tar.gz::{s("x86_64")}
\tsha256sums_x86_64 = {x64}
\tsource_aarch64 = trunc-{version}-aarch64.tar.gz::{s("aarch64")}
\tsha256sums_aarch64 = {arm}

pkgname = trunc-bin
""")


if __name__ == "__main__":
    version = sys.argv[1].lstrip("v")
    h = sums(version, sys.argv[2] if len(sys.argv) > 2 else None)
    scoop(version, h)
    winget(version, h)
    aur(version, h)
