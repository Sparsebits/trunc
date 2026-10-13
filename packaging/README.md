# Packaging

Manifests for package managers. Each one downloads the release archives, so they can only go
out after the GitHub release is published. For a new version:

1. Publish the GitHub release.
2. `python packaging/update.py <version>` rewrites every manifest with that release's checksums.
3. Ship each one:
   - **crates.io:** `cargo publish --workspace` from a clean checkout of the tag. This also makes
     `cargo binstall trunc-cli` work (the metadata is in `crates/trunc-cli/Cargo.toml`).
   - **Scoop:** copy `scoop/trunc.json` to `bucket/trunc.json` in
     [Sparsebits/scoop-bucket](https://github.com/Sparsebits/scoop-bucket).
   - **winget:** open a PR to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)
     adding `winget/manifests/s/Sparsebits/trunc/<version>/`.
   - **AUR:** copy `aur/trunc-bin/PKGBUILD` and `.SRCINFO` to the `trunc-bin` AUR repository and
     push.

Bump the `=x.y.z` versions of the internal crates in the root `Cargo.toml` with the workspace
version. crates.io needs them to match.
