# layerless

**Pull a container image straight to a root filesystem: no tarball, no daemon, no double disk.**

```console
$ layerless pull alpine:3 -C rootfs
pulling docker.io/library/alpine:3 (linux/amd64, 1 layers, 3.7 MiB)
  layer 1/1 e2de96513ba9    3.7 MiB  verified
84 files, 96 directories, 8.0 MiB written to rootfs in 26.8s
```

The usual way to get an image's filesystem is `docker pull`, `docker create`, `docker export`
and `tar -x`. That needs a daemon and root, and the image ends up on disk two or three times.
layerless talks to the registry itself. Each layer goes from the HTTPS response through the
decoder and the tar reader into a staging directory, so a layer is never stored as a file. The
blob's sha256 and the layer's `diff_id` are checked as the bytes arrive. The merged tree is
renamed into place only after every digest has passed. If anything fails, the destination is
left as it was.

Built on [trunc](../../../README.md), the extractor that frees an archive's disk space while it
unpacks.

## Install

```console
cargo install --path crates/flavors/layerless
```

It builds to one static binary: pure-Rust HTTPS (rustls, with Mozilla's root certificates
built in), no async runtime and no OpenSSL.

## Usage

```console
layerless pull <ref> -C <dir> [--platform os/arch[/variant]]
layerless inspect <ref> [--platform os/arch]
layerless unpack image.tar -C <dir> [--platform os/arch]
```

- `<ref>` is anything `docker pull` accepts: `alpine`, `alpine:3.20`, `bitnami/redis:7`,
  `ghcr.io/owner/name:tag`, `quay.io/org/img@sha256:...`.
- `--platform` picks one entry of a multi-platform image. The default is `linux/<this
  machine's architecture>`, including on Windows and macOS.
- `inspect` prints the index (platforms), the chosen manifest, the config and every layer
  with its size and compression. It downloads no layers.
- `unpack` does the same as `trunc x` on a `docker save` or OCI archive tarball.

## How it works

1. **Resolve.** The tag is fetched with an anonymous bearer token (from the registry's
   `WWW-Authenticate` challenge, e.g. auth.docker.io). An index (manifest list) is resolved to
   the requested platform's manifest. Then the config is fetched, which gives the `diff_ids`.
   Manifests fetched by digest and the config are checked against their digests.
2. **Stream.** Layers are read one at a time, in order. gzip and zstd are decoded by trunc's own
   decoders, single-threaded and front to back. Uncompressed layers are read as they are. Each
   entry is written into `<dir>/.layerless-stage-*` as it appears.
3. **Merge as you go.** Layers arrive in order and there is no second pass, so OCI whiteouts
   (`.wh.name`), opaque directories (`.wh..wh..opq`) and later entries that replace earlier
   paths **delete what earlier layers wrote inside the staging directory**. A whiteout only
   ever hides lower layers, never entries of its own layer. The tarball path (`trunc x`,
   `layerless unpack`) can scan first and write only the files that survive. A pull can't,
   so short-lived bytes do get written and deleted again.
4. **Commit.** Once the last layer is verified, the top-level entries are renamed from staging
   into `<dir>`. Names that already exist in `<dir>` are refused.

## Limits (v0)

- **Public images only.** Anonymous bearer tokens work on Docker Hub, GHCR, Quay and most OCI
  registries. Basic auth and credential helpers are not supported yet.
- **Symlinks, hard links, devices and FIFOs are skipped and counted**, as in trunc. A root
  filesystem made this way is fine for inspecting, scanning and copying files out. It is not a
  bootable or runnable rootfs. On Linux, ownership (uid/gid) and xattrs are not kept either.
- Layers are downloaded one after another on a single connection. Interrupted pulls start
  over: there is no resume yet.
- Docker schema 1 manifests, encrypted layers, and foreign or non-distributable layers whose
  blobs are not in the registry are refused.
- Plain HTTP is used only for loopback registries (`localhost`, `127.0.0.1`). There is no
  `--insecure` flag.
- File contents are not fsynced one by one before the final rename (directories are), the same
  as trunc's image extraction.
