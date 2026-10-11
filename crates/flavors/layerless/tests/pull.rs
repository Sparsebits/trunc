//! `layerless::pull` against an in-process fake registry (std TcpListener): bearer-token auth,
//! an index with gzip and zstd platforms, a CDN redirect, whiteouts, and digest refusal.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;

use trunc_testkit::imagebuild::{self as ib, Compression, Layer};
use trunc_testkit::tarbuild::Spec;

struct Registry {
    port: u16,
}

/// Serve `blobs` (digest -> bytes) and `manifests` (tag or digest -> (media type, bytes)).
fn serve(
    manifests: HashMap<String, (String, Vec<u8>)>,
    blobs: HashMap<String, Vec<u8>>,
) -> Registry {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let m = Arc::new(manifests);
    let b = Arc::new(blobs);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let (m, b) = (m.clone(), b.clone());
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().expect("clone"));
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                let mut auth = false;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    if h.to_ascii_lowercase()
                        .starts_with("authorization: bearer secret")
                    {
                        auth = true;
                    }
                }
                let reply = |s: &mut std::net::TcpStream,
                             status: &str,
                             extra: &str,
                             body: &[u8]| {
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
                        body.len()
                    );
                    let _ = s.write_all(head.as_bytes());
                    let _ = s.write_all(body);
                };
                if path.starts_with("/token?") {
                    assert!(path.contains("scope=repository:test/img:pull"), "{path}");
                    return reply(&mut s, "200 OK", "", br#"{"token":"secret"}"#);
                }
                if let Some(d) = path.strip_prefix("/cdn/") {
                    return match b.get(d) {
                        Some(data) => reply(&mut s, "200 OK", "", data),
                        None => reply(&mut s, "404 Not Found", "", b""),
                    };
                }
                if !auth {
                    let ch = format!(
                        "WWW-Authenticate: Bearer realm=\"http://127.0.0.1:{port}/token\",service=\"fake\",scope=\"repository:test/img:pull\"\r\n"
                    );
                    return reply(&mut s, "401 Unauthorized", &ch, b"");
                }
                if let Some(t) = path.strip_prefix("/v2/test/img/manifests/") {
                    return match m.get(t) {
                        Some((mt, data)) => {
                            reply(&mut s, "200 OK", &format!("Content-Type: {mt}\r\n"), data)
                        }
                        None => reply(&mut s, "404 Not Found", "", b""),
                    };
                }
                if let Some(d) = path.strip_prefix("/v2/test/img/blobs/") {
                    return reply(
                        &mut s,
                        "307 Temporary Redirect",
                        &format!("Location: /cdn/{d}\r\n"),
                        b"",
                    );
                }
                reply(&mut s, "404 Not Found", "", b"");
            });
        }
    });
    Registry { port }
}

fn layers(c: Compression) -> Vec<Layer> {
    vec![
        ib::layer(
            &[
                Spec::dir("etc"),
                Spec::file("etc/os-release", b"fake os\n"),
                Spec::file("etc/old", b"to be deleted"),
                Spec::dir("var/cache"),
                Spec::file("var/cache/a", b"cache"),
                Spec::file("big", &vec![7u8; 3 << 20]),
            ],
            c,
        ),
        ib::layer(
            &[
                Spec::file("etc/.wh.old", b""),
                Spec::file("var/cache/.wh..wh..opq", b""),
                Spec::file("var/cache/b", b"fresh"),
                Spec::file("etc/os-release", b"patched\n"),
            ],
            c,
        ),
    ]
}

/// An index with linux/amd64 (gzip) and linux/arm64 (zstd) under tag `v1`. `tamper`: flip a
/// byte of the last arm64 layer as served.
fn registry(tamper: bool) -> Registry {
    let mut manifests = HashMap::new();
    let mut blobs = HashMap::new();
    let mut descs = Vec::new();
    for (p, c) in [
        ("linux/amd64", Compression::Gzip),
        ("linux/arm64", Compression::Zstd),
    ] {
        let ls = layers(c);
        let ids: Vec<&str> = ls.iter().map(|l| l.diff_id.as_str()).collect();
        let cfg = ib::config(p, &ids);
        blobs.insert(ib::digest(&cfg), cfg.clone());
        for (i, l) in ls.iter().enumerate() {
            let mut data = l.blob.clone();
            if tamper && c == Compression::Zstd && i == 1 {
                let n = data.len() - 3;
                data[n] ^= 1;
            }
            blobs.insert(l.digest.clone(), data);
        }
        let m = ib::manifest(&cfg, &ls);
        descs.push(ib::descriptor(ib::MANIFEST, &m, &ib::platform(p)));
        manifests.insert(ib::digest(&m), (ib::MANIFEST.to_owned(), m));
    }
    manifests.insert("v1".into(), (ib::INDEX.to_owned(), ib::index(&descs)));
    serve(manifests, blobs)
}

#[test]
fn pulls_gzip_and_zstd_platforms_with_whiteouts() {
    let reg = registry(false);
    for p in ["linux/amd64", "linux/arm64"] {
        let dir = tempfile::tempdir().expect("tmp");
        let dest = dir.path().join("rootfs");
        let mut done = Vec::new();
        let s = layerless::pull(
            &format!("127.0.0.1:{}/test/img:v1", reg.port),
            &dest,
            Some(p),
            &mut |r| assert_eq!(r.config.platform, p),
            &mut |i, _| done.push(i),
        )
        .unwrap_or_else(|e| panic!("{p}: {e:#}"));
        assert_eq!(done, vec![0, 1]);
        assert_eq!(
            std::fs::read(dest.join("etc/os-release")).expect("r"),
            b"patched\n"
        );
        assert!(!dest.join("etc/old").exists(), "whiteout");
        assert!(!dest.join("var/cache/a").exists(), "opaque dir");
        assert_eq!(
            std::fs::read(dest.join("var/cache/b")).expect("r"),
            b"fresh"
        );
        assert_eq!(
            std::fs::read(dest.join("big")).expect("r"),
            vec![7u8; 3 << 20]
        );
        assert_eq!(s.stats.whiteouts, 1);
        assert_eq!(s.stats.opaques, 1);
        let names: Vec<_> = std::fs::read_dir(&dest)
            .expect("ls")
            .map(|e| e.expect("e").file_name().into_string().expect("utf8"))
            .collect();
        assert!(
            !names.iter().any(|n| n.starts_with(".layerless")),
            "{names:?}"
        );
    }
}

#[test]
fn digest_mismatch_leaves_destination_untouched() {
    let reg = registry(true);
    let dir = tempfile::tempdir().expect("tmp");
    let dest = dir.path().join("rootfs");
    std::fs::create_dir(&dest).expect("mkdir");
    let e = layerless::pull(
        &format!("127.0.0.1:{}/test/img:v1", reg.port),
        &dest,
        Some("linux/arm64"),
        &mut |_| {},
        &mut |_, _| {},
    )
    .expect_err("tampered layer must be refused");
    let msg = format!("{e:#}");
    assert!(msg.contains("sha256") || msg.contains("corrupt"), "{msg}");
    assert_eq!(std::fs::read_dir(&dest).expect("ls").count(), 0, "{msg}");
    // A destination the pull created is removed again.
    let fresh = dir.path().join("new");
    assert!(
        layerless::pull(
            &format!("127.0.0.1:{}/test/img:v1", reg.port),
            &fresh,
            Some("linux/arm64"),
            &mut |_| {},
            &mut |_, _| {},
        )
        .is_err()
    );
    assert!(!fresh.exists());
}

#[test]
fn missing_platform_is_refused() {
    let reg = registry(false);
    let dir = tempfile::tempdir().expect("tmp");
    let e = layerless::pull(
        &format!("127.0.0.1:{}/test/img:v1", reg.port),
        &dir.path().join("x"),
        Some("linux/s390x"),
        &mut |_| {},
        &mut |_, _| {},
    )
    .expect_err("no such platform");
    assert!(
        format!("{e:#}").contains("linux/amd64, linux/arm64"),
        "{e:#}"
    );
}

/// Against the real Docker Hub (network): `cargo test --release -p layerless -- --ignored`.
#[test]
#[ignore = "needs network access to Docker Hub"]
fn docker_hub_alpine() {
    let dir = tempfile::tempdir().expect("tmp");
    let dest = dir.path().join("alpine");
    layerless::pull("alpine:3", &dest, None, &mut |_| {}, &mut |_, _| {}).expect("pull");
    assert!(dest.join("etc/alpine-release").exists());
}
