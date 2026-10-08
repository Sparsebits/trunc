//! gzip (RFC 1952) member framing. The compressed data inside a member is a raw DEFLATE stream,
//! decoded by [`crate::inflate`]. A `.tar.gz` may hold several members back to back (`pigz -i`,
//! `cat a.gz b.gz`); their outputs concatenate.

use trunc_fs::FileHandle;

pub const MAGIC: [u8; 2] = [0x1f, 0x8b];
const CM_DEFLATE: u8 = 8;
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;
const FLAGS_RESERVED: u8 = 0xE0;
/// Headers longer than this (huge names, comments or extra fields) are refused.
const MAX_HEADER: usize = 64 * 1024;
pub const TRAILER_LEN: u64 = 8;

#[derive(Debug, thiserror::Error)]
pub enum GzipError {
    #[error("not a gzip file")]
    NotGzip,
    #[error("corrupt gzip header at byte {0}: {1}")]
    Header(u64, &'static str),
    #[error(transparent)]
    Fs(#[from] trunc_fs::FsError),
}

/// Parse the member header at `at`; returns where its DEFLATE data starts.
pub fn read_header(src: &dyn FileHandle, at: u64, file_len: u64) -> Result<u64, GzipError> {
    let avail =
        usize::try_from(file_len.saturating_sub(at).min(MAX_HEADER as u64)).expect("<= 64 KiB");
    if avail < 10 {
        return Err(if at == 0 {
            GzipError::NotGzip
        } else {
            GzipError::Header(at, "truncated")
        });
    }
    let mut b = vec![0u8; avail];
    src.read_exact_at(&mut b, at)?;
    if b[..2] != MAGIC {
        return Err(if at == 0 {
            GzipError::NotGzip
        } else {
            GzipError::Header(at, "bad magic")
        });
    }
    let bad = |why| GzipError::Header(at, why);
    if b[2] != CM_DEFLATE {
        return Err(bad("compression method is not deflate"));
    }
    let flags = b[3];
    if flags & FLAGS_RESERVED != 0 {
        return Err(bad("reserved flag bits set"));
    }
    let mut p = 10usize;
    if flags & FEXTRA != 0 {
        let xlen = usize::from(u16::from_le_bytes(
            b.get(p..p + 2)
                .ok_or(bad("truncated"))?
                .try_into()
                .expect("2"),
        ));
        p += 2 + xlen;
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            let rest = b.get(p..).ok_or(bad("truncated"))?;
            let nul = rest
                .iter()
                .position(|&c| c == 0)
                .ok_or(bad("name or comment too long"))?;
            p += nul + 1;
        }
    }
    if flags & FHCRC != 0 {
        let stored = u16::from_le_bytes(
            b.get(p..p + 2)
                .ok_or(bad("truncated"))?
                .try_into()
                .expect("2"),
        );
        // The header CRC is the low 16 bits of the CRC-32 by definition.
        #[allow(clippy::cast_possible_truncation)]
        let actual = crc32fast::hash(&b[..p]) as u16;
        if stored != actual {
            return Err(bad("header checksum mismatch"));
        }
        p += 2;
    }
    if p > b.len() {
        return Err(bad("truncated"));
    }
    Ok(at + p as u64)
}

/// The member trailer at `at`: CRC-32 and size (mod 2^32) of the member's output.
pub fn read_trailer(src: &dyn FileHandle, at: u64) -> Result<(u32, u32), GzipError> {
    let mut b = [0u8; 8];
    src.read_exact_at(&mut b, at)?;
    Ok((
        u32::from_le_bytes(b[..4].try_into().expect("4")),
        u32::from_le_bytes(b[4..].try_into().expect("4")),
    ))
}

/// True if `[from, file_len)` is empty or all zeros (padding some tools add after the last member).
pub fn only_padding_after(
    src: &dyn FileHandle,
    from: u64,
    file_len: u64,
) -> Result<bool, GzipError> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut off = from;
    while off < file_len {
        let n = usize::try_from((file_len - off).min(buf.len() as u64)).expect("<= 64 KiB");
        src.read_exact_at(&mut buf[..n], off)?;
        if buf[..n].iter().any(|&c| c != 0) {
            return Ok(false);
        }
        off += n as u64;
    }
    Ok(true)
}
