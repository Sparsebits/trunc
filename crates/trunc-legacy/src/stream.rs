//! One interface over the resumable stream decoders (gzip, bzip2, xz, zstd).
//!
//! Each decoder runs from the start of a file, or from a cursor it produced earlier, to the end
//! of the input. Output goes to a sink in order. At a *safe point* (the first codec boundary
//! after `every` bytes of output since the previous one) the decoder hands out a cursor to resume
//! from and the offset below which the input is no longer needed. Safe points depend only on the
//! input and `every`, so a second pass and a resumed pass meet the same ones as the first.
//!
//! Decoders with a large window (xz, zstd) do not put the window in the cursor. On resume they
//! read it back through [`History`] from the output already written, and check it against a
//! CRC-32 stored in the cursor.

use trunc_fs::{FileHandle, FsError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl Codec {
    pub const ALL: [Codec; 4] = [Codec::Gzip, Codec::Bzip2, Codec::Xz, Codec::Zstd];

    pub fn id(self) -> u8 {
        match self {
            Codec::Gzip => 1,
            Codec::Bzip2 => 2,
            Codec::Xz => 3,
            Codec::Zstd => 4,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.id() == id)
    }

    pub fn name(self) -> &'static str {
        match self {
            Codec::Gzip => "gzip",
            Codec::Bzip2 => "bzip2",
            Codec::Xz => "xz",
            Codec::Zstd => "zstd",
        }
    }

    /// What the decoder counts as one unit of the stream (shown by `inspect`).
    pub fn unit(self) -> &'static str {
        match self {
            Codec::Gzip => "gzip members",
            Codec::Bzip2 => "bzip2 streams",
            Codec::Xz => "xz streams",
            Codec::Zstd => "zstd frames",
        }
    }

    /// The largest cursor this codec's decoder hands out, in bytes.
    pub fn max_cursor(self) -> usize {
        match self {
            // Member offsets and an inflate checkpoint with its 32 KiB window.
            Codec::Gzip => 16 + 24 + 32 * 1024,
            Codec::Bzip2 => 21,
            // LZMA probabilities (lc + lp <= 4) dominate.
            Codec::Xz => 32 * 1024,
            Codec::Zstd => 4 * 1024,
        }
    }

    /// Whether resuming needs earlier output back (see [`History`]).
    pub fn needs_history(self) -> bool {
        matches!(self, Codec::Xz | Codec::Zstd)
    }

    /// The codec a file starting with `head` uses, if any.
    pub fn sniff(head: &[u8]) -> Option<Self> {
        match head {
            [0x1f, 0x8b, 8, ..] => Some(Codec::Gzip),
            [
                b'B',
                b'Z',
                b'h',
                b'1'..=b'9',
                0x31,
                0x41,
                0x59,
                0x26,
                0x53,
                0x59,
                ..,
            ]
            | [
                b'B',
                b'Z',
                b'h',
                b'1'..=b'9',
                0x17,
                0x72,
                0x45,
                0x38,
                0x50,
                0x90,
                ..,
            ] => Some(Codec::Bzip2),
            [0xFD, b'7', b'z', b'X', b'Z', 0, ..] => Some(Codec::Xz),
            [0x28, 0xB5, 0x2F, 0xFD, ..] => Some(Codec::Zstd),
            [m, 0x2A, 0x4D, 0x18, ..] if m & 0xF0 == 0x50 => Some(Codec::Zstd),
            _ => None,
        }
    }

    /// File-name suffixes this codec's files use, longest first, with what they stand for
    /// once decompressed (`""` for nothing, `".tar"` for the tarball shorthands).
    pub fn suffixes(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Codec::Gzip => &[(".tgz", ".tar"), (".taz", ".tar"), (".gz", ""), (".z", "")],
            Codec::Bzip2 => &[
                (".tbz2", ".tar"),
                (".tbz", ".tar"),
                (".tb2", ".tar"),
                (".bz2", ""),
            ],
            Codec::Xz => &[(".txz", ".tar"), (".xz", "")],
            Codec::Zstd => &[(".tzst", ".tar"), (".zstd", ""), (".zst", "")],
        }
    }

    /// The name a single decompressed file gets: the archive name with the codec's suffix
    /// removed (case-insensitively), or with `.out` appended when it has none.
    pub fn output_name(self, archive_name: &str) -> String {
        let lower = archive_name.to_ascii_lowercase();
        for (suffix, becomes) in self.suffixes() {
            if lower.len() > suffix.len() && lower.ends_with(suffix) {
                let stem = &archive_name[..archive_name.len() - suffix.len()];
                return format!("{stem}{becomes}");
            }
        }
        format!("{archive_name}.out")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Not this format, or a header that cannot be parsed.
    #[error("{0}")]
    Format(String),
    /// Damaged data: a check failed or the stream is inconsistent.
    #[error("{0}")]
    Corrupt(String),
    /// Valid, but uses something this decoder does not implement.
    #[error("{0}")]
    Unsupported(String),
    #[error(transparent)]
    Fs(#[from] FsError),
    /// A sink or safe-point callback asked to stop; the caller holds the reason.
    #[error("stopped by the caller")]
    Stopped,
}

pub type Result<T> = std::result::Result<T, StreamError>;

/// A place decoding can resume from.
#[derive(Debug, Clone, Copy)]
pub struct SafePoint<'a> {
    /// Codec-specific state; pass it back as `start` to resume.
    pub cursor: &'a [u8],
    /// Output produced before this point.
    pub out: u64,
    /// Input bytes before this offset are no longer needed.
    pub free_below: u64,
}

/// Output written earlier, read back when a decoder resumes and needs its window.
pub trait History {
    /// Fill `buf` with output bytes `[at, at + buf.len())`.
    fn read(&mut self, at: u64, buf: &mut [u8]) -> Result<()>;
}

/// A [`History`] for runs that never resume (scans, plain extraction).
#[derive(Debug, Default)]
pub struct NoHistory;

impl History for NoHistory {
    fn read(&mut self, _at: u64, _buf: &mut [u8]) -> Result<()> {
        Err(StreamError::Corrupt(
            "resuming needs earlier output, which is not available".into(),
        ))
    }
}

/// Bounds a decoder enforces.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Total output allowed (absolute, from the start of the stream).
    pub max_out: u64,
    /// Largest decoder window (and so memory) allowed.
    pub max_window: u64,
}

impl Limits {
    pub const DEFAULT_MAX_WINDOW: u64 = 256 << 20;

    pub fn new(max_out: u64) -> Self {
        Self {
            max_out,
            max_window: Self::DEFAULT_MAX_WINDOW,
        }
    }
}

/// How a complete decode ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEnd {
    /// Total output (from the start of the stream, also when resumed).
    pub out_len: u64,
    /// Units decoded in this run (members, streams or frames).
    pub units: u32,
}

/// The input: `[0, len)` of `src`.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    pub src: &'a dyn FileHandle,
    pub len: u64,
}

pub type Sink<'a> = dyn FnMut(&[u8]) -> Result<()> + 'a;
pub type OnPoint<'a> = dyn FnMut(SafePoint<'_>) -> Result<()> + 'a;

/// Decode `input` with `codec`, from the start or from `start` (a cursor from a safe point).
#[allow(clippy::too_many_arguments)]
pub fn decode(
    codec: Codec,
    input: Input<'_>,
    start: Option<&[u8]>,
    history: &mut dyn History,
    limits: Limits,
    every: u64,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> Result<StreamEnd> {
    match codec {
        Codec::Gzip => crate::gzip::decode(input, start, limits, every, sink, on_point),
        Codec::Bzip2 => crate::bzip2::decode(input, start, limits, every, sink, on_point),
        Codec::Xz => crate::xz::decode(input, start, history, limits, every, sink, on_point),
        Codec::Zstd => crate::zstd::decode(input, start, history, limits, every, sink, on_point),
    }
}

/// The first `n` bytes of output (fewer if the stream is shorter), decoding as little as
/// possible. Used to tell a tarball from a single compressed file.
pub fn peek(codec: Codec, input: Input<'_>, n: usize) -> Result<Vec<u8>> {
    let mut first = Vec::with_capacity(n);
    let r = decode(
        codec,
        input,
        None,
        &mut NoHistory,
        Limits::new(u64::MAX),
        0,
        &mut |b| {
            let take = (n - first.len()).min(b.len());
            first.extend_from_slice(&b[..take]);
            if first.len() == n {
                Err(StreamError::Stopped)
            } else {
                Ok(())
            }
        },
        &mut |_| Ok(()),
    );
    match r {
        Ok(_) | Err(StreamError::Stopped) => Ok(first),
        Err(e) => Err(e),
    }
}

/// CRC-32 of a window, stored in cursors to check the window read back on resume.
pub fn window_crc(window: &[u8]) -> u32 {
    crc32fast::hash(window)
}

/// Read a window of `len` bytes ending at output offset `end` through `history`, and check it.
pub fn restore_window(history: &mut dyn History, end: u64, len: u64, crc: u32) -> Result<Vec<u8>> {
    let n = usize::try_from(len)
        .map_err(|_| StreamError::Corrupt("window larger than memory".into()))?;
    let mut w = vec![0u8; n];
    history.read(end - len, &mut w)?;
    if window_crc(&w) != crc {
        return Err(StreamError::Corrupt(
            "the output read back to resume decoding differs from what was written".into(),
        ));
    }
    Ok(w)
}

/// Little-endian field reader for cursors.
pub(crate) struct Fields<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Fields<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(2)?.try_into().ok()?))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(4)?.try_into().ok()?))
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(8)?.try_into().ok()?))
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.p..];
        self.p = self.b.len();
        s
    }

    pub(crate) fn done(&self) -> bool {
        self.p == self.b.len()
    }
}

pub(crate) fn bad_cursor() -> StreamError {
    StreamError::Corrupt("journaled decoder state is unreadable".into())
}
