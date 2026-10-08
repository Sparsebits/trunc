//! Positional file I/O that works with a shared `&File` on Windows and Unix.

use std::fs::File;
use std::io;

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(f, buf, off)
}

#[cfg(windows)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(f, buf, off)
}

#[cfg(unix)]
fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::write_at(f, buf, off)
}

#[cfg(windows)]
fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_write(f, buf, off)
}

pub(crate) fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match read_at(f, buf, off) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub(crate) fn write_all_at(f: &File, mut buf: &[u8], mut off: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match write_at(f, buf, off) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                buf = &buf[n..];
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Convert a length that has been validated against `MAX_BLOCK_U` (or similar) to `usize`.
pub(crate) fn len_usize(x: u64) -> usize {
    usize::try_from(x).expect("validated length fits in usize")
}
