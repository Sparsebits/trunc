//! The DEFLATE decoder against flate2 (miniz_oxide), and resumed from a checkpoint.
//!
//! Header `[sel, level, flush, pick]`, then the payload. `sel` bit 0 set: deflate the payload
//! (bit 1: expanded first, with long matches at distances of 1-16) at `level` (0: stored
//! blocks), flushing as `flush` says (many short blocks); bit 2: then flip one bit. Bit 0 clear:
//! decode the payload as it is.
//! - whatever the decoder accepts, flate2 decodes to the same output;
//! - an undamaged stream decodes to the original, using exactly its bytes;
//! - resuming from the checkpoint `pick` selects gives the rest of the output.

#![no_main]
use flate2::{Decompress, FlushDecompress, Status};
use libfuzzer_sys::fuzz_target;
use trunc_legacy::inflate::{Checkpoint, Finished, InflateError, Inflater};

#[path = "common/units.rs"]
mod units;

const MAX_OUT: u64 = 4 << 20;

enum Reference {
    End(Vec<u8>),
    TooLong,
    Bad,
}

/// flate2's view: a complete raw DEFLATE stream at the start of `input`, or not.
fn reference(input: &[u8]) -> Reference {
    let mut d = Decompress::new(false);
    let mut out = Vec::new();
    loop {
        if out.len() == out.capacity() {
            if out.len() as u64 > MAX_OUT {
                return Reference::TooLong;
            }
            out.reserve(64 * 1024);
        }
        let (tin, tout) = (d.total_in(), d.total_out());
        let at = usize::try_from(tin).unwrap();
        match d.decompress_vec(&input[at..], &mut out, FlushDecompress::None) {
            Ok(Status::StreamEnd) => {
                return if out.len() as u64 > MAX_OUT {
                    Reference::TooLong
                } else {
                    Reference::End(out)
                };
            }
            Ok(_) if d.total_in() == tin && d.total_out() == tout && out.len() < out.capacity() => {
                return Reference::Bad;
            }
            Ok(_) => {}
            Err(_) => return Reference::Bad,
        }
    }
}

fn inflate(
    input: &[u8],
    from: &Checkpoint,
    every: u64,
) -> (Vec<u8>, Vec<Checkpoint>, Result<Finished, InflateError>) {
    let (_fs, h) = units::host(input);
    let mut out = Vec::new();
    let mut cks = Vec::new();
    let r = Inflater::new(from, MAX_OUT).run(
        h.as_ref(),
        0,
        input.len() as u64,
        &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        },
        every,
        &mut |ck| {
            assert!(Checkpoint::from_bytes(&ck.to_bytes()).as_ref() == Some(ck));
            cks.push(ck.clone());
            Ok(())
        },
    );
    (out, cks, r)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let (head, payload) = data.split_at(4);
    let [sel, level, flush, pick] = [head[0], head[1], head[2], head[3]];
    let structured = sel & 1 != 0;
    let mut damaged = false;
    let (original, input) = if structured {
        let original = if sel & 2 != 0 {
            units::expand(payload)
        } else {
            payload.to_vec()
        };
        let mut c = units::deflate(
            &original,
            u32::from(level % 10),
            units::flush_pattern(flush),
        );
        if sel & 4 != 0 && !c.is_empty() {
            let at = (usize::from(pick) * 7919 + payload.len()) % c.len();
            c[at] ^= 1 << (level % 8);
            damaged = true;
        }
        (Some(original), c)
    } else {
        (None, payload.to_vec())
    };
    let every = [0, 1, 1000, 32 << 10][usize::from(sel >> 6)];
    let (out, cks, r) = inflate(&input, &Checkpoint::start(), every);
    assert!(out.len() as u64 <= MAX_OUT);
    let reference = reference(&input);
    let fin = match r {
        Ok(fin) => {
            assert_eq!(fin.out_total, out.len() as u64);
            assert_eq!(fin.crc, units::crc32(&out), "CRC of the output is wrong");
            assert!(fin.in_bits.div_ceil(8) <= input.len() as u64);
            match &reference {
                Reference::End(r) => assert!(*r == out, "output differs from flate2"),
                Reference::TooLong => panic!("decoded {} bytes, flate2 more", out.len()),
                Reference::Bad => panic!("accepted a stream flate2 rejects"),
            }
            fin
        }
        Err(e) => {
            // (Expanded payloads stay far below MAX_OUT.)
            assert!(
                original.is_none() || damaged,
                "refused a stream flate2 wrote: {e}"
            );
            return;
        }
    };
    if let (Some(original), false) = (&original, damaged) {
        assert!(out == *original, "output differs from the original");
        assert_eq!(
            fin.in_bits.div_ceil(8),
            input.len() as u64,
            "the stream did not end where flate2 ended it"
        );
    }
    if cks.is_empty() {
        return;
    }
    let ck = &cks[usize::from(pick) % cks.len()];
    let at = usize::try_from(ck.out_total).unwrap();
    // The input before the checkpoint is no longer needed.
    let mut punched = input.clone();
    punched[..usize::try_from(ck.in_bit / 8).unwrap()].fill(0);
    let (rest, later, r) = inflate(&punched, ck, every);
    let end = r.unwrap_or_else(|e| panic!("resume at {at} failed: {e}"));
    assert!(rest == out[at..], "resume at {at} differs");
    assert_eq!(end, fin, "resume at {at} ends differently");
    let expect: Vec<_> = cks
        .iter()
        .filter(|c| c.out_total > ck.out_total)
        .cloned()
        .collect();
    assert!(later == expect, "resume at {at} meets other checkpoints");
});
