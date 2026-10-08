//! Block codecs.
//!
//! Every block is compressed independently: one complete zstd frame or lz4 block per trunc
//! block, so decoding a block never needs state from any other block (ADR-0001). An optional
//! zstd dictionary, stored once in the archive header region, recovers most of the ratio lost
//! by not sharing history between blocks.

pub use trunc_core::CodecId;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("compression failed: {0}")]
    Compress(String),
    #[error("decompression failed: {0}")]
    Decompress(String),
    #[error("decoded length {got} does not match expected {expected}")]
    LengthMismatch { expected: usize, got: usize },
    #[error("dictionary training failed: {0}")]
    Dict(String),
}

/// Raw zstd dictionary bytes.
#[derive(Debug, Clone)]
pub struct Dict(pub Vec<u8>);

/// Compression settings chosen by the producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecChoice {
    Store,
    Lz4,
    Zstd { level: i32 },
}

impl CodecChoice {
    pub fn id(self) -> CodecId {
        match self {
            CodecChoice::Store => CodecId::Store,
            CodecChoice::Lz4 => CodecId::Lz4,
            CodecChoice::Zstd { .. } => CodecId::Zstd,
        }
    }

    /// Parse `store`, `lz4`, `zstd` or `zstd:<level>`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "store" => Some(CodecChoice::Store),
            "lz4" => Some(CodecChoice::Lz4),
            "zstd" => Some(CodecChoice::Zstd { level: 9 }),
            _ => {
                let level = s.strip_prefix("zstd:")?.parse::<i32>().ok()?;
                (-7..=22)
                    .contains(&level)
                    .then_some(CodecChoice::Zstd { level })
            }
        }
    }
}

/// Compress one block. Returns the codec actually used: if compression does not shrink the
/// data, the block is stored instead so `c_len <= u_len` always holds for compressed blocks.
pub fn compress(
    choice: CodecChoice,
    raw: &[u8],
    dict: Option<&Dict>,
) -> Result<(CodecId, Vec<u8>), CodecError> {
    let out = match choice {
        CodecChoice::Store => None,
        CodecChoice::Lz4 => Some(lz4_flex::block::compress(raw)),
        CodecChoice::Zstd { level } => {
            let mut c = match dict {
                Some(d) => zstd::bulk::Compressor::with_dictionary(level, &d.0),
                None => zstd::bulk::Compressor::new(level),
            }
            .map_err(|e| CodecError::Compress(e.to_string()))?;
            Some(
                c.compress(raw)
                    .map_err(|e| CodecError::Compress(e.to_string()))?,
            )
        }
    };
    Ok(match out {
        Some(c) if c.len() < raw.len() => (choice.id(), c),
        _ => (CodecId::Store, raw.to_vec()),
    })
}

/// Decompress one block into `out`, which must be exactly the block's decoded length.
pub fn decompress(
    codec: CodecId,
    comp: &[u8],
    out: &mut [u8],
    dict: Option<&Dict>,
) -> Result<(), CodecError> {
    let got = match codec {
        CodecId::Store => {
            if comp.len() != out.len() {
                return Err(CodecError::LengthMismatch {
                    expected: out.len(),
                    got: comp.len(),
                });
            }
            out.copy_from_slice(comp);
            comp.len()
        }
        CodecId::Lz4 => lz4_flex::block::decompress_into(comp, out)
            .map_err(|e| CodecError::Decompress(e.to_string()))?,
        CodecId::Zstd => {
            let mut d = match dict {
                Some(dict) => zstd::bulk::Decompressor::with_dictionary(&dict.0),
                None => zstd::bulk::Decompressor::new(),
            }
            .map_err(|e| CodecError::Decompress(e.to_string()))?;
            d.decompress_to_buffer(comp, out)
                .map_err(|e| CodecError::Decompress(e.to_string()))?
        }
    };
    if got != out.len() {
        return Err(CodecError::LengthMismatch {
            expected: out.len(),
            got,
        });
    }
    Ok(())
}

/// Train a zstd dictionary from sample buffers.
pub fn train_dict(samples: &[Vec<u8>], max_size: usize) -> Result<Dict, CodecError> {
    zstd::dict::from_samples(samples, max_size)
        .map(Dict)
        .map_err(|e| CodecError::Dict(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn text(n: usize) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .copied()
            .cycle()
            .take(n)
            .collect()
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn round_trip(choice: CodecChoice, data: &[u8], dict: Option<&Dict>) -> CodecId {
        let (id, comp) = compress(choice, data, dict).unwrap();
        let mut out = vec![0u8; data.len()];
        decompress(id, &comp, &mut out, dict).unwrap();
        assert_eq!(out, data);
        assert!(comp.len() <= data.len());
        id
    }

    #[test]
    fn compressible_data_uses_requested_codec() {
        let d = text(1 << 20);
        assert_eq!(round_trip(CodecChoice::Lz4, &d, None), CodecId::Lz4);
        assert_eq!(
            round_trip(CodecChoice::Zstd { level: 3 }, &d, None),
            CodecId::Zstd
        );
        assert_eq!(round_trip(CodecChoice::Store, &d, None), CodecId::Store);
        assert_eq!(
            round_trip(CodecChoice::Zstd { level: 3 }, &vec![0u8; 1 << 20], None),
            CodecId::Zstd
        );
    }

    #[test]
    fn incompressible_data_falls_back_to_store() {
        let d = noise(1 << 16);
        assert_eq!(
            round_trip(CodecChoice::Zstd { level: 19 }, &d, None),
            CodecId::Store
        );
        assert_eq!(round_trip(CodecChoice::Lz4, &d, None), CodecId::Store);
    }

    #[test]
    fn dictionary_round_trip() {
        let samples: Vec<Vec<u8>> = (0..200)
            .map(|i| {
                format!(
                    "{{\"id\":{i},\"name\":\"user{i}\",\"active\":true,\"tags\":[\"a\",\"b\"]}}"
                )
                .into_bytes()
            })
            .collect();
        let dict = train_dict(&samples, 4096).unwrap();
        let data = samples[7].clone();
        let (id, comp) = compress(CodecChoice::Zstd { level: 9 }, &data, Some(&dict)).unwrap();
        if id == CodecId::Zstd {
            let mut out = vec![0u8; data.len()];
            decompress(id, &comp, &mut out, Some(&dict)).unwrap();
            assert_eq!(out, data);
            // Without the dictionary the frame must not decode.
            assert!(decompress(id, &comp, &mut out, None).is_err());
        }
    }

    #[test]
    fn wrong_length_is_an_error() {
        let d = text(4096);
        let (id, comp) = compress(CodecChoice::Zstd { level: 3 }, &d, None).unwrap();
        let mut short = vec![0u8; d.len() - 1];
        assert!(decompress(id, &comp, &mut short, None).is_err());
        let mut long = vec![0u8; d.len() + 1];
        assert!(decompress(id, &comp, &mut long, None).is_err());
    }

    #[test]
    fn corrupt_input_is_an_error_not_a_panic() {
        let d = text(8192);
        for choice in [CodecChoice::Lz4, CodecChoice::Zstd { level: 3 }] {
            let (id, mut comp) = compress(choice, &d, None).unwrap();
            let mid = comp.len() / 2;
            comp[mid] ^= 0xFF;
            comp.truncate(comp.len() - 3);
            let mut out = vec![0u8; d.len()];
            let _ = decompress(id, &comp, &mut out, None);
        }
    }

    #[test]
    fn parse_choices() {
        assert_eq!(
            CodecChoice::parse("zstd:19"),
            Some(CodecChoice::Zstd { level: 19 })
        );
        assert_eq!(
            CodecChoice::parse("zstd"),
            Some(CodecChoice::Zstd { level: 9 })
        );
        assert_eq!(CodecChoice::parse("lz4"), Some(CodecChoice::Lz4));
        assert_eq!(CodecChoice::parse("zstd:99"), None);
        assert_eq!(CodecChoice::parse("gzip"), None);
    }

    proptest! {
        #[test]
        fn arbitrary_round_trip(data in proptest::collection::vec(any::<u8>(), 1..4096), which in 0u8..3) {
            let choice = match which { 0 => CodecChoice::Store, 1 => CodecChoice::Lz4, _ => CodecChoice::Zstd { level: 1 } };
            round_trip(choice, &data, None);
        }
    }
}
