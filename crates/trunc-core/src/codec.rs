use crate::FormatError;

/// Codec identifier stored in footers and block records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CodecId {
    Store = 0,
    Lz4 = 1,
    Zstd = 2,
}

impl CodecId {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn name(self) -> &'static str {
        match self {
            CodecId::Store => "store",
            CodecId::Lz4 => "lz4",
            CodecId::Zstd => "zstd",
        }
    }
}

impl TryFrom<u16> for CodecId {
    type Error = FormatError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(CodecId::Store),
            1 => Ok(CodecId::Lz4),
            2 => Ok(CodecId::Zstd),
            other => Err(FormatError::UnknownCodec(other)),
        }
    }
}
