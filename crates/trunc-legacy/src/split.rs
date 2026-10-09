//! Names of split archives: `name.001`, `name.002`, … (7-Zip, HJSplit, `split -d`) and
//! `name.aa`, `name.ab`, … (`split`). The parts are plain slices of one file.

/// How the parts of a set are numbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Numbering {
    /// Decimal, zero-padded to `width`, starting at `start` (0 or 1).
    Digits { width: usize, start: u64 },
    /// Lowercase letters, `width` of them, starting at `aa…`.
    Letters { width: usize },
}

/// A file name that may be one part of a split set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartName {
    /// Everything before the part number, including the dot (`backup.tar.gz.`).
    pub stem: String,
    pub numbering: Numbering,
    /// Position of this part in the set (0 for the first).
    pub index: u64,
}

impl PartName {
    /// Parse `name`; `None` if it does not end in a part number.
    pub fn parse(name: &str) -> Option<Self> {
        let dot = name.rfind('.')?;
        let (stem, suffix) = (&name[..=dot], &name[dot + 1..]);
        if stem.len() < 2 || suffix.len() < 2 || suffix.len() > 6 {
            return None;
        }
        if suffix.bytes().all(|c| c.is_ascii_digit()) {
            let v: u64 = suffix.parse().ok()?;
            // A set starts at 000 or 001; which one is decided by whether a 000 part exists, so
            // here the index is relative to 1 and the caller adjusts.
            return Some(Self {
                stem: stem.to_owned(),
                numbering: Numbering::Digits {
                    width: suffix.len(),
                    start: 1,
                },
                index: v.checked_sub(1).unwrap_or(u64::MAX),
            });
        }
        if suffix.bytes().all(|c| c.is_ascii_lowercase()) && suffix.len() <= 3 {
            let index = suffix
                .bytes()
                .fold(0u64, |acc, c| acc * 26 + u64::from(c - b'a'));
            return Some(Self {
                stem: stem.to_owned(),
                numbering: Numbering::Letters {
                    width: suffix.len(),
                },
                index,
            });
        }
        None
    }

    /// The same name numbered from zero (`.000`), for sets that start there.
    pub fn from_zero(&self) -> Self {
        match self.numbering {
            Numbering::Digits { width, .. } => Self {
                stem: self.stem.clone(),
                numbering: Numbering::Digits { width, start: 0 },
                index: self.index.wrapping_add(1),
            },
            Numbering::Letters { .. } => self.clone(),
        }
    }

    /// The file name of part `index` of this set, or `None` past the last representable one.
    pub fn name_of(&self, index: u64) -> Option<String> {
        match self.numbering {
            Numbering::Digits { width, start } => {
                let n = index.checked_add(start)?;
                Some(format!("{}{n:0width$}", self.stem))
            }
            Numbering::Letters { width } => {
                let w = u32::try_from(width).ok()?;
                if index >= 26u64.pow(w) {
                    return None;
                }
                let mut s = vec![b'a'; width];
                let mut v = index;
                for c in s.iter_mut().rev() {
                    *c = b'a' + u8::try_from(v % 26).expect("< 26");
                    v /= 26;
                }
                Some(format!(
                    "{}{}",
                    self.stem,
                    String::from_utf8(s).expect("ascii")
                ))
            }
        }
    }

    /// The name the joined file would have (the stem without its final dot).
    pub fn joined(&self) -> &str {
        &self.stem[..self.stem.len() - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_names_parts() {
        let p = PartName::parse("big.tar.gz.001").unwrap();
        assert_eq!((p.stem.as_str(), p.index), ("big.tar.gz.", 0));
        assert_eq!(p.name_of(1).unwrap(), "big.tar.gz.002");
        assert_eq!(p.name_of(999).unwrap(), "big.tar.gz.1000");
        assert_eq!(p.joined(), "big.tar.gz");
        let z = PartName::parse("x.zip.000").unwrap().from_zero();
        assert_eq!((z.index, z.name_of(0).unwrap()), (0, "x.zip.000".into()));
        let d = PartName::parse("img.00").unwrap().from_zero();
        assert_eq!(d.name_of(10).unwrap(), "img.10");

        let a = PartName::parse("disk.img.ab").unwrap();
        assert_eq!(a.index, 1);
        assert_eq!(a.name_of(0).unwrap(), "disk.img.aa");
        assert_eq!(a.name_of(26).unwrap(), "disk.img.ba");
        assert_eq!(a.name_of(26 * 26), None);

        // Ordinary extensions also parse as letters; a set is only recognised when its first
        // and second parts exist, which the caller checks.
        for not in ["file", "file.7", "x.ABC", ".001", "a.tar.gz7"] {
            assert!(PartName::parse(not).is_none(), "{not}");
        }
    }
}
