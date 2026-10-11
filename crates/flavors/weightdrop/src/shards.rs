//! Shard-set detection from file names alone (no file is opened here).
//!
//! Recognised shapes, each with any of the archive suffixes in [`ARCHIVE_SUFFIXES`]:
//!
//! * WebDataset: `name-000000.tar.zst`, `name_0001.tar.gz`, `000017.tar`
//! * "of" sets: `train-00000-of-00042.tar`, `shard-00001-of-00010.tar.gz`
//! * split parts of one archive: `name.tar.zst.001`, `name.tar.zst.aa` (trunc reads the parts
//!   as one file; they form a single shard here)
//!
//! An archive without a number is a set of its own. Shards of one set may use different codecs.
//! Numbering must be complete: a gap, a duplicate number or an index past the `-of-N` total is
//! refused, since unpacking an incomplete dataset is almost always a mistake.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Archive suffixes, longest first so `.tar.gz` wins over `.gz`-less `.tar`.
pub const ARCHIVE_SUFFIXES: &[&str] = &[
    ".tar.zstd",
    ".tar.zst",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tzst",
    ".tbz2",
    ".tbz",
    ".tgz",
    ".txz",
    ".tar",
];

/// One shard: an archive, or the first part of a split archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// The file name passed to trunc (the first part for a split archive).
    pub name: String,
    /// The archive suffix, lower-case (`.tar.zst`, `.tgz`, ...).
    pub suffix: String,
    /// Shard number, `None` for an archive without one.
    pub index: Option<u64>,
    /// Folder name used when shards get their own folder: the name without suffixes.
    pub stem: String,
    /// All part names of a split archive, in order (empty for a single file).
    pub parts: Vec<String>,
}

impl Shard {
    /// Uncompressed tar, which trunc does not consume yet.
    pub fn is_plain_tar(&self) -> bool {
        self.suffix == ".tar"
    }
}

/// Shards sharing a name prefix (and `-of-N` total), in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardSet {
    /// Prefix before the number (`train` for `train-00000-of-00042.tar`), or the whole stem
    /// for an unnumbered archive.
    pub prefix: String,
    pub total: Option<u64>,
    pub shards: Vec<Shard>,
}

/// The parsed shape of one archive name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    prefix: String,
    index: Option<u64>,
    total: Option<u64>,
    suffix: String,
    stem: String,
}

/// Split the archive suffix off `name`: `(stem, suffix)` with the suffix lower-cased.
pub fn split_suffix(name: &str) -> Option<(&str, String)> {
    let lower = name.to_ascii_lowercase();
    ARCHIVE_SUFFIXES.iter().find_map(|s| {
        (lower.len() > s.len() && lower.ends_with(s))
            .then(|| (&name[..name.len() - s.len()], (*s).to_owned()))
    })
}

/// `name.001` / `name.aa`: the joined name and the part's sort key, if `name` looks like a part
/// of a split archive whose joined name is an archive.
fn split_part(name: &str) -> Option<(&str, &str)> {
    let (base, ext) = name.rsplit_once('.')?;
    let numeric = ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit());
    let letters = ext.len() == 2 && ext.bytes().all(|b| b.is_ascii_lowercase());
    ((numeric || letters) && split_suffix(base).is_some()).then_some((base, ext))
}

/// Trailing ASCII digits of `s`: `(rest, digits)`.
fn trailing_digits(s: &str) -> Option<(&str, &str)> {
    let start = s
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_digit())
        .last()
        .map(|(i, _)| i)?;
    Some((&s[..start], &s[start..]))
}

fn strip_sep(s: &str) -> &str {
    s.strip_suffix(['-', '_', '.']).unwrap_or(s)
}

fn parse(name: &str) -> Option<Parsed> {
    let (stem, suffix) = split_suffix(name)?;
    let mut p = Parsed {
        prefix: stem.to_owned(),
        index: None,
        total: None,
        suffix,
        stem: stem.to_owned(),
    };
    let of_total = trailing_digits(stem).and_then(|(rest, total)| {
        let rest = rest.strip_suffix("-of-").or(rest.strip_suffix("_of_"))?;
        trailing_digits(rest).map(|(prefix, index)| (prefix, index, total))
    });
    if let Some((prefix, index, total)) = of_total {
        p.prefix = strip_sep(prefix).to_owned();
        p.index = index.parse().ok();
        p.total = total.parse().ok();
        return p.index.is_some().then_some(p);
    }
    if let Some((prefix, index)) = trailing_digits(stem) {
        p.prefix = strip_sep(prefix).to_owned();
        p.index = index.parse().ok();
    }
    Some(p)
}

/// Names that are not archives (and not parts of one) are returned separately so the caller
/// can mention them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Detected {
    pub sets: Vec<ShardSet>,
    pub ignored: Vec<String>,
}

impl Detected {
    pub fn shard_count(&self) -> usize {
        self.sets.iter().map(|s| s.shards.len()).sum()
    }
}

/// Group file names into shard sets and check their numbering.
pub fn detect(names: &[String]) -> Result<Detected, String> {
    let mut out = Detected::default();
    // Split parts grouped by their joined name.
    let mut parts: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut singles: Vec<String> = Vec::new();
    for name in names {
        // An archive suffix wins: `a.tar.gz` is not part `gz` of `a.tar`.
        if split_suffix(name).is_some() {
            singles.push(name.clone());
        } else if let Some((joined, key)) = split_part(name) {
            parts
                .entry(joined.to_owned())
                .or_default()
                .push((key.to_owned(), name.clone()));
        } else {
            out.ignored.push(name.clone());
        }
    }
    let mut candidates: Vec<(Parsed, Shard)> = Vec::new();
    for name in singles {
        if parts.contains_key(&name) {
            return Err(format!(
                "{name} exists both whole and as split parts ({name}.001 ...); remove one"
            ));
        }
        let p = parse(&name).ok_or_else(|| format!("cannot parse {name}"))?;
        let shard = Shard {
            name,
            suffix: p.suffix.clone(),
            index: p.index,
            stem: p.stem.clone(),
            parts: Vec::new(),
        };
        candidates.push((p, shard));
    }
    for (joined, mut ps) in parts {
        ps.sort();
        let p = parse(&joined).ok_or_else(|| format!("cannot parse {joined}"))?;
        let shard = Shard {
            name: ps[0].1.clone(),
            suffix: p.suffix.clone(),
            index: p.index,
            stem: p.stem.clone(),
            parts: ps.into_iter().map(|(_, n)| n).collect(),
        };
        candidates.push((p, shard));
    }

    // Group: numbered shards by (prefix, total); unnumbered archives stand alone.
    let mut groups: BTreeMap<(String, Option<u64>, bool, String), Vec<Shard>> = BTreeMap::new();
    for (p, shard) in candidates {
        let key = match p.index {
            Some(_) => (p.prefix.clone(), p.total, true, String::new()),
            None => (p.prefix.clone(), None, false, shard.name.clone()),
        };
        groups.entry(key).or_default().push(shard);
    }
    for ((prefix, total, numbered, _), mut shards) in groups {
        if numbered {
            shards.sort_by_key(|s| s.index);
            check_numbering(&prefix, total, &shards)?;
        }
        out.sets.push(ShardSet {
            prefix,
            total,
            shards,
        });
    }
    // A lone number-only archive like `report-2024.tar.gz` forms a one-shard set, which is
    // fine. Two sets that differ only by `-of-N` totals are suspicious enough to refuse.
    for w in out.sets.windows(2) {
        if w[0].prefix == w[1].prefix && w[0].total.is_some() && w[0].total != w[1].total {
            return Err(format!(
                "shards named {}-*-of-{} and {}-*-of-{} are mixed; unpack one set at a time",
                w[0].prefix,
                w[0].total.unwrap_or(0),
                w[1].prefix,
                w[1].total.unwrap_or(0)
            ));
        }
    }
    Ok(out)
}

fn check_numbering(prefix: &str, total: Option<u64>, shards: &[Shard]) -> Result<(), String> {
    for w in shards.windows(2) {
        if w[0].index == w[1].index {
            return Err(format!(
                "shard {} of set {prefix:?} appears twice: {} and {}",
                w[0].index.unwrap_or(0),
                w[0].name,
                w[1].name
            ));
        }
    }
    let idx: Vec<u64> = shards.iter().filter_map(|s| s.index).collect();
    let (Some(&first), Some(&last)) = (idx.first(), idx.last()) else {
        return Ok(());
    };
    let (lo, hi) = match total {
        Some(0) => return Err(format!("set {prefix:?} says it has 0 shards (-of-0)")),
        // `-00000-of-00042` counts from 0, `-00001-of-00010` from 1.
        Some(t) if first == 0 => (0, t - 1),
        Some(t) => (1, t),
        None => (first, last),
    };
    if let Some(t) = total.filter(|_| last > hi) {
        return Err(format!(
            "set {prefix:?}: shard {last} is past the total of {t}"
        ));
    }
    let have: std::collections::BTreeSet<u64> = idx.iter().copied().collect();
    let missing: Vec<u64> = (lo..=hi).filter(|i| !have.contains(i)).collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut list = String::new();
    for (k, m) in missing.iter().take(10).enumerate() {
        if k > 0 {
            list.push_str(", ");
        }
        let _ = write!(list, "{m}");
    }
    if missing.len() > 10 {
        let _ = write!(list, " and {} more", missing.len() - 10);
    }
    Err(format!(
        "set {prefix:?} is incomplete: {} of {} shards missing (numbers {list}); \
         finish the download, or pass only the shards you want",
        missing.len(),
        hi - lo + 1
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn order(d: &Detected) -> Vec<Vec<&str>> {
        d.sets
            .iter()
            .map(|s| s.shards.iter().map(|x| x.name.as_str()).collect())
            .collect()
    }

    #[test]
    fn webdataset_shards_are_ordered() {
        let d = detect(&names(&[
            "train-000002.tar.zst",
            "train-000000.tar.zst",
            "train-000001.tar.zst",
        ]))
        .unwrap();
        assert_eq!(
            order(&d),
            vec![vec![
                "train-000000.tar.zst",
                "train-000001.tar.zst",
                "train-000002.tar.zst"
            ]]
        );
        assert_eq!(d.sets[0].prefix, "train");
        assert_eq!(d.sets[0].shards[1].stem, "train-000001");
    }

    #[test]
    fn numeric_order_not_lexical() {
        let d = detect(&names(&["s-10.tar.gz", "s-9.tar.gz", "s-8.tar.gz"])).unwrap();
        assert_eq!(
            order(&d),
            vec![vec!["s-8.tar.gz", "s-9.tar.gz", "s-10.tar.gz"]]
        );
    }

    #[test]
    fn underscore_and_bare_numbers() {
        let d = detect(&names(&["shard_0001.tgz", "shard_0000.tgz"])).unwrap();
        assert_eq!(d.sets[0].prefix, "shard");
        assert_eq!(d.sets[0].shards[0].name, "shard_0000.tgz");
        let d = detect(&names(&["000001.tar", "000000.tar"])).unwrap();
        assert_eq!(d.sets[0].prefix, "");
        assert_eq!(d.sets[0].shards.len(), 2);
    }

    #[test]
    fn of_total_sets_from_zero_and_one() {
        let d = detect(&names(&[
            "train-00001-of-00003.tar",
            "train-00000-of-00003.tar",
            "train-00002-of-00003.tar",
        ]))
        .unwrap();
        assert_eq!(d.sets[0].total, Some(3));
        assert_eq!(d.sets[0].shards[0].index, Some(0));
        let d = detect(&names(&[
            "model-00002-of-00002.tar.zst",
            "model-00001-of-00002.tar.zst",
        ]))
        .unwrap();
        assert_eq!(d.sets[0].prefix, "model");
        assert_eq!(d.sets[0].shards[0].name, "model-00001-of-00002.tar.zst");
    }

    #[test]
    fn of_total_missing_last_shard_is_refused() {
        let e = detect(&names(&[
            "train-00000-of-00003.tar.gz",
            "train-00001-of-00003.tar.gz",
        ]))
        .unwrap_err();
        assert!(e.contains("incomplete") && e.contains("numbers 2"), "{e}");
    }

    #[test]
    fn index_past_total_is_refused() {
        let e = detect(&names(&[
            "x-00001-of-00002.tar.gz",
            "x-00002-of-00002.tar.gz",
            "x-00003-of-00002.tar.gz",
        ]))
        .unwrap_err();
        assert!(e.contains("past the total"), "{e}");
    }

    #[test]
    fn gaps_are_refused_with_the_missing_numbers() {
        let e = detect(&names(&[
            "data-000000.tar.zst",
            "data-000001.tar.zst",
            "data-000004.tar.zst",
        ]))
        .unwrap_err();
        assert!(e.contains("2 of 5 shards missing"), "{e}");
        assert!(e.contains("numbers 2, 3"), "{e}");
    }

    #[test]
    fn long_gap_lists_are_shortened() {
        let e = detect(&names(&["d-0.tar.gz", "d-100.tar.gz"])).unwrap_err();
        assert!(e.contains("and 89 more"), "{e}");
    }

    #[test]
    fn duplicates_across_codecs_are_refused() {
        let e = detect(&names(&["d-000000.tar.gz", "d-000000.tar.zst"])).unwrap_err();
        assert!(e.contains("appears twice"), "{e}");
    }

    #[test]
    fn mixed_codecs_form_one_set() {
        let d = detect(&names(&[
            "mix-000000.tar.gz",
            "mix-000001.tar.zst",
            "mix-000002.tar.xz",
            "mix-000003.tar.bz2",
            "mix-000004.tgz",
        ]))
        .unwrap();
        assert_eq!(d.sets.len(), 1);
        let suffixes: Vec<&str> = d.sets[0].shards.iter().map(|s| s.suffix.as_str()).collect();
        assert_eq!(
            suffixes,
            vec![".tar.gz", ".tar.zst", ".tar.xz", ".tar.bz2", ".tgz"]
        );
    }

    #[test]
    fn several_sets_and_ignored_files() {
        let d = detect(&names(&[
            "val-000000.tar.zst",
            "train-000001.tar.zst",
            "train-000000.tar.zst",
            "README.md",
            "dataset_info.json",
            "train-000000.tar.zst.trncj",
        ]))
        .unwrap();
        assert_eq!(
            order(&d),
            vec![
                vec!["train-000000.tar.zst", "train-000001.tar.zst"],
                vec!["val-000000.tar.zst"]
            ]
        );
        assert_eq!(d.ignored.len(), 3);
        assert_eq!(d.shard_count(), 3);
    }

    #[test]
    fn split_parts_are_one_shard() {
        let d = detect(&names(&[
            "weights.tar.zst.002",
            "weights.tar.zst.001",
            "weights.tar.zst.003",
        ]))
        .unwrap();
        assert_eq!(d.sets.len(), 1);
        let s = &d.sets[0].shards[0];
        assert_eq!(s.name, "weights.tar.zst.001");
        assert_eq!(s.parts.len(), 3);
        assert_eq!(s.stem, "weights");
        assert_eq!(s.index, None);
        let d = detect(&names(&["w.tar.gz.ab", "w.tar.gz.aa"])).unwrap();
        assert_eq!(d.sets[0].shards[0].name, "w.tar.gz.aa");
    }

    #[test]
    fn split_parts_of_numbered_shards() {
        let d = detect(&names(&[
            "m-00001-of-00002.tar.zst.001",
            "m-00001-of-00002.tar.zst.002",
            "m-00002-of-00002.tar.zst",
        ]))
        .unwrap();
        assert_eq!(d.sets.len(), 1);
        assert_eq!(d.sets[0].shards[0].parts.len(), 2);
        assert_eq!(d.sets[0].shards[1].name, "m-00002-of-00002.tar.zst");
    }

    #[test]
    fn whole_and_split_copies_conflict() {
        let e = detect(&names(&["a.tar.gz", "a.tar.gz.001", "a.tar.gz.002"])).unwrap_err();
        assert!(e.contains("both whole and as split parts"), "{e}");
    }

    #[test]
    fn unnumbered_archives_stand_alone() {
        let d = detect(&names(&["photos.tar.gz", "code.tar.xz"])).unwrap();
        assert_eq!(d.sets.len(), 2);
        assert!(d.sets.iter().all(|s| s.shards.len() == 1));
    }

    #[test]
    fn plain_tar_is_flagged_and_suffix_is_case_insensitive() {
        let d = detect(&names(&["A-0.TAR.ZST", "A-1.tar"])).unwrap();
        assert!(!d.sets[0].shards[0].is_plain_tar());
        assert!(d.sets[0].shards[1].is_plain_tar());
        assert_eq!(d.sets[0].shards[0].stem, "A-0");
    }

    #[test]
    fn xz_and_gz_are_not_split_letters() {
        // `.gz` and `.xz` are two lower-case letters but are archives, not parts.
        let d = detect(&names(&["a-0.tar.gz", "a-1.tar.xz"])).unwrap();
        assert!(d.sets[0].shards.iter().all(|s| s.parts.is_empty()));
    }
}
