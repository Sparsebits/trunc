//! The small state file weightdrop keeps in the destination, `.weightdrop-state`.
//!
//! It records the shard list (so a re-run knows the set even after consumed shards are gone),
//! the output layout chosen up front, and how far each shard got. A shard interrupted half way
//! is continued by trunc from its own journal (`<shard>.trncj`); this file only orders shards.
//!
//! Format: UTF-8 text, one record per line, fields separated by tabs: a `weightdrop-state 1`
//! header, `mode consume|keep`, `layout flat|per-shard`, then one
//! `shard pending|started|done <subfolder or .> <absolute archive path>` line per shard.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub const FILE_NAME: &str = ".weightdrop-state";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Every shard's top-level names go straight into the destination.
    Flat,
    /// Each shard goes into `<dest>/<shard stem>/`.
    PerShard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Started,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardState {
    pub status: Status,
    /// Subfolder of the destination the shard unpacks into (empty: the destination itself).
    pub subdir: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub keep: bool,
    pub layout: Layout,
    pub shards: Vec<ShardState>,
}

pub fn path_in(dest: &Path) -> PathBuf {
    dest.join(FILE_NAME)
}

impl State {
    pub fn encode(&self) -> String {
        let mut s = String::from("weightdrop-state\t1\n");
        s.push_str(if self.keep {
            "mode\tkeep\n"
        } else {
            "mode\tconsume\n"
        });
        s.push_str(match self.layout {
            Layout::Flat => "layout\tflat\n",
            Layout::PerShard => "layout\tper-shard\n",
        });
        for sh in &self.shards {
            let st = match sh.status {
                Status::Pending => "pending",
                Status::Started => "started",
                Status::Done => "done",
            };
            let sub = if sh.subdir.is_empty() {
                "."
            } else {
                &sh.subdir
            };
            s.push_str(&format!("shard\t{st}\t{sub}\t{}\n", sh.path.display()));
        }
        s
    }

    pub fn decode(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        if lines.next() != Some("weightdrop-state\t1") {
            bail!("not a weightdrop state file (or written by a newer version)");
        }
        let (mut keep, mut layout) = (None, None);
        let mut shards = Vec::new();
        for line in lines.filter(|l| !l.is_empty()) {
            let f: Vec<&str> = line.splitn(4, '\t').collect();
            match f.as_slice() {
                ["mode", "keep"] => keep = Some(true),
                ["mode", "consume"] => keep = Some(false),
                ["layout", "flat"] => layout = Some(Layout::Flat),
                ["layout", "per-shard"] => layout = Some(Layout::PerShard),
                ["shard", st, sub, path] => {
                    let status = match *st {
                        "pending" => Status::Pending,
                        "started" => Status::Started,
                        "done" => Status::Done,
                        _ => bail!("bad shard status {st:?}"),
                    };
                    shards.push(ShardState {
                        status,
                        subdir: if *sub == "." {
                            String::new()
                        } else {
                            (*sub).to_owned()
                        },
                        path: PathBuf::from(path),
                    });
                }
                _ => bail!("bad line {line:?}"),
            }
        }
        Ok(Self {
            keep: keep.context("mode missing")?,
            layout: layout.context("layout missing")?,
            shards,
        })
    }

    pub fn load(dest: &Path) -> Result<Option<Self>> {
        let p = path_in(dest);
        match std::fs::read_to_string(&p) {
            Ok(t) => Self::decode(&t)
                .map(Some)
                .with_context(|| format!("{} is damaged", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// Write durably: a temporary file, flushed, then renamed over the old one.
    pub fn save(&self, dest: &Path) -> Result<()> {
        let p = path_in(dest);
        let tmp = dest.join(format!("{FILE_NAME}.tmp"));
        {
            let mut f = std::fs::File::create(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            f.write_all(self.encode().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p).with_context(|| format!("writing {}", p.display()))?;
        Ok(())
    }

    pub fn remove(dest: &Path) -> Result<()> {
        match std::fs::remove_file(path_in(dest)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = State {
            keep: false,
            layout: Layout::PerShard,
            shards: vec![
                ShardState {
                    status: Status::Done,
                    subdir: "train-000000".into(),
                    path: PathBuf::from("/data/with space/train-000000.tar.zst"),
                },
                ShardState {
                    status: Status::Pending,
                    subdir: String::new(),
                    path: PathBuf::from("/data/train-000001.tar.zst"),
                },
            ],
        };
        assert_eq!(State::decode(&s.encode()).unwrap(), s);
        assert!(State::decode("hello").is_err());
    }
}
