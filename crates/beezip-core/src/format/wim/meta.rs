//! An image's metadata resource: its security data, then its tree of directory entries
//! ("dentries"), each with its stream entries.
//!
//! The layout is Microsoft's paper's where it's right; past the hash its field order is wrong,
//! and what's here was read from sample files and checked against them (the M8 spike):
//! - **Dentry:** length (8), attributes (4), security id (4), the offset of its folder's list
//!   (8), two unused (16), created, accessed and written times (8 each, 100 ns), the hash of its
//!   data (20), an unused u32; then at 88 the reparse tag, a reserved u16 and at 94 a u16 that's
//!   0 when the target was fixed at capture and 1 when not, or, for other files, the 64-bit hard
//!   link group; the stream count (2), the short name's and the name's byte counts (2 each), the
//!   name and a NUL, the short name and a NUL. Tagged data may follow (wimlib's
//!   `--unix-data`). Its stream entries start at the next 8-byte boundary after its length.
//! - **Stream entry:** length (8), unused (8), hash (20), the name's byte count (2), the name.
//! - **A folder's list** ends with a length of 0.
//!
//! The walk keeps a set of folder lists listed, goes at most [`MAX_DEPTH`] folders deep, and
//! caps the entries and the bytes of their paths. What it leaves out is a warning: a bad name, a
//! folder list met twice or too deep, and the rest of a folder whose list is damaged.

use std::collections::HashSet;

use super::container::{Hash, ZERO, bad, le16, le32, le64};
use crate::{Error, Result, format::reparse::utf16};

pub const ATTR_DIRECTORY: u32 = 0x10;
pub const ATTR_REPARSE: u32 = 0x400;
pub const ATTR_ENCRYPTED: u32 = 0x4000;

/// The deepest folder listed, as for NTFS.
pub const MAX_DEPTH: usize = 256;
/// A dentry's part before its names.
const DENTRY_FIXED: usize = 102;
/// A stream entry's part before its name.
const STREAM_FIXED: usize = 38;

/// A named or unnamed stream of a dentry.
#[derive(Debug, Clone)]
pub struct StreamEnt {
    pub name: String,
    pub hash: Hash,
}

/// An entry of the tree, its path from the image's root.
#[derive(Debug, Clone)]
pub struct Dentry {
    /// `/`-separated; the root's is empty.
    pub path: String,
    pub attrs: u32,
    pub mtime: u64,
    pub hash: Hash,
    pub reparse_tag: u32,
    /// 0 when a reparse point's target was fixed at capture.
    pub not_fixed: u16,
    /// The hard link group, when it isn't a reparse point.
    pub link: u64,
    pub streams: Vec<StreamEnt>,
    pub dir: bool,
}

impl Dentry {
    pub fn is_reparse(&self) -> bool {
        self.attrs & ATTR_REPARSE != 0
    }

    /// The reparse data's blob (reparse points) and the unnamed data's. A reparse point keeps
    /// its reparse data in the dentry's hash (Microsoft's captures) or in a first unnamed stream
    /// entry, then its unnamed data in a second (wimlib's).
    pub fn data(&self) -> (Option<Hash>, Hash) {
        let mut unnamed = self
            .streams
            .iter()
            .filter(|s| s.name.is_empty())
            .map(|s| s.hash);
        if self.is_reparse() {
            if self.hash != ZERO {
                (Some(self.hash), unnamed.next().unwrap_or(ZERO))
            } else {
                let rp = unnamed.next();
                (rp, unnamed.next().unwrap_or(ZERO))
            }
        } else if self.hash != ZERO {
            (None, self.hash)
        } else {
            (None, unnamed.next().unwrap_or(ZERO))
        }
    }
}

/// What the walk may take.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub entries: u64,
    pub path_bytes: u64,
}

fn align8(x: usize) -> usize {
    x.saturating_add(7) & !7
}

/// The parts of a dentry before its streams, bounds checked.
struct Raw {
    len: usize,
    attrs: u32,
    sub: u64,
    mtime: u64,
    hash: Hash,
    tag: u32,
    not_fixed: u16,
    link: u64,
    streams: u16,
    name: String,
}

fn dentry(meta: &[u8], at: usize) -> Option<Raw> {
    let len = usize::try_from(le64(meta, at)).ok()?;
    let end = at.checked_add(len)?;
    if len < DENTRY_FIXED || end > meta.len() {
        return None;
    }
    let short_len = usize::from(le16(meta, at + 98));
    let name_len = usize::from(le16(meta, at + 100));
    if name_len % 2 != 0 || short_len % 2 != 0 {
        return None;
    }
    let names = DENTRY_FIXED
        + name_len
        + if name_len > 0 { 2 } else { 0 }
        + if short_len > 0 { short_len + 2 } else { 0 };
    if names > len {
        return None;
    }
    let attrs = le32(meta, at + 8);
    let reparse = attrs & ATTR_REPARSE != 0;
    Some(Raw {
        len,
        attrs,
        sub: le64(meta, at + 16),
        mtime: le64(meta, at + 56),
        hash: meta.get(at + 64..at + 84)?.try_into().ok()?,
        tag: if reparse { le32(meta, at + 88) } else { 0 },
        not_fixed: if reparse { le16(meta, at + 94) } else { 0 },
        link: if reparse { 0 } else { le64(meta, at + 88) },
        streams: le16(meta, at + 96),
        name: utf16(meta.get(at + DENTRY_FIXED..at + DENTRY_FIXED + name_len)?),
    })
}

/// A dentry's stream entries, from `at`; the offset after them.
fn streams(meta: &[u8], mut at: usize, n: u16) -> Option<(Vec<StreamEnt>, usize)> {
    let mut out = Vec::with_capacity(usize::from(n.min(64)));
    for _ in 0..n {
        let len = usize::try_from(le64(meta, at)).ok()?;
        let name_len = usize::from(le16(meta, at + 36));
        let end = at.checked_add(len)?;
        if len < STREAM_FIXED || end > meta.len() || STREAM_FIXED + name_len > len {
            return None;
        }
        let hash: Hash = meta[at + 16..at + 36].try_into().ok()?;
        let name = utf16(&meta[at + STREAM_FIXED..at + STREAM_FIXED + name_len]);
        out.push(StreamEnt { name, hash });
        at = align8(end);
    }
    Some((out, at))
}

/// Walks a metadata resource: the root first (path ""), then parents before what's in them,
/// each folder's entries in stored order. `warn` hears what's left out.
pub fn walk(meta: &[u8], caps: Caps, warn: &mut dyn FnMut(String)) -> Result<Vec<Dentry>> {
    if meta.len() < 8 {
        return Err(bad("an image's metadata too short for its security data"));
    }
    let sec_len = le32(meta, 0) as usize;
    let sec_n = le32(meta, 4) as usize;
    if sec_len < 8
        || sec_len > meta.len()
        || sec_n
            .checked_mul(8)
            .and_then(|s| s.checked_add(8))
            .is_none_or(|s| s > sec_len)
    {
        return Err(bad(format!(
            "an image's security data of {sec_len} bytes holding {sec_n} descriptors"
        )));
    }
    let mut sum = 0u64;
    for i in 0..sec_n {
        sum = sum.saturating_add(le64(meta, 8 + 8 * i));
    }
    if sum > (sec_len - 8 - 8 * sec_n) as u64 {
        return Err(bad(
            "an image's security descriptors larger than their table",
        ));
    }
    let root = align8(sec_len);
    let r = dentry(meta, root).ok_or_else(|| bad("an image without a root folder"))?;
    if r.attrs & ATTR_DIRECTORY == 0 {
        return Err(bad("an image whose root isn't a folder"));
    }
    let mut out = vec![Dentry {
        path: String::new(),
        attrs: r.attrs,
        mtime: r.mtime,
        hash: ZERO,
        reparse_tag: 0,
        not_fixed: 0,
        link: 0,
        streams: Vec::new(),
        dir: true,
    }];
    let mut visited = HashSet::new();
    let mut path_bytes = 0u64;
    // A folder's list: where it is, the folder's path and depth.
    let mut stack: Vec<(usize, String, usize)> = Vec::new();
    if r.sub != 0 {
        visited.insert(r.sub);
        stack.push((
            usize::try_from(r.sub).unwrap_or(usize::MAX),
            String::new(),
            0,
        ));
    }
    let shown = |p: &str| {
        if p.is_empty() {
            "the root folder".to_owned()
        } else {
            format!("`{p}`")
        }
    };
    while let Some((mut at, parent, depth)) = stack.pop() {
        let mut subdirs = Vec::new();
        loop {
            if at.checked_add(8).is_none_or(|e| e > meta.len()) {
                warn(format!(
                    "{}'s list runs past the image's metadata; the rest of it isn't listed",
                    shown(&parent)
                ));
                break;
            }
            if le64(meta, at) == 0 {
                break;
            }
            let Some((d, after)) = dentry(meta, at)
                .and_then(|d| streams(meta, align8(at + d.len), d.streams).map(|s| (d, s)))
            else {
                warn(format!(
                    "{}'s list is damaged at {at}; the rest of it isn't listed",
                    shown(&parent)
                ));
                break;
            };
            let (streams, next) = after;
            at = next;
            if d.name.is_empty() || d.name == "." || d.name == ".." || d.name.contains(['/', '\0'])
            {
                warn(format!(
                    "{} holds a name no file can have, {:?}; it's left out",
                    shown(&parent),
                    d.name
                ));
                continue;
            }
            if out.len() as u64 >= caps.entries {
                return Err(Error::limit(format!(
                    "the archive has more than {} entries (limit `max_entries`)",
                    caps.entries
                )));
            }
            let path = if parent.is_empty() {
                d.name.clone()
            } else {
                format!("{parent}/{}", d.name)
            };
            path_bytes += path.len() as u64;
            if path_bytes > caps.path_bytes {
                return Err(Error::limit(format!(
                    "wim: the paths of an image's entries take more than {} bytes",
                    caps.path_bytes
                )));
            }
            let dir = d.attrs & ATTR_DIRECTORY != 0;
            if dir && d.sub != 0 && d.attrs & ATTR_REPARSE == 0 {
                if depth + 1 >= MAX_DEPTH {
                    warn(format!(
                        "`{path}` is more than {MAX_DEPTH} folders deep; what's in it isn't \
                         listed"
                    ));
                } else if visited.insert(d.sub) {
                    subdirs.push((
                        usize::try_from(d.sub).unwrap_or(usize::MAX),
                        path.clone(),
                        depth + 1,
                    ));
                } else {
                    warn(format!(
                        "`{path}`'s list is another folder's; it isn't listed again"
                    ));
                }
            }
            out.push(Dentry {
                path,
                attrs: d.attrs,
                mtime: d.mtime,
                hash: d.hash,
                reparse_tag: d.tag,
                not_fixed: d.not_fixed,
                link: d.link,
                streams,
                dir,
            });
        }
        // Its folders after it, in stored order: the stack takes the first one first.
        stack.extend(subdirs.into_iter().rev());
    }
    Ok(out)
}
