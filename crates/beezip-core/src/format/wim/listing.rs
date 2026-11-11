//! The images as BeeZip lists them (docs/M8.md §5.2, decision 8): a folder per image when there
//! are several (`1/`, `2/`… as 7-Zip names them), straight at the top when there's one; alternate
//! streams as `file:stream`; a further name of a hard link group as a hard link to the first;
//! reparse points decoded as NTFS's are; no `[1].xml` and no `[DELETED]/`.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use super::{
    container::{Container, Hash, ZERO, hex},
    meta::{ATTR_DIRECTORY, ATTR_ENCRYPTED, Dentry},
};
use crate::{
    Error, ErrorKind, Result,
    format::{
        Entry, EntryKind,
        reparse::{self, Reparse},
    },
    limits::Limits,
    time::from_ntfs,
};

/// What an entry's data is.
#[derive(Debug, Clone)]
pub enum Item {
    /// A folder, a link or a special file: none.
    None,
    /// A file of no bytes.
    Empty,
    /// A blob of the lookup table.
    Blob(Hash),
    /// A further name of a file (or of its stream): that entry's data.
    Link(usize),
    /// Data BeeZip doesn't read, or can't find, and why.
    Refused(Error),
}

/// The reparse tags whose data says what the file is: links, and WOF's method.
pub fn wants_data(tag: u32) -> bool {
    matches!(
        tag,
        reparse::TAG_SYMLINK
            | reparse::TAG_MOUNT_POINT
            | reparse::TAG_LX_SYMLINK
            | reparse::TAG_WOF
    )
}

/// A file with several names: the first name's entry, its data, and its streams' entries by
/// name.
type First = (usize, Hash, Vec<(String, usize)>);

/// One image's dentries, walked.
pub struct Image {
    pub index: usize,
    pub dentries: Vec<Dentry>,
}

pub struct Listing {
    pub entries: Vec<Entry>,
    pub items: Vec<Item>,
    /// Blobs of the lookup table no image refers to (7-Zip's `[DELETED]/`).
    pub unreferenced: usize,
    /// Links whose targets were fixed at capture and are made relative.
    pub fixed: usize,
}

/// A link target DISM or wimlib "fixed" at capture: absolute, from the captured folder's root
/// (`\??\C:\names`, `C:\names`, `\names`), made relative to the link at `link` (its path in the
/// image), so that it stays inside the image: `links/junction` → `../names`. `None` when it isn't
/// such a path (a volume's, a share's, a relative one): it stays as stored.
pub fn fixed_target(link: &str, target: &str) -> Option<String> {
    let mut t = target;
    for p in ["/??/", "//?/"] {
        if let Some(rest) = t.strip_prefix(p) {
            t = rest;
            break;
        }
    }
    let b = t.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        t = &t[2..];
    }
    let rest = t.strip_prefix('/')?;
    let names: Vec<&str> = rest
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let mut out: Vec<&str> = vec![".."; link.matches('/').count()];
    out.extend(names);
    Some(if out.is_empty() {
        ".".to_owned()
    } else {
        out.join("/")
    })
}

/// The entries of `images`, in their order. `reparse` holds the reparse data read for the
/// tags [`wants_data`] names; `rpfix`, whether the image's links were fixed at capture.
#[allow(clippy::too_many_lines)]
pub fn list(
    c: &Container,
    images: &[Image],
    reparse_data: &HashMap<Hash, Vec<u8>>,
    limits: &Limits,
    warn: &mut dyn FnMut(String),
) -> Result<Listing> {
    let rpfix = c.header.flags & super::container::HDR_RP_FIX != 0;
    let split_missing = c.parts.iter().any(Option::is_none);
    let several = images.len() > 1;
    let mut l = Listing {
        entries: Vec::new(),
        items: Vec::new(),
        unreferenced: 0,
        fixed: 0,
    };
    let mut referenced: HashSet<Hash> = HashSet::new();
    let push = |l: &mut Listing, path: String, kind: EntryKind, item: Item| -> Result<usize> {
        limits.check_entries(l.entries.len() as u64 + 1)?;
        let id = l.entries.len();
        l.entries.push(Entry::new(id, path, kind));
        l.items.push(item);
        Ok(id)
    };
    // A blob's item, size, bytes in the file and method.
    let blob = |h: &Hash, path: &str| -> (Item, u64, u64, Option<Cow<'static, str>>) {
        if *h == ZERO {
            return (Item::Empty, 0, 0, None);
        }
        match c.blobs.get(h) {
            Some(b) => (
                Item::Blob(*h),
                b.size,
                c.packed(b),
                Some(Cow::Borrowed(c.method_of(b).name())),
            ),
            None if split_missing => (
                Item::Refused(Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "wim: `{path}`'s data isn't in the parts of the split set found beside \
                         it"
                    ),
                )),
                0,
                0,
                None,
            ),
            None => (
                Item::Refused(super::container::bad(format!(
                    "`{path}`'s data, blob {}, isn't in the lookup table",
                    hex(h)
                ))),
                0,
                0,
                None,
            ),
        }
    };
    for img in images {
        let prefix = if several {
            format!("{}/", img.index)
        } else {
            String::new()
        };
        // Files with several names: the first name's entry, and its streams' entries by name.
        let mut first: HashMap<u64, First> = HashMap::new();
        for d in &img.dentries {
            let modified = (d.mtime > 0).then(|| from_ntfs(d.mtime)).flatten();
            if d.path.is_empty() {
                if several {
                    let id = push(&mut l, img.index.to_string(), EntryKind::Dir, Item::None)?;
                    l.entries[id].modified = modified;
                    l.entries[id].dos_attrs = Some(d.attrs);
                }
                continue;
            }
            let path = format!("{prefix}{}", d.path);
            referenced.insert(d.hash);
            referenced.extend(d.streams.iter().map(|s| s.hash));
            let (rp, data) = d.data();
            let mut refused: Option<Error> = None;
            let mut method = None;
            let kind = if d.is_reparse() {
                let tag = d.reparse_tag;
                let rp_bytes = rp.and_then(|h| reparse_data.get(&h));
                let r = match rp_bytes {
                    Some(v) => reparse::decode(tag, v),
                    None if wants_data(tag) && tag != reparse::TAG_WOF => Reparse::Bad,
                    None => reparse::decode(tag, &[]),
                };
                match r {
                    Reparse::Link(t) => {
                        let relative =
                            rp_bytes.is_some_and(|v| reparse::symlink_is_relative(tag, v));
                        let fix = rpfix
                            && d.not_fixed == 0
                            && !relative
                            && matches!(tag, reparse::TAG_SYMLINK | reparse::TAG_MOUNT_POINT);
                        match fix.then(|| fixed_target(&d.path, &t)).flatten() {
                            Some(f) => {
                                l.fixed += 1;
                                EntryKind::Symlink { target: f }
                            }
                            None => EntryKind::Symlink { target: t },
                        }
                    }
                    Reparse::Special => EntryKind::Other,
                    Reparse::Bad => {
                        warn(format!("`{path}`'s link can't be read"));
                        EntryKind::Other
                    }
                    Reparse::Wof(m, _) if !d.dir => {
                        method = Some(Cow::Borrowed(m));
                        refused = Some(Error::unsupported(format!(
                            "wim: `{path}` is compressed by Windows ({m}), which BeeZip doesn't \
                             read in a WIM"
                        )));
                        EntryKind::File
                    }
                    Reparse::Dedup if !d.dir => {
                        refused = Some(Error::unsupported(format!(
                            "wim: `{path}` is deduplicated by Windows Server; its data isn't in \
                             the image"
                        )));
                        EntryKind::File
                    }
                    _ if d.dir => EntryKind::Dir,
                    _ => EntryKind::File,
                }
            } else if d.dir {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let encrypted = kind == EntryKind::File && d.attrs & ATTR_ENCRYPTED != 0;
            if encrypted {
                refused = Some(Error::unsupported(format!(
                    "wim: `{path}` is encrypted with EFS, which BeeZip doesn't read"
                )));
            }
            // A further name of a file with several.
            if kind == EntryKind::File
                && d.link != 0
                && let Some((fid, fdata, fstreams)) = first.get(&d.link)
            {
                if *fdata == data {
                    let (fid, fstreams) = (*fid, fstreams.clone());
                    let (fkind, fitem) = match &l.items[fid] {
                        Item::Refused(e) => (EntryKind::File, Item::Refused(e.clone())),
                        _ => (
                            EntryKind::Hardlink {
                                target: l.entries[fid].path.clone(),
                            },
                            Item::Link(fid),
                        ),
                    };
                    let id = push(&mut l, path.clone(), fkind, fitem)?;
                    l.entries[id].modified = modified;
                    l.entries[id].dos_attrs = Some(d.attrs);
                    for (name, sid) in fstreams {
                        let item = match &l.items[sid] {
                            Item::Refused(e) => Item::Refused(e.clone()),
                            _ => Item::Link(sid),
                        };
                        let kind = match item {
                            Item::Link(_) => EntryKind::Hardlink {
                                target: l.entries[sid].path.clone(),
                            },
                            _ => EntryKind::File,
                        };
                        let id = push(&mut l, format!("{path}:{name}"), kind, item)?;
                        l.entries[id].modified = modified;
                        l.entries[id].dos_attrs = l.entries[sid].dos_attrs;
                    }
                    continue;
                }
                warn(format!(
                    "`{path}` shares a hard link group with `{}` but not its data; it's listed \
                     as a file of its own",
                    l.entries[*fid].path
                ));
            }
            let (item, size, packed, m) = match (&kind, refused) {
                (EntryKind::File, Some(e)) => {
                    let (_, size, packed, _) = blob(&data, &path);
                    (Item::Refused(e), size, packed, method)
                }
                (EntryKind::File, None) => blob(&data, &path),
                _ => (Item::None, 0, 0, None),
            };
            let is_file = kind == EntryKind::File;
            let id = push(&mut l, path.clone(), kind, item)?;
            {
                let e = &mut l.entries[id];
                e.modified = modified;
                e.dos_attrs = Some(d.attrs);
                e.encrypted = encrypted;
                if is_file {
                    e.size = Some(size);
                    e.packed_size = Some(packed);
                    e.method = m;
                }
            }
            let mut streams = Vec::new();
            for s in d.streams.iter().filter(|s| !s.name.is_empty()) {
                if s.name.contains(['/', '\0', ':']) {
                    warn(format!(
                        "`{path}`'s stream {:?} has a name no stream can have; it's left out",
                        s.name
                    ));
                    continue;
                }
                let spath = format!("{path}:{}", s.name);
                let (item, size, packed, m) = blob(&s.hash, &spath);
                let item = if encrypted {
                    Item::Refused(Error::unsupported(format!(
                        "wim: `{spath}` is encrypted with EFS, which BeeZip doesn't read"
                    )))
                } else {
                    item
                };
                let sid = push(&mut l, spath, EntryKind::File, item)?;
                let e = &mut l.entries[sid];
                e.modified = modified;
                e.dos_attrs = Some(d.attrs & !ATTR_DIRECTORY);
                e.encrypted = encrypted;
                e.size = Some(size);
                e.packed_size = Some(packed);
                e.method = m;
                streams.push((s.name.clone(), sid));
            }
            if is_file && d.link != 0 {
                first.entry(d.link).or_insert((id, data, streams));
            }
        }
    }
    l.unreferenced = c.blobs.keys().filter(|h| !referenced.contains(*h)).count();
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_targets_become_relative_inside_the_image() {
        assert_eq!(
            fixed_target("links/junction", "/??/C:/names").as_deref(),
            Some("../names")
        );
        assert_eq!(
            fixed_target("abs-link", "/sub/nested/deep.txt").as_deref(),
            Some("sub/nested/deep.txt")
        );
        assert_eq!(
            fixed_target("a/b/c", "C:/x/y").as_deref(),
            Some("../../x/y")
        );
        assert_eq!(fixed_target("top", "/").as_deref(), Some("."));
        assert_eq!(fixed_target("a/top", "/??/C:/").as_deref(), Some(".."));
        // Not from the captured folder's root: as stored.
        assert_eq!(fixed_target("x", "/??/Volume{1}/x"), None);
        assert_eq!(fixed_target("x", "/??/UNC/server/share"), None);
        assert_eq!(fixed_target("x", "relative/y"), None);
    }
}
