//! The reader against WIMs built here, stored (no compression), byte by byte: the listing's
//! rules, extraction in data order, what's refused and what's damaged. The compressed and solid
//! variants are wimlib's, in `tests/fixtures/thirdparty/wim/` (`tests/wim.rs`).

use std::{collections::VecDeque, io::Read};

use sha1::{Digest, Sha1};

use super::{
    container::{HEADER_LEN, MAGIC, VERSION_WIM},
    *,
};
use crate::{
    EntryKind, ErrorKind, FsOptions, FsSink, Limits, OpenOptions, OverwritePolicy, SimpleCtx,
    format::reparse,
};

const DIR: u32 = 0x10;
const REPARSE: u32 = 0x400;
const FILE: u32 = 0x20;

/// One dentry and what's in it.
#[derive(Clone, Default)]
struct Node {
    name: String,
    attrs: u32,
    mtime: u64,
    data: Option<Vec<u8>>,
    tag: u32,
    not_fixed: u16,
    /// A reparse point's data (kept in the dentry's hash, as Microsoft's captures do).
    reparse: Option<Vec<u8>>,
    link: u64,
    streams: Vec<(String, Vec<u8>)>,
    children: Vec<Node>,
    /// Its folder list at this offset instead of its own (a loop).
    sub: Option<u64>,
    /// A damaged length.
    bad_len: bool,
}

fn file(name: &str, data: &[u8]) -> Node {
    Node {
        name: name.into(),
        attrs: FILE,
        mtime: 133_000_000_000_000_000,
        data: Some(data.to_vec()),
        ..Node::default()
    }
}

fn dir(name: &str, children: Vec<Node>) -> Node {
    Node {
        name: name.into(),
        attrs: DIR,
        mtime: 133_000_000_000_000_000,
        children,
        ..Node::default()
    }
}

fn symlink(name: &str, target: &str, relative: bool, not_fixed: u16) -> Node {
    let t: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut d = Vec::new();
    for n in [0, t.len(), t.len(), t.len()] {
        d.extend_from_slice(&(n as u16).to_le_bytes());
    }
    d.extend_from_slice(&u32::from(relative).to_le_bytes());
    d.extend_from_slice(&t);
    d.extend_from_slice(&t);
    Node {
        name: name.into(),
        attrs: FILE | REPARSE,
        tag: reparse::TAG_SYMLINK,
        not_fixed,
        reparse: Some(d),
        ..Node::default()
    }
}

fn sha1(data: &[u8]) -> Hash {
    Sha1::digest(data).into()
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn pad8(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(8) {
        b.push(0);
    }
}

/// A stored WIM of `images` (roots), with their names.
#[derive(Default)]
struct Builder {
    images: Vec<(Node, String)>,
    /// Blobs no image refers to.
    extra: Vec<Vec<u8>>,
    flags: u32,
    integrity: bool,
}

/// Where the built WIM keeps things, for tests that damage them.
struct Built {
    bytes: Vec<u8>,
    /// Each blob's offset, by its data's SHA-1.
    blobs: HashMap<Hash, u64>,
    /// The lookup table's offset.
    lookup: u64,
}

impl Builder {
    fn image(mut self, root: Node, name: &str) -> Self {
        self.images.push((root, name.into()));
        self
    }

    fn build(&self) -> Built {
        let mut out = vec![0u8; HEADER_LEN];
        let mut blobs: Vec<(Hash, u64, u64)> = Vec::new();
        let mut at: HashMap<Hash, u64> = HashMap::new();
        let mut add = |out: &mut Vec<u8>, data: &[u8]| -> Hash {
            if data.is_empty() {
                return ZERO;
            }
            let h = sha1(data);
            if let std::collections::hash_map::Entry::Vacant(v) = at.entry(h) {
                v.insert(out.len() as u64);
                blobs.push((h, out.len() as u64, data.len() as u64));
                out.extend_from_slice(data);
            }
            h
        };
        let mut metas = Vec::new();
        for (root, _) in &self.images {
            let meta = metadata(root, &mut |d| add(&mut out, d));
            metas.push(meta);
        }
        for e in &self.extra {
            add(&mut out, e);
        }
        let mut meta_entries = Vec::new();
        for m in &metas {
            meta_entries.push((sha1(m), out.len() as u64, m.len() as u64));
            out.extend_from_slice(m);
        }
        let lookup = out.len() as u64;
        let entry = |out: &mut Vec<u8>, h: &Hash, off: u64, size: u64, flags: u8| {
            out.extend_from_slice(&(size | u64::from(flags) << 56).to_le_bytes());
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&1u16.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(h);
        };
        for (h, off, size) in &meta_entries {
            entry(&mut out, h, *off, *size, 2);
        }
        for (h, off, size) in &blobs {
            entry(&mut out, h, *off, *size, 0);
        }
        let lookup_len = out.len() as u64 - lookup;
        let mut xml = String::from("\u{FEFF}<WIM>");
        for (i, (_, name)) in self.images.iter().enumerate() {
            xml += &format!("<IMAGE INDEX=\"{}\"><NAME>{name}</NAME></IMAGE>", i + 1);
        }
        xml += "</WIM>";
        let xml = utf16(&xml);
        let xml_at = out.len() as u64;
        out.extend_from_slice(&xml);
        let mut integrity = (0u64, 0u64);
        if self.integrity {
            let chunk = 4096u64;
            let end = lookup + lookup_len;
            let hashes: Vec<Hash> = out[HEADER_LEN..end as usize]
                .chunks(chunk as usize)
                .map(sha1)
                .collect();
            let mut t = Vec::new();
            t.extend_from_slice(&((12 + 20 * hashes.len()) as u32).to_le_bytes());
            t.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
            t.extend_from_slice(&(chunk as u32).to_le_bytes());
            for h in &hashes {
                t.extend_from_slice(h);
            }
            integrity = (out.len() as u64, t.len() as u64);
            out.extend_from_slice(&t);
        }
        let h = &mut out[..HEADER_LEN];
        h[..8].copy_from_slice(MAGIC);
        h[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        h[12..16].copy_from_slice(&VERSION_WIM.to_le_bytes());
        h[16..20].copy_from_slice(&self.flags.to_le_bytes());
        h[24..40].copy_from_slice(&[7; 16]);
        h[40..42].copy_from_slice(&1u16.to_le_bytes());
        h[42..44].copy_from_slice(&1u16.to_le_bytes());
        h[44..48].copy_from_slice(&(self.images.len() as u32).to_le_bytes());
        let res = |h: &mut [u8], at: usize, off: u64, size: u64| {
            h[at..at + 8].copy_from_slice(&size.to_le_bytes());
            h[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            h[at + 16..at + 24].copy_from_slice(&size.to_le_bytes());
        };
        res(h, 48, lookup, lookup_len);
        res(h, 72, xml_at, xml.len() as u64);
        res(h, 124, integrity.0, integrity.1);
        Built {
            bytes: out,
            blobs: at,
            lookup,
        }
    }
}

/// [`Node::sub`]: the root folder's list.
const ROOT_LIST: u64 = u64::MAX;

/// An image's metadata: no security descriptors, the root, then each folder's list.
fn metadata(root: &Node, add: &mut dyn FnMut(&[u8]) -> Hash) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&8u32.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    let root_sub = dentry(&mut m, root, add);
    m.extend_from_slice(&[0; 8]);
    let root_list = m.len() as u64;
    let mut queue = VecDeque::from([(root_sub, root)]);
    while let Some((pos, node)) = queue.pop_front() {
        if node.children.is_empty() && node.sub.is_none() {
            continue;
        }
        let list = match node.sub {
            Some(ROOT_LIST) => root_list,
            Some(s) => s,
            None => m.len() as u64,
        };
        m[pos..pos + 8].copy_from_slice(&list.to_le_bytes());
        if node.sub.is_some() {
            continue;
        }
        for c in &node.children {
            let p = dentry(&mut m, c, add);
            if c.attrs & DIR != 0 && c.attrs & REPARSE == 0 {
                queue.push_back((p, c));
            }
        }
        m.extend_from_slice(&[0; 8]);
    }
    m
}

/// Writes a dentry and its streams; where its folder list's offset goes.
fn dentry(m: &mut Vec<u8>, n: &Node, add: &mut dyn FnMut(&[u8]) -> Hash) -> usize {
    let at = m.len();
    let name = utf16(&n.name);
    let len = 102 + name.len() + if name.is_empty() { 0 } else { 2 };
    m.resize(at + len, 0);
    let len_field = if n.bad_len { 50 } else { len as u64 };
    m[at..at + 8].copy_from_slice(&len_field.to_le_bytes());
    m[at + 8..at + 12].copy_from_slice(&n.attrs.to_le_bytes());
    m[at + 56..at + 64].copy_from_slice(&n.mtime.to_le_bytes());
    let hash = match (&n.reparse, &n.data) {
        (Some(r), _) => add(r),
        (None, Some(d)) if !d.is_empty() => add(d),
        _ => ZERO,
    };
    m[at + 64..at + 84].copy_from_slice(&hash);
    if n.attrs & REPARSE != 0 {
        m[at + 88..at + 92].copy_from_slice(&n.tag.to_le_bytes());
        m[at + 94..at + 96].copy_from_slice(&n.not_fixed.to_le_bytes());
    } else {
        m[at + 88..at + 96].copy_from_slice(&n.link.to_le_bytes());
    }
    // A reparse point's data, then its file data, in unnamed streams, as wimlib keeps them.
    let mut streams: Vec<(String, Hash)> = n
        .streams
        .iter()
        .map(|(s, d)| (s.clone(), if d.is_empty() { ZERO } else { add(d) }))
        .collect();
    if n.reparse.is_some()
        && let Some(d) = &n.data
    {
        streams.insert(0, (String::new(), add(d)));
    }
    m[at + 96..at + 98].copy_from_slice(&(streams.len() as u16).to_le_bytes());
    m[at + 100..at + 102].copy_from_slice(&(name.len() as u16).to_le_bytes());
    m[at + 102..at + 102 + name.len()].copy_from_slice(&name);
    pad8(m);
    for (s, h) in streams {
        let sn = utf16(&s);
        let sat = m.len();
        let slen = 38 + sn.len() + if sn.is_empty() { 0 } else { 2 };
        m.resize(sat + slen, 0);
        m[sat..sat + 8].copy_from_slice(&(slen as u64).to_le_bytes());
        m[sat + 16..sat + 36].copy_from_slice(&h);
        m[sat + 36..sat + 38].copy_from_slice(&(sn.len() as u16).to_le_bytes());
        m[sat + 38..sat + 38 + sn.len()].copy_from_slice(&sn);
        pad8(m);
    }
    at + 16
}

fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn opts(threads: u32) -> OpenOptions {
    OpenOptions::new(Limits::default()).with_threads(threads)
}

fn reader(path: &std::path::Path, threads: u32) -> Result<WimReader> {
    let source = Source::new(path, Vec::new(), &opts(threads))?;
    WimReader::open(source, &mut SimpleCtx::new())
}

fn read_all(r: &mut WimReader, path: &str) -> Result<Vec<u8>> {
    let id = r
        .entries
        .iter()
        .position(|e| e.path == path)
        .unwrap_or_else(|| panic!("{path} isn't listed"));
    let mut v = Vec::new();
    r.open_entry(id, &mut SimpleCtx::new())?
        .read_to_end(&mut v)
        .map_err(|e| crate::io::read_error(&e))?;
    Ok(v)
}

fn kinds(r: &WimReader) -> Vec<(String, EntryKind)> {
    r.entries
        .iter()
        .map(|e| (e.path.clone(), e.kind.clone()))
        .collect()
}

/// A tree with most of what the listing decides: streams, a hard link pair, a file shared by
/// two names that aren't links, links of each kind, and files BeeZip doesn't read.
fn rich() -> Node {
    let mut wof = Node {
        name: "wof.bin".into(),
        attrs: FILE | REPARSE,
        tag: reparse::TAG_WOF,
        reparse: Some(vec![1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]),
        data: Some(Vec::new()),
        ..Node::default()
    };
    wof.streams
        .push(("WofCompressedData".into(), b"opaque".to_vec()));
    let mut streams = file("streams.txt", b"main\n");
    streams
        .streams
        .push(("one".into(), b"stream one\n".to_vec()));
    streams.streams.push(("bad:name".into(), b"x".to_vec()));
    let mut a = file("a.txt", b"linked\n");
    a.link = 9;
    let mut b = file("b.txt", b"linked\n");
    b.link = 9;
    let efs = Node {
        attrs: FILE | 0x4000,
        ..file("efs.bin", b"ciphertext")
    };
    let dedup = Node {
        attrs: FILE | REPARSE,
        tag: reparse::TAG_DEDUP,
        reparse: Some(vec![0; 8]),
        data: Some(b"stub".to_vec()),
        ..file("dedup.bin", b"")
    };
    let fifo = Node {
        attrs: FILE | REPARSE,
        tag: reparse::TAG_LX_FIFO,
        reparse: Some(Vec::new()),
        ..file("fifo", b"")
    };
    let other = Node {
        attrs: FILE | REPARSE,
        tag: 0x9000_001A,
        reparse: Some(b"cloud".to_vec()),
        data: Some(b"cloud file data\n".to_vec()),
        ..file("cloud.txt", b"")
    };
    dir(
        "",
        vec![
            file("readme.txt", b"hello\n"),
            file("empty.txt", b""),
            a,
            b,
            streams,
            wof,
            efs,
            dedup,
            fifo,
            other,
            file("bad/name", b"left out"),
            symlink("rel", "readme.txt", true, 1),
            symlink("fixed", r"\??\C:\sub\deep.txt", false, 0),
            symlink("unfixed", r"\??\C:\Windows", false, 1),
            dir(
                "sub",
                vec![
                    file("deep.txt", b"deep\n"),
                    file("same.txt", b"hello\n"),
                    symlink("up-fixed", r"\??\C:\readme.txt", false, 0),
                ],
            ),
        ],
    )
}

#[test]
fn lists_streams_links_and_what_it_doesnt_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut b = Builder {
        flags: container::HDR_RP_FIX,
        extra: vec![b"nobody's".to_vec()],
        ..Builder::default()
    };
    b = b.image(rich(), "Rich");
    let path = write(tmp.path(), "rich.wim", &b.build().bytes);
    let mut r = reader(&path, 1).unwrap();
    let k = kinds(&r);
    let kind = |p: &str| k.iter().find(|(q, _)| q == p).map(|(_, k)| k.clone());
    assert_eq!(kind("readme.txt"), Some(EntryKind::File));
    assert_eq!(
        kind("b.txt"),
        Some(EntryKind::Hardlink {
            target: "a.txt".into()
        })
    );
    assert_eq!(kind("streams.txt:one"), Some(EntryKind::File));
    assert_eq!(kind("streams.txt:bad:name"), None);
    assert_eq!(kind("bad/name"), None);
    assert_eq!(
        kind("rel"),
        Some(EntryKind::Symlink {
            target: "readme.txt".into()
        })
    );
    // Fixed at capture: inside the image, relative to the link.
    assert_eq!(
        kind("fixed"),
        Some(EntryKind::Symlink {
            target: "sub/deep.txt".into()
        })
    );
    assert_eq!(
        kind("sub/up-fixed"),
        Some(EntryKind::Symlink {
            target: "../readme.txt".into()
        })
    );
    assert_eq!(
        kind("unfixed"),
        Some(EntryKind::Symlink {
            target: "/??/C:/Windows".into()
        })
    );
    assert_eq!(kind("fifo"), Some(EntryKind::Other));
    // A tag BeeZip leaves alone: the file's data.
    assert_eq!(read_all(&mut r, "cloud.txt").unwrap(), b"cloud file data\n");
    assert_eq!(
        read_all(&mut r, "streams.txt:one").unwrap(),
        b"stream one\n"
    );
    assert_eq!(read_all(&mut r, "b.txt").unwrap(), b"linked\n");
    for (p, what) in [
        ("wof.bin", "compressed by Windows (LZX)"),
        ("efs.bin", "EFS"),
        ("dedup.bin", "deduplicated"),
    ] {
        let e = read_all(&mut r, p).unwrap_err();
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{p}: {e}");
        assert!(e.message.contains(what), "{p}: {e}");
    }
    // The WOF file's stream is listed: it isn't decoded in a WIM.
    assert_eq!(kind("wof.bin:WofCompressedData"), Some(EntryKind::File));
    let info = r.info(&mut SimpleCtx::new()).unwrap();
    let ext = info.external.unwrap();
    assert_eq!(ext.levels, ["wim"]);
    assert!(
        ext.properties
            .iter()
            .any(|p| p.name == "Image 1" && p.value == "Rich")
    );
    assert!(ext.notes.iter().any(|n| n.starts_with("2 blobs no image")));
    assert!(
        ext.notes
            .iter()
            .any(|n| n.starts_with("2 links were fixed"))
    );

    // Extracted: the files BeeZip doesn't read are skipped and the rest written, a hard link as
    // a copy, a shared blob decoded once.
    for threads in [1, 4] {
        let dest = tempfile::tempdir().unwrap();
        let mut sink = FsSink::new(
            dest.path(),
            FsOptions {
                overwrite: OverwritePolicy::Always,
                ..FsOptions::default()
            },
        )
        .unwrap();
        let mut r = reader(&path, threads).unwrap();
        r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
            .unwrap();
        let report = sink.finish(&mut SimpleCtx::new()).unwrap();
        let skipped: Vec<_> = report.skipped.iter().map(|s| s.path.as_str()).collect();
        for p in ["wof.bin", "efs.bin", "dedup.bin"] {
            assert!(skipped.contains(&p), "{p}: {skipped:?}");
        }
        let read = |p: &str| std::fs::read(dest.path().join(p)).unwrap();
        assert_eq!(read("readme.txt"), b"hello\n");
        assert_eq!(read("sub/same.txt"), b"hello\n");
        assert_eq!(read("a.txt"), b"linked\n");
        assert_eq!(read("b.txt"), b"linked\n");
        assert_eq!(read("empty.txt"), b"");
    }
}

#[test]
fn several_images_are_folders_and_share_their_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    let one = dir_node(vec![
        file("same.txt", b"shared data\n"),
        file("one.txt", b"1"),
    ]);
    let two = dir_node(vec![file("same.txt", b"shared data\n")]);
    let empty = dir_node(Vec::new());
    let b = Builder::default()
        .image(one, "One")
        .image(two, "Two")
        .image(empty, "Empty");
    let path = write(tmp.path(), "multi.wim", &b.build().bytes);
    let mut r = reader(&path, 1).unwrap();
    let paths: Vec<_> = r.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        ["1", "1/same.txt", "1/one.txt", "2", "2/same.txt", "3"]
    );
    let mut sink = crate::TestSink::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    assert!(sink.report.ok(), "{:?}", sink.report);
    // The second name of the shared blob was passed as a copy of the first.
    assert_eq!(sink.report.entries, 6);
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(report.ok());
}

fn dir_node(children: Vec<Node>) -> Node {
    dir("", children)
}

#[test]
fn damage_fails_the_files_it_touches() {
    let tmp = tempfile::tempdir().unwrap();
    let b = Builder::default().image(
        dir_node(vec![
            file("good.txt", b"fine and well\n"),
            file("bad.txt", b"this will be damaged\n"),
        ]),
        "Img",
    );
    let built = b.build();
    let mut bytes = built.bytes.clone();
    let at = built.blobs[&sha1(b"this will be damaged\n")] as usize;
    bytes[at] ^= 0x20;
    let path = write(tmp.path(), "flip.wim", &bytes);
    let mut r = reader(&path, 1).unwrap();
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert_eq!(report.errors[0].path, "bad.txt");
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    assert!(report.errors[0].message.contains("SHA-1"));
    let e = read_all(&mut r, "bad.txt").unwrap_err();
    assert!(e.message.contains("`bad.txt`"), "{e}");
    assert_eq!(read_all(&mut r, "good.txt").unwrap(), b"fine and well\n");

    // Its metadata damaged: the image isn't opened.
    let mut bytes = built.bytes.clone();
    bytes[built.lookup as usize - 20] ^= 1;
    let path = write(tmp.path(), "meta.wim", &bytes);
    let e = reader(&path, 1).err().unwrap();
    assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    assert!(e.message.contains("image 1's metadata"), "{e}");
}

#[test]
fn the_integrity_table_is_checked_by_test_only() {
    let tmp = tempfile::tempdir().unwrap();
    let b = Builder {
        integrity: true,
        extra: vec![b"no image has me".to_vec()],
        ..Builder::default()
    }
    .image(dir_node(vec![file("a.txt", b"a\n")]), "Img");
    let built = b.build();
    let path = write(tmp.path(), "ok.wim", &built.bytes);
    let mut r = reader(&path, 2).unwrap();
    assert!(r.test(&mut SimpleCtx::new()).unwrap().unwrap().ok());
    // A byte no file holds: the extraction doesn't see it, the test does.
    let mut bytes = built.bytes.clone();
    bytes[built.blobs[&sha1(b"no image has me")] as usize] ^= 1;
    let path = write(tmp.path(), "bad.wim", &bytes);
    let mut r = reader(&path, 2).unwrap();
    let mut sink = crate::TestSink::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    assert!(sink.report.ok());
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert!(report.errors[0].message.contains("integrity table"));
}

#[test]
fn damaged_folders_list_the_rest_and_loops_and_depth_stop() {
    let tmp = tempfile::tempdir().unwrap();
    let broken = Node {
        bad_len: true,
        ..file("broken.txt", b"x")
    };
    let mut looped = dir("loop", Vec::new());
    looped.sub = Some(ROOT_LIST);
    // 300 folders deep.
    let mut deep = file("bottom.txt", b"bottom");
    for i in (0..300).rev() {
        deep = dir(&format!("d{i}"), vec![deep]);
    }
    let root = dir_node(vec![
        dir(
            "sub",
            vec![file("ok.txt", b"ok"), broken, file("after.txt", b"lost")],
        ),
        file("top.txt", b"top"),
        looped,
        deep,
    ]);
    let b = Builder::default().image(root, "Img");
    let path = write(tmp.path(), "broken.wim", &b.build().bytes);
    let source = Source::new(&path, Vec::new(), &opts(1)).unwrap();
    let mut cx = SimpleCtx::new();
    let r = WimReader::open(source, &mut cx).unwrap();
    let paths: Vec<_> = r.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"sub/ok.txt") && paths.contains(&"top.txt"));
    assert!(!paths.iter().any(|p| p.ends_with("after.txt")));
    assert!(!paths.iter().any(|p| p.ends_with("bottom.txt")));
    let deepest = paths.iter().map(|p| p.matches('/').count()).max().unwrap();
    assert_eq!(deepest, meta::MAX_DEPTH - 1);
    let warned = cx.warnings.join("\n");
    assert!(warned.contains("`sub`'s list is damaged"), "{warned}");
    assert!(warned.contains("isn't listed again"), "{warned}");
    assert!(warned.contains("folders deep"), "{warned}");
}

#[test]
fn what_it_doesnt_read_is_unsupported() {
    let tmp = tempfile::tempdir().unwrap();
    let built = Builder::default()
        .image(dir_node(vec![file("a.txt", b"a")]), "Img")
        .build();
    let refused = |name: &str, edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = built.bytes.clone();
        edit(&mut bytes);
        let path = write(tmp.path(), name, &bytes);
        reader(&path, 1).err().map(|e| e.kind)
    };
    // Another version; wimlib's pipable layout; unknown compression flags; a spanned resource.
    assert_eq!(
        refused("v.wim", &|b| b[12..16]
            .copy_from_slice(&0x10900u32.to_le_bytes())),
        Some(ErrorKind::UnsupportedOperation)
    );
    assert_eq!(
        refused("p.wim", &|b| b[..8].copy_from_slice(b"WLPWM\0\0\0")),
        Some(ErrorKind::UnsupportedOperation)
    );
    assert_eq!(
        refused("f.wim", &|b| b[16..20]
            .copy_from_slice(&0x10_0002u32.to_le_bytes())),
        Some(ErrorKind::UnsupportedOperation)
    );
    let lookup = built.lookup as usize;
    assert_eq!(
        refused("s.wim", &|b| b[lookup + 7] |= 0x8),
        Some(ErrorKind::UnsupportedOperation)
    );
    // A compressed lookup table, which no writer makes.
    assert_eq!(
        refused("c.wim", &|b| b[55] |= 0x4),
        Some(ErrorKind::UnsupportedOperation)
    );
    // A lookup table past the file's end is damage.
    assert_eq!(
        refused("t.wim", &|b| b[56..64]
            .copy_from_slice(&u64::MAX.to_le_bytes())),
        Some(ErrorKind::Corrupt)
    );
}

#[test]
fn blobs_that_overlap_are_corrupt() {
    let tmp = tempfile::tempdir().unwrap();
    let built = Builder::default()
        .image(
            dir_node(vec![file("a.txt", b"aaaaaaaa"), file("b.txt", b"bbbbbbbb")]),
            "Img",
        )
        .build();
    let mut bytes = built.bytes.clone();
    // b.txt's lookup entry points at a.txt's data.
    let lookup = built.lookup as usize;
    let a = built.blobs[&sha1(b"aaaaaaaa")];
    let hb = sha1(b"bbbbbbbb");
    let at = (0..)
        .map(|i| lookup + 50 * i)
        .find(|&e| bytes[e + 30..e + 50] == hb)
        .unwrap();
    bytes[at + 8..at + 16].copy_from_slice(&(a + 1).to_le_bytes());
    let path = write(tmp.path(), "overlap.wim", &bytes);
    let mut r = reader(&path, 1).unwrap();
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert!(report.errors[0].message.contains("overlaps"), "{report:?}");
}

#[test]
fn a_split_set_opens_from_any_part() {
    let tmp = tempfile::tempdir().unwrap();
    let built = Builder::default()
        .image(dir_node(vec![file("a.txt", b"in part 2\n")]), "Img")
        .build();
    // Part 2 holds a.txt's blob, part 1 the rest: its lookup entry moves to part 2's table.
    let mut one = built.bytes.clone();
    let lookup = built.lookup as usize;
    let ha = sha1(b"in part 2\n");
    let entries: Vec<Vec<u8>> = one[lookup..]
        .chunks(50)
        .take_while(|e| e.len() == 50 && (e[30..50] == ha || e[7] & 2 != 0))
        .map(<[u8]>::to_vec)
        .collect();
    let (blob_entry, meta_entry): (Vec<_>, Vec<_>) =
        entries.into_iter().partition(|e| e[30..50] == ha);
    // Part 1: its table holds the metadata only.
    one.truncate(lookup);
    one.extend_from_slice(&meta_entry[0]);
    one[48..56].copy_from_slice(&50u64.to_le_bytes());
    one[64..72].copy_from_slice(&50u64.to_le_bytes());
    one[72..96].fill(0);
    one[42..44].copy_from_slice(&2u16.to_le_bytes());
    // Part 2: a header, the blob, its table.
    let mut two = one[..HEADER_LEN].to_vec();
    two[40..42].copy_from_slice(&2u16.to_le_bytes());
    let data_at = two.len() as u64;
    two.extend_from_slice(b"in part 2\n");
    let mut e = blob_entry[0].clone();
    e[8..16].copy_from_slice(&data_at.to_le_bytes());
    e[24..26].copy_from_slice(&2u16.to_le_bytes());
    let table = two.len() as u64;
    two.extend_from_slice(&e);
    two[48..56].copy_from_slice(&50u64.to_le_bytes());
    two[56..64].copy_from_slice(&table.to_le_bytes());
    two[64..72].copy_from_slice(&50u64.to_le_bytes());
    write(tmp.path(), "set.swm", &one);
    let p2 = write(tmp.path(), "set2.swm", &two);
    let mut r = reader(&p2, 1).unwrap();
    assert_eq!(read_all(&mut r, "a.txt").unwrap(), b"in part 2\n");
    assert_eq!(r.info(&mut SimpleCtx::new()).unwrap().volumes, 2);
    // Renamed, part 2 is found by its GUID.
    std::fs::rename(&p2, tmp.path().join("other.swm")).unwrap();
    let mut r = reader(&tmp.path().join("set.swm"), 1).unwrap();
    assert_eq!(read_all(&mut r, "a.txt").unwrap(), b"in part 2\n");
    // Without it, the file can't be read, and says why.
    std::fs::remove_file(tmp.path().join("other.swm")).unwrap();
    let mut r = reader(&tmp.path().join("set.swm"), 1).unwrap();
    let e = read_all(&mut r, "a.txt").unwrap_err();
    assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
}

#[test]
fn the_limits_are_checked_before_extracting() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write(
        tmp.path(),
        "small.wim",
        &Builder::default()
            .image(dir_node(vec![file("a.txt", &[7; 5000])]), "Img")
            .build()
            .bytes,
    );
    let limits = Limits {
        max_total_bytes: Some(1000),
        ..Limits::default()
    };
    let source = Source::new(&path, Vec::new(), &OpenOptions::new(limits)).unwrap();
    let mut r = WimReader::open(source, &mut SimpleCtx::new()).unwrap();
    let e = r
        .extract(
            &Selection::all(),
            &mut crate::TestSink::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
}

/// A file of more than 4 GiB has a chunk table of 8-byte entries; read here from a file that
/// holds only the table, the rest of it reading as zeros.
#[test]
fn files_over_4_gib_have_8_byte_chunk_tables() {
    struct Sparse {
        len: u64,
        at: u64,
        table: Vec<u8>,
    }
    impl ReadAt for Sparse {
        fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
            for (i, b) in buf.iter_mut().enumerate() {
                let p = off + i as u64;
                *b = p
                    .checked_sub(self.at)
                    .and_then(|r| self.table.get(r as usize))
                    .copied()
                    .unwrap_or(0);
            }
            Ok(())
        }
    }
    let original = (5u64 << 30) + 123;
    let chunk = 32_768u64;
    let n = original.div_ceil(chunk);
    let mut table = Vec::new();
    for i in 1..n {
        table.extend_from_slice(&(i * 100).to_le_bytes());
    }
    let res_at = 4096u64;
    let size = table.len() as u64 + n * 100;
    let mut header = vec![0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    header[12..16].copy_from_slice(&VERSION_WIM.to_le_bytes());
    header[16..20].copy_from_slice(&0x4_0002u32.to_le_bytes());
    header[40..42].copy_from_slice(&1u16.to_le_bytes());
    header[42..44].copy_from_slice(&1u16.to_le_bytes());
    let mut all = header.clone();
    all.resize(res_at as usize, 0);
    all.extend_from_slice(&table);
    let input = Sparse {
        len: res_at + size,
        at: 0,
        table: all,
    };
    let part = Part {
        header: container::Header::parse(&header).unwrap(),
        len: input.len,
        input: Arc::new(input),
        path: None,
    };
    let c = Container::open(part, &mut |_| {}).unwrap();
    let res = container::Res {
        size,
        flags: 0x4,
        offset: res_at,
        original,
    };
    let mut it = c.chunks(0, &res).unwrap();
    let first = it.next(&c).unwrap().unwrap();
    assert_eq!(first.offset, res_at + table.len() as u64);
    assert_eq!(first.packed, 100);
    let second = it.next(&c).unwrap().unwrap();
    assert_eq!(second.offset, res_at + table.len() as u64 + 100);
    let mut last = second;
    for ch in std::iter::from_fn(|| it.next(&c)) {
        last = ch.unwrap();
    }
    assert_eq!(last.size, original - (n - 1) * chunk);
    assert_eq!(last.offset + last.packed, res_at + size);
}
