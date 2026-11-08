//! XAR and macOS packages (docs/M6.md §5), read by BeeZip's own reader: archives written here
//! by a small XAR writer, in every encoding and checksum, packages with gzip'd, pbzx and Apple
//! Archive payloads, and damage of each kind the reader checks for. The interop with xar,
//! bsdtar, pkgbuild and 7-Zip is the fixtures'.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, UNIX_EPOCH},
};

use beezip_core::{
    CodecId, EncodeOpts, EntryKind, ErrorKind, FinishWrite, FormatId, FsOptions, OpenOptions,
    Selection, SimpleCtx, SkipReason, detect_path,
    format::{ArchiveWriter, Entry, NewEntry, NewKind, cpio::CpioWriter},
    open, ops,
};
use sha2::Digest;

/// 2021-03-04T05:06:07Z.
const MTIME: &str = "2021-03-04T05:06:07Z";
const MTIME_SECS: u64 = 1_614_834_367;

// ---- A small XAR writer. ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Enc {
    Store,
    /// `x-gzip` as xar writes it: zlib.
    Zlib,
    /// `x-gzip` holding a real gzip stream.
    Gzip,
    Bzip2,
    Xz,
    /// `x-lzma` holding xz, as Apple's xar writes it.
    LzmaXz,
    /// `x-lzma` holding `.lzma`, as libarchive writes it.
    LzmaAlone,
}

impl Enc {
    const ALL: [Enc; 7] = [
        Enc::Store,
        Enc::Zlib,
        Enc::Gzip,
        Enc::Bzip2,
        Enc::Xz,
        Enc::LzmaXz,
        Enc::LzmaAlone,
    ];

    fn style(self) -> &'static str {
        match self {
            Enc::Store => "application/octet-stream",
            Enc::Zlib | Enc::Gzip => "application/x-gzip",
            Enc::Bzip2 => "application/x-bzip2",
            Enc::Xz => "application/x-xz",
            Enc::LzmaXz | Enc::LzmaAlone => "application/x-lzma",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Enc::Store => "Store",
            Enc::Zlib | Enc::Gzip => "Deflate",
            Enc::Bzip2 => "BZip2",
            Enc::Xz => "XZ",
            Enc::LzmaXz | Enc::LzmaAlone => "LZMA",
        }
    }

    fn encode(self, data: &[u8]) -> Vec<u8> {
        let codec = match self {
            Enc::Store => return data.to_vec(),
            Enc::Zlib => CodecId::Zlib,
            Enc::Gzip => CodecId::Gzip,
            Enc::Bzip2 => CodecId::Bzip2,
            Enc::Xz | Enc::LzmaXz => CodecId::Xz,
            Enc::LzmaAlone => CodecId::Lzma,
        };
        encode(codec, data)
    }
}

fn encode(codec: CodecId, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let opts = EncodeOpts {
        threads: 1,
        ..EncodeOpts::default()
    };
    let mut w = codec.codec().encoder(Box::new(&mut out), &opts).unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap();
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ck {
    None,
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl Ck {
    const ALL: [Ck; 5] = [Ck::None, Ck::Md5, Ck::Sha1, Ck::Sha256, Ck::Sha512];

    fn style(self) -> &'static str {
        match self {
            Ck::None => "none",
            Ck::Md5 => "md5",
            Ck::Sha1 => "sha1",
            Ck::Sha256 => "sha256",
            Ck::Sha512 => "sha512",
        }
    }

    fn digest(self, d: &[u8]) -> Vec<u8> {
        match self {
            Ck::None => Vec::new(),
            Ck::Md5 => md5::Md5::digest(d).to_vec(),
            Ck::Sha1 => sha1::Sha1::digest(d).to_vec(),
            Ck::Sha256 => sha2::Sha256::digest(d).to_vec(),
            Ck::Sha512 => sha2::Sha512::digest(d).to_vec(),
        }
    }

    /// The header's type: xar 1.6.1 writes 3 ("other") for the strong ones.
    fn header_type(self) -> u32 {
        match self {
            Ck::None => 0,
            Ck::Sha1 => 1,
            Ck::Md5 => 2,
            Ck::Sha256 | Ck::Sha512 => 3,
        }
    }
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64(d: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in d.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[derive(Debug, Clone)]
struct Node {
    id: u64,
    name: String,
    b64: bool,
    kind: &'static str,
    /// `<type link="…">`.
    link: Option<String>,
    /// A symlink's target.
    target: Option<String>,
    data: Option<Vec<u8>>,
    /// The data's encoding, when not the archive's.
    enc: Option<Enc>,
    mode: &'static str,
    children: Vec<Node>,
}

fn node(id: u64, name: &str, kind: &'static str) -> Node {
    Node {
        id,
        name: name.into(),
        b64: false,
        kind,
        link: None,
        target: None,
        data: None,
        enc: None,
        mode: if kind == "directory" { "0755" } else { "0644" },
        children: Vec::new(),
    }
}

fn file(id: u64, name: &str, data: &[u8]) -> Node {
    Node {
        data: Some(data.to_vec()),
        ..node(id, name, "file")
    }
}

fn folder(id: u64, name: &str, children: Vec<Node>) -> Node {
    Node {
        children,
        ..node(id, name, "directory")
    }
}

#[derive(Debug, Clone)]
struct Xar {
    enc: Enc,
    file_ck: Ck,
    toc_ck: Ck,
    nodes: Vec<Node>,
}

impl Xar {
    fn new(nodes: Vec<Node>) -> Self {
        Self {
            enc: Enc::Zlib,
            file_ck: Ck::Sha1,
            toc_ck: Ck::Sha1,
            nodes,
        }
    }

    /// The archive, and where each file's data lies in it.
    fn bytes(&self) -> Vec<u8> {
        let mut heap = vec![0u8; self.toc_ck.digest(b"").len()];
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n <toc>\n");
        if self.toc_ck != Ck::None {
            xml += &format!(
                "  <checksum style=\"{}\">\n   <offset>0</offset>\n   <size>{}</size>\n  </checksum>\n",
                self.toc_ck.style(),
                heap.len()
            );
        }
        xml += "  <creation-time>2026-11-07T00:00:00Z</creation-time>\n";
        for n in &self.nodes {
            self.write(n, &mut xml, &mut heap);
        }
        xml += " </toc>\n</xar>\n";
        assemble(&xml, heap, self.toc_ck)
    }

    fn write(&self, n: &Node, xml: &mut String, heap: &mut Vec<u8>) {
        *xml += &format!("<file id=\"{}\">", n.id);
        if let Some(data) = &n.data {
            let enc = n.enc.unwrap_or(self.enc);
            let packed = enc.encode(data);
            *xml += &format!(
                "<data><length>{}</length><offset>{}</offset><size>{}</size><encoding style=\"{}\"/>",
                packed.len(),
                heap.len(),
                data.len(),
                enc.style()
            );
            if self.file_ck != Ck::None {
                let s = self.file_ck.style();
                *xml += &format!(
                    "<archived-checksum style=\"{s}\">{}</archived-checksum><extracted-checksum style=\"{s}\">{}</extracted-checksum>",
                    hex(&self.file_ck.digest(&packed)),
                    hex(&self.file_ck.digest(data))
                );
            }
            *xml += "</data>";
            heap.extend_from_slice(&packed);
        }
        *xml += &format!("<mtime>{MTIME}</mtime><mode>{}</mode>", n.mode);
        if let Some(t) = &n.target {
            *xml += &format!("<link type=\"file\">{}</link>", esc(t));
        }
        match &n.link {
            Some(l) => *xml += &format!("<type link=\"{l}\">{}</type>", n.kind),
            None => *xml += &format!("<type>{}</type>", n.kind),
        }
        if n.b64 {
            *xml += &format!(
                "<name enctype=\"base64\">{}</name>",
                base64(n.name.as_bytes())
            );
        } else {
            // Apple's tools write the name twice.
            *xml += &format!("<name>{0}</name><name>{0}</name>", esc(&n.name));
        }
        for c in &n.children {
            self.write(c, xml, heap);
        }
        *xml += "</file>\n";
    }
}

/// A XAR of a table of contents and a heap, the table's checksum (at heap offset 0) filled in.
fn assemble(xml: &str, mut heap: Vec<u8>, toc_ck: Ck) -> Vec<u8> {
    let packed = encode(CodecId::Zlib, xml.as_bytes());
    let d = toc_ck.digest(&packed);
    heap[..d.len()].copy_from_slice(&d);
    let mut out = b"xar!".to_vec();
    out.extend_from_slice(&28u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(packed.len() as u64).to_be_bytes());
    out.extend_from_slice(&(xml.len() as u64).to_be_bytes());
    out.extend_from_slice(&toc_ck.header_type().to_be_bytes());
    out.extend_from_slice(&packed);
    out.extend_from_slice(&heap);
    out
}

/// A XAR whose table is `xml` as given, with an empty heap and no checksum.
fn raw_xar(xml: &str) -> Vec<u8> {
    assemble(xml, Vec::new(), Ck::None)
}

// ---- Helpers. ----

fn sha256(d: &[u8]) -> String {
    hex(&sha2::Sha256::digest(d))
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

fn entries(path: &Path) -> Vec<Entry> {
    let mut cx = SimpleCtx::new();
    let mut o = open(path, &OpenOptions::default(), &mut cx).unwrap();
    o.reader.entries(&mut cx).unwrap().to_vec()
}

fn paths(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.path.as_str()).collect()
}

fn read_entry(path: &Path, id: usize) -> beezip_core::Result<Vec<u8>> {
    let mut cx = SimpleCtx::new();
    let mut o = open(path, &OpenOptions::default(), &mut cx)?;
    let mut out = Vec::new();
    o.reader
        .open_entry(id, &mut cx)?
        .read_to_end(&mut out)
        .map_err(|e| beezip_core::io::read_error(&e))?;
    Ok(out)
}

/// The files under `dir`, with their contents' SHA-256.
fn files(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .map(Result::unwrap)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(dir).unwrap();
            (
                rel.to_string_lossy().replace('\\', "/"),
                sha256(&fs::read(e.path()).unwrap()),
            )
        })
        .collect();
    out.sort();
    out
}

fn extract(path: &Path, dest: &Path) -> beezip_core::Result<beezip_core::ExtractReport> {
    ops::extract(
        path,
        dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
}

fn test(path: &Path) -> beezip_core::TestReport {
    ops::test(
        path,
        &Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap()
}

// ---- XAR. ----

fn big() -> Vec<u8> {
    let mut big = Vec::new();
    for i in 0..20_000u32 {
        big.extend_from_slice(format!("line {i}\n").as_bytes());
    }
    let mut x = 0x2545_f491_u32;
    for _ in 0..60_000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        big.push(x as u8);
    }
    big
}

/// Every kind of entry: folders, an empty file, an escaped and a base64 name, a symlink, a
/// FIFO, and a hard link listed before the file holding its data.
fn tree() -> Vec<Node> {
    vec![
        Node {
            link: Some("11".into()),
            ..node(10, "hl2", "hardlink")
        },
        file(1, "hello.txt", b"Hello, XAR!\n"),
        folder(
            2,
            "docs",
            vec![file(3, "big.bin", &big()), node(4, "empty.bin", "file")],
        ),
        file(5, "a & b.txt", b"ampersand"),
        Node {
            b64: true,
            ..file(6, "emoji 🐝.txt", b"bee")
        },
        Node {
            target: Some("hello.txt".into()),
            mode: "0777",
            ..node(7, "link", "symlink")
        },
        node(8, "fifo", "fifo"),
        Node {
            link: Some("original".into()),
            ..file(11, "hl1", b"linked")
        },
    ]
}

const LISTED: [&str; 10] = [
    "hello.txt",
    "docs/",
    "docs/big.bin",
    "docs/empty.bin",
    "a & b.txt",
    "emoji 🐝.txt",
    "link",
    "fifo",
    "hl1",
    "hl2",
];

fn check_tree(path: &Path, method: &str) {
    let mut cx = SimpleCtx::new();
    let mut o = open(path, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(o.detection.chain(), "xar");
    let es = o.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(paths(&es), LISTED);
    let by = |p: &str| es.iter().find(|e| e.path == p).unwrap();
    assert_eq!(
        by("hl2").kind,
        EntryKind::Hardlink {
            target: "hl1".into()
        }
    );
    assert_eq!(
        by("link").kind,
        EntryKind::Symlink {
            target: "hello.txt".into()
        }
    );
    assert_eq!(by("fifo").kind, EntryKind::Other);
    assert_eq!(by("docs/").kind, EntryKind::Dir);
    assert_eq!(by("docs/").unix_mode, Some(0o040_755));
    let hello = by("hello.txt");
    assert_eq!(hello.size, Some(12));
    assert_eq!(hello.unix_mode, Some(0o100_644));
    assert_eq!(hello.method.as_deref(), Some(method));
    assert_eq!(
        hello.modified,
        Some(UNIX_EPOCH + Duration::from_secs(MTIME_SECS))
    );
    assert_eq!(by("docs/empty.bin").size, Some(0));
    let info = o.reader.info(&mut cx).unwrap();
    assert_eq!(info.format, FormatId::Xar);
    assert!(info.methods.iter().any(|m| m == method), "{info:?}");

    // Each file through open_entry, the hard link through its target.
    let want: Vec<(&str, Vec<u8>)> = vec![
        ("hello.txt", b"Hello, XAR!\n".to_vec()),
        ("docs/big.bin", big()),
        ("docs/empty.bin", Vec::new()),
        ("a & b.txt", b"ampersand".to_vec()),
        ("emoji 🐝.txt", b"bee".to_vec()),
        ("hl1", b"linked".to_vec()),
        ("hl2", b"linked".to_vec()),
    ];
    for (p, data) in &want {
        let mut got = Vec::new();
        o.reader
            .open_entry(by(p).id, &mut cx)
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, *data, "{p}");
    }

    // Extraction: every file, the hard link as a copy; the symlink and the FIFO skipped.
    let dest = tempfile::tempdir().unwrap();
    let report = extract(path, dest.path()).unwrap();
    let mut skipped: Vec<_> = report
        .skipped
        .iter()
        .map(|s| (s.path.as_str(), s.reason))
        .collect();
    skipped.sort_by_key(|s| s.0);
    assert_eq!(
        skipped,
        [
            ("fifo", SkipReason::Unsupported),
            ("link", SkipReason::LinksDisabled)
        ]
    );
    let mut want: Vec<(String, String)> = want
        .iter()
        .map(|(p, d)| ((*p).to_owned(), sha256(d)))
        .collect();
    want.sort();
    assert_eq!(files(dest.path()), want);
    let t = fs::metadata(dest.path().join("hello.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(t, UNIX_EPOCH + Duration::from_secs(MTIME_SECS));

    let report = test(path);
    assert!(report.ok(), "{:?}", report.errors);
}

#[test]
fn every_encoding_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    for enc in Enc::ALL {
        let x = Xar {
            enc,
            ..Xar::new(tree())
        };
        let path = write(dir.path(), &format!("{enc:?}.xar"), &x.bytes());
        check_tree(&path, enc.method());
    }
}

#[test]
fn every_checksum_is_checked() {
    let dir = tempfile::tempdir().unwrap();
    for ck in Ck::ALL {
        for toc_ck in Ck::ALL {
            let x = Xar {
                file_ck: ck,
                toc_ck,
                ..Xar::new(tree())
            };
            let path = write(dir.path(), &format!("{ck:?}-{toc_ck:?}.xar"), &x.bytes());
            check_tree(&path, "Deflate");
        }
    }
}

/// Where `needle` is in `hay`, once.
fn find(hay: &[u8], needle: &[u8]) -> usize {
    let at: Vec<usize> = hay
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 1, "{:?}", String::from_utf8_lossy(needle));
    at[0]
}

#[test]
fn a_bad_file_checksum_is_corrupt_and_names_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    for ck in [Ck::Md5, Ck::Sha1, Ck::Sha256, Ck::Sha512] {
        // Stored: the damage reaches the checksums, not a decoder.
        let x = Xar {
            enc: Enc::Store,
            file_ck: ck,
            ..Xar::new(tree())
        };
        let mut bytes = x.bytes();
        let at = find(&bytes, b"line 12345\n");
        bytes[at + 5] = b'X';
        let path = write(dir.path(), &format!("bad-{ck:?}.xar"), &bytes);
        let report = test(&path);
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        let e = &report.errors[0];
        assert_eq!(e.path, "docs/big.bin");
        assert_eq!(e.kind, ErrorKind::Corrupt);
        assert!(e.message.contains("checksum"), "{}", e.message);
        // Extraction stops at it, naming it.
        let dest = tempfile::tempdir().unwrap();
        let err = extract(&path, dest.path()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Corrupt);
        assert!(err.message.contains("docs/big.bin"), "{}", err.message);
        // So does reading it alone; the others read.
        let es = entries(&path);
        let id = es.iter().position(|e| e.path == "docs/big.bin").unwrap();
        assert_eq!(read_entry(&path, id).unwrap_err().kind, ErrorKind::Corrupt);
        assert_eq!(read_entry(&path, 0).unwrap(), b"Hello, XAR!\n");
    }

    // Compressed: the damage fails the decoder or the checksum, either naming the entry.
    for enc in [Enc::Zlib, Enc::Bzip2, Enc::Xz] {
        let x = Xar {
            enc,
            ..Xar::new(vec![file(1, "a.bin", &big()), file(2, "b.txt", b"fine")])
        };
        let mut bytes = x.bytes();
        let n = bytes.len();
        // a.bin's data is the heap's first after the table's checksum, and much the largest.
        bytes[n - 2000] ^= 0x55;
        let path = write(dir.path(), &format!("bad-{enc:?}.xar"), &bytes);
        let report = test(&path);
        assert_eq!(report.errors.len(), 1, "{enc:?}: {:?}", report.errors);
        assert_eq!(report.errors[0].path, "a.bin");
        assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    }
}

#[test]
fn sizes_and_extracted_checksums_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let good = Xar::new(vec![file(1, "a.txt", b"hello")]).bytes();
    let xml_of = |b: &[u8]| {
        let packed = &b[28..28 + u64::from_be_bytes(b[8..16].try_into().unwrap()) as usize];
        let mut xml = String::new();
        flate2::read::ZlibDecoder::new(packed)
            .read_to_string(&mut xml)
            .unwrap();
        xml
    };
    let heap =
        |b: &[u8]| b[28 + u64::from_be_bytes(b[8..16].try_into().unwrap()) as usize..].to_vec();
    let xml = xml_of(&good);
    for (what, from, to) in [
        ("size", "<size>5</size>", "<size>4</size>"),
        ("size", "<size>5</size>", "<size>6</size>"),
        (
            "extracted",
            "<extracted-checksum style=\"sha1\">a",
            "<extracted-checksum style=\"sha1\">b",
        ),
        ("length", "<length>", "<length>1"),
    ] {
        let bad = assemble(&xml.replacen(from, to, 1), heap(&good), Ck::Sha1);
        let path = write(dir.path(), "bad.xar", &bad);
        match open(&path, &OpenOptions::default(), &mut SimpleCtx::new()) {
            // A length past the end fails on open.
            Err(e) => assert_eq!((what, e.kind), ("length", ErrorKind::Corrupt), "{e}"),
            Ok(_) => {
                let report = test(&path);
                assert_eq!(report.errors.len(), 1, "{what}");
                assert_eq!(report.errors[0].path, "a.txt");
                assert_eq!(report.errors[0].kind, ErrorKind::Corrupt, "{what}");
            }
        }
    }
}

#[test]
fn a_bad_table_checksum_lists_but_reads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    for ck in [Ck::Md5, Ck::Sha1, Ck::Sha256, Ck::Sha512] {
        let x = Xar {
            toc_ck: ck,
            ..Xar::new(tree())
        };
        let mut bytes = x.bytes();
        let heap = 28 + u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
        bytes[heap] ^= 1;
        let path = write(dir.path(), &format!("toc-{ck:?}.xar"), &bytes);
        let mut cx = SimpleCtx::new();
        let mut o = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        assert_eq!(paths(o.reader.entries(&mut cx).unwrap()), LISTED);
        assert!(
            cx.warnings.iter().any(|w| w.contains("checksum")),
            "{:?}",
            cx.warnings
        );
        assert_eq!(
            o.reader.open_entry(0, &mut cx).err().unwrap().kind,
            ErrorKind::Corrupt
        );
        let report = test(&path);
        assert!(!report.ok());
        assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
        let dest = tempfile::tempdir().unwrap();
        assert_eq!(
            extract(&path, dest.path()).unwrap_err().kind,
            ErrorKind::Corrupt
        );
        assert!(files(dest.path()).is_empty());
    }
}

#[test]
fn damaged_tables_are_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let ok = "<?xml version=\"1.0\"?><xar><toc><file id=\"1\"><name>a</name><type>directory</type></file></toc></xar>";
    let path = write(dir.path(), "ok.xar", &raw_xar(ok));
    assert_eq!(paths(&entries(&path)), ["a/"]);

    let deep = format!(
        "<xar><toc>{}{}</toc></xar>",
        "<file><name>d</name><type>directory</type>".repeat(2000),
        "</file>".repeat(2000)
    );
    let long_name = format!(
        "<xar><toc><file><name>{}</name></file></toc></xar>",
        "n".repeat(2 << 20)
    );
    let cases: Vec<(&str, String)> = vec![
        ("billion laughs", BILLION_LAUGHS.to_owned()),
        ("unknown entity", "<xar><toc><file><name>&nope;</name></file></toc></xar>".into()),
        ("no name", "<xar><toc><file id=\"1\"><type>file</type></file></toc></xar>".into()),
        ("unclosed", "<xar><toc><file><name>a</name></file>".into()),
        ("mismatched", "<xar><toc><file><name>a</name></toc></file></xar>".into()),
        ("no toc", "<xar></xar>".into()),
        ("not xml", "\u{1}\u{2}garbage".into()),
        ("deep", deep),
        ("long name", long_name),
        (
            "link to nothing",
            "<xar><toc><file id=\"1\"><name>l</name><type link=\"9\">hardlink</type></file></toc></xar>".into(),
        ),
        (
            "data without offset",
            "<xar><toc><file id=\"1\"><name>f</name><data><length>1</length><size>1</size></data></file></toc></xar>".into(),
        ),
        (
            "data past the end",
            "<xar><toc><file id=\"1\"><name>f</name><data><offset>0</offset><length>1</length><size>1</size></data></file></toc></xar>".into(),
        ),
    ];
    for (what, xml) in cases {
        let path = write(dir.path(), "bad.xar", &raw_xar(&xml));
        let t = Instant::now();
        let e = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
            .err()
            .unwrap_or_else(|| panic!("{what} opened"));
        assert_eq!(e.kind, ErrorKind::Corrupt, "{what}: {e}");
        assert!(t.elapsed() < Duration::from_secs(5), "{what}");
    }

    // The header's lengths: a table longer or shorter than it says, and one past the limits.
    let good = raw_xar(ok);
    for (at, value) in [(16, 10u64), (16, ok.len() as u64 + 1), (8, 3)] {
        let mut bad = good.clone();
        bad[at..at + 8].copy_from_slice(&value.to_be_bytes());
        let path = write(dir.path(), "bad.xar", &bad);
        let e = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
            .err()
            .unwrap();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{at}={value}: {e}");
    }
    let mut huge = good.clone();
    huge[16..24].copy_from_slice(&(4u64 << 30).to_be_bytes());
    let path = write(dir.path(), "huge.xar", &huge);
    let e = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    // Cut short anywhere.
    let x = Xar::new(tree()).bytes();
    for cut in [10, 30, 100, x.len() / 2] {
        let path = write(dir.path(), "cut.xar", &x[..cut]);
        assert!(
            open(&path, &OpenOptions::default(), &mut SimpleCtx::new()).is_err()
                || !test(&path).ok(),
            "cut at {cut}"
        );
    }
}

const BILLION_LAUGHS: &str = "<?xml version=\"1.0\"?>\n<!DOCTYPE xar [\n<!ENTITY a \"aaaaaaaaaa\">\n<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">\n<!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">\n<!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\">\n<!ENTITY e \"&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;\">\n<!ENTITY f \"&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;\">\n<!ENTITY g \"&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;\">\n<!ENTITY h \"&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;\">\n<!ENTITY i \"&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;\">\n]>\n<xar><toc><file id=\"1\"><name>&i;</name><type>file</type></file></toc></xar>\n";

#[test]
fn a_xar_inside_a_codec_is_spooled() {
    let dir = tempfile::tempdir().unwrap();
    let x = Xar::new(tree()).bytes();
    let path = write(dir.path(), "t.xar.gz", &encode(CodecId::Gzip, &x));
    let det = detect_path(&path, &beezip_core::Limits::default()).unwrap();
    assert_eq!(det.chain(), "gzip → xar");
    assert_eq!(paths(&entries(&path)), LISTED);
    assert_eq!(read_entry(&path, 2).unwrap(), big());
    assert!(test(&path).ok());
}

// ---- macOS packages. ----

/// A FinishWrite into a Vec, for an uncompressed cpio.
struct Plain<'a>(&'a mut Vec<u8>);

impl Write for Plain<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl FinishWrite for Plain<'_> {
    fn finish(self: Box<Self>) -> io::Result<()> {
        Ok(())
    }
}

/// `(path, data)`: a folder when `data` is `None`, a symlink when it starts with `->`.
type Members<'a> = &'a [(&'a str, Option<&'a [u8]>)];

/// A newc cpio from BeeZip's own writer, gzip'd with its own codec when `gzip`.
fn cpio(members: Members<'_>, gzip: bool) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let sink: Box<dyn FinishWrite + '_> = if gzip {
            let opts = EncodeOpts {
                threads: 1,
                ..EncodeOpts::default()
            };
            CodecId::Gzip
                .codec()
                .encoder(Box::new(&mut out), &opts)
                .unwrap()
        } else {
            Box::new(Plain(&mut out))
        };
        let mut w = Box::new(CpioWriter::new(sink));
        let mut cx = SimpleCtx::new();
        for (path, data) in members {
            let (kind, data) = match data {
                None => (NewKind::Dir, &b""[..]),
                Some(d) if d.starts_with(b"->") => (
                    NewKind::Symlink {
                        target: String::from_utf8(d[2..].to_vec()).unwrap(),
                    },
                    &b""[..],
                ),
                Some(d) => (NewKind::File, *d),
            };
            let e = NewEntry {
                path: (*path).into(),
                kind,
                size: data.len() as u64,
                modified: Some(UNIX_EPOCH + Duration::from_secs(MTIME_SECS)),
                unix_mode: Some(if data.is_empty() { 0o755 } else { 0o644 }),
                dos_attrs: None,
                source: None,
            };
            w.add(&e, &mut &data[..], &mut cx).unwrap();
        }
        w.finish(&mut cx).unwrap();
    }
    out
}

/// An odc cpio, as Apple's tools write payloads, gzip'd.
fn odc(members: Members<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut add = |name: &str, mode: u32, data: &[u8]| {
        out.extend_from_slice(
            format!(
                "070707{:06o}{:06o}{mode:06o}{:06o}{:06o}{:06o}{:06o}{MTIME_SECS:011o}{:06o}{:011o}",
                0,
                out.len() % 0o777_777,
                0,
                0,
                1,
                0,
                name.len() + 1,
                data.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(data);
    };
    for (path, data) in members {
        match data {
            None => add(path, 0o040_755, b""),
            Some(d) => add(path, 0o100_755, d),
        }
    }
    add("TRAILER!!!", 0, b"");
    encode(CodecId::Gzip, &out)
}

/// A pbzx of `data`: an xz chunk, then a stored one.
fn pbzx(data: &[u8]) -> Vec<u8> {
    let (a, b) = data.split_at(data.len() / 2);
    let mut out = b"pbzx".to_vec();
    out.extend_from_slice(&(1u64 << 24).to_be_bytes());
    let xz = encode(CodecId::Xz, a);
    for (raw, body) in [(a, &xz[..]), (b, b)] {
        out.extend_from_slice(&(raw.len() as u64).to_be_bytes());
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

const PAYLOAD: Members<'static> = &[
    (".", None),
    ("./usr", None),
    ("./usr/bin", None),
    ("./usr/bin/tool", Some(b"#!/bin/sh\necho tool\n")),
    ("./usr/bin/t", Some(b"->tool")),
    ("./usr/share/doc.txt", Some(b"the docs")),
];
const SCRIPTS: Members<'static> = &[(".", None), ("./postinstall", Some(b"#!/bin/sh\nexit 0\n"))];

fn stored(id: u64, name: &str, data: &[u8]) -> Node {
    Node {
        enc: Some(Enc::Store),
        ..file(id, name, data)
    }
}

fn component() -> Vec<Node> {
    vec![
        file(1, "Bom", b"BOMStore fake bom"),
        stored(2, "Payload", &cpio(PAYLOAD, true)),
        stored(3, "Scripts", &odc(SCRIPTS)),
        file(
            4,
            "PackageInfo",
            b"<pkg-info identifier=\"com.example.tool\"/>",
        ),
    ]
}

const COMPONENT_LISTED: [&str; 10] = [
    "Bom",
    "Payload/",
    "Payload/usr/",
    "Payload/usr/bin/",
    "Payload/usr/bin/tool",
    "Payload/usr/bin/t",
    "Payload/usr/share/doc.txt",
    "Scripts/",
    "Scripts/postinstall",
    "PackageInfo",
];

#[test]
fn a_component_package_lists_as_pkgutil_expands_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "tool.pkg", &Xar::new(component()).bytes());
    let mut cx = SimpleCtx::new();
    let mut o = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(o.detection.chain(), "pkg");
    let es = o.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(paths(&es), COMPONENT_LISTED);
    // The folder is the cpio's `.`.
    assert_eq!(es[1].unix_mode, Some(0o040_755));
    assert_eq!(
        es[1].modified,
        Some(UNIX_EPOCH + Duration::from_secs(MTIME_SECS))
    );
    assert_eq!(
        es[5].kind,
        EntryKind::Symlink {
            target: "tool".into()
        }
    );
    assert_eq!(es[6].size, Some(8));
    let info = o.reader.info(&mut cx).unwrap();
    assert_eq!(info.format, FormatId::Pkg);
    assert_eq!(info.methods, ["Deflate", "Store", "gzip"]);
    assert!(cx.warnings.is_empty(), "{:?}", cx.warnings);
    // A member, and a XAR file, by open_entry.
    let mut data = String::new();
    o.reader
        .open_entry(8, &mut cx)
        .unwrap()
        .read_to_string(&mut data)
        .unwrap();
    assert_eq!(data, "#!/bin/sh\nexit 0\n");
    drop(o);
    assert_eq!(read_entry(&path, 6).unwrap(), b"the docs");
    assert_eq!(
        read_entry(&path, 9).unwrap(),
        b"<pkg-info identifier=\"com.example.tool\"/>"
    );

    let dest = tempfile::tempdir().unwrap();
    let report = extract(&path, dest.path()).unwrap();
    assert_eq!(report.skipped.len(), 1, "{:?}", report.skipped);
    assert_eq!(
        files(dest.path()),
        [
            ("Bom".to_owned(), sha256(b"BOMStore fake bom")),
            (
                "PackageInfo".to_owned(),
                sha256(b"<pkg-info identifier=\"com.example.tool\"/>")
            ),
            (
                "Payload/usr/bin/tool".to_owned(),
                sha256(b"#!/bin/sh\necho tool\n")
            ),
            ("Payload/usr/share/doc.txt".to_owned(), sha256(b"the docs")),
            (
                "Scripts/postinstall".to_owned(),
                sha256(b"#!/bin/sh\nexit 0\n")
            ),
        ]
    );
    let report = test(&path);
    assert!(report.ok(), "{:?}", report.errors);
    assert_eq!(report.entries, 10);

    // The same file named `.xar` is a XAR, listed as one.
    let as_xar = write(dir.path(), "tool.xar", &fs::read(&path).unwrap());
    assert_eq!(
        paths(&entries(&as_xar)),
        ["Bom", "Payload", "Scripts", "PackageInfo"]
    );
}

#[test]
fn a_product_archive_expands_each_component() {
    let dir = tempfile::tempdir().unwrap();
    let nodes = vec![
        file(1, "Distribution", b"<installer-gui-script/>"),
        folder(
            2,
            "Resources",
            vec![folder(3, "en.lproj", vec![file(4, "Welcome.txt", b"hi")])],
        ),
        folder(
            5,
            "tool.pkg",
            vec![
                file(6, "Bom", b"bom"),
                // Apple's own: pbzx, without a `.`.
                stored(7, "Payload", &pbzx(&cpio(&PAYLOAD[1..], false))),
                stored(8, "Scripts", &odc(SCRIPTS)),
                file(9, "PackageInfo", b"<pkg-info/>"),
            ],
        ),
        folder(
            10,
            "new.pkg",
            vec![
                file(11, "PackageInfo", b"<pkg-info/>"),
                // macOS 12's `--compression latest`: Apple Archive, LZFSE-compressed.
                stored(12, "Payload", b"pbze\0\0\0\0\0\x10\0\0not expanded"),
            ],
        ),
        folder(
            13,
            "odd.pkg",
            vec![
                file(14, "PackageInfo", b"<pkg-info/>"),
                stored(15, "Payload", b"neither cpio nor anything else"),
            ],
        ),
    ];
    let path = write(dir.path(), "product.pkg", &Xar::new(nodes).bytes());
    let mut cx = SimpleCtx::new();
    let mut o = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(o.detection.chain(), "pkg");
    let es = o.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(
        paths(&es),
        [
            "Distribution",
            "Resources/",
            "Resources/en.lproj/",
            "Resources/en.lproj/Welcome.txt",
            "tool.pkg/",
            "tool.pkg/Bom",
            "tool.pkg/Payload/",
            "tool.pkg/Payload/usr/",
            "tool.pkg/Payload/usr/bin/",
            "tool.pkg/Payload/usr/bin/tool",
            "tool.pkg/Payload/usr/bin/t",
            "tool.pkg/Payload/usr/share/doc.txt",
            "tool.pkg/Scripts/",
            "tool.pkg/Scripts/postinstall",
            "tool.pkg/PackageInfo",
            "new.pkg/",
            "new.pkg/PackageInfo",
            "new.pkg/Payload",
            "odd.pkg/",
            "odd.pkg/PackageInfo",
            "odd.pkg/Payload",
        ]
    );
    // Without a `.`, the folder takes the Payload file's time.
    assert_eq!(
        es[6].modified,
        Some(UNIX_EPOCH + Duration::from_secs(MTIME_SECS))
    );
    assert_eq!(cx.warnings.len(), 2, "{:?}", cx.warnings);
    assert!(cx.warnings[0].contains("new.pkg/Payload") && cx.warnings[0].contains("Apple Archive"));
    assert!(cx.warnings[1].contains("odd.pkg/Payload"));
    let info = o.reader.info(&mut cx).unwrap();
    assert_eq!(
        info.methods,
        ["Deflate", "Store", "pbzx", "gzip", "Apple Archive"]
    );
    drop(o);
    assert_eq!(read_entry(&path, 11).unwrap(), b"the docs");
    assert_eq!(
        read_entry(&path, 17).unwrap(),
        b"pbze\0\0\0\0\0\x10\0\0not expanded"
    );

    let dest = tempfile::tempdir().unwrap();
    extract(&path, dest.path()).unwrap();
    let got: Vec<String> = files(dest.path()).into_iter().map(|(p, _)| p).collect();
    assert_eq!(
        got,
        [
            "Distribution",
            "Resources/en.lproj/Welcome.txt",
            "new.pkg/PackageInfo",
            "new.pkg/Payload",
            "odd.pkg/PackageInfo",
            "odd.pkg/Payload",
            "tool.pkg/Bom",
            "tool.pkg/PackageInfo",
            "tool.pkg/Payload/usr/bin/tool",
            "tool.pkg/Payload/usr/share/doc.txt",
            "tool.pkg/Scripts/postinstall",
        ]
    );
    assert!(test(&path).ok());
}

#[test]
fn a_damaged_payload_fails_its_test() {
    let dir = tempfile::tempdir().unwrap();
    // The payload stored without compression, so a flipped byte reaches only the checksums.
    let nodes = vec![
        file(1, "PackageInfo", b"<pkg-info/>"),
        stored(2, "Payload", &cpio(PAYLOAD, false)),
    ];
    let mut bytes = Xar::new(nodes).bytes();
    let at = find(&bytes, b"the docs");
    bytes[at] = b'T';
    let path = write(dir.path(), "bad.pkg", &bytes);
    // Listing reads the payload's headers only.
    assert_eq!(entries(&path).len(), 7);
    let report = test(&path);
    assert!(!report.ok());
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    assert!(
        report.errors[0].message.contains("Payload"),
        "{:?}",
        report.errors
    );
}

/// A newc member, for hard links: BeeZip's writer gives every file its own inode.
fn newc(name: &str, mode: u32, nlink: u32, ino: u32, data: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "070701{ino:08X}{mode:08X}{:08X}{:08X}{nlink:08X}{MTIME_SECS:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
        0,
        0,
        data.len(),
        0,
        1,
        0,
        0,
        name.len() + 1,
        0
    )
    .into_bytes();
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

#[test]
fn newc_hard_links_in_a_payload_follow_their_data() {
    let dir = tempfile::tempdir().unwrap();
    let payload = [
        newc(".", 0o040_755, 2, 1, b""),
        newc("./a", 0o100_644, 3, 7, b""),
        newc("./b", 0o100_644, 3, 7, b""),
        newc("./c", 0o100_644, 3, 7, b"shared"),
        newc("./d", 0o100_644, 1, 8, b"own"),
        newc("./e", 0o100_644, 2, 9, b""),
        newc("TRAILER!!!", 0, 1, 0, b""),
    ]
    .concat();
    let nodes = vec![
        file(1, "PackageInfo", b"<pkg-info/>"),
        stored(2, "Payload", &encode(CodecId::Gzip, &payload)),
    ];
    let path = write(dir.path(), "links.pkg", &Xar::new(nodes).bytes());
    let es = entries(&path);
    let link = |t: &str| EntryKind::Hardlink { target: t.into() };
    let got: Vec<(&str, EntryKind)> = es
        .iter()
        .map(|e| (e.path.as_str(), e.kind.clone()))
        .collect();
    assert_eq!(
        got,
        [
            ("PackageInfo", EntryKind::File),
            ("Payload/", EntryKind::Dir),
            ("Payload/c", EntryKind::File),
            ("Payload/a", link("Payload/c")),
            ("Payload/b", link("Payload/c")),
            ("Payload/d", EntryKind::File),
            // A group that never had its data: an empty file.
            ("Payload/e", EntryKind::File),
        ]
    );
    assert_eq!(read_entry(&path, 3).unwrap(), b"shared");
    let dest = tempfile::tempdir().unwrap();
    extract(&path, dest.path()).unwrap();
    let shared = sha256(b"shared");
    assert_eq!(
        files(dest.path()),
        [
            ("PackageInfo".to_owned(), sha256(b"<pkg-info/>")),
            ("Payload/a".to_owned(), shared.clone()),
            ("Payload/b".to_owned(), shared.clone()),
            ("Payload/c".to_owned(), shared),
            ("Payload/d".to_owned(), sha256(b"own")),
            ("Payload/e".to_owned(), sha256(b"")),
        ]
    );
    assert!(test(&path).ok());
}

#[test]
fn files_sharing_part_of_their_data_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = |id: u32, name: &str, offset: u32, length: u32| {
        format!(
            "<file id=\"{id}\"><name>{name}</name><data><offset>{offset}</offset>\
             <length>{length}</length><size>{length}</size></data></file>"
        )
    };
    let xar = |files: &[String]| {
        assemble(
            &format!("<xar><toc>{}</toc></xar>", files.concat()),
            b"0123456789".to_vec(),
            Ck::None,
        )
    };
    // The same range twice is xar's `--link-same`.
    let path = write(
        dir.path(),
        "same.xar",
        &xar(&[f(1, "a", 0, 10), f(2, "b", 0, 10), f(3, "c", 0, 0)]),
    );
    assert_eq!(read_entry(&path, 1).unwrap(), b"0123456789");
    // Part of a range is the overlapping-entry bomb.
    let path = write(
        dir.path(),
        "overlap.xar",
        &xar(&[f(1, "a", 0, 6), f(2, "b", 4, 6)]),
    );
    let e = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(e.kind, ErrorKind::Unsafe, "{e}");

    // Many copies of one stream that decodes to a lot: past the ratio limit, unless it's off.
    let bomb = encode(CodecId::Xz, &vec![0u8; 64 << 20]);
    let copies: String = (0..64)
        .map(|i| {
            format!(
                "<file id=\"{i}\"><name>c{i}</name><data><offset>0</offset><length>{}</length>\
                 <size>{}</size><encoding style=\"application/x-xz\"/></data></file>",
                bomb.len(),
                64 << 20
            )
        })
        .collect();
    let bytes = assemble(&format!("<xar><toc>{copies}</toc></xar>"), bomb, Ck::None);
    let path = write(dir.path(), "copies.xar", &bytes);
    let e = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(e.kind, ErrorKind::LimitExceeded, "{e}");
    let unlimited = OpenOptions::new(beezip_core::Limits::unlimited());
    let mut cx = SimpleCtx::new();
    let mut o = open(&path, &unlimited, &mut cx).unwrap();
    assert_eq!(o.reader.entries(&mut cx).unwrap().len(), 64);
}

#[test]
fn a_payload_named_twice_is_expanded_once() {
    let dir = tempfile::tempdir().unwrap();
    let payload = cpio(PAYLOAD, true);
    // Two components whose Payloads are the same bytes in the heap.
    let mut xml = String::from("<xar><toc>");
    for (id, name) in [(1, "a.pkg"), (3, "b.pkg")] {
        xml += &format!(
            "<file id=\"{id}\"><name>{name}</name><type>directory</type>\
             <file id=\"{}\"><name>Payload</name><data><offset>0</offset><length>{2}</length>\
             <size>{2}</size></data></file>\
             <file id=\"{}\"><name>PackageInfo</name></file></file>",
            id * 10,
            id * 10 + 1,
            payload.len()
        );
    }
    xml += "</toc></xar>";
    let path = write(
        dir.path(),
        "twice.pkg",
        &assemble(&xml, payload.clone(), Ck::None),
    );
    let mut cx = SimpleCtx::new();
    let mut o = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(o.detection.chain(), "pkg");
    let es = o.reader.entries(&mut cx).unwrap().to_vec();
    assert!(paths(&es).contains(&"a.pkg/Payload/usr/bin/tool"));
    assert!(paths(&es).contains(&"b.pkg/Payload"));
    assert_eq!(cx.warnings.len(), 1, "{:?}", cx.warnings);
    assert!(cx.warnings[0].contains("b.pkg/Payload"));
}
