//! ACE (docs/M6.md §4, §10): unarc-rs's three samples, whose contents acefile 0.6.14 and unace
//! 2.5 agree on, and archives built here byte by byte, LZ77 included, for what the samples
//! don't have: folders, names in the OEM code page, damage, passwords, ACE 2.0's modes, sets
//! built here and an ACE inside gzip. No ACE writer runs here (WinACE isn't installed, by the
//! rules). With `BEEZIP_ACE_OUT` naming a folder, the built archives are copied there for a
//! look with acefile or unace.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use beezip_core::{
    Ctx, EntryKind, ErrorKind, FsOptions, OpenOptions, OverwriteChoice, Progress, Selection,
    SimpleCtx, TestReport,
    format::{Encryption, ace},
    open, ops,
    time::{DosTime, from_dos},
};

// ---- the samples ----

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty/unarc/ace")
        .join(name)
}

/// The text the two license samples hold: unarc-rs's Apache license.
fn apache() -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/thirdparty/unarc/LICENSE-APACHE"),
    )
    .unwrap()
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn extract_to(archive: &Path, dest: &Path, cx: &mut dyn Ctx) -> beezip_core::ExtractReport {
    ops::extract(
        archive,
        dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        cx,
    )
    .unwrap()
}

fn test(archive: &Path, cx: &mut dyn Ctx) -> beezip_core::Result<TestReport> {
    ops::test(archive, &Selection::all(), &OpenOptions::default(), cx)
}

fn read_entry(archive: &Path, id: usize, cx: &mut dyn Ctx) -> beezip_core::Result<Vec<u8>> {
    let mut opened = open(archive, &OpenOptions::default(), cx)?;
    let mut out = Vec::new();
    opened
        .reader
        .open_entry(id, cx)?
        .read_to_end(&mut out)
        .map_err(|e| beezip_core::Error::from_io(&e))?;
    Ok(out)
}

fn names(archive: &Path) -> Vec<String> {
    let mut cx = SimpleCtx::new();
    let mut opened = open(archive, &OpenOptions::default(), &mut cx).unwrap();
    opened
        .reader
        .entries(&mut cx)
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect()
}

#[test]
fn the_license_samples_match_acefile() {
    let text = apache();
    for (name, method) in [("license1.ace", "ACE 1.0"), ("license2.ace", "ACE 2.0")] {
        let path = fixture(name);
        let mut cx = SimpleCtx::new();
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 1, "{name}");
        let e = &entries[0];
        assert_eq!(e.path, "LICENSE");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, Some(11_357));
        assert_eq!(e.packed_size, Some(3_952));
        assert_eq!(e.method.as_deref(), Some(method));
        assert_eq!(e.crc32, Some(crc32fast::hash(&text)));
        assert_eq!(e.dos_attrs, Some(0x20));
        // 2024-05-16 23:08:26, local time.
        let when = from_dos(DosTime {
            date: 0x58B0,
            time: 0xB90D,
        });
        assert_eq!(e.modified, when);
        let info = opened.reader.info(&mut cx).unwrap();
        assert!(info.solid);
        assert_eq!(info.volumes, 1);
        assert_eq!(info.methods, [method]);
        assert_eq!(info.encryption, Encryption::None);

        let dir = tempfile::tempdir().unwrap();
        let report = extract_to(&path, dir.path(), &mut SimpleCtx::new());
        assert_eq!(report.files, 1);
        assert_eq!(
            fs::read(dir.path().join("LICENSE")).unwrap(),
            text,
            "{name}"
        );
        let tested = test(&path, &mut SimpleCtx::new()).unwrap();
        assert!(tested.ok(), "{name}: {tested:?}");
        assert_eq!(tested.bytes, 11_357);
        assert_eq!(read_entry(&path, 0, &mut SimpleCtx::new()).unwrap(), text);
    }
}

/// `UNARC`, 4 007 168 bytes of an x86-64 ELF, one solid LZ77 stream split across three parts.
/// Its SHA-256 is acefile's and unace's.
const UNARC_SHA256: &str = "37b58726e3edce686c8068888528f4439d6dcb7a3ebe3971f058ecdf49055445";

#[test]
fn the_volume_set_decodes_across_its_parts() {
    for first in ["unarc.ace", "unarc.c00", "unarc.c01"] {
        let path = fixture(first);
        let mut cx = SimpleCtx::new();
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 1, "{first}");
        assert_eq!(entries[0].path, "UNARC");
        assert_eq!(entries[0].size, Some(4_007_168));
        assert_eq!(entries[0].packed_size, Some(599_929 + 599_929 + 286_818));
        // The whole entry's CRC is in its last part's header.
        assert_eq!(entries[0].crc32, Some(!0xF325_9889));
        let info = opened.reader.info(&mut cx).unwrap();
        assert_eq!(info.volumes, 3, "{first}");
        assert!(info.solid);

        let mut cx = SimpleCtx::new();
        let dir = tempfile::tempdir().unwrap();
        extract_to(&path, dir.path(), &mut cx);
        let data = fs::read(dir.path().join("UNARC")).unwrap();
        assert_eq!(sha256(&data), UNARC_SHA256, "{first}");
        // Progress counts all three parts.
        let p: Progress = cx.last_progress.clone().unwrap();
        assert_eq!(p.bytes_total, Some(600_000 + 600_000 + 286_889));
        assert_eq!(p.bytes_done, p.bytes_total.unwrap());
    }
    assert!(
        test(&fixture("unarc.c00"), &mut SimpleCtx::new())
            .unwrap()
            .ok()
    );
    let data = read_entry(&fixture("unarc.ace"), 0, &mut SimpleCtx::new()).unwrap();
    assert_eq!(sha256(&data), UNARC_SHA256);
}

// ---- building archives ----

const MAIN: u8 = 0;
const FILE32: u8 = 1;
const FILE64: u8 = 3;
const ADDSIZE: u16 = 1;
const COMMENT: u16 = 1 << 1;
const WIDE: u16 = 1 << 2;
const MULTIVOLUME: u16 = 1 << 11;
const CONTPREV: u16 = 1 << 12;
const CONTNEXT: u16 = 1 << 13;
const PASSWORD: u16 = 1 << 14;
const SOLID: u16 = 1 << 15;
const STORED: u8 = 0;
const LZ77: u8 = 1;
const BLOCKED: u8 = 2;
/// 2026-01-01 00:00:00 as a DOS date and time.
const DOS: u32 = (((2026 - 1980) << 9 | 1 << 5 | 1) << 16) as u32;

fn ace_crc(data: &[u8]) -> u32 {
    !crc32fast::hash(data)
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = (ace_crc(body) as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn main_header(flags: u16, volume: u8, comment: Option<&[u8]>) -> Vec<u8> {
    let mut b = vec![MAIN];
    b.extend_from_slice(&(flags | if comment.is_some() { COMMENT } else { 0 }).to_le_bytes());
    b.extend_from_slice(b"**ACE**");
    b.extend_from_slice(&[20, 20, 2, volume]);
    b.extend_from_slice(&DOS.to_le_bytes());
    b.extend_from_slice(&[0; 8]);
    if let Some(c) = comment {
        b.extend_from_slice(&(c.len() as u16).to_le_bytes());
        b.extend_from_slice(c);
    }
    framed(&b)
}

/// An entry as built: its name bytes, attributes, method and data as stored.
#[derive(Clone)]
struct Item {
    name: Vec<u8>,
    attribs: u32,
    method: u8,
    /// The data, before packing.
    data: Vec<u8>,
    /// What's stored: the data itself for stored entries.
    packed: Vec<u8>,
    flags: u16,
    crc: u32,
    /// A 64-bit header (type 3).
    wide: bool,
}

impl Item {
    fn stored(name: &str, data: &[u8]) -> Self {
        Self::raw(name.as_bytes(), STORED, data, data.to_vec())
    }

    fn raw(name: &[u8], method: u8, data: &[u8], packed: Vec<u8>) -> Self {
        Self {
            name: name.to_vec(),
            attribs: 0x20,
            method,
            data: data.to_vec(),
            packed,
            flags: 0,
            crc: ace_crc(data),
            wide: false,
        }
    }

    fn lz(name: &str, method: u8, data: &[u8], syms: &[Sym]) -> Self {
        Self::raw(name.as_bytes(), method, data, lz77(syms))
    }

    fn dir(name: &str) -> Self {
        Self {
            attribs: 0x10,
            ..Self::stored(name, b"")
        }
    }

    fn encrypted(mut self, password: &str) -> Self {
        self.packed = ace::encrypt(password, &self.packed);
        self.flags |= PASSWORD;
        self
    }

    /// Its header for `packed` bytes of data in this part.
    fn header(&self, packed: usize, flags: u16, crc: u32) -> Vec<u8> {
        let mut b = vec![if self.wide { FILE64 } else { FILE32 }];
        let wide = if self.wide { WIDE } else { 0 };
        b.extend_from_slice(&(ADDSIZE | wide | self.flags | flags).to_le_bytes());
        if self.wide {
            b.extend_from_slice(&(packed as u64).to_le_bytes());
            b.extend_from_slice(&(self.data.len() as u64).to_le_bytes());
        } else {
            b.extend_from_slice(&(packed as u32).to_le_bytes());
            b.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        }
        b.extend_from_slice(&DOS.to_le_bytes());
        b.extend_from_slice(&self.attribs.to_le_bytes());
        b.extend_from_slice(&crc.to_le_bytes());
        b.push(self.method);
        b.push(if self.method == STORED { 0 } else { 3 });
        // A 64 KiB dictionary: 1 << (6 + 10).
        b.extend_from_slice(&6u16.to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.name);
        framed(&b)
    }
}

fn archive(flags: u16, items: &[Item]) -> Vec<u8> {
    let mut out = main_header(flags, 0, None);
    for it in items {
        out.extend(it.header(it.packed.len(), 0, it.crc));
        out.extend_from_slice(&it.packed);
    }
    out
}

/// A set as ACE writes one: the entries one after another, each part holding at most `room`
/// bytes of data, an entry cut where its part ends going on at the start of the next.
fn set(flags: u16, items: &[Item], room: usize) -> Vec<Vec<u8>> {
    let mut parts = vec![main_header(flags | MULTIVOLUME, 0, None)];
    let mut left = room;
    for it in items {
        let mut from = 0;
        loop {
            if left == 0 {
                parts.push(main_header(flags | MULTIVOLUME, parts.len() as u8, None));
                left = room;
            }
            let take = (it.packed.len() - from).min(left);
            let last = from + take == it.packed.len();
            let f = if from > 0 { CONTPREV } else { 0 } | if last { 0 } else { CONTNEXT };
            // Only the last piece's header has the whole entry's CRC.
            let crc = if last { it.crc } else { 0x1234_5678 };
            let part = parts.last_mut().unwrap();
            part.extend(it.header(take, f, crc));
            part.extend_from_slice(&it.packed[from..from + take]);
            from += take;
            left -= take;
            if last {
                break;
            }
        }
    }
    parts
}

/// A copy of the whole `n` bytes before: the longest copy is 257 bytes, so two.
fn whole_again(n: u32) -> Vec<Sym> {
    vec![Sym::Copy(n, 200), Sym::Again(0, n - 200)]
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    if let Ok(out) = std::env::var("BEEZIP_ACE_OUT") {
        fs::create_dir_all(&out).unwrap();
        fs::write(Path::new(&out).join(name), bytes).unwrap();
    }
    path
}

// ---- an LZ77 encoder, for the decoder to read ----

/// Bits, high first, into little-endian 32-bit words.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn put(&mut self, v: u32, bits: u32) {
        if bits == 0 {
            return;
        }
        self.acc = (self.acc << bits) | u64::from(v & (u32::MAX >> (32 - bits)));
        self.n += bits;
        while self.n >= 32 {
            self.n -= 32;
            self.out
                .extend_from_slice(&((self.acc >> self.n) as u32).to_le_bytes());
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            let pad = 32 - self.n;
            self.put(0, pad);
        }
        self.out
    }
}

/// ACE's code assignment: symbols sorted by width, widest first, with ACE's own quicksort
/// (equal widths end up where it leaves them), then given table slots from the narrowest.
fn codes(widths: &[u8], max: u8) -> Vec<(u32, u8)> {
    fn sort(k: &mut [u8], v: &mut [usize], left: usize, right: usize) {
        let m = k[right];
        let (mut l, mut r) = (left, right as isize);
        loop {
            while k[l] > m {
                l += 1;
            }
            while k[r as usize] < m {
                r -= 1;
            }
            if l as isize <= r {
                k.swap(l, r as usize);
                v.swap(l, r as usize);
                l += 1;
                r -= 1;
            }
            if l as isize >= r {
                break;
            }
        }
        if (left as isize) < r {
            let r = r as usize;
            if left + 1 < r {
                sort(k, v, left, r);
            } else if k[left] < k[r] {
                k.swap(left, r);
                v.swap(left, r);
            }
        }
        if right > l {
            if l + 1 < right {
                sort(k, v, l, right);
            } else if k[l] < k[right] {
                k.swap(l, right);
                v.swap(l, right);
            }
        }
    }
    let mut k = widths.to_vec();
    let mut v: Vec<usize> = (0..widths.len()).collect();
    sort(&mut k, &mut v, 0, widths.len() - 1);
    let used = k.iter().take_while(|&&w| w > 0).count();
    let mut out = vec![(0, 0); widths.len()];
    let mut slot = 0u32;
    for i in (0..used).rev() {
        let w = k[i];
        out[v[i]] = (slot >> (max - w), w);
        slot += 1 << (max - w);
    }
    assert!(slot <= 1 << max, "too many codes");
    out
}

/// A tree of `widths`: no lower width, 12 as the upper (widths up to 11), every width-width 4.
fn put_tree(bits: &mut Bits, widths: &[u8]) {
    const UPPER: u8 = 12;
    bits.put(widths.len() as u32 - 1, 9);
    bits.put(0, 4);
    bits.put(u32::from(UPPER), 4);
    let ww = vec![4u8; usize::from(UPPER) + 1];
    for &w in &ww {
        bits.put(u32::from(w), 3);
    }
    let wcodes = codes(&ww, 7);
    let mut prev = 0u8;
    for (i, &w) in widths.iter().enumerate() {
        let d = if i == 0 {
            w
        } else {
            (w + UPPER - prev) % UPPER
        };
        let (c, cw) = wcodes[usize::from(d)];
        bits.put(c, u32::from(cw));
        prev = w;
    }
}

#[derive(Clone, Copy)]
enum Sym {
    Lit(u8),
    /// A copy at `dist` bytes back (1 the last byte), coded with its distance.
    Copy(u32, u32),
    /// A copy at a recent distance: 0 the latest of the last four.
    Again(u8, u32),
    /// ACE 2.0's type code: a mode, and its arguments' bits.
    Mode(u8, &'static [(u32, u32)]),
}

const MAIN_CODES: usize = 284;
const LEN_CODES: usize = 255;

/// One block of `syms`, every main code 9 bits wide and every length code 8.
fn lz77(syms: &[Sym]) -> Vec<u8> {
    let main_widths = vec![9u8; MAIN_CODES];
    let len_widths = vec![8u8; LEN_CODES];
    let (main, len) = (codes(&main_widths, 11), codes(&len_widths, 11));
    let mut b = Bits::default();
    put_tree(&mut b, &main_widths);
    put_tree(&mut b, &len_widths);
    b.put(syms.len() as u32, 15);
    let sym = |b: &mut Bits, s: usize| b.put(main[s].0, u32::from(main[s].1));
    let length = |b: &mut Bits, l: u32| {
        let (c, w) = len[l as usize];
        b.put(c, u32::from(w));
    };
    for &s in syms {
        match s {
            Sym::Lit(c) => sym(&mut b, usize::from(c)),
            Sym::Copy(dist, n) => {
                let d = dist - 1;
                let bits = if d < 2 { d } else { 32 - d.leading_zeros() };
                sym(&mut b, 260 + bits as usize);
                if bits >= 2 {
                    b.put(d - (1 << (bits - 1)), bits - 1);
                }
                let base = match d {
                    0..=255 => 2,
                    256..=8191 => 3,
                    _ => 4,
                };
                length(&mut b, n - base);
            }
            Sym::Again(offset, n) => {
                sym(&mut b, 256 + usize::from(offset));
                length(&mut b, n - if offset > 1 { 3 } else { 2 });
            }
            Sym::Mode(mode, args) => {
                sym(&mut b, 283);
                b.put(u32::from(mode), 8);
                for &(v, bits) in args {
                    b.put(v, bits);
                }
            }
        }
    }
    b.finish()
}

fn lits(s: &[u8]) -> Vec<Sym> {
    s.iter().map(|&c| Sym::Lit(c)).collect()
}

/// An archive comment: its size, a tree, then literals.
fn packed_comment(text: &[u8]) -> Vec<u8> {
    let widths = vec![9u8; MAIN_CODES];
    let main = codes(&widths, 11);
    let mut b = Bits::default();
    b.put(text.len() as u32, 15);
    put_tree(&mut b, &widths);
    for &c in text {
        b.put(main[usize::from(c)].0, u32::from(main[usize::from(c)].1));
    }
    b.finish()
}

/// A text with repeats, and how to code it: literals, a long copy, a copy at a recent distance.
fn repetitive() -> (Vec<u8>, Vec<Sym>) {
    let head = b"The quick brown fox jumps over the lazy dog. ";
    let mut data = head.to_vec();
    let mut syms = lits(head);
    // 200 bytes from 45 back: the head again and again, overlapping itself.
    for _ in 0..200 {
        data.push(data[data.len() - head.len()]);
    }
    syms.push(Sym::Copy(head.len() as u32, 200));
    syms.extend(lits(b"|"));
    data.push(b'|');
    // The same distance once more, from the history.
    for _ in 0..10 {
        data.push(data[data.len() - head.len()]);
    }
    syms.push(Sym::Again(0, 10));
    (data, syms)
}

/// Extracts everything and returns the files, by path.
fn extracted(path: &Path, cx: &mut dyn Ctx) -> Vec<(String, Vec<u8>)> {
    let dir = tempfile::tempdir().unwrap();
    extract_to(path, dir.path(), cx);
    let mut out: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(dir.path())
        .min_depth(1)
        .into_iter()
        .map(|e| e.unwrap())
        .map(|e| {
            let rel = e
                .path()
                .strip_prefix(dir.path())
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let data = if e.file_type().is_file() {
                fs::read(e.path()).unwrap()
            } else {
                Vec::new()
            };
            (rel, data)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn stored_entries_folders_and_oem_names() {
    let dir = tempfile::tempdir().unwrap();
    // 0x81 is ü in code page 437, and stays a byte in `raw_path`.
    let oem = Item::raw(b"docs\\gr\x81n.txt", STORED, b"green", b"green".to_vec());
    let path = write(
        dir.path(),
        "stored.ace",
        &archive(
            0,
            &[
                Item::dir("docs"),
                Item::stored("docs\\a.txt", b"hello, ACE"),
                Item::stored("empty.txt", b""),
                oem,
                // A NUL ends a name.
                Item::stored("hidden.txt\0.exe", b"x"),
            ],
        ),
    );
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(opened.detection.format(), Some(beezip_core::FormatId::Ace));
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "docs/",
            "docs/a.txt",
            "empty.txt",
            "docs/grün.txt",
            "hidden.txt"
        ]
    );
    assert_eq!(entries[0].kind, EntryKind::Dir);
    assert_eq!(entries[0].size, None);
    assert_eq!(entries[3].raw_path, b"docs\\gr\x81n.txt");
    assert_eq!(entries[1].method.as_deref(), Some("Store"));
    let info = opened.reader.info(&mut cx).unwrap();
    assert!(!info.solid);
    assert_eq!(info.comment, None);

    assert_eq!(
        extracted(&path, &mut SimpleCtx::new()),
        [
            ("docs".into(), vec![]),
            ("docs/a.txt".into(), b"hello, ACE".to_vec()),
            ("docs/grün.txt".into(), b"green".to_vec()),
            ("empty.txt".into(), vec![]),
            ("hidden.txt".into(), b"x".to_vec()),
        ]
    );
    let report = test(&path, &mut SimpleCtx::new()).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.entries, 5);
    assert_eq!(
        read_entry(&path, 3, &mut SimpleCtx::new()).unwrap(),
        b"green"
    );
    assert_eq!(read_entry(&path, 0, &mut SimpleCtx::new()).unwrap(), b"");
}

#[test]
fn a_bad_header_crc_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let good = archive(0, &[Item::stored("a.txt", b"abc")]);
    // The file header's first byte of name.
    let mut bad = good.clone();
    let at = good.windows(5).position(|w| w == b"a.txt").unwrap();
    bad[at] = b'b';
    let path = write(dir.path(), "bad-header.ace", &bad);
    let err = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");
    assert!(err.message.contains("CRC-16"), "{err}");
}

/// A file cut short is listed as far as it goes; the entry it cuts fails when read, with a
/// warning, as unace and acefile have it.
#[test]
fn an_archive_cut_short() {
    let dir = tempfile::tempdir().unwrap();
    let (data, syms) = repetitive();
    let whole = archive(
        0,
        &[
            Item::stored("a.txt", b"complete"),
            Item::lz("b.txt", LZ77, &data, &syms),
        ],
    );
    // Inside the second entry's data, and inside its header.
    let header_at = whole.windows(5).position(|w| w == b"b.txt").unwrap();
    for (name, cut) in [("cut.ace", whole.len() - 7), ("cut-header.ace", header_at)] {
        let path = write(dir.path(), name, &whole[..cut]);
        let mut cx = SimpleCtx::new();
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        let listed = opened.reader.entries(&mut cx).unwrap().len();
        assert!(!cx.warnings.is_empty(), "{name}");
        let report = test(&path, &mut SimpleCtx::new()).unwrap();
        assert_eq!(
            read_entry(&path, 0, &mut SimpleCtx::new()).unwrap(),
            b"complete"
        );
        if name == "cut.ace" {
            assert_eq!(listed, 2);
            assert_eq!(report.errors_total, 1, "{report:?}");
            assert_eq!(report.errors[0].path, "b.txt");
            assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
        } else {
            assert_eq!(listed, 1);
            assert!(report.ok(), "{report:?}");
        }
        // The same inside gzip, where the end shows only when the data is skipped.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&whole[..cut]).unwrap();
        let gz_path = write(dir.path(), &format!("{name}.gz"), &gz.finish().unwrap());
        let mut cx = SimpleCtx::new();
        let mut opened = open(&gz_path, &OpenOptions::default(), &mut cx).unwrap();
        assert_eq!(
            opened.reader.entries(&mut cx).unwrap().len(),
            listed,
            "{name}.gz"
        );
        let gz_report = test(&gz_path, &mut SimpleCtx::new()).unwrap();
        let summary = |r: &TestReport| {
            let errors: Vec<_> = r.errors.iter().map(|e| (e.path.clone(), e.kind)).collect();
            (r.entries, r.bytes, errors)
        };
        assert_eq!(summary(&gz_report), summary(&report), "{name}.gz");
    }
}

#[test]
fn a_bad_data_crc_fails_only_its_entry() {
    let dir = tempfile::tempdir().unwrap();
    let mut broken = Item::stored("broken.txt", b"some data");
    broken.crc ^= 1;
    let path = write(
        dir.path(),
        "bad-crc.ace",
        &archive(
            0,
            &[
                Item::stored("first.txt", b"fine"),
                broken,
                Item::stored("last.txt", b"fine too"),
            ],
        ),
    );
    let report = test(&path, &mut SimpleCtx::new()).unwrap();
    assert_eq!(report.entries, 3);
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert_eq!(report.errors[0].path, "broken.txt");
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    assert!(report.errors[0].message.contains("CRC-32"), "{report:?}");
    assert_eq!(
        read_entry(&path, 2, &mut SimpleCtx::new()).unwrap(),
        b"fine too"
    );
}

#[test]
fn lz77_entries_decode() {
    let dir = tempfile::tempdir().unwrap();
    let (data, syms) = repetitive();
    // ACE 2.0 switching to mode 0, LZ77 itself, midway.
    let mut blocked = syms.clone();
    blocked.insert(10, Sym::Mode(0, &[]));
    let path = write(
        dir.path(),
        "lz77.ace",
        &archive(
            0,
            &[
                Item::lz("v1.txt", LZ77, &data, &syms),
                Item::lz("v2.txt", BLOCKED, &data, &blocked),
            ],
        ),
    );
    let files = extracted(&path, &mut SimpleCtx::new());
    assert_eq!(
        files,
        [
            ("v1.txt".into(), data.clone()),
            ("v2.txt".into(), data.clone())
        ]
    );
    assert!(test(&path, &mut SimpleCtx::new()).unwrap().ok());
    assert_eq!(read_entry(&path, 1, &mut SimpleCtx::new()).unwrap(), data);

    // A type code in ACE 1.0 data: unace 2.5 reads it as ACE 2.0 does (acefile refuses it).
    let path = write(
        dir.path(),
        "lz77-mode.ace",
        &archive(0, &[Item::lz("v1.txt", LZ77, &data, &blocked)]),
    );
    assert_eq!(read_entry(&path, 0, &mut SimpleCtx::new()).unwrap(), data);

    // A copy from before the start of the data.
    let path = write(
        dir.path(),
        "lz77-far.ace",
        &archive(
            0,
            &[Item::lz(
                "far.txt",
                LZ77,
                b"aaaa",
                &[Sym::Lit(b'a'), Sym::Copy(2, 3)],
            )],
        ),
    );
    let report = test(&path, &mut SimpleCtx::new()).unwrap();
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt, "{report:?}");
}

#[test]
fn a_solid_archive_shares_its_dictionary() {
    let dir = tempfile::tempdir().unwrap();
    let (data, syms) = repetitive();
    // The second entry is a copy of the first, from 266 bytes back; the third, stored, feeds
    // the dictionary too, and the fourth copies from it.
    let n = data.len() as u32;
    let second = Item::lz("second.txt", LZ77, &data, &whole_again(n));
    let third = Item::stored("third.txt", b"stored, then copied");
    let fourth = Item::lz(
        "fourth.txt",
        BLOCKED,
        b"stored, then copied",
        &[Sym::Copy(19, 19)],
    );
    let path = write(
        dir.path(),
        "solid.ace",
        &archive(
            SOLID,
            &[
                Item::lz("first.txt", LZ77, &data, &syms),
                second,
                third,
                fourth,
            ],
        ),
    );
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    assert!(opened.reader.info(&mut cx).unwrap().solid);
    let files = extracted(&path, &mut SimpleCtx::new());
    assert_eq!(
        files[1],
        ("fourth.txt".into(), b"stored, then copied".to_vec())
    );
    assert_eq!(files[2], ("second.txt".into(), data.clone()));
    assert!(test(&path, &mut SimpleCtx::new()).unwrap().ok());
    // One entry alone decodes those before it.
    assert_eq!(
        read_entry(&path, 3, &mut SimpleCtx::new()).unwrap(),
        b"stored, then copied"
    );
    let dest = tempfile::tempdir().unwrap();
    let report = ops::extract(
        &path,
        dest.path(),
        &Selection::ids([1]),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(report.files, 1);
    assert_eq!(fs::read(dest.path().join("second.txt")).unwrap(), data);

    // Without the dictionary, outside a solid archive, the copy reaches before the data.
    let lone = write(
        dir.path(),
        "not-solid.ace",
        &archive(
            0,
            &[
                Item::lz("first.txt", LZ77, &data, &syms),
                Item::lz("second.txt", LZ77, &data, &whole_again(n)),
            ],
        ),
    );
    let report = test(&lone, &mut SimpleCtx::new()).unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
}

/// The second entry of a solid archive copies from 5 000 bytes back, into the first: the
/// dictionary is the header's 64 KiB, not 1 KiB (unarc-rs reads the size bits as the size's
/// log, and keeps 1 KiB of a solid archive's history).
#[test]
fn a_solid_dictionary_reaches_far_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut x = 0x9E37_79B9_u32;
    let first: Vec<u8> = (0..6000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    let second = first[1000..1450].to_vec();
    let path = write(
        dir.path(),
        "solid-far.ace",
        &archive(
            SOLID,
            &[
                Item::lz("first.bin", LZ77, &first, &lits(&first)),
                Item::lz(
                    "second.bin",
                    LZ77,
                    &second,
                    &[Sym::Copy(5000, 250), Sym::Again(0, 200)],
                ),
            ],
        ),
    );
    assert!(test(&path, &mut SimpleCtx::new()).unwrap().ok());
    assert_eq!(read_entry(&path, 1, &mut SimpleCtx::new()).unwrap(), second);
}

/// A file header of type 3, with 64-bit sizes (unarc-rs takes it for a recovery record and
/// skips it).
#[test]
fn a_64_bit_file_header() {
    let dir = tempfile::tempdir().unwrap();
    let wide = Item {
        wide: true,
        ..Item::stored("wide.txt", b"sizes in 64 bits")
    };
    let path = write(
        dir.path(),
        "wide.ace",
        &archive(0, &[wide, Item::stored("narrow.txt", b"32")]),
    );
    assert_eq!(names(&path), ["wide.txt", "narrow.txt"]);
    assert_eq!(
        read_entry(&path, 0, &mut SimpleCtx::new()).unwrap(),
        b"sizes in 64 bits"
    );
    assert!(test(&path, &mut SimpleCtx::new()).unwrap().ok());
}

/// A context that counts its password prompts.
struct Asking {
    inner: SimpleCtx,
    asked: u32,
}

impl Ctx for Asking {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn progress(&mut self, _: &Progress) {}
    fn warn(&mut self, m: String) {
        self.inner.warn(m);
    }
    fn password(&mut self, entry: Option<&str>, attempt: u32) -> beezip_core::Result<String> {
        self.asked += 1;
        self.inner.password(entry, attempt)
    }
    fn overwrite(&mut self, p: &Path) -> beezip_core::Result<OverwriteChoice> {
        self.inner.overwrite(p)
    }
}

#[test]
fn encrypted_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (data, syms) = repetitive();
    let path = write(
        dir.path(),
        "encrypted.ace",
        &archive(
            0,
            &[
                Item::stored("stored.txt", b"a secret, stored").encrypted("secret"),
                Item::lz("lz77.txt", LZ77, &data, &syms).encrypted("secret"),
            ],
        ),
    );
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert!(entries.iter().all(|e| e.encrypted));
    assert_eq!(
        opened.reader.info(&mut cx).unwrap().encryption,
        Encryption::All
    );

    // The right password, asked once: it's tried first on the next entry.
    let mut asking = Asking {
        inner: SimpleCtx::new().with_password("secret"),
        asked: 0,
    };
    assert_eq!(
        extracted(&path, &mut asking),
        [
            ("lz77.txt".into(), data.clone()),
            ("stored.txt".into(), b"a secret, stored".to_vec()),
        ]
    );
    assert_eq!(asking.asked, 1);

    // A wrong one, then the right one.
    let mut cx = SimpleCtx::new().with_passwords(&["wrong", "secret"]);
    assert_eq!(extracted(&path, &mut cx).len(), 2);
    let mut cx = SimpleCtx::new().with_passwords(&["wrong", "secret"]);
    assert!(test(&path, &mut cx).unwrap().ok());
    let mut cx = SimpleCtx::new().with_passwords(&["wrong", "secret"]);
    assert_eq!(read_entry(&path, 1, &mut cx).unwrap(), data);

    // Only wrong ones, and none.
    let err = test(&path, &mut SimpleCtx::new().with_password("wrong")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongPassword, "{err}");
    assert!(
        err.message.contains("wrong password or damaged data"),
        "{err}"
    );
    let err = test(&path, &mut SimpleCtx::new()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PasswordRequired, "{err}");
    let err = read_entry(&path, 0, &mut SimpleCtx::new().with_password("wrong")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongPassword, "{err}");

    // A context that never gives up is stopped after MAX_PASSWORD_TRIES.
    let wrong: Vec<&str> = vec!["wrong"; 20];
    let mut cx = Asking {
        inner: SimpleCtx::new().with_passwords(&wrong),
        asked: 0,
    };
    assert_eq!(
        test(&path, &mut cx).unwrap_err().kind,
        ErrorKind::WrongPassword
    );
    assert_eq!(cx.asked, beezip_core::ctx::MAX_PASSWORD_TRIES);
}

#[test]
fn a_solid_encrypted_archive_tries_again_from_its_dictionary() {
    let dir = tempfile::tempdir().unwrap();
    let (data, syms) = repetitive();
    let n = data.len() as u32;
    let path = write(
        dir.path(),
        "solid-encrypted.ace",
        &archive(
            SOLID,
            &[
                Item::lz("first.txt", LZ77, &data, &syms).encrypted("one"),
                Item::lz("second.txt", LZ77, &data, &whole_again(n)).encrypted("two"),
            ],
        ),
    );
    let mut cx = SimpleCtx::new().with_passwords(&["one", "two"]);
    let files = extracted(&path, &mut cx);
    assert_eq!(files[1], ("second.txt".into(), data.clone()));
    // The second alone: the first is decoded for the dictionary, with its own password.
    let mut cx = SimpleCtx::new().with_passwords(&["one", "two"]);
    assert_eq!(read_entry(&path, 1, &mut cx).unwrap(), data);
}

#[test]
fn ace_2_modes_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    for (mode, name, args) in [
        (1u8, "DELTA", &[(4u32, 8u32), (100, 17)][..]),
        (2, "EXE", &[(1, 8)][..]),
        (3, "SOUND_8", &[][..]),
        (6, "SOUND_32B", &[][..]),
        (7, "PIC", &[][..]),
    ] {
        let mut syms = lits(b"MZ");
        syms.push(Sym::Mode(mode, args));
        syms.extend(lits(b"rest"));
        let file = format!("mode-{name}.ace");
        let path = write(
            dir.path(),
            &file,
            &archive(
                0,
                &[
                    Item::lz("setup.exe", BLOCKED, b"MZrest", &syms),
                    Item::stored("readme.txt", b"fine"),
                ],
            ),
        );
        // Listing doesn't need the mode.
        assert_eq!(names(&path), ["setup.exe", "readme.txt"]);
        let report = test(&path, &mut SimpleCtx::new()).unwrap();
        assert_eq!(report.errors_total, 1, "{name}: {report:?}");
        let e = &report.errors[0];
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{name}");
        assert!(
            e.message.contains("setup.exe") && e.message.contains(name),
            "{e:?}"
        );
        let err = read_entry(&path, 0, &mut SimpleCtx::new()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedOperation, "{name}");
        assert_eq!(
            read_entry(&path, 1, &mut SimpleCtx::new()).unwrap(),
            b"fine"
        );
    }
    // A mode ACE 2.0 doesn't have is damage.
    let mut syms = lits(b"MZ");
    syms.push(Sym::Mode(9, &[]));
    let path = write(
        dir.path(),
        "mode-9.ace",
        &archive(0, &[Item::lz("x.bin", BLOCKED, b"MZ..", &syms)]),
    );
    let report = test(&path, &mut SimpleCtx::new()).unwrap();
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt, "{report:?}");
}

#[test]
fn an_archive_comment() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = main_header(0, 0, Some(&packed_comment(b"Hello from ACE.\r\n")));
    let it = Item::stored("a.txt", b"a");
    bytes.extend(it.header(1, 0, it.crc));
    bytes.extend_from_slice(b"a");
    let path = write(dir.path(), "comment.ace", &bytes);
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.comment.as_deref(), Some("Hello from ACE.\r\n"));
}

#[test]
fn built_sets_decode_across_their_parts() {
    let dir = tempfile::tempdir().unwrap();
    let (data, syms) = repetitive();
    let sealed = b"encrypted, its blocks cut by the parts";
    let items = [
        Item::stored("stored.txt", b"split across parts, byte by byte"),
        Item::stored("sealed.txt", sealed).encrypted("pw"),
        Item::lz("lz77.txt", LZ77, &data, &syms),
    ];
    // 13 bytes of data a part: every entry is cut, an encrypted block too, and the LZ77
    // stream's words.
    let parts = set(SOLID, &items, 13);
    assert!(parts.len() > 20);
    let mut last = PathBuf::new();
    for (i, p) in parts.iter().enumerate() {
        let name = match i {
            0 => "set.ace".to_owned(),
            i => format!("set.c{:02}", i - 1),
        };
        last = write(dir.path(), &name, p);
    }
    let first = dir.path().join("set.ace");
    assert_eq!(names(&first), ["stored.txt", "sealed.txt", "lz77.txt"]);
    let mut cx = SimpleCtx::new().with_password("pw");
    let mut opened = open(&first, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(opened.reader.info(&mut cx).unwrap().volumes, parts.len());
    let files = extracted(&first, &mut cx);
    assert_eq!(files[0], ("lz77.txt".into(), data.clone()));
    assert_eq!(files[1], ("sealed.txt".into(), sealed.to_vec()));
    assert!(
        test(&first, &mut SimpleCtx::new().with_password("pw"))
            .unwrap()
            .ok()
    );
    // From a part in the middle.
    let middle = dir.path().join("set.c07");
    assert_eq!(
        read_entry(&middle, 2, &mut SimpleCtx::new().with_password("pw")).unwrap(),
        data
    );

    // Without its last part, the entry that goes on there is listed, and fails when read.
    fs::remove_file(&last).unwrap();
    let mut cx = SimpleCtx::new();
    let mut opened = open(&first, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(opened.reader.entries(&mut cx).unwrap().len(), 3);
    assert!(
        cx.warnings.iter().any(|w| w.contains("lz77.txt")),
        "{:?}",
        cx.warnings
    );
    let report = test(&first, &mut SimpleCtx::new().with_password("pw")).unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert_eq!(report.errors[0].path, "lz77.txt");
    assert_eq!(report.errors[0].kind, ErrorKind::NotFound, "{report:?}");
}

#[test]
fn an_ace_inside_gzip() {
    let dir = tempfile::tempdir().unwrap();
    let (data, syms) = repetitive();
    let plain = archive(
        SOLID,
        &[
            Item::stored("a.txt", b"first"),
            Item::lz("b.txt", LZ77, &data, &syms),
        ],
    );
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&plain).unwrap();
    let path = write(dir.path(), "inside.ace.gz", &gz.finish().unwrap());
    assert_eq!(names(&path), ["a.txt", "b.txt"]);
    let files = extracted(&path, &mut SimpleCtx::new());
    assert_eq!(files[1], ("b.txt".into(), data.clone()));
    assert_eq!(read_entry(&path, 1, &mut SimpleCtx::new()).unwrap(), data);
    assert_eq!(
        read_entry(&path, 0, &mut SimpleCtx::new()).unwrap(),
        b"first"
    );
}

#[test]
fn cancelling_stops_a_pass() {
    use std::sync::{Arc, atomic::AtomicBool};
    let flag = Arc::new(AtomicBool::new(true));
    let mut cx = SimpleCtx::new().with_cancel(flag);
    let dir = tempfile::tempdir().unwrap();
    let err = ops::extract(
        &fixture("unarc.ace"),
        dir.path(),
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
}
