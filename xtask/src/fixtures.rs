//! `cargo xtask gen-fixtures`: the malicious corpus in `tests/fixtures/malicious/`
//! (docs/M1.md §6). The files are committed, so the fuzzers can seed from them too.
//!
//! Every archive is built by hand here: the `tar` crate refuses `..` in names, and a zip whose
//! entries share data can't be made through a well-behaved writer. Times are fixed, so the
//! output is byte-identical from run to run and `--check` can compare it.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};

/// Relative to the workspace root.
pub const DIR: &str = "tests/fixtures/malicious";

/// 2026-01-01T00:00:00Z.
const MTIME: u32 = 1_767_225_600;
/// The same instant as a DOS date and time (stored as written, without a time zone).
const DOS_TIME: u16 = 0;
const DOS_DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;

fn workspace_root() -> PathBuf {
    let xtask_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    xtask_dir.parent().unwrap_or(xtask_dir).to_path_buf()
}

pub fn run(check: bool) -> anyhow::Result<()> {
    let dir = workspace_root().join(DIR);
    let files = corpus()?;
    let mut stale = Vec::new();
    for (name, bytes) in &files {
        let path = dir.join(name);
        let current = std::fs::read(&path).ok();
        if current.as_deref() == Some(bytes.as_slice()) {
            continue;
        }
        if check {
            stale.push(*name);
        } else {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
            println!("wrote {DIR}/{name}");
        }
    }
    if !stale.is_empty() {
        bail!(
            "{} out of date in {DIR}; run `cargo xtask gen-fixtures`",
            stale.join(", ")
        );
    }
    println!("{DIR}: {} files up to date", files.len());
    Ok(())
}

fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    let file = |name: &str, data: &[u8]| ZipFile::stored(name, data);
    Ok(vec![
        // Paths.
        (
            "traversal.zip",
            zip(&[
                file("../evil.txt", b"escaped"),
                file("ok/../../evil2.txt", b"escaped"),
                file("safe.txt", b"safe"),
            ]),
        ),
        (
            "traversal.tar",
            tar(&[
                TarEntry::file("../evil.txt", b"escaped"),
                TarEntry::file("safe.txt", b"safe"),
            ]),
        ),
        (
            "absolute.zip",
            zip(&[
                file("/etc/beezip-abs.txt", b"abs"),
                file("C:\\Windows\\beezip-drive.txt", b"drive"),
                file("\\\\server\\share\\beezip-unc.txt", b"unc"),
            ]),
        ),
        (
            "absolute.tar",
            tar(&[TarEntry::file("/tmp/beezip-abs.txt", b"abs")]),
        ),
        (
            "devices.zip",
            zip(&[
                file("CON", b"con"),
                file("aux.txt", b"aux"),
                file("sub/NUL.log", b"nul"),
            ]),
        ),
        (
            "streams.zip",
            zip(&[
                file("a:b", b"stream"),
                file("x.txt:Zone.Identifier", b"zone"),
            ]),
        ),
        (
            "trailing.zip",
            zip(&[file("trailing.", b"dot"), file("spaces  ", b"space")]),
        ),
        // Links.
        (
            "symlink-escape.tar",
            tar(&[
                TarEntry::symlink("link", ".."),
                TarEntry::file("link/evil.txt", b"through the link"),
            ]),
        ),
        (
            "hardlink-absolute.tar",
            tar(&[TarEntry::hardlink("passwd", "/etc/passwd")]),
        ),
        // Bombs.
        ("overlap.zip", overlap_zip()),
        ("ratio.zip", ratio_zip()?),
        ("nested5.gz", nested_gz(5)?),
        // M3: 7z and RAR (docs/M3.md §6). Paths, links and devices, then the two 7z memory
        // bombs, which BeeZip must refuse before decoding anything.
        (
            "traversal.7z",
            sevenz(&[
                SzFile::new("../evil.txt", b"escaped"),
                SzFile::new("/etc/beezip-abs.txt", b"abs"),
                SzFile::new("CON", b"device"),
                // 7-Zip's Unix link: the extension bit, S_IFLNK in the high half, the target
                // as data.
                SzFile {
                    attrs: Some(0x8000 | (0o120_777 << 16) | 0x20),
                    ..SzFile::new("up", b"..")
                },
                SzFile::new("safe.txt", b"safe"),
            ]),
        ),
        ("bomb-header.7z", sevenz_bomb_header()),
        ("huge-dict.7z", sevenz_huge_dict()),
        (
            "traversal.rar",
            rar5(&[
                RarFile::new("../evil.txt", b"escaped"),
                RarFile::new("C:/abs.txt", b"abs"),
                RarFile::new("CON", b"device"),
                RarFile {
                    symlink: Some(".."),
                    ..RarFile::new("up", b"")
                },
                RarFile::new("safe.txt", b"safe"),
            ]),
        ),
        // Edge cases.
        ("empty.zip", zip(&[])),
        // Not malicious, just damaged: a stored entry whose CRC doesn't match its data.
        (
            "crc-mismatch.zip",
            zip(&[
                file("fine.txt", b"this one is intact"),
                ZipFile {
                    crc: crc32fast::hash(b"something else"),
                    ..ZipFile::stored("damaged.txt", b"the stored CRC is for other data")
                },
            ]),
        ),
    ])
}

struct ZipFile {
    name: Vec<u8>,
    method: u16,
    crc: u32,
    size: u32,
    packed: Vec<u8>,
}

impl ZipFile {
    fn stored(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            method: 0,
            crc: crc32fast::hash(data),
            size: u32::try_from(data.len()).unwrap_or(u32::MAX),
            packed: data.to_vec(),
        }
    }
}

fn local_header(f: &ZipFile) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"PK\x03\x04");
    h.extend_from_slice(&20u16.to_le_bytes()); // version needed
    h.extend_from_slice(&0u16.to_le_bytes()); // flags
    h.extend_from_slice(&f.method.to_le_bytes());
    h.extend_from_slice(&DOS_TIME.to_le_bytes());
    h.extend_from_slice(&DOS_DATE.to_le_bytes());
    h.extend_from_slice(&f.crc.to_le_bytes());
    h.extend_from_slice(&len32(&f.packed).to_le_bytes());
    h.extend_from_slice(&f.size.to_le_bytes());
    h.extend_from_slice(&len16(&f.name).to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // extra length
    h.extend_from_slice(&f.name);
    h
}

fn central_header(f: &ZipFile, offset: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"PK\x01\x02");
    h.extend_from_slice(&20u16.to_le_bytes()); // made by: DOS
    h.extend_from_slice(&20u16.to_le_bytes()); // version needed
    h.extend_from_slice(&0u16.to_le_bytes()); // flags
    h.extend_from_slice(&f.method.to_le_bytes());
    h.extend_from_slice(&DOS_TIME.to_le_bytes());
    h.extend_from_slice(&DOS_DATE.to_le_bytes());
    h.extend_from_slice(&f.crc.to_le_bytes());
    h.extend_from_slice(&len32(&f.packed).to_le_bytes());
    h.extend_from_slice(&f.size.to_le_bytes());
    h.extend_from_slice(&len16(&f.name).to_le_bytes());
    h.extend_from_slice(&[0; 2 + 2 + 2 + 2]); // extra, comment, disk, internal attrs
    h.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    h.extend_from_slice(&offset.to_le_bytes());
    h.extend_from_slice(&f.name);
    h
}

fn eocd(entries: u16, cd_size: u32, cd_offset: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"PK\x05\x06");
    h.extend_from_slice(&[0; 4]); // disk numbers
    h.extend_from_slice(&entries.to_le_bytes());
    h.extend_from_slice(&entries.to_le_bytes());
    h.extend_from_slice(&cd_size.to_le_bytes());
    h.extend_from_slice(&cd_offset.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // comment length
    h
}

fn zip(files: &[ZipFile]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for f in files {
        offsets.push(len32(&out));
        out.extend(local_header(f));
        out.extend_from_slice(&f.packed);
    }
    let cd_start = len32(&out);
    for (f, off) in files.iter().zip(offsets) {
        out.extend(central_header(f, off));
    }
    let cd_size = len32(&out) - cd_start;
    out.extend(eocd(len16(files), cd_size, cd_start));
    out
}

/// The overlapping-entry bomb: one local header and its data, listed under many names in the
/// central directory. Each name extracts the same data.
fn overlap_zip() -> Vec<u8> {
    let data = vec![b'A'; 4096];
    let f = ZipFile::stored("payload.bin", &data);
    let mut out = local_header(&f);
    out.extend_from_slice(&f.packed);
    let cd_start = len32(&out);
    let copies = 64u16;
    for i in 0..copies {
        let alias = ZipFile {
            name: format!("copy{i:02}.bin").into_bytes(),
            ..ZipFile::stored("", &data)
        };
        out.extend(central_header(&alias, 0));
    }
    let cd_size = len32(&out) - cd_start;
    out.extend(eocd(copies, cd_size, cd_start));
    out
}

/// One bzip2 entry of 192 MiB of zeros: far past 10 000:1 once the 64 MiB grace is spent.
fn ratio_zip() -> anyhow::Result<Vec<u8>> {
    const SIZE: usize = 192 << 20;
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
    let zeros = vec![0u8; 1 << 20];
    let mut crc = crc32fast::Hasher::new();
    for _ in 0..SIZE >> 20 {
        enc.write_all(&zeros)?;
        crc.update(&zeros);
    }
    let packed = enc.finish()?;
    Ok(zip(&[ZipFile {
        name: b"zeros.bin".to_vec(),
        method: 12,
        crc: crc.finalize(),
        size: u32::try_from(SIZE)?,
        packed,
    }]))
}

/// gzip nested `depth` times, one more than detection unwraps by default.
fn nested_gz(depth: usize) -> anyhow::Result<Vec<u8>> {
    let mut data = b"the innermost data\n".to_vec();
    for _ in 0..depth {
        let mut enc = flate2::GzBuilder::new()
            .mtime(MTIME)
            .write(Vec::new(), flate2::Compression::best());
        enc.write_all(&data)?;
        data = enc.finish()?;
    }
    Ok(data)
}

struct TarEntry {
    name: String,
    kind: u8,
    link: String,
    data: Vec<u8>,
}

impl TarEntry {
    fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.into(),
            kind: b'0',
            link: String::new(),
            data: data.to_vec(),
        }
    }

    fn symlink(name: &str, target: &str) -> Self {
        Self {
            name: name.into(),
            kind: b'2',
            link: target.into(),
            data: Vec::new(),
        }
    }

    fn hardlink(name: &str, target: &str) -> Self {
        Self {
            name: name.into(),
            kind: b'1',
            link: target.into(),
            data: Vec::new(),
        }
    }
}

fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let s = format!("{value:0digits$o}");
    field[..digits].copy_from_slice(s.as_bytes());
    field[digits] = 0;
}

/// A ustar archive with the names exactly as given.
fn tar(entries: &[TarEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        let mut h = [0u8; 512];
        h[..e.name.len()].copy_from_slice(e.name.as_bytes());
        octal(&mut h[100..108], if e.kind == b'2' { 0o777 } else { 0o644 });
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], e.data.len() as u64);
        octal(&mut h[136..148], u64::from(MTIME));
        h[156] = e.kind;
        h[157..157 + e.link.len()].copy_from_slice(e.link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&e.data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

// ---------------------------------------------------------------------------------------------
// 7z, by hand: an uncompressed header (kHeader) over stored blocks, so every field is ours.

struct SzFile {
    name: &'static str,
    data: Vec<u8>,
    attrs: Option<u32>,
}

impl SzFile {
    fn new(name: &'static str, data: &[u8]) -> Self {
        Self {
            name,
            data: data.to_vec(),
            attrs: None,
        }
    }
}

/// 7z's variable-length number.
fn sz_number(out: &mut Vec<u8>, v: u64) {
    if v < 0x80 {
        out.push(v as u8);
        return;
    }
    // The 0xFF form: eight bytes follow. Every 7z reader accepts it.
    out.push(0xFF);
    out.extend_from_slice(&v.to_le_bytes());
}

/// The 32-byte start header pointing at `next`, which follows `packed` bytes of data.
fn sz_start(packed: u64, next: &[u8]) -> Vec<u8> {
    let mut sh = Vec::new();
    sh.extend_from_slice(&packed.to_le_bytes());
    sh.extend_from_slice(&(next.len() as u64).to_le_bytes());
    sh.extend_from_slice(&crc32fast::hash(next).to_le_bytes());
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4];
    out.extend_from_slice(&crc32fast::hash(&sh).to_le_bytes());
    out.extend_from_slice(&sh);
    out
}

/// A folder (block) with one simple coder.
fn sz_folder(out: &mut Vec<u8>, id: &[u8], props: &[u8]) {
    out.push(0x01); // one coder
    let mut main = id.len() as u8;
    if !props.is_empty() {
        main |= 0x20;
    }
    out.push(main);
    out.extend_from_slice(id);
    if !props.is_empty() {
        sz_number(out, props.len() as u64);
        out.extend_from_slice(props);
    }
}

/// Every file stored (Copy) in a block of its own, with names and, where given, attributes.
fn sevenz(files: &[SzFile]) -> Vec<u8> {
    let packed: Vec<u8> = files.iter().flat_map(|f| f.data.clone()).collect();
    let mut h = vec![0x01, 0x04]; // kHeader, kMainStreamsInfo
    h.extend_from_slice(&[0x06, 0x00]); // kPackInfo, pack position 0
    sz_number(&mut h, files.len() as u64);
    h.push(0x09); // kSize
    for f in files {
        sz_number(&mut h, f.data.len() as u64);
    }
    h.push(0x00);
    h.extend_from_slice(&[0x07, 0x0B]); // kUnpackInfo, kFolder
    sz_number(&mut h, files.len() as u64);
    h.push(0x00); // not external
    for _ in files {
        sz_folder(&mut h, &[0x00], &[]);
    }
    h.push(0x0C); // kCodersUnpackSize
    for f in files {
        sz_number(&mut h, f.data.len() as u64);
    }
    h.push(0x00);
    h.extend_from_slice(&[0x08, 0x0A, 0x01]); // kSubStreamsInfo, kCRC, all defined
    for f in files {
        h.extend_from_slice(&crc32fast::hash(&f.data).to_le_bytes());
    }
    h.extend_from_slice(&[0x00, 0x00]); // end of substreams, end of streams info
    h.push(0x05); // kFilesInfo
    sz_number(&mut h, files.len() as u64);
    let mut names = vec![0x00]; // not external
    for f in files {
        for u in f.name.encode_utf16().chain([0]) {
            names.extend_from_slice(&u.to_le_bytes());
        }
    }
    h.push(0x11); // kName
    sz_number(&mut h, names.len() as u64);
    h.extend_from_slice(&names);
    let mut attrs = vec![0x01, 0x00]; // all defined, not external
    for f in files {
        attrs.extend_from_slice(&f.attrs.unwrap_or(0x20).to_le_bytes());
    }
    h.push(0x15); // kWinAttributes
    sz_number(&mut h, attrs.len() as u64);
    h.extend_from_slice(&attrs);
    h.extend_from_slice(&[0x00, 0x00]); // end of files info, end of header
    let mut out = sz_start(packed.len() as u64, &h);
    out.extend_from_slice(&packed);
    out.extend_from_slice(&h);
    out
}

/// An encoded header that says it unpacks to 8 GiB from a few bytes of LZMA: sevenz-rust2
/// would grow its buffer as it decoded, so BeeZip must refuse it from the declared size.
fn sevenz_bomb_header() -> Vec<u8> {
    let packed = [0x00u8, 0x41, 0xFE, 0xFB, 0xFF, 0xFF, 0xA4, 0x00, 0x00, 0x00];
    let mut h = vec![0x17, 0x06, 0x00, 0x01, 0x09]; // kEncodedHeader, kPackInfo, pos 0, 1 stream
    sz_number(&mut h, packed.len() as u64);
    h.push(0x00);
    h.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00]); // kUnpackInfo, kFolder, 1 folder
    let mut props = vec![0x5D];
    props.extend_from_slice(&(1u32 << 16).to_le_bytes());
    sz_folder(&mut h, &[0x03, 0x01, 0x01], &props);
    h.push(0x0C);
    sz_number(&mut h, 8 << 30);
    h.extend_from_slice(&[0x00, 0x00]);
    let mut out = sz_start(packed.len() as u64, &h);
    out.extend_from_slice(&packed);
    out.extend_from_slice(&h);
    out
}

/// One file in an LZMA2 block whose dictionary property asks for 4 GiB (the largest value,
/// 40): BeeZip checks a block's coders against `decoder_memory` before decoding it.
fn sevenz_huge_dict() -> Vec<u8> {
    let data = b"a small file in a block that asks for a 4 GiB dictionary";
    // An LZMA2 stream of one uncompressed chunk (with a dictionary reset), then the end.
    let mut packed = vec![0x01];
    packed.extend_from_slice(&((data.len() - 1) as u16).to_be_bytes());
    packed.extend_from_slice(data);
    packed.push(0x00);
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09];
    sz_number(&mut h, packed.len() as u64);
    h.push(0x00);
    h.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00]);
    sz_folder(&mut h, &[0x21], &[40]);
    h.push(0x0C);
    sz_number(&mut h, data.len() as u64);
    h.push(0x00);
    h.extend_from_slice(&[0x08, 0x0A, 0x01]);
    h.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    h.extend_from_slice(&[0x00, 0x00, 0x05, 0x01]);
    let mut names = vec![0x00];
    for u in "big.bin".encode_utf16().chain([0]) {
        names.extend_from_slice(&u.to_le_bytes());
    }
    h.push(0x11);
    sz_number(&mut h, names.len() as u64);
    h.extend_from_slice(&names);
    h.extend_from_slice(&[0x00, 0x00]);
    let mut out = sz_start(packed.len() as u64, &h);
    out.extend_from_slice(&packed);
    out.extend_from_slice(&h);
    out
}

// ---------------------------------------------------------------------------------------------
// RAR5, by hand from UnRAR's RAR5Format.md: stored files, names exactly as given.

struct RarFile {
    name: &'static str,
    data: Vec<u8>,
    symlink: Option<&'static str>,
}

impl RarFile {
    fn new(name: &'static str, data: &[u8]) -> Self {
        Self {
            name,
            data: data.to_vec(),
            symlink: None,
        }
    }
}

/// RAR5's variable-length integer: seven bits a byte, low first.
fn vint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// A header block: its CRC32, then its size and `body`.
fn rar_block(body: &[u8]) -> Vec<u8> {
    let mut sized = Vec::new();
    vint(&mut sized, body.len() as u64);
    sized.extend_from_slice(body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

fn rar5(files: &[RarFile]) -> Vec<u8> {
    let mut out = b"Rar!\x1A\x07\x01\x00".to_vec();
    // Main header: type 1, no flags, no archive flags.
    out.extend_from_slice(&rar_block(&[0x01, 0x00, 0x00]));
    for f in files {
        let mut extra = Vec::new();
        if let Some(target) = f.symlink {
            // File system redirection: type 5; redirection 1 (Unix symlink); no flags.
            let mut rec = vec![0x05, 0x01, 0x00];
            vint(&mut rec, target.len() as u64);
            rec.extend_from_slice(target.as_bytes());
            vint(&mut extra, rec.len() as u64);
            extra.extend_from_slice(&rec);
        }
        let mut b = vec![0x02]; // file header
        let header_flags = 0x0002 | if extra.is_empty() { 0 } else { 0x0001 };
        vint(&mut b, header_flags);
        if !extra.is_empty() {
            vint(&mut b, extra.len() as u64);
        }
        vint(&mut b, f.data.len() as u64); // data size
        vint(&mut b, 0x0002 | 0x0004); // file flags: mtime, CRC32
        vint(&mut b, f.data.len() as u64); // unpacked size
        vint(
            &mut b,
            if f.symlink.is_some() {
                0o120_777
            } else {
                0o100_644
            },
        ); // attributes
        b.extend_from_slice(&MTIME.to_le_bytes());
        b.extend_from_slice(&crc32fast::hash(&f.data).to_le_bytes());
        vint(&mut b, 0); // compression: version 0, stored
        vint(&mut b, 1); // host OS: Unix
        vint(&mut b, f.name.len() as u64);
        b.extend_from_slice(f.name.as_bytes());
        b.extend_from_slice(&extra);
        out.extend_from_slice(&rar_block(&b));
        out.extend_from_slice(&f.data);
    }
    // End of archive: type 5, no flags, not the last volume of a set... nor any volume.
    out.extend_from_slice(&rar_block(&[0x05, 0x00, 0x00]));
    out
}

fn len16<T>(v: &[T]) -> u16 {
    u16::try_from(v.len()).unwrap_or(u16::MAX)
}

fn len32<T>(v: &[T]) -> u32 {
    u32::try_from(v.len()).unwrap_or(u32::MAX)
}
