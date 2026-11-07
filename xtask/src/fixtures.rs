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
        // M5: cpio, ar, deb, RPM, CAB, LHA, .Z and lzop (docs/M5.md §10). A path traversal in
        // each archive format, sizes past the end, and bombs: each must be refused with the
        // right error and without a large allocation.
        (
            "traversal.cpio",
            cpio(&[
                ("../evil.txt", 0o100_644, b"escaped"),
                ("/etc/beezip-abs.txt", 0o100_644, b"abs"),
                ("up", 0o120_777, b".."),
                ("safe.txt", 0o100_644, b"safe"),
            ]),
        ),
        ("past-end.cpio", cpio_past_end()),
        (
            "traversal.ar",
            ar(&[("../evil.txt", b"escaped"), ("safe.txt", b"safe")]),
        ),
        ("past-end.ar", ar_past_end()),
        ("traversal.deb", deb_traversal()),
        ("traversal.rpm", rpm_traversal(false)),
        ("past-end.rpm", rpm_traversal(true)),
        (
            "traversal.cab",
            cab(&[("..\\evil.txt", b"escaped"), ("safe.txt", b"safe")], None),
        ),
        (
            "folder-bomb.cab",
            cab(&[("big.bin", b"tiny")], Some(u32::MAX)),
        ),
        (
            "traversal.lzh",
            lzh(&[("..\\evil.txt", b"escaped"), ("safe.txt", b"safe")]),
        ),
        ("traversal.iso", iso_traversal()?),
        ("cyclic.iso", iso_cyclic()?),
        ("bomb.Z", compress_bomb()),
        ("bomb.lzo", lzop_bomb()),
        // M5 PR 5: squashfs (docs/M5.md §5.10). Names are bytes, so a name can hold `/` and `\`.
        (
            "traversal.squashfs",
            squashfs(&[
                Sq::Dir(&[
                    (b"..", 1),
                    (b"../evil.txt", 2),
                    (b"..\\evil2.txt", 3),
                    (b"/etc/beezip-abs.txt", 4),
                    (b"safe.txt", 5),
                    (b"up", 6),
                ]),
                Sq::Dir(&[(b"evil3.txt", 7)]),
                Sq::File(b"escaped"),
                Sq::File(b"escaped"),
                Sq::File(b"abs"),
                Sq::File(b"safe"),
                Sq::Symlink(b".."),
                Sq::File(b"escaped"),
            ]),
        ),
        (
            "squashfs-blocks.squashfs",
            squashfs(&[
                Sq::Dir(&[(b"huge.bin", 1), (b"safe.txt", 2)]),
                // 4 TiB in 4 KiB blocks: a list of 2³⁰ blocks, 4 GiB, from a 16-byte inode.
                Sq::Huge(1 << 42),
                Sq::File(b"safe"),
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

// ---------------------------------------------------------------------------------------------
// M5's formats, by hand (docs/M5.md §10).

/// A newc cpio of (name, mode, data), with its trailer.
fn cpio(members: &[(&str, u32, &[u8])]) -> Vec<u8> {
    fn member(out: &mut Vec<u8>, name: &str, mode: u32, data: &[u8], ino: usize) {
        let fields = [
            ino,
            mode as usize,
            0,
            0,
            1,
            MTIME as usize,
            data.len(),
            0,
            0,
            0,
            0,
            name.len() + 1,
            0,
        ];
        out.extend_from_slice(b"070701");
        for f in fields {
            out.extend_from_slice(format!("{f:08X}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.resize(out.len().div_ceil(4) * 4, 0);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(4) * 4, 0);
    }
    let mut out = Vec::new();
    for (i, (name, mode, data)) in members.iter().enumerate() {
        member(&mut out, name, *mode, data, i + 1);
    }
    member(&mut out, "TRAILER!!!", 0, b"", 0);
    out
}

/// A cpio whose member claims 4 GiB of data that isn't there.
fn cpio_past_end() -> Vec<u8> {
    let mut out = cpio(&[("big.bin", 0o100_644, b"tiny")]);
    // The first header's filesize field.
    out[54..62].copy_from_slice(b"FFFFFFFF");
    out
}

fn ar_header(name: &str, size: u64) -> Vec<u8> {
    format!(
        "{name:<16}{MTIME:<12}{:<6}{:<6}{:<8}{size:<10}`\n",
        0, 0, 100_644
    )
    .into_bytes()
}

/// A GNU ar whose names all go through its `//` table, so any name can be stored.
fn ar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut table = Vec::new();
    let mut offsets = Vec::new();
    for (name, _) in members {
        offsets.push(table.len());
        table.extend_from_slice(name.as_bytes());
        table.extend_from_slice(b"/\n");
    }
    let mut out = b"!<arch>\n".to_vec();
    out.extend(ar_header("//", table.len() as u64));
    out.extend_from_slice(&table);
    if table.len() % 2 == 1 {
        out.push(b'\n');
    }
    for ((_, data), off) in members.iter().zip(offsets) {
        out.extend(ar_header(&format!("/{off}"), data.len() as u64));
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// An ar whose member claims 9 GB.
fn ar_past_end() -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    out.extend(ar_header("big.bin/", 9_000_000_000));
    out.extend_from_slice(b"tiny");
    out
}

/// A Debian package (plain tars) whose data has a `../` path.
fn deb_traversal() -> Vec<u8> {
    let control = tar(&[TarEntry::file("./control", b"Package: evil\n")]);
    let data = tar(&[
        TarEntry::file("./../evil.txt", b"escaped"),
        TarEntry::file("./safe.txt", b"safe"),
    ]);
    let mut out = b"!<arch>\n".to_vec();
    for (name, body) in [
        ("debian-binary", b"2.0\n".as_slice()),
        ("control.tar", &control),
        ("data.tar", &data),
    ] {
        out.extend(ar_header(name, body.len() as u64));
        out.extend_from_slice(body);
        if body.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

/// One RPM header structure from (tag, type, count, data).
fn rpm_header(tags: &[(u32, u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut index = Vec::new();
    let mut store = Vec::new();
    for (tag, ty, count, data) in tags {
        // Integers are aligned to their size, as rpm writes them.
        let align = match ty {
            3 => 2,
            4 => 4,
            _ => 1,
        };
        store.resize(store.len().div_ceil(align) * align, 0);
        for v in [*tag, *ty, len32(&store), *count] {
            index.extend_from_slice(&v.to_be_bytes());
        }
        store.extend_from_slice(data);
    }
    let mut out = vec![0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0];
    out.extend_from_slice(&len32(tags).to_be_bytes());
    out.extend_from_slice(&len32(&store).to_be_bytes());
    out.extend(index);
    out.extend(store);
    out
}

/// An RPM (uncompressed cpio payload) listing `../evil.txt` and `safe.txt`; `past_end` makes
/// its header claim more data than the file holds.
fn rpm_traversal(past_end: bool) -> Vec<u8> {
    let mut out = vec![0u8; 96];
    out[..4].copy_from_slice(&[0xED, 0xAB, 0xEE, 0xDB]);
    out[4] = 3;
    out[10..14].copy_from_slice(b"evil");
    out[78..80].copy_from_slice(&5u16.to_be_bytes());
    let sig = rpm_header(&[(1000, 4, 1, 0u32.to_be_bytes().to_vec())]);
    let pad = (8 - sig.len() % 8) % 8;
    out.extend(sig);
    out.resize(out.len() + pad, 0);
    let strings = |s: &[&str]| -> Vec<u8> {
        s.iter()
            .flat_map(|x| [x.as_bytes(), b"\0"].concat())
            .collect()
    };
    let u32s = |v: &[u32]| -> Vec<u8> { v.iter().flat_map(|x| x.to_be_bytes()).collect() };
    let u16s = |v: &[u16]| -> Vec<u8> { v.iter().flat_map(|x| x.to_be_bytes()).collect() };
    let mut main = rpm_header(&[
        (1000, 6, 1, b"evil\0".to_vec()),
        (1028, 4, 2, u32s(&[7, 4])),
        (1030, 3, 2, u16s(&[0o100_644, 0o100_644])),
        (1116, 4, 2, u32s(&[0, 1])),
        (1117, 8, 2, strings(&["evil.txt", "safe.txt"])),
        (1118, 8, 2, strings(&["/../", "/"])),
        (1124, 6, 1, b"cpio\0".to_vec()),
    ]);
    if past_end {
        main[12..16].copy_from_slice(&(200u32 << 20).to_be_bytes());
    }
    out.extend(main);
    out.extend(cpio(&[
        ("./../evil.txt", 0o100_644, b"escaped"),
        ("./safe.txt", 0o100_644, b"safe"),
    ]));
    out
}

/// A cabinet of stored files in one folder, with no checksums. `claim` makes the first file
/// claim that many bytes, more than the folder's one block can hold.
fn cab(files: &[(&str, &[u8])], claim: Option<u32>) -> Vec<u8> {
    let data: Vec<u8> = files.iter().flat_map(|(_, d)| d.to_vec()).collect();
    let mut table = Vec::new();
    let mut offset = 0u32;
    for (i, (name, d)) in files.iter().enumerate() {
        let size = match (i, claim) {
            (0, Some(c)) => c,
            _ => len32(d),
        };
        table.extend_from_slice(&size.to_le_bytes());
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&0u16.to_le_bytes()); // folder 0
        table.extend_from_slice(&DOS_DATE.to_le_bytes());
        table.extend_from_slice(&DOS_TIME.to_le_bytes());
        table.extend_from_slice(&0x20u16.to_le_bytes()); // archive
        table.extend_from_slice(name.as_bytes());
        table.push(0);
        offset += len32(d);
    }
    // CFHEADER is 36 bytes, CFFOLDER 8, then the files, then the block.
    let coff_files = 36 + 8;
    let coff_data = coff_files + len32(&table);
    let total = coff_data + 8 + len32(&data);
    let mut out = Vec::new();
    out.extend_from_slice(b"MSCF");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&coff_files.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3, 1]); // version 1.3
    out.extend_from_slice(&1u16.to_le_bytes()); // folders
    out.extend_from_slice(&len16(files).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0x1234u16.to_le_bytes()); // set id
    out.extend_from_slice(&0u16.to_le_bytes()); // cabinet 0
    out.extend_from_slice(&coff_data.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // one block
    out.extend_from_slice(&0u16.to_le_bytes()); // stored
    out.extend(table);
    out.extend_from_slice(&0u32.to_le_bytes()); // no checksum
    out.extend_from_slice(&len16(&data).to_le_bytes());
    out.extend_from_slice(&len16(&data).to_le_bytes());
    out.extend(data);
    out
}

/// The LHA CRC-16 (polynomial 0xA001).
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// An LHA archive of stored (`-lh0-`) files with level-0 headers, and its end byte.
fn lzh(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in files {
        let mut h = Vec::new();
        h.extend_from_slice(b"-lh0-");
        h.extend_from_slice(&len32(data).to_le_bytes());
        h.extend_from_slice(&len32(data).to_le_bytes());
        h.extend_from_slice(&DOS_TIME.to_le_bytes());
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.push(0x20);
        h.push(0); // level 0
        h.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
        h.extend_from_slice(name.as_bytes());
        h.extend_from_slice(&crc16(data).to_le_bytes());
        let sum = h.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        out.push(u8::try_from(h.len()).unwrap_or(u8::MAX));
        out.push(sum);
        out.extend(h);
        out.extend_from_slice(data);
    }
    out.push(0);
    out
}

/// A `.Z` of LZW codes that each define the string before them plus a zero: 0, 257, 258…, then
/// the longest string over and over. About 130 KiB that decode to over 3 GiB.
fn compress_bomb() -> Vec<u8> {
    struct Bits {
        out: Vec<u8>,
        bits: u64,
        count: u32,
    }
    impl Bits {
        fn put(&mut self, code: u32, n: u32) {
            self.bits |= u64::from(code) << self.count;
            self.count += n;
            while self.count >= 8 {
                self.out.push(self.bits as u8);
                self.bits >>= 8;
                self.count -= 8;
            }
        }
    }
    let mut w = Bits {
        out: vec![0x1F, 0x9D, 0x90],
        bits: 0,
        count: 0,
    };
    let (mut n_bits, mut in_group) = (9u32, 0u32);
    let mut maxcode = (1u32 << 9) - 1;
    let mut free_ent = 257u32;
    let codes = std::iter::once(0)
        .chain(257..65_536)
        .chain(std::iter::repeat_n(65_535, 20_000));
    for (i, code) in codes.enumerate() {
        if free_ent > maxcode {
            // Pad the group of eight codes, as compress does when the width grows.
            while in_group != 0 {
                w.put(0, n_bits);
                in_group = (in_group + 1) % 8;
            }
            n_bits += 1;
            maxcode = if n_bits == 16 {
                1 << 16
            } else {
                (1 << n_bits) - 1
            };
        }
        w.put(code, n_bits);
        in_group = (in_group + 1) % 8;
        if i > 0 && free_ent < 1 << 16 {
            free_ent += 1;
        }
    }
    if w.count > 0 {
        w.out.push(w.bits as u8);
    }
    w.out
}

/// An lzop file whose one block claims 64 MiB from 16 bytes.
fn lzop_bomb() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&0x1040u16.to_be_bytes());
    h.extend_from_slice(&0x20a0u16.to_be_bytes());
    h.extend_from_slice(&0x0940u16.to_be_bytes());
    h.extend_from_slice(&[3, 9]);
    h.extend_from_slice(&0x0300_0000u32.to_be_bytes()); // flags: Unix, no checksums
    h.extend_from_slice(&0o100_644u32.to_be_bytes());
    h.extend_from_slice(&MTIME.to_be_bytes());
    h.extend_from_slice(&0u32.to_be_bytes());
    h.push(0); // no name
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &h {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    let mut out = vec![0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A];
    out.extend_from_slice(&h);
    out.extend_from_slice(&(b << 16 | a).to_be_bytes());
    out.extend_from_slice(&(64u32 << 20).to_be_bytes());
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(&[0x11; 16]);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// What [`iso`] puts in an image.
enum IsoItem<'a> {
    Dir(&'a str),
    File(&'a str, &'a [u8]),
    Link(&'a str, &'a str),
}

/// An ISO from BeeZip's own writer (Joliet and Rock Ridge), dated at the corpus's fixed time so
/// the bytes come out the same on every run.
fn iso(items: &[IsoItem<'_>]) -> anyhow::Result<Vec<u8>> {
    use beezip_core::{
        SimpleCtx,
        format::{
            ArchiveWriter, NewEntry, NewKind,
            iso::{IsoWriteOptions, IsoWriter},
        },
    };
    let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(MTIME));
    let dir = workspace_root().join("target").join("gen-fixtures");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("image.iso");
    let out = std::fs::File::create(&path)?;
    let opts = IsoWriteOptions { time: Some(when) };
    let mut w = Box::new(IsoWriter::new(Box::new(out), opts, &path)?);
    let mut cx = SimpleCtx::new();
    for item in items {
        let (path, kind, data): (&str, NewKind, &[u8]) = match item {
            IsoItem::Dir(p) => (p, NewKind::Dir, b""),
            IsoItem::File(p, d) => (p, NewKind::File, d),
            IsoItem::Link(p, t) => (
                p,
                NewKind::Symlink {
                    target: (*t).to_owned(),
                },
                b"",
            ),
        };
        let e = NewEntry {
            path: path.to_owned(),
            kind,
            size: data.len() as u64,
            modified: Some(when),
            unix_mode: None,
            dos_attrs: None,
            source: None,
        };
        w.add(&e, &mut &data[..], &mut cx)?;
    }
    w.finish(&mut cx)?;
    let bytes = std::fs::read(&path)?;
    std::fs::remove_file(&path)?;
    Ok(bytes)
}

/// The extent (first sector, length) of the directory record at `at`.
fn iso_extent(img: &[u8], at: usize) -> anyhow::Result<(u32, u32)> {
    let r = img.get(at..at + 34).context("a record past the image")?;
    let lba = u32::from_le_bytes([r[2], r[3], r[4], r[5]]);
    let len = u32::from_le_bytes([r[10], r[11], r[12], r[13]]);
    Ok((lba, len))
}

/// Where the record named `name` is in the folder at `extent`.
fn iso_record(img: &[u8], extent: (u32, u32), name: &[u8]) -> anyhow::Result<usize> {
    let start = extent.0 as usize * 2048;
    let mut at = start;
    while at < start + extent.1 as usize {
        let len = usize::from(img[at]);
        if len == 0 {
            at = (at / 2048 + 1) * 2048;
            continue;
        }
        let n = usize::from(img[at + 32]);
        if &img[at + 33..at + 33 + n] == name {
            return Ok(at);
        }
        at += len;
    }
    bail!("no record named {}", String::from_utf8_lossy(name))
}

/// `..\evil.txt` (one Rock Ridge name, with Windows' separator in it), a symlink to `..`, and a
/// safe file.
fn iso_traversal() -> anyhow::Result<Vec<u8>> {
    iso(&[
        IsoItem::File("..\\evil.txt", b"escaped"),
        IsoItem::Link("up", ".."),
        IsoItem::File("safe.txt", b"safe"),
    ])
}

/// `a/b` whose record points at the top folder's sectors, so a reader that follows it goes
/// round `a` → `b` → the top without end. Only the primary tree is changed: Rock Ridge reads it.
fn iso_cyclic() -> anyhow::Result<Vec<u8>> {
    let mut img = iso(&[
        IsoItem::Dir("a"),
        IsoItem::Dir("a/b"),
        IsoItem::File("a/b/inside.txt", b"unreachable"),
        IsoItem::File("top.txt", b"top"),
    ])?;
    // The primary volume descriptor's root record is at byte 156 of sector 16.
    let root = iso_extent(&img, 16 * 2048 + 156)?;
    let a = iso_record(&img, root, b"A")?;
    let b = iso_record(&img, iso_extent(&img, a)?, b"B")?;
    let mut field = Vec::new();
    for v in [root.0, root.1] {
        field.extend_from_slice(&v.to_le_bytes());
        field.extend_from_slice(&v.to_be_bytes());
    }
    img[b + 2..b + 18].copy_from_slice(&field);
    Ok(img)
}

/// A squashfs node; the first is the root.
enum Sq {
    /// Its entries: a name (bytes, any bytes) and the node it names.
    Dir(&'static [(&'static [u8], usize)]),
    /// At most one 4 KiB block, stored uncompressed.
    File(&'static [u8]),
    /// An extended file inode claiming this size, with no block list behind it.
    Huge(u64),
    Symlink(&'static [u8]),
}

/// A squashfs 4.0 image by hand: every block stored uncompressed, 4 KiB data blocks, one folder
/// header per entry, no fragments.
fn squashfs(nodes: &[Sq]) -> Vec<u8> {
    const META: usize = 8192;
    let le16 = |v: usize| u16::try_from(v).unwrap_or(u16::MAX).to_le_bytes();
    let le32 = |v: usize| u32::try_from(v).unwrap_or(u32::MAX).to_le_bytes();
    // A position in a table's decoded bytes as a reference: its block's offset in the stored
    // table (blocks of 8 KiB, each with a 2-byte header), and the offset in it.
    let reference = |pos: usize| ((pos / META) * (META + 2), pos % META);
    let kind = |n: &Sq| -> u16 {
        match n {
            Sq::Dir(_) => 1,
            Sq::File(_) => 2,
            Sq::Huge(_) => 9,
            Sq::Symlink(_) => 3,
        }
    };
    let mut out = vec![0u8; 96];
    let mut data_at = Vec::new();
    for n in nodes {
        data_at.push(out.len());
        if let Sq::File(d) = n {
            out.extend_from_slice(d);
        }
    }
    let mut inode_at = Vec::new();
    let mut at = 0;
    for n in nodes {
        inode_at.push(at);
        at += 16
            + match n {
                Sq::Dir(_) => 16,
                Sq::File(d) => 16 + if d.is_empty() { 0 } else { 4 },
                Sq::Huge(_) => 40,
                Sq::Symlink(t) => 8 + t.len(),
            };
    }
    let mut inodes = Vec::new();
    let mut dirs = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        inodes.extend_from_slice(&kind(n).to_le_bytes());
        inodes.extend_from_slice(&0o755u16.to_le_bytes());
        inodes.extend_from_slice(&[0; 4]); // uid and gid: the first id
        inodes.extend_from_slice(&MTIME.to_le_bytes());
        inodes.extend_from_slice(&le32(i + 1));
        match n {
            Sq::Dir(entries) => {
                let listing = dirs.len();
                for (name, child) in *entries {
                    let (block, offset) = reference(inode_at[*child]);
                    dirs.extend_from_slice(&0u32.to_le_bytes()); // one entry
                    dirs.extend_from_slice(&le32(block));
                    dirs.extend_from_slice(&le32(child + 1));
                    dirs.extend_from_slice(&le16(offset));
                    dirs.extend_from_slice(&0u16.to_le_bytes());
                    let basic = match nodes[*child] {
                        Sq::Huge(_) => 2,
                        ref c => kind(c),
                    };
                    dirs.extend_from_slice(&basic.to_le_bytes());
                    dirs.extend_from_slice(&le16(name.len().saturating_sub(1)));
                    dirs.extend_from_slice(name);
                }
                let (block, offset) = reference(listing);
                inodes.extend_from_slice(&le32(block));
                inodes.extend_from_slice(&2u32.to_le_bytes());
                inodes.extend_from_slice(&le16(dirs.len() - listing + 3));
                inodes.extend_from_slice(&le16(offset));
                inodes.extend_from_slice(&1u32.to_le_bytes());
            }
            Sq::File(d) => {
                inodes.extend_from_slice(&le32(data_at[i]));
                inodes.extend_from_slice(&u32::MAX.to_le_bytes()); // no fragment
                inodes.extend_from_slice(&0u32.to_le_bytes());
                inodes.extend_from_slice(&le32(d.len()));
                if !d.is_empty() {
                    inodes.extend_from_slice(&(len32(d) | 1 << 24).to_le_bytes());
                }
            }
            Sq::Huge(size) => {
                inodes.extend_from_slice(&96u64.to_le_bytes());
                inodes.extend_from_slice(&size.to_le_bytes());
                inodes.extend_from_slice(&0u64.to_le_bytes()); // sparse
                inodes.extend_from_slice(&1u32.to_le_bytes());
                inodes.extend_from_slice(&u32::MAX.to_le_bytes()); // no fragment
                inodes.extend_from_slice(&0u32.to_le_bytes());
                inodes.extend_from_slice(&u32::MAX.to_le_bytes()); // no xattrs
            }
            Sq::Symlink(t) => {
                inodes.extend_from_slice(&1u32.to_le_bytes());
                inodes.extend_from_slice(&le32(t.len()));
                inodes.extend_from_slice(t);
            }
        }
    }
    let table = |out: &mut Vec<u8>, bytes: &[u8]| {
        for chunk in bytes.chunks(META) {
            out.extend_from_slice(&(0x8000 | len16(chunk)).to_le_bytes());
            out.extend_from_slice(chunk);
        }
    };
    let inode_table = out.len();
    table(&mut out, &inodes);
    let dir_table = out.len();
    table(&mut out, &dirs);
    let ids = out.len();
    table(&mut out, &0u32.to_le_bytes());
    let id_table = out.len();
    out.extend_from_slice(&(ids as u64).to_le_bytes());

    let (block, offset) = reference(inode_at[0]);
    let mut sb = Vec::with_capacity(96);
    sb.extend_from_slice(b"hsqs");
    sb.extend_from_slice(&le32(nodes.len()));
    sb.extend_from_slice(&MTIME.to_le_bytes());
    sb.extend_from_slice(&4096u32.to_le_bytes());
    sb.extend_from_slice(&0u32.to_le_bytes()); // no fragments
    sb.extend_from_slice(&1u16.to_le_bytes()); // gzip
    sb.extend_from_slice(&12u16.to_le_bytes());
    sb.extend_from_slice(&0x001Bu16.to_le_bytes()); // stored uncompressed, no fragments
    sb.extend_from_slice(&1u16.to_le_bytes()); // one id
    sb.extend_from_slice(&4u16.to_le_bytes());
    sb.extend_from_slice(&0u16.to_le_bytes());
    let root = ((block as u64) << 16) | offset as u64;
    let not_set = u64::MAX;
    let len = out.len() as u64;
    for v in [
        root,
        len,
        id_table as u64,
        not_set,
        inode_table as u64,
        dir_table as u64,
        not_set,
        not_set,
    ] {
        sb.extend_from_slice(&v.to_le_bytes());
    }
    out[..96].copy_from_slice(&sb);
    out
}
