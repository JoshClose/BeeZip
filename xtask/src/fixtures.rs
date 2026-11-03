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
        // Edge cases.
        ("empty.zip", zip(&[])),
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

fn len16<T>(v: &[T]) -> u16 {
    u16::try_from(v.len()).unwrap_or(u16::MAX)
}

fn len32<T>(v: &[T]) -> u32 {
    u32::try_from(v.len()).unwrap_or(u32::MAX)
}
