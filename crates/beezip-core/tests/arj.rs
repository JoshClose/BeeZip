//! ARJ (docs/M6.md §4): unarc-rs's samples, archives built here byte by byte for what no sample
//! has, and, when `BEEZIP_ARJ_CORPUS` names the M6 spike's corpus folder, ARJ 3.10's archives
//! in every method checked against the tree they were made from.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use beezip_core::{
    Ctx, EntryKind, ErrorKind, FormatId, FsOptions, OpenOptions, OverwriteChoice, Progress,
    Selection, SimpleCtx,
    format::{Encryption, arj::ArjReader},
    open, ops,
    source::Source,
    time::{DosTime, from_dos},
};

fn unarc(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty/unarc")
        .join(name)
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// unarc-rs's LICENSE, which its ARJ samples hold: 11 357 bytes.
const LICENSE_SHA256: &str = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4";
const LICENSE_CRC: u32 = 0x7B5D_04BC;

/// Every file's path and bytes, read through `open_entry`.
fn read_all(path: &Path, cx: &mut dyn Ctx) -> beezip_core::Result<Vec<(String, Vec<u8>)>> {
    let mut opened = open(path, &OpenOptions::default(), cx)?;
    let entries = opened.reader.entries(cx)?.to_vec();
    let mut out = Vec::new();
    for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
        let mut data = Vec::new();
        opened
            .reader
            .open_entry(e.id, cx)?
            .read_to_end(&mut data)
            .map_err(beezip_core::Error::from)?;
        out.push((e.path.clone(), data));
    }
    Ok(out)
}

/// The files under `dir`, with their SHA-256s.
fn tree(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(dir).unwrap();
            let data = fs::read(e.path()).unwrap();
            (rel.to_string_lossy().replace('\\', "/"), sha256(&data))
        })
        .collect();
    out.sort();
    out
}

fn extract(path: &Path, dest: &Path, cx: &mut dyn Ctx) -> beezip_core::Result<()> {
    ops::extract(
        path,
        dest,
        &Selection::all(),
        &OpenOptions::default(),
        FsOptions::default(),
        cx,
    )
    .map(|_| ())
}

fn test(path: &Path, cx: &mut dyn Ctx) -> beezip_core::Result<beezip_core::TestReport> {
    ops::test(path, &Selection::all(), &OpenOptions::default(), cx)
}

#[test]
fn unarc_samples_in_every_method() {
    for (name, method) in [
        ("stored", "Store"),
        ("method1", "ARJ 1"),
        ("method2", "ARJ 2"),
        ("method3", "ARJ 3"),
        ("method4", "ARJ 4"),
    ] {
        let path = unarc(&format!("arj/{name}.arj"));
        let mut cx = SimpleCtx::new();
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        assert_eq!(opened.detection.format(), Some(FormatId::Arj), "{name}");
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 1, "{name}");
        let e = &entries[0];
        assert_eq!(e.path, "LICENSE");
        assert_eq!(e.size, Some(11_357));
        assert_eq!(e.crc32, Some(LICENSE_CRC));
        assert_eq!(e.method.as_deref(), Some(method), "{name}");
        // Made on Unix, so a Unix time: 2024-05-16 12:50:32 UTC. Read as a DOS time it would be
        // 2031-02-06, as 7-Zip 26.00 shows it.
        assert_eq!(
            e.modified,
            Some(UNIX_EPOCH + Duration::from_secs(1_715_863_832)),
            "{name}"
        );
        assert_eq!(e.unix_mode, Some(0o100_664), "{name}");
        let info = opened.reader.info(&mut cx).unwrap();
        assert_eq!(info.methods, [method]);
        assert_eq!(info.encryption, Encryption::None);
        assert_eq!(info.volumes, 1);

        let files = read_all(&path, &mut cx).unwrap();
        assert_eq!(sha256(&files[0].1), LICENSE_SHA256, "{name}");
        let report = test(&path, &mut cx).unwrap();
        assert!(report.ok(), "{name}: {report:?}");
        assert_eq!(report.bytes, 11_357);

        let dir = tempfile::tempdir().unwrap();
        extract(&path, dir.path(), &mut cx).unwrap();
        let out = fs::read(dir.path().join("LICENSE")).unwrap();
        assert_eq!(sha256(&out), LICENSE_SHA256, "{name}");
    }
}

#[test]
fn a_wrong_crc_is_reported_for_its_entry() {
    let path = unarc("broken/wrongcrc32.arj");
    let report = test(&path, &mut SimpleCtx::new()).unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert_eq!(report.errors[0].path, "LICENSE");
    assert_eq!(report.errors[0].kind, ErrorKind::Corrupt);
    assert!(report.errors[0].message.contains("CRC-32"), "{report:?}");
    let dir = tempfile::tempdir().unwrap();
    let err = extract(&path, dir.path(), &mut SimpleCtx::new()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err:?}");
    assert!(err.message.contains("LICENSE"), "{err:?}");
}

#[test]
fn a_garbled_entry_with_and_without_its_password() {
    let path = unarc("arj/license_crypted.arj");
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let e = opened.reader.entries(&mut cx).unwrap()[0].clone();
    assert!(e.encrypted);
    assert_eq!(e.path, "LICENSE");
    // Made on DOS: a local DOS time, 2025-12-16 16:18:58.
    let dos = DosTime {
        date: 0x5B90,
        time: 0x825D,
    };
    assert_eq!(e.modified, from_dos(dos));
    assert_eq!(e.dos_attrs, Some(0x20));
    assert_eq!(
        opened.reader.info(&mut cx).unwrap().encryption,
        Encryption::All
    );

    // Listing needs no password; reading does.
    let dir = tempfile::tempdir().unwrap();
    let err = extract(&path, dir.path(), &mut SimpleCtx::new()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PasswordRequired);
    let err = test(&path, &mut SimpleCtx::new()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PasswordRequired);

    let err = extract(
        &path,
        dir.path(),
        &mut SimpleCtx::new().with_password("nope"),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongPassword);
    assert_eq!(err.message, "wrong password or damaged data");
    assert!(!dir.path().join("LICENSE").exists());
    let err = read_all(&path, &mut SimpleCtx::new().with_password("nope")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongPassword);

    let mut good = SimpleCtx::new().with_password("secret");
    extract(&path, dir.path(), &mut good).unwrap();
    let out = fs::read(dir.path().join("LICENSE")).unwrap();
    assert_eq!(sha256(&out), LICENSE_SHA256);
    let files = read_all(&path, &mut good).unwrap();
    assert_eq!(sha256(&files[0].1), LICENSE_SHA256);
    assert!(test(&path, &mut good).unwrap().ok());

    // A wrong password, then the right one.
    let mut retry = SimpleCtx::new().with_passwords(&["nope", "secret"]);
    let files = read_all(&path, &mut retry).unwrap();
    assert_eq!(sha256(&files[0].1), LICENSE_SHA256);
    let mut retry = SimpleCtx::new().with_passwords(&["nope", "secret"]);
    assert!(test(&path, &mut retry).unwrap().ok());
}

/// A volume set opened from any of its parts: one file split across three.
#[test]
fn a_volume_set_from_any_part() {
    for part in ["test_file.arj", "test_file.a01", "test_file.a02"] {
        let path = unarc(&format!("arj/{part}"));
        let mut cx = SimpleCtx::new();
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        assert_eq!(opened.detection.volumes.len(), 3, "{part}");
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 1, "{part}");
        assert_eq!(entries[0].path, "TEST.ICY");
        assert_eq!(entries[0].size, Some(29_813));
        assert_eq!(entries[0].packed_size, Some(9297 + 9302 + 3166));
        assert_eq!(entries[0].crc32, None, "three pieces, three CRCs");
        let info = opened.reader.info(&mut cx).unwrap();
        assert_eq!(info.volumes, 3);
        let files = read_all(&path, &mut cx).unwrap();
        // 7-Zip 26.00 reads one part at a time, writing its piece at the piece's position:
        // the three pieces it wrote, put together. (The first alone, 11 109 bytes, is what it
        // and unar 1.10 extract from test_file.arj.)
        assert_eq!(
            sha256(&files[0].1),
            "be8a087b4563b116bd79d2f8b1f0544c2709a70c4787e05a57b7e11ec33a7f74",
            "{part}"
        );
        assert_eq!(
            sha256(&files[0].1[..11_109]),
            "adba63c0dc6b622649d55dd93b9a4c6931002028bb9a0f2f9571ffd38a0cf743"
        );
        assert!(test(&path, &mut cx).unwrap().ok(), "{part}");
    }
    let dir = tempfile::tempdir().unwrap();
    extract(
        &unarc("arj/test_file.a01"),
        dir.path(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!(
        fs::metadata(dir.path().join("TEST.ICY")).unwrap().len(),
        29_813
    );
}

/// The three crafted headers that panicked unarc-rs 0.8.1's parser (docs/M6.md §16): each has a
/// valid header CRC-32.
#[test]
fn crafted_headers_are_clean_errors() {
    let cases: [(&str, &[u8]); 3] = [
        (
            "arj-short-main-header.arj",
            &[0x60, 0xEA, 0x01, 0x00, 0x1E, 0xEE, 0xD2, 0x0D, 0x28],
        ),
        (
            "arj-name-without-nul.arj",
            &[
                0x60, 0xEA, 0x22, 0x00, 0x1E, 0x0B, 0x01, 0x02, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x41, 0x4D, 0x45, 0x9E, 0x72, 0x3B, 0xA1,
            ],
        ),
        (
            "arj-short-file-header.arj",
            &[
                0x60, 0xEA, 0x25, 0x00, 0x1E, 0x0B, 0x01, 0x02, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x2E, 0x61, 0x72, 0x6A, 0x00, 0x00, 0x15,
                0xDF, 0x52, 0xBA, 0x00, 0x00, 0x60, 0xEA, 0x03, 0x00, 0x03, 0x00, 0x00, 0x4B, 0x67,
                0x07, 0xFD,
            ],
        ),
    ];
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in cases {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        let source = Source::new(&path, Vec::new(), &OpenOptions::default()).unwrap();
        let err = ArjReader::open(source, &mut SimpleCtx::new())
            .err()
            .unwrap_or_else(|| panic!("{name} opened"));
        assert_eq!(err.kind, ErrorKind::Corrupt, "{name}: {err:?}");
        // Through detection too: none sniffs as ARJ, so only the extension says ARJ.
        let err = test(&path, &mut SimpleCtx::new()).unwrap_err();
        assert!(
            matches!(err.kind, ErrorKind::Corrupt | ErrorKind::UnsupportedFormat),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn detection_checks_the_header_not_just_the_magic() {
    let limits = beezip_core::Limits::default();
    let good = Arj::new().file(File::stored("a.txt", b"hi")).build();
    let det = beezip_core::detect_bytes(&good, None, &limits);
    assert_eq!(det.format(), Some(FormatId::Arj));
    assert_eq!(det.layers[0].confidence, beezip_core::Confidence::Certain);
    let mut bad = good.clone();
    bad[10] ^= 1;
    assert_eq!(
        beezip_core::detect_bytes(&bad, None, &limits).format(),
        None
    );
    let magic = b"\x60\xEA\x10\x00 just the magic";
    assert_eq!(
        beezip_core::detect_bytes(magic, None, &limits).format(),
        None
    );
    let named = beezip_core::detect_bytes(magic, Some("x.arj"), &limits);
    assert_eq!(named.layers[0].confidence, beezip_core::Confidence::Guess);
}

// Archives built here, for what the samples don't have.

/// 2026-01-01 00:00:00 UTC.
const MTIME: u32 = 1_767_225_600;
const OS_DOS: u8 = 0;
const OS_UNIX: u8 = 2;

/// One local header and its packed bytes.
#[derive(Clone)]
struct File {
    name: Vec<u8>,
    host: u8,
    flags: u8,
    method: u8,
    file_type: u8,
    modifier: u8,
    time: u32,
    size: u32,
    crc: u32,
    mode: u16,
    ext_pos: u32,
    packed: Vec<u8>,
    /// A packed size to claim instead of the real one.
    claim: Option<u32>,
}

impl File {
    fn stored(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            host: OS_UNIX,
            flags: 0,
            method: 0,
            file_type: 0,
            modifier: 0,
            time: MTIME,
            size: u32::try_from(data.len()).unwrap(),
            crc: crc32fast::hash(data),
            mode: 0x1000 | 0o644,
            ext_pos: 0,
            packed: data.to_vec(),
            claim: None,
        }
    }

    fn dir(name: &str) -> Self {
        Self {
            file_type: 3,
            mode: 0x2000 | 0o755,
            ..Self::stored(name, b"")
        }
    }

    /// Garbled with `password`, as ARJ's `-g` does.
    fn garbled(mut self, password: &[u8], modifier: u8) -> Self {
        self.flags |= 0x01;
        self.modifier = modifier;
        for (i, b) in self.packed.iter_mut().enumerate() {
            *b ^= modifier.wrapping_add(password[i % password.len()]);
        }
        self
    }

    fn header(&self) -> Vec<u8> {
        let mut f = vec![46u8, 11, 1, self.host, self.flags, self.method];
        f.extend_from_slice(&[self.file_type, self.modifier]);
        f.extend_from_slice(&self.time.to_le_bytes());
        let packed = self
            .claim
            .unwrap_or_else(|| u32::try_from(self.packed.len()).unwrap());
        f.extend_from_slice(&packed.to_le_bytes());
        f.extend_from_slice(&self.size.to_le_bytes());
        f.extend_from_slice(&self.crc.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&self.mode.to_le_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&self.ext_pos.to_le_bytes());
        f.extend_from_slice(&self.time.to_le_bytes());
        f.extend_from_slice(&self.time.to_le_bytes());
        f.extend_from_slice(&0u32.to_le_bytes());
        f.extend_from_slice(&self.name);
        f.extend_from_slice(&[0, 0]);
        basic(&f)
    }
}

/// A basic header around `b`, with its CRC and no extended headers.
fn basic(b: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60, 0xEA];
    out.extend_from_slice(&u16::try_from(b.len()).unwrap().to_le_bytes());
    out.extend_from_slice(b);
    out.extend_from_slice(&crc32fast::hash(b).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// One part: a main header, the files, the end.
struct Arj {
    flags: u8,
    encryption: u8,
    comment: Vec<u8>,
    files: Vec<File>,
}

impl Arj {
    fn new() -> Self {
        Self {
            flags: 0,
            encryption: 0,
            comment: Vec::new(),
            files: Vec::new(),
        }
    }

    fn file(mut self, f: File) -> Self {
        self.files.push(f);
        self
    }

    fn build(&self) -> Vec<u8> {
        let mut m = vec![34u8, 11, 1, OS_UNIX, self.flags, 0, 2, 0];
        m.extend_from_slice(&MTIME.to_le_bytes());
        m.extend_from_slice(&MTIME.to_le_bytes());
        m.extend_from_slice(&[0; 12]);
        m.extend_from_slice(&[self.encryption, 0, 0, 0, 0, 0]);
        m.extend_from_slice(b"built.arj\0");
        m.extend_from_slice(&self.comment);
        m.push(0);
        let mut out = basic(&m);
        for f in &self.files {
            out.extend(f.header());
            out.extend_from_slice(&f.packed);
        }
        out.extend_from_slice(&[0x60, 0xEA, 0, 0]);
        out
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn folders_comments_and_times() {
    let dos_time = (u32::from(0x5C21u16) << 16) | 0x6000;
    let archive = Arj {
        comment: b"made for a test\r\n".to_vec(),
        ..Arj::new()
    }
    .file(File::dir("docs"))
    .file(File::stored("docs\\a.txt", b"backslash"))
    .file(File {
        host: OS_DOS,
        time: dos_time,
        mode: 0x21,
        ..File::stored("dos.txt", b"dos")
    })
    .build();
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "x.arj", &archive);
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["docs/", "docs/a.txt", "dos.txt"]);
    assert_eq!(entries[0].kind, EntryKind::Dir);
    assert_eq!(entries[0].size, None);
    assert_eq!(entries[0].unix_mode, Some(0o040_755));
    assert_eq!(entries[1].raw_path, b"docs\\a.txt");
    let unix = UNIX_EPOCH + Duration::from_secs(u64::from(MTIME));
    assert_eq!(entries[1].modified, Some(unix));
    assert_eq!(entries[1].unix_mode, Some(0o100_644));
    let dos = DosTime {
        date: 0x5C21,
        time: 0x6000,
    };
    assert_eq!(entries[2].modified, from_dos(dos));
    assert_eq!(entries[2].dos_attrs, Some(0x21));
    assert_eq!(entries[2].unix_mode, None);
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.comment.as_deref(), Some("made for a test\r\n"));

    let out = dir.path().join("out");
    extract(&path, &out, &mut cx).unwrap();
    assert_eq!(fs::read(out.join("docs/a.txt")).unwrap(), b"backslash");
    assert_eq!(fs::read(out.join("dos.txt")).unwrap(), b"dos");
    let t = fs::metadata(out.join("docs/a.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(t, unix);
}

#[test]
fn oem_names_decode_through_the_code_page() {
    // `é` in code page 437 is 0x82.
    let archive = Arj::new()
        .file(File {
            name: b"caf\x82.txt".to_vec(),
            ..File::stored("", b"x")
        })
        .build();
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "x.arj", &archive);
    let opts = OpenOptions::default().with_names(beezip_core::NameDecoding {
        encoding: beezip_core::NameEncoding::from_name("cp437").unwrap(),
        ..beezip_core::NameDecoding::default()
    });
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &opts, &mut cx).unwrap();
    let e = opened.reader.entries(&mut cx).unwrap()[0].clone();
    assert_eq!(e.path, "café.txt");
    assert_eq!(e.raw_path, b"caf\x82.txt");
}

/// Counts the passwords asked for.
struct Asking {
    inner: SimpleCtx,
    asked: Vec<u32>,
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
        self.asked.push(attempt);
        self.inner.password(entry, attempt)
    }
    fn overwrite(&mut self, p: &Path) -> beezip_core::Result<OverwriteChoice> {
        self.inner.overwrite(p)
    }
}

#[test]
fn the_password_that_worked_is_tried_first() {
    let archive = Arj::new()
        .file(File::stored("one.txt", b"first secret").garbled(b"pw", 7))
        .file(File::stored("plain.txt", b"not garbled"))
        .file(File::stored("two.txt", b"second secret").garbled(b"pw", 9))
        .file(File::stored("empty.txt", b"").garbled(b"pw", 9))
        .build();
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "x.arj", &archive);

    let mut cx = Asking {
        inner: SimpleCtx::new().with_passwords(&["no", "pw"]),
        asked: Vec::new(),
    };
    let out = dir.path().join("out");
    extract(&path, &out, &mut cx).unwrap();
    assert_eq!(cx.asked, [0, 1], "asked twice for one.txt, then never");
    assert_eq!(fs::read(out.join("two.txt")).unwrap(), b"second secret");
    assert_eq!(fs::read(out.join("empty.txt")).unwrap(), b"");

    let mut opened = open(&path, &OpenOptions::default(), &mut SimpleCtx::new()).unwrap();
    assert_eq!(
        opened
            .reader
            .info(&mut SimpleCtx::new())
            .unwrap()
            .encryption,
        Encryption::Some
    );
    let mut cx = Asking {
        inner: SimpleCtx::new().with_password("pw"),
        asked: Vec::new(),
    };
    for id in [0, 2, 0] {
        let mut data = Vec::new();
        opened
            .reader
            .open_entry(id, &mut cx)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
    }
    assert_eq!(cx.asked, [0]);

    // A context that never gives up is stopped all the same.
    let mut cx = Asking {
        inner: SimpleCtx::new().with_passwords(&["a"; 20]),
        asked: Vec::new(),
    };
    let err = extract(&path, &dir.path().join("out2"), &mut cx).unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongPassword);
    assert_eq!(cx.asked.len(), 8);
}

/// Three parts, one garbled file split across all three, a file after it, as ARJ 3.10 writes
/// them: the volume flag on every piece but the last, the ext-file flag and position on every
/// piece but the first, the garble starting over with each piece.
fn split_set(dir: &Path, base: &str) -> Vec<PathBuf> {
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
    let cuts = [0, 1000, 2200, 3000];
    let mut paths = Vec::new();
    for k in 0..3 {
        let piece = &data[cuts[k]..cuts[k + 1]];
        let mut f = File::stored("big.bin", piece).garbled(b"secret", 40 + k as u8);
        if k < 2 {
            f.flags |= 0x04;
        }
        if k > 0 {
            f.flags |= 0x08;
            f.ext_pos = u32::try_from(cuts[k]).unwrap();
        }
        let mut part = Arj {
            flags: if k < 2 { 0x04 } else { 0 },
            ..Arj::new()
        }
        .file(f);
        if k == 2 {
            part = part.file(File::stored("after.txt", b"after"));
        }
        let name = if k == 0 {
            format!("{base}.arj")
        } else {
            format!("{base}.a{k:02}")
        };
        paths.push(write(dir, &name, &part.build()));
    }
    paths
}

#[test]
fn a_garbled_file_split_across_three_parts() {
    let dir = tempfile::tempdir().unwrap();
    let parts = split_set(dir.path(), "set");
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
    for part in &parts {
        let mut cx = SimpleCtx::new().with_password("secret");
        let mut opened = open(part, &OpenOptions::default(), &mut cx).unwrap();
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].size, Some(3000));
        assert!(entries[0].encrypted);
        let files = read_all(part, &mut cx).unwrap();
        assert_eq!(files[0].1, data);
        assert_eq!(files[1].1, b"after");
        assert!(test(part, &mut cx).unwrap().ok());
    }
    let out = dir.path().join("out");
    extract(
        &parts[1],
        &out,
        &mut SimpleCtx::new().with_password("secret"),
    )
    .unwrap();
    assert_eq!(fs::read(out.join("big.bin")).unwrap(), data);
    let err = test(&parts[0], &mut SimpleCtx::new().with_password("wrong")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongPassword);
}

#[test]
fn a_missing_last_part() {
    let dir = tempfile::tempdir().unwrap();
    let parts = split_set(dir.path(), "cut");
    fs::remove_file(&parts[2]).unwrap();
    let mut cx = SimpleCtx::new().with_password("secret");
    let mut opened = open(&parts[0], &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size, Some(2200), "what the parts here hold");
    let err = opened.reader.open_entry(0, &mut cx).err().unwrap();
    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(err.message.contains("cut.a01"), "{err:?}");
    let report = test(&parts[0], &mut cx).unwrap();
    assert_eq!(report.errors_total, 1);
    assert_eq!(report.errors[0].kind, ErrorKind::NotFound);
}

#[test]
fn a_continued_piece_without_its_start() {
    let dir = tempfile::tempdir().unwrap();
    let parts = split_set(dir.path(), "late");
    // The second part on its own, under a name that isn't a set's.
    let alone = dir.path().join("alone.arj");
    fs::copy(&parts[1], &alone).unwrap();
    let mut cx = SimpleCtx::new().with_password("secret");
    let mut opened = open(&alone, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(opened.reader.entries(&mut cx).unwrap().len(), 1);
    let err = opened.reader.open_entry(0, &mut cx).err().unwrap();
    assert_eq!(err.kind, ErrorKind::NotFound);
    assert!(err.message.contains("starts in a part before"), "{err:?}");
}

#[test]
fn a_part_that_doesnt_continue_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let parts = split_set(dir.path(), "mix");
    // The second part replaced by an unrelated archive.
    let other = Arj::new().file(File::stored("other.txt", b"x")).build();
    fs::write(&parts[1], other).unwrap();
    let err = open(&parts[0], &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Corrupt);
    assert!(err.message.contains("big.bin"), "{err:?}");
}

#[test]
fn gost_entries_list_but_dont_read() {
    let archive = Arj {
        flags: 0x01,
        encryption: 4,
        ..Arj::new()
    }
    .file(File::stored("secret.txt", b"gost").garbled(b"pw", 1))
    .file(File::stored("open.txt", b"plain"))
    .build();
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "g.arj", &archive);
    let mut cx = SimpleCtx::new().with_password("pw");
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(entries.len(), 2);
    assert!(entries[0].encrypted);
    let err = opened.reader.open_entry(0, &mut cx).err().unwrap();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
    assert!(err.message.contains("secret.txt"), "{err:?}");
    let mut data = Vec::new();
    opened
        .reader
        .open_entry(1, &mut cx)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"plain");
    let report = test(&path, &mut SimpleCtx::new()).unwrap();
    assert_eq!(report.errors_total, 1, "{report:?}");
    assert_eq!(report.errors[0].kind, ErrorKind::UnsupportedOperation);
    let err = extract(&path, &dir.path().join("out"), &mut cx).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedOperation);
}

#[test]
fn unknown_methods_and_short_data() {
    let mut odd = File::stored("odd.bin", b"data");
    odd.method = 7;
    let mut short = File::stored("short.bin", b"0123456789");
    short.packed.truncate(4);
    let archive = Arj::new().file(odd).file(short).build();
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "u.arj", &archive);
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert_eq!(entries[0].method.as_deref(), Some("ARJ method 7"));
    let err = opened.reader.open_entry(0, &mut cx).err().unwrap();
    assert_eq!(err.kind, ErrorKind::UnsupportedFormat);
    let report = test(&path, &mut cx).unwrap();
    assert_eq!(report.errors_total, 2, "{report:?}");
    assert_eq!(report.errors[1].kind, ErrorKind::Corrupt);
    assert!(report.errors[1].message.contains("short.bin"), "{report:?}");
}

#[test]
fn a_packed_size_past_the_end_is_corrupt_on_open() {
    // 4 GiB of packed data claimed by a 100-byte file.
    let archive = Arj::new()
        .file(File {
            size: u32::MAX,
            claim: Some(u32::MAX),
            ..File::stored("huge.bin", b"tiny")
        })
        .build();
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "h.arj", &archive);
    let err = open(&path, &OpenOptions::default(), &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err:?}");
    assert!(err.message.contains("past the end"), "{err:?}");
}

#[test]
fn many_entries_hit_the_entry_limit() {
    let mut a = Arj::new();
    for i in 0..20 {
        a = a.file(File::stored(&format!("f{i}.txt"), b"x"));
    }
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "m.arj", &a.build());
    let opts = OpenOptions::new(beezip_core::Limits {
        max_entries: Some(10),
        ..beezip_core::Limits::default()
    });
    let err = open(&path, &opts, &mut SimpleCtx::new()).err().unwrap();
    assert_eq!(err.kind, ErrorKind::LimitExceeded);
}

/// ARJ 3.10's own archives, made in Docker from a seeded tree (the M6 spike's corpus, not
/// committed): set `BEEZIP_ARJ_CORPUS` to its folder to run this.
#[test]
fn arj_3_10_corpus() {
    let Some(dir) = std::env::var_os("BEEZIP_ARJ_CORPUS").map(PathBuf::from) else {
        eprintln!("BEEZIP_ARJ_CORPUS isn't set: skipped");
        return;
    };
    let expected: Vec<(String, String)> = {
        let mut v: Vec<(String, String)> = fs::read_to_string(dir.join("tree.sha256"))
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once("  "))
            .map(|(h, p)| (p.trim_start_matches("/out/tree/").to_owned(), h.to_owned()))
            .collect();
        v.sort();
        v
    };
    for (name, password) in [
        ("arj_m0.arj", None),
        ("arj_m1.arj", None),
        ("arj_m2.arj", None),
        ("arj_m3.arj", None),
        ("arj_m4.arj", None),
        ("arj_jm.arj", None),
        ("arj_garble.arj", Some("secret")),
        ("arj_multi.arj", None),
        ("arj_multi.a01", None),
    ] {
        let path = dir.join(name);
        let mut cx = match password {
            Some(p) => SimpleCtx::new().with_password(p),
            None => SimpleCtx::new(),
        };
        let out = tempfile::tempdir().unwrap();
        extract(&path, out.path(), &mut cx).unwrap();
        assert_eq!(tree(out.path()), expected, "{name}");
        assert!(test(&path, &mut cx).unwrap().ok(), "{name}");
        let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
        let e = opened.reader.entries(&mut cx).unwrap()[0].clone();
        // 2026-11-07 13:57:37 UTC, as `arj v` shows it.
        assert_eq!(
            e.modified,
            Some(UNIX_EPOCH + Duration::from_secs(1_794_059_857)),
            "{name}"
        );
    }
    let path = dir.join("many20k.arj");
    let mut cx = SimpleCtx::new();
    let t = std::time::Instant::now();
    let mut opened = open(&path, &OpenOptions::default(), &mut cx).unwrap();
    assert_eq!(opened.reader.entries(&mut cx).unwrap().len(), 20_000);
    let report = test(&path, &mut cx).unwrap();
    assert!(report.ok());
    assert_eq!(report.entries, 20_000);
    eprintln!("many20k.arj: listed and tested in {:?}", t.elapsed());
}
