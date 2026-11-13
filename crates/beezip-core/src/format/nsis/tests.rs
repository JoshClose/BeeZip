use std::collections::BTreeMap;

use super::{
    write::{Layout, Method as W, Op, Strings as S, nsis},
    *,
};
use crate::{NameDecoding, NameEncoding, OpenOptions, SimpleCtx};

/// Bytes that don't repeat, so a misplaced record shows.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

struct Sample {
    big: Vec<u8>,
    text: Vec<u8>,
    uninst: Vec<u8>,
}

impl Sample {
    fn new() -> Self {
        Self {
            big: noise(150_000, 1),
            text: b"an installer's readme\r\n".repeat(400),
            uninst: noise(3000, 2),
        }
    }

    fn ops(&self) -> Vec<Op<'_>> {
        vec![
            Op::SetOutPath(b"$INSTDIR"),
            Op::File(b"readme.txt", &self.text),
            Op::File(b"big.bin", &self.big),
            // The same data as readme.txt: stored once.
            Op::File(b"copy-of-readme.txt", &self.text),
            Op::Attributes(b"copy-of-readme.txt", 0x21),
            Op::SetOutPath(b"$INSTDIR\\sub"),
            Op::File(b"in-sub.txt", b"in sub"),
            Op::SetOutPath(b"$OUTDIR\\deeper"),
            Op::File(b"deeper.txt", b"deeper"),
            Op::SetOutPath(b"$PLUGINSDIR"),
            Op::File(b"plugin.dll", b"MZ plugin"),
            Op::SetOutPath(b"$SYSDIR"),
            Op::File(b"sys.dll", b"MZ system"),
            Op::File(b"$INSTDIR\\absolute.txt", b"absolute"),
            Op::EmptyFile(b"$INSTDIR\\empty.txt"),
            Op::WriteUninstaller {
                name: b"uninstall.exe",
                alt: Some(b"$INSTDIR\\uninstall.exe"),
                data: &self.uninst,
                patches: vec![(300, b"ICON".to_vec())],
            },
        ]
    }

    /// Each file's data, by name, for a stub of `stub` bytes.
    fn want(&self, stub: usize) -> BTreeMap<String, Vec<u8>> {
        let mut uninst = super::write::stub(stub);
        let name = if stub == 0 {
            "uninstall.exe.nsis"
        } else {
            uninst[300..304].copy_from_slice(b"ICON");
            "uninstall.exe"
        };
        uninst.extend_from_slice(&self.uninst);
        [
            ("readme.txt", self.text.clone()),
            ("big.bin", self.big.clone()),
            ("copy-of-readme.txt", self.text.clone()),
            ("sub/in-sub.txt", b"in sub".to_vec()),
            ("sub/deeper/deeper.txt", b"deeper".to_vec()),
            ("$PLUGINSDIR/plugin.dll", b"MZ plugin".to_vec()),
            ("$SYSDIR/sys.dll", b"MZ system".to_vec()),
            ("absolute.txt", b"absolute".to_vec()),
            ("empty.txt", Vec::new()),
            (name, uninst),
        ]
        .into_iter()
        .map(|(p, d)| (p.to_owned(), d))
        .collect()
    }
}

fn open_with(bytes: &[u8], opts: &OpenOptions) -> (tempfile::TempDir, Result<NsisReader>) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("setup.exe");
    std::fs::write(&p, bytes).unwrap();
    let r =
        Source::new(&p, Vec::new(), opts).and_then(|s| NsisReader::open(s, &mut SimpleCtx::new()));
    (dir, r)
}

fn open(bytes: &[u8]) -> (tempfile::TempDir, Result<NsisReader>) {
    open_with(bytes, &OpenOptions::default())
}

/// Each entry's data, or why it failed.
#[derive(Default)]
struct Collect(BTreeMap<String, std::result::Result<Vec<u8>, ErrorKind>>);

impl EntrySink for Collect {
    fn entry(&mut self, e: &Entry, data: &mut dyn Read, _: &mut dyn Ctx) -> Result<()> {
        let mut v = Vec::new();
        let r = data
            .read_to_end(&mut v)
            .map(|_| v)
            .map_err(|e| crate::io::read_error(&e).kind);
        self.0.insert(e.path.clone(), r);
        Ok(())
    }
}

fn extract(r: &mut NsisReader) -> BTreeMap<String, std::result::Result<Vec<u8>, ErrorKind>> {
    let mut sink = Collect::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    sink.0
}

fn read_entry(r: &mut NsisReader, path: &str) -> std::result::Result<Vec<u8>, ErrorKind> {
    let id = r
        .entries
        .iter()
        .position(|e| e.path == path)
        .unwrap_or_else(|| panic!("no {path}"));
    let mut v = Vec::new();
    r.open_entry(id, &mut SimpleCtx::new())
        .map_err(|e| e.kind)?
        .read_to_end(&mut v)
        .map_err(|e| crate::io::read_error(&e).kind)?;
    Ok(v)
}

fn prop(r: &mut NsisReader, name: &str) -> Option<String> {
    r.info(&mut SimpleCtx::new())
        .unwrap()
        .external?
        .properties
        .into_iter()
        .find(|p| p.name == name)
        .map(|p| p.value)
}

/// Every file comes out whole, in one pass and one by one (backwards), with its exact size,
/// and the test passes.
fn reads_whole(bytes: &[u8], want: &BTreeMap<String, Vec<u8>>, what: &str) -> NsisReader {
    let (_d, r) = open(bytes);
    let mut r = r.unwrap_or_else(|e| panic!("{what}: {e}"));
    let listed: Vec<&str> = r.entries.iter().map(|e| e.path.as_str()).collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    let wanted: Vec<&str> = want.keys().map(String::as_str).collect();
    assert_eq!(sorted, wanted, "{what}: listed {listed:?}");
    for e in &r.entries {
        assert_eq!(
            e.size,
            Some(want[&e.path].len() as u64),
            "{what}: {}",
            e.path
        );
    }
    let got = extract(&mut r);
    for (p, data) in want {
        assert!(
            got.get(p) == Some(&Ok(data.clone())),
            "{what}: {p}: {:?}",
            got.get(p).map(|r| r.as_ref().map(Vec::len))
        );
    }
    for (p, data) in want.iter().rev() {
        assert!(
            read_entry(&mut r, p).as_ref() == Ok(data),
            "{what}: {p} alone"
        );
    }
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(report.ok(), "{what}: {:?}", report.errors);
    r
}

#[test]
fn reads_every_layout() {
    let s = Sample::new();
    let ops = s.ops();
    let methods = [
        W::Deflate,
        W::Nsis2Deflate,
        W::Lzma { filter: None },
        W::Lzma {
            filter: Some(false),
        },
        W::Lzma { filter: Some(true) },
    ];
    for strings in [S::Nsis3Unicode, S::Nsis3Ansi, S::Nsis2Ansi, S::ParkUnicode] {
        for method in methods {
            for (solid, header_compressed) in [(true, true), (false, true), (false, false)] {
                for is64 in [false, true] {
                    let what = format!(
                        "{strings:?} {method:?} solid {solid} header {header_compressed} 64 {is64}"
                    );
                    let layout = Layout {
                        strings,
                        solid,
                        method,
                        header_compressed,
                        is64,
                        ..Layout::default()
                    };
                    let mut r = reads_whole(&nsis(&ops, &layout), &s.want(4096), &what);
                    let info = r.info(&mut SimpleCtx::new()).unwrap();
                    assert_eq!(info.solid, solid, "{what}");
                    assert_eq!(
                        prop(&mut r, "Target").is_some(),
                        is64,
                        "{what}: {:?}",
                        prop(&mut r, "Target")
                    );
                }
            }
        }
    }
}

#[test]
fn lists_as_7zip_does() {
    let s = Sample::new();
    let (_d, r) = open(&nsis(&s.ops(), &Layout::default()));
    let r = r.unwrap();
    let listed: Vec<&str> = r.entries.iter().map(|e| e.path.as_str()).collect();
    // By data position, the empty file first; shared data together.
    assert_eq!(listed[0], "empty.txt");
    let by = |p: &str| r.entries.iter().find(|e| e.path == p).unwrap();
    assert_eq!(by("copy-of-readme.txt").dos_attrs, Some(0x21));
    assert_eq!(by("readme.txt").dos_attrs, None);
    assert_eq!(
        by("readme.txt").modified,
        from_ntfs(Layout::default().mtime)
    );
    assert!(by("uninstall.exe").modified.is_none());
    assert_eq!(by("readme.txt").method.as_deref(), Some("LZMA:20"));
    let pos = |p: &str| r.parsed.items[by(p).id].pos;
    assert_eq!(pos("readme.txt"), pos("copy-of-readme.txt"));
}

#[test]
fn a_bare_installer_names_its_uninstaller_as_7zip_does() {
    let s = Sample::new();
    let layout = Layout {
        stub: 0,
        ..Layout::default()
    };
    reads_whole(&nsis(&s.ops(), &layout), &s.want(0), "no stub");
}

/// With no icon patch, `WriteUninstaller` writes its record alone: the whole uninstaller, as
/// makensis stores one `!uninstfinalize` signed.
#[test]
fn an_uninstaller_without_a_patch_is_its_record() {
    let whole = b"MZ a finished, signed uninstaller".to_vec();
    for solid in [true, false] {
        let ops = [
            Op::File(b"a.txt", b"a"),
            Op::WriteUninstaller {
                name: b"$INSTDIR\\uninstall.exe",
                alt: None,
                data: &whole,
                patches: Vec::new(),
            },
        ];
        let layout = Layout {
            solid,
            method: W::Deflate,
            ..Layout::default()
        };
        let (_d, r) = open(&nsis(&ops, &layout));
        let mut r = r.unwrap();
        let e = r
            .entries
            .iter()
            .find(|e| e.path == "uninstall.exe")
            .unwrap();
        assert_eq!(e.size, Some(whole.len() as u64), "solid {solid}");
        assert_eq!(
            read_entry(&mut r, "uninstall.exe"),
            Ok(whole.clone()),
            "solid {solid}"
        );
        assert_eq!(
            extract(&mut r)["uninstall.exe"],
            Ok(whole.clone()),
            "solid {solid}"
        );
    }
}

#[test]
fn installlib_names_its_library() {
    let lib = b"MZ the library".to_vec();
    for old in [false, true] {
        // InstallLib puts the library's name in $R4, then 28 instructions on extracts to $R0
        // (26 on, after a Goto, in its old form).
        let mut ops = vec![
            Op::Raw([7, 0, 0, 0, 0, 0, 0]),
            Op::Assign(14, b"$SYSDIR\\lib.dll"),
        ];
        let fill = if old { 24 } else { 27 };
        ops.extend((0..fill).map(|_| Op::Raw([7, 0, 0, 0, 0, 0, 0])));
        if old {
            ops.push(Op::Nop);
        }
        ops.push(Op::File(b"$R0", &lib));
        let (_d, r) = open(&nsis(&ops, &Layout::default()));
        let mut r = r.unwrap();
        assert_eq!(r.entries[0].path, "$SYSDIR/lib.dll", "old {old}");
        assert_eq!(read_entry(&mut r, "$SYSDIR/lib.dll"), Ok(lib.clone()));
    }
}

#[test]
fn parks_instruction_numbers_are_read() {
    let s = Sample::new();
    for fonts in 0..=2 {
        let layout = Layout {
            strings: S::ParkUnicode,
            park_fonts: fonts,
            ..Layout::default()
        };
        let mut r = reads_whole(&nsis(&s.ops(), &layout), &s.want(4096), &format!("{fonts}"));
        assert_eq!(
            prop(&mut r, "Version").as_deref(),
            Some("NSIS 2 (Jim Park's), Unicode")
        );
    }
}

#[test]
fn ansi_names_take_the_encoding() {
    let ops = [
        Op::File(b"caf\xe9.txt", b"latin"),
        Op::File("名前.txt".as_bytes(), b"utf8"),
    ];
    let layout = Layout {
        strings: S::Nsis2Ansi,
        ..Layout::default()
    };
    let opts = OpenOptions {
        names: NameDecoding {
            encoding: NameEncoding::Cp1252,
            ..NameDecoding::default()
        },
        ..OpenOptions::default()
    };
    let (_d, r) = open_with(&nsis(&ops, &layout), &opts);
    let r = r.unwrap();
    let names: Vec<&str> = r.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(names.contains(&"café.txt"), "{names:?}");
    // UTF-8 bytes read as UTF-8 first (makensis 2 wrote a UTF-8 script's bytes as they were).
    let (_d, r) = open(&nsis(&ops, &layout));
    let r = r.unwrap();
    assert!(r.entries.iter().any(|e| e.path == "名前.txt"));
}

#[test]
fn a_crc_mismatch_fails_the_test_not_the_files() {
    let s = Sample::new();
    let mut bytes = nsis(&s.ops(), &Layout::default());
    // In the stub: no file's data changes.
    bytes[1000] ^= 1;
    let (_d, r) = open(&bytes);
    let mut r = r.unwrap();
    assert!(
        extract(&mut r)
            .iter()
            .filter(|(p, _)| *p != "uninstall.exe")
            .all(|(_, d)| d.is_ok())
    );
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.path.is_empty() && e.message.contains("CRC"))
    );
    // Built without its CRC: a note says so.
    let layout = Layout {
        crc: false,
        ..Layout::default()
    };
    let (_d, r) = open(&nsis(&s.ops(), &layout));
    let mut r = r.unwrap();
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(report.ok());
    assert!(report.note.unwrap().contains("CRCCheck off"));
}

#[test]
fn a_cut_installer_lists_whole_and_reads_up_to_the_cut() {
    let s = Sample::new();
    for (solid, method) in [
        (true, W::Lzma { filter: None }),
        (true, W::Deflate),
        (false, W::Lzma { filter: None }),
        (false, W::Deflate),
    ] {
        let layout = Layout {
            solid,
            method,
            ..Layout::default()
        };
        let bytes = nsis(&s.ops(), &layout);
        let what = format!("solid {solid} {method:?}");
        // A third in: the header and the small files are in; big.bin is cut.
        let keep = bytes.len() * 2 / 3;
        let (_d, r) = open(&bytes[..keep]);
        let mut r = r.unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(r.entries.len(), 10, "{what}");
        let got = extract(&mut r);
        assert_eq!(got["readme.txt"], Ok(s.text.clone()), "{what}");
        assert_eq!(got["big.bin"], Err(ErrorKind::Corrupt), "{what}");
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert!(!report.ok(), "{what}");
        // Before the header's end, nothing lists.
        let (_d, r) = open(&bytes[..4096 + 40]);
        assert_eq!(r.err().map(|e| e.kind), Some(ErrorKind::Corrupt), "{what}");
    }
}

#[test]
fn an_lzma_filter_byte_nsis_doesnt_write_goes_to_7zip() {
    let layout = Layout {
        solid: false,
        method: W::Lzma {
            filter: Some(false),
        },
        ..Layout::default()
    };
    let mut bytes = nsis(&[Op::File(b"a.txt", b"a")], &layout);
    // The first record's filter byte, after the header record, made 2.
    let at = 4096 + 28;
    let hlen = (u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) & 0x7FFF_FFFF) as usize;
    let rec = at + 4 + hlen;
    assert_eq!(bytes[rec + 4], 0);
    bytes[rec + 4] = 2;
    let (_d, r) = open(&bytes);
    let e = r.err().unwrap();
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    assert!(e.message.contains("filter byte 2"), "{e}");
}

#[test]
fn damaged_headers_are_corrupt() {
    let s = Sample::new();
    let good = nsis(&s.ops(), &Layout::default());
    // A header length of 4 GiB.
    let mut b = good.clone();
    b[4096 + 20..4096 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    let (_d, r) = open(&b);
    assert_eq!(r.err().map(|e| e.kind), Some(ErrorKind::Corrupt));
    // No first header.
    let (_d, r) = open(&vec![0u8; 8192]);
    assert_eq!(r.err().map(|e| e.kind), Some(ErrorKind::Corrupt));
    // First-header flags NSIS doesn't write: a fork's.
    let mut b = good;
    b[4096] = 0x70;
    let (_d, r) = open(&b);
    assert_eq!(
        r.err().map(|e| e.kind),
        Some(ErrorKind::UnsupportedOperation)
    );
}

#[test]
fn a_large_dictionary_is_refused() {
    let layout = Layout {
        dict: 1 << 30,
        ..Layout::default()
    };
    let bytes = nsis(&[Op::File(b"a", b"a")], &layout);
    let opts = OpenOptions {
        limits: crate::Limits {
            decoder_memory: 64 << 20,
            ..crate::Limits::default()
        },
        ..OpenOptions::default()
    };
    let (_d, r) = open_with(&bytes, &opts);
    assert_eq!(r.err().map(|e| e.kind), Some(ErrorKind::LimitExceeded));
}

#[test]
fn info_says_how_it_was_built() {
    let s = Sample::new();
    let layout = Layout {
        strings: S::Nsis2Ansi,
        solid: false,
        method: W::Nsis2Deflate,
        uninstaller: true,
        ..Layout::default()
    };
    let (_d, r) = open(&nsis(&s.ops(), &layout));
    let mut r = r.unwrap();
    let info = r.info(&mut SimpleCtx::new()).unwrap();
    assert!(!info.solid);
    assert!(info.sfx);
    let x = info.external.unwrap();
    assert_eq!(x.levels, ["nsis"]);
    let props: BTreeMap<String, String> = x
        .properties
        .into_iter()
        .map(|p| (p.name, p.value))
        .collect();
    assert_eq!(props["Version"], "NSIS 2, ANSI");
    assert_eq!(props["Kind"], "uninstaller");
    assert_eq!(props["Method"], "Deflate");
    assert_eq!(props["Stub"], "4096 bytes");
    assert_eq!(props["Checksum"], "CRC-32 of the installer");
    assert_eq!(
        r.entries
            .iter()
            .find(|e| e.path == "big.bin")
            .unwrap()
            .packed_size,
        Some(150_000 + 15)
    );
}

#[test]
fn entries_over_the_limit_fail() {
    let s = Sample::new();
    let opts = OpenOptions {
        limits: crate::Limits {
            max_entries: Some(5),
            ..crate::Limits::default()
        },
        ..OpenOptions::default()
    };
    let (_d, r) = open_with(&nsis(&s.ops(), &Layout::default()), &opts);
    assert_eq!(r.err().map(|e| e.kind), Some(ErrorKind::LimitExceeded));
}
