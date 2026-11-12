use std::collections::BTreeMap;

use super::{
    write::{File, Layout, Raw as Extra, chm},
    *,
};
use crate::{Limits, OpenOptions, SimpleCtx};

/// Bytes that don't repeat, so a misplaced frame shows.
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

/// `#SYSTEM`: version 3, then code 2 (default topic), 3 (title), 4 (language) and 9 (compiler).
fn system() -> Vec<u8> {
    let mut d = 3u32.to_le_bytes().to_vec();
    let mut rec = |code: u16, v: &[u8]| {
        d.extend_from_slice(&code.to_le_bytes());
        d.extend_from_slice(&(v.len() as u16).to_le_bytes());
        d.extend_from_slice(v);
    };
    rec(2, b"index.htm\0");
    rec(3, b"BeeZip test help\0");
    let mut lang = 0x0407u32.to_le_bytes().to_vec();
    lang.extend_from_slice(&[0; 24]);
    rec(4, &lang);
    rec(9, b"HHA Version 4.74.8702\0");
    d
}

struct Sample {
    sys: Vec<u8>,
    big: Vec<u8>,
    gif: Vec<u8>,
}

impl Sample {
    fn new() -> Self {
        Self {
            sys: system(),
            // Past two reset intervals of 64 KiB, so it spans frames and resets.
            big: noise(150_000, 1),
            gif: noise(40_000, 2),
        }
    }

    fn files(&self) -> Vec<File<'_>> {
        vec![
            File {
                name: "/index.htm",
                section: 1,
                data: b"<html>hello</html>",
            },
            File {
                name: "/pages/a.htm",
                section: 1,
                data: &self.big,
            },
            File {
                name: "/pages/b.htm",
                section: 1,
                data: b"<html>b</html>",
            },
            File {
                name: "/images/x.gif",
                section: 1,
                data: &self.gif,
            },
            File {
                name: "/#SYSTEM",
                section: 0,
                data: &self.sys,
            },
            File {
                name: "/#ITBITS",
                section: 0,
                data: b"",
            },
            File {
                name: "/$WWKeywordLinks/Property",
                section: 0,
                data: b"\0\0\0\0",
            },
        ]
    }

    fn want(&self) -> BTreeMap<String, Vec<u8>> {
        self.files()
            .iter()
            .map(|f| (f.name[1..].to_owned(), f.data.to_vec()))
            .collect()
    }
}

/// The reader over `bytes`, with the folder that holds its file.
fn open_with(bytes: &[u8], opts: &OpenOptions) -> (tempfile::TempDir, Result<ChmReader>) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("t.chm");
    std::fs::write(&p, bytes).unwrap();
    let r =
        Source::new(&p, Vec::new(), opts).and_then(|s| ChmReader::open(s, &mut SimpleCtx::new()));
    (dir, r)
}

fn open(bytes: &[u8]) -> (tempfile::TempDir, Result<ChmReader>) {
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

fn extract(r: &mut ChmReader) -> BTreeMap<String, std::result::Result<Vec<u8>, ErrorKind>> {
    let mut sink = Collect::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    sink.0
}

fn read_entry(r: &mut ChmReader, path: &str) -> std::result::Result<Vec<u8>, ErrorKind> {
    let id = r.entries.iter().position(|e| e.path == path).unwrap();
    let mut v = Vec::new();
    r.open_entry(id, &mut SimpleCtx::new())
        .map_err(|e| e.kind)?
        .read_to_end(&mut v)
        .map_err(|e| crate::io::read_error(&e).kind)?;
    Ok(v)
}

/// Every file comes out whole, in one pass and one by one (backwards, so each reaches back to
/// its reset point).
fn reads_whole(bytes: &[u8], s: &Sample, what: &str) {
    let (_d, r) = open(bytes);
    let mut r = r.unwrap_or_else(|e| panic!("{what}: {e}"));
    let want = s.want();
    let got = extract(&mut r);
    for (p, data) in &want {
        assert_eq!(got.get(p), Some(&Ok(data.clone())), "{what}: {p}");
    }
    for (p, data) in want.iter().rev() {
        assert_eq!(read_entry(&mut r, p).as_ref(), Ok(data), "{what}: {p}");
    }
}

#[test]
fn encints_are_read_up_to_nine_bytes() {
    let mut p = 0;
    assert_eq!(encint(&[0x05], &mut p), Some(5));
    let mut p = 0;
    assert_eq!(encint(&[0x81, 0x00], &mut p), Some(128));
    assert_eq!(p, 2);
    let mut p = 0;
    let mut nine = vec![0xff; 8];
    nine.push(0x7f);
    assert_eq!(encint(&nine, &mut p), Some(u64::MAX >> 1));
    let mut p = 0;
    assert_eq!(encint(&[0x80; 10], &mut p), None);
    let mut p = 0;
    assert_eq!(encint(&[0x80, 0x80], &mut p), None);
}

#[test]
fn lists_folders_first_then_files_in_data_order() {
    let s = Sample::new();
    let (_d, r) = open(&chm(&s.files(), &Layout::default()));
    let r = r.unwrap();
    let listed: Vec<(&str, bool)> = r
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e.is_dir()))
        .collect();
    assert_eq!(
        listed,
        [
            ("$WWKeywordLinks", true),
            ("images", true),
            ("pages", true),
            ("#SYSTEM", false),
            ("#ITBITS", false),
            ("$WWKeywordLinks/Property", false),
            ("index.htm", false),
            ("pages/a.htm", false),
            ("pages/b.htm", false),
            ("images/x.gif", false),
        ]
    );
    let by = |p: &str| r.entries.iter().find(|e| e.path == p).unwrap();
    assert_eq!(by("#SYSTEM").method.as_deref(), Some("Copy"));
    assert_eq!(by("pages/a.htm").method.as_deref(), Some("LZX:16"));
    assert_eq!(by("pages/a.htm").size, Some(150_000));
    assert_eq!(by("#ITBITS").size, Some(0));
    assert_eq!(by("pages").method, None);
    assert_eq!(r.methods, ["Copy", "LZX:16"]);
}

#[test]
fn reads_every_layout() {
    let s = Sample::new();
    let layouts = [
        ("default", Layout::default()),
        (
            "ITSF version 2",
            Layout {
                itsf_version: 2,
                ..Layout::default()
            },
        ),
        (
            "directory last, content offset 0 (7-Zip's help)",
            Layout {
                dir_at_end: true,
                ..Layout::default()
            },
        ),
        (
            "LZXC version 1 (bytes)",
            Layout {
                lzxc_version: 1,
                ..Layout::default()
            },
        ),
        (
            "128 KiB window and interval",
            Layout {
                reset_frames: 4,
                window_frames: 4,
                ..Layout::default()
            },
        ),
        (
            "a 2 MiB window, a reset every frame",
            Layout {
                reset_frames: 1,
                window_frames: 64,
                ..Layout::default()
            },
        ),
        (
            "small chunks, the first misnamed (chmcmd)",
            Layout {
                chunk_size: 0x100,
                first_pmgl: Some(1),
                ..Layout::default()
            },
        ),
    ];
    for (what, l) in layouts {
        reads_whole(&chm(&s.files(), &l), &s, what);
    }
}

#[test]
fn info_says_what_system_says() {
    let s = Sample::new();
    let (_d, r) = open(&chm(&s.files(), &Layout::default()));
    let info = r.unwrap().info(&mut SimpleCtx::new()).unwrap();
    let x = info.external.unwrap();
    assert_eq!(x.backend, None);
    assert_eq!(x.levels, ["chm"]);
    let props: Vec<(String, String)> = x
        .properties
        .into_iter()
        .map(|p| (p.name, p.value))
        .collect();
    let want = [
        ("Title", "BeeZip test help"),
        ("Default topic", "index.htm"),
        ("Language", "0x0407"),
        ("Compiler", "HHA Version 4.74.8702"),
        ("LZX window", "64 KiB"),
        ("Reset interval", "64 KiB"),
    ];
    assert_eq!(
        props,
        want.map(|(n, v)| (n.to_owned(), v.to_owned())).to_vec()
    );
    assert_eq!(info.methods, ["Copy", "LZX:16"]);
}

#[test]
fn a_cut_file_lists_whole_and_gives_what_is_left() {
    let s = Sample::new();
    let whole = chm(&s.files(), &Layout::default());
    // Cut inside the directory: nothing to list.
    let (_d, r) = open(&whole[..0x200]);
    assert_eq!(r.err().unwrap().kind, ErrorKind::Corrupt);
    // Cut 20 KB before the end, in section 1's last frame: the files before it come out, and
    // images/x.gif, which ends in it, fails.
    let (_d, r) = open(&whole[..whole.len() - 20_000]);
    let mut r = r.unwrap();
    assert_eq!(r.entries.len(), 10);
    let got = extract(&mut r);
    let want = s.want();
    for p in [
        "#SYSTEM",
        "#ITBITS",
        "$WWKeywordLinks/Property",
        "index.htm",
        "pages/a.htm",
        "pages/b.htm",
    ] {
        assert_eq!(got[p], Ok(want[p].clone()), "{p}");
    }
    assert_eq!(got["images/x.gif"], Err(ErrorKind::Corrupt));
    // The test names them, and says what it can't check.
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    let failed: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(failed, ["images/x.gif"]);
    assert!(report.errors[0].message.contains("cut short"));
    assert_eq!(report.note.as_deref(), Some(NO_CHECKSUMS));
    // Whole, it passes.
    let (_d, r) = open(&whole);
    let report = r.unwrap().test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(report.ok());
    assert_eq!(report.entries, 10);
}

#[test]
fn what_beezip_does_not_read_goes_to_7zip() {
    let s = Sample::new();
    let cases = [
        Layout {
            itsf_version: 4,
            ..Layout::default()
        },
        Layout {
            lzxc_magic: *b"LZXD",
            ..Layout::default()
        },
        Layout {
            lzxc_version: 3,
            ..Layout::default()
        },
        Layout {
            reset_version: 3,
            ..Layout::default()
        },
        Layout {
            reset_entry_size: 4,
            ..Layout::default()
        },
        Layout {
            reset_block: 0x1_0000,
            ..Layout::default()
        },
        Layout {
            section_names: vec![
                "Uncompressed".to_owned(),
                "MSCompressed".to_owned(),
                "Other".to_owned(),
            ],
            ..Layout::default()
        },
        Layout {
            transform: "{0A9007C1-4076-11D3-8789-0000F8105754}".to_owned(),
            ..Layout::default()
        },
    ];
    for l in cases {
        let (_d, r) = open(&chm(&s.files(), &l));
        let e = r.err().unwrap_or_else(|| panic!("{l:?} opened"));
        assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{l:?}: {e}");
    }
}

#[test]
fn damage_is_corrupt() {
    let s = Sample::new();
    // The directory: nothing can be listed.
    for l in [
        Layout {
            chunk_size_field: Some(0),
            ..Layout::default()
        },
        Layout {
            chunk_size_field: Some(u32::MAX),
            ..Layout::default()
        },
        Layout {
            encint_padding: 20,
            ..Layout::default()
        },
    ] {
        let (_d, r) = open(&chm(&s.files(), &l));
        let e = r.err().unwrap_or_else(|| panic!("{l:?} opened"));
        assert_eq!(e.kind, ErrorKind::Corrupt, "{l:?}: {e}");
    }
    // Section 1's description: the listing stands, section 1's files fail, section 0's read.
    let frames = 6; // 190,032 bytes of section 1
    for l in [
        Layout {
            window_frames: 128,
            ..Layout::default()
        },
        Layout {
            reset_frames: 0,
            ..Layout::default()
        },
        Layout {
            uncompressed: Some(1 << 40),
            ..Layout::default()
        },
        Layout {
            reset_starts: Some((0..frames).rev().map(|f| f * 0x8000).collect()),
            ..Layout::default()
        },
    ] {
        let (_d, r) = open(&chm(&s.files(), &l));
        let mut r = r.unwrap_or_else(|e| panic!("{l:?}: {e}"));
        let got = extract(&mut r);
        assert_eq!(got["index.htm"], Err(ErrorKind::Corrupt), "{l:?}");
        assert_eq!(got["#SYSTEM"], Ok(s.sys.clone()), "{l:?}");
    }
    // Entries that point past their data.
    let l = Layout {
        extra: vec![
            Extra {
                name: b"/past0.htm".to_vec(),
                section: 0,
                offset: 1 << 40,
                length: 10,
            },
            Extra {
                name: b"/past1.htm".to_vec(),
                section: 1,
                offset: 1 << 40,
                length: 10,
            },
            Extra {
                name: b"/section5.htm".to_vec(),
                section: 5,
                offset: 0,
                length: 10,
            },
        ],
        ..Layout::default()
    };
    let (_d, r) = open(&chm(&s.files(), &l));
    let mut r = r.unwrap();
    let got = extract(&mut r);
    for p in ["past0.htm", "past1.htm", "section5.htm"] {
        assert_eq!(got[p], Err(ErrorKind::Corrupt), "{p}");
    }
    assert_eq!(got["pages/a.htm"], Ok(s.big.clone()));
}

#[test]
fn a_damaged_frame_fails_its_reset_interval_only() {
    let s = Sample::new();
    let whole = chm(&s.files(), &Layout::default());
    let (_d, r) = open(&whole);
    let r = r.unwrap();
    let sec1 = r.inner.sec1.clone().unwrap();
    // The second interval's block header: an LZX block of type 0, which there isn't.
    let at = (sec1.content_at + sec1.starts[2]) as usize;
    let mut bad_bytes = whole.clone();
    bad_bytes[at + 1] &= 0x8f;
    let (_d, r) = open(&bad_bytes);
    let mut r = r.unwrap();
    let got = extract(&mut r);
    // pages/a.htm runs from frame 0 into the damaged interval; pages/b.htm and images/x.gif
    // are in the third interval, after a reset, and read.
    assert_eq!(got["index.htm"], Ok(b"<html>hello</html>".to_vec()));
    assert_eq!(got["pages/a.htm"], Err(ErrorKind::Corrupt));
    assert_eq!(got["pages/b.htm"], Ok(b"<html>b</html>".to_vec()));
    assert_eq!(got["images/x.gif"], Ok(s.gif.clone()));
}

#[test]
fn entries_count_against_the_limit() {
    let s = Sample::new();
    let opts = OpenOptions::new(Limits {
        max_entries: Some(5),
        ..Limits::default()
    });
    let (_d, r) = open_with(&chm(&s.files(), &Layout::default()), &opts);
    assert_eq!(r.err().unwrap().kind, ErrorKind::LimitExceeded);
}
