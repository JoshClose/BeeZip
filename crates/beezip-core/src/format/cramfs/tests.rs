use std::collections::BTreeMap;

use super::{
    write::{Built, Ext, Layout, Node, cramfs},
    *,
};
use crate::{Limits, NameEncoding, OpenOptions, SimpleCtx};

/// Bytes that don't repeat, so a misplaced block shows.
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
    holes: Vec<u8>,
    text: Vec<u8>,
}

impl Sample {
    fn new() -> Self {
        let mut holes = noise(5000, 2);
        holes.extend_from_slice(&[0; 70_000]);
        holes.extend_from_slice(&noise(3000, 3));
        Self {
            // Over 4 blocks of every size up to 64 KiB, and not a whole number of any.
            big: noise(300_001, 1),
            holes,
            text: b"cramfs ".repeat(20_000),
        }
    }

    fn tree(&self) -> Vec<Node<'_>> {
        let mut setuid = Node::file(b"setuid.bin", b"#!/bin/sh\n");
        setuid.mode = 0o104_755;
        vec![
            Node::file(b"readme.txt", b"hello cramfs\n"),
            Node::file(b"empty.txt", b""),
            Node::dir(
                b"sub",
                vec![
                    Node::file(b"big.bin", &self.big),
                    Node::dir(b"inner", vec![Node::file(b"a.txt", b"a\n")]),
                    Node::link(b"up", b"../readme.txt"),
                ],
            ),
            Node::dir(b"empty-dir", vec![]),
            Node::file(b"holes.bin", &self.holes),
            Node::file("café-名前.txt".as_bytes(), &self.text),
            Node::link(b"link", b"readme.txt"),
            Node::special(b"null", 0o20_666, 0x0103),
            Node::special(b"sda1", 0o60_660, 0x0801),
            Node::special(b"fifo", 0o10_644, 0),
            Node::special(b"sock", 0o140_755, 0),
            setuid,
        ]
    }

    /// Each file's data, by path.
    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        [
            ("readme.txt", b"hello cramfs\n".to_vec()),
            ("empty.txt", Vec::new()),
            ("sub/big.bin", self.big.clone()),
            ("sub/inner/a.txt", b"a\n".to_vec()),
            ("holes.bin", self.holes.clone()),
            ("café-名前.txt", self.text.clone()),
            ("setuid.bin", b"#!/bin/sh\n".to_vec()),
        ]
        .into_iter()
        .map(|(p, d)| (p.to_owned(), d))
        .collect()
    }
}

fn open_with(
    bytes: &[u8],
    opts: &OpenOptions,
) -> (tempfile::TempDir, Result<CramfsReader>, SimpleCtx) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("t.img");
    std::fs::write(&p, bytes).unwrap();
    let mut cx = SimpleCtx::new();
    let r = Source::new(&p, Vec::new(), opts).and_then(|s| CramfsReader::open(s, &mut cx));
    (dir, r, cx)
}

fn open(bytes: &[u8]) -> (tempfile::TempDir, Result<CramfsReader>) {
    let (d, r, _) = open_with(bytes, &OpenOptions::default());
    (d, r)
}

/// Each entry's data, or why it failed.
#[derive(Default)]
struct Collect(BTreeMap<String, std::result::Result<Vec<u8>, ErrorKind>>);

impl EntrySink for Collect {
    fn entry(&mut self, e: &Entry, data: &mut dyn Read, _: &mut dyn Ctx) -> Result<()> {
        if e.kind == EntryKind::File {
            let mut v = Vec::new();
            let r = data
                .read_to_end(&mut v)
                .map(|_| v)
                .map_err(|e| crate::io::read_error(&e).kind);
            self.0.insert(e.path.clone(), r);
        }
        Ok(())
    }
}

fn extract(r: &mut CramfsReader) -> BTreeMap<String, std::result::Result<Vec<u8>, ErrorKind>> {
    let mut sink = Collect::default();
    r.extract(&Selection::all(), &mut sink, &mut SimpleCtx::new())
        .unwrap();
    sink.0
}

fn read_entry(r: &mut CramfsReader, path: &str) -> std::result::Result<Vec<u8>, ErrorKind> {
    let id = r.entries.iter().position(|e| e.path == path).unwrap();
    let mut v = Vec::new();
    r.open_entry(id, &mut SimpleCtx::new())
        .map_err(|e| e.kind)?
        .read_to_end(&mut v)
        .map_err(|e| crate::io::read_error(&e).kind)?;
    Ok(v)
}

fn prop(r: &mut CramfsReader, name: &str) -> Option<String> {
    let info = r.info(&mut SimpleCtx::new()).unwrap();
    info.external?
        .properties
        .into_iter()
        .find(|p| p.name == name)
        .map(|p| p.value)
}

/// Every file comes out whole, in one pass and one by one, and the test passes.
fn reads_whole(bytes: &[u8], s: &Sample, what: &str) -> CramfsReader {
    let (_d, r) = open(bytes);
    let mut r = r.unwrap_or_else(|e| panic!("{what}: {e}"));
    let want = s.files();
    let got = extract(&mut r);
    let got_ok: BTreeMap<String, Vec<u8>> = got
        .into_iter()
        .map(|(p, d)| {
            (
                p.clone(),
                d.unwrap_or_else(|e| panic!("{what}: {p}: {e:?}")),
            )
        })
        .collect();
    assert_eq!(
        got_ok.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>(),
        "{what}"
    );
    for (p, data) in &want {
        assert!(got_ok[p] == *data, "{what}: {p}");
        assert!(
            read_entry(&mut r, p).as_ref() == Ok(data),
            "{what}: {p} alone"
        );
    }
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(report.ok(), "{what}: {:?}", report.errors);
    assert_eq!(report.note, None, "{what}: the CRC was checked");
    r
}

#[test]
fn lists_as_7zip_does() {
    let s = Sample::new();
    let (_d, r) = open(&cramfs(&s.tree(), &Layout::default()).image);
    let r = r.unwrap();
    let listed: Vec<&str> = r.entries.iter().map(|e| e.path.as_str()).collect();
    // Each folder's children, then each child folder's.
    assert_eq!(
        listed,
        [
            "readme.txt",
            "empty.txt",
            "sub",
            "empty-dir",
            "holes.bin",
            "café-名前.txt",
            "link",
            "null",
            "sda1",
            "fifo",
            "sock",
            "setuid.bin",
            "sub/big.bin",
            "sub/inner",
            "sub/up",
            "sub/inner/a.txt",
        ]
    );
    let by = |p: &str| r.entries.iter().find(|e| e.path == p).unwrap();
    assert_eq!(by("sub").kind, EntryKind::Dir);
    assert_eq!(by("sub").unix_mode, Some(0o40755));
    assert_eq!(by("sub/big.bin").size, Some(300_001));
    assert_eq!(by("sub/big.bin").method.as_deref(), Some("zlib"));
    assert_eq!(by("empty.txt").size, Some(0));
    assert_eq!(by("empty.txt").method, None);
    assert_eq!(by("setuid.bin").unix_mode, Some(0o104_755));
    assert_eq!(
        by("link").kind,
        EntryKind::Symlink {
            target: "readme.txt".to_owned()
        }
    );
    assert_eq!(
        by("sub/up").kind,
        EntryKind::Symlink {
            target: "../readme.txt".to_owned()
        }
    );
    for p in ["null", "sda1", "fifo", "sock"] {
        assert_eq!(by(p).kind, EntryKind::Other, "{p}");
        assert_eq!(by(p).size, None, "{p}");
    }
    assert_eq!(by("null").unix_mode, Some(0o20_666));
    assert!(
        by("readme.txt").modified.is_none(),
        "CramFS stores no times"
    );
}

#[test]
fn reads_every_layout() {
    let s = Sample::new();
    let tree = s.tree();
    for big_endian in [false, true] {
        for block_size in [4096, 8192, 16384, 32768, 65536] {
            for (pad, holes) in [(false, false), (true, false), (false, true), (true, true)] {
                let what = format!("be {big_endian}, {block_size}, pad {pad}, holes {holes}");
                let layout = Layout {
                    big_endian,
                    block_size,
                    pad,
                    holes,
                    ..Layout::default()
                };
                let mut r = reads_whole(&cramfs(&tree, &layout).image, &s, &what);
                assert_eq!(r.inner.blk, block_size, "{what}");
                assert_eq!(
                    prop(&mut r, "Block size"),
                    Some(format!("{} KiB", block_size / 1024))
                );
                assert_eq!(
                    prop(&mut r, "Byte order").as_deref(),
                    Some(if big_endian {
                        "big-endian"
                    } else {
                        "little-endian"
                    })
                );
                assert_eq!(
                    prop(&mut r, "Boot block"),
                    pad.then(|| "512 bytes".to_owned()),
                    "{what}"
                );
            }
        }
    }
}

#[test]
fn holes_take_no_room() {
    let s = Sample::new();
    let tree = s.tree();
    let plain = cramfs(&tree, &Layout::default());
    let holes = cramfs(
        &tree,
        &Layout {
            holes: true,
            ..Layout::default()
        },
    );
    // 70,000 zeros: 16 whole blocks of them are holes.
    let t = holes.table_at(b"holes.bin");
    let ends: Vec<u32> = (0..20).map(|k| holes.u32_at(t + 4 * k)).collect();
    assert_eq!(ends.windows(2).filter(|w| w[0] == w[1]).count(), 16);
    assert!(holes.image.len() < plain.image.len());
    let (_d, r) = open(&holes.image);
    let mut r = r.unwrap();
    assert_eq!(read_entry(&mut r, "holes.bin"), Ok(s.holes.clone()));
    assert_eq!(
        prop(&mut r, "Flags").as_deref(),
        Some("sorted folders, holes")
    );
}

#[test]
fn reads_extended_block_pointers() {
    let s = Sample::new();
    let tree = s.tree();
    for be in [false, true] {
        for pattern in [
            vec![Ext::Stored, Ext::DirectStored, Ext::Direct, Ext::Plain],
            vec![Ext::Direct],
            vec![Ext::DirectStored, Ext::Plain],
            vec![Ext::Plain, Ext::Stored],
        ] {
            let what = format!("be {be}, {pattern:?}");
            let layout = Layout {
                big_endian: be,
                ext: pattern,
                ..Layout::default()
            };
            let mut r = reads_whole(&cramfs(&tree, &layout).image, &s, &what);
            assert_eq!(
                prop(&mut r, "Flags").as_deref(),
                Some("sorted folders, extended block pointers")
            );
        }
    }
}

#[test]
fn small_files_only_are_4_kib_blocks() {
    let tree = [Node::file(b"a", b"aaaa"), Node::file(b"b", &[7; 4096])];
    for block_size in [4096, 16384] {
        let built = cramfs(
            &tree,
            &Layout {
                block_size,
                ..Layout::default()
            },
        );
        let (_d, r) = open(&built.image);
        let mut r = r.unwrap();
        assert_eq!(r.inner.blk, 4096);
        assert_eq!(read_entry(&mut r, "b"), Ok(vec![7; 4096]));
    }
}

#[test]
fn a_block_size_settles_by_most_files() {
    // Holes everywhere but one file: the holes count for every size they fit, the data for its
    // own.
    let data = noise(40_000, 9);
    let zeros = vec![0u8; 40_000];
    let tree = [
        Node::file(b"zeros", &zeros),
        Node::file(b"data", &data),
        Node::file(b"data2", &data),
    ];
    let built = cramfs(
        &tree,
        &Layout {
            block_size: 8192,
            holes: true,
            ..Layout::default()
        },
    );
    let (_d, r) = open(&built.image);
    let mut r = r.unwrap();
    assert_eq!(r.inner.blk, 8192);
    assert_eq!(read_entry(&mut r, "data"), Ok(data.clone()));
    assert_eq!(read_entry(&mut r, "zeros"), Ok(zeros));
}

#[test]
fn flags_linux_doesnt_know_go_to_7zip() {
    let s = Sample::new();
    // 7-Zip's LZMA variant: method 2 in bits 14–15.
    let built = cramfs(
        &s.tree(),
        &Layout {
            flags: 2 << 14,
            ..Layout::default()
        },
    );
    let (_d, r) = open(&built.image);
    let e = r.err().unwrap();
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    assert!(e.message.contains("0x8000"), "{e}");
}

#[test]
fn no_superblock_is_corrupt() {
    let (_d, r) = open(&[0u8; 2000]);
    assert_eq!(r.err().unwrap().kind, ErrorKind::Corrupt);
    let built = cramfs(&[Node::file(b"a", b"a")], &Layout::default());
    let (_d, r) = open(&built.image[..60]);
    assert_eq!(r.err().unwrap().kind, ErrorKind::Corrupt);
}

#[test]
fn a_crc_mismatch_fails_the_test_not_the_files() {
    let s = Sample::new();
    let mut built = cramfs(&s.tree(), &Layout::default());
    let at = built.inode_at(b"readme.txt");
    // The owner, which nothing reads: the files still read whole.
    built.image[at + 2] ^= 1;
    let (_d, r) = open(&built.image);
    let mut r = r.unwrap();
    let got = extract(&mut r);
    assert!(got.values().all(Result::is_ok));
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert_eq!(report.errors_total, 1, "{:?}", report.errors);
    assert_eq!(report.errors[0].path, "");
    assert!(
        report.errors[0].message.contains("CRC"),
        "{:?}",
        report.errors
    );
}

#[test]
fn version_1_says_it_has_no_checksum() {
    let s = Sample::new();
    let built = cramfs(
        &s.tree(),
        &Layout {
            version2: false,
            ..Layout::default()
        },
    );
    let (_d, r) = open(&built.image);
    let mut r = r.unwrap();
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    assert!(report.note.unwrap().contains("version 1"));
    assert_eq!(
        prop(&mut r, "Checksum").as_deref(),
        Some("none (version 1)")
    );
}

#[test]
fn a_cut_image_lists_whole_and_reads_up_to_the_cut() {
    let s = Sample::new();
    let built = cramfs(&s.tree(), &Layout::default());
    // The data is in folder order: holes.bin and the files after it are past this cut.
    let cut = built.table_at(b"holes.bin") + 8;
    let (_d, r) = open(&built.image[..cut]);
    let mut r = r.unwrap();
    assert_eq!(r.entries.len(), 16);
    let got = extract(&mut r);
    assert_eq!(got["readme.txt"], Ok(b"hello cramfs\n".to_vec()));
    for p in [
        "holes.bin",
        "café-名前.txt",
        "setuid.bin",
        "sub/big.bin",
        "sub/inner/a.txt",
    ] {
        assert_eq!(got[p], Err(ErrorKind::Corrupt), "{p}");
    }
    // The links after the cut list as files of their blocks, which fail.
    let up = r.entries.iter().find(|e| e.path == "sub/up").unwrap();
    assert_eq!(up.kind, EntryKind::File);
    let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.path.is_empty() && e.message.contains("cut short"))
    );
    assert!(report.errors.iter().any(|e| e.path == "sub/big.bin"));
    // Inside the folders: nothing lists.
    let (_d, r) = open(&built.image[..100]);
    assert_eq!(r.err().unwrap().kind, ErrorKind::Corrupt);
}

#[test]
fn damaged_blocks_fail_their_files() {
    let s = Sample::new();
    let tree = s.tree();
    let fresh = || cramfs(&tree, &Layout::default());
    let mut cases: Vec<(&str, Built)> = Vec::new();
    // A pointer before the block's start.
    let mut b = fresh();
    let t = b.table_at(b"sub/big.bin");
    let v = b.u32_at(t + 4);
    b.set_u32(t + 8, v - 1);
    cases.push(("backwards", b));
    // A pointer past the end of the image.
    let mut b = fresh();
    let t = b.table_at(b"sub/big.bin");
    b.set_u32(t + 4, u32::MAX >> 1);
    cases.push(("past the end", b));
    // A block over twice the block size.
    let mut b = fresh();
    let t = b.table_at(b"sub/big.bin");
    let v = b.u32_at(t);
    b.set_u32(t, v + 9000);
    cases.push(("too long", b));
    // A file claiming more than its blocks hold.
    let mut b = fresh();
    b.set_inode(b"sub/big.bin", |i| i.size += 1);
    cases.push(("size", b));
    for (what, mut b) in cases {
        b.seal();
        let (_d, r) = open(&b.image);
        let mut r = r.unwrap_or_else(|e| panic!("{what}: {e}"));
        let got = extract(&mut r);
        assert_eq!(got["sub/big.bin"], Err(ErrorKind::Corrupt), "{what}");
        assert_eq!(got["readme.txt"], Ok(b"hello cramfs\n".to_vec()), "{what}");
    }
}

#[test]
fn bad_folders_are_corrupt_or_skipped() {
    let s = Sample::new();
    let tree = s.tree();
    // A name length of 0, as mkfs.cramfs writes a 253–255-byte name.
    let long = vec![b'n'; 255];
    let b = cramfs(
        &[Node::file(&long, b"x"), Node::file(b"after", b"y")],
        &Layout::default(),
    );
    let (_d, r) = open(&b.image);
    let e = r.err().unwrap();
    assert_eq!(e.kind, ErrorKind::Corrupt);
    assert!(e.message.contains("no length"), "{e}");
    // A name of 252 bytes, the longest the field holds, reads.
    let longest = vec![b'n'; 252];
    let b = cramfs(&[Node::file(&longest, b"x")], &Layout::default());
    let (_d, r) = open(&b.image);
    assert_eq!(r.unwrap().entries[0].path.len(), 252);
    // A folder holding itself: skipped, with a warning.
    let mut b = cramfs(&tree, &Layout::default());
    let root = b.inode(b"");
    b.set_inode(b"sub/inner", |i| {
        i.offset = root.offset;
        i.size = root.size;
    });
    b.seal();
    let (_d, r, cx) = open_with(&b.image, &OpenOptions::default());
    let r = r.unwrap();
    assert!(r.entries.iter().all(|e| !e.path.starts_with("sub/inner/")));
    assert!(
        cx.warnings.iter().any(|w| w.contains("loop")),
        "{:?}",
        cx.warnings
    );
    // A folder's run past the end, or over the superblock.
    for offset in [0x0FFF_FFF0, 8] {
        let mut b = cramfs(&tree, &Layout::default());
        b.set_inode(b"sub", |i| i.offset = offset);
        b.seal();
        let (_d, r) = open(&b.image);
        assert_eq!(r.err().unwrap().kind, ErrorKind::Corrupt, "{offset}");
    }
}

#[test]
fn deep_folders_stop_at_256() {
    fn nest(depth: usize, leaf: Node<'static>) -> Node<'static> {
        (0..depth).fold(leaf, |n, _| Node::dir(b"d", vec![n]))
    }
    let ok = nest(255, Node::file(b"f", b"bottom"));
    let (_d, r) = open(&cramfs(&[ok], &Layout::default()).image);
    let r = r.unwrap();
    assert_eq!(r.entries.len(), 256);
    let deep = nest(300, Node::file(b"f", b"bottom"));
    let (_d, r) = open(&cramfs(&[deep], &Layout::default()).image);
    let e = r.err().unwrap();
    assert_eq!(e.kind, ErrorKind::Corrupt);
    assert!(e.message.contains("256"), "{e}");
}

#[test]
fn entries_over_the_limit_fail() {
    let s = Sample::new();
    let opts = OpenOptions {
        limits: Limits {
            max_entries: Some(10),
            ..Limits::default()
        },
        ..OpenOptions::default()
    };
    let (_d, r, _) = open_with(&cramfs(&s.tree(), &Layout::default()).image, &opts);
    assert_eq!(r.err().unwrap().kind, ErrorKind::LimitExceeded);
}

#[test]
fn names_that_arent_utf8_take_the_encoding() {
    let tree = [Node::file(b"caf\xe9.txt", b"latin")];
    let image = cramfs(&tree, &Layout::default()).image;
    let opts = OpenOptions {
        names: crate::names::NameDecoding {
            encoding: NameEncoding::Cp1252,
            ..crate::names::NameDecoding::default()
        },
        ..OpenOptions::default()
    };
    let (_d, r, _) = open_with(&image, &opts);
    let r = r.unwrap();
    assert_eq!(r.entries[0].path, "café.txt");
    assert_eq!(r.entries[0].raw_path, b"caf\xe9.txt");
}

#[test]
fn info_says_what_the_superblock_does() {
    let s = Sample::new();
    let built = cramfs(
        &s.tree(),
        &Layout {
            name: b"BeeZipCramfs".to_vec(),
            edition: 7,
            ..Layout::default()
        },
    );
    let (_d, r) = open(&built.image);
    let mut r = r.unwrap();
    let info = r.info(&mut SimpleCtx::new()).unwrap();
    assert_eq!(info.methods, ["zlib"]);
    let x = info.external.unwrap();
    assert_eq!((x.backend, x.levels), (None, vec!["cramfs".to_owned()]));
    let props: Vec<(String, String)> = x
        .properties
        .into_iter()
        .map(|p| (p.name, p.value))
        .collect();
    let want = [
        ("Name", "BeeZipCramfs"),
        ("Edition", "7"),
        ("Byte order", "little-endian"),
        ("Block size", "4 KiB"),
        ("Flags", "sorted folders"),
        ("Checksum", "CRC-32 of the image"),
        ("Files", "17"),
    ];
    let want: Vec<(String, String)> = want
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect();
    assert_eq!(props, want);
}
