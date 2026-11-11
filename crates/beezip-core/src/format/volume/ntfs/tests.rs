//! The committed images: 7-Zip's (`thirdparty/7zip/ntfs.img`, `gpt-ntfs.img`) against their
//! records, and `thirdparty/ntfs/` (`tests/fixtures/make-ntfs.sh`), plus the pieces that guard
//! fstool.

use std::{
    io::{Cursor, Read},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use super::*;
use crate::{OpenOptions, Opened, SimpleCtx, ops, source::open as open_path};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `t` as the manifest writes times: `2024-05-06T07:08:09.123456700Z`.
fn utc(t: SystemTime) -> String {
    let t = ::time::OffsetDateTime::from(t);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.nanosecond()
    )
}

/// The image opened by BeeZip's own reader, its entries and the warnings it gave.
fn native(rel: &str) -> (Opened, Vec<Entry>, Vec<String>) {
    let mut cx = SimpleCtx::new();
    let mut opened = open_path(&fixture(rel), &OpenOptions::default(), &mut cx).unwrap();
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.external.unwrap().backend, None, "{rel} went to 7-Zip");
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    (opened, entries, cx.warnings)
}

fn find<'a>(entries: &'a [Entry], path: &str) -> &'a Entry {
    entries
        .iter()
        .find(|e| e.path == path)
        .unwrap_or_else(|| panic!("no `{path}`"))
}

fn data(opened: &mut Opened, id: usize) -> Result<Vec<u8>> {
    let mut cx = SimpleCtx::new();
    let mut r = opened.reader.open_entry(id, &mut cx)?;
    let mut out = Vec::new();
    r.read_to_end(&mut out).map_err(|e| read_error(&e))?;
    Ok(out)
}

/// Every folder before what's in it, every file before its further names, ids in order.
fn well_ordered(entries: &[Entry]) {
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.id, i);
        let parent = e.path.rsplit_once('/').map(|(p, _)| p);
        if let Some(p) = parent {
            let at = entries.iter().position(|d| d.path == p).unwrap();
            assert!(
                at < i && entries[at].is_dir(),
                "`{}` before its folder",
                e.path
            );
        }
        if let EntryKind::Hardlink { target } = &e.kind {
            let at = entries.iter().position(|d| d.path == *target).unwrap();
            assert!(at < i, "`{}` before its target", e.path);
        }
    }
}

#[test]
fn every_file_7zip_lists_is_here() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("manifest.json")).unwrap()).unwrap();
    for file in ["7zip/ntfs.img", "7zip/gpt-ntfs.img"] {
        let record = manifest["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["file"] == file)
            .unwrap();
        let (mut opened, entries, warnings) = native(&format!("thirdparty/{file}"));
        assert!(warnings.is_empty(), "{file}: {warnings:?}");
        well_ordered(&entries);
        let wanted = record["entries"].as_array().unwrap();
        assert_eq!(wanted.len(), 26, "{file}");
        for want in wanted {
            let path = want["path"].as_str().unwrap();
            let e = find(&entries, path);
            match want["kind"].as_str().unwrap() {
                "symlink" => assert_eq!(
                    e.kind,
                    EntryKind::Symlink {
                        target: want["target"].as_str().unwrap().to_owned()
                    },
                    "{file}: {path}"
                ),
                kind => {
                    assert_eq!(kind, "file");
                    let f = match &e.kind {
                        EntryKind::Hardlink { target } => find(&entries, target),
                        _ => e,
                    };
                    assert_eq!(f.kind, EntryKind::File, "{file}: {path}");
                    assert_eq!(f.size, want["size"].as_u64(), "{file}: {path}");
                    let bytes = data(&mut opened, f.id).unwrap();
                    assert_eq!(sha256(&bytes), want["sha256"], "{file}: {path}");
                    assert_eq!(
                        e.modified.map(utc).as_deref(),
                        want["mtime"].as_str(),
                        "{file}: {path}"
                    );
                }
            }
        }

        // What 7-Zip leaves out or lists differently (decision 3).
        for dir in [
            "[SYSTEM]",
            "[SYSTEM]/$Extend",
            "sub",
            "sub/nested",
            "Ünïcödé dir",
        ] {
            assert!(find(&entries, dir).is_dir(), "{file}: {dir}");
        }
        // The first name in the root's index (in collation order) is the file.
        assert_eq!(
            find(&entries, "readme.txt").kind,
            EntryKind::Hardlink {
                target: "hard-readme.txt".into()
            }
        );
        let hidden = find(&entries, "hard-readme.txt:hidden");
        assert_eq!(
            data(&mut opened, hidden.id).unwrap(),
            b"an alternate stream\n"
        );
        assert_eq!(
            find(&entries, "readme.txt:hidden").kind,
            EntryKind::Hardlink {
                target: "hard-readme.txt:hidden".into()
            }
        );
        let mtime = find(&entries, "mtime.txt").modified.unwrap();
        assert_eq!(
            mtime,
            UNIX_EPOCH + Duration::new(1_714_979_289, 123_456_700)
        );
        assert_eq!(find(&entries, "[SYSTEM]/$MFT").packed_size, Some(94_208));
        assert_eq!(find(&entries, "[SYSTEM]/$Extend").dos_attrs, Some(0x16));
        assert!(
            !entries.iter().any(|e| e.path.contains(":$Bad")
                || e.path == "[SYSTEM]/."
                || e.path.contains('~'))
        );
        assert_eq!(entries.len(), 35, "{file}");

        let info = opened.reader.info(&mut SimpleCtx::new()).unwrap();
        assert!(info.methods.is_empty());
        let ext = info.external.unwrap();
        let prop = |name: &str| {
            ext.properties
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.value.as_str())
        };
        assert_eq!(prop("Label"), Some("BeeZipNTFS"));
        assert_eq!(prop("File System"), Some("NTFS 3.1"));
        assert_eq!(prop("Cluster Size"), Some("4096"));
        assert_eq!(prop("MFT Record Size"), Some("1024"));
        assert_eq!(ext.levels.last().map(String::as_str), Some("ntfs"));
    }
}

#[test]
fn rich_image() {
    let (mut opened, entries, warnings) = native("thirdparty/ntfs/rich.img");
    assert!(warnings.is_empty(), "{warnings:?}");
    well_ordered(&entries);
    let mut read = |path: &str| {
        let id = find(&entries, path).id;
        data(&mut opened, id)
    };

    // LZNT1 (units of 64 KiB), one with a hole; and a sparse file, which 7-Zip 26.00 can't read.
    for (path, size, hash) in [
        (
            "compressed/text.txt",
            215_000,
            "2716af02862be9907922fd5806d7c828400407eb8cf4e36dbbe471c26b3ec520",
        ),
        (
            "compressed/random.bin",
            40_000,
            "1807e5036ee223f44da87dcfe9d58e965394b5951ea884328fd0336862ba6ae4",
        ),
        (
            "compressed/mixed.bin",
            180_000,
            "927678369e3b53b2a5156d5c9b456d2d220be1bfbf160da531dba5d2d744c039",
        ),
        (
            "compressed/sparse-compressed.bin",
            3_148_728,
            "cf552db76f3b3455a8aa8d0b911b0a769ccfe174d73fd5ecf0a4ad64218bfda9",
        ),
        (
            "sparse.bin",
            8 << 20,
            "651502d0eb94d27e65cdd696ca786547e9453f4201ae26e12683768f4da3a455",
        ),
        (
            "streams.txt:big",
            20_000,
            "ec5d3a776264925b93b931d95d2e4e7c7dd141874268a8b64145c8f753a428df",
        ),
    ] {
        let bytes = read(path).unwrap();
        assert_eq!(
            (bytes.len(), sha256(&bytes).as_str()),
            (size, hash),
            "{path}"
        );
    }
    let text = find(&entries, "compressed/text.txt");
    assert_eq!(text.method.as_deref(), Some("LZNT1"));
    assert!(text.packed_size.unwrap() < 64 * 1024);
    // Three islands of 8 KiB.
    assert_eq!(find(&entries, "sparse.bin").packed_size, Some(24 * 1024));

    // Links of every kind, targets as stored.
    for (path, target) in [
        ("symlink-rel", "target-dir/in.txt"),
        ("symlink-abs", "/??/C:/Windows/win.ini"),
        ("junction", "/??/C:/Users"),
        ("lx-symlink", "target-dir/in.txt"),
        ("interix-link", "target-dir/in.txt"),
        ("interix-dirlink", "target-dir"),
    ] {
        assert_eq!(
            find(&entries, path).kind,
            EntryKind::Symlink {
                target: target.into()
            },
            "{path}"
        );
    }
    assert_eq!(find(&entries, "interix-chr").kind, EntryKind::Other);
    // ntfs-3g's FIFO is an empty system file, like any other.
    assert_eq!(find(&entries, "interix-fifo").size, Some(0));

    // 61 names of one file: the first in the folder's index is the file.
    let first = "links/hard-link-number-000-".to_owned() + &"x".repeat(60) + ".txt";
    assert_eq!(read(&first).unwrap(), b"linked\n");
    let names: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.path.starts_with("links/"))
        .collect();
    assert_eq!(names.len(), 61);
    assert!(names.iter().all(|e| e.path == first
        || e.kind
            == EntryKind::Hardlink {
                target: first.clone()
            }));

    // 41 streams, after their file; its time to 100 ns.
    let streams = find(&entries, "streams.txt");
    let after: Vec<&str> = entries[streams.id + 1..streams.id + 42]
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert!(
        after.iter().all(|p| p.starts_with("streams.txt:")),
        "{after:?}"
    );
    assert_eq!(
        read("streams.txt:stream07").unwrap(),
        b"stream 7 ".repeat(20)
    );
    assert_eq!(
        streams.modified,
        Some(UNIX_EPOCH + Duration::new(1_715_000_000, 123_456_700))
    );

    // A folder of 200, in name order; the deep path.
    let big: Vec<&str> = entries
        .iter()
        .filter_map(|e| e.path.strip_prefix("big/"))
        .collect();
    let mut sorted = big.clone();
    sorted.sort_unstable();
    assert_eq!((big.len(), &big), (200, &sorted));
    let deep = (0..30).map(|i| format!("d{i:02}/")).collect::<String>() + &"n".repeat(251) + ".txt";
    assert_eq!(read(&deep).unwrap(), b"deep\n");

    // DOS names left out; case twins both in; the deleted file gone.
    assert!(!entries.iter().any(|e| e.path.contains('~')));
    assert_eq!(read("Case.txt").unwrap(), b"upper\n");
    assert_eq!(read("case.txt").unwrap(), b"lower\n");
    assert!(!entries.iter().any(|e| e.path == "deleted.txt"));

    // EFS and WIMBoot: listed, not read.
    let enc = find(&entries, "encrypted.bin");
    assert!(enc.encrypted);
    assert_eq!(
        read("encrypted.bin").unwrap_err().kind,
        ErrorKind::UnsupportedOperation
    );
    assert_eq!(find(&entries, "wof.dll").method.as_deref(), Some("WIM"));
    let e = read("wof.dll").unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation);
    assert!(e.message.contains("WIMBoot"), "{e}");

    let info = opened.reader.info(&mut SimpleCtx::new()).unwrap();
    assert_eq!(info.methods, ["LZNT1", "WIM"]);
}

/// `thirdparty/ntfs/wof.img` (docs/M8.md §4): the same 40,000 bytes WOF-compressed with each
/// algorithm, XPRESS's by Windows' own compressor and LZX's by wimlib's (`tests/fixtures/wof/`),
/// and damaged ones.
#[test]
fn files_windows_compressed() {
    let streams = std::fs::read_to_string(fixture("wof/streams.txt")).unwrap();
    let want = streams.split_whitespace().nth(2).unwrap().to_owned();
    let (mut opened, entries, warnings) = native("thirdparty/ntfs/wof.img");
    assert!(warnings.is_empty(), "{warnings:?}");
    let mut read = |path: &str| data(&mut opened, find(&entries, path).id);
    for (name, method) in [
        ("xpress4k.bin", "XPRESS4K"),
        ("xpress8k.bin", "XPRESS8K"),
        ("xpress16k.bin", "XPRESS16K"),
        ("lzx.bin", "LZX"),
    ] {
        let e = find(&entries, name);
        assert_eq!(e.size, Some(40_000), "{name}");
        assert_eq!(e.method.as_deref(), Some(method), "{name}");
        // What the volume holds for it: its stream.
        assert!(
            e.packed_size.unwrap() < 20_000,
            "{name}: {:?}",
            e.packed_size
        );
        assert_eq!(sha256(&read(name).unwrap()), want, "{name}");
        // Its compressed stream isn't listed once it decodes, as Windows hides it.
        let stream = format!("{name}:WofCompressedData");
        assert!(!entries.iter().any(|e| e.path == stream), "{stream}");
    }
    let e = read("no-stream.bin").unwrap_err();
    assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    let e = read("bad-chunk.bin").unwrap_err();
    assert_eq!(e.kind, ErrorKind::Corrupt, "{e}");
    assert!(e.message.contains("chunk 0"), "{e}");
    let e = read("unknown.bin").unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    // What can't be decoded keeps its stream listed, as before.
    assert!(
        entries
            .iter()
            .any(|e| e.path == "unknown.bin:WofCompressedData")
    );
    assert!(
        !entries
            .iter()
            .any(|e| e.path == "bad-chunk.bin:WofCompressedData")
    );

    let info = opened.reader.info(&mut SimpleCtx::new()).unwrap();
    assert_eq!(
        info.methods,
        ["LZX", "WOF", "XPRESS16K", "XPRESS4K", "XPRESS8K"]
    );
}

/// Testing the whole volume reads everything but the two files it can't, and says so.
#[test]
fn rich_image_tests_but_two() {
    let report = ops::test(
        &fixture("thirdparty/ntfs/rich.img"),
        &crate::Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let failed: Vec<(&str, ErrorKind)> = report
        .errors
        .iter()
        .map(|e| (e.path.as_str(), e.kind))
        .collect();
    assert_eq!(
        failed,
        [
            ("encrypted.bin", ErrorKind::UnsupportedOperation),
            ("wof.dll", ErrorKind::UnsupportedOperation)
        ]
    );
    assert_eq!(report.entries, 376);
}

/// Extracting the whole volume skips the two files it can't read, saying why, and writes the
/// rest (docs/M7.md §16); the first of them used to stop the extraction there.
#[test]
fn rich_image_extracts_but_two() {
    let dest = tempfile::tempdir().unwrap();
    let mut cx = SimpleCtx::new();
    let report = ops::extract(
        &fixture("thirdparty/ntfs/rich.img"),
        dest.path(),
        &crate::Selection::all(),
        &OpenOptions::default(),
        // `Case.txt` and `case.txt` meet on Windows.
        crate::FsOptions {
            overwrite: crate::OverwritePolicy::Rename,
            ..crate::FsOptions::default()
        },
        &mut cx,
    )
    .unwrap();
    let unreadable: Vec<&str> = report
        .skipped
        .iter()
        .filter(|s| s.reason == crate::SkipReason::Unreadable)
        .map(|s| s.path.as_str())
        .collect();
    assert_eq!(unreadable, ["encrypted.bin", "wof.dll"]);
    for (name, why) in [
        ("encrypted.bin", "encrypted with EFS"),
        (
            "wof.dll",
            "compressed by Windows from a WIM file elsewhere (WIMBoot)",
        ),
    ] {
        assert!(!dest.path().join(name).exists(), "{name}");
        assert!(
            cx.warnings
                .iter()
                .any(|w| w.contains(&format!("skipped `{name}`")) && w.contains(why)),
            "{name}: {:?}",
            cx.warnings
        );
    }
    assert!(dest.path().join("streams.txt").is_file());
    // 331 on Windows; hard links may count as links elsewhere.
    assert!(report.files + report.links > 300, "{report:?}");
}

/// Clusters of 512 bytes, smaller than a record; two files whose runs are split over extension
/// records, with a non-resident attribute list; LZNT1 in units of 8 KiB.
#[test]
fn fragmented_image() {
    let (mut opened, entries, warnings) = native("thirdparty/ntfs/frag.img");
    assert!(warnings.is_empty(), "{warnings:?}");
    for tag in ["a", "b"] {
        let want: Vec<u8> = (0..400)
            .flat_map(|i| {
                let piece = format!("frag-{tag} {i:05} ").repeat(64);
                piece.into_bytes().into_iter().take(512)
            })
            .collect();
        let e = find(&entries, &format!("frag-{tag}.bin"));
        assert_eq!(e.packed_size, Some(400 * 512));
        assert!(data(&mut opened, e.id).unwrap() == want, "frag-{tag}.bin");
    }
    let text = find(&entries, "compressed/text.txt");
    assert_eq!(text.method.as_deref(), Some("LZNT1"));
    assert_eq!(
        sha256(&data(&mut opened, text.id).unwrap()),
        "9955c8cad8d722f096a15b9fc6f4c943b36ad4699ae66810c3163ae512bf9a3a"
    );
}

/// Empty streams Windows made non-resident: one piece, last cluster −1, no runs. BeeZip 0.2.0
/// took them for damaged, so every Windows-formatted volume stopped extracting at
/// `$Extend/$RmMetadata/$Repair` (docs/M8.md, decision 1).
#[test]
fn empty_non_resident_streams() {
    let rel = "thirdparty/ntfs/empty-nonres.img";
    let (mut opened, entries, warnings) = native(rel);
    assert!(warnings.is_empty(), "{warnings:?}");
    for path in ["empty.bin", "after.txt:empty"] {
        let e = find(&entries, path);
        assert_eq!((e.size, e.packed_size), (Some(0), Some(0)), "{path}");
        assert_eq!(data(&mut opened, e.id).unwrap(), b"", "{path}");
    }
    let after = find(&entries, "after.txt").id;
    assert_eq!(data(&mut opened, after).unwrap(), b"after the empty one\n");
    let report = ops::test(
        &fixture(rel),
        &crate::Selection::all(),
        &OpenOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);

    // Runs past such a piece's end are damage, as is a second piece after it.
    let g = Geometry {
        sector: 512,
        cluster: 4096,
        record: 1024,
        mft_lcn: 4,
        len: 1 << 20,
        clusters: 256,
        serial: 0,
    };
    let empty = || Piece {
        first_vcn: 0,
        last_vcn: u64::MAX,
        size: 0,
        unit: 0,
        runs: Vec::new(),
    };
    assert_eq!(
        join_checked(&g, &mut [empty()]).unwrap().total_clusters(),
        0
    );
    let mut runs = empty();
    runs.runs.push(Extent {
        lcn: Some(8),
        length: 1,
    });
    assert!(join_checked(&g, &mut [runs]).is_err());
    let mut second = empty();
    second.first_vcn = 1;
    assert!(join_checked(&g, &mut [empty(), second]).is_err());
}

fn base_image() -> Vec<u8> {
    std::fs::read(fixture("thirdparty/7zip/ntfs.img")).unwrap()
}

fn open_bytes(bytes: Vec<u8>) -> Result<Volume> {
    let len = bytes.len() as u64;
    Volume::open(
        Device::new(Box::new(Cursor::new(bytes)), len),
        &Limits::default(),
        &mut SimpleCtx::new(),
    )
}

#[test]
fn boot_sectors_beezip_doesnt_read_are_unsupported() {
    let kind = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut b = base_image();
        edit(&mut b);
        open_bytes(b).map(|_| ()).unwrap_err()
    };
    // 2^8 sectors of 512 bytes: 128 KiB.
    let e = kind(&|b| b[13] = 0xF8);
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    assert!(e.message.contains("128 KiB"), "{e}");
    // 2 sectors, written the negative way.
    assert_eq!(
        kind(&|b| b[13] = 0xFF).kind,
        ErrorKind::UnsupportedOperation
    );
    // Sectors of 4 KiB, 32 to a cluster.
    let e = kind(&|b| {
        b[11..13].copy_from_slice(&4096u16.to_le_bytes());
        b[13] = 32;
    });
    assert_eq!(e.kind, ErrorKind::UnsupportedOperation, "{e}");
    // Damage.
    for edit in [
        &(|b: &mut Vec<u8>| b[13] = 3) as &dyn Fn(&mut Vec<u8>),
        &|b| b[0x40] = 0,
        &|b| b[0x30..0x38].copy_from_slice(&u64::MAX.to_le_bytes()),
        &|b| b.truncate(300),
        &|b| b[3] = b'X',
    ] {
        assert_eq!(kind(edit).kind, ErrorKind::Corrupt);
    }
}

/// A record that ends in a resident attribute of 16 bytes: fstool 0.5.2's `AttributeIter`
/// reads its value's offset past the record and panics (`attribute.rs:170`).
fn short_attribute_record() -> Vec<u8> {
    let mut r = vec![0u8; 1024];
    r[..4].copy_from_slice(b"FILE");
    r[0x14..0x16].copy_from_slice(&1008u16.to_le_bytes());
    r[1008..1012].copy_from_slice(&0x40u32.to_le_bytes());
    r[1012..1016].copy_from_slice(&16u32.to_le_bytes());
    r
}

#[test]
fn a_short_resident_attribute_is_refused() {
    assert!(check_attrs(&short_attribute_record()).is_err());
    // Long enough, it's fine; and so is a record that just ends.
    let mut r = short_attribute_record();
    r[0x14..0x16].copy_from_slice(&1000u16.to_le_bytes());
    r[1000..].fill(0);
    r[1000..1004].copy_from_slice(&0x40u32.to_le_bytes());
    r[1004..1008].copy_from_slice(&24u32.to_le_bytes());
    assert!(check_attrs(&r[..1024]).is_ok());
}

/// The fstool bug [`check_attrs`] guards against, still there: when this fails, fstool fixed
/// it (docs/UPSTREAM.md).
#[test]
#[should_panic(expected = "out of range")]
fn fstool_still_reads_past_a_short_attribute() {
    let r = short_attribute_record();
    let _ = AttributeIter::new(&r, 1008).next();
}

#[test]
fn reparse_points() {
    fn names(subst: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
        let s: Vec<u8> = subst.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let p: Vec<u8> = print.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut d = Vec::new();
        for n in [0, s.len(), s.len(), p.len()] {
            d.extend_from_slice(&(n as u16).to_le_bytes());
        }
        if let Some(f) = flags {
            d.extend_from_slice(&f.to_le_bytes());
        }
        d.extend_from_slice(&s);
        d.extend_from_slice(&p);
        d
    }
    fn value(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut v = tag.to_le_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(data);
        v
    }
    let link = |t: &str| Reparse::Link(t.into());
    let cases = [
        (
            value(TAG_SYMLINK, &names(r"a\b.txt", r"a\b.txt", Some(1))),
            link("a/b.txt"),
        ),
        (
            value(TAG_SYMLINK, &names(r"\??\C:\x", r"C:\x", Some(0))),
            link("/??/C:/x"),
        ),
        // No substitute name: the print name.
        (value(TAG_SYMLINK, &names("", "p", Some(1))), link("p")),
        (
            value(TAG_MOUNT_POINT, &names(r"\??\C:\Users", r"C:\Users", None)),
            link("/??/C:/Users"),
        ),
        (value(TAG_LX_SYMLINK, b"\x02\0\0\0../up"), link("../up")),
        (value(TAG_LX_SYMLINK, b"\x02\0\0\0a\0b"), Reparse::Bad),
        (value(TAG_SYMLINK, &names("", "", Some(0))), Reparse::Bad),
        (value(TAG_LX_FIFO, b""), Reparse::Special),
        (
            value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0]),
            Reparse::Wof("XPRESS16K", Some(Algorithm::Xpress16k)),
        ),
        (
            value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]),
            Reparse::Wof("LZX", Some(Algorithm::Lzx)),
        ),
        // Another provider version, or an algorithm BeeZip doesn't know: named, not decoded.
        (
            value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]),
            Reparse::Wof("LZX", None),
        ),
        (
            value(TAG_WOF, &[1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0]),
            Reparse::Wof("WOF", None),
        ),
        (
            value(TAG_WOF, &[1, 0, 0, 0, 1, 0, 0, 0]),
            Reparse::Wof("WIM", None),
        ),
        (value(TAG_DEDUP, b""), Reparse::Dedup),
        (value(0x9000_001A, b"cloud"), Reparse::Other),
    ];
    for (v, want) in &cases {
        assert_eq!(decode_reparse(v), *want);
        // Cut anywhere, or with lengths past the value: no panic.
        for n in 0..v.len() {
            let _ = decode_reparse(&v[..n]);
            let mut w = v[..n].to_vec();
            w.extend_from_slice(&[0xFF; 16]);
            let _ = decode_reparse(&w);
        }
    }
    // An offset past the buffer.
    let mut v = value(TAG_SYMLINK, &names("abc", "abc", Some(0)));
    v[8..10].copy_from_slice(&0xFFF0u16.to_le_bytes());
    assert_eq!(decode_reparse(&v), link("abc"));
    v[12..14].copy_from_slice(&0xFFF0u16.to_le_bytes());
    assert_eq!(decode_reparse(&v), Reparse::Bad);
}

#[test]
fn interix_files() {
    let mut link = b"IntxLNK\x01".to_vec();
    link.extend("dir/x".encode_utf16().flat_map(u16::to_le_bytes));
    assert_eq!(interix(&link), Some(Reparse::Link("dir/x".into())));
    assert_eq!(interix(b"IntxCHR\0\x01\0\0\0"), Some(Reparse::Special));
    assert_eq!(interix(b"IntxBLK\0"), Some(Reparse::Special));
    assert_eq!(interix(b"IntxLNK\x01"), Some(Reparse::Bad));
    assert_eq!(interix(b"plain text"), None);
}
