//! Unit tests of the format's parts together: files built by hand (`build.rs`) and read back,
//! and the index parser against every rule of docs/bhive.md §9.

use std::io::Read;

use super::{
    BhiveReader, Level,
    build::{Build, extent},
    layout::{
        self, Bytes, Cell, Coder, INDEX_HEAD_LEN, IndexHead, ItemRef, Items, Kind, MAX_CELL,
        ROW_LEN, Record, checksum, lzma2_dict, lzma2_param, parse_index, parse_journal, put_item,
        put_svarint, put_uvarint, stamp,
    },
};
use crate::{
    ArchiveReader, EntryKind, ErrorKind, OpenOptions, Selection, SimpleCtx, TestSink,
    source::Source, time::from_unix,
};

/// A reader and the folder its file is in, which goes when the reader does.
struct Opened {
    r: BhiveReader,
    _dir: tempfile::TempDir,
}

impl std::ops::Deref for Opened {
    type Target = BhiveReader;

    fn deref(&self) -> &BhiveReader {
        &self.r
    }
}

impl std::ops::DerefMut for Opened {
    fn deref_mut(&mut self) -> &mut BhiveReader {
        &mut self.r
    }
}

/// Opens `bytes` as a `.bhive`, from a file of its own.
fn open_with(bytes: &[u8], opts: &OpenOptions) -> crate::Result<(Opened, SimpleCtx)> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.bhive");
    std::fs::write(&path, bytes).unwrap();
    let mut cx = SimpleCtx::new();
    let r = BhiveReader::open(Source::new(&path, Vec::new(), opts)?, &mut cx)?;
    Ok((Opened { r, _dir: dir }, cx))
}

fn open(bytes: &[u8]) -> crate::Result<Opened> {
    open_with(bytes, &OpenOptions::default()).map(|(r, _)| r)
}

fn recovering() -> OpenOptions {
    OpenOptions {
        recover: true,
        ..OpenOptions::default()
    }
}

fn read(r: &mut BhiveReader, id: usize) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.open_entry(id, &mut SimpleCtx::new())?
        .read_to_end(&mut out)
        .map_err(|e| crate::io::read_error(&e))?;
    Ok(out)
}

fn paths(r: &BhiveReader) -> Vec<&str> {
    r.entries.iter().map(|e| e.path.as_str()).collect()
}

/// Two stored cells; files that share bytes, one across both cells, an empty one, a folder and
/// a link.
fn small() -> Build {
    let mut b = Build::new();
    b.file("a.txt", &[extent(0, 0, 5)])
        .file("b.txt", &[extent(0, 5, 6)])
        .file("empty", &[]);
    b.stored(b"hello world");
    b.file(
        "both.txt",
        &[extent(0, 0, 5), extent(1, 0, 4), extent(0, 5, 6)],
    )
    .item(&ItemRef {
        kind: Kind::Folder,
        path: b"dir",
        modified: Some((1_700_000_000, 5)),
        created: Some((-1, 999_999_999)),
        mode: Some(0o40755),
        attrs: Some(0x10),
        extents: &[],
        target: b"",
    })
    .item(&ItemRef {
        kind: Kind::Link,
        path: b"dir/link",
        modified: None,
        created: None,
        mode: None,
        attrs: None,
        extents: &[],
        target: b"../a.txt",
    });
    b.stored(b" bee");
    b
}

#[test]
fn a_file_built_by_hand_reads() {
    let mut r = open(&small().finish()).unwrap();
    assert_eq!(
        paths(&r),
        ["a.txt", "b.txt", "empty", "both.txt", "dir", "dir/link"]
    );
    assert_eq!(read(&mut r, 0).unwrap(), b"hello");
    assert_eq!(read(&mut r, 1).unwrap(), b" world");
    assert_eq!(read(&mut r, 2).unwrap(), b"");
    assert_eq!(read(&mut r, 3).unwrap(), b"hello bee world");
    assert_eq!(r.entries[3].size, Some(15));
    let dir = &r.entries[4];
    assert_eq!(dir.kind, EntryKind::Dir);
    assert_eq!(dir.modified, from_unix(1_700_000_000, 5));
    assert_eq!(dir.created, from_unix(-1, 999_999_999));
    assert_eq!((dir.unix_mode, dir.dos_attrs), (Some(0o40755), Some(0x10)));
    assert_eq!(
        r.entries[5].kind,
        EntryKind::Symlink {
            target: "../a.txt".into()
        }
    );
    assert!(r.recovered().is_none());
    assert_eq!(r.level(), None);
    let mut cx = SimpleCtx::new();
    let report = r.test(&mut cx).unwrap().unwrap();
    assert!(report.ok());
    assert_eq!((report.entries, report.bytes), (6, 26));
}

/// More cells after the footer, then a new index and footer: only the last index counts, and
/// its table names the cells on both sides of the old one (docs/bhive.md §3).
#[test]
fn a_file_added_to_in_place_reads() {
    let mut b = small();
    b.close();
    let first = b.bytes.clone();
    b.file("later.txt", &[extent(2, 0, 3), extent(0, 0, 5)]);
    b.stored(b"new");
    let bytes = b.finish();
    assert!(bytes.starts_with(&first));

    let mut r = open(&bytes).unwrap();
    assert_eq!(r.entries.len(), 7);
    assert_eq!(read(&mut r, 6).unwrap(), b"newhello");
    assert_eq!(read(&mut r, 3).unwrap(), b"hello bee world");
    assert!(r.cells[2].offset > first.len() as u64);

    // Without its last footer the records still list everything, the old index stepped over.
    let cut = &bytes[..bytes.len() - 1];
    assert_eq!(open(cut).err().map(|e| e.kind), Some(ErrorKind::Corrupt));
    let (mut r, cx) = open_with(cut, &recovering()).unwrap();
    assert!(r.recovered().is_some());
    assert_eq!(cx.warnings.len(), 1, "{:?}", cx.warnings);
    assert_eq!(r.entries.len(), 7);
    assert_eq!(read(&mut r, 6).unwrap(), b"newhello");
}

/// Cut anywhere, a file opens to recover exactly the entries of the cells that are whole, and
/// every one of them reads; without `recover` it is `Corrupt`.
#[test]
fn a_cut_file_lists_the_cells_before_the_cut() {
    let b = small();
    let ends: Vec<u64> = b.cells.iter().map(Cell::end).collect();
    let bytes = b.finish();
    for len in 0..bytes.len() {
        let cut = &bytes[..len];
        let strict = open(cut).err().map(|e| e.kind);
        if len < 16 {
            // Not even a header: nothing to recover.
            assert!(open_with(cut, &recovering()).is_err(), "{len}");
            continue;
        }
        assert_eq!(strict, Some(ErrorKind::Corrupt), "{len}");
        let (mut r, _) = open_with(cut, &recovering()).unwrap();
        let whole = ends.iter().filter(|&&e| e <= len as u64).count();
        let want: &[&str] = match whole {
            0 => &[],
            1 => &["a.txt", "b.txt", "empty"],
            _ => &["a.txt", "b.txt", "empty", "both.txt", "dir", "dir/link"],
        };
        assert_eq!(paths(&r), want, "cut at {len}");
        for id in 0..r.entries.len() {
            read(&mut r, id).unwrap();
        }
        // It tests as damaged: its index is gone.
        let report = r.test(&mut SimpleCtx::new()).unwrap().unwrap();
        assert!(!report.ok(), "cut at {len}");
    }
}

/// A damaged record ends the recovery there; what came before stands.
#[test]
fn recovery_stops_at_a_record_that_fails_its_checks() {
    let b = small();
    // The second record starts where the first cell ends.
    let second = b.cells[0].end() as usize;
    let journal_of_second = b.cells[1].offset as usize - second - 48;
    let bytes = b.finish();
    let cut_footer = bytes.len() - 1;
    // In turn: the tag, the number, a length, the journal, the record checksum.
    for at in [second, second + 4, second + 9, second + 50, second + 41] {
        assert!(journal_of_second > 2);
        let mut bad = bytes[..cut_footer].to_vec();
        bad[at] ^= 0x01;
        let (r, _) = open_with(&bad, &recovering()).unwrap();
        assert_eq!(paths(&r), ["a.txt", "b.txt", "empty"], "byte {at}");
    }
}

/// A cell that fails its checksum fails the files with bytes in it, and only those.
#[test]
fn a_damaged_cell_fails_only_its_files() {
    let b = small();
    let at = b.cells[1].offset as usize;
    let mut bytes = b.finish();
    bytes[at] ^= 0x20;
    let mut r = open(&bytes).unwrap();
    assert_eq!(read(&mut r, 0).unwrap(), b"hello");
    let e = read(&mut r, 3).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Corrupt);
    assert!(e.message.contains("cell 1 fails its checksum"), "{e}");
    // Again, from the cache's memory of it.
    assert_eq!(read(&mut r, 3).unwrap_err().kind, ErrorKind::Corrupt);

    let mut cx = SimpleCtx::new();
    let report = r.test(&mut cx).unwrap().unwrap();
    let failed: Vec<&str> = report.errors.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(failed, ["both.txt"]);

    // Through a sink: the one entry is recorded, the rest are read.
    let mut sink = TestSink::default();
    r.extract(&Selection::all(), &mut sink, &mut cx).unwrap();
    assert_eq!(sink.report.errors_total, 1);
    assert_eq!(sink.report.entries, 6);
}

fn index_of(b: &Build) -> (Vec<u8>, u64) {
    (b.index(Some(2)), b.bytes.len() as u64)
}

#[test]
fn the_index_parser_reads_what_the_writer_writes() {
    let b = small();
    let (raw, at) = index_of(&b);
    let ix = parse_index(&raw, at, None).unwrap();
    assert_eq!(ix.cells, b.cells);
    assert_eq!(ix.items.items.len(), 6);
    assert_eq!(ix.level, Some(2));
    assert_eq!(ix.items.items[3].size, 15);
    assert_eq!(
        ix.items.extents_of(&ix.items.items[3]),
        [extent(0, 0, 5), extent(1, 0, 4), extent(0, 5, 6)]
    );

    // Sections a reader doesn't know are stepped over; half a section isn't.
    let mut more = raw.clone();
    put_uvarint(&mut more, 77);
    put_uvarint(&mut more, 3);
    more.extend_from_slice(b"abc");
    assert_eq!(parse_index(&more, at, None).unwrap().level, Some(2));
    more.extend_from_slice(&[78, 9, 1]);
    assert_eq!(
        parse_index(&more, at, None).unwrap_err().kind,
        ErrorKind::Corrupt
    );

    // `max_entries` is a limit, not damage.
    let e = parse_index(&raw, at, Some(5)).unwrap_err();
    assert_eq!(e.kind, ErrorKind::LimitExceeded);
}

/// An index with one cell of `cell` and nothing else.
fn index_with(cells: &[Cell]) -> Vec<u8> {
    layout::encode_index(cells, 0, &[], None)
}

fn stored_cell(offset: u64, len: u32) -> Cell {
    Cell {
        offset,
        stored: len,
        raw: len,
        coder: Coder::Stored,
        param: 0,
        checksum: 0,
    }
}

#[test]
fn the_cell_table_is_checked() {
    let ok = stored_cell(64, 100);
    let at = 1000;
    assert!(parse_index(&index_with(&[ok]), at, None).is_ok());
    assert!(parse_index(&index_with(&[ok, stored_cell(212, 100)]), at, None).is_ok());
    let zstd = Cell {
        coder: Coder::Zstd,
        stored: 50,
        ..ok
    };
    let lzma = Cell {
        coder: Coder::Lzma2,
        stored: 50,
        param: 32,
        ..ok
    };
    assert!(parse_index(&index_with(&[zstd, lzma_at(lzma, 162)]), at, None).is_ok());
    let cases: Vec<(&str, Vec<Cell>)> = vec![
        ("before the first record", vec![stored_cell(63, 100)]),
        ("past the index", vec![stored_cell(950, 100)]),
        (
            "no room for a record between",
            vec![ok, stored_cell(211, 100)],
        ),
        ("overlapping", vec![ok, stored_cell(100, 100)]),
        ("out of order", vec![stored_cell(400, 100), ok]),
        ("offset overflow", vec![stored_cell(u64::MAX - 10, 100)]),
        (
            "over 256 MiB",
            vec![Cell {
                raw: MAX_CELL + 1,
                stored: 10,
                coder: Coder::Zstd,
                ..ok
            }],
        ),
        ("stored with two lengths", vec![Cell { raw: 101, ..ok }]),
        ("stored with a parameter", vec![Cell { param: 1, ..ok }]),
        (
            "zstd that didn't shrink",
            vec![Cell {
                stored: 100,
                ..zstd
            }],
        ),
        ("zstd with a parameter", vec![Cell { param: 1, ..zstd }]),
        (
            "a dictionary over 256 MiB",
            vec![Cell { param: 33, ..lzma }],
        ),
        (
            "LZMA2 that grew",
            vec![Cell {
                stored: 101,
                ..lzma
            }],
        ),
    ];
    for (what, cells) in cases {
        let e = parse_index(&index_with(&cells), at, None).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{what}");
    }
    // A coder version 1 doesn't have.
    let mut raw = index_with(&[ok]);
    raw[1 + 16] = 3;
    assert!(parse_index(&raw, at, None).is_err());
    // A table, or a list of entries, that the index has no bytes for.
    let mut huge = Vec::new();
    put_uvarint(&mut huge, 1 << 60);
    assert!(parse_index(&huge, at, None).is_err());
    let mut huge = index_with(&[]);
    huge.pop();
    put_uvarint(&mut huge, 1 << 60);
    assert_eq!(
        parse_index(&huge, at, None).unwrap_err().kind,
        ErrorKind::Corrupt
    );
    assert_eq!(ROW_LEN, 26);
}

fn lzma_at(cell: Cell, offset: u64) -> Cell {
    Cell { offset, ..cell }
}

/// One item's bytes, parsed against two cells of 100 and 50 bytes.
fn parse_item(bytes: &[u8]) -> crate::Result<Items> {
    let cells = [stored_cell(64, 100), stored_cell(212, 50)];
    let mut out = Items::default();
    let mut b = Bytes::new(bytes);
    layout::item(&mut b, &cells, &mut out)?;
    assert_eq!(b.left(), 0, "bytes left over");
    Ok(out)
}

fn item_bytes(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut v = Vec::new();
    f(&mut v);
    v
}

#[test]
fn items_are_checked() {
    let file = |extents: &[(u64, u64, u64)]| {
        item_bytes(|v| {
            v.push(0);
            put_uvarint(v, 1);
            v.push(b'f');
            put_uvarint(v, extents.len() as u64);
            for &(c, o, l) in extents {
                put_uvarint(v, c);
                put_uvarint(v, o);
                put_uvarint(v, l);
            }
        })
    };
    let ok = parse_item(&file(&[(0, 0, 100), (1, 49, 1), (0, 0, 100)])).unwrap();
    assert_eq!(ok.items[0].size, 201);
    assert_eq!(parse_item(&file(&[])).unwrap().items[0].size, 0);
    for (what, extents) in [
        ("no bytes", vec![(0, 0, 0)]),
        ("past its cell", vec![(0, 1, 100)]),
        ("past its cell", vec![(1, 50, 1)]),
        ("a cell that isn't there", vec![(2, 0, 1)]),
        ("a cell number of 2^40", vec![(1 << 40, 0, 1)]),
        ("an offset that overflows", vec![(0, u64::MAX, 2)]),
    ] {
        let e = parse_item(&file(&extents)).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Corrupt, "{what}");
    }
    // More extents than bytes.
    let lying = item_bytes(|v| {
        v.extend_from_slice(&[0, 1, b'f']);
        put_uvarint(v, 1 << 50);
    });
    assert!(parse_item(&lying).is_err());

    // Flags: a reserved bit, the unused kind.
    for flags in [0x40, 0x80, 0x03] {
        assert!(parse_item(&[flags, 1, b'x']).is_err(), "{flags:#x}");
    }
    // A time with a whole second of nanoseconds; a mode and attributes of more than 32 bits.
    let with = |flags: u8, f: &dyn Fn(&mut Vec<u8>)| {
        item_bytes(|v| {
            v.extend_from_slice(&[flags | 1, 1, b'd']);
            f(v);
        })
    };
    let time = |nanos: u64| {
        move |v: &mut Vec<u8>| {
            put_svarint(v, -5);
            put_uvarint(v, nanos);
        }
    };
    assert_eq!(
        parse_item(&with(0x04, &time(999_999_999))).unwrap().items[0].modified,
        Some((-5, 999_999_999))
    );
    assert!(parse_item(&with(0x04, &time(1_000_000_000))).is_err());
    assert!(parse_item(&with(0x08, &time(1 << 40))).is_err());
    let number = |n: u64| move |v: &mut Vec<u8>| put_uvarint(v, n);
    assert_eq!(
        parse_item(&with(0x10, &number(u64::from(u32::MAX))))
            .unwrap()
            .items[0]
            .mode,
        Some(u32::MAX)
    );
    assert!(parse_item(&with(0x10, &number(1 << 32))).is_err());
    assert!(parse_item(&with(0x20, &number(1 << 32))).is_err());
    // A path, or a link's target, longer than the bytes left.
    assert!(parse_item(&[1, 9, b'x']).is_err());
    assert!(parse_item(&[2, 1, b'l', 5, b't']).is_err());
    // A path that isn't UTF-8 is kept as it is, for the reader to show somehow.
    assert_eq!(
        parse_item(&[1, 2, 0xFF, 0xFE]).unwrap().items[0].path,
        [0xFF, 0xFE]
    );
}

/// A journal names only its own cell and the ones before, and holds its items exactly.
#[test]
fn a_journal_names_no_later_cell() {
    let cells = [stored_cell(64, 100), stored_cell(212, 50)];
    let mut journal = Vec::new();
    for e in [extent(0, 0, 1), extent(1, 0, 1)] {
        put_item(
            &mut journal,
            &ItemRef {
                kind: Kind::File,
                path: b"f",
                modified: None,
                created: None,
                mode: None,
                attrs: None,
                extents: &[e],
                target: b"",
            },
        );
    }
    let mut out = Items::default();
    parse_journal(&journal, 2, &cells, &mut out).unwrap();
    assert_eq!(out.items.len(), 2);
    // The record of cell 0 can't name cell 1.
    assert!(parse_journal(&journal, 2, &cells[..1], &mut Items::default()).is_err());
    // Fewer items than it holds, or more.
    assert!(parse_journal(&journal, 1, &cells, &mut Items::default()).is_err());
    assert!(parse_journal(&journal, 3, &cells, &mut Items::default()).is_err());
}

#[test]
fn numbers_round_trip() {
    for v in [
        0,
        1,
        127,
        128,
        16_383,
        16_384,
        u64::from(u32::MAX),
        u64::MAX - 1,
        u64::MAX,
    ] {
        let mut b = Vec::new();
        put_uvarint(&mut b, v);
        assert_eq!(
            b.len(),
            (64 - v.leading_zeros()).max(1).div_ceil(7) as usize
        );
        assert_eq!(Bytes::new(&b).uvarint().unwrap(), v);
    }
    for v in [0, -1, 1, -64, 64, i64::MIN, i64::MAX, -11_644_473_600] {
        let mut b = Vec::new();
        put_svarint(&mut b, v);
        assert_eq!(Bytes::new(&b).svarint().unwrap(), v);
    }
    // Eleven bytes, and ten that hold a 65th bit.
    assert!(Bytes::new(&[0x80; 11]).uvarint().is_err());
    assert!(
        Bytes::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02])
            .uvarint()
            .is_err()
    );
    assert!(Bytes::new(&[0x80]).uvarint().is_err());
}

#[test]
fn times_before_1970_count_forward_from_a_negative_second() {
    for (secs, nanos) in [
        (0, 0),
        (1_700_000_000, 123_456_700),
        // In steps of 100 ns: what Windows keeps.
        (-1, 999_999_900),
        (-1, 0),
        // Windows' zero: 1601-01-01.
        (-11_644_473_600, 0),
        (-11_644_473_600, 100),
    ] {
        let t = from_unix(secs, nanos).unwrap();
        assert_eq!(stamp(t), (secs, nanos));
    }
}

#[test]
fn headers_and_heads_round_trip() {
    let h = layout::header();
    assert_eq!(&h[..8], b"\x89BHIVE\r\n");
    layout::check_header(&h).unwrap();
    let mut newer = h;
    newer[8] = 2;
    let e = layout::check_header(&newer).unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnsupportedFormat);
    let mut feature = h;
    feature[12] = 1;
    assert_eq!(
        layout::check_header(&feature).unwrap_err().kind,
        ErrorKind::UnsupportedFormat
    );
    // The reserved field is ignored.
    let mut reserved = h;
    reserved[10] = 0xFF;
    layout::check_header(&reserved).unwrap();
    assert!(layout::check_header(&h[..15]).is_err());

    assert_eq!(layout::parse_footer(&layout::footer(12_345)), Some(12_345));
    assert_eq!(layout::parse_footer(&[0; 16]), None);

    let record = Record {
        number: 7,
        raw: 1000,
        stored: 400,
        coder: Coder::Lzma2,
        param: 12,
        journal_zstd: true,
        journal_items: 3,
        journal_raw: 90,
        journal_stored: 60,
        checksum: 0x0123_4567_89AB_CDEF,
    };
    let journal = [9u8; 60];
    let head = record.encode(&journal);
    let (back, sum) = Record::parse(&head).unwrap();
    assert_eq!(back, record);
    assert_eq!(sum, layout::record_checksum(&head, &journal));
    assert_ne!(sum, layout::record_checksum(&head, &journal[..59]));

    let head = IndexHead {
        zstd: true,
        stored: 5,
        raw: 9,
        checksum: 1,
    };
    assert_eq!(IndexHead::parse(&head.encode()).unwrap(), head);
    assert_eq!(head.encode().len(), INDEX_HEAD_LEN);
    assert_eq!(checksum(b""), 0x2D06_8005_38D3_94C2);
}

#[test]
fn dictionary_sizes_are_xzs() {
    assert_eq!(lzma2_dict(0), 4 << 10);
    assert_eq!(lzma2_dict(1), 6 << 10);
    assert_eq!(lzma2_dict(24), 16 << 20);
    assert_eq!(lzma2_dict(32), 256 << 20);
    for p in 0..=32 {
        assert_eq!(lzma2_param(lzma2_dict(p)), p);
    }
    assert_eq!(lzma2_param(5000), 1);
    assert_eq!(lzma2_param(u32::MAX), 32);
}

/// The builder's coded cells read too: every level's coder, by hand.
#[test]
fn hand_built_cells_of_every_coder_read() {
    let text: Vec<u8> = b"bees make honey; "
        .iter()
        .copied()
        .cycle()
        .take(5000)
        .collect();
    for level in Level::ALL {
        let mut b = Build::new();
        b.file("t", &[extent(0, 10, 4000)]);
        b.cell(&text, level);
        assert_eq!(b.cells[0].coder, super::build::coder_of(level));
        let mut r = open(&b.finish()).unwrap();
        assert_eq!(read(&mut r, 0).unwrap(), text[10..4010]);
    }
}
