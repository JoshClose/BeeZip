//! The `.bhive` fixtures (docs/M13.md §8).
//!
//! - **`tests/fixtures/bhive/`:** one archive for each level and each feature of the format,
//!   written by BeeZip's writer or built by hand (`beezip_core::format::bhive::build`), with a
//!   `manifest.json` that says what each must list and hold. A later BeeZip is checked against
//!   these files, and so is the Python reader (`docs/bhive_reader.py`).
//! - **`tests/fixtures/malicious/`:** archives that break a rule of docs/bhive.md §9, or that
//!   keep every rule and still mean harm.

use std::{
    io::{self, Cursor, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};

use anyhow::Context;
use beezip_core::{
    ArchiveWriter, NewEntry, NewKind, SimpleCtx,
    format::bhive::{
        BhiveWriteOptions, BhiveWriter, Level,
        build::{Build, extent},
        crypt::{Labelled, Protection, Recipient, Strength, prim, recovery},
        layout::{self, Cell, Coder, Extent, ItemRef, Kind, Record, checksum},
    },
    time::from_unix,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Relative to the workspace root.
pub const DIR: &str = "tests/fixtures/bhive";

/// Seconds and nanoseconds since 1970.
type Stamp = (i64, u32);

/// An entry to put in a fixture, and to expect back from it.
#[derive(Clone)]
struct Planted {
    path: &'static str,
    kind: Kind,
    data: Vec<u8>,
    target: &'static str,
    modified: Option<Stamp>,
    created: Option<Stamp>,
    mode: Option<u32>,
    attrs: Option<u32>,
}

/// 2026-01-01T00:00:00Z, and a little later for each entry.
const BASE: i64 = 1_767_225_600;

fn file(path: &'static str, data: Vec<u8>) -> Planted {
    Planted {
        path,
        kind: Kind::File,
        data,
        target: "",
        modified: Some((BASE, 0)),
        created: None,
        mode: None,
        attrs: None,
    }
}

fn folder(path: &'static str) -> Planted {
    Planted {
        kind: Kind::Folder,
        ..file(path, Vec::new())
    }
}

fn link(path: &'static str, target: &'static str) -> Planted {
    Planted {
        kind: Kind::Link,
        target,
        ..file(path, Vec::new())
    }
}

/// Bytes with no pattern.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.extend_from_slice(&s.to_le_bytes());
    }
    v.truncate(len);
    v
}

/// Bytes that compress: words.
fn words(len: usize, seed: u64) -> Vec<u8> {
    let list = [
        "bee", "zip", "hive", "honey", "comb", "wax", "pollen", "queen", "drone", "nectar",
    ];
    let mut out = Vec::with_capacity(len + 8);
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(list[(x % 10) as usize].as_bytes());
        out.push(if x.is_multiple_of(7) { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

/// The tree every level's fixture holds: empty and tiny files, text and noise, names beyond
/// ASCII, a long path, a copy and a shifted copy, folders (one empty), a link, and every kind
/// of metadata. Times are in steps of 100 ns, which every system keeps.
fn tree() -> Vec<Planted> {
    let text = words(60_000, 1);
    let mut shifted = text[..20_000].to_vec();
    shifted.extend_from_slice(b"an insertion that moves every byte after it\n");
    shifted.extend_from_slice(&text[20_000..]);
    let mut entries = vec![
        folder("tree"),
        file("tree/hello.txt", b"Hello, BeeZip!\n".to_vec()),
        file("tree/empty.txt", Vec::new()),
        folder("tree/docs"),
        file("tree/docs/readme.md", words(1361, 2)),
        folder("tree/data"),
        file("tree/data/random.bin", noise(4096, 3)),
        file("tree/data/words.txt", text.clone()),
        file("tree/data/zeros.bin", vec![0; 100_000]),
        folder("tree/ünïcödé"),
        file(
            "tree/ünïcödé/名前.txt",
            "日本語のテキスト\n".as_bytes().to_vec(),
        ),
        file(
            "tree/deep/directory-with-a-long-name-0123456789/another-long-directory-name-abcdefghij/file-with-a-long-name-past-100-characters.txt",
            b"deep inside\n".to_vec(),
        ),
        folder("tree/copies"),
        file("tree/copies/words again.txt", text),
        file("tree/copies/words shifted.txt", shifted),
        file("tree/copies/hello again.txt", b"Hello, BeeZip!\n".to_vec()),
        folder("tree/empty folder"),
        link("tree/link to hello", "hello.txt"),
        file("tree/script.sh", b"#!/bin/sh\necho bee\n".to_vec()),
        file("tree/read only.txt", b"look, don't touch\n".to_vec()),
    ];
    for (i, e) in entries.iter_mut().enumerate() {
        let i = i as i64;
        e.modified = Some((BASE + i * 61, (i as u32 * 123_456_700) % 1_000_000_000));
        e.created = Some((BASE - 86_400 + i, 500));
        e.mode = Some(match e.kind {
            Kind::Folder => 0o40755,
            Kind::Link => 0o120777,
            Kind::File if e.path.ends_with(".sh") => 0o100755,
            Kind::File => 0o100644,
        });
        e.attrs = Some(match e.kind {
            Kind::Folder => 0x10,
            _ if e.path.ends_with("read only.txt") => 0x21,
            _ => 0x20,
        });
    }
    entries
}

/// A tree with files several cells long, for small cells.
fn long_tree() -> Vec<Planted> {
    let big = words(70_000, 11);
    let mut entries = tree();
    entries.extend([
        file("tree/big/words.txt", big.clone()),
        file("tree/big/noise.bin", noise(50_000, 12)),
        file("tree/big/words again.txt", big),
        file("tree/big/noise again.bin", noise(50_000, 12)),
        file("tree/big/last.txt", b"the last file\n".to_vec()),
    ]);
    entries
}

/// A buffer the writer writes to and the fixture is taken from.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Cursor<Vec<u8>>>>);

impl Shared {
    fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .map(|c| c.get_ref().clone())
            .unwrap_or_default()
    }
}

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for Shared {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?
            .seek(pos)
    }
}

/// `entries` through BeeZip's writer.
fn written(entries: &[Planted], level: Level, cell_size: Option<u32>) -> anyhow::Result<Vec<u8>> {
    written_with(entries, level, cell_size, None)
}

/// [`written`], encrypted for `protection` when there is one.
fn written_with(
    entries: &[Planted],
    level: Level,
    cell_size: Option<u32>,
    protection: Option<Protection>,
) -> anyhow::Result<Vec<u8>> {
    let out = Shared::default();
    let opts = BhiveWriteOptions {
        level,
        // One thread and several write the same bytes; one keeps the generator simple, and
        // keeps an encrypted fixture's random bytes on the thread that seeds them.
        threads: 1,
        memory: None,
        cell_size,
        inherit: false,
        protection,
        ..BhiveWriteOptions::default()
    };
    let mut cx = SimpleCtx::new();
    let mut w: Box<dyn ArchiveWriter> = Box::new(BhiveWriter::new(Box::new(out.clone()), &opts)?);
    let time = |t: Option<Stamp>| t.and_then(|(s, n)| from_unix(s, n));
    for e in entries {
        let entry = NewEntry {
            path: e.path.to_owned(),
            kind: match e.kind {
                Kind::File => NewKind::File,
                Kind::Folder => NewKind::Dir,
                Kind::Link => NewKind::Symlink {
                    target: e.target.to_owned(),
                },
            },
            size: e.data.len() as u64,
            modified: time(e.modified),
            created: time(e.created),
            unix_mode: e.mode,
            dos_attrs: e.attrs,
            source: None,
        };
        w.add(&entry, &mut &e.data[..], &mut cx)
            .with_context(|| format!("adding {}", e.path))?;
    }
    w.finish(&mut cx)?;
    Ok(out.bytes())
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What a fixture's entries must read back as.
fn expected(entries: &[Planted]) -> Value {
    let stamp = |t: Option<Stamp>| t.map_or(Value::Null, |(s, n)| json!([s, n]));
    entries
        .iter()
        .map(|e| {
            let mut v = json!({
                "path": e.path,
                "kind": match e.kind {
                    Kind::File => "file",
                    Kind::Folder => "folder",
                    Kind::Link => "link",
                },
                "modified": stamp(e.modified),
                "created": stamp(e.created),
                "mode": e.mode,
                "attributes": e.attrs,
            });
            match e.kind {
                Kind::File => {
                    v["size"] = json!(e.data.len());
                    v["sha256"] = json!(sha256(&e.data));
                }
                Kind::Folder => {}
                Kind::Link => v["target"] = json!(e.target),
            }
            v
        })
        .collect()
}

/// A fixture and its record in the manifest.
struct Fixture {
    file: &'static str,
    bytes: Vec<u8>,
    record: Value,
}

fn fixture(file: &'static str, what: &str, bytes: Vec<u8>, entries: &[Planted]) -> Fixture {
    Fixture {
        file,
        record: json!({
            "file": file,
            "what": what,
            "entries": expected(entries),
        }),
        bytes,
    }
}

impl Fixture {
    fn with(mut self, key: &str, value: Value) -> Self {
        self.record[key] = value;
        self
    }
}

/// An item for the builder from a planted entry.
fn item<'a>(e: &'a Planted, extents: &'a [Extent]) -> ItemRef<'a> {
    ItemRef {
        kind: e.kind,
        path: e.path.as_bytes(),
        modified: e.modified,
        created: e.created,
        mode: e.mode,
        attrs: e.attrs,
        extents,
        target: e.target.as_bytes(),
    }
}

/// Entries whose times no writer on Windows could give: before 1601, far ahead, nanoseconds
/// finer than 100, and none at all. Built by hand, each file's bytes in one stored cell.
fn odd_times() -> (Vec<u8>, Vec<Planted>) {
    let mut entries = vec![
        file("before 1970.txt", b"1969\n".to_vec()),
        file("before 1601.txt", b"1066\n".to_vec()),
        file("year 9999.txt", b"9999\n".to_vec()),
        file("a nanosecond.txt", b"1 ns\n".to_vec()),
        file("no time.txt", b"never\n".to_vec()),
        folder("no time"),
    ];
    let stamps: [Option<Stamp>; 6] = [
        Some((-1, 999_999_900)),
        Some((-28_500_000_000, 0)),
        Some((253_402_300_799, 999_999_999)),
        Some((BASE, 1)),
        None,
        None,
    ];
    for (e, t) in entries.iter_mut().zip(stamps) {
        e.modified = t;
        e.created = t.map(|(s, n)| (s - 1, n));
    }
    let mut b = Build::new();
    let mut raw = Vec::new();
    for e in &entries {
        let at = raw.len() as u32;
        raw.extend_from_slice(&e.data);
        let extents = [extent(0, at, e.data.len() as u32)];
        b.item(&item(e, if e.kind == Kind::File { &extents } else { &[] }));
    }
    b.stored(&raw);
    (b.finish(), entries)
}

/// Three stored cells, built by hand so that what each record lists is known: two files in the
/// first, one across the first two, two in the third. Returns the builder before its index.
fn three_cells() -> (Build, Vec<Planted>) {
    let entries = vec![
        file("one.txt", b"the first cell\n".to_vec()),
        file("two.txt", b"still the first\n".to_vec()),
        file(
            "across.txt",
            b"still the first\nand the second cell\n".to_vec(),
        ),
        folder("folder"),
        file("three.txt", b"the third cell\n".to_vec()),
        file("one again.txt", b"the first cell\n".to_vec()),
    ];
    let mut b = Build::new();
    b.item(&item(&entries[0], &[extent(0, 0, 15)]));
    b.item(&item(&entries[1], &[extent(0, 15, 16)]));
    b.stored(b"the first cell\nstill the first\n");
    b.item(&item(&entries[2], &[extent(0, 15, 16), extent(1, 0, 20)]));
    b.item(&item(&entries[3], &[]));
    b.stored(b"and the second cell\n");
    b.item(&item(&entries[4], &[extent(2, 0, 15)]));
    b.item(&item(&entries[5], &[extent(0, 0, 15)]));
    b.stored(b"the third cell\n");
    (b, entries)
}

/// The specification's second example (docs/bhive.md §11): a folder, two files that share
/// bytes and a link, in one stored cell.
fn spec_small() -> (Vec<u8>, Vec<Planted>) {
    let mut entries = vec![
        folder("docs"),
        file("docs/a.txt", b"honey\n".to_vec()),
        file("docs/b.txt", b"honeycomb\n".to_vec()),
        link("latest", "docs/b.txt"),
    ];
    for e in &mut entries {
        e.modified = Some((BASE, 0));
    }
    entries[2].modified = Some((BASE + 1, 500_000_000));
    entries[2].mode = Some(0o100644);
    let mut b = Build::new();
    b.item(&item(&entries[0], &[]));
    b.item(&item(&entries[1], &[extent(0, 0, 5), extent(0, 9, 1)]));
    b.item(&item(&entries[2], &[extent(0, 0, 10)]));
    b.item(&item(&entries[3], &[]));
    b.stored(b"honeycomb\n");
    (b.finish(), entries)
}

/// The encrypted fixtures' test secrets: never a real archive's.
const SEALED_PASSWORD: &str = "honey";
const SEALED_RECOVERY_KEY: [u8; 16] = *b"BeeZip test key!";

/// An encrypted fixture: `entries` at `level` for these ways in, its random bytes made from
/// `name`, so that the generator writes the same file every time.
fn sealed(
    name: &str,
    entries: &[Planted],
    level: Level,
    passwords: &[&str],
    recovery: bool,
) -> anyhow::Result<Vec<u8>> {
    // Argon2 at a cost a test can afford; BeeZip writes 1 GiB or 2 GiB.
    let cost = Strength::Cost {
        memory_kib: 256,
        passes: 2,
        lanes: 4,
    };
    let mut ways: Vec<Labelled> = passwords
        .iter()
        .map(|p| Labelled {
            recipient: Recipient::password(p, cost),
            label: Some("Password".into()),
        })
        .collect();
    if recovery {
        ways.push(Labelled {
            recipient: Recipient::recovery_key(&SEALED_RECOVERY_KEY),
            label: Some("Recovery key".into()),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&Sha256::digest(format!("bhive fixture {name}")));
    prim::seeded(seed, || {
        written_with(entries, level, None, Some(Protection::New(ways)))
    })
}

/// The encrypted fixtures (docs/bhive.md §12), and `sealed.json`, which says what each holds
/// and what opens it: the tree at every level behind a password and a recovery key, the tree
/// behind two passwords, and behind a recovery key alone (cheap to open, for mutating).
fn sealed_fixtures() -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let tree = tree();
    let digits = recovery::format(&SEALED_RECOVERY_KEY).to_string();
    let mut all = Vec::new();
    for level in Level::ALL {
        let file: &'static str = match level {
            Level::None => "sealed-none.bhive",
            Level::Fast => "sealed-fast.bhive",
            Level::Balanced => "sealed-balanced.bhive",
            Level::High => "sealed-high.bhive",
            Level::Max => "sealed-max.bhive",
        };
        let bytes = sealed(file, &tree, level, &[SEALED_PASSWORD], true)?;
        let what = format!("the tree at level {}, encrypted", level.name());
        all.push(
            fixture(file, &what, bytes, &tree)
                .with("level", json!(level.name()))
                .with("passwords", json!([SEALED_PASSWORD]))
                .with("recovery_key", json!(digits)),
        );
    }
    let file = "sealed-two-passwords.bhive";
    let bytes = sealed(file, &tree, Level::Fast, &[SEALED_PASSWORD, "bees"], false)?;
    all.push(
        fixture(
            file,
            "the tree behind either of two passwords",
            bytes,
            &tree,
        )
        .with("level", json!("fast"))
        .with("passwords", json!([SEALED_PASSWORD, "bees"])),
    );
    let file = "sealed-recovery.bhive";
    let bytes = sealed(file, &tree, Level::Fast, &[], true)?;
    all.push(
        fixture(file, "the tree behind a recovery key alone", bytes, &tree)
            .with("level", json!("fast"))
            .with("passwords", json!([]))
            .with("recovery_key", json!(digits)),
    );
    let manifest = json!({
        "note": "Written by `cargo xtask gen-fixtures` (xtask/src/fixtures/bhive.rs). Encrypted                  archives (docs/bhive.md §12), each opened by the passwords and the recovery key                  its record lists. These are test secrets, never a real archive's.",
        "fixtures": all.iter().map(|f| f.record.clone()).collect::<Vec<_>>(),
    });
    let mut out: Vec<(String, Vec<u8>)> = all
        .into_iter()
        .map(|f| (f.file.to_owned(), f.bytes))
        .collect();
    let mut text = serde_json::to_string_pretty(&manifest)?;
    text.push('\n');
    out.push(("sealed.json".to_owned(), text.into_bytes()));
    Ok(out)
}

/// Every fixture of `tests/fixtures/bhive/`, and `manifest.json` last; the encrypted ones and
/// `sealed.json` before it.
pub fn fixtures() -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let sealed = sealed_fixtures()?;
    let tree = tree();
    let mut all = Vec::new();
    for level in Level::ALL {
        let file: &'static str = match level {
            Level::None => "none.bhive",
            Level::Fast => "fast.bhive",
            Level::Balanced => "balanced.bhive",
            Level::High => "high.bhive",
            Level::Max => "max.bhive",
        };
        let what = format!(
            "the tree at level {}, in the level's own cells",
            level.name()
        );
        all.push(
            fixture(file, &what, written(&tree, level, None)?, &tree)
                .with("level", json!(level.name())),
        );
    }
    let long = long_tree();
    all.push(
        fixture(
            "cells.bhive",
            "Balanced in cells of 8 KiB: files across cells, extents into earlier cells",
            written(&long, Level::Balanced, Some(8 << 10))?,
            &long,
        )
        .with("level", json!("balanced")),
    );
    all.push(
        fixture(
            "probe.bhive",
            "High in cells of 32 KiB: LZMA2 cells, and stored ones for what doesn't shrink",
            written(&long, Level::High, Some(32 << 10))?,
            &long,
        )
        .with("level", json!("high"))
        .with("coders", json!(["Store", "LZMA2"])),
    );
    all.push(
        fixture(
            "max-cells.bhive",
            "Max in cells of 16 KiB: LZMA2 with dictionaries no larger than the cells",
            written(&long, Level::Max, Some(16 << 10))?,
            &long,
        )
        .with("level", json!("max")),
    );
    all.push(
        fixture(
            "empty.bhive",
            "no entries: a header, an index block and a footer",
            written(&[], Level::Balanced, None)?,
            &[],
        )
        .with("level", json!("balanced")),
    );
    let folders = [folder("a"), folder("a/b"), link("a/link", "b"), folder("c")];
    all.push(
        fixture(
            "folders.bhive",
            "folders and a link, no bytes: one record with an empty cell",
            written(&folders, Level::Fast, None)?,
            &folders,
        )
        .with("level", json!("fast")),
    );
    let (bytes, entries) = odd_times();
    all.push(fixture(
        "times.bhive",
        "times before 1970 and before 1601, in the year 9999, to the nanosecond, and none (built by hand)",
        bytes,
        &entries,
    ));

    let (b, entries) = three_cells();
    let whole = b.clone().finish();
    all.push(fixture(
        "three-cells.bhive",
        "three stored cells built by hand, a file across two and one that repeats another",
        whole.clone(),
        &entries,
    ));
    // Cut in the third cell's data: the first two cells and what their records list are left.
    let cut = b.cells[2].offset as usize + 5;
    all.push(
        fixture(
            "cut.bhive",
            "three-cells.bhive cut short inside its third cell: read with recover, it lists the first two",
            whole[..cut].to_vec(),
            &entries[..4],
        )
        .with("recover", json!(true)),
    );
    // Added to in place: the old index block and footer stay where they were.
    let mut added = b.clone();
    added.close();
    let mut more = entries.clone();
    more.push(file("added.txt", b"added later\nthe third cell\n".to_vec()));
    added.item(&item(&more[6], &[extent(3, 0, 12), extent(2, 0, 15)]));
    added.stored(b"added later\n");
    all.push(fixture(
        "added.bhive",
        "three-cells.bhive added to in place: a fourth cell after the first footer, then a new index and footer",
        added.finish(),
        &more,
    ));

    all.push(fixture(
        "spec-empty.bhive",
        "docs/bhive.md's first example, byte for byte",
        Build::new().finish(),
        &[],
    ));
    let (bytes, entries) = spec_small();
    all.push(fixture(
        "spec-small.bhive",
        "docs/bhive.md's second example, byte for byte",
        bytes,
        &entries,
    ));

    let manifest = json!({
        "note": "Written by `cargo xtask gen-fixtures` (xtask/src/fixtures/bhive.rs). Each \
                 record says what its archive must list and hold; BeeZip's tests and \
                 docs/bhive_reader.py are both checked against it.",
        "fixtures": all.iter().map(|f| f.record.clone()).collect::<Vec<_>>(),
    });
    let mut out: Vec<(String, Vec<u8>)> = all
        .into_iter()
        .map(|f| (f.file.to_owned(), f.bytes))
        .collect();
    let mut text = serde_json::to_string_pretty(&manifest)?;
    text.push('\n');
    out.splice(0..0, sealed);
    out.push(("manifest.json".to_owned(), text.into_bytes()));
    Ok(out)
}

/// A file of `extents`, with nothing else said.
fn plain(b: &mut Build, path: &str, extents: &[Extent]) {
    b.file(path, extents);
}

/// The index block and footer for `raw`, with the head's lengths as given.
fn close_lying(b: &mut Build, raw: &[u8], stored: &[u8], zstd: bool, claims: u64) {
    let offset = b.bytes.len() as u64;
    let head = layout::IndexHead {
        zstd,
        stored: stored.len() as u64,
        raw: claims,
        checksum: checksum(raw),
    };
    b.bytes.extend_from_slice(&head.encode());
    b.bytes.extend_from_slice(stored);
    b.bytes.extend_from_slice(&layout::footer(offset));
}

/// One zstd frame of `raw`, by BeeZip's own coder: a cell built at level Fast.
fn zstd_cell(raw: &[u8]) -> (Cell, Vec<u8>) {
    let mut b = Build::new();
    b.cell(raw, Level::Fast);
    let cell = b.cells[0];
    let data = b.bytes[cell.offset as usize..cell.end() as usize].to_vec();
    (cell, data)
}

/// `(file name, bytes)` for each malicious case, in `tests/fixtures/malicious/`.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    let mut files: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // Names that leave the destination, and a link that points out of it.
    let mut b = Build::new();
    for (path, at) in [
        ("../evil.txt", 0),
        ("ok/../../evil2.txt", 0),
        ("/etc/beezip-abs.txt", 0),
        ("C:\\Windows\\beezip-drive.txt", 0),
        ("safe.txt", 7),
    ] {
        plain(&mut b, path, &[extent(0, at, if at == 0 { 7 } else { 4 })]);
    }
    b.item(&ItemRef {
        kind: Kind::Link,
        path: b"escape",
        modified: None,
        created: None,
        mode: None,
        attrs: None,
        extents: &[],
        target: b"../../outside",
    });
    b.stored(b"escapedsafe");
    files.push(("traversal.bhive", b.finish()));

    // A bomb that keeps every rule: one cell of 4 MiB of zeros, a few hundred bytes stored,
    // and three thousand files that are each all of it. 12 GiB from 40 KiB.
    let mut b = Build::new();
    let names: Vec<String> = (0..3000).map(|i| format!("zeros/{i:04}.bin")).collect();
    for name in &names {
        plain(&mut b, name, &[extent(0, 0, 4 << 20)]);
    }
    b.cell(&vec![0u8; 4 << 20], Level::Fast);
    files.push(("bhive-bomb.bhive", b.finish()));

    // One file of 2,000 extents, each all of the same 4 MiB of zeros: 8 GiB from a few hundred
    // stored bytes. The file's own ratio stops it.
    let mut b = Build::new();
    let many: Vec<Extent> = (0..2000).map(|_| extent(0, 0, 4 << 20)).collect();
    plain(&mut b, "one-file.bin", &many);
    b.cell(&vec![0u8; 4 << 20], Level::Fast);
    files.push(("bhive-bomb-one-file.bhive", b.finish()));

    // An extent past its cell's end, and one into a cell that isn't there.
    for (name, bad) in [
        ("bhive-extent-past-cell.bhive", extent(0, 6, 6)),
        ("bhive-extent-no-cell.bhive", extent(1, 0, 1)),
    ] {
        let mut b = Build::new();
        plain(&mut b, "ok.txt", &[extent(0, 0, 11)]);
        plain(&mut b, "bad.txt", &[bad]);
        b.stored(b"hello world");
        files.push((name, b.finish()));
    }

    // A cell table whose second cell lies inside the first.
    let mut b = Build::new();
    plain(&mut b, "a.txt", &[extent(0, 0, 11)]);
    b.stored(b"hello world");
    plain(&mut b, "b.txt", &[extent(1, 0, 4)]);
    b.stored(b" bee");
    b.cells[1].offset = b.cells[0].offset + 2;
    files.push(("bhive-cells-overlap.bhive", b.finish()));

    // An index that claims 2^60 entries, and one whose table claims 2^60 cells.
    let mut b = Build::new();
    plain(&mut b, "a.txt", &[extent(0, 0, 11)]);
    b.stored(b"hello world");
    let mut raw = layout::encode_index(&b.cells, 0, &[], None);
    raw.pop();
    layout::put_uvarint(&mut raw, 1 << 60);
    raw.extend_from_slice(&b.items);
    let mut entries = b.clone();
    entries.close_with(&raw);
    files.push(("bhive-entries-2-60.bhive", entries.bytes));
    let mut raw = Vec::new();
    layout::put_uvarint(&mut raw, 1 << 60);
    raw.extend_from_slice(&[0; 64]);
    b.close_with(&raw);
    files.push(("bhive-cells-2-60.bhive", b.bytes));

    // A zstd cell whose raw size lies, each way: the files in it fail, the other is read.
    let text = words(20_000, 5);
    let (cell, data) = zstd_cell(&text);
    for (name, claims) in [
        ("bhive-raw-more.bhive", cell.raw + 1000),
        ("bhive-raw-less.bhive", cell.raw - 1000),
    ] {
        let mut b = Build::new();
        plain(&mut b, "ok.txt", &[extent(0, 0, 11)]);
        b.stored(b"hello world");
        plain(&mut b, "lies.txt", &[extent(1, 0, 5000)]);
        let record = Record {
            number: 1,
            raw: claims,
            stored: data.len() as u32,
            coder: Coder::Zstd,
            param: 0,
            journal_zstd: false,
            journal_items: b.journal_items,
            journal_raw: b.journal.len() as u32,
            journal_stored: b.journal.len() as u32,
            checksum: cell.checksum,
        };
        let journal = std::mem::take(&mut b.journal);
        b.journal_items = 0;
        b.cell_as(&record, &journal, &data);
        files.push((name, b.finish()));
    }

    // A cell of 256 MiB of zeros in a few KiB, and an LZMA2 cell that asks for a 256 MiB
    // dictionary: both within the format's limits, and over a small `decoder_memory`.
    let (cell, data) = zstd_cell(&vec![0u8; 256 << 20]);
    let mut b = Build::new();
    plain(&mut b, "ok.txt", &[extent(0, 0, 11)]);
    b.stored(b"hello world");
    plain(&mut b, "huge.bin", &[extent(1, 0, 256 << 20)]);
    let record = Record {
        number: 1,
        raw: cell.raw,
        stored: cell.stored,
        coder: Coder::Zstd,
        param: 0,
        journal_zstd: false,
        journal_items: b.journal_items,
        journal_raw: b.journal.len() as u32,
        journal_stored: b.journal.len() as u32,
        checksum: cell.checksum,
    };
    let journal = std::mem::take(&mut b.journal);
    b.journal_items = 0;
    b.cell_as(&record, &journal, &data);
    files.push(("bhive-cell-256m.bhive", b.finish()));

    let mut b = Build::new();
    plain(&mut b, "small.txt", &[extent(0, 0, 100)]);
    b.cell(&words(5000, 6), Level::High);
    b.cells[0].param = 32;
    files.push(("bhive-dict-256m.bhive", b.finish()));

    // A cell over the format's 256 MiB, by its record and table alone.
    let mut b = Build::new();
    plain(&mut b, "a.txt", &[extent(0, 0, 11)]);
    b.stored(b"hello world");
    b.cells[0].raw = (256 << 20) + 1;
    b.cells[0].coder = Coder::Zstd;
    files.push(("bhive-cell-over-256m.bhive", b.finish()));

    // An index whose head claims 2^40 raw bytes, and one that decodes to more than it claims.
    let mut b = Build::new();
    plain(&mut b, "a.txt", &[extent(0, 0, 11)]);
    b.stored(b"hello world");
    let raw = b.index(None);
    let (_, frame) = zstd_cell(&[raw.clone(), vec![0; 4096]].concat());
    let mut claims = b.clone();
    close_lying(&mut claims, &raw, &frame, true, 1 << 40);
    files.push(("bhive-index-2-40.bhive", claims.bytes));
    let mut more = b.clone();
    close_lying(&mut more, &raw, &frame, true, raw.len() as u64);
    files.push(("bhive-index-more.bhive", more.bytes));

    // A footer that points past the file, and one that points into a cell.
    let whole = b.clone().finish();
    for (name, offset) in [
        ("bhive-footer-outside.bhive", whole.len() as u64 + 100),
        ("bhive-footer-in-cell.bhive", b.cells[0].offset),
    ] {
        let mut bytes = whole.clone();
        let at = bytes.len() - 16;
        bytes[at..at + 8].copy_from_slice(&offset.to_le_bytes());
        files.push((name, bytes));
    }

    // A version and a feature this BeeZip doesn't have. Bit 0 is encryption (docs/bhive.md
    // §12), so the unknown feature is bit 1.
    let mut newer = whole.clone();
    newer[8] = 2;
    files.push(("bhive-version-2.bhive", newer));
    let mut feature = whole.clone();
    feature[12] = 0x02;
    files.push(("bhive-feature.bhive", feature));

    // Cut short at each part: in the header, a record, a journal, a cell, the index, the footer.
    let (three, _) = three_cells();
    let record2 = three.cells[0].end() as usize;
    let cell2 = three.cells[1].offset as usize;
    let index = three.bytes.len();
    let whole = three.finish();
    for (name, len) in [
        ("bhive-cut-header.bhive", 9),
        ("bhive-cut-record.bhive", record2 + 20),
        ("bhive-cut-journal.bhive", record2 + 60),
        ("bhive-cut-cell.bhive", cell2 + 7),
        ("bhive-cut-index-head.bhive", index + 10),
        ("bhive-cut-index.bhive", index + 40),
        ("bhive-cut-footer.bhive", whole.len() - 3),
    ] {
        files.push((name, whole[..len].to_vec()));
    }
    Ok(files)
}
