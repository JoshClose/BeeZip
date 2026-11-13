//! MSI installers, read by BeeZip itself (docs/M7.md §8, §10):
//!
//! - the committed `wixl.msi`, whose files 7-Zip lists by their File keys, listed under the
//!   folders the installer puts them in, with the bytes the manifest records;
//! - `multi.msi`, built here with the msi crate and BeeZip's CAB writer: several folders and
//!   cabinets, a standard folder and a merge module's copy of one, a loop, the same path twice,
//!   Binary and Icon streams, an external cabinet there and one missing, an uncompressed file in
//!   the source image and one missing, a name in code page 0, a wrong hash and a wrong size;
//! - merge modules built here with the msi crate and BeeZip's CAB writer, listed where they put
//!   their files; patches and transforms listed as their compound files under 7-Zip's names
//!   (docs/M11.md); the committed ones in `thirdparty/msi/` are checked by `fixtures.rs`;
//! - with `BEEZIP_MSI_SAMPLES` naming folders of real installers (the M7 spike's RustDesk,
//!   QGIS and LLVM ones), an ignored test that reads every file natively and through 7-Zip and
//!   compares them by File key: `cargo test --release --test msi -- --ignored real_installers`;
//!   and one that compares every patch, transform and merge module in them with 7-Zip's
//!   extraction (docs/M11.md §8): `-- --ignored real_patches`.
//!
//! The malicious MSIs in `tests/fixtures/malicious/` are written by another ignored test here,
//! `write_the_malicious_msis`; `tests/malicious/msi.rs` reads them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use beezip_core::{
    CreateOptions, Entry, EntryKind, ErrorKind, External, FormatId, FsOptions, NameDecoding,
    OpenOptions, SevenZipOptions, SimpleCtx, WriteSpec,
    format::cab::{CabMethod, CabWriteOptions},
    open, ops,
    source::Source,
};
use md5::Digest as _;
use msi::{CodePage, Column, Insert, Package, PackageType, Value};
use sha2::Sha256;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Native reading, with 7-Zip turned off so nothing falls back to it unseen.
fn native() -> OpenOptions {
    OpenOptions::default().with_seven_zip(SevenZipOptions {
        path: None,
        enabled: false,
    })
}

fn read_entry(r: &mut dyn beezip_core::ArchiveReader, id: usize) -> beezip_core::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.open_entry(id, &mut SimpleCtx::new())?
        .read_to_end(&mut v)
        .map_err(|e| beezip_core::io::read_error(&e))?;
    Ok(v)
}

fn by_path<'a>(entries: &'a [Entry], path: &str) -> &'a Entry {
    entries.iter().find(|e| e.path == path).unwrap_or_else(|| {
        let all: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        panic!("`{path}` isn't listed: {all:?}")
    })
}

// --- wixl.msi --------------------------------------------------------------------------------

/// What the manifest records for `7zip/wixl.msi`: 7-Zip's key → sha256.
fn wixl_record() -> HashMap<String, String> {
    let text = fs::read_to_string(fixtures().join("manifest.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let fx = v["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["file"] == "7zip/wixl.msi")
        .unwrap();
    fx["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["path"].as_str().unwrap().to_owned(),
                e["sha256"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn wixl_lists_files_where_the_installer_puts_them() {
    let path = fixtures().join("thirdparty/7zip/wixl.msi");
    let record = wixl_record();
    // 7-Zip's keys, and where the installer puts each (名前.txt's name is empty in the table:
    // wixl 0.103 drops non-ASCII names, so it's listed under its key).
    let dir = "LocalAppDataFolder/BeeZip fixture";
    let names = [
        ("readme", "readme.txt"),
        ("empty", "empty.txt"),
        ("random", "random.bin"),
        ("cjk", "cjk"),
    ];
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &native(), &mut cx).unwrap();
    assert_eq!(
        opened.detection.format(),
        Some(FormatId::External(External::Msi))
    );
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let listed: Vec<(&str, bool)> = entries
        .iter()
        .map(|e| (e.path.as_str(), e.is_dir()))
        .collect();
    assert_eq!(
        listed,
        [
            ("LocalAppDataFolder", true),
            ("LocalAppDataFolder/BeeZip fixture", true),
            ("LocalAppDataFolder/BeeZip fixture/readme.txt", false),
            ("LocalAppDataFolder/BeeZip fixture/empty.txt", false),
            ("LocalAppDataFolder/BeeZip fixture/random.bin", false),
            ("LocalAppDataFolder/BeeZip fixture/cjk", false),
        ]
    );
    assert!(cx.warnings.is_empty(), "{:?}", cx.warnings);
    for (key, name) in names {
        let e = by_path(&entries, &format!("{dir}/{name}"));
        assert!(e.modified.is_some(), "{name}: the cabinet's time");
        assert_eq!(e.method.as_deref(), Some("MSZIP"));
        let data = read_entry(&mut *opened.reader, e.id).unwrap();
        assert_eq!(e.size, Some(data.len() as u64));
        assert_eq!(sha256(&data), record[key], "{name}");
    }
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.methods, ["MSZIP"]);
    let ext = info.external.unwrap();
    assert_eq!(ext.backend, None);
    assert_eq!(ext.levels, ["msi", "cab"]);
    let props: Vec<(&str, &str)> = ext
        .properties
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    assert!(
        props.contains(&("ProductName", "BeeZip fixture")),
        "{props:?}"
    );

    // Extracted, and tested.
    let dest = tempfile::tempdir().unwrap();
    let report = ops::extract(
        &path,
        dest.path(),
        &beezip_core::Selection::all(),
        &native(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert_eq!((report.files, report.dirs), (4, 2));
    for (key, name) in names {
        let data = fs::read(dest.path().join(dir).join(name)).unwrap();
        assert_eq!(sha256(&data), record[key], "{name}");
    }
    let tested = ops::test(
        &path,
        &beezip_core::Selection::all(),
        &native(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(tested.ok(), "{:?}", tested.errors);
    assert_eq!(tested.entries, 6);
}

// --- Building MSIs ----------------------------------------------------------------------------

/// A new file to write a package into: the msi crate reads back what it writes.
fn new_file(path: &Path) -> fs::File {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap()
}

fn s(v: &str) -> Value {
    Value::Str(v.to_owned())
}

fn n(v: i32) -> Value {
    Value::Int(v)
}

/// The tables BeeZip reads, as WiX declares them.
fn create_tables(pkg: &mut Package<fs::File>) {
    let tables = [
        (
            "Directory",
            vec![
                Column::build("Directory").primary_key().id_string(72),
                Column::build("Directory_Parent").nullable().id_string(72),
                Column::build("DefaultDir").text_string(0),
            ],
        ),
        (
            "Component",
            vec![
                Column::build("Component").primary_key().id_string(72),
                Column::build("ComponentId").nullable().string(38),
                Column::build("Directory_").id_string(72),
                Column::build("Attributes").int16(),
                Column::build("Condition").nullable().string(255),
                Column::build("KeyPath").nullable().id_string(72),
            ],
        ),
        (
            "File",
            vec![
                Column::build("File").primary_key().id_string(72),
                Column::build("Component_").id_string(72),
                Column::build("FileName").text_string(0),
                Column::build("FileSize").int32(),
                Column::build("Version").nullable().string(72),
                Column::build("Language").nullable().string(20),
                Column::build("Attributes").nullable().int16(),
                Column::build("Sequence").int32(),
            ],
        ),
        (
            "Media",
            vec![
                Column::build("DiskId").primary_key().int16(),
                Column::build("LastSequence").int32(),
                Column::build("DiskPrompt").nullable().text_string(64),
                Column::build("Cabinet").nullable().string(255),
                Column::build("VolumeLabel").nullable().text_string(32),
                Column::build("Source").nullable().string(72),
            ],
        ),
        (
            "MsiFileHash",
            vec![
                Column::build("File_").primary_key().id_string(72),
                Column::build("Options").int16(),
                Column::build("HashPart1").int32(),
                Column::build("HashPart2").int32(),
                Column::build("HashPart3").int32(),
                Column::build("HashPart4").int32(),
            ],
        ),
        (
            "Property",
            vec![
                Column::build("Property").primary_key().id_string(72),
                Column::build("Value").text_string(0),
            ],
        ),
    ];
    for (name, cols) in tables {
        pkg.create_table(name, cols).unwrap();
    }
    for t in ["Binary", "Icon"] {
        pkg.create_table(
            t,
            vec![
                Column::build("Name").primary_key().id_string(72),
                Column::build("Data").binary(),
            ],
        )
        .unwrap();
    }
}

/// A cabinet of `files`, each named by its key, written by BeeZip.
fn cab(out: &Path, files: &[(&str, &[u8])], method: CabMethod) {
    let dir = tempfile::tempdir().unwrap();
    let inputs: Vec<PathBuf> = files
        .iter()
        .map(|(k, data)| {
            let p = dir.path().join(k);
            fs::write(&p, data).unwrap();
            p
        })
        .collect();
    ops::create(
        out,
        &inputs,
        &WriteSpec::Cab(CabWriteOptions { method }),
        &CreateOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
}

/// MSI's stream-name packing (as BeeZip's reader does it), for patching a stream with cfb.
fn stream_path(name: &str, table: bool) -> String {
    let b64 = |c: char| match c {
        '0'..='9' => Some(c as u32 - '0' as u32),
        'A'..='Z' => Some(c as u32 - 'A' as u32 + 10),
        'a'..='z' => Some(c as u32 - 'a' as u32 + 36),
        '.' => Some(62),
        '_' => Some(63),
        _ => None,
    };
    let mut out = String::from("/");
    if table {
        out.push('\u{4840}');
    }
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        match (b64(c), chars.peek().copied().and_then(b64)) {
            (Some(v1), Some(v2)) => {
                chars.next();
                out.push(char::from_u32(0x3800 + (v2 << 6) + v1).unwrap());
            }
            (Some(v1), None) => out.push(char::from_u32(0x4800 + v1).unwrap()),
            (None, _) => out.push(c),
        }
    }
    out
}

/// Rewrites the stream `name` of the package at `path` with `edit`.
fn patch_stream(path: &Path, name: &str, table: bool, edit: impl FnOnce(&mut Vec<u8>)) {
    let mut comp = cfb::open_rw(path).unwrap();
    let p = stream_path(name, table);
    let mut data = Vec::new();
    comp.open_stream(&p)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    edit(&mut data);
    let mut s = comp.create_stream(&p).unwrap();
    s.write_all(&data).unwrap();
    drop(s);
    comp.flush().unwrap();
}

/// Whether the hash of a file is right, wrong, or WiX's zeros for an empty file.
#[derive(Clone, Copy, PartialEq)]
enum Hash {
    Right,
    Wrong,
    Zeros,
}

/// A File row of `multi.msi`: its FileName, key, component, attributes, data, where its data
/// is (`#one.cab`…, an external cabinet, or `None`: the source image) and its hash.
struct F {
    name: &'static str,
    key: &'static str,
    comp: &'static str,
    attrs: i32,
    data: Vec<u8>,
    hash: Hash,
    /// The size the File table claims, when it isn't the data's.
    claims: Option<i32>,
}

fn f(name: &'static str, key: &'static str, comp: &'static str, data: &[u8]) -> F {
    F {
        name,
        key,
        comp,
        attrs: 0,
        data: data.to_vec(),
        hash: Hash::Right,
        claims: None,
    }
}

/// `multi.msi` and what's beside it, in `dir`: the files in their order of Sequence, and the
/// Media rows (last sequence, cabinet) they're in.
fn multi_files() -> (Vec<F>, Vec<(i32, Option<&'static str>)>) {
    let files = vec![
        // #one.cab (MSZIP)
        f("BEEZIP~1.EXE|beezip.exe", "f_exe", "C_app", b"MZ beezip"),
        F {
            attrs: 1,
            ..f(
                "readme.txt",
                "f_readme",
                "C_sub",
                b"readme from the app's folder\n",
            )
        },
        // #two.cab (stored): the same path twice, and a file of several blocks.
        f("msvcp140.dll", "f_x64", "C_x64", b"the x64 runtime"),
        f("msvcp140.dll", "f_arm", "C_arm", b"the Arm64 runtime"),
        f("manual.txt", "f_manual", "C_docs", &[b'm'; 70_000]),
        // ext.cab, beside the MSI.
        f("ext.txt", "f_ext", "C_app", b"in the external cabinet\n"),
        // missing.cab, which isn't.
        f("lost.txt", "f_lost", "C_app", b"in a missing cabinet\n"),
        // No cabinet: the source image.
        F {
            attrs: 0x2000,
            ..f(
                "LOOSE~1.TXT|loose.txt",
                "f_loose",
                "C_docs",
                b"uncompressed, in the source image\n",
            )
        },
        F {
            attrs: 0x2000,
            ..f(
                "nosrc.txt",
                "f_nosrc",
                "C_docs",
                b"uncompressed, and not there\n",
            )
        },
        // #three.cab (MSZIP)
        f("café.txt", "f_cafe", "C_root2", "café\n".as_bytes()),
        f("", "f_noname", "C_app", b"a file without a name\n"),
        F {
            hash: Hash::Wrong,
            ..f("bad.txt", "f_bad", "C_app", b"its hash is wrong\n")
        },
        F {
            hash: Hash::Zeros,
            ..f("empty.txt", "f_empty", "C_app", b"")
        },
        f("loop.txt", "f_loop", "C_loop", b"in a loop of folders\n"),
        F {
            claims: Some(5),
            ..f("short.txt", "f_short", "C_app", b"abc")
        },
    ];
    let media = vec![
        (2, Some("#one.cab")),
        (5, Some("#two.cab")),
        (6, Some("ext.cab")),
        (7, Some("missing.cab")),
        (9, None),
        (15, Some("#three.cab")),
    ];
    (files, media)
}

/// Writes `multi.msi` into `dir`, with `ext.cab` and the source image beside it.
fn build_multi(dir: &Path) -> PathBuf {
    let (files, media) = multi_files();
    let msi = dir.join("multi.msi");
    let mut pkg = Package::create(PackageType::Installer, new_file(&msi)).unwrap();
    // Written in 1252, then marked neutral (0) below: the msi crate can't write code page 0.
    pkg.set_database_codepage(CodePage::Windows1252);
    pkg.summary_info_mut().set_word_count(2);
    create_tables(&mut pkg);
    let dirs: &[(&str, Option<&str>, &str)] = &[
        ("TARGETDIR", None, "SourceDir"),
        ("ProgramFilesFolder", Some("TARGETDIR"), "PFiles"),
        (
            "APPDIR",
            Some("ProgramFilesFolder"),
            "BEEZIP~1|BeeZip App:BEEZIP~2|BeeZip Source",
        ),
        ("SUBDIR", Some("APPDIR"), "."),
        ("DOCS", Some("APPDIR"), "docs"),
        // A standard folder under another starts at the top; so does a merge module's copy.
        ("System64Folder", Some("APPDIR"), "sys"),
        (
            "System64Folder.DFEFC2FE_EEE6_424C_841B_D4E66F0C84A3",
            Some("TARGETDIR"),
            ".",
        ),
        ("ROOT2", None, "Other"),
        ("LOOPA", Some("LOOPB"), "a"),
        ("LOOPB", Some("LOOPA"), "b"),
    ];
    let mut q = Insert::into("Directory");
    for (d, p, dd) in dirs {
        q = q.row(vec![s(d), p.map_or(Value::Null, s), s(dd)]);
    }
    pkg.insert_rows(q).unwrap();
    let mut q = Insert::into("Component");
    for (c, d) in [
        ("C_app", "APPDIR"),
        ("C_sub", "SUBDIR"),
        ("C_docs", "DOCS"),
        ("C_x64", "System64Folder"),
        (
            "C_arm",
            "System64Folder.DFEFC2FE_EEE6_424C_841B_D4E66F0C84A3",
        ),
        ("C_root2", "ROOT2"),
        ("C_loop", "LOOPA"),
    ] {
        q = q.row(vec![
            s(c),
            Value::Null,
            s(d),
            n(0),
            Value::Null,
            Value::Null,
        ]);
    }
    pkg.insert_rows(q).unwrap();
    let (mut rows, mut hashes) = (Insert::into("File"), Insert::into("MsiFileHash"));
    for (i, file) in files.iter().enumerate() {
        rows = rows.row(vec![
            s(file.key),
            s(file.comp),
            s(file.name),
            n(file.claims.unwrap_or(file.data.len() as i32)),
            Value::Null,
            Value::Null,
            n(file.attrs),
            n(i as i32 + 1),
        ]);
        let mut h: [u8; 16] = md5::Md5::digest(&file.data).into();
        match file.hash {
            Hash::Right => {}
            Hash::Wrong => h[0] ^= 1,
            Hash::Zeros => h = [0; 16],
        }
        let part = |i: usize| n(i32::from_le_bytes(h[i * 4..i * 4 + 4].try_into().unwrap()));
        hashes = hashes.row(vec![s(file.key), n(0), part(0), part(1), part(2), part(3)]);
    }
    pkg.insert_rows(rows).unwrap();
    pkg.insert_rows(hashes).unwrap();
    let mut q = Insert::into("Media");
    for (i, (last, cabinet)) in media.iter().enumerate() {
        q = q.row(vec![
            n(i as i32 + 1),
            n(*last),
            Value::Null,
            cabinet.map_or(Value::Null, s),
            Value::Null,
            Value::Null,
        ]);
    }
    pkg.insert_rows(q).unwrap();
    pkg.insert_rows(
        Insert::into("Property")
            .row(vec![s("ProductName"), s("BeeZip multi")])
            .row(vec![s("ProductVersion"), s("1.2.3")])
            .row(vec![s("Manufacturer"), s("BeeZip")]),
    )
    .unwrap();
    pkg.insert_rows(Insert::into("Binary").row(vec![s("Logo"), Value::Binary]))
        .unwrap();
    pkg.insert_rows(Insert::into("Icon").row(vec![s("app.ico"), Value::Binary]))
        .unwrap();
    pkg.write_stream("Binary.Logo")
        .unwrap()
        .write_all(b"BM a bitmap")
        .unwrap();
    pkg.write_stream("Icon.app.ico")
        .unwrap()
        .write_all(b"\0\0\x01\0 an icon")
        .unwrap();

    // The cabinets, by the Media rows each file's sequence falls in.
    let work = tempfile::tempdir().unwrap();
    let mut first = 1;
    for (last, cabinet) in &media {
        let these: Vec<(&str, &[u8])> = files[first - 1..*last as usize]
            .iter()
            .filter(|f| f.attrs & 0x2000 == 0)
            .map(|f| (f.key, f.data.as_slice()))
            .collect();
        first = *last as usize + 1;
        let Some(cabinet) = cabinet else {
            continue;
        };
        let method = if *cabinet == "#two.cab" {
            CabMethod::Store
        } else {
            CabMethod::Mszip
        };
        match cabinet.strip_prefix('#') {
            Some(name) => {
                let p = work.path().join(name);
                cab(&p, &these, method);
                pkg.write_stream(name)
                    .unwrap()
                    .write_all(&fs::read(&p).unwrap())
                    .unwrap();
            }
            None if *cabinet == "ext.cab" => cab(&dir.join(cabinet), &these, method),
            None => {}
        }
    }
    drop(pkg);
    // Code page 0, "neutral": the pool's header keeps only its long-references bit.
    patch_stream(&msi, "_StringPool", true, |pool| {
        pool[..2].fill(0);
    });

    // The source image: TARGETDIR is the MSI's folder, with long source names.
    let src = dir.join("PFiles/BeeZip Source/docs");
    fs::create_dir_all(&src).unwrap();
    let loose = files.iter().find(|f| f.key == "f_loose").unwrap();
    fs::write(src.join("loose.txt"), &loose.data).unwrap();
    msi
}

// --- multi.msi --------------------------------------------------------------------------------

const APP: &str = "ProgramFilesFolder/BeeZip App";

/// Where each file of `multi.msi` is listed, by key.
fn multi_paths() -> HashMap<&'static str, String> {
    [
        ("f_exe", format!("{APP}/beezip.exe")),
        ("f_readme", format!("{APP}/readme.txt")),
        ("f_x64", "System64Folder/msvcp140.dll".to_owned()),
        ("f_arm", "System64Folder/msvcp140.f_arm.dll".to_owned()),
        ("f_manual", format!("{APP}/docs/manual.txt")),
        ("f_ext", format!("{APP}/ext.txt")),
        ("f_lost", format!("{APP}/lost.txt")),
        ("f_loose", format!("{APP}/docs/loose.txt")),
        ("f_nosrc", format!("{APP}/docs/nosrc.txt")),
        ("f_cafe", "ROOT2/café.txt".to_owned()),
        ("f_noname", format!("{APP}/f_noname")),
        ("f_bad", format!("{APP}/bad.txt")),
        ("f_empty", format!("{APP}/empty.txt")),
        ("f_loop", "LOOPA/loop.txt".to_owned()),
        ("f_short", format!("{APP}/short.txt")),
    ]
    .into_iter()
    .collect()
}

/// How reading each file that can't be read fails.
fn multi_failures() -> HashMap<&'static str, ErrorKind> {
    [
        ("f_lost", ErrorKind::NotFound),
        ("f_nosrc", ErrorKind::NotFound),
        ("f_bad", ErrorKind::Corrupt),
        ("f_short", ErrorKind::Corrupt),
    ]
    .into_iter()
    .collect()
}

#[test]
fn multi_lists_every_kind_of_file() {
    let dir = tempfile::tempdir().unwrap();
    let msi = build_multi(dir.path());
    let (files, _) = multi_files();
    let paths = multi_paths();
    let failures = multi_failures();

    let mut cx = SimpleCtx::new();
    let mut opened = open(&msi, &native(), &mut cx).unwrap();
    let r = &mut *opened.reader;
    let entries = r.entries(&mut cx).unwrap().to_vec();

    // Folders first, parents before children, then the files, then the streams.
    let dirs: Vec<&str> = entries
        .iter()
        .take_while(|e| e.is_dir())
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(
        dirs,
        [
            "LOOPA",
            "ProgramFilesFolder",
            "ProgramFilesFolder/BeeZip App",
            "ProgramFilesFolder/BeeZip App/docs",
            "ROOT2",
            "System64Folder",
            "[Binary]",
            "[Icon]",
        ]
    );
    let rest: Vec<&str> = entries[dirs.len()..]
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(rest.len(), files.len() + 2, "{rest:?}");
    assert_eq!(&rest[rest.len() - 2..], ["[Binary]/Logo", "[Icon]/app.ico"]);
    // In the order their data is read: the cabinets in the Media table's order.
    assert_eq!(rest[0], paths["f_exe"]);
    assert_eq!(rest[2], paths["f_x64"]);
    assert_eq!(*rest.last().unwrap(), "[Icon]/app.ico");

    // Each file: its size, attributes and bytes, or how it fails.
    for file in &files {
        let e = by_path(&entries, &paths[file.key]);
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(
            e.size,
            Some(file.claims.unwrap_or(file.data.len() as i32) as u64),
            "{}",
            file.key
        );
        let got = read_entry(r, e.id);
        match failures.get(file.key) {
            Some(kind) => assert_eq!(got.unwrap_err().kind, *kind, "{}", file.key),
            None => assert!(got.unwrap() == file.data, "{}", file.key),
        }
    }
    assert_eq!(by_path(&entries, &paths["f_readme"]).dos_attrs, Some(1));
    assert!(by_path(&entries, &paths["f_exe"]).modified.is_some());
    assert_eq!(
        by_path(&entries, &paths["f_manual"]).method.as_deref(),
        Some("Store")
    );
    for (p, want) in [
        ("[Binary]/Logo", &b"BM a bitmap"[..]),
        ("[Icon]/app.ico", b"\0\0\x01\0 an icon"),
    ] {
        let e = by_path(&entries, p);
        assert_eq!(e.size, Some(want.len() as u64));
        assert_eq!(read_entry(r, e.id).unwrap(), want);
    }

    // Warned once each, saying where it looked.
    let warned = |what: &str| cx.warnings.iter().filter(|w| w.contains(what)).count();
    assert_eq!(warned("missing.cab"), 1, "{:?}", cx.warnings);
    let looked = dir.path().join("missing.cab");
    assert_eq!(
        warned(&looked.display().to_string()),
        1,
        "{:?}",
        cx.warnings
    );
    let looked = dir
        .path()
        .join("PFiles")
        .join("BeeZip Source")
        .join("docs")
        .join("nosrc.txt");
    assert_eq!(
        warned(&looked.display().to_string()),
        1,
        "{:?}",
        cx.warnings
    );
    assert_eq!(warned("loop"), 1, "{:?}", cx.warnings);

    let info = r.info(&mut cx).unwrap();
    assert_eq!(info.format, FormatId::External(External::Msi));
    assert!(info.methods.contains(&"MSZIP".into()) && info.methods.contains(&"Store".into()));
    let ext = info.external.unwrap();
    assert_eq!(ext.levels, ["msi", "cab"]);
    let props: Vec<(&str, &str)> = ext
        .properties
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    assert_eq!(
        props,
        [
            ("ProductName", "BeeZip multi"),
            ("ProductVersion", "1.2.3"),
            ("Manufacturer", "BeeZip")
        ]
    );
    assert!(
        ext.notes.iter().any(|n| n.contains("File key")),
        "{:?}",
        ext.notes
    );
}

#[test]
fn multi_extracts_and_tests_file_by_file() {
    let dir = tempfile::tempdir().unwrap();
    let msi = build_multi(dir.path());
    let (files, _) = multi_files();
    let paths = multi_paths();
    let failures = multi_failures();

    // Testing reads every file, and records each that fails.
    let report = ops::test(
        &msi,
        &beezip_core::Selection::all(),
        &native(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let failed: HashMap<String, ErrorKind> = report
        .errors
        .iter()
        .map(|e| (e.path.clone(), e.kind))
        .collect();
    let want: HashMap<String, ErrorKind> = failures
        .iter()
        .map(|(k, kind)| (paths[k].clone(), *kind))
        .collect();
    assert_eq!(failed, want);
    assert_eq!(report.errors_total, 4);

    // Extracting all stops at the first file that can't be read.
    let dest = tempfile::tempdir().unwrap();
    let err = ops::extract(
        &msi,
        dest.path(),
        &beezip_core::Selection::all(),
        &native(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound, "{err}");

    // The rest extract, each to its bytes, with the job's progress over the whole package.
    let exclude: Vec<String> = failures
        .keys()
        .map(|k| paths[k].rsplit('/').next().unwrap().to_owned())
        .collect();
    let sel = beezip_core::Selection::new(&[], &[], &exclude).unwrap();
    let dest = tempfile::tempdir().unwrap();
    let mut cx = SimpleCtx::new();
    let report = ops::extract(
        &msi,
        dest.path(),
        &sel,
        &native(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap();
    assert_eq!(report.files as usize, files.len() - failures.len() + 2);
    for file in files.iter().filter(|f| !failures.contains_key(f.key)) {
        let got = fs::read(dest.path().join(&paths[file.key])).unwrap();
        assert!(got == file.data, "{}", file.key);
    }
    assert_eq!(
        fs::read(dest.path().join("[Binary]/Logo")).unwrap(),
        b"BM a bitmap"
    );
    let p = cx.last_progress.unwrap();
    assert_eq!(p.entries_total, Some(p.entries_done));
    assert!(
        p.bytes_done > 0 && p.bytes_done <= p.bytes_total.unwrap(),
        "{p:?}"
    );

    // Cancelled, it stops.
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut cx = SimpleCtx::new().with_cancel(flag);
    let dest = tempfile::tempdir().unwrap();
    let err = ops::extract(
        &msi,
        dest.path(),
        &sel,
        &native(),
        FsOptions::default(),
        &mut cx,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
}

/// Code page 0 is the system's ANSI code page: café on a Western system, Cyrillic on a
/// Russian one, as Windows Installer would show it there.
#[test]
fn code_page_zero_is_the_systems() {
    let dir = tempfile::tempdir().unwrap();
    let msi = build_multi(dir.path());
    let names = |ansi: u16| -> Vec<String> {
        let opts = native().with_names(NameDecoding {
            ansi,
            ..NameDecoding::default()
        });
        let mut opened = open(&msi, &opts, &mut SimpleCtx::new()).unwrap();
        let entries = opened.reader.entries(&mut SimpleCtx::new()).unwrap();
        entries
            .iter()
            .filter(|e| e.path.starts_with("ROOT2/"))
            .map(|e| e.path.clone())
            .collect()
    };
    assert_eq!(names(1252), ["ROOT2/café.txt"]);
    assert_eq!(names(1251), ["ROOT2/cafй.txt"]);
}

/// A file that isn't a compound file, or a package without its string pool, is damaged: it
/// fails cleanly, and doesn't go to 7-Zip.
#[test]
fn damaged_packages_are_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.msi");
    fs::write(&junk, vec![0xAB; 4096]).unwrap();
    let source = Source::new(&junk, Vec::new(), &native()).unwrap();
    let err = beezip_core::format::msi::open(source, &mut SimpleCtx::new())
        .err()
        .unwrap();
    assert_eq!(err.kind, ErrorKind::Corrupt, "{err}");

    // Every prefix of a real package either opens or fails cleanly.
    let msi = build_multi(dir.path());
    let bytes = fs::read(&msi).unwrap();
    let cut = dir.path().join("cut.msi");
    for len in (0..bytes.len()).step_by(4093) {
        fs::write(&cut, &bytes[..len]).unwrap();
        let source = Source::new(&cut, Vec::new(), &native()).unwrap();
        if let Ok(mut r) = beezip_core::format::msi::open(source, &mut SimpleCtx::new()) {
            let _ = r.extract(
                &beezip_core::Selection::all(),
                &mut beezip_core::NullSink::default(),
                &mut SimpleCtx::new(),
            );
        }
    }
}

/// The fuzz target's body over bit-flipped, overwritten and cut copies of every MSI here: none
/// may panic or hang. `BEEZIP_MUTATIONS` sets the copies per package (default 150).
#[test]
fn mutated_packages_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let mut seeds = vec![
        fs::read(fixtures().join("thirdparty/7zip/wixl.msi")).unwrap(),
        fs::read(build_multi(dir.path())).unwrap(),
    ];
    for name in [
        "module.msm",
        "module-lzx.msm",
        "patch.msp",
        "v1-to-v2.mst",
        "v2-to-v1.mst",
    ] {
        seeds.push(fs::read(fixtures().join("thirdparty/msi").join(name)).unwrap());
    }
    for name in [
        "deep.msi",
        "pool-4gib.msi",
        "catalog-nulls.msi",
        "summary-2gib.msi",
        "msp-names.msp",
        "mst-claim.mst",
        "msm-no-cab.msm",
    ] {
        seeds.push(fs::read(fixtures().join("malicious").join(name)).unwrap());
    }
    let per = std::env::var("BEEZIP_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150usize);
    let limits = beezip_core::Limits {
        max_ratio: Some(200),
        ratio_grace: 1 << 20,
        max_total_bytes: Some(32 << 20),
        max_entries: Some(10_000),
        max_layers: 4,
        decoder_memory: 64 << 20,
    };
    let opts = OpenOptions::new(limits);
    let mut x = 0x00BE_E21F_u64;
    let mut next = move || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let input = dir.path().join("input.msi");
    for seed in &seeds {
        for _ in 0..per {
            let mut d = seed.clone();
            let len = d.len().max(1) as u64;
            match next() % 3 {
                0 => {
                    for _ in 0..1 + next() % 8 {
                        let i = (next() % len) as usize;
                        if let Some(b) = d.get_mut(i) {
                            *b ^= 1 << (next() % 8);
                        }
                    }
                }
                1 => {
                    let i = (next() % len) as usize;
                    let v = [0u8, 0xFF, 0x7F, 0x80][(next() % 4) as usize];
                    for b in d.iter_mut().skip(i).take(1 + (next() % 4) as usize) {
                        *b = v;
                    }
                }
                _ => d.truncate((next() % len) as usize),
            }
            fs::write(&input, &d).unwrap();
            let Ok(source) = Source::new(&input, Vec::new(), &opts) else {
                continue;
            };
            let mut cx = SimpleCtx::new();
            let Ok(mut r) = beezip_core::format::msi::open(source, &mut cx) else {
                continue;
            };
            let count = r.entries(&mut cx).map(<[_]>::len).unwrap_or(0);
            let _ = r.info(&mut cx);
            let _ = r.extract(
                &beezip_core::Selection::all(),
                &mut beezip_core::NullSink::default(),
                &mut cx,
            );
            for id in 0..count.min(8) {
                if let Ok(mut e) = r.open_entry(id, &mut cx) {
                    let _ = std::io::copy(&mut e.by_ref().take(1 << 20), &mut std::io::sink());
                }
            }
        }
    }
}

// --- Merge modules, patches and transforms (docs/M11.md) ---------------------------------------

/// The GUID a merge module's keys carry.
const G: &str = "8D5E0F2A_1B2C_4D3E_9F40_112233445566";

/// What a merge module's `MergeModule.CABinet` stream is.
#[derive(Clone, Copy)]
enum ModuleCab {
    Sound,
    Missing,
    NotACabinet,
}

/// A merge module built with the msi crate and BeeZip's CAB writer, as `module.msm` is with
/// msi.dll: no Media table, its files in `MergeModule.CABinet`, at the merge point (TARGETDIR's
/// `.` child), in a folder below it, in a modularized standard folder and in a folder of a
/// modularized one, and a custom action. Its word count says its files aren't compressed, which a
/// module's always are. Returns each file's path as BeeZip lists it, with its bytes.
fn build_module(path: &Path, cabinet: ModuleCab) -> Vec<(String, Vec<u8>)> {
    let mut pkg = Package::create(PackageType::Installer, new_file(path)).unwrap();
    pkg.summary_info_mut().set_word_count(0);
    pkg.summary_info_mut()
        .set_subject("BeeZip test module".to_owned());
    create_tables(&mut pkg);
    pkg.drop_table("Media").unwrap();
    pkg.create_table(
        "ModuleSignature",
        vec![
            Column::build("ModuleID").primary_key().id_string(72),
            Column::build("Language").primary_key().int16(),
            Column::build("Version").string(32),
        ],
    )
    .unwrap();
    pkg.insert_rows(Insert::into("ModuleSignature").row(vec![
        Value::from(format!("BeeZipTest.{G}")),
        n(1033),
        s("2.0.1"),
    ]))
    .unwrap();
    let k = |name: &str| format!("{name}.{G}");
    let dirs = [
        ("TARGETDIR".to_owned(), None, "SourceDir"),
        (k("MergeRedirectFolder"), Some("TARGETDIR".to_owned()), "."),
        (k("Docs"), Some(k("MergeRedirectFolder")), "DOCS|Docs"),
        (k("SystemFolder"), Some("TARGETDIR".to_owned()), "System"),
        (
            k("ProgramFilesFolder"),
            Some("TARGETDIR".to_owned()),
            "PFiles",
        ),
        (k("Vendor"), Some(k("ProgramFilesFolder")), "Vendor"),
    ];
    let mut q = Insert::into("Directory");
    for (d, p, dd) in dirs {
        q = q.row(vec![
            Value::from(d),
            p.map_or(Value::Null, Value::from),
            s(dd),
        ]);
    }
    pkg.insert_rows(q).unwrap();
    // FileName, key, its folder, data, and where BeeZip lists it.
    let files: [(&str, String, String, &[u8], &str); 4] = [
        (
            "top.txt",
            k("top.txt"),
            k("MergeRedirectFolder"),
            b"at the merge point\n",
            "top.txt",
        ),
        (
            "GUIDE~1.TXT|guide.txt",
            k("guide.txt"),
            k("Docs"),
            b"a guide\n",
            "Docs/guide.txt",
        ),
        (
            "sys.dll",
            k("sys.dll"),
            k("SystemFolder"),
            b"MZ sys",
            "SystemFolder/sys.dll",
        ),
        (
            "tool.dll",
            k("tool.dll"),
            k("Vendor"),
            &[b't'; 40_000],
            "ProgramFilesFolder/Vendor/tool.dll",
        ),
    ];
    let (mut comps, mut rows, mut hashes) = (
        Insert::into("Component"),
        Insert::into("File"),
        Insert::into("MsiFileHash"),
    );
    for (i, (name, key, dir, data, _)) in files.iter().enumerate() {
        comps = comps.row(vec![
            Value::from(key.clone()),
            Value::Null,
            Value::from(dir.clone()),
            n(0),
            Value::Null,
            Value::Null,
        ]);
        rows = rows.row(vec![
            Value::from(key.clone()),
            Value::from(key.clone()),
            s(name),
            n(data.len() as i32),
            Value::Null,
            Value::Null,
            n(0),
            n(i as i32 + 1),
        ]);
        let h: [u8; 16] = md5::Md5::digest(data).into();
        let part = |i: usize| n(i32::from_le_bytes(h[i * 4..i * 4 + 4].try_into().unwrap()));
        hashes = hashes.row(vec![
            Value::from(key.clone()),
            n(0),
            part(0),
            part(1),
            part(2),
            part(3),
        ]);
    }
    pkg.insert_rows(comps).unwrap();
    pkg.insert_rows(rows).unwrap();
    pkg.insert_rows(hashes).unwrap();
    let action: &[u8] = b"MZ a custom action";
    pkg.insert_rows(Insert::into("Binary").row(vec![Value::from(k("Action")), Value::Binary]))
        .unwrap();
    pkg.write_stream(&format!("Binary.{}", k("Action")))
        .unwrap()
        .write_all(action)
        .unwrap();
    let bytes = match cabinet {
        ModuleCab::Sound => {
            let work = tempfile::tempdir().unwrap();
            let c = work.path().join("module.cab");
            let data: Vec<(&str, &[u8])> = files
                .iter()
                .map(|(_, key, _, d, _)| (key.as_str(), *d))
                .collect();
            cab(&c, &data, CabMethod::Mszip);
            Some(fs::read(&c).unwrap())
        }
        ModuleCab::Missing => None,
        ModuleCab::NotACabinet => Some(b"not a cabinet, though named as one".repeat(10)),
    };
    if let Some(bytes) = bytes {
        pkg.write_stream("MergeModule.CABinet")
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    drop(pkg);
    let mut want: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|(_, _, _, d, p)| ((*p).to_owned(), d.to_vec()))
        .collect();
    want.push((format!("[Binary]/{}", k("Action")), action.to_vec()));
    want
}

#[test]
fn merge_modules_list_where_they_put_their_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("module.msm");
    let want = build_module(&path, ModuleCab::Sound);
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &native(), &mut cx).unwrap();
    assert_eq!(
        opened.detection.format(),
        Some(FormatId::External(External::Msi))
    );
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let mut files: Vec<&str> = entries
        .iter()
        .filter(|e| !e.is_dir())
        .map(|e| e.path.as_str())
        .collect();
    files.sort_unstable();
    let mut paths: Vec<&str> = want.iter().map(|(p, _)| p.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(files, paths);
    for (p, data) in &want {
        let id = by_path(&entries, p).id;
        assert_eq!(&read_entry(&mut *opened.reader, id).unwrap(), data, "{p}");
    }
    let info = opened.reader.info(&mut cx).unwrap();
    let x = info.external.unwrap();
    assert_eq!(x.levels, ["msm", "cab"]);
    let prop = |name: &str| {
        x.properties
            .iter()
            .find(|p| p.name == name)
            .map(|p| (p.level.as_str(), p.value.as_str()))
    };
    assert_eq!(
        prop("Module"),
        Some(("msm", format!("BeeZipTest.{G}").as_str()))
    );
    assert_eq!(prop("Version"), Some(("msm", "2.0.1")));
    assert_eq!(prop("Language"), Some(("msm", "1033")));
    assert_eq!(prop("Subject"), Some(("msm", "BeeZip test module")));
    assert!(x.notes[0].contains("merge module"), "{:?}", x.notes);
    assert!(cx.warnings.is_empty(), "{:?}", cx.warnings);

    // Tested and extracted whole: the MsiFileHash rows hold.
    let report = ops::test(&path, &beezip_core::Selection::all(), &native(), &mut cx).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let out = tempfile::tempdir().unwrap();
    ops::extract(
        &path,
        out.path(),
        &beezip_core::Selection::all(),
        &native(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    for (p, data) in &want {
        assert_eq!(&fs::read(out.path().join(p)).unwrap(), data, "{p}");
    }
}

/// A module without its cabinet, or with a stream of that name that isn't one, lists its files,
/// and each fails when it's read; the custom action still reads.
#[test]
fn a_merge_modules_missing_cabinet_fails_its_files() {
    let dir = tempfile::tempdir().unwrap();
    for (cabinet, says) in [
        (
            ModuleCab::Missing,
            "the merge module's cabinet, `MergeModule.CABinet`, isn't in it",
        ),
        (ModuleCab::NotACabinet, "can't be read"),
    ] {
        let path = dir.path().join("broken.msm");
        let want = build_module(&path, cabinet);
        let mut cx = SimpleCtx::new();
        let mut opened = open(&path, &native(), &mut cx).unwrap();
        assert!(
            cx.warnings.iter().any(|w| w.contains(says)),
            "{:?}",
            cx.warnings
        );
        let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
        for (p, data) in &want {
            let got = read_entry(&mut *opened.reader, by_path(&entries, p).id);
            if p.starts_with("[Binary]/") {
                assert_eq!(&got.unwrap(), data);
            } else {
                assert_eq!(got.unwrap_err().kind, ErrorKind::Corrupt, "{p}");
            }
        }
    }
}

/// Adds `streams` (cfb path, bytes) and `storages` to the compound file at `path`.
fn add_to_compound(path: &Path, storages: &[&str], streams: &[(&str, &[u8])]) {
    let mut comp = cfb::open_rw(path).unwrap();
    for st in storages {
        comp.create_storage(st).unwrap();
    }
    for (name, data) in streams {
        let mut s = comp.create_stream(name).unwrap();
        s.write_all(data).unwrap();
    }
    comp.flush().unwrap();
}

/// A cabinet of one small file, written by BeeZip.
fn small_cab() -> Vec<u8> {
    let work = tempfile::tempdir().unwrap();
    let c = work.path().join("small.cab");
    cab(
        &c,
        &[("payload.txt", b"inside the cabinet\n")],
        CabMethod::Mszip,
    );
    fs::read(&c).unwrap()
}

/// A transform is detected by its CLSID and listed as its compound file, with 7-Zip's names:
/// packed names unpacked, the table mark as `!`, a control character as `[n]`; a cabinet stream
/// gets `.cab`; storages first, then streams, by name ignoring case.
#[test]
fn transforms_list_their_streams_under_7zips_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.mst");
    drop(Package::create(PackageType::Transform, new_file(&path)).unwrap());
    let cabinet = small_cab();
    let storage = stream_path("TGT_1ToUPG_1", false);
    let inner = format!("{storage}{}", &stream_path("Property", true)[..]);
    let file_table = stream_path("File", true);
    let pcw = stream_path("PCW_CAB_X", false);
    let named_cab = stream_path("data.cab", false);
    add_to_compound(
        &path,
        &[&storage],
        &[
            (&file_table, b"rows of changes"),
            (&inner, b"a property"),
            (&pcw, &cabinet),
            (&named_cab, &cabinet),
            ("/\u{1}Ole", b"control"),
            ("/名前", b"a name in CJK"),
        ],
    );
    let det = beezip_core::detect_path(&path, &beezip_core::Limits::default()).unwrap();
    assert_eq!(det.format(), Some(FormatId::External(External::Msi)));
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &native(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    // The storage first, then every stream by its name ignoring case.
    assert_eq!(paths[0], "TGT_1ToUPG_1");
    assert!(entries[0].is_dir());
    let files: Vec<&str> = paths[1..].to_vec();
    let mut sorted = files.clone();
    sorted.sort_by_key(|p| p.to_lowercase());
    assert_eq!(files, sorted);
    for (p, data) in [
        ("!File", &b"rows of changes"[..]),
        ("TGT_1ToUPG_1/!Property", b"a property"),
        ("PCW_CAB_X.cab", &cabinet),
        ("data.cab", &cabinet),
        ("[1]Ole", b"control"),
        ("名前", "a name in CJK".as_bytes()),
    ] {
        let e = by_path(&entries, p);
        assert_eq!(e.size, Some(data.len() as u64), "{p}");
        assert_eq!(read_entry(&mut *opened.reader, e.id).unwrap(), data, "{p}");
    }
    assert!(paths.contains(&"[5]SummaryInformation"), "{paths:?}");
    let info = opened.reader.info(&mut cx).unwrap();
    assert_eq!(info.external.unwrap().levels, ["mst"]);

    // The test reads every stream, and says a compound file has no checksums.
    let report = ops::test(&path, &beezip_core::Selection::all(), &native(), &mut cx).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(report.note.unwrap().contains("no checksums"));

    // The extracted cabinet opens as one.
    let out = tempfile::tempdir().unwrap();
    ops::extract(
        &path,
        out.path(),
        &beezip_core::Selection::all(),
        &native(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    let mut cab_r = open(&out.path().join("PCW_CAB_X.cab"), &native(), &mut cx)
        .unwrap()
        .reader;
    let inside: Vec<String> = cab_r
        .entries(&mut cx)
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(inside, ["payload.txt"]);
}

/// A patch's Info comes from its MsiPatchMetadata table and summary; another kind of compound
/// file that reaches the reader by its name is listed the same way, with its CLSID.
#[test]
fn patches_and_other_compound_files_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.msp");
    let mut pkg = Package::create(PackageType::Patch, new_file(&path)).unwrap();
    pkg.create_table(
        "MsiPatchMetadata",
        vec![
            Column::build("Company")
                .primary_key()
                .nullable()
                .id_string(72),
            Column::build("Property").primary_key().id_string(72),
            Column::build("Value").text_string(0),
        ],
    )
    .unwrap();
    pkg.insert_rows(
        Insert::into("MsiPatchMetadata")
            .row(vec![Value::Null, s("DisplayName"), s("BeeZip test patch")])
            .row(vec![Value::Null, s("Classification"), s("Update")])
            .row(vec![Value::Null, s("AllowRemoval"), s("1")]),
    )
    .unwrap();
    drop(pkg);
    add_to_compound(
        &path,
        &[],
        &[(&stream_path("PCW_CAB_A", false), &small_cab())],
    );
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &native(), &mut cx).unwrap();
    let x = opened.reader.info(&mut cx).unwrap().external.unwrap();
    assert_eq!(x.levels, ["msp"]);
    let props: Vec<(&str, &str)> = x
        .properties
        .iter()
        .map(|p| (p.name.as_str(), p.value.as_str()))
        .collect();
    assert!(
        props.contains(&("DisplayName", "BeeZip test patch")),
        "{props:?}"
    );
    assert!(props.contains(&("Classification", "Update")), "{props:?}");
    assert!(
        !props.iter().any(|(n, _)| *n == "AllowRemoval"),
        "{props:?}"
    );
    let entries = opened.reader.entries(&mut cx).unwrap();
    assert!(entries.iter().any(|e| e.path == "PCW_CAB_A.cab"));
    assert!(entries.iter().any(|e| e.path == "!MsiPatchMetadata"));

    // A Word document's CLSID: listed as its storages and streams, saying what it is.
    let doc = dir.path().join("doc.msi");
    let mut comp = cfb::create(&doc).unwrap();
    let word = uuid::Uuid::parse_str("00020906-0000-0000-c000-000000000046").unwrap();
    comp.set_storage_clsid("/", word).unwrap();
    comp.create_stream("/WordDocument")
        .unwrap()
        .write_all(b"text")
        .unwrap();
    comp.flush().unwrap();
    drop(comp);
    let source = Source::new(&doc, Vec::new(), &native()).unwrap();
    let mut r = beezip_core::format::msi::open(source, &mut cx).unwrap();
    let x = r.info(&mut cx).unwrap().external.unwrap();
    assert_eq!(x.levels, ["compound"]);
    assert_eq!(x.properties[0].name, "CLSID");
    assert_eq!(
        x.properties[0].value,
        "{00020906-0000-0000-c000-000000000046}"
    );
    let entries = r.entries(&mut cx).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "WordDocument");
}

/// The msi crate's empty patch, transform and merge module open, as their kinds.
#[test]
fn empty_patches_transforms_and_merge_modules_open() {
    let dir = tempfile::tempdir().unwrap();
    for (name, t, level) in [
        ("patch.msp", PackageType::Patch, "msp"),
        ("transform.mst", PackageType::Transform, "mst"),
        ("module.msm", PackageType::Installer, "msm"),
    ] {
        let p = dir.path().join(name);
        let mut pkg = Package::create(t, new_file(&p)).unwrap();
        if level == "msm" {
            pkg.create_table(
                "ModuleSignature",
                vec![
                    Column::build("ModuleID").primary_key().id_string(72),
                    Column::build("Language").primary_key().int16(),
                    Column::build("Version").string(32),
                ],
            )
            .unwrap();
        }
        drop(pkg);
        let source = Source::new(&p, Vec::new(), &native()).unwrap();
        let mut cx = SimpleCtx::new();
        let mut r = beezip_core::format::msi::open(source, &mut cx).unwrap();
        let x = r.info(&mut cx).unwrap().external.unwrap();
        assert_eq!(x.levels[0], level, "{name}");
        let report = r.test(&mut cx);
        if let Some(report) = report {
            assert!(report.unwrap().errors.is_empty(), "{name}");
        }
    }
}

// --- An embedded cabinet set ------------------------------------------------------------------

/// `thirdparty/msi/span-small.msi`: an MSI whose cabinet folder runs on from one embedded
/// cabinet into the next (docs/M8.md §7). makecab split `one.txt`, `two.bin` and `three.txt`
/// (LZX:15, `MaxDiskSize=20480`) across `a.cab` and `b.cab`, and the CAB spike's `mkmsi`
/// (`target/m8-spikes/cab/src/bin/mkmsi.rs`, on the msi crate) embedded both, with Media rows
/// `1:#a.cab` and `3:#b.cab` and MsiFileHash rows. Windows Installer's database API reads it,
/// and `7z t` passes it, though 7-Zip lists only its streams. BeeZip 0.2.0 failed two of its
/// files: "the file continues in b.cab, which is missing".
#[test]
fn an_embedded_cabinet_set_reads_whole() {
    let path = fixtures().join("thirdparty/msi/span-small.msi");
    let want = [
        (
            "one.txt",
            "37eb6cf711e31036e0aff78f202a5c2c7c042f38096c74e5070caa06230c639b",
        ),
        (
            "two.bin",
            "5eb9962cbe2cf0da534e868d671afc6acf63b4728e8d78e26c6b5815b42e8bf2",
        ),
        (
            "three.txt",
            "c748558a528106262b39b135741607db1c8f172a17f510c7d1bffa28dd288f28",
        ),
    ];
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &native(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap().to_vec();
    assert!(cx.warnings.is_empty(), "{:?}", cx.warnings);
    for (name, hash) in want {
        let e = by_path(&entries, &format!("ProgramFilesFolder/BeeZip Span/{name}"));
        assert_eq!(
            sha256(&read_entry(&mut *opened.reader, e.id).unwrap()),
            hash,
            "{name}"
        );
    }

    let report = ops::test(
        &path,
        &beezip_core::Selection::all(),
        &native(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);

    let dest = tempfile::tempdir().unwrap();
    ops::extract(
        &path,
        dest.path(),
        &beezip_core::Selection::all(),
        &native(),
        FsOptions::default(),
        &mut SimpleCtx::new(),
    )
    .unwrap();
    for (name, hash) in want {
        let got = fs::read(
            dest.path()
                .join("ProgramFilesFolder/BeeZip Span")
                .join(name),
        )
        .unwrap();
        assert_eq!(sha256(&got), hash, "{name}");
    }
}

// --- The malicious corpus ---------------------------------------------------------------------

/// A package whose folders nest `depth` deep, each named `name` (one string), with a file in
/// the deepest and one halfway, in an embedded cabinet: the spike's `deep.msi`.
fn deep(out: &Path, depth: usize, name: &str) {
    let mut pkg = Package::create(PackageType::Installer, new_file(out)).unwrap();
    pkg.set_database_codepage(CodePage::Utf8);
    pkg.summary_info_mut().set_word_count(2);
    create_tables(&mut pkg);
    let mut q = Insert::into("Directory").row(vec![s("TARGETDIR"), Value::Null, s("SourceDir")]);
    for i in 1..=depth {
        let parent = if i == 1 {
            "TARGETDIR".to_owned()
        } else {
            format!("D{}", i - 1)
        };
        q = q.row(vec![
            Value::from(format!("D{i}")),
            Value::from(parent),
            s(name),
        ]);
    }
    pkg.insert_rows(q).unwrap();
    let half = format!("D{}", depth / 2);
    let last = format!("D{depth}");
    let files: [(&str, &str, &[u8]); 2] = [
        ("f_half", half.as_str(), b"halfway down\n"),
        ("f_deep", last.as_str(), b"at the bottom\n"),
    ];
    let (mut comps, mut rows) = (Insert::into("Component"), Insert::into("File"));
    for (i, (key, d, data)) in files.iter().enumerate() {
        comps = comps.row(vec![
            s(key),
            Value::Null,
            s(d),
            n(0),
            Value::Null,
            Value::Null,
        ]);
        rows = rows.row(vec![
            s(key),
            s(key),
            s(&format!("{key}.txt")),
            n(data.len() as i32),
            Value::Null,
            Value::Null,
            n(0),
            n(i as i32 + 1),
        ]);
    }
    pkg.insert_rows(comps).unwrap();
    pkg.insert_rows(rows).unwrap();
    pkg.insert_rows(Insert::into("Media").row(vec![
        n(1),
        n(2),
        Value::Null,
        s("#deep.cab"),
        Value::Null,
        Value::Null,
    ]))
    .unwrap();
    let work = tempfile::tempdir().unwrap();
    let c = work.path().join("deep.cab");
    let data: Vec<(&str, &[u8])> = files.iter().map(|(k, _, d)| (*k, *d)).collect();
    cab(&c, &data, CabMethod::Mszip);
    pkg.write_stream("deep.cab")
        .unwrap()
        .write_all(&fs::read(&c).unwrap())
        .unwrap();
    drop(pkg);
}

/// A small, sound package to damage.
fn small(out: &Path) {
    let mut pkg = Package::create(PackageType::Installer, new_file(out)).unwrap();
    pkg.summary_info_mut().set_word_count(2);
    create_tables(&mut pkg);
    pkg.insert_rows(
        Insert::into("Directory")
            .row(vec![s("TARGETDIR"), Value::Null, s("SourceDir")])
            .row(vec![s("APP"), s("TARGETDIR"), s("App")]),
    )
    .unwrap();
    pkg.insert_rows(Insert::into("Component").row(vec![
        s("C"),
        Value::Null,
        s("APP"),
        n(0),
        Value::Null,
        Value::Null,
    ]))
    .unwrap();
    pkg.insert_rows(Insert::into("File").row(vec![
        s("f"),
        s("C"),
        s("a.txt"),
        n(2),
        Value::Null,
        Value::Null,
        n(0),
        n(1),
    ]))
    .unwrap();
    pkg.insert_rows(Insert::into("Media").row(vec![
        n(1),
        n(1),
        Value::Null,
        s("#a.cab"),
        Value::Null,
        Value::Null,
    ]))
    .unwrap();
    let work = tempfile::tempdir().unwrap();
    let c = work.path().join("a.cab");
    cab(&c, &[("f", b"hi")], CabMethod::Mszip);
    pkg.write_stream("a.cab")
        .unwrap()
        .write_all(&fs::read(&c).unwrap())
        .unwrap();
    drop(pkg);
}

/// The compound file's directory entry for `name` (a raw, packed name): where its stream size
/// is, so a claim can be written there without the sectors behind it.
fn dir_entry_size_at(bytes: &[u8], name: &str) -> usize {
    let le32 = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let shift = u16::from_le_bytes([bytes[0x1E], bytes[0x1F]]);
    let sector = 1usize << shift;
    let fat: Vec<u32> = (0..109)
        .map(|i| le32(0x4C + i * 4))
        .filter(|&s| s < 0xFFFF_FFFA)
        .flat_map(|s| {
            let at = (s as usize + 1) * sector;
            (0..sector / 4).map(move |i| (at, i))
        })
        .map(|(at, i)| le32(at + i * 4))
        .collect();
    let want: Vec<u16> = name.encode_utf16().collect();
    let mut s = le32(0x30);
    while s < 0xFFFF_FFFA {
        let at = (s as usize + 1) * sector;
        for e in 0..sector / 128 {
            let entry = at + e * 128;
            let len = usize::from(u16::from_le_bytes([
                bytes[entry + 0x40],
                bytes[entry + 0x41],
            ]));
            let units: Vec<u16> = (0..len.saturating_sub(2) / 2)
                .map(|i| u16::from_le_bytes([bytes[entry + i * 2], bytes[entry + i * 2 + 1]]))
                .collect();
            if units == want {
                return entry + 0x78;
            }
        }
        s = fat[s as usize];
    }
    panic!("no directory entry {name:?}");
}

/// Writes the malicious MSIs into `tests/fixtures/malicious/` (run by hand, then commit them):
/// `cargo test --test msi -- --ignored write_the_malicious_msis`.
#[test]
#[ignore = "writes the committed corpus"]
fn write_the_malicious_msis() {
    let out = fixtures().join("malicious");
    // 3,000 folders deep, each named with 2,000 characters.
    deep(&out.join("deep.msi"), 3000, &"n".repeat(2000));

    // A string pool whose last string claims 4 GiB.
    let p = out.join("pool-4gib.msi");
    small(&p);
    patch_stream(&p, "_StringPool", true, |pool| {
        pool.extend_from_slice(&[0, 0, 1, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
    });

    // A catalog with null cells and column numbers out of order and out of range.
    let p = out.join("catalog-nulls.msi");
    small(&p);
    patch_stream(&p, "_Columns", true, |cols| {
        // Four columns of 2-byte cells: the Table, Number, Name and Type of each row.
        let rows = cols.len() / 8;
        for r in (0..rows).step_by(3) {
            cols[r * 2..r * 2 + 2].fill(0); // the Table, null
        }
        for r in (1..rows).step_by(4) {
            let at = rows * 2 + r * 2;
            cols[at..at + 2].copy_from_slice(&(0x7FFF_u16 ^ 0x8000).to_le_bytes());
        }
        for r in (2..rows).step_by(5) {
            let at = rows * 6 + r * 2;
            cols[at..at + 2].fill(0); // the Type, null
        }
    });

    // A table's stream whose directory entry claims 4 GiB.
    let p = out.join("stream-4gib.msi");
    small(&p);
    let mut bytes = fs::read(&p).unwrap();
    let packed = stream_path("File", true);
    let at = dir_entry_size_at(&bytes, packed.trim_start_matches('/'));
    bytes[at..at + 8].copy_from_slice(&0xFFFF_FFF0_u64.to_le_bytes());
    fs::write(&p, &bytes).unwrap();

    // Summary information with a string claiming 2 GiB before the word count.
    let p = out.join("summary-2gib.msi");
    small(&p);
    let mut comp = cfb::open_rw(&p).unwrap();
    let mut s = Vec::new();
    s.extend_from_slice(&[0xFE, 0xFF, 0, 0, 2, 0, 0, 0]);
    s.extend_from_slice(&[0; 16]);
    s.extend_from_slice(&1u32.to_le_bytes());
    s.extend_from_slice(&[0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10]);
    s.extend_from_slice(&[0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9]);
    s.extend_from_slice(&48u32.to_le_bytes());
    // The section: its size, two properties, the title (VT_LPSTR, 2 GiB) and the word count.
    let section = [
        64u32,
        2,
        2,
        24,
        15,
        40,
        30,
        0x7FFF_FFF0,
        0x4141_4141,
        0,
        3,
        2,
        0,
        0,
        0,
        0,
    ];
    for v in section {
        s.extend_from_slice(&v.to_le_bytes());
    }
    let mut st = comp.create_stream("/\u{5}SummaryInformation").unwrap();
    st.write_all(&s).unwrap();
    drop(st);
    comp.flush().unwrap();
    drop(comp);

    // docs/M11.md §8: patches, transforms and merge modules.
    // A patch with names unsafe on disk: a packed `..` storage holding a file, a control
    // character, `CON`.
    let p = out.join("msp-names.msp");
    drop(Package::create(PackageType::Patch, new_file(&p)).unwrap());
    let dotdot = stream_path("..", false);
    add_to_compound(
        &p,
        &[&dotdot],
        &[
            (&format!("{dotdot}/escaped.txt"), &b"out of reach\n"[..]),
            ("/\u{2}ctl", b"a control character\n"),
            ("/CON", b"a device's name\n"),
        ],
    );

    // A patch with `/`, `\` and `:` in names, which MS-CFB forbids: written as other
    // characters, then renamed in the directory.
    let p = out.join("msp-slash.msp");
    drop(Package::create(PackageType::Patch, new_file(&p)).unwrap());
    add_to_compound(
        &p,
        &[],
        &[
            ("/aXb", b"slash"),
            ("/cYd", b"backslash"),
            ("/eZf", b"colon"),
        ],
    );
    let mut bytes = fs::read(&p).unwrap();
    for (from, to) in [("aXb", "a/b"), ("cYd", "c\\d"), ("eZf", "e:f")] {
        let entry = dir_entry_size_at(&bytes, from) - 0x78;
        for (i, u) in to.encode_utf16().enumerate() {
            bytes[entry + i * 2..entry + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    fs::write(&p, &bytes).unwrap();

    // A transform 300 storages deep, with a stream at the bottom.
    let p = out.join("mst-deep.mst");
    drop(Package::create(PackageType::Transform, new_file(&p)).unwrap());
    let mut comp = cfb::open_rw(&p).unwrap();
    let mut at = String::new();
    for _ in 0..300 {
        at.push_str("/d");
        comp.create_storage(&at).unwrap();
    }
    comp.create_stream(format!("{at}/bottom"))
        .unwrap()
        .write_all(b"300 deep\n")
        .unwrap();
    comp.flush().unwrap();
    drop(comp);

    // A transform of 2,000 streams.
    let p = out.join("mst-many.mst");
    drop(Package::create(PackageType::Transform, new_file(&p)).unwrap());
    let mut comp = cfb::open_rw(&p).unwrap();
    for i in 0..2000 {
        comp.create_stream(format!("/s{i}"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
    }
    comp.flush().unwrap();
    drop(comp);

    // A transform with a stream whose directory entry claims 4 GiB.
    let p = out.join("mst-claim.mst");
    drop(Package::create(PackageType::Transform, new_file(&p)).unwrap());
    add_to_compound(
        &p,
        &[],
        &[("/claim", b"claims 4 GiB"), ("/fine", b"reads\n")],
    );
    let mut bytes = fs::read(&p).unwrap();
    let at = dir_entry_size_at(&bytes, "claim");
    bytes[at..at + 8].copy_from_slice(&0xFFFF_FFF0_u64.to_le_bytes());
    fs::write(&p, &bytes).unwrap();

    // Merge modules without their cabinet, and with a stream of its name that isn't one.
    build_module(&out.join("msm-no-cab.msm"), ModuleCab::Missing);
    build_module(&out.join("msm-not-cab.msm"), ModuleCab::NotACabinet);

    for name in [
        "deep.msi",
        "pool-4gib.msi",
        "catalog-nulls.msi",
        "stream-4gib.msi",
        "summary-2gib.msi",
        "msp-names.msp",
        "msp-slash.msp",
        "mst-deep.mst",
        "mst-many.mst",
        "mst-claim.mst",
        "msm-no-cab.msm",
        "msm-not-cab.msm",
    ] {
        let len = fs::metadata(out.join(name)).unwrap().len();
        println!("{name}: {len} bytes");
    }
}

// --- Real installers, against 7-Zip -----------------------------------------------------------

/// Hashes every file it's given, by path.
#[derive(Default)]
struct Hashes(HashMap<String, (u64, String)>);

impl beezip_core::EntrySink for Hashes {
    fn entry(
        &mut self,
        e: &Entry,
        data: &mut dyn Read,
        cx: &mut dyn beezip_core::Ctx,
    ) -> beezip_core::Result<()> {
        if e.is_dir() {
            return Ok(());
        }
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut size = 0u64;
        loop {
            cx.check()?;
            let k = data
                .read(&mut buf)
                .map_err(|e| beezip_core::io::read_error(&e))?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            size += k as u64;
        }
        let hex = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        self.0.insert(e.path.clone(), (size, hex));
        Ok(())
    }
}

/// Every installer in `BEEZIP_MSI_SAMPLES`, read natively and through 7-Zip: each file 7-Zip
/// lists by its File key comes out of BeeZip's reader with the same bytes, under the name the
/// File table gives it, and no file more or less.
#[test]
#[ignore = "reads the large installers named by BEEZIP_MSI_SAMPLES"]
fn real_installers_read_as_7zip_reads_them() {
    let Some(dir) = std::env::var_os("BEEZIP_MSI_SAMPLES") else {
        eprintln!("skipping: BEEZIP_MSI_SAMPLES isn't set");
        return;
    };
    let mut samples: Vec<PathBuf> = std::env::split_paths(&dir)
        .flat_map(|d| fs::read_dir(d).unwrap())
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")))
        .collect();
    samples.sort();
    for msi_path in samples {
        let t = std::time::Instant::now();
        let mut cx = SimpleCtx::new();
        let mut native_r = open(&msi_path, &native(), &mut cx).unwrap().reader;
        let listed = native_r.entries(&mut cx).unwrap().len();
        let list_time = t.elapsed();
        let mut ours = Hashes::default();
        native_r
            .extract(&beezip_core::Selection::all(), &mut ours, &mut cx)
            .unwrap();
        let native_time = t.elapsed();

        let t = std::time::Instant::now();
        let via = OpenOptions {
            native: false,
            ..OpenOptions::default()
        };
        let mut theirs = Hashes::default();
        let mut sz = open(&msi_path, &via, &mut SimpleCtx::new()).unwrap().reader;
        sz.extract(
            &beezip_core::Selection::all(),
            &mut theirs,
            &mut SimpleCtx::new(),
        )
        .unwrap();
        let sz_time = t.elapsed();

        // The File table, by key: its long name.
        let mut pkg = msi::open(&msi_path).unwrap();
        let rows = pkg.select_rows(msi::Select::table("File")).unwrap();
        let mut names: HashMap<String, String> = HashMap::new();
        for row in rows {
            let key = row["File"].as_str().unwrap().to_owned();
            let name = row["FileName"].as_str().unwrap_or_default();
            let long = name.split_once('|').map_or(name, |(_, l)| l).to_owned();
            names.insert(key, long);
        }
        // Ours, by the leaf of each path.
        let mut by_leaf: HashMap<&str, Vec<&(u64, String)>> = HashMap::new();
        for (p, h) in &ours.0 {
            if !p.starts_with("[Binary]/") && !p.starts_with("[Icon]/") {
                by_leaf
                    .entry(p.rsplit('/').next().unwrap())
                    .or_default()
                    .push(h);
            }
        }
        let files = by_leaf.values().map(Vec::len).sum::<usize>();
        let mut compared = 0;
        for (key, h) in &theirs.0 {
            let Some(name) = names.get(key) else {
                continue; // a stream 7-Zip lists that isn't a file
            };
            let leaf = if name.is_empty() {
                key.as_str()
            } else {
                name.as_str()
            };
            let keyed = match leaf.rfind('.') {
                Some(i) if i > 0 => format!("{}.{key}{}", &leaf[..i], &leaf[i..]),
                _ => format!("{leaf}.{key}"),
            };
            let found = [leaf, keyed.as_str()]
                .iter()
                .filter_map(|l| by_leaf.get(l))
                .flatten()
                .any(|ours| *ours == h);
            assert!(
                found,
                "{}: `{key}` ({leaf}) isn't in BeeZip's listing with its bytes",
                msi_path.display()
            );
            compared += 1;
        }
        assert_eq!(compared, files, "{}: files compared", msi_path.display());
        println!(
            "{}: {listed} entries, {files} files the same as 7-Zip's; listed in {list_time:?}, \
             read in {native_time:?} (7-Zip {sz_time:?}); warnings {:?}",
            msi_path.display(),
            cx.warnings
        );
    }
}

/// 7-Zip's name for a path on Windows: what it writes in place of what a name can't hold.
fn seven_zip_on_disk(path: &str) -> String {
    if !cfg!(windows) {
        return path.to_owned();
    }
    path.chars()
        .map(|c| {
            if "<>:\"|?*".contains(c) || (c as u32) < 32 {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Every file under `dir`, by its path (`/`-separated), with its size and SHA-256.
fn hashed_tree(dir: &Path) -> HashMap<String, (u64, String)> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .map(Result::unwrap)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let data = fs::read(e.path()).unwrap();
            let rel = e.path().strip_prefix(dir).unwrap();
            (
                rel.to_string_lossy().replace('\\', "/"),
                (data.len() as u64, sha256(&data)),
            )
        })
        .collect()
}

/// Runs `7z x` on `file` into `out`.
fn seven_zip_x(seven: &Path, file: &Path, out: &Path) {
    let status = std::process::Command::new(seven)
        .args(["x", "-y", "-bso0", "-bsp0"])
        .arg(format!("-o{}", out.display()))
        .arg(file)
        .status()
        .unwrap();
    assert!(status.success(), "7z x {}", file.display());
}

/// Every patch, transform and merge module under the folders `BEEZIP_MSI_SAMPLES` names
/// (separated as PATH is, searched to any depth), against 7-Zip's extraction (docs/M11.md §8):
/// each stream of a patch or transform has 7-Zip's bytes under 7-Zip's name (`.cab` added to a
/// cabinet's); a merge module's files are those 7-Zip extracts from its `MergeModule.CABinet`,
/// compared by their bytes since 7-Zip names them by their keys. The spike's samples, which
/// can't be redistributed, stay in `target/m11-spikes/`:
/// `cargo test --release --test msi -- --ignored real_patches`.
#[test]
#[ignore = "reads the samples named by BEEZIP_MSI_SAMPLES"]
fn real_patches_transforms_and_modules_read_as_7zip_extracts_them() {
    let Some(folders) = std::env::var_os("BEEZIP_MSI_SAMPLES") else {
        eprintln!("skipping: BEEZIP_MSI_SAMPLES isn't set");
        return;
    };
    let seven = beezip_core::backend::find(&SevenZipOptions::default())
        .expect("BEEZIP_MSI_SAMPLES needs 7-Zip");
    let mut samples: Vec<PathBuf> = std::env::split_paths(&folders)
        .flat_map(walkdir::WalkDir::new)
        .map(Result::unwrap)
        .map(walkdir::DirEntry::into_path)
        .filter(|p| {
            p.extension().is_some_and(|e| {
                ["msp", "mst", "msm"]
                    .iter()
                    .any(|x| e.eq_ignore_ascii_case(x))
            })
        })
        .collect();
    samples.sort();
    let (mut streams, mut module_files) = (0usize, 0usize);
    for path in &samples {
        let mut cx = SimpleCtx::new();
        let mut r = open(path, &native(), &mut cx)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .reader;
        let levels = r.info(&mut cx).unwrap().external.unwrap().levels;
        let mut ours = Hashes::default();
        r.extract(&beezip_core::Selection::all(), &mut ours, &mut cx)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let out = tempfile::tempdir().unwrap();
        seven_zip_x(&seven.exe, path, out.path());
        let theirs = hashed_tree(out.path());
        if levels[0] == "msm" {
            // The module's cabinet, as 7-Zip extracts it (an empty module has none).
            let cab = out.path().join("MergeModule.CABinet");
            let cab_out = tempfile::tempdir().unwrap();
            if cab.exists() {
                seven_zip_x(&seven.exe, &cab, cab_out.path());
            }
            let in_cab = hashed_tree(cab_out.path());
            let mut want: Vec<&(u64, String)> = in_cab.values().collect();
            let mut got: Vec<&(u64, String)> = ours
                .0
                .iter()
                .filter(|(p, _)| !p.starts_with("[Binary]/") && !p.starts_with("[Icon]/"))
                .map(|(_, h)| h)
                .collect();
            want.sort();
            got.sort();
            assert_eq!(got, want, "{}: the module's files", path.display());
            module_files += got.len();
        } else {
            let mut ours_by_name: HashMap<String, &(u64, String)> = HashMap::new();
            for (p, h) in &ours.0 {
                ours_by_name.insert(seven_zip_on_disk(p), h);
            }
            for (p, h) in &theirs {
                let got = ours_by_name
                    .get(p)
                    .or_else(|| ours_by_name.get(&format!("{p}.cab")));
                assert_eq!(got, Some(&h), "{}: `{p}`", path.display());
            }
            assert_eq!(ours.0.len(), theirs.len(), "{}: streams", path.display());
            streams += theirs.len();
        }
    }
    println!(
        "{} files: {streams} streams of patches and transforms and {module_files} files of \
         merge modules as 7-Zip extracts them",
        samples.len()
    );
}

/// `deep.msi` keeps to its caps: each path within 4,096 bytes, the deep folders under their
/// keys. (The malicious corpus checks it extracts safely and fast.)
#[test]
fn deep_folders_are_listed_under_their_keys() {
    let path = fixtures().join("malicious/deep.msi");
    let mut cx = SimpleCtx::new();
    let mut opened = open(&path, &native(), &mut cx).unwrap();
    let entries = opened.reader.entries(&mut cx).unwrap();
    let files: Vec<&str> = entries
        .iter()
        .filter(|e| !e.is_dir())
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(files, ["D1500/f_half.txt", "D3000/f_deep.txt"]);
    assert!(entries.iter().all(|e| e.path.len() <= 4096));
    assert!(
        cx.warnings.iter().any(|w| w.contains("Directory keys")),
        "{:?}",
        cx.warnings
    );
}
