#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use proptest::prelude::*;

use crate::{
    Entry, Item, JobRequest, REQUEST_VERSION, Selected, Settings, TITLE_MAX, add_name,
    archive_stem, file_name, is_archive, menu, title, volume_key,
};

fn items(entries: &[Entry]) -> Vec<&'static str> {
    entries.iter().map(|e| e.item.id()).collect()
}

fn titles(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.title.as_str()).collect()
}

const ADD: [&str; 4] = ["add-zip", "add-7z", "add-tar-zst", "compress-to"];
const ALL: [&str; 9] = [
    "open",
    "extract-here",
    "extract-folder",
    "extract-to",
    "test",
    "add-zip",
    "add-7z",
    "add-tar-zst",
    "compress-to",
];

#[test]
fn one_archive_gets_everything() {
    let m = menu(
        &[Selected::file(r"C:\Users\me\Downloads\photos.tar.zst")],
        &Settings::default(),
    );
    assert_eq!(items(&m), ALL);
    assert_eq!(
        titles(&m),
        [
            "Open with BeeZip",
            "Extract here",
            r#"Extract to "photos\""#,
            "Extract to…",
            "Test archive",
            r#"Add to "photos.zip""#,
            r#"Add to "photos.7z""#,
            r#"Add to "photos.tar.zst""#,
            "Compress to…",
        ]
    );
    let separators: Vec<bool> = m.iter().map(|e| e.separator_before).collect();
    assert_eq!(
        separators,
        [false, false, false, false, false, true, false, false, false]
    );
}

#[test]
fn several_archives_get_each_and_no_dialog() {
    let m = menu(
        &[Selected::file(r"C:\x\a.zip"), Selected::file(r"C:\x\b.7z")],
        &Settings::default(),
    );
    assert_eq!(
        items(&m),
        [
            "open",
            "extract-here",
            "extract-folder",
            "test",
            "add-zip",
            "add-7z",
            "add-tar-zst",
            "compress-to"
        ]
    );
    assert_eq!(m[2].title, "Extract each to its own folder");
    assert_eq!(m[3].title, "Test archives");
    assert_eq!(m[4].title, r#"Add to "x.zip""#);
}

#[test]
fn a_volume_set_counts_once() {
    for set in [
        [r"C:\x\a.7z.001", r"C:\x\a.7z.002"],
        [r"C:\x\a.part1.rar", r"C:\x\a.part2.rar"],
        [r"C:\x\a.rar", r"C:\x\a.r00"],
    ] {
        let sel: Vec<Selected> = set.iter().map(|p| Selected::file(*p)).collect();
        let m = menu(&sel, &Settings::default());
        assert!(items(&m).contains(&"extract-to"), "{set:?}: {m:?}");
        assert_eq!(m[2].title, r#"Extract to "a\""#, "{set:?}");
        assert_eq!(m[4].title, "Test archive", "{set:?}");
    }
    // The same name in two folders is two archives (search results span folders).
    let m = menu(
        &[Selected::file(r"C:\x\a.zip"), Selected::file(r"C:\y\a.zip")],
        &Settings::default(),
    );
    assert!(!items(&m).contains(&"extract-to"));
}

#[test]
fn files_and_folders_get_the_add_items() {
    let one_file = menu(&[Selected::file(r"C:\x\notes.txt")], &Settings::default());
    assert_eq!(items(&one_file), ADD);
    assert_eq!(one_file[0].title, r#"Add to "notes.zip""#);
    assert!(!one_file[0].separator_before, "no archive items above it");

    let folder = menu(&[Selected::folder(r"C:\x\my.photos")], &Settings::default());
    assert_eq!(items(&folder), ADD);
    assert_eq!(folder[0].title, r#"Add to "my.photos.zip""#);

    // A folder named like an archive is still a folder.
    let named = menu(&[Selected::folder(r"C:\x\old.zip")], &Settings::default());
    assert_eq!(items(&named), ADD);

    // Mixed: an archive and a file.
    let mixed = menu(
        &[
            Selected::file(r"C:\work\a.zip"),
            Selected::file(r"C:\work\b.txt"),
        ],
        &Settings::default(),
    );
    assert_eq!(items(&mixed), ADD);
    assert_eq!(mixed[0].title, r#"Add to "work.zip""#);
}

#[test]
fn hidden_items_go_and_the_separator_follows() {
    let settings = Settings {
        hidden: vec![Item::Test, Item::AddZip, Item::Open],
    };
    let m = menu(&[Selected::file(r"C:\x\a.zip")], &settings);
    assert_eq!(
        items(&m),
        [
            "extract-here",
            "extract-folder",
            "extract-to",
            "add-7z",
            "add-tar-zst",
            "compress-to"
        ]
    );
    assert!(m[3].separator_before);

    let only_adds = Settings {
        hidden: Item::ALL.into_iter().filter(|i| i.for_archives()).collect(),
    };
    let m = menu(&[Selected::file(r"C:\x\a.zip")], &only_adds);
    assert_eq!(items(&m), ADD);
    assert!(m.iter().all(|e| !e.separator_before));

    let none = Settings {
        hidden: Item::ALL.to_vec(),
    };
    assert!(menu(&[Selected::file(r"C:\x\a.zip")], &none).is_empty());
}

#[test]
fn nothing_without_a_file_system_path() {
    assert!(menu(&[], &Settings::default()).is_empty());
    let phone = Selected {
        path: None,
        folder: false,
    };
    assert!(menu(std::slice::from_ref(&phone), &Settings::default()).is_empty());
    assert!(
        menu(
            &[Selected::file(r"C:\x\a.zip"), phone],
            &Settings::default()
        )
        .is_empty()
    );
}

#[test]
fn archives_by_name() {
    for yes in [
        "a.zip",
        "A.ZIP",
        "a.tar.zst",
        "a.tgz",
        "notes.txt.gz",
        "a.7z",
        "a.7z.001",
        "a.7z.002",
        "big.iso.001",
        "a.part1.rar",
        "a.part12.rar",
        "a.r00",
        "a.r57",
        "a.jar",
        "report.docx",
        "a.epub",
        "a.cbz",
        "a.lz4",
        // M5: the new formats and codecs, `.cab` included (Windows keeps the association; the
        // menu still offers BeeZip's items).
        "a.cab",
        "a.rpm",
        "python3-six_1.17.0-1_all.deb",
        "a.udeb",
        "initrd.cpio.gz",
        "a.ar",
        "a.lzh",
        "A.LHA",
        "a.tar.Z",
        "a.taz",
        "a.tzo",
        "notes.txt.lzo",
    ] {
        assert!(is_archive(yes), "{yes}");
    }
    for no in [
        "notes.txt",
        "zip",
        ".zip",
        "a.000",
        "a.01",
        "a.exe",
        "a.zipx",
        "README",
        // Build files ar reads by content, but BeeZip doesn't claim.
        "libfoo.a",
        "kernel32.lib",
        "",
    ] {
        assert!(!is_archive(no), "{no}");
    }
}

#[test]
fn stems() {
    for (name, stem) in [
        ("a.tar.zst", "a"),
        ("b.zip", "b"),
        ("c.tgz", "c"),
        ("C.TGZ", "C"),
        ("notes.txt.gz", "notes.txt"),
        ("d.e.zip", "d.e"),
        (".zip", ".zip"),
        ("e.tar.zst.002", "e"),
        // A split ISO is an image's set; a split file of anything else keeps its name.
        ("big.iso.001", "big"),
        ("big.img.001", "big.img"),
        ("a.7z.001", "a"),
        ("a.part1.rar", "a"),
        ("a.part01.rar", "a"),
        ("a.r00", "a"),
        ("a.r57", "a"),
        ("a.rar", "a"),
        ("photos.cb7", "photos"),
        ("initrd.cpio.gz", "initrd"),
        ("a.tar.Z", "a"),
        ("a.taz", "a"),
        ("pkg.deb", "pkg"),
        ("drivers.cab", "drivers"),
        ("x.tar.gz.zip", "x"),
        ("", "archive"),
    ] {
        assert_eq!(archive_stem(name), stem, "{name}");
    }
}

#[test]
fn names_and_keys() {
    assert_eq!(file_name(r"C:\a\b.zip"), "b.zip");
    assert_eq!(file_name("/srv/a/b.zip"), "b.zip");
    assert_eq!(file_name(r"C:\a\folder\"), "folder");
    assert_eq!(file_name(r"C:\"), "");
    assert_eq!(file_name("b.zip"), "b.zip");
    assert_eq!(file_name(r"\\server\share\a.7z"), "a.7z");
    assert_eq!(volume_key(r"C:\X\A.7z.001"), volume_key(r"c:\x\a.7z.002"));
    assert_eq!(volume_key(r"C:\x\a.rar"), volume_key(r"C:\x\a.r00"));
    assert_ne!(volume_key(r"C:\x\a.zip"), volume_key(r"C:\y\a.zip"));
    assert_eq!(add_name(&[Selected::folder(r"C:\")]), "archive");
    assert_eq!(
        add_name(&[Selected::file(r"C:\a.txt"), Selected::file(r"C:\b.txt")]),
        "archive",
        "the root of a drive has no name"
    );
    assert_eq!(add_name(&[Selected::file(r"C:\x\.bashrc")]), ".bashrc");
}

#[test]
fn long_names_are_cut() {
    let long = format!(r"C:\x\{}.zip", "a".repeat(80));
    let m = menu(&[Selected::file(&long)], &Settings::default());
    for e in &m {
        assert!(e.title.chars().count() <= TITLE_MAX, "{:?}", e.title);
    }
    assert_eq!(m[2].title, format!(r#"Extract to "{}…\""#, "a".repeat(25)));
    assert!(m[5].title.ends_with("….zip\""), "{}", m[5].title);
    assert!(m[7].title.ends_with("….tar.zst\""), "{}", m[7].title);
}

#[test]
fn ids_round_trip() {
    for item in Item::ALL {
        assert_eq!(Item::from_id(item.id()), Some(item));
        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(json, format!("\"{}\"", item.id()));
        assert_eq!(serde_json::from_str::<Item>(&json).unwrap(), item);
    }
    assert_eq!(Item::from_id("add7z"), None);
}

#[test]
fn requests_round_trip_and_check_their_version() {
    let req = JobRequest::new(
        Item::ExtractHere,
        vec![
            PathBuf::from(r"C:\Users\me\Downloads\a.zip"),
            PathBuf::from(r"C:\Users\me\Downloads\b.7z"),
        ],
    );
    let json = req.to_json().unwrap();
    assert_eq!(
        json,
        r#"{"version":1,"item":"extract-here","paths":["C:\\Users\\me\\Downloads\\a.zip","C:\\Users\\me\\Downloads\\b.7z"]}"#
    );
    assert_eq!(JobRequest::parse(&json).unwrap(), req);
    assert_eq!(req.version, REQUEST_VERSION);

    let err = JobRequest::parse(r#"{"version":2,"item":"test","paths":[]}"#).unwrap_err();
    assert!(err.contains("version 2"), "{err}");
    let err = JobRequest::parse(r#"{"item":"test","paths":[]}"#).unwrap_err();
    assert!(err.contains("no version"), "{err}");
    let err = JobRequest::parse(r#"{"version":1,"item":"explode","paths":[]}"#).unwrap_err();
    assert!(err.contains("isn't a job request"), "{err}");
    let err = JobRequest::parse(r#"{"version":1,"item":"test","paths":[],"x":1}"#).unwrap_err();
    assert!(err.contains("isn't a job request"), "{err}");
    assert!(JobRequest::parse("[").unwrap_err().contains("isn't JSON"));
}

#[test]
fn a_title_without_a_selection_is_still_a_title() {
    assert_eq!(
        title(Item::ExtractFolder, &[]),
        "Extract each to its own folder"
    );
    assert_eq!(title(Item::AddZip, &[]), r#"Add to "archive.zip""#);
}

fn name() -> impl Strategy<Value = String> {
    let ext = prop_oneof![
        Just(String::new()),
        Just(".zip".to_owned()),
        Just(".tar.zst".to_owned()),
        Just(".7z.001".to_owned()),
        Just(".part3.rar".to_owned()),
        Just(".r01".to_owned()),
        "\\.[a-z0-9]{1,4}",
    ];
    ("\\PC{0,60}", ext).prop_map(|(stem, ext)| format!("{stem}{ext}"))
}

proptest! {
    #[test]
    fn menus_never_panic_and_titles_fit(
        names in prop::collection::vec((name(), any::<bool>(), any::<bool>()), 0..6),
        hidden in prop::collection::vec(0usize..9, 0..4),
    ) {
        let selection: Vec<Selected> = names
            .iter()
            .map(|(n, folder, reachable)| Selected {
                path: reachable.then(|| format!(r"C:\dir\{n}")),
                folder: *folder,
            })
            .collect();
        let settings = Settings { hidden: hidden.iter().map(|i| Item::ALL[*i]).collect() };
        let entries = menu(&selection, &settings);
        for e in &entries {
            prop_assert!(e.title.chars().count() <= TITLE_MAX, "{:?}", e.title);
            prop_assert!(!settings.hidden.contains(&e.item));
        }
        prop_assert!(entries.iter().filter(|e| e.separator_before).count() <= 1);
        for item in Item::ALL {
            prop_assert!(title(item, &selection).chars().count() <= TITLE_MAX);
        }
    }

    #[test]
    fn stems_never_panic_or_grow(n in name()) {
        let stem = archive_stem(&n);
        prop_assert!(!stem.is_empty());
        // `.tgz` becomes `.tar` before going, so a stem is never longer than its name.
        prop_assert!(stem.len() <= n.len().max("archive".len()), "{n:?} -> {stem:?}");
        let _ = is_archive(&n);
        let _ = volume_key(&n);
    }
}
