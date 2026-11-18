//! `.bhive` through the engine, as every front end runs it (docs/M13.md §5): created at its
//! levels by number and by name, listed, described, tested, extracted, edited and converted,
//! and opened from its records when its index is gone.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use beezip_commands::{
    CmdError, Engine, EngineOptions, ErrorCode, NonInteractive, Policy, registry,
};
use serde_json::{Value, json};

fn run(name: &str, args: Value) -> Result<Value, CmdError> {
    Engine::new(registry())
        .invoke(name, args, Arc::new(NonInteractive), Arc::new(|_| {}))
        .unwrap()
        .join()
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/bhive")
        .join(name)
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

/// A folder of a few files: text, a copy of it, and something that doesn't compress.
fn tree(dir: &Path) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("docs")).unwrap();
    let text = "bees make honey in the hive\n".repeat(4000);
    std::fs::write(src.join("a.txt"), &text).unwrap();
    std::fs::write(src.join("docs/copy of a.txt"), &text).unwrap();
    std::fs::write(src.join("docs/b.txt"), "bravo").unwrap();
    let noise: Vec<u8> = (0..50_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    std::fs::write(src.join("noise.bin"), noise).unwrap();
    src
}

fn names(archive: &Path) -> Vec<String> {
    let out = run(
        "archive.list",
        json!({ "archive": s(archive), "flat": true }),
    )
    .unwrap();
    let mut names: Vec<String> = out["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

fn property<'a>(info: &'a Value, name: &str) -> Option<&'a str> {
    info["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"] == name)?["value"]
        .as_str()
}

#[test]
fn create_at_every_level_by_number_and_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let mut sizes = Vec::new();
    for (level, name) in [
        (json!(0), "none"),
        (json!("fast"), "fast"),
        (Value::Null, "balanced"),
        (json!(3), "high"),
        (json!("max"), "max"),
    ] {
        let archive = dir.path().join(format!("{name}.bhive"));
        let mut args = json!({ "output": s(&archive), "inputs": [s(&src)] });
        if !level.is_null() {
            args["level"] = level;
        }
        let out = run("archive.create", args).unwrap();
        assert_eq!(out["format"], "bhive", "{name}");
        assert_eq!(out["files"], 4, "{name}");
        let info = run("archive.info", json!({ "archive": s(&archive) })).unwrap();
        assert_eq!(info["format"], "bhive");
        assert_eq!(property(&info, "Level"), Some(name));
        assert_eq!(property(&info, "Cells"), Some("1"));
        // The copy is stored once from Fast up, and twice in a bundle.
        let once = property(&info, "Stored Once").unwrap();
        assert_eq!(once != "0", name != "none", "{name}: {once}");
        let test = run("archive.test", json!({ "archive": s(&archive) })).unwrap();
        assert_eq!(test["entries"], 6, "{name}");
        sizes.push(out["bytes_out"].as_u64().unwrap());
    }
    // None is the files' size and a little; each level after it is smaller.
    assert!(sizes[0] > 270_000, "{sizes:?}");
    assert!(sizes[1] < 60_000 && sizes[4] <= sizes[1], "{sizes:?}");

    // The format by its name, whatever the output is called.
    let odd = dir.path().join("odd.bin");
    run(
        "archive.create",
        json!({ "output": s(&odd), "inputs": [s(&src)], "format": "bhive" }),
    )
    .unwrap();
    let info = run("archive.info", json!({ "archive": s(&odd) })).unwrap();
    assert_eq!(info["format"], "bhive");
}

#[test]
fn options_that_do_not_fit_are_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = dir.path().join("x.bhive");
    for (extra, says) in [
        (json!({ "level": 5 }), "0 to 4"),
        (json!({ "level": -1 }), "0 to 4"),
        (json!({ "method": "zstd" }), "has levels"),
        (json!({ "password": "pw" }), "isn't encrypted"),
        (json!({ "solid": true }), "is for 7z"),
    ] {
        let mut args = json!({ "output": s(&out), "inputs": [s(&src)] });
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        let e = run("archive.create", args).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs, "{extra}: {e:?}");
        assert!(e.message.contains(says), "{extra}: {}", e.message);
        assert!(!out.exists());
    }
    // A level's name is a .bhive's; a level that isn't one is refused as the input is read.
    let zip = dir.path().join("x.zip");
    let e = run(
        "archive.create",
        json!({ "output": s(&zip), "inputs": [s(&src)], "level": "fast" }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(e.message.contains("level of a .bhive"), "{}", e.message);
    let e = run(
        "archive.create",
        json!({ "output": s(&out), "inputs": [s(&src)], "level": "fastest" }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
}

#[test]
fn extract_add_rename_remove_and_convert() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let archive = dir.path().join("a.bhive");
    run(
        "archive.create",
        json!({ "output": s(&archive), "inputs": [s(&src)], "level": "fast" }),
    )
    .unwrap();

    let dest = dir.path().join("out");
    let out = run(
        "archive.extract",
        json!({ "archive": s(&archive), "dest": s(&dest) }),
    )
    .unwrap();
    assert_eq!(out["files"], 4);
    assert_eq!(
        std::fs::read(dest.join("src/docs/copy of a.txt")).unwrap(),
        std::fs::read(src.join("a.txt")).unwrap()
    );

    let extra = dir.path().join("new.txt");
    std::fs::write(&extra, "november").unwrap();
    let out = run(
        "archive.add",
        json!({ "archive": s(&archive), "inputs": [s(&extra)], "dir": "src/docs" }),
    )
    .unwrap();
    assert_eq!(out["added"], 1);
    let out = run(
        "archive.rename",
        json!({ "archive": s(&archive), "from": "src/docs", "to": "src/papers" }),
    )
    .unwrap();
    assert_eq!(out["renamed"], 4);
    // Renaming decodes nothing.
    assert_eq!(out["recompressed"], 0);
    let out = run(
        "archive.remove",
        json!({ "archive": s(&archive), "entries": ["src/a.txt"] }),
    )
    .unwrap();
    assert_eq!(out["removed"], 1);
    assert_eq!(
        names(&archive),
        [
            "src",
            "src/noise.bin",
            "src/papers",
            "src/papers/b.txt",
            "src/papers/copy of a.txt",
            "src/papers/new.txt",
        ]
    );
    // The copy kept the bytes it shared with the file that was removed.
    let read = run(
        "entry.read",
        json!({ "archive": s(&archive), "entry": "src/papers/copy of a.txt", "max_bytes": 28 }),
    )
    .unwrap();
    assert_eq!(read["data"], "bees make honey in the hive\n");
    let test = run("archive.test", json!({ "archive": s(&archive) })).unwrap();
    assert_eq!(test["entries"], 6);

    // To a zip and back, and to another level.
    let zip = dir.path().join("a.zip");
    run(
        "archive.convert",
        json!({ "archive": s(&archive), "output": s(&zip) }),
    )
    .unwrap();
    let back = dir.path().join("back.bhive");
    let out = run(
        "archive.convert",
        json!({ "archive": s(&zip), "output": s(&back), "level": "high" }),
    )
    .unwrap();
    assert_eq!(out["format"], "bhive");
    assert_eq!(names(&back), names(&archive));
    let info = run("archive.info", json!({ "archive": s(&back) })).unwrap();
    assert_eq!(property(&info, "Level"), Some("high"));
}

/// An archive cut short is `Corrupt`, and says how to open what is left; with `recover` it is
/// listed, described, tested as damaged, read and extracted, and can be converted.
#[test]
fn recover_opens_an_archive_without_its_index() {
    let cut = fixture("cut.bhive");
    let args = |extra: Value| {
        let mut a = json!({ "archive": s(&cut) });
        for (k, v) in extra.as_object().unwrap() {
            a[k] = v.clone();
        }
        a
    };
    for command in ["archive.list", "archive.info", "archive.test"] {
        let e = run(command, args(json!({}))).unwrap_err();
        assert_eq!(e.code, ErrorCode::Corrupt, "{command}");
        assert!(e.message.contains("recover"), "{}", e.message);
    }
    let list = run(
        "archive.list",
        args(json!({ "recover": true, "flat": true })),
    )
    .unwrap();
    assert_eq!(list["total"], 4);
    let info = run("archive.info", args(json!({ "recover": true }))).unwrap();
    assert!(
        info["notes"][0].as_str().unwrap().contains("incomplete"),
        "{info}"
    );
    // What is left reads, and the archive still tests as damaged: its index is gone.
    let e = run("archive.test", args(json!({ "recover": true }))).unwrap_err();
    assert_eq!(e.code, ErrorCode::Corrupt);
    assert!(e.message.contains("incomplete"), "{}", e.message);
    let read = run(
        "entry.read",
        args(json!({ "recover": true, "entry": "across.txt" })),
    )
    .unwrap();
    assert_eq!(read["data"], "still the first\nand the second cell\n");

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let out = run(
        "archive.extract",
        args(json!({ "recover": true, "dest": s(&dest) })),
    )
    .unwrap();
    assert_eq!(out["files"], 3);
    // What is left, into an archive that is whole.
    let whole = dir.path().join("whole.bhive");
    run(
        "archive.convert",
        args(json!({ "recover": true, "output": s(&whole) })),
    )
    .unwrap();
    assert_eq!(
        names(&whole),
        ["across.txt", "folder", "one.txt", "two.txt"]
    );
    // It isn't edited as it is.
    let copy = dir.path().join("cut.bhive");
    std::fs::copy(&cut, &copy).unwrap();
    let e = run(
        "archive.rename",
        json!({ "archive": s(&copy), "from": "one.txt", "to": "1.txt" }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Corrupt);
}

/// `[levels] bhive` sets the level of new archives; an input's level wins over it, and one that
/// isn't a level is refused when an archive is made.
#[test]
fn the_config_sets_the_level() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let with = |config: &str, args: Value| {
        let config: beezip_commands::Config = toml::from_str(config).unwrap();
        Engine::with_options(
            registry(),
            EngineOptions::from_config(Ok(config), Policy::unrestricted()),
        )
        .invoke(
            "archive.create",
            args,
            Arc::new(NonInteractive),
            Arc::new(|_| {}),
        )
        .unwrap()
        .join()
    };
    let level = |archive: &Path| {
        let info = run("archive.info", json!({ "archive": s(archive) })).unwrap();
        property(&info, "Level").unwrap().to_owned()
    };
    let a = dir.path().join("a.bhive");
    with(
        "[levels]\nbhive = 1\n",
        json!({ "output": s(&a), "inputs": [s(&src)] }),
    )
    .unwrap();
    assert_eq!(level(&a), "fast");
    let b = dir.path().join("b.bhive");
    with(
        "[levels]\nbhive = 1\n",
        json!({ "output": s(&b), "inputs": [s(&src)], "level": "max" }),
    )
    .unwrap();
    assert_eq!(level(&b), "max");
    let c = dir.path().join("c.bhive");
    let e = with(
        "[levels]\nbhive = 9\n",
        json!({ "output": s(&c), "inputs": [s(&src)] }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(!c.exists());
}
