//! The edit commands (docs/M5.md §7): `archive.add`, `archive.remove`, `archive.rename`,
//! `archive.convert` and `entry.open`, run through the engine as every front end runs them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use beezip_commands::{
    CmdError, Engine, EngineOptions, ErrorCode, EventSink, Interactor, JobEvent, JobId, LogLevel,
    NonInteractive, OverwriteChoice, Policy, Prompt, PromptReply, registry,
};
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty")
        .join(name)
}

/// A copy of a fixture in `dir`, as a string for the JSON inputs.
fn copy(dir: &Path, name: &str) -> String {
    let to = dir.join(name);
    std::fs::copy(fixture(name), &to).unwrap();
    to.display().to_string()
}

/// Answers prompts from a script, and records them.
#[derive(Default)]
struct Scripted {
    replies: Mutex<Vec<PromptReply>>,
    asked: Mutex<Vec<Prompt>>,
}

impl Scripted {
    fn new(replies: Vec<PromptReply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into_iter().rev().collect()),
            asked: Mutex::new(Vec::new()),
        })
    }
}

impl Interactor for Scripted {
    fn prompt(&self, _job: JobId, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        self.asked.lock().unwrap().push(prompt.clone());
        self.replies
            .lock()
            .unwrap()
            .pop()
            .ok_or_else(|| CmdError::new(ErrorCode::PasswordRequired, "no more replies"))
    }
}

fn run_with(
    engine: &Engine,
    name: &str,
    args: Value,
    interactor: Arc<dyn Interactor>,
) -> (Result<Value, CmdError>, Vec<JobEvent>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = Arc::clone(&events);
    let sink: EventSink = Arc::new(move |e| sink_events.lock().unwrap().push(e));
    let result = engine.invoke(name, args, interactor, sink).unwrap().join();
    let events = events.lock().unwrap().clone();
    (result, events)
}

fn run(engine: &Engine, name: &str, args: Value) -> Result<Value, CmdError> {
    run_with(engine, name, args, Arc::new(NonInteractive)).0
}

/// Every path the archive lists, flat.
fn paths(engine: &Engine, archive: &str) -> Vec<String> {
    let out = run(
        engine,
        "archive.list",
        json!({ "archive": archive, "flat": true }),
    )
    .unwrap();
    out["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap().trim_end_matches('/').to_owned())
        .collect()
}

#[test]
fn add_remove_and_rename_through_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let a = copy(dir.path(), "7z-deflate.zip");
    // Listed first, so the cache holds it: the edits must make it list again.
    let before = paths(&engine, &a);
    assert!(before.contains(&"tree/hello.txt".to_owned()));
    let new = dir.path().join("notes.txt");
    std::fs::write(&new, "notes").unwrap();

    let out = run(
        &engine,
        "archive.add",
        json!({ "archive": a, "inputs": [new], "dir": "tree/docs" }),
    )
    .unwrap();
    assert_eq!(out["added"], 1);
    assert_eq!(out["format"], "zip");
    assert_eq!(out["copied"], before.len());
    assert!(out["bytes_after"].as_u64() > out["bytes_before"].as_u64());
    assert_eq!(out["plan"], Value::Null);
    assert!(paths(&engine, &a).contains(&"tree/docs/notes.txt".to_owned()));

    let out = run(
        &engine,
        "archive.rename",
        json!({ "archive": a, "from": "tree/docs", "to": "tree/papers" }),
    )
    .unwrap();
    assert_eq!(out["renamed"], 3, "the folder, readme.md and notes.txt");
    let now = paths(&engine, &a);
    assert!(now.contains(&"tree/papers/notes.txt".to_owned()), "{now:?}");
    assert!(!now.iter().any(|p| p.starts_with("tree/docs")), "{now:?}");

    let out = run(
        &engine,
        "archive.remove",
        json!({ "archive": a, "glob": ["*.md"] }),
    )
    .unwrap();
    assert_eq!(out["removed"], 1);
    assert!(!paths(&engine, &a).iter().any(|p| p.ends_with(".md")));
    let read = run(
        &engine,
        "entry.read",
        json!({ "archive": a, "entry": "tree/papers/notes.txt" }),
    )
    .unwrap();
    assert_eq!(read["data"], "notes");
}

#[test]
fn edits_say_why_they_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let a = copy(dir.path(), "7z-deflate.zip");
    let bytes = std::fs::read(&a).unwrap();
    let err = run(
        &engine,
        "archive.remove",
        json!({ "archive": a, "entries": ["nope"] }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    assert_eq!(err.message, "nothing in 7z-deflate.zip matches");
    let err = run(
        &engine,
        "archive.rename",
        json!({ "archive": a, "from": "tree/hello.txt", "to": "tree/empty.txt" }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
    let err = run(&engine, "archive.remove", json!({ "archive": a })).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
    let err = run(
        &engine,
        "archive.add",
        json!({ "archive": a, "inputs": [a.clone()], "method": "lzma2" }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs, "{err}");
    let split = fixture("7z-split.7z.001").display().to_string();
    let err = run(
        &engine,
        "archive.remove",
        json!({ "archive": split, "entries": ["x"] }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedOperation);
    assert!(err.message.contains("beezip convert"), "{err}");
    assert_eq!(std::fs::read(&a).unwrap(), bytes, "nothing changed");
}

#[test]
fn dry_runs_list_the_changes_and_write_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let a = copy(dir.path(), "gnutar-ustar.tar");
    let bytes = std::fs::read(&a).unwrap();
    let out = run(
        &engine,
        "archive.rename",
        json!({ "archive": a, "from": "links/docs", "to": "links/papers", "dry_run": true }),
    )
    .unwrap();
    assert_eq!(out["dry_run"], true);
    assert_eq!(
        out["plan"][1],
        json!({ "action": "rename", "path": "links/papers/readme.md", "from": "links/docs/readme.md" })
    );
    let out = run(
        &engine,
        "archive.remove",
        json!({ "archive": a, "entries": ["links/docs"], "dry_run": true }),
    )
    .unwrap();
    assert_eq!(out["removed"], 2);
    assert_eq!(out["plan"][0]["action"], "remove");
    assert_eq!(std::fs::read(&a).unwrap(), bytes);
}

#[test]
fn an_entry_already_there_is_asked_about_with_the_archive() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let a = copy(dir.path(), "7z-deflate.zip");
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("hello.txt"), "replaced").unwrap();
    // Nobody to ask: `Conflict`, naming the entry and the archive.
    let err = run(
        &engine,
        "archive.add",
        json!({ "archive": a, "inputs": [tree] }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
    assert_eq!(
        err.message,
        "`tree/hello.txt` is already in 7z-deflate.zip; pass an `overwrite` policy"
    );
    // Asked, and replaced.
    let ask = Scripted::new(vec![PromptReply::Overwrite {
        choice: OverwriteChoice::Replace,
    }]);
    let (out, _) = run_with(
        &engine,
        "archive.add",
        json!({ "archive": a, "inputs": [tree] }),
        ask.clone(),
    );
    let out = out.unwrap();
    assert_eq!(out["replaced"], 1);
    assert_eq!(
        ask.asked.lock().unwrap()[0],
        Prompt::Overwrite {
            path: "tree/hello.txt".into(),
            archive: Some("7z-deflate.zip".into()),
        }
    );
    let read = run(
        &engine,
        "entry.read",
        json!({ "archive": a, "entry": "tree/hello.txt" }),
    )
    .unwrap();
    assert_eq!(read["data"], "replaced");
}

#[test]
fn the_config_sets_the_add_policy() {
    let dir = tempfile::tempdir().unwrap();
    let config: beezip_commands::Config =
        toml::from_str("[edit]\noverwrite = \"rename\"\n").unwrap();
    let engine = Engine::with_options(
        registry(),
        EngineOptions::from_config(Ok(config), Policy::unrestricted()),
    );
    let a = copy(dir.path(), "7z-deflate.zip");
    let tree = dir.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("hello.txt"), "second").unwrap();
    let out = run(
        &engine,
        "archive.add",
        json!({ "archive": a, "inputs": [tree] }),
    )
    .unwrap();
    assert_eq!(out["added"], 1);
    assert!(paths(&engine, &a).contains(&"tree/hello (1).txt".to_owned()));
}

#[test]
fn two_edits_of_one_archive_take_turns() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let a = copy(dir.path(), "7z-lzma2-mt.7z");
    let names: Vec<String> = (0..4)
        .map(|i| {
            let p = dir.path().join(format!("f{i}.bin"));
            let data: Vec<u8> = (0..400_000u32)
                .map(|n| (n.wrapping_mul(i + 7) >> 3) as u8)
                .collect();
            std::fs::write(&p, data).unwrap();
            p.display().to_string()
        })
        .collect();
    let logs = Arc::new(Mutex::new(Vec::new()));
    let handles: Vec<_> = names
        .iter()
        .map(|n| {
            let logs = Arc::clone(&logs);
            let sink: EventSink = Arc::new(move |e| {
                if let JobEvent::Log { level, message } = e {
                    logs.lock().unwrap().push((level, message));
                }
            });
            engine
                .invoke(
                    "archive.add",
                    json!({ "archive": a, "inputs": [n] }),
                    Arc::new(NonInteractive),
                    sink,
                )
                .unwrap()
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    // Every add landed: none overwrote another's archive.
    let listed = paths(&engine, &a);
    for i in 0..4 {
        assert!(listed.contains(&format!("f{i}.bin")), "{listed:?}");
    }
    let waited = logs
        .lock()
        .unwrap()
        .iter()
        .filter(|(l, m)| {
            *l == LogLevel::Info && m == "Waiting for another change to 7z-lzma2-mt.7z"
        })
        .count();
    assert!(waited >= 1, "{:?}", logs.lock().unwrap());
}

#[test]
fn the_sandbox_confines_edits_to_its_roots() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let policy = Policy {
        roots: Some(vec![root.path().to_path_buf()]),
        ..Policy::unrestricted()
    };
    let engine = Engine::with_options(
        registry(),
        EngineOptions {
            policy,
            ..EngineOptions::default()
        },
    );
    let a = copy(outside.path(), "7z-deflate.zip");
    for (name, args) in [
        (
            "archive.remove",
            json!({ "archive": a, "entries": ["tree/hello.txt"] }),
        ),
        (
            "archive.rename",
            json!({ "archive": a, "from": "tree", "to": "x" }),
        ),
        (
            "archive.add",
            json!({ "archive": a, "inputs": [a.clone()] }),
        ),
    ] {
        let err = run(&engine, name, args).unwrap_err();
        assert_eq!(err.code, ErrorCode::OutsideSandbox, "{name}");
    }
    // Converting reads outside the roots and writes inside them.
    let out = root.path().join("a.7z").display().to_string();
    run(
        &engine,
        "archive.convert",
        json!({ "archive": a, "output": out }),
    )
    .unwrap();
    let bad = outside.path().join("b.7z").display().to_string();
    let err = run(
        &engine,
        "archive.convert",
        json!({ "archive": a, "output": bad }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::OutsideSandbox);
    // And a read-only session does no edits at all.
    let ro = Engine::with_options(
        registry(),
        EngineOptions {
            policy: Policy {
                read_only: true,
                ..Policy::unrestricted()
            },
            ..EngineOptions::default()
        },
    );
    let err = run(
        &ro,
        "archive.remove",
        json!({ "archive": a, "entries": ["tree"] }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedOperation);
}

#[test]
fn convert_through_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let out = dir.path().join("a.tar.zst").display().to_string();
    let r = run(
        &engine,
        "archive.convert",
        json!({ "archive": fixture("bsdtar.tar.gz"), "output": out }),
    )
    .unwrap();
    assert_eq!(r["format"], "tar.zst");
    assert!(r["recompressed"].as_u64().unwrap() > 0);
    assert_eq!(r["copied"], 0);
    assert_eq!(
        paths(&engine, &out),
        paths(&engine, &fixture("bsdtar.tar.gz").display().to_string())
    );
    // A method asks for the entries to be encoded again.
    let out7 = dir.path().join("a.7z").display().to_string();
    let r = run(
        &engine,
        "archive.convert",
        json!({ "archive": fixture("7z-lzma.7z"), "output": out7, "method": "ppmd" }),
    )
    .unwrap();
    assert_eq!(r["copied"], 0);
    // An encrypted source needs `new_password` or `decrypt`.
    let enc = fixture("7z-aes256.zip").display().to_string();
    let outz = dir.path().join("b.tar").display().to_string();
    let err = run(
        &engine,
        "archive.convert",
        json!({ "archive": enc, "output": outz, "password": "beezip" }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
    run(
        &engine,
        "archive.convert",
        json!({ "archive": enc, "output": outz, "password": "beezip", "decrypt": true }),
    )
    .unwrap();
    let dry = run(
        &engine,
        "archive.convert",
        json!({ "archive": fixture("7z-lzma.7z"), "output": dir.path().join("c.zip"), "dry_run": true, "glob": ["*.md"] }),
    )
    .unwrap();
    assert_eq!(dry["plan"], json!(["tree/docs/readme.md"]));
    assert!(!dir.path().join("c.zip").exists());
}

#[test]
fn entry_open_extracts_to_a_folder_of_its_own() {
    let engine = Engine::new(registry());
    let a = fixture("7z-deflate.zip").display().to_string();
    let open = |entry: &str| {
        run(
            &engine,
            "entry.open",
            json!({ "archive": a, "entry": entry, "launch": false }),
        )
    };
    let first = open("tree/hello.txt").unwrap();
    let second = open("tree/hello.txt").unwrap();
    let (p1, p2) = (
        PathBuf::from(first["path"].as_str().unwrap()),
        PathBuf::from(second["path"].as_str().unwrap()),
    );
    assert_ne!(p1, p2, "each in its own folder");
    assert_eq!(p1.file_name().unwrap(), "hello.txt");
    assert!(p1.starts_with(beezip_commands::commands::open_root()));
    assert_eq!(std::fs::read_to_string(&p1).unwrap(), "Hello, BeeZip!\n");
    assert_eq!(first["launched"], false);
    for e in ["tree/docs", "tree"] {
        assert_eq!(open(e).unwrap_err().code, ErrorCode::InvalidArgs, "{e}");
    }
    assert_eq!(open("tree/nope.txt").unwrap_err().code, ErrorCode::NotFound);
    let _ = std::fs::remove_dir_all(p1.parent().unwrap());
    let _ = std::fs::remove_dir_all(p2.parent().unwrap());
    // MCP doesn't see it.
    assert!(!registry().get("entry.open").unwrap().surfaces.mcp);
}

/// A download mark as the platform writes it: a `Zone.Identifier` stream on Windows, a
/// `com.apple.quarantine` record on macOS (docs/M6.md §8.3).
#[cfg(windows)]
const MARK: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";
#[cfg(target_os = "macos")]
const MARK: &[u8] = b"0083;6912f0a1;Safari;3F8C1B9E-4C1A-4E5B-9E0F-1D2C3B4A5968";

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn entry_open_keeps_the_mark_of_the_web() {
    use beezip_core::safefs::motw;
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let a = copy(dir.path(), "7z-deflate.zip");
    motw::write_zone(Path::new(&a), MARK).unwrap();
    let out = run(
        &engine,
        "entry.open",
        json!({ "archive": a, "entry": "tree/hello.txt", "launch": false }),
    )
    .unwrap();
    let p = out["path"].as_str().unwrap();
    assert_eq!(motw::read_zone(Path::new(p)).as_deref(), Some(MARK));
    let _ = std::fs::remove_dir_all(Path::new(p).parent().unwrap());

    // An edit keeps the archive's own mark.
    run(
        &engine,
        "archive.remove",
        json!({ "archive": a, "entries": ["tree/hello.txt"] }),
    )
    .unwrap();
    assert_eq!(motw::read_zone(Path::new(&a)).as_deref(), Some(MARK));
}

#[test]
fn a_slow_edit_can_be_cancelled_while_it_waits() {
    // The second of two edits waits; cancelling it ends the wait.
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(registry());
    let a = copy(dir.path(), "7z-deflate.zip");
    let big = dir.path().join("big.bin");
    let data: Vec<u8> = (0..40_000_000u32)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    std::fs::write(&big, data).unwrap();
    let first = engine
        .invoke(
            "archive.add",
            json!({ "archive": a, "inputs": [big], "method": "xz", "level": 9 }),
            Arc::new(NonInteractive),
            beezip_commands::discard_events(),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let second = engine
        .invoke(
            "archive.remove",
            json!({ "archive": a, "entries": ["tree/hello.txt"] }),
            Arc::new(NonInteractive),
            beezip_commands::discard_events(),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    second.cancel();
    let t = std::time::Instant::now();
    assert_eq!(second.join().unwrap_err().code, ErrorCode::Cancelled);
    assert!(t.elapsed() < Duration::from_secs(2));
    first.cancel();
    let _ = first.join();
}
