//! The M1 commands run through the engine, as every front end runs them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use beezip_commands::{
    CmdError, Config, Engine, EngineOptions, ErrorCode, EventSink, Interactor, JobEvent,
    NonInteractive, Policy, Prompt, PromptReply, registry,
};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fx(name: &str) -> String {
    fixtures().join(name).display().to_string()
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
    fn prompt(&self, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
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

fn run(name: &str, args: Value) -> Result<Value, CmdError> {
    run_with(
        &Engine::new(registry()),
        name,
        args,
        Arc::new(NonInteractive),
    )
    .0
}

fn listing(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = walkdir(dir)
        .iter()
        .map(|p| {
            p.strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    out.sort();
    out
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walkdir(&p));
        }
        out.push(p);
    }
    out
}

#[test]
fn formats_list_has_everything() {
    let out = run("formats.list", json!({})).unwrap();
    assert_eq!(out["formats"].as_array().unwrap().len(), 3);
    assert_eq!(out["codecs"].as_array().unwrap().len(), 11);
    assert_eq!(out["create"].as_array().unwrap().len(), 11);
    let zip = &out["formats"][0];
    assert_eq!(zip["id"], "zip");
    assert_eq!(zip["methods"][1]["id"], "deflate");
    assert_eq!(zip["methods"][1]["levels"]["min"], 1);
}

#[test]
fn file_detect_reports_chains() {
    let out = run(
        "file.detect",
        json!({ "path": fx("thirdparty/bsdtar.tar.zst") }),
    )
    .unwrap();
    assert_eq!(out["chain"], "zstd → tar");
    assert_eq!(out["format"], "tar");
    assert_eq!(out["layers"][0]["confidence"], "certain");
    let out = run("file.detect", json!({ "path": fx("manifest.json") })).unwrap();
    assert_eq!(out["format"], Value::Null);
    assert!(out["label"].is_string());
    let err = run("file.detect", json!({ "path": fx("nope.zip") })).unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[test]
fn archive_info_counts() {
    let out = run(
        "archive.info",
        json!({ "archive": fx("thirdparty/7z-deflate.zip") }),
    )
    .unwrap();
    assert_eq!(out["format"], "zip");
    assert_eq!(out["files"], 6);
    assert_eq!(out["encryption"], "none");
    let out = run(
        "archive.info",
        json!({ "archive": fx("thirdparty/gnutar-pax.tar") }),
    )
    .unwrap();
    assert_eq!(out["links"], 1);
}

#[test]
fn archive_list_levels_paging_and_globs() {
    let archive = fx("thirdparty/bsdtar.tar.gz");
    let top = run("archive.list", json!({ "archive": archive })).unwrap();
    let names: Vec<&str> = top["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["ascii/"], "{top}");

    let level = run(
        "archive.list",
        json!({ "archive": archive, "dir": "ascii" }),
    )
    .unwrap();
    assert_eq!(level["total"], 5, "{level}");

    let flat = run(
        "archive.list",
        json!({ "archive": archive, "flat": true, "offset": 2, "limit": 3 }),
    )
    .unwrap();
    assert_eq!(flat["entries"].as_array().unwrap().len(), 3);
    assert_eq!(flat["offset"], 2);
    assert_eq!(flat["has_more"], true);

    let md = run(
        "archive.list",
        json!({ "archive": archive, "glob": ["*.md"] }),
    )
    .unwrap();
    assert_eq!(md["total"], 1);
    assert_eq!(md["entries"][0]["path"], "ascii/docs/readme.md");
    assert!(
        md["entries"][0]["modified"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );

    // A zip without folder entries still lists its folders, as implied ones.
    let dotnet = run(
        "archive.list",
        json!({ "archive": fx("thirdparty/dotnet.zip"), "dir": "tree" }),
    )
    .unwrap();
    let docs = dotnet["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == "tree/docs")
        .unwrap();
    assert_eq!(docs["kind"], "dir");
}

#[test]
fn entry_read_encodings_offsets_and_eof() {
    let archive = fx("thirdparty/7z-lzma.zip");
    let out = run(
        "entry.read",
        json!({ "archive": archive, "entry": "tree/hello.txt" }),
    )
    .unwrap();
    assert_eq!(out["data"], "Hello, BeeZip!\n");
    assert_eq!(out["eof"], true);
    let out = run("entry.read", json!({ "archive": archive, "entry": "tree/hello.txt", "offset": 7, "max_bytes": 3, "encoding": "hex" })).unwrap();
    assert_eq!(out["data"], "426565");
    assert_eq!(out["eof"], false);
    let out = run(
        "entry.read",
        json!({ "archive": archive, "entry": "tree/hello.txt", "encoding": "base64" }),
    )
    .unwrap();
    assert_eq!(out["data"], "SGVsbG8sIEJlZVppcCEK");
    // A multi-byte character cut by max_bytes is left for the next read.
    let out = run(
        "entry.read",
        json!({ "archive": archive, "entry": "tree/ünïcödé/名前.txt", "max_bytes": 1 }),
    )
    .unwrap();
    assert_eq!(out["bytes_read"], 1);
    let out = run(
        "entry.read",
        json!({ "archive": fx("thirdparty/7z-readme.md.gz"), "index": 0, "max_bytes": 6 }),
    )
    .unwrap();
    assert_eq!(out["data"], "BeeZip");
    let err = run(
        "entry.read",
        json!({ "archive": archive, "entry": "tree/docs" }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedOperation);
    let err = run(
        "entry.read",
        json!({ "archive": archive, "max_bytes": 1u64 << 30, "index": 0 }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
}

#[test]
fn archive_test_passes_and_fails_with_details() {
    let out = run(
        "archive.test",
        json!({ "archive": fx("thirdparty/7z-bzip2.zip") }),
    )
    .unwrap();
    assert!(out["entries"].as_u64().unwrap() >= 6);
    let err = run(
        "archive.test",
        json!({ "archive": fx("malicious/crc-mismatch.zip") }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Corrupt);
    let details = err.details.unwrap();
    assert_eq!(details["errors_total"], 1);
    assert_eq!(details["errors"][0]["code"], "Corrupt");
}

#[test]
fn passwords_missing_wrong_and_prompted() {
    let archive = fx("thirdparty/7z-aes256.zip");
    let dest = tempfile::tempdir().unwrap();
    let args = |pw: Option<&str>| {
        let mut a = json!({ "archive": archive, "dest": dest.path(), "overwrite": "always" });
        if let Some(pw) = pw {
            a["password"] = json!(pw);
        }
        a
    };
    let err = run("archive.extract", args(None)).unwrap_err();
    assert_eq!(err.code, ErrorCode::PasswordRequired);
    assert_eq!(err.details.unwrap()["param"], "password");
    let err = run("archive.extract", args(Some("wrong"))).unwrap_err();
    assert_eq!(err.code, ErrorCode::WrongPassword, "{err:?}");
    run("archive.extract", args(Some("beezip"))).unwrap();

    // Two wrong answers, then the right one: asked three times, and it works.
    let interactor = Scripted::new(vec![
        PromptReply::Password {
            password: "nope".into(),
        },
        PromptReply::Password {
            password: "still no".into(),
        },
        PromptReply::Password {
            password: "beezip".into(),
        },
    ]);
    let engine = Engine::new(registry());
    let (result, events) = run_with(&engine, "archive.extract", args(None), interactor.clone());
    result.unwrap();
    assert_eq!(interactor.asked.lock().unwrap().len(), 3);
    assert!(events.iter().any(|e| matches!(e, JobEvent::Prompt { .. })));

    // Three wrong answers: WrongPassword, without a fourth prompt.
    let interactor = Scripted::new(vec![
        PromptReply::Password {
            password: "x".into()
        };
        5
    ]);
    let (result, _) = run_with(&engine, "archive.extract", args(None), interactor.clone());
    assert_eq!(result.unwrap_err().code, ErrorCode::WrongPassword);
    assert_eq!(interactor.asked.lock().unwrap().len(), 3);
}

#[test]
fn unsafe_entries_fail_after_the_rest_is_extracted() {
    let dest = tempfile::tempdir().unwrap();
    let err = run(
        "archive.extract",
        json!({ "archive": fx("malicious/traversal.zip"), "dest": dest.path() }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsafe);
    assert_eq!(err.exit_code(), 14);
    let details = err.details.unwrap();
    assert_eq!(details["unsafe_total"], 2);
    assert_eq!(details["files"], 1);
    assert_eq!(details["skipped"][0]["reason"], "traversal");
    assert_eq!(listing(dest.path()), ["safe.txt"]);
}

#[test]
fn extract_smart_dry_run_and_selection() {
    let root = tempfile::tempdir().unwrap();
    // One top-level folder: --smart extracts in place.
    let archive = fx("thirdparty/bsdtar.tar.zst");
    let out = run(
        "archive.extract",
        json!({ "archive": archive, "dest": root.path(), "smart": true }),
    )
    .unwrap();
    assert_eq!(Path::new(out["dest"].as_str().unwrap()), root.path());
    assert!(root.path().join("ascii/hello.txt").is_file());

    // Several top-level items: into a folder named after the archive.
    let dest = root.path().join("smart");
    let out = run(
        "archive.extract",
        json!({ "archive": fx("malicious/devices.zip"), "dest": dest, "smart": true }),
    )
    .unwrap();
    assert!(out["dest"].as_str().unwrap().ends_with("devices"), "{out}");

    let out = run(
        "archive.extract",
        json!({ "archive": fx("malicious/traversal.tar"), "dest": root.path().join("dry"), "dry_run": true }),
    )
    .unwrap();
    assert_eq!(out["dry_run"], true);
    assert_eq!(out["plan"][0]["skip"], "traversal");
    assert_eq!(out["plan"][1]["to"], "safe.txt");
    assert!(
        !root.path().join("dry").exists(),
        "a dry run writes nothing"
    );

    let sel = root.path().join("sel");
    run(
        "archive.extract",
        json!({ "archive": archive, "dest": sel, "entries": ["ascii/docs"], "exclude": ["*.bin"] }),
    )
    .unwrap();
    assert_eq!(
        listing(&sel),
        ["ascii", "ascii/docs", "ascii/docs/readme.md"]
    );

    // An existing file and nobody to ask: Conflict.
    let err = run(
        "archive.extract",
        json!({ "archive": archive, "dest": root.path() }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
}

#[test]
fn create_formats_levels_and_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), "aaaa".repeat(1000)).unwrap();
    std::fs::write(src.join("sub/b.txt"), "b").unwrap();

    let out = run(
        "archive.create",
        json!({ "output": root.path().join("t.tar.zst"), "inputs": [src], "level": 19 }),
    )
    .unwrap();
    assert_eq!(out["format"], "tar.zst");
    assert_eq!(out["files"], 2);
    assert!(out["ratio"].as_f64().unwrap() < 1.0);

    let out = run(
        "archive.list",
        json!({ "archive": root.path().join("t.tar.zst"), "flat": true }),
    )
    .unwrap();
    assert_eq!(out["total"], 4); // src, src/a.txt, src/sub, src/sub/b.txt

    let bad = |args: Value| run("archive.create", args).unwrap_err().code;
    assert_eq!(
        bad(json!({ "output": root.path().join("x.unknown"), "inputs": [src] })),
        ErrorCode::InvalidArgs
    );
    assert_eq!(
        bad(json!({ "output": root.path().join("x.tar.zst"), "inputs": [src], "level": 99 })),
        ErrorCode::InvalidArgs
    );
    assert_eq!(
        bad(json!({ "output": root.path().join("x.tar"), "inputs": [src], "password": "p" })),
        ErrorCode::InvalidArgs
    );
    assert_eq!(
        bad(json!({ "output": root.path().join("x.tar.gz"), "inputs": [src], "method": "zstd" })),
        ErrorCode::InvalidArgs
    );
    assert_eq!(
        bad(json!({ "output": root.path().join("t.tar.zst"), "inputs": [src] })),
        ErrorCode::Conflict
    );
    assert_eq!(
        bad(
            json!({ "output": root.path().join("n.zip"), "inputs": [root.path().join("missing")] })
        ),
        ErrorCode::NotFound
    );

    let out = run(
        "archive.create",
        json!({ "output": root.path().join("p.zip"), "inputs": [src], "method": "ppmd", "password": "pw", "encryption": "zipcrypto" }),
    )
    .unwrap();
    assert_eq!(out["format"], "zip");
    let info = run(
        "archive.info",
        json!({ "archive": root.path().join("p.zip"), "password": "pw" }),
    )
    .unwrap();
    assert_eq!(info["encryption"], "all");
    assert_eq!(info["methods"], json!(["PPMd"]));

    let plan = run(
        "archive.create",
        json!({ "output": root.path().join("d.zip"), "inputs": [src], "dry_run": true }),
    )
    .unwrap();
    assert_eq!(plan["plan"].as_array().unwrap().len(), 4);
    assert!(!root.path().join("d.zip").exists());
}

#[test]
fn stream_compress_and_decompress_round_trip() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, "notes ".repeat(5000)).unwrap();
    for codec in [
        "gzip", "zstd", "xz", "bzip2", "lz4", "brotli", "snappy", "lzip", "lzma", "zlib",
    ] {
        let out = run(
            "stream.compress",
            json!({ "input": file, "codec": codec, "overwrite": true }),
        )
        .unwrap();
        let packed = PathBuf::from(out["output"].as_str().unwrap());
        assert!(out["bytes_out"].as_u64().unwrap() < 30_000, "{codec}");
        let restored = root.path().join(format!("back-{codec}.txt"));
        let back = run(
            "stream.decompress",
            json!({ "input": packed, "output": restored }),
        )
        .unwrap();
        assert_eq!(back["codec"], codec);
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            std::fs::read(&file).unwrap(),
            "{codec}"
        );
    }
    // Default name: .gz goes, and an existing output is a Conflict.
    run(
        "stream.compress",
        json!({ "input": file, "codec": "gzip", "overwrite": true }),
    )
    .unwrap();
    std::fs::remove_file(&file).unwrap();
    let out = run(
        "stream.decompress",
        json!({ "input": root.path().join("notes.txt.gz") }),
    )
    .unwrap();
    assert!(out["output"].as_str().unwrap().ends_with("notes.txt"));
    let err = run(
        "stream.decompress",
        json!({ "input": root.path().join("notes.txt.gz") }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
    let err = run(
        "stream.decompress",
        json!({ "input": fx("thirdparty/7z-copy.zip") }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedFormat);
    let err = run(
        "stream.compress",
        json!({ "input": root.path(), "output": root.path().join("dir.zst") }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
    let err = run(
        "stream.compress",
        json!({ "input": root.path().join("notes.txt"), "codec": "lz4", "level": 3 }),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
}

#[test]
fn progress_is_throttled_and_the_last_update_goes_out() {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for i in 0..200 {
        std::fs::write(src.join(format!("f{i}.txt")), "x").unwrap();
    }
    let (result, events) = run_with(
        &Engine::new(registry()),
        "archive.create",
        json!({ "output": root.path().join("p.zip"), "inputs": [src] }),
        Arc::new(NonInteractive),
    );
    result.unwrap();
    let progress: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            JobEvent::Progress(p) => Some(p.clone()),
            _ => None,
        })
        .collect();
    // 201 entries reported, but a fast job sends only a few updates.
    assert!(
        !progress.is_empty() && progress.len() < 20,
        "{} updates",
        progress.len()
    );
    let last = progress.last().unwrap();
    assert_eq!(last.entries_done, 201);
    assert_eq!(last.entries_total, Some(201));
    assert!(matches!(events.last(), Some(JobEvent::Finished { .. })));
}

/// Cancels the job when its first progress event arrives (docs/M1.md §6, Cancellation).
fn cancel_on_progress(name: &str, args: Value) -> (Result<Value, CmdError>, Vec<JobEvent>) {
    let engine = Engine::new(registry());
    let job_id = Arc::new(Mutex::new(None));
    let events = Arc::new(Mutex::new(Vec::new()));
    let (e2, id2, eng2) = (Arc::clone(&events), Arc::clone(&job_id), engine.clone());
    let sink: EventSink = Arc::new(move |e: JobEvent| {
        match &e {
            JobEvent::Started { job } => *id2.lock().unwrap() = Some(*job),
            JobEvent::Progress(_) => {
                if let Some(id) = *id2.lock().unwrap() {
                    eng2.cancel(id);
                }
            }
            _ => {}
        }
        e2.lock().unwrap().push(e);
    });
    let result = engine
        .invoke(name, args, Arc::new(NonInteractive), sink)
        .unwrap()
        .join();
    let events = events.lock().unwrap().clone();
    (result, events)
}

fn partials(dir: &Path) -> Vec<String> {
    listing(dir)
        .into_iter()
        .filter(|p| p.ends_with(".beezip-partial"))
        .collect()
}

#[test]
fn cancelling_create_and_extract_leaves_nothing_behind() {
    let root = tempfile::tempdir().unwrap();
    let big = root.path().join("big.bin");
    let data: Vec<u8> = (0..32u32 << 20)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(&big, &data).unwrap();

    let out = root.path().join("big.tar.zst");
    let (result, events) =
        cancel_on_progress("archive.create", json!({ "output": out, "inputs": [big] }));
    assert_eq!(result.unwrap_err().code, ErrorCode::Cancelled);
    assert!(matches!(events.last(), Some(JobEvent::Cancelled)));
    assert!(!out.exists());
    assert!(
        partials(root.path()).is_empty(),
        "{:?}",
        partials(root.path())
    );

    // Make a real archive, then cancel its extraction.
    run(
        "archive.create",
        json!({ "output": out, "inputs": [big], "level": 1 }),
    )
    .unwrap();
    let dest = root.path().join("x");
    let (result, _) =
        cancel_on_progress("archive.extract", json!({ "archive": out, "dest": dest }));
    assert_eq!(result.unwrap_err().code, ErrorCode::Cancelled);
    assert!(partials(&dest).is_empty(), "{:?}", partials(&dest));
    assert!(!dest.join("big.bin").exists());
}

#[test]
fn read_only_and_roots_policies() {
    let read_only = Engine::with_options(
        registry(),
        EngineOptions {
            policy: Policy {
                read_only: true,
                ..Policy::unrestricted()
            },
            ..EngineOptions::default()
        },
    );
    let dest = tempfile::tempdir().unwrap();
    let args = json!({ "archive": fx("thirdparty/7z-copy.zip"), "dest": dest.path() });
    let (r, _) = run_with(
        &read_only,
        "archive.extract",
        args.clone(),
        Arc::new(NonInteractive),
    );
    assert_eq!(r.unwrap_err().code, ErrorCode::UnsupportedOperation);
    let (r, _) = run_with(
        &read_only,
        "archive.info",
        json!({ "archive": fx("thirdparty/7z-copy.zip") }),
        Arc::new(NonInteractive),
    );
    r.unwrap();

    let sandbox = tempfile::tempdir().unwrap();
    let rooted = Engine::with_options(
        registry(),
        EngineOptions {
            policy: Policy {
                roots: Some(vec![sandbox.path().to_path_buf()]),
                ..Policy::unrestricted()
            },
            ..EngineOptions::default()
        },
    );
    let (r, _) = run_with(&rooted, "archive.extract", args, Arc::new(NonInteractive));
    assert_eq!(r.unwrap_err().code, ErrorCode::OutsideSandbox);
    let inside =
        json!({ "archive": fx("thirdparty/7z-copy.zip"), "dest": sandbox.path().join("x") });
    let (r, _) = run_with(&rooted, "archive.extract", inside, Arc::new(NonInteractive));
    r.unwrap();
}

#[test]
fn a_bad_config_fails_the_commands_that_need_it() {
    let (config, _) = Config::parse("[extract]\nlinks = 3\n", Path::new("config.toml"));
    let engine = Engine::with_options(
        registry(),
        EngineOptions::from_config(config, Policy::unrestricted()),
    );
    let dest = tempfile::tempdir().unwrap();
    let (r, _) = run_with(
        &engine,
        "archive.extract",
        json!({ "archive": fx("thirdparty/7z-copy.zip"), "dest": dest.path() }),
        Arc::new(NonInteractive),
    );
    let err = r.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
    assert!(err.message.contains("line 2"), "{}", err.message);
    // Commands that don't need it still work.
    let (r, _) = run_with(&engine, "formats.list", json!({}), Arc::new(NonInteractive));
    r.unwrap();
}

#[test]
fn config_defaults_apply() {
    let (config, _) = Config::parse(
        "[extract]\noverwrite = \"rename\"\n[stream]\ncodec = \"gzip\"\n",
        Path::new("c.toml"),
    );
    let engine = Engine::with_options(
        registry(),
        EngineOptions::from_config(config, Policy::unrestricted()),
    );
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("a.txt");
    std::fs::write(&file, "aaa").unwrap();
    let (r, _) = run_with(
        &engine,
        "stream.compress",
        json!({ "input": file }),
        Arc::new(NonInteractive),
    );
    assert!(r.unwrap()["output"].as_str().unwrap().ends_with("a.txt.gz"));
    let args = json!({ "archive": fx("thirdparty/7z-copy.zip"), "dest": root.path() });
    run_with(
        &engine,
        "archive.extract",
        args.clone(),
        Arc::new(NonInteractive),
    )
    .0
    .unwrap();
    // The second time, existing files are renamed rather than asked about.
    let (r, _) = run_with(&engine, "archive.extract", args, Arc::new(NonInteractive));
    assert!(r.unwrap()["renamed_total"].as_u64().unwrap() > 0);
}
