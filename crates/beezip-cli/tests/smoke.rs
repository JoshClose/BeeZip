//! The PLAN §4 smoke test, end to end through the binary:
//! `formats`, `create t.tar.zst src -l 19`, `test`, `x -o out`, and
//! `run archive.list --json '{"archive":"t.tar.zst"}' --output json`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use serde_json::Value;

fn beezip(dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_beezip"));
    cmd.current_dir(dir)
        .env("BEEZIP_CONFIG", "no-such-beezip-config.toml");
    cmd
}

#[test]
fn smoke() {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("a.txt"), "smoke ".repeat(1000)).unwrap();
    std::fs::write(src.join("nested/b.bin"), [0u8, 1, 2, 3, 255]).unwrap();

    beezip(root.path()).arg("formats").assert().success();
    beezip(root.path())
        .args(["create", "t.tar.zst", "src", "-l", "19"])
        .assert()
        .success();
    beezip(root.path())
        .args(["test", "t.tar.zst"])
        .assert()
        .success();
    beezip(root.path())
        .args(["x", "t.tar.zst", "-o", "out"])
        .assert()
        .success();
    assert_eq!(
        std::fs::read(root.path().join("out/src/a.txt")).unwrap(),
        std::fs::read(src.join("a.txt")).unwrap()
    );
    assert_eq!(
        std::fs::read(root.path().join("out/src/nested/b.bin")).unwrap(),
        [0u8, 1, 2, 3, 255]
    );

    let out = beezip(root.path())
        .args([
            "run",
            "archive.list",
            "--json",
            r#"{"archive":"t.tar.zst"}"#,
            "--output",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listing: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(listing["entries"][0]["path"], "src/");
    assert_eq!(listing["has_more"], false);
}

#[test]
fn ndjson_streams_progress_and_the_result() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("f.txt"), "x".repeat(100_000)).unwrap();
    let out = beezip(root.path())
        .args(["--output", "ndjson", "compress", "f.txt"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let events: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events[0]["type"], "Started");
    assert!(events.iter().any(|e| e["type"] == "Progress"), "{events:?}");
    let last = events.last().unwrap();
    assert_eq!(last["type"], "Finished");
    assert_eq!(last["output"]["codec"], "zstd");
}
