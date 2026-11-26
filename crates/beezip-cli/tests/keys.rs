//! `beezip keys …` end to end (docs/M14.md §8): your keys and contacts, in a settings folder of
//! the test's own (`BEEZIP_CONFIG`), deleted when it ends so the system keeps nothing of it.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn beezip(settings: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_beezip"));
    cmd.env("BEEZIP_CONFIG", settings.join("config.toml"));
    cmd
}

/// A settings folder whose keys are deleted at the end, even when the test fails.
struct Settings(tempfile::TempDir);

impl Settings {
    fn new() -> Self {
        Self(tempfile::tempdir().expect("a temporary folder"))
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = beezip(self.path())
            .args(args)
            .args(["--output", "json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&out).expect("one JSON document")
    }
}

impl Drop for Settings {
    fn drop(&mut self) {
        let Ok(out) = beezip(self.path())
            .args(["keys", "list", "--output", "json"])
            .output()
        else {
            return;
        };
        let Ok(list) = serde_json::from_slice::<Value>(&out.stdout) else {
            return;
        };
        for k in list["keys"].as_array().into_iter().flatten() {
            if let Some(name) = k["name"].as_str() {
                let _ = beezip(self.path()).args(["keys", "delete", name]).output();
            }
        }
    }
}

#[test]
fn keys_from_the_command_line() {
    let s = Settings::new();
    beezip(s.path())
        .args(["keys", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No keys yet"));

    let made = s.json(&["keys", "create", "Mine"]);
    assert_eq!(made["kind"], "post-quantum");
    let public = made["public"].as_str().unwrap().to_owned();
    assert!(public.starts_with("age1pq1"));

    // Human output: the public key to share; export prints the key alone.
    beezip(s.path())
        .args(["keys", "create", "Old", "--kind", "classic"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Its public key, to share:\nage1"));
    beezip(s.path())
        .args(["keys", "export", "Mine"])
        .assert()
        .success()
        .stdout(format!("{public}\n"));
    beezip(s.path())
        .args(["keys", "export", "Mine", "--secret"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("AGE-SECRET-KEY-PQ-1"))
        .stderr(predicate::str::contains("private key"));

    // A contact's key from a file; listed after your own.
    let file = s.path().join("alice.txt");
    let alice = s.json(&["keys", "export", "Old"]);
    let other = Settings::new();
    std::fs::write(&file, alice["text"].as_str().unwrap()).unwrap();
    let added = other.json(&["keys", "import", "Alice", "--file", file.to_str().unwrap()]);
    assert_eq!(added["own"], false);
    other.json(&["keys", "create", "Me"]);
    let list = other.json(&["keys", "list"]);
    let names: Vec<&str> = list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Me", "Alice"]);

    // Refusals keep their codes: a name already used, a key that isn't one, nobody.
    beezip(s.path())
        .args(["keys", "create", "mine"])
        .assert()
        .code(10);
    beezip(s.path())
        .args(["keys", "import", "Bad", "--text", "age1notakey"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("a public key, but"));
    beezip(s.path())
        .args(["keys", "delete", "Nobody"])
        .assert()
        .code(3);

    beezip(s.path())
        .args(["keys", "delete", "mine"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted `Mine`."));
}
