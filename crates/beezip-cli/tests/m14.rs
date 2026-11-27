//! M14 end to end through the CLI (docs/M14.md §8, §11): encrypted and signed `.bhive`
//! archives with the real pieces: passwords, recovery keys, your stored keys, age identity
//! files, certificate files, signing keys and certificates, `--require-signer`. Each test has a
//! settings folder of its own (`BEEZIP_CONFIG`), whose keys are deleted when it ends. Nothing
//! here needs a device, a PIN or a person: no This PC, security key or Windows Hello.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

/// A password's Argon2 takes 1 GiB: one test at a time uses them.
static ARGON2: Mutex<()> = Mutex::new(());

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn testdata(name: &str) -> String {
    repo()
        .join("crates/beezip-keys/src/files/testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// age's example keys: an X25519 identity and recipient, an X-Wing identity and recipient.
fn age_examples() -> Vec<String> {
    std::fs::read_to_string(repo().join("tests/fixtures/keys/age-spec-examples.txt"))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// A settings folder and a work folder; the keys made in it are deleted at the end, even when
/// the test fails.
struct Here {
    settings: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Here {
    fn new() -> Self {
        let here = Self {
            settings: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        let src = here.path("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("a.txt"), "honey ".repeat(500)).unwrap();
        std::fs::write(src.join("b.txt"), "comb").unwrap();
        here
    }

    fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    fn arg(&self, name: &str) -> String {
        self.path(name).to_string_lossy().into_owned()
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_beezip"));
        cmd.env("BEEZIP_CONFIG", self.settings.path().join("config.toml"))
            .current_dir(self.work.path());
        cmd
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self
            .cmd()
            .args(args)
            .assert()
            .success()
            .get_output()
            .clone();
        String::from_utf8(out.stdout).unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.ok(&[args, &["--output", "json"]].concat());
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"))
    }

    fn fails(&self, args: &[&str], code: i32) -> String {
        let out = self
            .cmd()
            .args(args)
            .assert()
            .code(code)
            .get_output()
            .clone();
        String::from_utf8(out.stderr).unwrap()
    }

    /// A key file in the work folder.
    fn file(&self, name: &str, text: &str) -> String {
        std::fs::write(self.path(name), text).unwrap();
        self.arg(name)
    }
}

impl Drop for Here {
    fn drop(&mut self) {
        let Ok(out) = self
            .cmd()
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
                let _ = self.cmd().args(["keys", "delete", name]).output();
            }
        }
    }
}

#[test]
fn a_password_and_a_recovery_key() {
    let _argon2 = ARGON2.lock().unwrap_or_else(|e| e.into_inner());
    let h = Here::new();
    let made = h.json(&[
        "create",
        "a.bhive",
        "src",
        "--password",
        "pw",
        "--recovery-key",
    ]);
    let recovery = made["recovery_key"].as_str().unwrap().to_owned();
    assert_eq!(recovery.chars().filter(char::is_ascii_digit).count(), 48);

    h.ok(&["list", "a.bhive", "--password", "pw"]);
    // Nobody to ask: a password is required, as for a zip (exit 6), and the CLI says what to
    // pass.
    let e = h.fails(&["list", "a.bhive"], 6);
    assert!(
        e.contains("PasswordRequired") && e.contains("--password"),
        "{e}"
    );
    h.fails(&["list", "a.bhive", "--password", "wrong"], 7);

    // The recovery key opens it, through --password or --password-stdin, any separators.
    h.ok(&["extract", "a.bhive", "-o", "out", "--password", &recovery]);
    assert_eq!(
        std::fs::read_to_string(h.path("out/src/b.txt")).unwrap(),
        "comb"
    );
    let spaced = recovery.replace('-', " ");
    h.cmd()
        .args(["test", "a.bhive", "--password-stdin"])
        .write_stdin(format!("{spaced}\n"))
        .assert()
        .success();

    let info = h.json(&["info", "a.bhive", "--password", "pw"]);
    let ways = info["protection"]["ways"].as_array().unwrap();
    let kinds: Vec<&str> = ways.iter().map(|w| w["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["password", "recovery-key"]);
    let human = h.ok(&["protection", "a.bhive", "--password", "pw"]);
    assert!(human.contains("ecovery"), "{human}");
}

#[test]
fn age_identities_open_what_was_encrypted_to_them() {
    let keys = age_examples();
    let h = Here::new();
    let classic = h.file("classic.txt", &format!("# test key\n{}\n", keys[0]));
    let pq = h.file("pq.txt", &keys[2]);
    h.ok(&["create", "c.bhive", "src", "--to", &keys[1]]);
    h.ok(&["create", "pq.bhive", "src", "--to", &keys[3]]);

    h.fails(&["list", "c.bhive"], 15);
    h.ok(&["list", "c.bhive", "-i", &classic]);
    h.ok(&["test", "pq.bhive", "--identity", &pq]);
    h.fails(&["list", "pq.bhive", "-i", &classic], 15);

    let info = h.json(&["protection", "pq.bhive", "-i", &pq]);
    assert_eq!(info["post_quantum"], true);
    assert_eq!(info["ways"][0]["recipient"], keys[3].as_str());
    assert_eq!(info["ways"][0]["fingerprint"].as_str().unwrap().len(), 19);
    let info = h.json(&["protection", "c.bhive", "-i", &classic]);
    assert_eq!(info["post_quantum"], false);
}

#[test]
fn your_keys_open_and_sign() {
    let h = Here::new();
    h.ok(&["keys", "create", "Mine"]);
    h.ok(&["keys", "create", "Signer", "--kind", "signing"]);
    let signer = h.ok(&["keys", "export", "Signer"]).trim().to_owned();
    assert!(signer.starts_with("bzsig1"));

    // To your own key by name, signed by your own signing key.
    h.ok(&[
        "create", "s.bhive", "src", "--to", "Mine", "--sign", "Signer",
    ]);
    h.ok(&["list", "s.bhive"]);
    let out = h.ok(&["verify", "s.bhive"]);
    assert!(out.contains("signed by you"), "{out}");
    h.ok(&["verify", "s.bhive", "--require-signer", &signer]);
    h.ok(&["verify", "s.bhive", "--require-signer", "Signer"]);
    let info = h.json(&["info", "s.bhive"]);
    let s = &info["signatures"][0];
    assert_eq!(s["status"], "valid");
    assert_eq!(s["trust"], "yours");
    assert_eq!(s["post_quantum"], true);
    assert_eq!(s["public"], signer.as_str(), "for Add to contacts");

    // Someone else's signing key isn't enough, and a fingerprint is never matched.
    let other = Here::new();
    other.ok(&["keys", "create", "Other", "--kind", "signing"]);
    let stranger = other.ok(&["keys", "export", "Other"]).trim().to_owned();
    let e = h.fails(&["verify", "s.bhive", "--require-signer", &stranger], 16);
    assert!(e.contains("not signed by"), "{e}");
    let fingerprint = s["fingerprint"].as_str().unwrap();
    h.fails(&["verify", "s.bhive", "--require-signer", fingerprint], 3);
    // Extract checks before anything is written.
    h.fails(
        &[
            "extract",
            "s.bhive",
            "-o",
            "x",
            "--require-signer",
            &stranger,
        ],
        16,
    );
    assert!(!h.path("x/src/a.txt").exists());
    h.ok(&["extract", "s.bhive", "-o", "y", "--require-signer", &signer]);
    assert!(h.path("y/src/a.txt").exists());

    // Another settings folder has neither key: it can't open the archive, and the
    // signature is a stranger's there.
    other
        .cmd()
        .args(["list", &h.arg("s.bhive")])
        .assert()
        .code(15);
    other
        .cmd()
        .args(["verify", &h.arg("s.bhive")])
        .assert()
        .code(15);
}

#[test]
fn certificate_files_encrypt_and_sign() {
    let h = Here::new();
    let (rsa, p256) = (testdata("rsa.crt"), testdata("p256.crt"));
    // rsa.key beside rsa.crt signs.
    h.ok(&[
        "create",
        "r.bhive",
        "src",
        "--to-cert",
        &rsa,
        "--to-cert",
        &p256,
        "--sign",
        &rsa,
    ]);
    h.fails(&["list", "r.bhive"], 15);
    h.ok(&["list", "r.bhive", "-i", &testdata("rsa.key")]);
    h.ok(&["list", "r.bhive", "-i", &testdata("p256.key")]);
    let ways = h.json(&["protection", "r.bhive", "-i", &testdata("rsa.key")]);
    let kinds: Vec<&str> = ways["ways"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["rsa-certificate", "ec-p256"]);
    let info = h.json(&["info", "r.bhive", "-i", &testdata("rsa.key")]);
    let public = info["signatures"][0]["public"].as_str().unwrap();
    assert!(
        public.starts_with("-----BEGIN CERTIFICATE-----"),
        "{public}"
    );

    let id = ["-i", &testdata("rsa.key")];
    h.ok(&[&["verify", "r.bhive", "--require-signer", &rsa][..], &id].concat());
    // A self-signed certificate nobody trusts, or another one, isn't enough.
    h.fails(&[&["verify", "r.bhive"][..], &id].concat(), 16);
    h.fails(
        &[&["verify", "r.bhive", "--require-signer", &p256][..], &id].concat(),
        16,
    );

    // An expired certificate is still encrypted to, with a warning.
    h.cmd()
        .args([
            "create",
            "e.bhive",
            "src",
            "--to-cert",
            &testdata("rsa-expired.crt"),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("expired"));
    // A key file under a password needs a terminal to type it.
    h.ok(&[
        "create",
        "p.bhive",
        "src",
        "--to-cert",
        &testdata("p384.crt"),
    ]);
    let e = h.fails(
        &["list", "p.bhive", "-i", &testdata("p384-encrypted.key")],
        6,
    );
    assert!(e.contains("under a password"), "{e}");
}

#[test]
fn sign_and_protect_change_an_archive_in_place() {
    let keys = age_examples();
    let h = Here::new();
    h.ok(&["keys", "create", "Mine"]);
    h.ok(&["keys", "create", "Signer", "--kind", "signing"]);

    // Signing a plain archive, then removing its signature.
    h.ok(&["create", "p.bhive", "src"]);
    h.ok(&["sign", "p.bhive", "--sign", "Signer"]);
    let out = h.ok(&["info", "p.bhive"]);
    assert!(out.contains("1. signed by you"), "{out}");
    h.ok(&["sign", "p.bhive", "--sign", &testdata("rsa.crt")]);
    assert_eq!(
        h.json(&["info", "p.bhive"])["signatures"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    h.ok(&["sign", "p.bhive", "--remove", "2"]);
    assert_eq!(
        h.json(&["info", "p.bhive"])["signatures"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    h.fails(&["sign", "p.bhive", "--remove", "0"], 2);
    h.ok(&["sign", "p.bhive", "--remove-all"]);
    h.fails(&["verify", "p.bhive"], 16);

    // Adding and removing ways in keeps the contents, so the signature stays.
    h.ok(&[
        "create", "e.bhive", "src", "--to", "Mine", "--sign", "Signer",
    ]);
    let out = h.json(&["protect", "e.bhive", "--to", &keys[1]]);
    assert_eq!(out["ways"].as_array().unwrap().len(), 2);
    h.ok(&["verify", "e.bhive"]);
    h.ok(&["protect", "e.bhive", "--remove", "0"]);
    h.fails(&["list", "e.bhive"], 15);
    let classic = h.file("classic.txt", &keys[0]);
    h.ok(&["verify", "e.bhive", "-i", &classic]);

    // A new key for a key that isn't among yours or your contacts' needs it confirmed.
    let e = h.fails(&["protect", "e.bhive", "--new-key", "-i", &classic], 2);
    assert!(e.contains("slot 0"), "{e}");
    let before = std::fs::read(h.path("e.bhive")).unwrap();
    h.ok(&[
        "protect",
        "e.bhive",
        "--new-key",
        "--confirm",
        "0",
        "--to",
        "Mine",
        "-i",
        &classic,
    ]);
    assert_ne!(std::fs::read(h.path("e.bhive")).unwrap(), before);
    h.ok(&["verify", "e.bhive"]);
    h.ok(&["list", "e.bhive", "-i", &classic]);
}

#[test]
fn a_certificate_contact_through_the_cli() {
    let h = Here::new();
    let out = h.ok(&["keys", "import", "Bob", "--file", &testdata("rsa.der")]);
    assert!(
        out.contains("Added \"Bob\", a contact's certificate: BeeZip test rsa (self-signed)"),
        "{out}"
    );
    let table = h.ok(&["keys", "list"]);
    assert!(
        table.contains("Bob  certificate   contact  ")
            && table.contains("BeeZip test rsa, until 2"),
        "{table}"
    );
    h.ok(&["create", "c.bhive", "src", "--to", "Bob"]);
    h.fails(&["list", "c.bhive"], 15);
    h.ok(&["list", "c.bhive", "-i", &testdata("rsa.key")]);
    // Signed with Bob's key file, the signature is Bob's.
    h.ok(&["create", "s.bhive", "src", "--sign", &testdata("rsa.crt")]);
    let out = h.ok(&["info", "s.bhive"]);
    assert!(out.contains("signed by Bob"), "{out}");
    h.ok(&["verify", "s.bhive", "--require-signer", "Bob"]);
}

#[test]
fn convert_shows_the_recovery_key_it_makes() {
    let _argon2 = ARGON2.lock().unwrap_or_else(|e| e.into_inner());
    let h = Here::new();
    h.ok(&["create", "a.zip", "src", "--password", "old"]);
    let out = h.ok(&[
        "convert",
        "a.zip",
        "a.bhive",
        "--password",
        "old",
        "--new-password",
        "pw",
        "--recovery-key",
    ]);
    // As create and protect show it: once, with what to do with it.
    let line = out
        .lines()
        .find_map(|l| l.strip_prefix("Recovery key: "))
        .unwrap_or_else(|| panic!("{out}"));
    assert_eq!(
        line.chars().filter(char::is_ascii_digit).count(),
        48,
        "{out}"
    );
    assert!(out.contains("shown only this once"), "{out}");
    h.ok(&["test", "a.bhive", "--password", line]);

    // An archive only a recovery key opens needs a password too, with nobody to ask (exit 6).
    let made = h.json(&["create", "r.bhive", "src", "--recovery-key"]);
    let e = h.fails(&["list", "r.bhive"], 6);
    assert!(e.contains("PasswordRequired"), "{e}");
    h.ok(&[
        "list",
        "r.bhive",
        "-p",
        made["recovery_key"].as_str().unwrap(),
    ]);
}

/// Decision 12 (docs/M14.md §5): a password beside someone else's key or certificate is warned
/// of, since anyone it opens for could make an archive the password opens; beside one of your
/// own keys it isn't: you hold both.
#[test]
fn a_password_beside_someone_elses_key_is_warned_of() {
    let _argon2 = ARGON2.lock().unwrap_or_else(|e| e.into_inner());
    let keys = age_examples();
    let h = Here::new();
    h.ok(&["keys", "create", "Mine"]);
    h.ok(&["keys", "import", "Bob", "--text", &keys[3]]);
    let warns = |args: &[&str]| {
        let out = h.cmd().args(args).assert().success().get_output().clone();
        let stderr = String::from_utf8(out.stderr).unwrap();
        stderr.contains("your password opens")
    };
    let create = |name: &str, more: &[&str]| {
        let args = [&["create", name, "src", "--password", "pw"][..], more].concat();
        warns(&args)
    };
    assert!(!create("mine.bhive", &["--to", "Mine"]));
    assert!(create("bob.bhive", &["--to", "Bob"]));
    assert!(create("text.bhive", &["--to", &keys[1]]));
    assert!(create("both.bhive", &["--to", "Mine", "--to", "Bob"]));
    assert!(create("cert.bhive", &["--to-cert", &testdata("rsa.crt")]));

    // Adding a password to an archive only your key opens says nothing; adding Bob beside the
    // password then does.
    h.ok(&["create", "only.bhive", "src", "--to", "Mine"]);
    assert!(!warns(&["protect", "only.bhive", "--add-password", "pw"]));
    assert!(warns(&["protect", "only.bhive", "--to", "Bob"]));
}
