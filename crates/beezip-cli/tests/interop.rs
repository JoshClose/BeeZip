//! Interop with other tools (docs/M1.md §6), through the `beezip` binary:
//!
//! - Windows: every archive kind BeeZip writes passes `7z t`, and archives `7z a` makes extract
//!   identically. The formats to test come from `7z i`. With `BEEZIP_REQUIRE_7Z=1` (CI), a
//!   missing 7-Zip fails instead of skipping.
//! - Unix: GNU tar lists and extracts BeeZip's tars, and BeeZip reads GNU tar's, including a
//!   `--sparse` archive of a file with holes. `BEEZIP_REQUIRE_GNU_TAR=1` makes GNU tar required.
//! - Linux: lzop, uncompress, cpio, ar, xorriso and unsquashfs read what BeeZip writes
//!   (`BEEZIP_REQUIRE_LINUX_TOOLS=1`). With `BEEZIP_IMAGES_OUT=<dir>`, the ISO and DMG it wrote
//!   are left there with their files' hashes, for CI's macOS job to mount (docs/M5.md §10).

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

fn beezip(args: &[&str], cwd: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_beezip"))
        .args(args)
        .current_dir(cwd)
        .env("BEEZIP_CONFIG", "no-such-beezip-config.toml")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "beezip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A small tree with text, binary, empty, nested and non-ASCII files.
fn make_tree(root: &Path) {
    let t = root.join("tree");
    let mut next = 0x9E37_79B9_u32;
    let blob: Vec<u8> = (0..65_536)
        .map(|_| {
            next ^= next << 13;
            next ^= next >> 17;
            next ^= next << 5;
            (next >> 24) as u8
        })
        .collect();
    let files: [(&str, Vec<u8>); 6] = [
        ("hello.txt", b"Hello, BeeZip!\n".to_vec()),
        (
            "docs/readme.md",
            b"BeeZip reads and writes archives. ".repeat(200),
        ),
        ("data/blob.bin", blob),
        ("empty.txt", Vec::new()),
        ("ünïcödé/名前.txt", "non-ASCII names\n".as_bytes().to_vec()),
        ("deep/a/b/c/d.txt", b"deep\n".to_vec()),
    ];
    for (path, data) in files {
        let p = t.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }
}

/// Every file under `dir` by relative path, with its SHA-256.
fn hashes(dir: &Path) -> BTreeMap<String, String> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e
                .path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let sum: String = Sha256::digest(std::fs::read(e.path()).unwrap())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            (rel, sum)
        })
        .collect()
}

/// A required tool: missing is a skip, or a failure when `var` is `1`.
fn require(tool: Option<PathBuf>, var: &str, name: &str) -> Option<PathBuf> {
    if tool.is_none() {
        assert!(
            std::env::var(var).as_deref() != Ok("1"),
            "{name} is required ({var}=1) but wasn't found"
        );
        eprintln!("skipping: {name} not found (set {var}=1 to require it)");
    }
    tool
}

#[cfg(windows)]
mod seven_zip {
    use std::collections::HashSet;

    use super::*;

    fn find() -> Option<PathBuf> {
        let installed = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
        if installed.is_file() {
            return Some(installed);
        }
        Command::new("7z")
            .arg("i")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| PathBuf::from("7z"))
    }

    fn seven_zip() -> Option<PathBuf> {
        require(find(), "BEEZIP_REQUIRE_7Z", "7-Zip")
    }

    /// The archive formats `7z i` lists, lowercased: `zip`, `tar`, `gzip`, `zstd`…
    fn formats(exe: &Path) -> HashSet<String> {
        let out = Command::new(exe).arg("i").output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut in_formats = false;
        let mut found = HashSet::new();
        for line in text.lines() {
            if line.starts_with("Formats:") {
                in_formats = true;
                continue;
            }
            if in_formats && line.trim().is_empty() {
                break;
            }
            if in_formats {
                // `<n> <flags> [<more flags>] <name> <extensions…>`; flags have dots, names don't.
                if let Some(name) = line.split_whitespace().skip(1).find(|t| !t.contains('.')) {
                    found.insert(name.to_lowercase());
                }
            }
        }
        found
    }

    fn seven(exe: &Path, args: &[&str], cwd: &Path) -> bool {
        Command::new(exe)
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap()
            .status
            .success()
    }

    /// The 7-Zip format a BeeZip archive kind needs, by its outer layer.
    fn needs(kind: &str) -> &str {
        match kind.rsplit('.').next().unwrap_or(kind) {
            "7z" => "7z",
            "gz" => "gzip",
            "bz2" => "bzip2",
            "zst" => "zstd",
            "lz" => "lzip",
            "br" => "brotli",
            "sz" => "snappy",
            "Z" => "z",
            other => other,
        }
    }

    #[test]
    fn every_beezip_archive_passes_7z_t() {
        let Some(exe) = seven_zip() else { return };
        let have = formats(&exe);
        assert!(
            have.contains("zip") && have.contains("tar"),
            "7z i: {have:?}"
        );
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        let mut tested = Vec::new();

        for method in ["store", "deflate", "bzip2", "zstd", "xz", "ppmd"] {
            // 7-Zip's zip handler reads zstd entries in the versions that have the zstd format.
            if method == "zstd" && !have.contains("zstd") {
                continue;
            }
            for (enc, pw) in [
                (None, None),
                (Some("aes256"), Some("pw")),
                (Some("zipcrypto"), Some("pw")),
            ] {
                let name = format!("{method}-{}.zip", enc.unwrap_or("plain"));
                let mut args = vec!["create", &name, "tree", "-m", method];
                if let (Some(enc), Some(pw)) = (enc, pw) {
                    args.extend(["--password", pw, "--encryption", enc]);
                }
                beezip(&args, root.path());
                let pw_arg = format!("-p{}", pw.unwrap_or(""));
                let mut t = vec!["t", name.as_str()];
                if pw.is_some() {
                    t.push(&pw_arg);
                }
                assert!(seven(&exe, &t, root.path()), "7z t {name}");
                tested.push(name);
            }
        }
        // Everything but lzop, which 7-Zip doesn't read (docs/M5.md §10).
        for kind in [
            "tar",
            "tar.gz",
            "tar.bz2",
            "tar.xz",
            "tar.lzma",
            "tar.lz",
            "tar.zst",
            "tar.lz4",
            "tar.br",
            "tar.sz",
            "tar.Z",
            "cpio",
            "cpio.gz",
            "cpio.bz2",
            "cpio.xz",
            "cpio.lzma",
            "cpio.lz",
            "cpio.zst",
            "cpio.lz4",
            "cpio.br",
            "cpio.sz",
            "cpio.Z",
            "ar",
            "cab",
            "iso",
            "dmg",
        ] {
            if !have.contains(needs(kind)) {
                eprintln!("7-Zip doesn't read {kind}; not tested");
                continue;
            }
            let name = format!("t.{kind}");
            beezip(&["create", &name, "tree"], root.path());
            assert!(seven(&exe, &["t", &name], root.path()), "7z t {name}");
            tested.push(name);
        }
        for method in ["store", "mszip"] {
            let name = format!("{method}.cab");
            beezip(&["create", &name, "tree", "-m", method], root.path());
            assert!(seven(&exe, &["t", &name], root.path()), "7z t {name}");
            tested.push(name);
        }
        // squashfs in every compressor 7-Zip 26.00 reads: it can't open lz4 images.
        for method in ["gzip", "xz", "zstd", "lzo"] {
            let name = format!("{method}.squashfs");
            beezip(&["create", &name, "tree", "-m", method], root.path());
            assert!(seven(&exe, &["t", &name], root.path()), "7z t {name}");
            tested.push(name);
        }
        // This 7-Zip lacks lzip, lz4, brotli and snappy; one with them tests 44.
        assert!(tested.len() >= 36, "{tested:?}");
    }

    /// cpio, ar, CAB, `.Z` and the disk images from BeeZip extract to the same bytes in 7-Zip,
    /// and CABs in Windows' `expand.exe` too (docs/M5.md §10).
    #[test]
    fn m5_archives_extract_identically_elsewhere() {
        let Some(exe) = seven_zip() else { return };
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        let want = hashes(&root.path().join("tree"));
        for (name, args) in [
            ("t.tar.Z", vec![]),
            ("t.cpio", vec![]),
            ("t.cpio.xz", vec![]),
            ("t.ar", vec![]),
            ("s.cab", vec!["-m", "store"]),
            ("m.cab", vec!["-m", "mszip"]),
            ("t.iso", vec![]),
            ("t.squashfs", vec![]),
            ("x.squashfs", vec!["-m", "xz"]),
            ("t.dmg", vec![]),
        ] {
            let mut a = vec!["create", name, "tree"];
            a.extend(args);
            beezip(&a, root.path());
            // A compressed tar or cpio is two layers to 7-Zip: the outer one is unpacked first.
            let inner = if name.matches('.').count() > 1 {
                let dest = root.path().join(format!("o-{name}"));
                let out = format!("-o{}", dest.display());
                assert!(seven(&exe, &["x", name, &out], root.path()), "7z x {name}");
                dest.join(name.rsplit_once('.').unwrap().0)
            } else {
                root.path().join(name)
            };
            let dest = root.path().join(format!("x-{name}"));
            let out = format!("-o{}", dest.display());
            let inner = inner.to_str().unwrap().to_owned();
            assert!(
                seven(&exe, &["x", &inner, &out], root.path()),
                "7z x {inner}"
            );
            if name.ends_with(".dmg") {
                // 7-Zip puts a DMG's files in a folder named after the volume, and keeps HFS+'s
                // decomposed names: the ASCII paths must match, and every file's bytes.
                let got = hashes(&dest.join("t").join("tree"));
                let ascii = |m: &BTreeMap<String, String>| -> BTreeMap<String, String> {
                    m.iter()
                        .filter(|(p, _)| p.is_ascii())
                        .map(|(p, h)| (p.clone(), h.clone()))
                        .collect()
                };
                assert_eq!(ascii(&got), ascii(&want), "{name} in 7-Zip");
                let sums = |m: &BTreeMap<String, String>| {
                    let mut v: Vec<String> = m.values().cloned().collect();
                    v.sort();
                    v
                };
                assert_eq!(sums(&got), sums(&want), "{name}'s bytes in 7-Zip");
                continue;
            }
            let mut got = hashes(&dest.join("tree"));
            let mut want = want.clone();
            if name.ends_with(".ar") {
                // ar marks no encoding, and 7-Zip reads its names in the OEM code page: the
                // UTF-8 name comes out garbled there (GNU ar reads it right, docs/M5.md §16).
                got.retain(|p, _| p.is_ascii());
                want.retain(|p, _| p.is_ascii());
            }
            assert_eq!(got, want, "{name} in 7-Zip");
        }
        let expand = PathBuf::from(r"C:\Windows\System32\expand.exe");
        for name in ["s.cab", "m.cab"] {
            let dest = root.path().join(format!("e-{name}"));
            std::fs::create_dir(&dest).unwrap();
            let out = Command::new(&expand)
                .args([name, "-F:*", dest.to_str().unwrap()])
                .current_dir(root.path())
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "expand {name}: {}",
                String::from_utf8_lossy(&out.stdout)
            );
            assert_eq!(hashes(&dest.join("tree")), want, "{name} in expand.exe");
        }
    }

    #[test]
    fn archives_7z_makes_extract_identically() {
        let Some(exe) = seven_zip() else { return };
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        let want = hashes(&root.path().join("tree"));

        let mut made = Vec::new();
        for m in ["Copy", "Deflate", "Deflate64", "BZip2", "LZMA", "PPMd"] {
            let name = format!("7z-{m}.zip");
            assert!(
                seven(
                    &exe,
                    &["a", "-tzip", &format!("-mm={m}"), &name, "tree"],
                    root.path()
                ),
                "{name}"
            );
            made.push(name);
        }
        assert!(seven(&exe, &["a", "-ttar", "7z.tar", "tree"], root.path()));
        made.push("7z.tar".into());
        for name in &made {
            let dest = root.path().join(format!("x-{name}"));
            beezip(&["x", name, "-o", dest.to_str().unwrap()], root.path());
            assert_eq!(hashes(&dest.join("tree")), want, "{name}");
        }

        // Single-file codecs.
        let readme = root.path().join("tree/docs/readme.md");
        for (t, ext) in [("gzip", "gz"), ("bzip2", "bz2"), ("xz", "xz")] {
            let name = format!("readme.md.{ext}");
            assert!(
                seven(
                    &exe,
                    &[&format!("-t{t}"), "a", &name, readme.to_str().unwrap()],
                    root.path()
                ),
                "{name}"
            );
            let out = root.path().join(format!("readme-{t}.md"));
            beezip(
                &["decompress", &name, "-o", out.to_str().unwrap()],
                root.path(),
            );
            assert_eq!(
                std::fs::read(&out).unwrap(),
                std::fs::read(&readme).unwrap(),
                "{name}"
            );
        }
    }

    /// Every archive an edit writes passes `7z t` (docs/M5.md §10): BeeZip's own in each
    /// format and method, plain and encrypted, and 7-Zip's (LZMA, ZipCrypto, AES, solid 7z),
    /// after an add, a rename of a folder and a removal; and a convert between formats.
    #[test]
    fn every_beezip_edit_passes_7z_t() {
        let Some(exe) = seven_zip() else { return };
        let have = formats(&exe);
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        std::fs::write(
            root.path().join("added.txt"),
            "added by beezip
"
            .repeat(50),
        )
        .unwrap();
        let fixtures =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty");
        let mut cases: Vec<(String, Option<&str>)> = Vec::new();
        for (name, args, pw) in [
            ("deflate.zip", vec![], None),
            ("lzma2.7z", vec![], None),
            (
                "ppmd-nonsolid.7z",
                vec!["-m", "ppmd", "--solid=false"],
                None,
            ),
            ("aes.zip", vec!["-p", "pw"], Some("pw")),
            (
                "zipcrypto.zip",
                vec!["-p", "pw", "--encryption", "zipcrypto"],
                Some("pw"),
            ),
            ("aes.7z", vec!["-p", "pw"], Some("pw")),
            (
                "aes-names.7z",
                vec!["-p", "pw", "--encrypt-headers=false"],
                Some("pw"),
            ),
            ("t.tar", vec![], None),
            ("t.tar.gz", vec![], None),
            ("t.tar.zst", vec![], None),
            ("t.tar.xz", vec![], None),
        ] {
            let mut a = vec!["create", name, "tree"];
            a.extend(args.iter().copied());
            beezip(&a, root.path());
            cases.push((name.to_owned(), pw));
        }
        for (name, pw) in [
            ("7z-lzma.zip", None),
            ("7z-lzma-zipcrypto.zip", Some("beezip")),
            ("7z-aes256.zip", Some("beezip")),
            ("7z-descriptors.zip", None),
            ("7z-lzma.7z", None),
            ("7z-bcj2.7z", None),
            ("7z-aes-mhe.7z", Some("beezip")),
        ] {
            std::fs::copy(fixtures.join(name), root.path().join(name)).unwrap();
            cases.push((name.to_owned(), pw));
        }
        let mut tested = 0;
        for (name, pw) in &cases {
            if !have.contains(needs(name)) {
                eprintln!("7-Zip doesn't read {name}; not tested");
                continue;
            }
            let pw_args: Vec<String> = pw
                .map(|p| vec!["-p".to_owned(), p.to_owned()])
                .unwrap_or_default();
            let with_pw = |mut a: Vec<String>| {
                a.extend(pw_args.iter().cloned());
                a
            };
            let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
            let steps = [
                with_pw(s(&["add", name, "added.txt", "--dir", "tree/docs"])),
                with_pw(s(&["rename", name, "tree/docs", "tree/papers"])),
                with_pw(s(&["remove", name, "tree/hello.txt"])),
            ];
            for step in steps {
                let args: Vec<&str> = step.iter().map(String::as_str).collect();
                beezip(&args, root.path());
                let p = format!("-p{}", pw.unwrap_or(""));
                assert!(
                    seven(&exe, &["t", name, &p], root.path()),
                    "7z t {name} after {args:?}"
                );
            }
            tested += 1;
        }
        // Converts: a raw copy, a re-encoded stream, and across formats.
        for (from, to) in [
            ("deflate.zip", "copy.zip"),
            ("t.tar.gz", "t2.tar.zst"),
            ("t.tar", "c.7z"),
            ("lzma2.7z", "c.zip"),
        ] {
            beezip(&["convert", from, to], root.path());
            assert!(seven(&exe, &["t", to], root.path()), "7z t {to}");
        }
        assert!(tested >= 15, "{tested}");
    }

    /// Every 7z BeeZip writes passes `7z t` (docs/M3.md §6): each method, solid and not, with
    /// no password, AES, and AES with encrypted names; multithreaded LZMA2; and a split set,
    /// tested from its first part.
    #[test]
    fn every_beezip_7z_passes_7z_t() {
        let Some(exe) = seven_zip() else { return };
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        let mut tested = 0;
        for method in ["lzma2", "lzma", "ppmd", "bzip2", "deflate", "copy"] {
            for solid in ["--solid=true", "--solid=false"] {
                for (pw, headers) in [
                    (None, None),
                    (Some("pw"), Some("true")),
                    (Some("pw"), Some("false")),
                ] {
                    let name = format!(
                        "{method}{solid}-{}-{}.7z",
                        pw.unwrap_or("plain"),
                        headers.unwrap_or("x")
                    )
                    .replace("--solid=", "-");
                    let mut args = vec!["create", &name, "tree", "-m", method, solid];
                    let he = headers.map(|h| format!("--encrypt-headers={h}"));
                    if let (Some(pw), Some(he)) = (pw, he.as_deref()) {
                        args.extend(["--password", pw, he]);
                    }
                    beezip(&args, root.path());
                    let mut t = vec!["t", name.as_str()];
                    if pw.is_some() {
                        t.push("-ppw");
                    }
                    assert!(seven(&exe, &t, root.path()), "7z t {name}");
                    tested += 1;
                }
            }
        }
        beezip(
            &["create", "mt.7z", "tree", "--threads", "4", "-l", "9"],
            root.path(),
        );
        assert!(seven(&exe, &["t", "mt.7z"], root.path()), "7z t mt.7z");
        beezip(
            &["create", "split.7z", "tree", "-p", "pw", "-v", "8k"],
            root.path(),
        );
        assert!(
            root.path().join("split.7z.003").is_file(),
            "split into volumes"
        );
        assert!(
            seven(&exe, &["t", "split.7z.001", "-ppw"], root.path()),
            "7z t split.7z.001"
        );
        assert_eq!(tested, 36);
    }

    /// BeeZip extracts every 7z and RAR fixture as `7z x` does: the same bytes and the same
    /// mtimes. An archive with a password per entry is extracted by 7-Zip once per password, and
    /// each file must match one of those passes.
    #[test]
    fn sevenz_and_rar_fixtures_extract_like_7z_x() {
        let Some(exe) = seven_zip() else { return };
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let text = std::fs::read_to_string(fixtures.join("manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut checked = 0;
        for (n, fx) in manifest["fixtures"].as_array().unwrap().iter().enumerate() {
            let chain = fx["chain"].as_str().unwrap();
            if chain != "7z" && chain != "rar" {
                continue;
            }
            let file = fx["file"].as_str().unwrap();
            let path = fixtures.join("thirdparty").join(file);
            let mut passwords: Vec<String> = fx["passwords"]
                .as_array()
                .map(|a| a.iter().map(|p| p.as_str().unwrap().to_owned()).collect())
                .unwrap_or_default();
            if passwords.is_empty()
                && let Some(p) = fx["password"].as_str()
            {
                passwords.push(p.to_owned());
            }

            let ours = root.path().join(format!("b{n}"));
            let mut args = vec![
                "x".to_owned(),
                path.display().to_string(),
                "-o".to_owned(),
                ours.display().to_string(),
            ];
            for p in passwords.iter().take(1) {
                args.extend(["-p".to_owned(), p.clone()]);
            }
            // A password per entry needs the prompt BeeZip gives a TTY; without one, extract
            // what the first password opens and compare that.
            let out = Command::new(env!("CARGO_BIN_EXE_beezip"))
                .args(&args)
                .current_dir(root.path())
                .env("BEEZIP_CONFIG", "no-such-beezip-config.toml")
                .output()
                .unwrap();
            // Links are off by default: a fixture with symlinks skips them and exits 14.
            let links_skipped =
                out.status.code() == Some(14) && fx["symlinks"].as_u64().unwrap_or(0) > 0;
            assert!(
                out.status.success() || links_skipped || passwords.len() > 1,
                "beezip x {file}: {}",
                String::from_utf8_lossy(&out.stderr)
            );

            let mut passes = Vec::new();
            for (i, p) in passwords.iter().map(Some).chain([None]).enumerate() {
                if p.is_none() && !passwords.is_empty() {
                    break;
                }
                let theirs = root.path().join(format!("s{n}-{i}"));
                let mut a = vec![
                    "x".to_owned(),
                    "-y".to_owned(),
                    format!("-o{}", theirs.display()),
                    path.display().to_string(),
                ];
                if let Some(p) = p {
                    a.push(format!("-p{p}"));
                }
                let _ = Command::new(&exe).args(&a).output().unwrap();
                passes.push(theirs);
            }

            let ours_files = hashes(&ours);
            assert!(!ours_files.is_empty(), "{file}: BeeZip extracted nothing");
            for (rel, sum) in &ours_files {
                let ours_path = ours.join(rel);
                // 7-Zip decodes this Unix RAR 4 name in the OEM code page; BeeZip reads it as
                // the UTF-8 it is (fetch-rar.ps1 has the same fix).
                let their_rel = match rel.as_str() {
                    "abcdefghijklmnopqrsテスト.txt" => "abcdefghijklmnopqrsπâåπé╣πâê.txt",
                    r => r,
                };
                let matched = passes.iter().find(|p| {
                    let theirs = p.join(their_rel);
                    theirs.is_file() && hashes_one(&theirs) == *sum
                });
                let Some(pass) = matched else {
                    panic!("{file}: `{rel}` differs from 7z x");
                };
                let t = |p: &Path| std::fs::metadata(p).unwrap().modified().unwrap();
                let (a, b) = (t(&ours_path), t(&pass.join(their_rel)));
                // RAR 1.5–4 keeps DOS (local) times. UnRAR, and so BeeZip, converts them with
                // the offset in force at that date; 7-Zip with today's (the
                // LocalFileTimeToFileTime behaviour), so across a DST change they differ by an
                // hour.
                let dos = chain == "rar" && !file.contains("rar5");
                let off = a
                    .duration_since(b)
                    .or_else(|_| b.duration_since(a))
                    .unwrap();
                assert!(
                    a == b || (dos && off == std::time::Duration::from_secs(3600)),
                    "{file}: mtime of `{rel}`: {a:?} vs {b:?}"
                );
            }
            checked += 1;
        }
        assert!(checked >= 40, "{checked} fixtures checked");
    }
}

/// One file's SHA-256.
fn hashes_one(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(unix)]
mod gnu_tar {
    use super::*;

    fn find() -> Option<PathBuf> {
        ["tar", "gtar"].into_iter().map(PathBuf::from).find(|t| {
            Command::new(t)
                .arg("--version")
                .output()
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("GNU tar"))
        })
    }

    fn gnu_tar() -> Option<PathBuf> {
        require(find(), "BEEZIP_REQUIRE_GNU_TAR", "GNU tar")
    }

    fn tar(exe: &Path, args: &[&str], cwd: &Path) -> String {
        let out = Command::new(exe)
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "tar {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn gnu_tar_reads_beezip_tars() {
        let Some(exe) = gnu_tar() else { return };
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        let want = hashes(&root.path().join("tree"));
        for kind in ["tar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst"] {
            let name = format!("t.{kind}");
            beezip(&["create", &name, "tree"], root.path());
            let listing = tar(&exe, &["-tf", &name], root.path());
            assert!(listing.contains("tree/docs/readme.md"), "{kind}: {listing}");
            let dest = root.path().join(format!("x-{kind}"));
            std::fs::create_dir(&dest).unwrap();
            tar(
                &exe,
                &["-xf", &name, "-C", dest.to_str().unwrap()],
                root.path(),
            );
            assert_eq!(hashes(&dest.join("tree")), want, "{kind}");
        }
    }

    #[test]
    fn beezip_reads_gnu_tars_including_sparse_files() {
        let Some(exe) = gnu_tar() else { return };
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        // A 4 MiB file that is mostly a hole.
        let sparse = root.path().join("tree/sparse.bin");
        {
            use std::{
                io::{Seek, SeekFrom, Write},
                os::unix::fs::FileExt,
            };
            let mut f = std::fs::File::create(&sparse).unwrap();
            f.set_len(4 << 20).unwrap();
            f.write_at(b"middle", 1 << 20).unwrap();
            f.seek(SeekFrom::End(-4)).unwrap();
            f.write_all(b"end!").unwrap();
        }
        let want = hashes(&root.path().join("tree"));
        for (name, args) in [
            ("gnu.tar", vec!["--format=gnu", "-cf", "gnu.tar", "tree"]),
            ("pax.tar", vec!["--format=pax", "-cf", "pax.tar", "tree"]),
            (
                "ustar.tar",
                vec!["--format=ustar", "-cf", "ustar.tar", "tree"],
            ),
            (
                "sparse.tar",
                vec!["--sparse", "--format=gnu", "-cf", "sparse.tar", "tree"],
            ),
            // pax sparse files, which the tar crate doesn't decode: 1.0 (the default), 0.1, 0.0.
            (
                "sparse-pax.tar",
                vec!["--sparse", "--format=pax", "-cf", "sparse-pax.tar", "tree"],
            ),
            (
                "sparse-pax01.tar",
                vec![
                    "--sparse",
                    "--format=pax",
                    "--sparse-version=0.1",
                    "-cf",
                    "sparse-pax01.tar",
                    "tree",
                ],
            ),
            (
                "sparse-pax00.tar",
                vec![
                    "--sparse",
                    "--format=pax",
                    "--sparse-version=0.0",
                    "-cf",
                    "sparse-pax00.tar",
                    "tree",
                ],
            ),
            ("gz.tar.gz", vec!["-czf", "gz.tar.gz", "tree"]),
            ("zst.tar.zst", vec!["--zstd", "-cf", "zst.tar.zst", "tree"]),
        ] {
            tar(&exe, &args, root.path());
            let dest = root.path().join(format!("x-{name}"));
            beezip(&["x", name, "-o", dest.to_str().unwrap()], root.path());
            assert_eq!(hashes(&dest.join("tree")), want, "{name}");
        }
    }
}

/// The Linux tools on BeeZip's output (docs/M5.md §10): `lzop -t`, `uncompress`, `cpio -it` and
/// `ar t`. CI's Linux job installs them and sets `BEEZIP_REQUIRE_LINUX_TOOLS=1`.
#[cfg(unix)]
mod linux_tools {
    use std::{io::Write, process::Stdio};

    use super::*;

    fn found(name: &str, arg: &str) -> Option<PathBuf> {
        Command::new(name)
            .arg(arg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()
            .map(|_| PathBuf::from(name))
    }

    /// Runs `exe`, with `stdin` fed to it, and returns what it printed.
    fn run(exe: &Path, args: &[&str], cwd: &Path, stdin: Option<&[u8]>) -> Vec<u8> {
        let mut child = Command::new(exe)
            .args(args)
            .current_dir(cwd)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(data) = stdin {
            child.stdin.take().unwrap().write_all(data).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{} {args:?}: {}",
            exe.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    #[test]
    fn linux_tools_read_beezip_output() {
        let var = "BEEZIP_REQUIRE_LINUX_TOOLS";
        let (Some(lzop), Some(uncompress), Some(cpio), Some(ar)) = (
            require(found("lzop", "-V"), var, "lzop"),
            require(found("uncompress", "-V"), var, "uncompress"),
            require(found("cpio", "--version"), var, "cpio"),
            require(found("ar", "--version"), var, "ar"),
        ) else {
            return;
        };
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        let readme = std::fs::read(root.path().join("tree/docs/readme.md")).unwrap();
        let blob = std::fs::read(root.path().join("tree/data/blob.bin")).unwrap();

        // lzop: a bare file and a tar, tested and decoded.
        beezip(
            &[
                "compress",
                "tree/docs/readme.md",
                "-c",
                "lzop",
                "-o",
                "readme.md.lzo",
            ],
            root.path(),
        );
        run(&lzop, &["-t", "readme.md.lzo"], root.path(), None);
        let out = run(&lzop, &["-dc", "readme.md.lzo"], root.path(), None);
        assert_eq!(out, readme);
        beezip(&["create", "t.tar.lzo", "tree"], root.path());
        run(&lzop, &["-t", "t.tar.lzo"], root.path(), None);

        // .Z: text, and random data, which makes the table clear and the width grow.
        for (file, want) in [
            ("tree/docs/readme.md", &readme),
            ("tree/data/blob.bin", &blob),
        ] {
            let out = format!("{}.Z", file.rsplit('/').next().unwrap());
            beezip(
                &["compress", file, "-c", "compress", "-o", &out],
                root.path(),
            );
            let got = run(&uncompress, &["-c", &out], root.path(), None);
            assert_eq!(&got, want, "{out}");
        }

        // cpio: listed, and extracted to the same bytes.
        beezip(&["create", "t.cpio", "tree"], root.path());
        let bytes = std::fs::read(root.path().join("t.cpio")).unwrap();
        let listing = run(&cpio, &["-it"], root.path(), Some(&bytes));
        let listing = String::from_utf8_lossy(&listing).into_owned();
        assert!(listing.contains("tree/docs/readme.md"), "{listing}");
        let dest = root.path().join("x-cpio");
        std::fs::create_dir(&dest).unwrap();
        run(&cpio, &["-idm", "--quiet"], &dest, Some(&bytes));
        assert_eq!(
            hashes(&dest.join("tree")),
            hashes(&root.path().join("tree"))
        );

        // ar: every member listed, with its bytes.
        beezip(&["create", "t.ar", "tree"], root.path());
        let listing = run(&ar, &["t", "t.ar"], root.path(), None);
        let listing = String::from_utf8_lossy(&listing).into_owned();
        for name in [
            "tree/hello.txt",
            "tree/docs/readme.md",
            "tree/deep/a/b/c/d.txt",
        ] {
            assert!(listing.lines().any(|l| l == name), "{name} in {listing}");
        }
        // `P`: match the full path, not just the name.
        let got = run(
            &ar,
            &["pP", "t.ar", "tree/docs/readme.md"],
            root.path(),
            None,
        );
        assert_eq!(got, readme);
    }

    /// xorriso and unsquashfs read BeeZip's ISO and squashfs images: every file listed, and
    /// extracted to the same bytes. With `BEEZIP_IMAGES_OUT`, the ISO and a DMG are kept for
    /// macOS, beside `hashes.json` (path → SHA-256 of every file of the tree).
    #[test]
    fn linux_tools_read_beezip_images() {
        let var = "BEEZIP_REQUIRE_LINUX_TOOLS";
        let (Some(xorriso), Some(unsquashfs)) = (
            require(found("xorriso", "-version"), var, "xorriso"),
            require(found("unsquashfs", "-version"), var, "unsquashfs"),
        ) else {
            return;
        };
        let root = tempfile::tempdir().unwrap();
        make_tree(root.path());
        let want = hashes(&root.path().join("tree"));

        // ISO: Rock Ridge's names, as xorriso finds them, and its extraction.
        beezip(&["create", "t.iso", "tree"], root.path());
        let found = run(
            &xorriso,
            &["-indev", "t.iso", "-find", "/", "-type", "f"],
            root.path(),
            None,
        );
        let found = String::from_utf8_lossy(&found).into_owned();
        for path in want.keys() {
            assert!(
                found.contains(&format!("'/tree/{path}'")),
                "{path} in {found}"
            );
        }
        let dest = root.path().join("x-iso");
        run(
            &xorriso,
            &[
                "-osirrox",
                "on",
                "-indev",
                "t.iso",
                "-extract",
                "/",
                dest.to_str().unwrap(),
            ],
            root.path(),
            None,
        );
        assert_eq!(hashes(&dest.join("tree")), want, "t.iso in xorriso");

        // squashfs, in each compressor: the superblock, the listing and the files.
        for method in ["gzip", "xz", "zstd", "lz4", "lzo"] {
            let name = format!("t-{method}.squashfs");
            beezip(&["create", &name, "tree", "-m", method], root.path());
            let sb = run(&unsquashfs, &["-s", &name], root.path(), None);
            let sb = String::from_utf8_lossy(&sb).into_owned();
            assert!(
                sb.contains(&format!("Compression {method}")),
                "{name}: {sb}"
            );
            let listing = run(&unsquashfs, &["-l", &name], root.path(), None);
            let listing = String::from_utf8_lossy(&listing).into_owned();
            for path in want.keys() {
                assert!(
                    listing.contains(&format!("squashfs-root/tree/{path}")),
                    "{path} in {name}: {listing}"
                );
            }
            let dest = root.path().join(format!("x-{method}"));
            run(
                &unsquashfs,
                &["-q", "-d", dest.to_str().unwrap(), &name],
                root.path(),
                None,
            );
            assert_eq!(hashes(&dest.join("tree")), want, "{name} in unsquashfs");
        }

        if let Some(out) = std::env::var_os("BEEZIP_IMAGES_OUT") {
            let out = PathBuf::from(out);
            std::fs::create_dir_all(&out).unwrap();
            beezip(&["create", "t.dmg", "tree"], root.path());
            for name in ["t.iso", "t.dmg"] {
                std::fs::copy(root.path().join(name), out.join(name)).unwrap();
            }
            let json = serde_json::to_string_pretty(&want).unwrap();
            std::fs::write(out.join("hashes.json"), json).unwrap();
        }
    }
}
