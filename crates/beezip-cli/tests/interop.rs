//! Interop with other tools (docs/M1.md §6), through the `beezip` binary:
//!
//! - Windows: every archive kind BeeZip writes passes `7z t`, and archives `7z a` makes extract
//!   identically. The formats to test come from `7z i`. With `BEEZIP_REQUIRE_7Z=1` (CI), a
//!   missing 7-Zip fails instead of skipping.
//! - Unix: GNU tar lists and extracts BeeZip's tars, and BeeZip reads GNU tar's, including a
//!   `--sparse` archive of a file with holes. `BEEZIP_REQUIRE_GNU_TAR=1` makes GNU tar required.

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
            "gz" => "gzip",
            "bz2" => "bzip2",
            "zst" => "zstd",
            "lz" => "lzip",
            "br" => "brotli",
            "sz" => "snappy",
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
        for kind in [
            "tar", "tar.gz", "tar.bz2", "tar.xz", "tar.lzma", "tar.lz", "tar.zst", "tar.lz4",
            "tar.br", "tar.sz",
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
        assert!(tested.len() >= 20, "{tested:?}");
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
            (
                "sparse-pax.tar",
                vec!["--sparse", "--format=pax", "-cf", "sparse-pax.tar", "tree"],
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
