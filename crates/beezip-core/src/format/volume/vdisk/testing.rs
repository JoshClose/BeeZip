//! What the VMDK, QCOW2 and VDI readers' tests share: the fixtures `tests/fixtures/make-vdisk.sh`
//! makes in `tests/fixtures/thirdparty/vdisk/`, what each one's virtual disk is
//! (`expected.tsv`), and a short mutation run over them.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{Files, Handle, Origin, VirtualDisk};
use crate::{Error, Result, backend::External, io::Counter};

/// `tests/fixtures/thirdparty/vdisk/`.
pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/thirdparty/vdisk")
}

/// One line of `expected.tsv`.
#[derive(Debug, Clone)]
pub struct Expected {
    pub file: String,
    /// `read`, or the error kind opening or reading it gives.
    pub outcome: String,
    pub size: Option<u64>,
    pub digest: String,
}

pub fn expected() -> Vec<Expected> {
    let text = std::fs::read_to_string(dir().join("expected.tsv")).unwrap();
    text.lines()
        .skip(1)
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Expected {
                file: f[0].to_owned(),
                outcome: f[1].to_owned(),
                size: f[2].parse().ok(),
                digest: f[4].to_owned(),
            }
        })
        .collect()
}

/// The format a fixture is, by its extension.
pub fn kind_of(file: &str) -> External {
    match file.rsplit('.').next() {
        Some("vmdk") => External::Vmdk,
        Some("qcow2" | "qcow") => External::Qcow2,
        Some("vdi") => External::Vdi,
        e => panic!("no format for {e:?}"),
    }
}

/// The `kind` disk at `path`, its other files found by the rules every disk is opened with.
pub fn open_path(kind: External, path: &Path) -> Result<VirtualDisk> {
    let origin = Origin::of(path);
    let mut files = Files::new(&origin, Counter::new());
    let file = super::files::open_shared(path)?;
    let len = file
        .metadata()
        .map_err(|e| Error::io("reading a fixture", &e))?
        .len();
    super::open(kind, Handle::new(Box::new(file), len), origin, &mut files)
}

/// What `expected.tsv` records of a disk: SHA-256 over each 64 KiB-aligned chunk that isn't all
/// zeros, after its offset (8 bytes, little-endian), then the disk's size.
pub fn digest(d: &mut VirtualDisk) -> Result<String> {
    const CHUNK: u64 = 1 << 16;
    let len = d.len();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK as usize];
    let zero = vec![0u8; CHUNK as usize];
    let mut off = 0u64;
    while off < len {
        let n = CHUNK.min(len - off) as usize;
        d.read_exact(&mut buf[..n])
            .map_err(|e| crate::io::read_error(&e))?;
        if buf[..n] != zero[..n] {
            h.update(off.to_le_bytes());
            h.update(&buf[..n]);
        }
        off += n as u64;
    }
    h.update(len.to_le_bytes());
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// What opening and reading `e` gives, as `expected.tsv` writes it.
fn outcome(e: &Expected) -> (String, Option<(u64, String)>) {
    let path = dir().join(&e.file);
    let got = open_path(kind_of(&e.file), &path).and_then(|mut d| {
        let len = d.len();
        digest(&mut d).map(|s| (len, s))
    });
    match got {
        Ok(v) => ("read".to_owned(), Some(v)),
        Err(err) => (format!("{:?}", err.kind), None),
    }
}

/// Every fixture whose name ends with one of `exts` opens and reads as `expected.tsv` says.
pub fn check_all(exts: &[&str]) {
    let mut failures = Vec::new();
    let mut checked = 0;
    for e in expected()
        .iter()
        .filter(|e| exts.iter().any(|x| e.file.ends_with(x)))
    {
        checked += 1;
        let (kind, disk) = outcome(e);
        if kind != e.outcome {
            failures.push(format!("{}: {kind}, not {}", e.file, e.outcome));
            continue;
        }
        if let Some((len, digest)) = disk
            && (Some(len) != e.size || digest != e.digest)
        {
            failures.push(format!(
                "{}: {len} bytes, digest {digest}; expected {:?}, {}",
                e.file, e.size, e.digest
            ));
        }
    }
    assert!(checked > 0, "no fixtures for {exts:?}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The digest `expected.tsv` records for fixture `file`.
pub fn digest_of(file: &str) -> String {
    expected()
        .into_iter()
        .find(|e| e.file == file)
        .unwrap_or_else(|| panic!("no fixture {file}"))
        .digest
}

/// Of every fixture ending with one of `exts` that reads and is under 1 GiB: each 64 KiB its
/// files don't hold (no level holds data there) reads as zeros, so `held_in` is never low.
pub fn holdings_never_low(exts: &[&str]) {
    const CHUNK: u64 = 1 << 16;
    let mut buf = vec![0u8; CHUNK as usize];
    let zero = vec![0u8; CHUNK as usize];
    for e in expected().iter().filter(|e| {
        e.outcome == "read"
            && e.size.is_some_and(|s| s < 1 << 30)
            && exts.iter().any(|x| e.file.ends_with(x))
    }) {
        let mut d = open_path(kind_of(&e.file), &dir().join(&e.file)).unwrap();
        let len = d.len();
        let mut off = 0;
        while off < len {
            let n = CHUNK.min(len - off);
            let held = d.held_in(off, n);
            assert!(held <= n, "{}: {held} held of {n} at {off}", e.file);
            if held == 0 {
                std::io::Seek::seek(&mut d, std::io::SeekFrom::Start(off)).unwrap();
                d.read_exact(&mut buf[..n as usize]).unwrap();
                assert!(
                    buf[..n as usize] == zero[..n as usize],
                    "{}: data at {off}, which it says its files don't hold",
                    e.file
                );
            }
            off += n;
        }
    }
}

/// The error `file` (a fixture, or a path) gives, with its message.
pub fn error_of(kind: External, path: &Path) -> Error {
    match open_path(kind, path).and_then(|mut d| digest(&mut d)) {
        Ok(_) => panic!("{} read", path.display()),
        Err(e) => e,
    }
}

/// Copies `files` (fixtures, by their names) into `dir`, each under the name given.
pub fn copy_into(dir: &Path, files: &[(&str, &str)]) {
    for (from, to) in files {
        let to = dir.join(to);
        if let Some(p) = to.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::copy(self::dir().join(from), to).unwrap();
    }
}

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed | 1;
    move || {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Opens `copies` mutated copies of each fixture ending with one of `exts` (bytes flipped,
/// runs overwritten, the file cut short), each in a folder with the fixtures' other files, and
/// reads a few windows of what opens and asks it what it holds: none may panic, and none may
/// take long (each reader allocates only what its caps allow, checked by reading the code).
pub fn mutations(exts: &[&str], copies: usize, seed: u64) {
    let tmp = tempfile::tempdir().unwrap();
    for e in walkdir::WalkDir::new(dir()).min_depth(1) {
        let e = e.unwrap();
        if e.file_type().is_file() {
            let to = tmp.path().join(e.path().strip_prefix(dir()).unwrap());
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
    let mut next = rng(seed);
    let mut buf = vec![0u8; 1 << 16];
    for e in expected()
        .iter()
        .filter(|e| exts.iter().any(|x| e.file.ends_with(x)))
    {
        let path = tmp.path().join(&e.file);
        let original = std::fs::read(dir().join(&e.file)).unwrap();
        for _ in 0..copies {
            let mut d = original.clone();
            let n = |next: &mut dyn FnMut() -> u64, max: usize| {
                usize::try_from(next() % max.max(1) as u64).unwrap()
            };
            match next() % 4 {
                0 => {
                    for _ in 0..1 + n(&mut next, 8) {
                        let i = n(&mut next, d.len());
                        d[i] ^= 1 << n(&mut next, 8);
                    }
                }
                1 => {
                    // Somewhere in the first 4 KiB (headers, descriptors) most of the time.
                    let max = if next().is_multiple_of(4) {
                        d.len()
                    } else {
                        d.len().min(4096)
                    };
                    let i = n(&mut next, max);
                    let k = (1 + n(&mut next, 16)).min(d.len() - i);
                    let v = next().to_le_bytes();
                    for (j, b) in d[i..i + k].iter_mut().enumerate() {
                        *b = v[j % 8];
                    }
                }
                2 => {
                    let i = n(&mut next, d.len());
                    d[i..].fill(0xFF);
                }
                _ => {
                    let cut = n(&mut next, d.len());
                    d.truncate(cut);
                }
            }
            std::fs::write(&path, &d).unwrap();
            let start = std::time::Instant::now();
            if let Ok(mut disk) = open_path(kind_of(&e.file), &path) {
                let len = disk.len();
                let _ = disk.held_in(0, len);
                let _ = disk.properties();
                let _ = disk.notes();
                for at in [0, len / 3, len / 2, len.saturating_sub(70_000)] {
                    if std::io::Seek::seek(&mut disk, std::io::SeekFrom::Start(at)).is_ok() {
                        let _ = disk.read(&mut buf);
                    }
                }
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "{}: a mutation took {:?}",
                e.file,
                start.elapsed()
            );
        }
        std::fs::write(&path, &original).unwrap();
    }
}
