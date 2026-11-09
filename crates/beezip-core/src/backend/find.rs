//! Finding 7-Zip (docs/M6.md §3.1): `[seven_zip] path`, then 7-Zip's registry keys, then
//! PATH, then Program Files. The first one new enough wins. What each candidate is gets
//! remembered per process with its size and modified time, so a 7-Zip installed or updated
//! while BeeZip runs is found without a restart.

use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime},
};

use super::{SevenZipOptions, process};
use crate::{Error, ErrorKind};

/// 25.00 and 25.01 fixed the link-extraction CVEs (CVE-2025-11001, -11002 and -55188), and
/// `-slmu` and `-slsl` came in 24.03.
pub const MIN_VERSION: (u32, u32) = (25, 1);

/// A 7-Zip the backend can run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenZip {
    pub exe: PathBuf,
    /// "7-Zip 26.00", "NanaZip 7.0".
    pub name: String,
    /// `(26, 0)`; `None` for a console that names no version BeeZip reads.
    pub version: Option<(u32, u32)>,
    /// Where it was found: "settings", "registry", "PATH" or "Program Files".
    pub found_in: &'static str,
}

/// Why there's no 7-Zip to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// `[seven_zip] enabled = false`.
    Disabled,
    /// None anywhere; or, with `configured`, none at `[seven_zip] path`.
    NotFound { configured: Option<PathBuf> },
    /// The best one found is older than [`MIN_VERSION`].
    TooOld(SevenZip),
    /// A program that isn't a 7-Zip console BeeZip can drive.
    Unusable { exe: PathBuf, why: String },
}

impl Missing {
    /// The error for opening a file of `what` (a format's display name) without 7-Zip.
    pub fn error(&self, what: &str) -> Error {
        let need = format!(
            "Opening this {what} needs 7-Zip {}.{:02} or newer",
            MIN_VERSION.0, MIN_VERSION.1
        );
        let message = match self {
            Self::Disabled => format!("{need}, which is turned off in Settings."),
            Self::NotFound { configured: None } => {
                format!("{need}. Install it from 7-zip.org, or set its path in Settings.")
            }
            Self::NotFound {
                configured: Some(p),
            } => format!(
                "{need}, and there's no 7-Zip at {} (the path set in Settings).",
                p.display()
            ),
            Self::TooOld(z) => format!(
                "{need}, and the one at {} is {}. Update it from 7-zip.org, or set the path of a newer one in Settings.",
                z.exe.display(),
                z.name
            ),
            Self::Unusable { exe, why } => {
                format!(
                    "{need}, and {} isn't one BeeZip can use: {why}.",
                    exe.display()
                )
            }
        };
        Error::new(ErrorKind::BackendUnavailable, message)
    }

    /// One line for Settings and `formats.list`.
    pub fn reason(&self) -> String {
        match self {
            Self::Disabled => "turned off in Settings".to_owned(),
            Self::NotFound { configured: None } => "not found".to_owned(),
            Self::NotFound {
                configured: Some(p),
            } => format!("not found at {}", p.display()),
            Self::TooOld(z) => format!(
                "{} at {} is too old: 7-Zip {}.{:02} or newer is needed",
                z.name,
                z.exe.display(),
                MIN_VERSION.0,
                MIN_VERSION.1
            ),
            Self::Unusable { exe, why } => format!("{}: {why}", exe.display()),
        }
    }
}

/// The 7-Zip to run under `opts`, or why there's none.
pub fn find(opts: &SevenZipOptions) -> Result<SevenZip, Missing> {
    if !opts.enabled {
        return Err(Missing::Disabled);
    }
    if let Some(p) = &opts.path {
        // A path the user set is the only one tried: falling back to another would hide
        // that it's wrong.
        if !p.is_file() {
            return Err(Missing::NotFound {
                configured: Some(p.clone()),
            });
        }
        return check(p, "settings");
    }
    let mut first_problem = None;
    for (exe, found_in) in candidates() {
        match check(&exe, found_in) {
            Ok(z) => return Ok(z),
            Err(m) => {
                first_problem.get_or_insert(m);
            }
        }
    }
    Err(first_problem.unwrap_or(Missing::NotFound { configured: None }))
}

/// Debug builds take `BEEZIP_7Z_SEARCH`: a folder searched instead of the registry, PATH and
/// Program Files (an empty value searches nowhere), so tests and manual checks decide what's
/// found without touching an installed 7-Zip. Release builds ignore it.
fn search_override() -> Option<OsString> {
    env::var_os("BEEZIP_7Z_SEARCH").filter(|_| cfg!(debug_assertions))
}

/// Every place 7-Zip may be, best first; missing files and repeats left out.
fn candidates() -> Vec<(PathBuf, &'static str)> {
    let mut out: Vec<(PathBuf, &'static str)> = Vec::new();
    let mut push = |exe: PathBuf, found_in: &'static str| {
        if exe.is_file() && !out.iter().any(|(e, _)| same_file(e, &exe)) {
            out.push((exe, found_in));
        }
    };
    let names: &[&str] = if cfg!(windows) {
        &["7z.exe", "7zz.exe", "7za.exe", "NanaZipC.exe"]
    } else {
        &["7zz", "7z", "7za"]
    };
    if let Some(dir) = search_override() {
        if !dir.is_empty() {
            for n in names {
                push(Path::new(&dir).join(n), "PATH");
            }
        }
        return out;
    }
    #[cfg(windows)]
    for root in [registry::HKCU, registry::HKLM] {
        for value in ["Path64", "Path"] {
            if let Some(dir) = registry::string(root, r"SOFTWARE\7-Zip", value) {
                push(Path::new(&dir).join("7z.exe"), "registry");
            }
        }
    }
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            for n in names {
                push(dir.join(n), "PATH");
            }
        }
    }
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
            if let Some(pf) = env::var_os(var) {
                push(Path::new(&pf).join(r"7-Zip\7z.exe"), "Program Files");
            }
        }
    }
    out
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// What a program was found to be, remembered with its size and modified time.
#[derive(Debug, Clone)]
struct Probed {
    exe: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    result: Result<(String, Option<(u32, u32)>), String>,
}

static PROBED: Mutex<Vec<Probed>> = Mutex::new(Vec::new());

fn check(exe: &Path, found_in: &'static str) -> Result<SevenZip, Missing> {
    let meta = std::fs::metadata(exe).ok();
    let len = meta.as_ref().map_or(0, std::fs::Metadata::len);
    let modified = meta.and_then(|m| m.modified().ok());
    let cached = PROBED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|p| p.exe == exe && p.len == len && p.modified == modified)
        .map(|p| p.result.clone());
    let result = cached.unwrap_or_else(|| {
        let result = probe(exe);
        let mut probed = PROBED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        probed.retain(|p| p.exe != exe);
        probed.push(Probed {
            exe: exe.to_path_buf(),
            len,
            modified,
            result: result.clone(),
        });
        result
    });
    match result {
        Ok((name, version)) => {
            let z = SevenZip {
                exe: exe.to_path_buf(),
                name,
                version,
                found_in,
            };
            match version {
                Some(v) if v < MIN_VERSION && is_seven_zip(&z.name) => Err(Missing::TooOld(z)),
                _ => Ok(z),
            }
        }
        Err(why) => Err(Missing::Unusable {
            exe: exe.to_path_buf(),
            why,
        }),
    }
}

fn is_seven_zip(name: &str) -> bool {
    name.starts_with("7-Zip") || name.starts_with("p7zip")
}

/// Runs `exe` with no arguments, which prints the banner and the usage, and reads its name and
/// version. A console that isn't 7-Zip's own (NanaZip's) is accepted when it takes the
/// switches BeeZip passes: an unknown one exits 7 before any archive is read.
fn probe(exe: &Path) -> Result<(String, Option<(u32, u32)>), String> {
    let timeout = Duration::from_secs(10);
    let (_, stdout) = process::output(exe, &[], timeout).map_err(|e| e.message)?;
    let text = String::from_utf8_lossy(&stdout);
    let banner = text.lines().map(str::trim).find(|l| !l.is_empty());
    let Some(banner) = banner else {
        return Err("it printed no banner".to_owned());
    };
    let (name, version) = parse_banner(banner)
        .ok_or_else(|| format!("its banner isn't 7-Zip's (\"{}\")", short(banner)))?;
    if is_seven_zip(&name) && version.is_some() {
        return Ok((name, version));
    }
    let missing = env::temp_dir().join("beezip-no-such-archive.7z");
    let args: Vec<OsString> = [
        "l",
        "-slt",
        "-slmu",
        "-slsl",
        "-sns-",
        "-sccUTF-8",
        "-scsUTF-8",
        "-bse2",
        "-p",
        "--",
    ]
    .iter()
    .map(OsString::from)
    .chain([missing.into_os_string()])
    .collect();
    let (exit, _) = process::output(exe, &args, timeout).map_err(|e| e.message)?;
    if exit.code == Some(7) {
        return Err("it doesn't take the switches BeeZip passes (-slmu, -slsl)".to_owned());
    }
    Ok((name, version))
}

fn short(s: &str) -> String {
    s.chars().take(60).collect()
}

/// `7-Zip 26.00 (x64) : …`, `7-Zip (a) 23.01 (x64) : …`, `p7zip Version 16.02 (…)`,
/// `NanaZip 7.0 (x64) : …`: the product and `major.minor`.
pub fn parse_banner(banner: &str) -> Option<(String, Option<(u32, u32)>)> {
    let product = ["7-Zip", "p7zip", "NanaZip"]
        .into_iter()
        .find(|p| banner.starts_with(p))?;
    let version = banner[product.len()..]
        .split_whitespace()
        .filter(|w| !w.starts_with('(') && *w != "Version")
        .take(2)
        .find_map(|w| {
            let (major, minor) = w.split_once('.')?;
            let minor: String = minor.chars().take_while(char::is_ascii_digit).collect();
            Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?))
        });
    let name = match version {
        Some((major, minor)) if product == "NanaZip" => format!("{product} {major}.{minor}"),
        Some((major, minor)) => format!("{product} {major}.{minor:02}"),
        None => product.to_owned(),
    };
    Some((name, version))
}

#[cfg(windows)]
mod registry {
    use std::ptr;

    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
        RegGetValueW,
    };

    pub const HKCU: HKEY = HKEY_CURRENT_USER;
    pub const HKLM: HKEY = HKEY_LOCAL_MACHINE;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// A `REG_SZ`, from the 64-bit view, where 7-Zip's 64-bit installer writes.
    #[allow(unsafe_code)]
    pub fn string(root: HKEY, key: &str, value: &str) -> Option<String> {
        let (k, v) = (wide(key), wide(value));
        let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY;
        let mut len: u32 = 0;
        // SAFETY: `k` and `v` are NUL-terminated; a null buffer asks only for the size.
        let rc = unsafe {
            RegGetValueW(
                root,
                k.as_ptr(),
                v.as_ptr(),
                flags,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut len,
            )
        };
        if rc != 0 || len == 0 || len > 64 * 1024 {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2)];
        // SAFETY: `buf` holds `len` bytes, and `len` tells the call so.
        let rc = unsafe {
            RegGetValueW(
                root,
                k.as_ptr(),
                v.as_ptr(),
                flags,
                ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banners() {
        let b = |s| parse_banner(s).unwrap();
        assert_eq!(
            b("7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12"),
            ("7-Zip 26.00".to_owned(), Some((26, 0)))
        );
        assert_eq!(
            b("7-Zip (a) 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20"),
            ("7-Zip 23.01".to_owned(), Some((23, 1)))
        );
        assert_eq!(
            b("p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits)"),
            ("p7zip 16.02".to_owned(), Some((16, 2)))
        );
        assert_eq!(
            b("NanaZip 7.0 (x64) : Copyright (c) 1999-2025 Igor Pavlov"),
            ("NanaZip 7.0".to_owned(), Some((7, 0)))
        );
        assert!(parse_banner("Usage: something").is_none());
        assert!((25, 1) <= (26, 0) && (23, 1) < MIN_VERSION && (25, 0) < MIN_VERSION);
    }

    #[test]
    fn a_configured_path_that_isnt_there() {
        let opts = SevenZipOptions {
            path: Some(PathBuf::from("Z:/nowhere/7z.exe")),
            enabled: true,
        };
        let missing = find(&opts).unwrap_err();
        assert!(matches!(
            missing,
            Missing::NotFound {
                configured: Some(_)
            }
        ));
        let e = missing.error("WIM image");
        assert_eq!(e.kind, ErrorKind::BackendUnavailable);
        assert!(
            e.message.starts_with(
                "Opening this WIM image needs 7-Zip 25.01 or newer, and there's no 7-Zip at"
            ),
            "{}",
            e.message
        );
        let off = SevenZipOptions {
            enabled: false,
            ..SevenZipOptions::default()
        };
        assert_eq!(find(&off), Err(Missing::Disabled));
    }
}
