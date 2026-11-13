//! The files a virtual disk names besides itself: a differencing disk's parent, a VMDK's extents,
//! a QCOW2's backing and data files (docs/M8.md §3.6, decision 4). They're opened only by these
//! rules.
//!
//! - **Where, in order:**
//!   1. the path as recorded, when it's relative, from the naming file's folder, staying on that
//!      file's drive or share;
//!   2. the last part of each recorded name, beside the naming file (so
//!      `/var/lib/libvirt/images/base.qcow2` and `C:\VMs\base.vhdx` from another machine still
//!      resolve);
//!   3. for a parent that carries an identity BeeZip checks (VHD, VHDX, VMDK), the absolute path
//!      as recorded, on a local drive only.
//! - **Never:** a UNC path (`\\server\share`, `//server`), `\\?\UNC`, a device path (`\\.\`,
//!   `\\?\GLOBALROOT`, `/dev/…`), a mapped network drive, a `json:` or `proto://` name, an
//!   alternate stream, a DOS device name (`NUL`, `COM1`), a link on the way that leads off the
//!   local drives, or anything that isn't a regular file. Opening a UNC path would send the
//!   user's NTLM hash to whoever wrote the disk. A name that's only such a path is `Unsafe`, not
//!   a 7-Zip fallback.
//! - **Identity:** each candidate goes to the format's check (a VHDX's DataWriteGuid, a VHD's
//!   unique id, a VMDK's CID, a VDI's uuids); one that fails is passed over for the next.
//! - **Bounds:** at most [`MAX_DEPTH`] levels and [`MAX_FILES`] files a disk; a file already in
//!   the chain (by its canonical path) is `Corrupt`.
//! - **Nothing found:** `NotFound`, naming every place looked and why each failed. VMware and
//!   Hyper-V refuse such a chain too, and 7-Zip can't read it either.
//! - Every file opened is read through the archive's counter, so progress sees it.

use std::{
    collections::HashSet,
    fs::File,
    path::{Component, Path, PathBuf},
};

use super::Handle;
use crate::{Error, ErrorKind, Result, format::volume::Input, io::Counter, io::CountingReader};

/// The most levels a disk may have, the opened image included. Hyper-V allows a VM 50
/// checkpoints.
pub const MAX_DEPTH: usize = 64;
/// The most files one disk may open: extents, parents, data files and the headers of the VDIs
/// looked through for a parent.
pub const MAX_FILES: usize = 4096;
/// The most `.vdi` files whose headers are read looking for a VDI's parent.
pub const MAX_VDI_SCAN: usize = 1024;

/// Where a disk's file is.
#[derive(Debug, Clone)]
pub struct Origin {
    /// Its path, absolute: what the files it names are looked for beside.
    pub path: PathBuf,
    /// Its file name, for messages and Info.
    pub name: String,
}

impl Origin {
    /// The file at `path`, made absolute from the working folder.
    pub fn of(path: &Path) -> Self {
        let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self { path, name }
    }

    /// The folder it's in.
    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new(""))
    }
}

/// What a format's check made of a candidate: the level(s) it opened, or why it isn't the file
/// named (its identity differs), to try the next.
pub type Verdict<T> = std::result::Result<T, String>;

/// A format's check of a candidate (see [`Files::find`]).
pub type Accept<'a, T> = dyn FnMut(&mut Files, Handle, Origin) -> Result<Verdict<T>> + 'a;

/// One place to look, and how it was found.
#[derive(Debug, Clone)]
struct Candidate {
    path: PathBuf,
    how: String,
    /// Rule 3: an absolute path, which must be on a local drive.
    absolute: bool,
}

/// Opens the files one disk names (see the module's notes).
pub struct Files {
    counter: Counter,
    /// What a decoded grain or cluster may take: `decoder_memory` (docs/M11.md §6.1).
    pub memory: u64,
    /// The canonical paths of the files in the chain so far.
    chain: HashSet<String>,
    opened: usize,
    depth: usize,
    /// The file names of the parents found, in order, for Info.
    parents: Vec<String>,
}

impl Files {
    /// For the disk at `origin`, counting what's read with `counter`.
    pub fn new(origin: &Origin, counter: Counter) -> Self {
        let mut chain = HashSet::new();
        chain.insert(canonical(&origin.path));
        Self {
            counter,
            memory: crate::Limits::default().decoder_memory,
            chain,
            opened: 1,
            depth: 1,
            parents: Vec::new(),
        }
    }

    /// The same, holding decoded grains and clusters to `memory` bytes (`decoder_memory`).
    #[must_use]
    pub fn with_memory(mut self, memory: u64) -> Self {
        self.memory = memory;
        self
    }

    /// The parents found, by file name, nearest first.
    pub fn parents(&self) -> &[String] {
        &self.parents
    }

    /// Finds the file `from` names `recorded` (in the order its format gives them; the relative
    /// ones are tried as paths, all of them by their last part beside `from`, and the absolute
    /// ones as they are when `absolute` allows it), opens it and hands it to `accept`, which
    /// opens it as its format and checks its identity. `what` says what it is: "the parent
    /// disk". A parent (`parent`) is recorded for Info and counts as a level.
    pub fn find<T>(
        &mut self,
        from: &Origin,
        recorded: &[&str],
        absolute: bool,
        parent: bool,
        what: &str,
        mut accept: impl FnMut(&mut Self, Handle, Origin) -> Result<Verdict<T>>,
    ) -> Result<T> {
        let (cands, refused) = candidates(from, recorded, absolute);
        self.try_each(from, cands, refused, parent, what, &mut accept)
    }

    /// Finds a VDI's parent among the `.vdi` files beside `from` and in the folder above it,
    /// where VirtualBox keeps a base and `Snapshots/` its children: a VDI names its parent only
    /// by uuid. A file already a level of this disk (a child's sibling in `Snapshots/`) isn't a
    /// candidate, unless `is_it` says its header is the parent's: then the chain loops.
    pub fn find_vdi<T>(
        &mut self,
        from: &Origin,
        what: &str,
        mut is_it: impl FnMut(&mut Handle) -> bool,
        mut accept: impl FnMut(&mut Self, Handle, Origin) -> Result<Verdict<T>>,
    ) -> Result<T> {
        let mut cands = Vec::new();
        let dir = from.dir();
        let mut seen = 0usize;
        for d in [Some(dir), dir.parent()].into_iter().flatten() {
            let Ok(list) = std::fs::read_dir(d) else {
                continue;
            };
            let mut found: Vec<PathBuf> = list
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("vdi")))
                .collect();
            found.sort();
            for p in found {
                seen += 1;
                if seen > MAX_VDI_SCAN {
                    return Err(Error::limit(format!(
                        "more than {MAX_VDI_SCAN} .vdi files to look through for {what}"
                    )));
                }
                let id = canonical(&p);
                if id == canonical(&from.path) {
                    continue;
                }
                if self.chain.contains(&id) {
                    if let Ok((mut h, _)) = self.open(&p)
                        && is_it(&mut h)
                    {
                        return Err(Error::corrupt(format!(
                            "{what} named by {} is {}, which the disk already reads: its chain \
                             loops",
                            from.name,
                            p.display()
                        )));
                    }
                    continue;
                }
                cands.push(Candidate {
                    how: format!(
                        "a .vdi {}",
                        if d == dir {
                            "beside it"
                        } else {
                            "in the folder above"
                        }
                    ),
                    path: p,
                    absolute: false,
                });
            }
        }
        self.try_each(from, cands, Vec::new(), true, what, &mut accept)
    }

    fn try_each<T>(
        &mut self,
        from: &Origin,
        cands: Vec<Candidate>,
        refused: Vec<String>,
        parent: bool,
        what: &str,
        accept: &mut Accept<'_, T>,
    ) -> Result<T> {
        if parent && self.depth >= MAX_DEPTH {
            return Err(Error::limit(format!(
                "the disk has more than {MAX_DEPTH} levels of parents"
            )));
        }
        let mut tried = refused.clone();
        for c in cands {
            let at = c.path.display().to_string();
            let safe = if c.absolute {
                local(&c.path)
            } else {
                same_place(from.dir(), &c.path)
            };
            if let Err(why) = safe {
                tried.push(format!("{at} ({}: {why})", c.how));
                continue;
            }
            match std::fs::symlink_metadata(&c.path) {
                Ok(m) if m.is_file() && !reparse(&m) => {}
                Ok(_) => {
                    tried.push(format!("{at} ({}: not a regular file)", c.how));
                    continue;
                }
                Err(_) => {
                    tried.push(format!("{at} ({}: not there)", c.how));
                    continue;
                }
            }
            let id = canonical(&c.path);
            if self.chain.contains(&id) {
                return Err(Error::corrupt(format!(
                    "{what} named by {} is {at}, which the disk already reads: its chain loops",
                    from.name
                )));
            }
            let (handle, origin) = self.open(&c.path)?;
            self.chain.insert(id.clone());
            if parent {
                self.depth += 1;
                self.parents.push(origin.name.clone());
            }
            let verdict = accept(self, handle, origin);
            if parent {
                self.depth -= 1;
            }
            match verdict {
                Ok(Ok(t)) => return Ok(t),
                Ok(Err(why)) => {
                    self.chain.remove(&id);
                    if parent {
                        self.parents.pop();
                    }
                    tried.push(format!("{at} ({}: {why})", c.how));
                }
                Err(e) => return Err(e),
            }
        }
        let looked = if tried.is_empty() {
            "nowhere: it records no name to look for".to_owned()
        } else {
            tried.join("; ")
        };
        if !refused.is_empty() && tried.len() == refused.len() {
            return Err(Error::new(
                ErrorKind::Unsafe,
                format!("{what} named by {} is never opened: {looked}", from.name),
            ));
        }
        Err(Error::new(
            ErrorKind::NotFound,
            format!("{what} named by {} isn't found: {looked}", from.name),
        ))
    }

    /// `path`, opened read only (sharing reads and writes: Hyper-V may have it open) and
    /// counted.
    fn open(&mut self, path: &Path) -> Result<(Handle, Origin)> {
        self.opened += 1;
        if self.opened > MAX_FILES {
            return Err(Error::limit(format!(
                "the disk names more than {MAX_FILES} files"
            )));
        }
        let file = open_shared(path)?;
        let len = file
            .metadata()
            .map_err(|e| Error::io(format!("reading {}", path.display()), &e))?
            .len();
        let input: Box<dyn Input> = Box::new(CountingReader::new(file, self.counter.clone()));
        Ok((Handle::new(input, len), Origin::of(path)))
    }
}

/// `path` opened read only, sharing reads, writes and deletes.
pub fn open_shared(path: &Path) -> Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE: Hyper-V may have it open, and
        // reading it mustn't stop it being renamed or moved.
        o.share_mode(1 | 2 | 4);
    }
    o.open(path)
        .map_err(|e| Error::io(format!("opening {}", path.display()), &e))
}

/// A path's identity in the chain: canonical, and on Windows without case.
fn canonical(p: &Path) -> String {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = c.to_string_lossy().into_owned();
    if cfg!(windows) { s.to_lowercase() } else { s }
}

#[cfg(windows)]
fn reparse(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // FILE_ATTRIBUTE_REPARSE_POINT
    m.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn reparse(m: &std::fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

/// Why a recorded name is never followed, if it's one that isn't: a network or device path, or
/// a name that isn't a file's.
pub fn never(name: &str) -> Option<&'static str> {
    let n = name.trim();
    let slashed = n.replace('/', "\\");
    // `\\?\C:\…` and `\??\C:\…` are paths on a drive; every other `\\` or `\??\` path names
    // another machine or a device.
    let on_drive = ["\\\\?\\", "\\??\\"]
        .iter()
        .any(|p| slashed.strip_prefix(p).is_some_and(drive));
    if (slashed.starts_with("\\\\") || slashed.starts_with("\\??\\")) && !on_drive {
        return Some("a network or device path");
    }
    if n.starts_with("/dev/") || n.starts_with("/vmfs/devices/") || n.starts_with("/proc/") {
        return Some("a device");
    }
    if n.starts_with("json:") {
        return Some("a qemu json: name, not a file");
    }
    if let Some((scheme, _)) = n.split_once("://")
        && !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return Some("a URL, not a file");
    }
    if n.contains('\0') {
        return Some("a name with a NUL in it");
    }
    // qemu's `protocol:…` names (`nbd:host:10809`, `rbd:pool/image`, `file:…`): a colon before
    // the first separator that isn't a drive's.
    let sep = n.find(['/', '\\']).unwrap_or(n.len());
    if n[..sep].contains(':') && !drive_prefix(n) {
        return Some("a qemu protocol name, not a file");
    }
    if cfg!(windows) {
        // What follows a drive: no alternate data stream, no DOS device in any part.
        let rest = ["\\\\?\\", "\\??\\"]
            .iter()
            .find_map(|p| slashed.strip_prefix(p))
            .unwrap_or(&slashed);
        let rest = if drive_prefix(rest) { &rest[2..] } else { rest };
        if rest.contains(':') {
            return Some("an alternate data stream");
        }
        if rest.split('\\').any(dos_device) {
            return Some("a DOS device name");
        }
    }
    None
}

/// Whether `s` starts with a drive letter and its colon: `C:`.
fn drive_prefix(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Whether a file name is a DOS device's (`NUL`, `COM1.txt`, `con `), which Windows opens as the
/// device in any folder.
fn dos_device(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let stem = upper.split('.').next().unwrap_or("").trim_end();
    matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

/// Whether `s` starts with a drive: `C:\` or `C:/`.
fn drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// Whether a recorded name is relative: no drive, no leading slash.
fn relative(s: &str) -> bool {
    !s.starts_with(['\\', '/']) && !s.get(1..2).is_some_and(|c| c == ":")
}

/// The places to look for a file `from` names, in order, and the names never followed (see the
/// module's notes).
fn candidates(from: &Origin, recorded: &[&str], absolute: bool) -> (Vec<Candidate>, Vec<String>) {
    let mut out: Vec<Candidate> = Vec::new();
    let mut refused = Vec::new();
    let dir = from.dir();
    let parts = |s: &str| -> Vec<String> {
        s.split(['\\', '/'])
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let push = |out: &mut Vec<Candidate>, c: Candidate| {
        if !out.iter().any(|o| o.path == c.path) {
            out.push(c);
        }
    };
    let names: Vec<&str> = recorded
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter(|s| match never(s) {
            Some(why) => {
                refused.push(format!("{s} ({why})"));
                false
            }
            None => true,
        })
        .collect();
    // 1. Relative paths, from the naming file's folder.
    for r in names.iter().filter(|r| relative(r)) {
        let mut p = dir.to_path_buf();
        for part in parts(r) {
            match part.as_str() {
                "." => {}
                ".." => {
                    p.pop();
                }
                s => p.push(s),
            }
        }
        push(
            &mut out,
            Candidate {
                path: p,
                how: format!("its relative path {r}"),
                absolute: false,
            },
        );
    }
    // 2. Each name's last part, beside it.
    for n in &names {
        let Some(last) = parts(n).pop() else {
            continue;
        };
        if last == "." || last == ".." {
            continue;
        }
        push(
            &mut out,
            Candidate {
                path: dir.join(&last),
                how: format!("its name, {last}, beside {}", from.name),
                absolute: false,
            },
        );
    }
    // 3. Absolute paths, as recorded.
    if absolute {
        for a in names.iter().filter(|a| !relative(a)) {
            let s = ["\\\\?\\", "\\??\\"]
                .iter()
                .find_map(|p| a.strip_prefix(p).filter(|s| drive(s)))
                .unwrap_or(a);
            let p = PathBuf::from(s);
            if p.is_absolute() {
                push(
                    &mut out,
                    Candidate {
                        path: p,
                        how: format!("its absolute path {a}"),
                        absolute: true,
                    },
                );
            }
        }
    }
    (out, refused)
}

/// The path's root: its drive or share (`c:`, `\\server\share`), or `/`.
fn root(p: &Path) -> Option<String> {
    match p.components().next()? {
        Component::Prefix(px) => Some(px.as_os_str().to_string_lossy().to_lowercase()),
        Component::RootDir => Some("/".to_owned()),
        _ => None,
    }
}

/// A relative or same-folder candidate stays on the naming file's drive or share (a disk the
/// user opened from `\\server\share` may find its parent there, since that's the server the
/// user chose), with no stream or device name in it, and no link on the way that leads off it.
fn same_place(dir: &Path, p: &Path) -> std::result::Result<(), String> {
    if root(dir) != root(p) {
        return Err("it leaves the drive or share of the disk that names it".into());
    }
    names_and_links(p, root(dir).as_deref())
}

/// An absolute candidate is on a local drive, through no link that leads off the local drives.
fn local(p: &Path) -> std::result::Result<(), String> {
    #[cfg(windows)]
    {
        let s = p.to_str().ok_or("a path that isn't Unicode")?;
        if !drive(s) {
            return Err("not a path on a drive".into());
        }
        if !crate::safefs::disk::is_local_drive(p) {
            return Err(format!("drive {} isn't a local drive", &s[..2]));
        }
    }
    #[cfg(not(windows))]
    if !p.is_absolute() {
        return Err("not an absolute path".into());
    }
    names_and_links(p, None)
}

/// No alternate stream or DOS device name in `p`, and every link or junction on the way leads
/// to a local drive, or stays on `root`.
fn names_and_links(p: &Path, root_ok: Option<&str>) -> std::result::Result<(), String> {
    let s = p.to_str().ok_or("a path that isn't Unicode")?;
    if s.contains('\0') {
        return Err("a NUL in the path".into());
    }
    let mut at = PathBuf::new();
    for c in p.components() {
        at.push(c);
        let Component::Normal(n) = c else {
            continue;
        };
        let n = n.to_string_lossy();
        if cfg!(windows) {
            if n.contains(':') {
                return Err("an alternate data stream".into());
            }
            if dos_device(&n) {
                return Err(format!("the DOS device name {n}"));
            }
        }
        let Ok(m) = std::fs::symlink_metadata(&at) else {
            break;
        };
        if m.file_type().is_symlink() || reparse(&m) {
            let Ok(target) = std::fs::read_link(&at) else {
                return Err(format!("{} is a link BeeZip can't read", at.display()));
            };
            let t = target.to_string_lossy();
            let t = t
                .strip_prefix("\\\\?\\")
                .or_else(|| t.strip_prefix("\\??\\"))
                .unwrap_or(&t);
            let fine = if relative(t) {
                !t.contains(':')
            } else if cfg!(windows) {
                drive(t) && crate::safefs::disk::is_local_drive(Path::new(t))
                    || root(Path::new(t)).as_deref() == root_ok && root_ok.is_some()
            } else {
                !t.starts_with("//") && never(t).is_none()
            };
            if !fine {
                return Err(format!("{} links to {}", at.display(), target.display()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_never_followed() {
        for n in [
            r"\\server\share\base.vhdx",
            "//server/share/base.qcow2",
            r"\\?\UNC\server\share\x.vhd",
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\x.vhdx",
            r"\??\UNC\server\x",
            "/dev/sda",
            "json:{\"file.filename\":\"/etc/passwd\"}",
            "nbd://host/export",
            "https://example.com/x.qcow2",
            // qemu's protocol: names.
            "nbd:localhost:10809",
            "rbd:pool/image",
            "file:/etc/passwd",
        ] {
            assert!(never(n).is_some(), "{n}");
        }
        if cfg!(windows) {
            for n in [
                r"base.vhdx:stream",
                r"C:\VMs\base.vhdx:Zone.Identifier",
                r"..\NUL",
                r"C:\VMs\com1.vhdx",
                r"\\?\C:\CON\base.vhdx",
            ] {
                assert!(never(n).is_some(), "{n}");
            }
        }
        for n in [
            r"base.vhdx",
            r"..\parents\base.vhdx",
            r"C:\VMs\base.vhdx",
            r"\\?\C:\VMs\base.vhdx",
            "/var/lib/libvirt/images/base.qcow2",
            "Snapshots/x.vmdk",
            "C:base.vhd",
            r"C:\VMs\console.vhdx",
        ] {
            assert_eq!(never(n), None, "{n}");
        }
    }

    #[test]
    fn places_in_order() {
        let dir = std::env::temp_dir().join("beezip-vdisk-files");
        let from = Origin::of(&dir.join("kids").join("child.avhdx"));
        let (c, refused) = candidates(
            &from,
            &[
                r"..\parents\base.vhdx",
                r"C:\VMs\base.vhdx",
                r"\\srv\s\base.vhdx",
            ],
            true,
        );
        let paths: Vec<&Path> = c.iter().map(|c| c.path.as_path()).collect();
        assert_eq!(refused.len(), 1);
        assert_eq!(paths[0], dir.join("parents").join("base.vhdx"));
        assert_eq!(paths[1], dir.join("kids").join("base.vhdx"));
        if cfg!(windows) {
            assert_eq!(paths[2], Path::new(r"C:\VMs\base.vhdx"));
            assert_eq!(paths.len(), 3);
        }
        // Without rule 3, no absolute path.
        let (c, _) = candidates(&from, &[r"C:\VMs\base.vhdx"], false);
        assert_eq!(c.len(), 1);
        assert!(!c[0].absolute);
    }

    #[test]
    fn a_relative_path_stays_on_its_drive() {
        let dir = std::env::temp_dir();
        assert!(same_place(&dir, &dir.join("x.vhd")).is_ok());
        if cfg!(windows) {
            assert!(same_place(&dir, Path::new(r"\\server\share\x.vhd")).is_err());
            assert!(same_place(&dir, &dir.join("x.vhd:stream")).is_err());
            assert!(same_place(&dir, &dir.join("NUL.vhd")).is_err());
            assert!(local(Path::new(r"\\server\share\x.vhd")).is_err());
        }
    }
}
