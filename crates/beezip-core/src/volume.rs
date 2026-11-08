//! Volume sets (docs/M3.md §3.1): `name.001`, `name.002`… read as one seekable file, RAR's own
//! volume names, and a writer that splits a new archive into volumes.
//!
//! - **Numbered sets** (`a.7z.001`, three or more digits, from 1) are joined byte for byte by
//!   [`VolumeReader`], so any format reads them. Opening any part opens the set from part 1,
//!   and the set ends at the first missing number. A gap before a part that exists is
//!   `NotFound`; a missing last part can't be seen by name, so the archive reads as truncated.
//! - **RAR sets** (`a.part1.rar`…, or `a.rar`, `a.r00`, `a.r01`…) are separate archives that
//!   UnRAR opens one after another itself. BeeZip only names them, to find the first part and
//!   to report the set.
//! - **ARJ and ACE sets** (`a.arj`, `a.a01`…; `a.ace`, `a.c00`…, docs/M6.md §4) are named the
//!   way old RAR sets are, and their readers open the parts one after another.
//! - [`VolumeWriter`] writes `<output>.001`, `.002`… as partial files, each `volume_size` bytes
//!   but the last, and renames them into place on [`VolumeWriter::finish`].

use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
};

use crate::{Error, ErrorKind, Result, safefs::Partial};

/// The smallest volume size a writer accepts.
pub const MIN_VOLUME_SIZE: u64 = 1024;

/// How a set's parts are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    /// `name.001`, `name.002`…: one file split byte for byte.
    Numbered,
    /// `name.part1.rar`, `name.part2.rar`…
    RarParts,
    /// `name.rar`, `name.r00`, `name.r01`…
    RarOld,
    /// `name.arj`, `name.a01`, `name.a02`…
    Arj,
    /// `name.ace`, `name.c00`, `name.c01`…
    Ace,
}

/// A set named by letter and two digits after its first part: `x.rar`, `x.r00`… `x.r99`,
/// `x.s00`…, and ARJ's and ACE's the same way.
#[derive(Debug, Clone, Copy)]
struct Lettered {
    kind: SetKind,
    /// The first part's extension.
    first: &'static str,
    /// The second part's letter and number.
    letter: u8,
    from: u8,
    /// The last letter used before the names run out.
    last: u8,
}

const LETTERED: [Lettered; 3] = [
    Lettered {
        kind: SetKind::RarOld,
        first: "rar",
        letter: b'r',
        from: 0,
        last: b'z',
    },
    // ARJ goes `.a01`… `.a99`; past that it uses `.100`, which is a numbered part's name.
    Lettered {
        kind: SetKind::Arj,
        first: "arj",
        letter: b'a',
        from: 1,
        last: b'a',
    },
    Lettered {
        kind: SetKind::Ace,
        first: "ace",
        letter: b'c',
        from: 0,
        last: b'z',
    },
];

/// A set of volumes, first part first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSet {
    pub kind: SetKind,
    pub parts: Vec<PathBuf>,
    /// The joined file's name for a numbered set (`a.7z` for `a.7z.001`); the first part's for
    /// a RAR set.
    pub name: String,
}

/// `(base, number, digits)` for `base.NNN` with at least three digits.
pub fn numbered_name(name: &str) -> Option<(&str, u64, usize)> {
    let (base, digits) = name.rsplit_once('.')?;
    if base.is_empty() || digits.len() < 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((base, digits.parse().ok()?, digits.len()))
}

/// `(stem, number, digits)` for `stem.partN.rar`.
fn rar_part_name(name: &str) -> Option<(&str, u64, usize)> {
    let lower = name.to_ascii_lowercase();
    let without = lower.strip_suffix(".rar")?;
    let at = without.rfind(".part")?;
    let digits = &without[at + 5..];
    if at == 0 || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&name[..at], digits.parse().ok()?, digits.len()))
}

/// `(set, stem, index)` for a lettered set's part: `stem.rar` is 0, `stem.r00` is 1, `stem.r99`
/// is 100, `stem.s00` is 101…; `stem.arj` is 0, `stem.a01` is 1.
fn lettered_name(name: &str) -> Option<(Lettered, &str, u64)> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    let ext = ext.to_ascii_lowercase();
    let b = ext.as_bytes();
    LETTERED.into_iter().find_map(|l| {
        if ext == l.first {
            return Some((l, stem, 0));
        }
        if b.len() == 3
            && (l.letter..=l.last).contains(&b[0])
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
        {
            let n =
                u64::from(b[0] - l.letter) * 100 + u64::from((b[1] - b'0') * 10 + (b[2] - b'0'));
            let from = u64::from(l.from);
            return (n >= from).then(|| (l, stem, n - from + 1));
        }
        None
    })
}

/// Part `index` of a lettered set, or `None` past its last name.
fn lettered_part(l: Lettered, stem: &str, index: u64) -> Option<String> {
    if index == 0 {
        return Some(format!("{stem}.{}", l.first));
    }
    let n = index - 1 + u64::from(l.from);
    let letter = u64::from(l.letter) + n / 100;
    if letter > u64::from(l.last) {
        return None;
    }
    let letter = char::from(u8::try_from(letter).ok()?);
    Some(format!("{stem}.{letter}{:02}", n % 100))
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name().map(|n| n.to_string_lossy().into_owned())
}

/// The set `path` belongs to, if its name is a volume's. A single `name.001` is a set of one;
/// `name.rar` is a set only if `name.r00` exists.
pub fn find_set(path: &Path) -> Result<Option<VolumeSet>> {
    let Some(name) = file_name(path) else {
        return Ok(None);
    };
    let dir = path.parent().unwrap_or(Path::new(""));
    if let Some((base, number, digits)) = numbered_name(&name) {
        let part = |n: u64| dir.join(format!("{base}.{n:0digits$}"));
        let parts = consecutive(|n| Some(part(n + 1)));
        let found = parts.len() as u64;
        if found < number || later_part_exists(dir, base, found + 1) {
            return Err(missing(found + 1, base));
        }
        return Ok(Some(VolumeSet {
            kind: SetKind::Numbered,
            parts,
            name: base.to_owned(),
        }));
    }
    if let Some((stem, number, digits)) = rar_part_name(&name) {
        let part = |n: u64| dir.join(format!("{stem}.part{n:0digits$}.rar"));
        let parts = consecutive(|n| Some(part(n + 1)));
        if (parts.len() as u64) < number {
            return Err(missing(parts.len() as u64 + 1, &format!("{stem}.rar")));
        }
        let name = file_name(&parts[0]).unwrap_or_default();
        return Ok(Some(VolumeSet {
            kind: SetKind::RarParts,
            parts,
            name,
        }));
    }
    if let Some((l, stem, index)) = lettered_name(&name) {
        let parts = consecutive(|n| lettered_part(l, stem, n).map(|p| dir.join(p)));
        if index == 0 && parts.len() < 2 {
            return Ok(None);
        }
        let first = format!("{stem}.{}", l.first);
        if (parts.len() as u64) <= index {
            return Err(missing(parts.len() as u64 + 1, &first));
        }
        return Ok(Some(VolumeSet {
            kind: l.kind,
            parts,
            name: first,
        }));
    }
    Ok(None)
}

/// Paths `part(0)`, `part(1)`… while they are files.
fn consecutive(part: impl Fn(u64) -> Option<PathBuf>) -> Vec<PathBuf> {
    (0..)
        .map_while(part)
        .take_while(|p| p.is_file())
        .collect::<Vec<_>>()
}

/// Whether a numbered part `>= from` of `base` exists in `dir`, at any digit width.
fn later_part_exists(dir: &Path, base: &str, from: u64) -> bool {
    let Ok(read) = fs::read_dir(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }) else {
        return false;
    };
    let fold = |s: &str| {
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s.to_owned()
        }
    };
    let base = fold(base);
    read.flatten().any(|e| {
        let name = fold(&e.file_name().to_string_lossy());
        numbered_name(&name).is_some_and(|(b, n, _)| b == base && n >= from)
    })
}

fn missing(n: u64, base: &str) -> Error {
    Error::new(
        ErrorKind::NotFound,
        format!("volume {n} of {base} is missing"),
    )
}

/// The context a corrupt volume set's error gets: its last part may be missing.
pub fn truncated_hint(err: Error, parts: usize) -> Error {
    if err.kind == ErrorKind::Corrupt {
        let s = if parts == 1 { "" } else { "s" };
        err.context(format!(
            "{parts} volume{s} found, and the archive ends early; is the last one missing?"
        ))
    } else {
        err
    }
}

/// The parts of a numbered set read as one file. Parts stay closed until they are read, and
/// one that changed size since the set was opened is an `Io` error.
#[derive(Debug)]
pub struct VolumeReader {
    parts: Arc<[PathBuf]>,
    sizes: Arc<[u64]>,
    /// Where each part starts in the joined file.
    starts: Arc<[u64]>,
    total: u64,
    pos: u64,
    /// The open part, and the position in the joined file its handle is at.
    open: Option<(usize, File, u64)>,
}

impl VolumeReader {
    /// Opens `parts`, taking their sizes now.
    pub fn open(parts: &[PathBuf]) -> Result<Self> {
        let sizes: Vec<u64> = parts
            .iter()
            .map(|p| {
                fs::metadata(p)
                    .map(|m| m.len())
                    .map_err(|e| Error::io(format!("opening {}", p.display()), &e))
            })
            .collect::<Result<_>>()?;
        let mut starts = Vec::with_capacity(sizes.len());
        let mut total = 0u64;
        for s in &sizes {
            starts.push(total);
            total += s;
        }
        Ok(Self {
            parts: parts.into(),
            sizes: sizes.into(),
            starts: starts.into(),
            total,
            pos: 0,
            open: None,
        })
    }

    /// The joined size.
    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn parts(&self) -> &[PathBuf] {
        &self.parts
    }

    /// A second reader over the same parts, at the start, with the same recorded sizes.
    pub fn reopen(&self) -> Self {
        Self {
            parts: self.parts.clone(),
            sizes: self.sizes.clone(),
            starts: self.starts.clone(),
            total: self.total,
            pos: 0,
            open: None,
        }
    }

    /// The part holding byte `pos` of the joined file (`pos < total`).
    fn part_at(&self, pos: u64) -> usize {
        // The last part starting at or before `pos`, skipping empty parts.
        let i = self.starts.partition_point(|&s| s <= pos).saturating_sub(1);
        (i..self.sizes.len())
            .find(|&j| self.sizes[j] > 0 && pos < self.starts[j] + self.sizes[j])
            .unwrap_or(i)
    }

    fn open_part(&self, i: usize) -> io::Result<File> {
        let path = &self.parts[i];
        let file = File::open(path)?;
        let now = file.metadata()?.len();
        if now != self.sizes[i] {
            return Err(Error::new(
                ErrorKind::Io,
                format!(
                    "{} changed while it was being read ({} bytes, now {now})",
                    path.display(),
                    self.sizes[i]
                ),
            )
            .into_io());
        }
        Ok(file)
    }
}

impl Read for VolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.total {
            return Ok(0);
        }
        let i = self.part_at(self.pos);
        let in_part = self.pos - self.starts[i];
        let ready = matches!(&self.open, Some((j, _, at)) if *j == i && *at == self.pos);
        if !ready {
            let mut file = match self.open.take() {
                Some((j, f, _)) if j == i => f,
                _ => self.open_part(i)?,
            };
            file.seek(SeekFrom::Start(in_part))?;
            self.open = Some((i, file, self.pos));
        }
        let left = self.sizes[i] - in_part;
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let Some((_, file, at)) = self.open.as_mut() else {
            return Ok(0);
        };
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} ended early", self.parts[i].display()),
            ));
        }
        *at += n as u64;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for VolumeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.total.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        self.pos = to;
        Ok(to)
    }
}

/// The paths a writer creates: `<output>.001`, `.002`…
pub fn part_path(output: &Path, n: u64) -> PathBuf {
    let mut s = output.as_os_str().to_owned();
    s.push(format!(".{n:03}"));
    s.into()
}

struct WriterState {
    output: PathBuf,
    size: u64,
    overwrite: bool,
    parts: Vec<Partial>,
    /// The part whose handle is open; the others are closed, so a long set doesn't hold
    /// thousands of handles.
    open: Option<usize>,
    pos: u64,
    /// The joined length written so far.
    len: u64,
    finished: bool,
}

/// Splits what is written into `<output>.001`, `.002`…, each `volume_size` bytes but the last.
/// Seeking back rewrites earlier parts. Clones share the set, so an archive writer can own one
/// while the caller keeps another to [`finish`](Self::finish) it. Until then the parts are
/// partial files, which are deleted if the writer is dropped.
#[derive(Clone)]
pub struct VolumeWriter {
    state: Arc<Mutex<WriterState>>,
}

impl VolumeWriter {
    /// Without `overwrite`, an existing `<output>.001` is a `Conflict` now, and any other
    /// existing part at [`finish`](Self::finish).
    pub fn create(output: &Path, volume_size: u64, overwrite: bool) -> Result<Self> {
        if volume_size < MIN_VOLUME_SIZE {
            return Err(Error::invalid_args(format!(
                "volumes must be at least {MIN_VOLUME_SIZE} bytes"
            )));
        }
        if !overwrite {
            conflict(&part_path(output, 1))?;
        }
        Ok(Self {
            state: Arc::new(Mutex::new(WriterState {
                output: output.to_path_buf(),
                size: volume_size,
                overwrite,
                parts: Vec::new(),
                open: None,
                pos: 0,
                len: 0,
                finished: false,
            })),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, WriterState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Renames every part into place and returns their paths. With `overwrite`, parts of an
    /// older set beyond the new last part are deleted, so a reader can't join them on.
    pub fn finish(&self) -> Result<Vec<PathBuf>> {
        let mut st = self.state();
        if st.finished {
            return Err(Error::invalid_args("the volume set is already finished"));
        }
        if st.parts.is_empty() {
            // An empty archive is still one (empty) volume.
            st.part(0)?;
        }
        st.open = None;
        for p in &mut st.parts {
            p.close();
        }
        let n = st.parts.len() as u64;
        let finals: Vec<PathBuf> = (1..=n).map(|i| part_path(&st.output, i)).collect();
        if !st.overwrite {
            for f in &finals {
                conflict(f)?;
            }
        }
        let parts = std::mem::take(&mut st.parts);
        for (p, to) in parts.into_iter().zip(&finals) {
            p.persist(to)?;
        }
        if st.overwrite {
            let mut stale = n + 1;
            while fs::symlink_metadata(part_path(&st.output, stale)).is_ok() {
                let path = part_path(&st.output, stale);
                fs::remove_file(&path)
                    .map_err(|e| Error::io(format!("removing {}", path.display()), &e))?;
                stale += 1;
            }
        }
        st.finished = true;
        Ok(finals)
    }
}

fn conflict(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("`{}` already exists", path.display()),
        ));
    }
    Ok(())
}

impl WriterState {
    /// Part `i`, created (with the parts before it, filled to full size) if needed, with its
    /// handle open.
    fn part(&mut self, i: usize) -> Result<&mut File> {
        while self.parts.len() <= i {
            let n = self.parts.len();
            let dir = match self.output.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let name = file_name(&part_path(&self.output, n as u64 + 1)).unwrap_or_default();
            let mut p = Partial::create(&dir, &format!(".{name}"))?;
            if n > 0 {
                // A part only starts once the one before it is full.
                let prev = &mut self.parts[n - 1];
                let size = self.size;
                prev.open()?
                    .set_len(size)
                    .map_err(|e| Error::io(format!("writing {}", prev.path().display()), &e))?;
                prev.close();
            }
            p.close();
            self.parts.push(p);
        }
        if let Some(open) = self.open
            && open != i
        {
            self.parts[open].close();
        }
        self.open = Some(i);
        self.parts[i].open()
    }
}

impl Write for VolumeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state();
        if st.finished {
            return Err(io::Error::other("the volume set is already finished"));
        }
        let size = st.size;
        let pos = st.pos;
        let i = usize::try_from(pos / size).map_err(io::Error::other)?;
        let at = pos % size;
        let want = buf
            .len()
            .min(usize::try_from(size - at).unwrap_or(usize::MAX));
        let file = st.part(i).map_err(Error::into_io)?;
        file.seek(SeekFrom::Start(at))?;
        let n = file.write(&buf[..want])?;
        st.pos += n as u64;
        st.len = st.len.max(st.pos);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut st = self.state();
        match st.open {
            Some(i) => st.parts[i].open().map_err(Error::into_io)?.flush(),
            None => Ok(()),
        }
    }
}

impl Seek for VolumeWriter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut st = self.state();
        let to = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => st.len.checked_add_signed(d),
            SeekFrom::Current(d) => st.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        st.pos = to;
        Ok(to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(dir: &Path, names: &[&str]) {
        for n in names {
            fs::write(dir.join(n), n.as_bytes()).unwrap();
        }
    }

    #[test]
    fn names() {
        assert_eq!(numbered_name("a.7z.001"), Some(("a.7z", 1, 3)));
        assert_eq!(numbered_name("big.iso.0012"), Some(("big.iso", 12, 4)));
        assert_eq!(numbered_name("a.01"), None);
        assert_eq!(numbered_name(".001"), None);
        assert_eq!(rar_part_name("x.part02.rar"), Some(("x", 2, 2)));
        assert_eq!(rar_part_name("x.PART1.RAR"), Some(("x", 1, 1)));
        assert_eq!(rar_part_name("x.rar"), None);
        fn name(n: &str) -> Option<(SetKind, &str, u64)> {
            lettered_name(n).map(|(l, stem, i)| (l.kind, stem, i))
        }
        assert_eq!(name("x.rar"), Some((SetKind::RarOld, "x", 0)));
        assert_eq!(name("x.r00"), Some((SetKind::RarOld, "x", 1)));
        assert_eq!(name("x.s01"), Some((SetKind::RarOld, "x", 102)));
        assert_eq!(name("x.ARJ"), Some((SetKind::Arj, "x", 0)));
        assert_eq!(name("x.a01"), Some((SetKind::Arj, "x", 1)));
        assert_eq!(name("x.a00"), None);
        assert_eq!(name("x.b01"), None);
        assert_eq!(name("x.ace"), Some((SetKind::Ace, "x", 0)));
        assert_eq!(name("x.c00"), Some((SetKind::Ace, "x", 1)));
        assert_eq!(name("x.d00"), Some((SetKind::Ace, "x", 101)));
        let [rar, arj, ace] = LETTERED;
        assert_eq!(lettered_part(rar, "x", 0).unwrap(), "x.rar");
        assert_eq!(lettered_part(rar, "x", 1).unwrap(), "x.r00");
        assert_eq!(lettered_part(rar, "x", 101).unwrap(), "x.s00");
        assert_eq!(lettered_part(arj, "x", 1).unwrap(), "x.a01");
        assert_eq!(lettered_part(arj, "x", 99).unwrap(), "x.a99");
        assert_eq!(lettered_part(arj, "x", 100), None);
        assert_eq!(lettered_part(ace, "x", 1).unwrap(), "x.c00");
        for l in LETTERED {
            for i in 0..300 {
                let Some(part) = lettered_part(l, "x", i) else {
                    continue;
                };
                let (k, stem, j) = lettered_name(&part).unwrap();
                assert_eq!((k.kind, stem, j), (l.kind, "x", i), "{part}");
            }
        }
    }

    #[test]
    fn arj_and_ace_sets() {
        let d = tempfile::tempdir().unwrap();
        touch(
            d.path(),
            &["v.arj", "v.a01", "v.a02", "w.ace", "w.c00", "lone.arj"],
        );
        let set = find_set(&d.path().join("v.a02")).unwrap().unwrap();
        assert_eq!(set.kind, SetKind::Arj);
        assert_eq!(set.parts.len(), 3);
        assert_eq!(set.name, "v.arj");
        let set = find_set(&d.path().join("w.ace")).unwrap().unwrap();
        assert_eq!(set.kind, SetKind::Ace);
        assert_eq!(set.parts.len(), 2);
        assert_eq!(find_set(&d.path().join("lone.arj")).unwrap(), None);
        touch(d.path(), &["gap.arj", "gap.a02"]);
        assert_eq!(
            find_set(&d.path().join("gap.a02")).unwrap_err().kind,
            ErrorKind::NotFound
        );
    }

    #[test]
    fn numbered_sets() {
        let d = tempfile::tempdir().unwrap();
        touch(d.path(), &["a.7z.001", "a.7z.002", "a.7z.003", "lone.001"]);
        let set = find_set(&d.path().join("a.7z.002")).unwrap().unwrap();
        assert_eq!(set.kind, SetKind::Numbered);
        assert_eq!(set.name, "a.7z");
        assert_eq!(set.parts.len(), 3);
        assert!(set.parts[0].ends_with("a.7z.001"));
        let lone = find_set(&d.path().join("lone.001")).unwrap().unwrap();
        assert_eq!(lone.parts.len(), 1);
        assert_eq!(find_set(&d.path().join("a.7z")).unwrap(), None);

        // A gap before a part that exists.
        touch(d.path(), &["b.zip.001", "b.zip.003"]);
        let err = find_set(&d.path().join("b.zip.001")).unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound);
        assert!(err.message.contains("volume 2 of b.zip"), "{}", err.message);
        // Part 1 missing.
        touch(d.path(), &["c.002"]);
        let err = find_set(&d.path().join("c.002")).unwrap_err();
        assert!(err.message.contains("volume 1 of c"), "{}", err.message);
    }

    #[test]
    fn rar_sets() {
        let d = tempfile::tempdir().unwrap();
        touch(
            d.path(),
            &[
                "n.part1.rar",
                "n.part2.rar",
                "o.rar",
                "o.r00",
                "o.r01",
                "p.rar",
            ],
        );
        let set = find_set(&d.path().join("n.part2.rar")).unwrap().unwrap();
        assert_eq!(set.kind, SetKind::RarParts);
        assert_eq!(set.parts.len(), 2);
        assert_eq!(set.name, "n.part1.rar");
        let set = find_set(&d.path().join("o.r01")).unwrap().unwrap();
        assert_eq!(set.kind, SetKind::RarOld);
        assert_eq!(set.parts.len(), 3);
        assert!(set.parts[0].ends_with("o.rar"));
        assert_eq!(find_set(&d.path().join("p.rar")).unwrap(), None);
        touch(d.path(), &["q.part2.rar"]);
        assert_eq!(
            find_set(&d.path().join("q.part2.rar")).unwrap_err().kind,
            ErrorKind::NotFound
        );
    }

    #[test]
    fn a_changed_part_is_an_io_error() {
        let d = tempfile::tempdir().unwrap();
        touch(d.path(), &["x.001", "x.002"]);
        let set = find_set(&d.path().join("x.001")).unwrap().unwrap();
        let mut r = VolumeReader::open(&set.parts).unwrap();
        fs::write(&set.parts[1], b"longer than before").unwrap();
        let err = r.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(Error::from(err).kind, ErrorKind::Io);
    }
}
