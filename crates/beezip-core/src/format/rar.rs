//! RAR 1.5–7, read only, through UnRAR in `beezip-unrar` (docs/M3.md §3.4).
//!
//! - **The index** comes from a list-mode pass, which reads only headers, even in a solid
//!   archive. Links: `RedirType` 1–3 (Unix symlink, Windows symlink, junction) are symlinks, 4
//!   (hard link) and 5 (file copy) hard links, since both copy an earlier entry.
//! - **Extracting** tests each selected entry; its data streams back from UnRAR's thread, and
//!   BeeZip's sinks decide every path. UnRAR never creates a file.
//! - **Passwords:** UnRAR asks once per handle and reuses the answer for the rest. When an
//!   entry has a different one (`ERAR_BAD_PASSWORD`, or a CRC failure on RAR 1.5–4 data, which
//!   has no check value), the archive is reopened, skipped to that entry, and given the next
//!   answer. A wrong header password fails the open itself, and is asked again the same way.
//! - **Limits:** an entry whose dictionary is over `decoder_memory` is refused before it is
//!   decoded. UnRAR reads the archive itself, so the ratio and progress counter adds each
//!   entry's packed size when it starts.
//! - **Volumes and SFX:** UnRAR opens later volumes and finds the archive inside an SFX
//!   itself. A missing volume fails with `NotFound`, naming it.

use super::{ArchiveFormat, FormatCaps, FormatId};
use crate::detect::{Confidence, Probe};

pub struct Rar;

const RAR4: &[u8; 7] = b"Rar!\x1A\x07\x00";
const RAR5: &[u8; 8] = b"Rar!\x1A\x07\x01\x00";
const RAR14: &[u8; 4] = b"RE~^";

impl ArchiveFormat for Rar {
    fn id(&self) -> FormatId {
        FormatId::Rar
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".rar", ".cbr", ".r00"]
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        signature(probe.head)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            volumes: true,
            ..FormatCaps::default()
        }
    }
}

/// How sure `head` (from the archive's first byte) is a RAR: the signature is likely; with the
/// first header's CRC, certain.
pub fn signature(head: &[u8]) -> Option<Confidence> {
    let checked = |ok: bool| {
        Some(if ok {
            Confidence::Certain
        } else {
            Confidence::Likely
        })
    };
    if head.starts_with(RAR5) {
        // CRC32 of the header size (a vint) and the header that follows it.
        let crc = u32::from_le_bytes(head.get(8..12)?.try_into().ok()?);
        let (size, len) = vint(head.get(12..)?)?;
        let end = 12usize
            .checked_add(len)?
            .checked_add(usize::try_from(size).ok()?)?;
        return checked(head.get(12..end).is_some_and(|h| crc32fast::hash(h) == crc));
    }
    if head.starts_with(RAR4) {
        // The low 16 bits of the CRC32 of the main header, from its type byte on.
        let crc = u16::from_le_bytes(head.get(7..9)?.try_into().ok()?);
        let size = usize::from(u16::from_le_bytes(head.get(12..14)?.try_into().ok()?));
        let ok = size >= 7
            && head.get(9) == Some(&0x73)
            && head
                .get(9..7 + size)
                .is_some_and(|h| crc32fast::hash(h) as u16 == crc);
        return checked(ok);
    }
    head.starts_with(RAR14).then_some(Confidence::Likely)
}

/// RAR5's variable-length integer: 7 bits a byte, low first. (value, bytes).
fn vint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, &b) in buf.iter().take(10).enumerate() {
        v |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// What BeeZip reads from a RAR 2.x–4 file header itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rar4Extra {
    /// A Unix symlink's target, which is its stored data.
    pub target: Option<String>,
    /// The name as UTF-8, for a Unix-made name without the Unicode flag that is valid UTF-8.
    pub utf8_name: Option<String>,
}

/// Facts UnRAR doesn't give about RAR 2.x–4 entries, in file-header order (continuations of
/// split files left out, as UnRAR lists them):
///
/// - **Unix symlinks** keep their target as stored data, which UnRAR reads past its data
///   callback; it follows the file header uncompressed, so BeeZip reads it.
/// - **Names** without the Unicode flag are in the creator's encoding. UnRAR (and 7-Zip) decode
///   them in a Windows code page; RAR for Linux and macOS writes the locale's, which is UTF-8.
///   A Unix-made name that is valid UTF-8 is read as UTF-8.
///
/// Each block header gives its type and size, so the walk reads headers only. It yields
/// nothing for encrypted headers. `files` is how many file headers UnRAR listed.
pub fn rar4_extras(volumes: &[std::path::PathBuf], files: usize) -> Vec<Rar4Extra> {
    use std::io::{Read, Seek, SeekFrom};
    let mut out = Vec::new();
    for v in volumes {
        let Ok(mut f) = std::fs::File::open(v) else {
            break;
        };
        // An SFX puts the archive after its module: find the marker.
        let mut head = Vec::new();
        if f.by_ref().take(4 << 20).read_to_end(&mut head).is_err() {
            break;
        }
        let Some(mut pos) = memchr::memmem::find(&head, RAR4).map(|p| p as u64 + 7) else {
            break;
        };
        let len = f.metadata().map_or(0, |m| m.len());
        loop {
            // A block: CRC (2), type (1), flags (2), size (2); with flag 0x8000 a 4-byte data
            // size follows. File headers (0x74) go on: unpacked size (4), host OS (1), CRC (4),
            // time (4), version (1), method (1), name size (2), attributes (4), and with flag
            // 0x100 the high halves of both sizes.
            let mut h = [0u8; 36];
            if f.seek(SeekFrom::Start(pos)).is_err() {
                break;
            }
            let got = f.by_ref().take(36).read(&mut h).unwrap_or(0);
            if got < 7 {
                break;
            }
            let u32_at = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
            let kind = h[2];
            let flags = u16::from_le_bytes([h[3], h[4]]);
            let size = u64::from(u16::from_le_bytes([h[5], h[6]]));
            if size < 7 || kind == 0x7B {
                break;
            }
            let mut add = if flags & 0x8000 != 0 && got >= 11 {
                u64::from(u32_at(7))
            } else {
                0
            };
            if kind == 0x74 {
                if got < 32 {
                    break;
                }
                if flags & 0x100 != 0 && got >= 36 {
                    add |= u64::from(u32_at(32)) << 32;
                }
                let host = h[15];
                let attr = u32_at(28);
                let link = host == 3 && attr & 0o170_000 == 0o120_000;
                let encrypted = flags & 0x04 != 0;
                let split_before = flags & 0x01 != 0;
                if !split_before {
                    let mut extra = Rar4Extra::default();
                    let name_len = usize::from(u16::from_le_bytes([h[26], h[27]]));
                    let name_at = pos + if flags & 0x100 != 0 { 40 } else { 32 };
                    if host == 3 && flags & 0x200 == 0 && name_len > 0 {
                        let mut name = vec![0u8; name_len];
                        if f.seek(SeekFrom::Start(name_at)).is_ok()
                            && f.read_exact(&mut name).is_ok()
                            && !name.is_ascii()
                            && let Ok(s) = String::from_utf8(name)
                        {
                            extra.utf8_name = Some(s);
                        }
                    }
                    if link && !encrypted && add <= 64 * 1024 {
                        let mut t = vec![0u8; usize::try_from(add).unwrap_or(0)];
                        if f.seek(SeekFrom::Start(pos + size)).is_ok()
                            && f.read_exact(&mut t).is_ok()
                        {
                            extra.target = Some(String::from_utf8_lossy(&t).into_owned());
                        }
                    }
                    out.push(extra);
                    if out.len() >= files {
                        return out;
                    }
                }
            }
            let next = pos.saturating_add(size).saturating_add(add);
            if next <= pos || next >= len {
                break;
            }
            pos = next;
        }
    }
    out
}

#[cfg(feature = "rar")]
pub use imp::RarReader;

#[cfg(not(feature = "rar"))]
pub struct RarReader;

#[cfg(not(feature = "rar"))]
impl RarReader {
    pub fn open(
        _: crate::source::Source,
        _: bool,
        _: &mut dyn crate::Ctx,
    ) -> crate::Result<Box<dyn super::ArchiveReader>> {
        Err(crate::Error::new(
            crate::ErrorKind::BackendUnavailable,
            "this build of BeeZip reads no RAR archives (built without the `rar` feature)",
        ))
    }
}

#[cfg(feature = "rar")]
mod imp {
    use std::{
        collections::BTreeSet,
        io::{self, Read},
        path::PathBuf,
    };

    use beezip_unrar::{Failure, Header, Mode, Session, code, flags, redir};

    use super::super::{
        ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatId, Selection,
    };
    use crate::{
        Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
        io::copy,
        safefs::Partial,
        source::Source,
        time::{DosTime, from_dos, from_ntfs},
    };

    /// A failure from UnRAR as a core error. `encrypted`: the entry being read is encrypted,
    /// so damage most likely means a wrong password (RAR 1.5–4 data has no check value).
    fn rar_error(f: &Failure, encrypted: bool) -> Error {
        match f.code {
            code::BAD_PASSWORD => Error::new(ErrorKind::WrongPassword, "wrong password"),
            code::MISSING_PASSWORD => {
                Error::new(ErrorKind::PasswordRequired, "the RAR is encrypted")
            }
            code::BAD_DATA if encrypted => {
                Error::new(ErrorKind::WrongPassword, "wrong password or damaged data")
            }
            code::BAD_DATA => Error::corrupt("RAR: CRC error or damaged data"),
            code::BAD_ARCHIVE => Error::corrupt("RAR: the archive is damaged"),
            code::UNKNOWN_FORMAT => Error::unsupported_format("RAR: an unknown format or version"),
            code::EOPEN => match &f.missing_volume {
                Some(v) => Error::new(ErrorKind::NotFound, format!("volume {v} is missing")),
                None => Error::new(ErrorKind::Io, "RAR: could not open the archive"),
            },
            code::NO_MEMORY => Error::limit("UnRAR ran out of memory"),
            code::LARGE_DICT => {
                Error::limit("the RAR's dictionary is over the limit (`decoder_memory`)")
            }
            // UnRAR reports reading past the end of damaged or cut-off data this way.
            code::EREAD => Error::corrupt("RAR: the archive ends early or is damaged"),
            code::SMALL_BUF => Error::corrupt("RAR: a name or comment is too long"),
            code::EREFERENCE => Error::corrupt("RAR: a file reference can't be resolved"),
            c => Error::corrupt(format!("RAR: UnRAR error {c}")),
        }
    }

    /// Answers UnRAR's password requests in a session: a known password first, then what the
    /// job offers. Remembers what it gave and why it couldn't.
    #[derive(Default)]
    struct Answers {
        /// The next answer to give, without asking the job.
        next: Option<String>,
        /// The answer this session's handle was given.
        given: Option<String>,
        /// Why the job gave none.
        error: Option<Error>,
    }

    impl Answers {
        fn new(next: Option<String>) -> Self {
            Self {
                next,
                ..Self::default()
            }
        }

        fn answer(&mut self, cx: &mut dyn Ctx, entry: Option<&str>, failed: u32) -> Option<String> {
            let pw = match self.next.take() {
                Some(pw) => pw,
                None => match cx.password(entry, failed) {
                    Ok(pw) => pw,
                    Err(e) => {
                        self.error = Some(e);
                        return None;
                    }
                },
            };
            self.given = Some(pw.clone());
            Some(pw)
        }
    }

    pub struct RarReader {
        source: Source,
        /// The file UnRAR opens: the first volume, the SFX, or a spooled copy.
        path: PathBuf,
        _spool: Option<Partial>,
        entries: Vec<Entry>,
        dicts: Vec<u64>,
        /// Links whose target is their data (RAR 2.x–4 Unix symlinks): its size, read when the
        /// entry is extracted or opened.
        data_links: Vec<Option<u64>>,
        /// Some entry is RAR 1.5–4 (its names and links get `rar4_extras`).
        rar4: bool,
        flags: u32,
        comment: Option<String>,
        sfx: bool,
        /// The last password that worked.
        password: Option<String>,
        /// The session behind the reader `open_entry` returned.
        open: Option<Session>,
    }

    fn entry(id: usize, h: &Header) -> Entry {
        let native = |s: &str| {
            if cfg!(windows) {
                s.replace('\\', "/")
            } else {
                s.to_owned()
            }
        };
        let target = native(&h.redir_name);
        let kind = match h.redir_type {
            redir::UNIX_SYMLINK | redir::WIN_SYMLINK | redir::JUNCTION => {
                EntryKind::Symlink { target }
            }
            redir::HARDLINK | redir::FILE_COPY => EntryKind::Hardlink { target },
            _ if h.is_dir() => EntryKind::Dir,
            _ => EntryKind::File,
        };
        let mut e = Entry::new(id, native(&h.name), kind);
        if e.kind == EntryKind::File {
            e.size = Some(h.unp_size);
            e.packed_size = Some(h.pack_size);
        }
        e.modified = if h.mtime != 0 {
            from_ntfs(h.mtime)
        } else {
            from_dos(DosTime {
                date: u16::try_from(h.file_time >> 16).unwrap_or(0),
                time: u16::try_from(h.file_time & 0xFFFF).unwrap_or(0),
            })
        };
        e.crc32 = (h.hash_type == beezip_unrar::HASH_CRC32 && e.kind == EntryKind::File)
            .then_some(h.file_crc);
        e.method = (e.kind == EntryKind::File).then(|| method_name(h));
        e.encrypted = h.is_encrypted();
        match h.host_os {
            beezip_unrar::HOST_UNIX => e.unix_mode = Some(h.file_attr),
            _ => e.dos_attrs = Some(h.file_attr & 0xFFFF),
        }
        e
    }

    /// Store, or the algorithm version: RAR 1.5, 2.0, 2.9, 5.0 or 7.0.
    fn method_name(h: &Header) -> &'static str {
        if h.method == 0x30 {
            return "Store";
        }
        match h.unp_ver {
            0..=19 => "RAR 1.5",
            20..=28 => "RAR 2.0",
            29..=49 => "RAR 2.9",
            50..=69 => "RAR 5.0",
            _ => "RAR 7.0",
        }
    }

    impl RarReader {
        pub fn open(source: Source, sfx: bool, cx: &mut dyn Ctx) -> Result<Box<dyn ArchiveReader>> {
            // UnRAR opens only files, so a RAR inside a codec or a byte-split set is spooled.
            let (path, spool) = if source.joined || !source.codecs.is_empty() {
                let mut tmp = Partial::create_temp("beezip-spool.rar")?;
                let mut stream = source.guard(source.open_stream()?);
                copy(&mut stream, tmp.file_mut(), cx)?;
                tmp.close();
                (tmp.path().to_path_buf(), Some(tmp))
            } else {
                (source.path.clone(), None)
            };
            let mut r = Self {
                source,
                path,
                _spool: spool,
                entries: Vec::new(),
                dicts: Vec::new(),
                data_links: Vec::new(),
                rar4: false,
                flags: 0,
                comment: None,
                sfx,
                password: None,
                open: None,
            };
            r.list(cx)?;
            r.fill_link_targets();
            Ok(Box::new(r))
        }

        /// RAR 2.x–4 Unix symlinks keep their target as data; read it from the archive.
        fn fill_link_targets(&mut self) {
            if self.flags & flags::ENCRYPTED_HEADERS != 0 || !self.rar4 {
                return;
            }
            let volumes = if self._spool.is_some() {
                vec![self.path.clone()]
            } else {
                self.source.volumes.clone()
            };
            let extras = super::rar4_extras(&volumes, self.entries.len());
            for (id, x) in extras.into_iter().enumerate() {
                let Some(e) = self.entries.get_mut(id) else {
                    break;
                };
                if let Some(name) = x.utf8_name {
                    e.raw_path = name.as_bytes().to_vec();
                    e.path = name;
                }
                if let (Some(Some(_)), Some(target)) = (self.data_links.get(id), x.target) {
                    e.kind = EntryKind::Symlink { target };
                }
            }
        }

        fn max_dict(&self) -> u64 {
            self.source.limits.decoder_memory
        }

        /// Opens a session, asking again while the header password is wrong.
        fn session(&mut self, mode: Mode, cx: &mut dyn Ctx) -> Result<(Session, Answers)> {
            self.session_after(mode, 0, cx)
        }

        /// [`Self::session`] after `failed` wrong header passwords.
        fn session_after(
            &mut self,
            mode: Mode,
            failed: u32,
            cx: &mut dyn Ctx,
        ) -> Result<(Session, Answers)> {
            let mut failed = failed;
            loop {
                cx.check()?;
                let mut answers = Answers::new(if failed == 0 {
                    self.password.clone()
                } else {
                    None
                });
                let opened = Session::open(&self.path, mode, self.max_dict(), &mut || {
                    answers.answer(cx, None, failed)
                });
                match opened {
                    Ok((s, o)) => {
                        self.flags = o.flags;
                        self.comment = o.comment;
                        if answers.given.is_some() {
                            self.password = answers.given.clone();
                        }
                        return Ok((s, answers));
                    }
                    Err(f) => {
                        if let Some(e) = answers.error.take() {
                            return Err(match e.kind {
                                ErrorKind::WrongPassword if failed > 0 => Error::new(
                                    ErrorKind::WrongPassword,
                                    "wrong password or damaged data",
                                ),
                                _ => e,
                            });
                        }
                        // RAR 1.5–4 headers have no password check: a wrong one reads as damage.
                        let wrong = matches!(
                            f.code,
                            code::BAD_PASSWORD | code::BAD_DATA | code::BAD_ARCHIVE
                        );
                        if wrong && answers.given.is_some() {
                            failed += 1;
                            self.password = None;
                            continue;
                        }
                        return Err(rar_error(&f, false));
                    }
                }
            }
        }

        fn list(&mut self, cx: &mut dyn Ctx) -> Result<()> {
            let mut failed = 0u32;
            loop {
                let (mut s, mut answers) = self.session_after(Mode::List, failed, cx)?;
                match self.read_headers(&mut s, &mut answers, failed, cx) {
                    // RAR 1.5–4 headers have no password check: a wrong one opens, and the
                    // first header reads as damage. Ask again.
                    Err(Some(f))
                        if answers.given.is_some()
                            && self.entries.is_empty()
                            && matches!(
                                f.code,
                                code::BAD_PASSWORD | code::BAD_DATA | code::BAD_ARCHIVE
                            ) =>
                    {
                        failed += 1;
                        self.password = None;
                        drop(s);
                        cx.check()?;
                        // The job says when to stop asking; this is a backstop for one that
                        // never does.
                        if failed > crate::ctx::MAX_PASSWORD_TRIES {
                            return Err(Error::new(
                                ErrorKind::WrongPassword,
                                "wrong password or damaged data",
                            ));
                        }
                    }
                    Err(Some(f)) => {
                        return Err(answers.error.take().unwrap_or_else(|| rar_error(&f, false)));
                    }
                    Err(None) => {
                        return Err(answers
                            .error
                            .take()
                            .unwrap_or_else(|| Error::corrupt("RAR: could not read the headers")));
                    }
                    Ok(()) => return Ok(()),
                }
            }
        }

        /// Reads every header into the index. `Err(Some)`: UnRAR failed; `Err(None)`: BeeZip
        /// stopped (a limit, cancellation), with the reason in `answers.error`.
        fn read_headers(
            &mut self,
            s: &mut Session,
            answers: &mut Answers,
            failed: u32,
            cx: &mut dyn Ctx,
        ) -> std::result::Result<(), Option<Failure>> {
            let mut entries = Vec::new();
            let mut dicts = Vec::new();
            let mut data_links = Vec::new();
            let stop = |answers: &mut Answers, e: Error| {
                answers.error = Some(e);
                None
            };
            loop {
                if let Err(e) = cx.check() {
                    return Err(stop(answers, e));
                }
                // RAR 4 may ask for the header password here rather than at open: `failed`
                // says how many answers were wrong, so the job doesn't give the same one again.
                let h = match s.next(&mut || answers.answer(cx, None, failed)) {
                    Ok(Some(h)) => h,
                    Ok(None) => break,
                    Err(f) => return Err(Some(f)),
                };
                if let Err(e) = self.source.limits.check_entries(entries.len() as u64 + 1) {
                    return Err(stop(answers, e));
                }
                entries.push(entry(entries.len(), &h));
                dicts.push(h.dict_size);
                self.rar4 |= h.unp_ver < 50;
                data_links.push(
                    (h.redir_type == redir::UNIX_SYMLINK
                        && h.redir_name.is_empty()
                        && h.unp_size > 0)
                        .then_some(h.unp_size),
                );
                s.skip(&mut || answers.answer(cx, None, failed))
                    .map_err(Some)?;
            }
            self.entries = entries;
            self.dicts = dicts;
            self.data_links = data_links;
            Ok(())
        }

        fn check_dict(&self, id: usize) -> Result<()> {
            let need = self.dicts.get(id).copied().unwrap_or(0);
            let max = self.max_dict();
            if need > max {
                return Err(Error::limit(format!(
                    "`{}` needs a {need}-byte dictionary, over the {max}-byte limit \
                     (`decoder_memory`)",
                    self.entries[id].path
                )));
            }
            Ok(())
        }
    }

    /// One entry's data from a session: chunks until UnRAR says it ended. The answer to a
    /// password request is decided before the sink starts reading.
    struct RarData<'s> {
        session: &'s mut Session,
        answer: Option<String>,
        encrypted: bool,
        cur: Vec<u8>,
        pos: usize,
        done: bool,
        failure: Option<Failure>,
        /// The answer was asked for (and given) while reading.
        asked: bool,
    }

    impl<'s> RarData<'s> {
        fn new(session: &'s mut Session, answer: Option<String>, encrypted: bool) -> Self {
            Self {
                session,
                answer,
                encrypted,
                cur: Vec::new(),
                pos: 0,
                done: false,
                failure: None,
                asked: false,
            }
        }

        fn fill(&mut self) -> std::result::Result<bool, Failure> {
            if self.done {
                return Ok(false);
            }
            if let Some(f) = &self.failure {
                return Err(f.clone());
            }
            let answer = &mut self.answer;
            let asked = &mut self.asked;
            match self.session.chunk(&mut || {
                *asked = true;
                answer.take()
            }) {
                Ok(Some(d)) => {
                    self.cur = d;
                    self.pos = 0;
                    Ok(true)
                }
                Ok(None) => {
                    self.done = true;
                    Ok(false)
                }
                Err(f) => {
                    self.failure = Some(f.clone());
                    Err(f)
                }
            }
        }

        /// Reads what the sink left, so the entry ends and UnRAR is ready for the next.
        fn finish(&mut self) -> std::result::Result<(), Failure> {
            while self.fill()? {}
            Ok(())
        }
    }

    impl Read for RarData<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                if self.pos < self.cur.len() {
                    let n = buf.len().min(self.cur.len() - self.pos);
                    buf[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
                    self.pos += n;
                    return Ok(n);
                }
                match self.fill() {
                    Ok(true) => {}
                    Ok(false) => return Ok(0),
                    Err(f) => return Err(rar_error(&f, self.encrypted).into_io()),
                }
            }
        }
    }

    /// A reader that owns its session's place in `RarReader::open`.
    struct Owned<'s>(RarData<'s>);

    impl Read for Owned<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Drop for Owned<'_> {
        fn drop(&mut self) {
            if !self.0.done {
                self.0.session.stop();
            }
        }
    }

    /// The next header that starts an entry. In extract mode UnRAR also shows the continuation
    /// of a split file that was skipped, in its next volume (list mode hides them); those are
    /// skipped too, so ids stay the listing's.
    fn next_start(
        s: &mut Session,
        answers: &mut Answers,
        cx: &mut dyn Ctx,
    ) -> Result<Option<Header>> {
        loop {
            match s.next(&mut || answers.answer(cx, None, 0)) {
                Ok(Some(h)) if h.flags & beezip_unrar::entry_flags::SPLIT_BEFORE != 0 => {
                    s.skip(&mut || answers.answer(cx, None, 0))
                        .map_err(|f| rar_error(&f, false))?;
                }
                Ok(h) => return Ok(h),
                Err(f) => {
                    return Err(answers.error.take().unwrap_or_else(|| rar_error(&f, false)));
                }
            }
        }
    }

    enum Outcome {
        Done,
        /// The entry's password was wrong: reopen and try the next.
        WrongPassword,
    }

    impl ArchiveReader for RarReader {
        fn format(&self) -> FormatId {
            FormatId::Rar
        }

        fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
            Ok(&self.entries)
        }

        fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
            let methods: BTreeSet<&'static str> = self
                .entries
                .iter()
                .filter(|e| e.kind == EntryKind::File)
                .filter_map(|e| e.method)
                .collect();
            let files: Vec<&Entry> = self
                .entries
                .iter()
                .filter(|e| e.kind == EntryKind::File)
                .collect();
            let encrypted = files.iter().filter(|e| e.encrypted).count();
            let headers = self.flags & flags::ENCRYPTED_HEADERS != 0;
            Ok(ArchiveInfo {
                format: FormatId::Rar,
                codecs: self.source.codecs.clone(),
                methods: methods.into_iter().collect(),
                comment: self.comment.clone(),
                encryption: match encrypted {
                    _ if headers => Encryption::All,
                    0 => Encryption::None,
                    n if n >= files.len() => Encryption::All,
                    _ => Encryption::Some,
                },
                solid: self.flags & flags::SOLID != 0,
                sfx: self.sfx,
                volumes: self.source.volumes.len(),
                solid_blocks: None,
                encrypted_headers: headers,
                locked: self.flags & flags::LOCK != 0,
                recovery_record: self.flags & flags::RECOVERY != 0,
            })
        }

        fn extract(
            &mut self,
            sel: &Selection,
            sink: &mut dyn EntrySink,
            cx: &mut dyn Ctx,
        ) -> Result<()> {
            let mut meter = Meter::new(self.source.counter.clone(), Some(self.source.size));
            meter.entries_total = Some(self.entries.len() as u64);
            self.source.counter.set(0);
            // After a wrong password: where to resume, how many failed, what to answer next.
            let mut resume = 0usize;
            let mut failed = 0u32;
            let mut pending: Option<String> = None;
            'session: loop {
                let (mut s, mut answers) = self.session(Mode::Extract, cx)?;
                // Whether this handle has a password: UnRAR asks only once.
                let mut has_password = answers.given.is_some();
                let mut id = 0usize;
                loop {
                    cx.check()?;
                    let Some(h) = next_start(&mut s, &mut answers, cx)? else {
                        break 'session;
                    };
                    let e = match self.entries.get(id) {
                        Some(e) => e.clone(),
                        None => entry(id, &h),
                    };
                    let selected = id >= resume && sel.matches(&e);
                    if !selected || e.kind != EntryKind::File {
                        // Skipping a solid archive's encrypted entry decodes it, so it may ask.
                        let pw = pending.clone().or_else(|| self.password.clone());
                        let mut skip_answers = Answers::new(pw);
                        s.skip(&mut || skip_answers.answer(cx, Some(&e.path), failed))
                            .map_err(|f| {
                                skip_answers
                                    .error
                                    .take()
                                    .unwrap_or_else(|| rar_error(&f, e.encrypted))
                            })?;
                        has_password |= skip_answers.given.is_some();
                        if selected {
                            meter.entries_done = id as u64;
                            meter.current = Some(e.path.clone());
                            let mut mcx = MeteredCtx::new(cx, &meter);
                            sink.entry(&e, &mut io::empty(), &mut mcx)?;
                        }
                        id += 1;
                        continue;
                    }
                    self.check_dict(id)?;
                    // The answer UnRAR will get if it asks, decided now: the sink has the job.
                    let answer = if e.encrypted && !has_password {
                        let mut a = Answers::new(pending.take().or_else(|| self.password.clone()));
                        match a.answer(cx, Some(&e.path), failed) {
                            Some(pw) => Some(pw),
                            None => {
                                return Err(match a.error {
                                    Some(err) if err.kind == ErrorKind::WrongPassword => {
                                        Error::new(ErrorKind::WrongPassword, "wrong password")
                                    }
                                    Some(err) => err,
                                    None => Error::new(
                                        ErrorKind::PasswordRequired,
                                        "the RAR is encrypted",
                                    ),
                                });
                            }
                        }
                    } else {
                        None
                    };
                    meter.entries_done = id as u64;
                    meter.current = Some(e.path.clone());
                    s.test().map_err(|f| rar_error(&f, e.encrypted))?;
                    let outcome = {
                        let mut data = RarData::new(&mut s, answer.clone(), e.encrypted);
                        let mut guarded = self.source.guard(&mut data);
                        // UnRAR reads the archive itself: count the entry's packed bytes.
                        self.source.counter.add(e.packed_size.unwrap_or(0));
                        let mut mcx = MeteredCtx::new(cx, &meter);
                        mcx.report();
                        let sent = sink.entry(&e, &mut guarded, &mut mcx);
                        drop(guarded);
                        let asked = data.asked;
                        let ended = match sent {
                            Ok(()) => data.finish().map_err(|f| rar_error(&f, e.encrypted)),
                            Err(err) => Err(err),
                        };
                        if asked {
                            has_password = true;
                        }
                        match ended {
                            Ok(()) => {
                                if asked && answer.is_some() {
                                    self.password = answer.clone();
                                }
                                Outcome::Done
                            }
                            Err(err) if err.kind == ErrorKind::WrongPassword && e.encrypted => {
                                Outcome::WrongPassword
                            }
                            Err(err) => {
                                data.session.stop();
                                return Err(err);
                            }
                        }
                    };
                    match outcome {
                        Outcome::Done => {
                            failed = 0;
                            id += 1;
                        }
                        Outcome::WrongPassword => {
                            failed += 1;
                            if failed > crate::ctx::MAX_PASSWORD_TRIES {
                                return Err(Error::new(
                                    ErrorKind::WrongPassword,
                                    "wrong password or damaged data",
                                ));
                            }
                            self.password = None;
                            pending = Some(match cx.password(Some(&e.path), failed) {
                                Ok(pw) => pw,
                                Err(err) if err.kind == ErrorKind::WrongPassword => {
                                    return Err(Error::new(
                                        ErrorKind::WrongPassword,
                                        "wrong password or damaged data",
                                    ));
                                }
                                Err(err) => return Err(err),
                            });
                            resume = id;
                            continue 'session;
                        }
                    }
                }
            }
            meter.entries_done = self.entries.len() as u64;
            MeteredCtx::new(cx, &meter).report();
            Ok(())
        }

        fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
            let e = self
                .entries
                .get(id)
                .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?
                .clone();
            match &e.kind {
                EntryKind::File => {}
                EntryKind::Symlink { target } => {
                    return Ok(Box::new(io::Cursor::new(target.clone().into_bytes())));
                }
                EntryKind::Hardlink { target } => {
                    let target = crate::format::normalize(target);
                    let earlier = self.entries[..id]
                        .iter()
                        .rev()
                        .find(|x| {
                            x.kind == EntryKind::File && crate::format::normalize(&x.path) == target
                        })
                        .map(|x| x.id)
                        .ok_or_else(|| {
                            Error::corrupt(format!("hard link target `{target}` is missing"))
                        })?;
                    return self.open_entry(earlier, cx);
                }
                _ => return Ok(Box::new(io::empty())),
            }
            self.check_dict(id)?;
            self.open = None;
            let mut failed = 0u32;
            let mut pending: Option<String> = None;
            loop {
                let (mut s, mut answers) = self.session(Mode::Extract, cx)?;
                let mut has_password = answers.given.is_some();
                for k in 0..id {
                    cx.check()?;
                    let skipped = self.entries[k].path.clone();
                    next_start(&mut s, &mut answers, cx)?;
                    let mut a = Answers::new(pending.clone().or_else(|| self.password.clone()));
                    s.skip(&mut || a.answer(cx, Some(&skipped), failed))
                        .map_err(|f| a.error.take().unwrap_or_else(|| rar_error(&f, false)))?;
                    has_password |= a.given.is_some();
                }
                next_start(&mut s, &mut answers, cx)?.ok_or_else(|| {
                    Error::corrupt(format!("entry {id} vanished on a second pass"))
                })?;
                let answer = if e.encrypted && !has_password {
                    let mut a = Answers::new(pending.take().or_else(|| self.password.clone()));
                    let pw = a.answer(cx, Some(&e.path), failed);
                    if pw.is_none() {
                        return Err(a.error.unwrap_or_else(|| {
                            Error::new(ErrorKind::PasswordRequired, "the RAR is encrypted")
                        }));
                    }
                    pw
                } else {
                    None
                };
                s.test().map_err(|f| rar_error(&f, e.encrypted))?;
                // A wrong password shows before any data: look at the first piece.
                let mut probe = RarData::new(&mut s, answer.clone(), e.encrypted);
                let first = probe.fill();
                let (cur, done, asked) = (std::mem::take(&mut probe.cur), probe.done, probe.asked);
                match first {
                    Err(f)
                        if e.encrypted && rar_error(&f, true).kind == ErrorKind::WrongPassword =>
                    {
                        failed += 1;
                        if failed > crate::ctx::MAX_PASSWORD_TRIES {
                            return Err(Error::new(
                                ErrorKind::WrongPassword,
                                "wrong password or damaged data",
                            ));
                        }
                        self.password = None;
                        pending = Some(match cx.password(Some(&e.path), failed) {
                            Ok(pw) => pw,
                            Err(err) if err.kind == ErrorKind::WrongPassword => {
                                return Err(Error::new(
                                    ErrorKind::WrongPassword,
                                    "wrong password or damaged data",
                                ));
                            }
                            Err(err) => return Err(err),
                        });
                        continue;
                    }
                    Err(f) => return Err(rar_error(&f, e.encrypted)),
                    Ok(_) => {}
                }
                if asked && answer.is_some() {
                    self.password = answer;
                }
                self.source.counter.set(0);
                let session = self.open.insert(s);
                let mut data = RarData::new(session, None, e.encrypted);
                data.cur = cur;
                data.done = done;
                let guarded = self.source.guard(Owned(data));
                self.source.counter.add(e.packed_size.unwrap_or(0));
                return Ok(Box::new(guarded));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures() {
        // RAR5: the signature, then the main header with its CRC32.
        let mut v = RAR5.to_vec();
        let header = [0x03u8, 0x01, 0x00, 0x00];
        let body = &header[..];
        v.extend_from_slice(&crc32fast::hash(body).to_le_bytes());
        v.extend_from_slice(body);
        assert_eq!(signature(&v), Some(Confidence::Certain));
        v[13] ^= 1;
        assert_eq!(signature(&v), Some(Confidence::Likely));

        // RAR4: the marker block, then the main header (type 0x73, size 13).
        let mut m = RAR4.to_vec();
        let main = [0x73u8, 0x00, 0x00, 13, 0x00, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&(crc32fast::hash(&main) as u16).to_le_bytes());
        m.extend_from_slice(&main);
        assert_eq!(signature(&m), Some(Confidence::Certain));
        assert_eq!(signature(b"RE~^...."), Some(Confidence::Likely));
        assert_eq!(signature(b"Rar!\x1A\x07\x02"), None);
        assert_eq!(vint(&[0x81, 0x01]), Some((129, 2)));
    }
}
