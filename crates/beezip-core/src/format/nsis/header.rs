//! An NSIS installer's header (docs/M10.md §3.2, §4.1): its block table, its strings, and the
//! instructions BeeZip lists files from, written from NSIS's `Source/exehead/fileform.h` and
//! `exec.c` (zlib licence). The listing follows 7-Zip's rules, so that names don't change for
//! someone who used 7-Zip: `SetOutPath` sets the folder later files go to, a `File` lands there
//! unless its name is absolute, `WriteUninstaller` is a file, Library.nsh's `InstallLib` names
//! its library, and `FileOpen` with `FileClose` right after it is an empty file.

use crate::{Error, Result};

/// The instructions BeeZip reads, as NSIS 3 numbers them.
const EW_NOP: u32 = 2;
const EW_SETFILEATTRIBUTES: u32 = 10;
const EW_CREATEDIR: u32 = 11;
const EW_EXTRACTFILE: u32 = 20;
const EW_ASSIGNVAR: u32 = 25;
const EW_GETDLGITEM: u32 = 35;
const EW_REGISTERDLL: u32 = 44;
const EW_FCLOSE: u32 = 54;
const EW_FOPEN: u32 = 55;
const EW_WRITEUNINSTALLER: u32 = 62;

/// Variables, by number.
const VAR_R0: u32 = 10;
const VAR_R4: u32 = 14;
const VAR_INSTDIR: u32 = 21;
const VAR_OUTDIR: u32 = 22;
const VAR_EXEDIR: u32 = 23;
const VAR_TEMP: u32 = 25;
const VAR_PLUGINSDIR: u32 = 26;
/// `$HWNDPARENT` before NSIS 2.26 added `$EXEPATH` and `$EXEFILE`.
const VAR_HWNDPARENT_225: u32 = 27;
/// `$_OUTDIR`, which `SetOutPath "$OUTDIR\…"` in a macro saves the folder in.
const VAR_SPEC_OUTDIR: u32 = 31;
const VAR_SPEC_OUTDIR_225: u32 = 29;
const VAR_NAMES: [&str; 12] = [
    "CMDLINE",
    "INSTDIR",
    "OUTDIR",
    "EXEDIR",
    "LANGUAGE",
    "TEMP",
    "PLUGINSDIR",
    "EXEPATH",
    "EXEFILE",
    "HWNDPARENT",
    "_CLICK",
    "_OUTDIR",
];

/// `FileOpen`'s access and disposition for writing a new file.
const GENERIC_WRITE: u32 = 1 << 30;
const CREATE_ALWAYS: u32 = 2;

/// The longest string decoded, in characters, and the longest path: 7-Zip stops reading paths
/// at 4,096 characters too, and a longer one would only make thousands of nested folders.
const MAX_STRING: usize = 1 << 16;
const MAX_PATH: usize = 4096;
/// All the names together.
const MAX_NAMES: usize = 64 << 20;

fn bad(message: impl std::fmt::Display) -> Error {
    Error::corrupt(format!("nsis: {message}"))
}

fn le32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

fn le16(d: &[u8], at: usize) -> Option<u16> {
    let b = d.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Which NSIS wrote the strings, which sets their codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Strings {
    /// NSIS 2, and Park's ANSI builds: codes 252 to 255.
    Nsis2Ansi,
    /// NSIS 3: codes 1 to 4.
    Nsis3Ansi,
    Nsis3Unicode,
    /// Jim Park's Unicode NSIS 2: codes 0xE000 to 0xE003.
    ParkUnicode,
}

impl Strings {
    pub(super) fn unicode(self) -> bool {
        matches!(self, Self::Nsis3Unicode | Self::ParkUnicode)
    }

    /// The codes: skip, variable, shell folder, language string.
    fn codes(self) -> [u16; 4] {
        match self {
            Self::Nsis2Ansi => [252, 253, 254, 255],
            Self::Nsis3Ansi | Self::Nsis3Unicode => [4, 3, 2, 1],
            Self::ParkUnicode => [0xE000, 0xE001, 0xE002, 0xE003],
        }
    }

    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::Nsis2Ansi => "NSIS 2, ANSI",
            Self::Nsis3Ansi => "NSIS 3, ANSI",
            Self::Nsis3Unicode => "NSIS 3, Unicode",
            Self::ParkUnicode => "NSIS 2 (Jim Park's), Unicode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ItemKind {
    File,
    /// `WriteUninstaller`: the installer's stub, patched by the record at `pos` when `patch`,
    /// then the uninstaller's data in the record after.
    Uninstaller {
        patch: bool,
    },
    /// `FileOpen` and `FileClose`.
    Empty,
}

/// A file, as the instructions name it.
#[derive(Debug, Clone)]
pub(super) struct Item {
    /// Its name: ANSI bytes, or UTF-8 for a Unicode installer; `/` between folders,
    /// `$INSTDIR/` dropped.
    pub(super) name: Vec<u8>,
    /// Where its data is: in the solid stream after the header, or the data block.
    pub(super) pos: u32,
    pub(super) kind: ItemKind,
    /// A FILETIME.
    pub(super) mtime: Option<u64>,
    pub(super) attrib: Option<u32>,
}

/// The header, read.
#[derive(Debug)]
pub(super) struct Parsed {
    pub(super) strings: Strings,
    pub(super) is64: bool,
    pub(super) instructions: usize,
    pub(super) items: Vec<Item>,
}

/// The header's strings and how to read them.
struct Table<'a> {
    /// The string table: bytes, or UTF-16LE units' bytes.
    s: &'a [u8],
    kind: Strings,
    /// NSIS 2.25 and older number some variables differently, and 2.00 has fewer.
    nsis225: bool,
    nsis200: bool,
}

impl Table<'_> {
    /// The number of characters in the table.
    fn chars(&self) -> usize {
        if self.kind.unicode() {
            self.s.len() / 2
        } else {
            self.s.len()
        }
    }

    fn unit(&self, i: usize) -> Option<u16> {
        if self.kind.unicode() {
            le16(self.s, i.checked_mul(2)?)
        } else {
            self.s.get(i).map(|&b| u16::from(b))
        }
    }

    /// A string's bytes (ANSI, or UTF-8), with variables and folders written as NSIS names them.
    /// `None` for one that runs past the table or over 64 KiB.
    fn string(&self, index: u32) -> Option<Vec<u8>> {
        // A negative index is a language string.
        if index as i32 >= 0 && index as usize >= self.chars() {
            return None;
        }
        if (index as i32) < 0 {
            let n = -(index as i32 + 1);
            return Some(format!("$(LSTR_{n})").into_bytes());
        }
        let [skip, var, shell, lang] = self.kind.codes();
        let mut out: Vec<u8> = Vec::new();
        let mut units: Vec<u16> = Vec::new();
        let flush = |out: &mut Vec<u8>, units: &mut Vec<u16>| {
            out.extend_from_slice(String::from_utf16_lossy(units).as_bytes());
            units.clear();
        };
        let mut i = index as usize;
        loop {
            if out.len() + units.len() > MAX_STRING {
                return None;
            }
            let c = self.unit(i)?;
            i += 1;
            if c == 0 {
                break;
            }
            let special = match self.kind {
                Strings::Nsis2Ansi => c >= skip,
                Strings::Nsis3Ansi | Strings::Nsis3Unicode => c <= skip,
                Strings::ParkUnicode => (skip..=lang).contains(&c),
            };
            if !special {
                if self.kind.unicode() {
                    units.push(c);
                } else {
                    out.push(c as u8);
                }
                continue;
            }
            // A code's argument: one unit in Unicode, two bytes in ANSI (but after skip).
            let a = self.unit(i)?;
            i += 1;
            if a == 0 {
                break;
            }
            if c == skip {
                if self.kind.unicode() {
                    units.push(a);
                } else {
                    out.push(a as u8);
                }
                continue;
            }
            let (lo, hi) = if self.kind.unicode() {
                ((a & 0xFF) as u8, (a >> 8) as u8)
            } else {
                let b = self.unit(i)?;
                i += 1;
                if b == 0 {
                    break;
                }
                (a as u8, b as u8)
            };
            flush(&mut out, &mut units);
            if c == shell {
                out.extend_from_slice(self.shell(lo, hi).as_bytes());
                continue;
            }
            let n = if self.kind == Strings::ParkUnicode {
                u32::from(a & 0x7FFF)
            } else {
                u32::from(lo & 0x7F) | (u32::from(hi & 0x7F) << 7)
            };
            if c == var {
                out.extend_from_slice(self.var_name(n).as_bytes());
            } else if c == lang {
                out.extend_from_slice(format!("$(LSTR_{n})").as_bytes());
            }
        }
        flush(&mut out, &mut units);
        Some(out)
    }

    /// A plain string, codes and all: a registry value's name.
    fn plain(&self, index: usize) -> String {
        let mut units = Vec::new();
        let mut i = index;
        while let Some(c) = self.unit(i).filter(|&c| c != 0) {
            units.push(c);
            i += 1;
            if units.len() > 256 {
                break;
            }
        }
        if self.kind.unicode() {
            String::from_utf16_lossy(&units)
        } else {
            units.iter().map(|&c| char::from(c as u8)).collect()
        }
    }

    /// A shell folder: a CSIDL, or a registry value under `Windows\CurrentVersion`.
    fn shell(&self, a: u8, b: u8) -> String {
        if a & 0x80 != 0 {
            let name = self.plain(usize::from(a & 0x3F));
            let base = match name.as_str() {
                "ProgramFilesDir" => "$PROGRAMFILES".to_owned(),
                "CommonFilesDir" => "$COMMONFILES".to_owned(),
                _ => format!("$_ERROR_UNSUPPORTED_VALUE_REGISTRY_({name})"),
            };
            return if a & 0x40 != 0 {
                format!("{base}64")
            } else {
                base
            };
        }
        match csidl(a).or_else(|| csidl(b)) {
            Some(n) => format!("${n}"),
            None => format!("$_ERROR_UNSUPPORTED_SHELL_[{a},{b}]"),
        }
    }

    fn internal_vars(&self) -> u32 {
        if self.nsis200 {
            29
        } else if self.nsis225 {
            30
        } else {
            32
        }
    }

    fn var_name(&self, n: u32) -> String {
        match n {
            0..=9 => format!("${n}"),
            10..=19 => format!("$R{}", n - 10),
            _ if n < self.internal_vars() => {
                let k = if self.nsis225 && n >= 27 { n + 2 } else { n };
                format!("${}", VAR_NAMES[(k - 20) as usize])
            }
            _ => format!("$_{}_", n - self.internal_vars()),
        }
    }

    /// The variable a string starts with, and the characters it takes.
    fn leading_var(&self, index: u32) -> Option<(u32, usize)> {
        let i = index as usize;
        if i >= self.chars() {
            return None;
        }
        let [_, var, _, _] = self.kind.codes();
        if self.unit(i)? != var {
            return None;
        }
        let a = self.unit(i + 1)?;
        if a == 0 {
            return None;
        }
        if self.kind.unicode() {
            let n = if self.kind == Strings::ParkUnicode {
                u32::from(a & 0x7FFF)
            } else {
                u32::from(a & 0x7F) | (u32::from((a >> 8) & 0x7F) << 7)
            };
            return Some((n, 2));
        }
        let b = self.unit(i + 2)?;
        if b == 0 {
            return None;
        }
        Some((u32::from(a & 0x7F) | (u32::from(b & 0x7F) << 7), 3))
    }

    /// Whether the string is exactly variable `v`.
    fn is_var(&self, index: u32, v: u32) -> bool {
        self.leading_var(index)
            .is_some_and(|(n, len)| n == v && self.unit(index as usize + len) == Some(0))
    }

    /// Whether a path is absolute: from `$INSTDIR`, `$EXEDIR`, `$TEMP` or `$PLUGINSDIR`, or a
    /// drive or a share.
    fn absolute(&self, index: u32, s: &[u8]) -> bool {
        matches!(
            self.leading_var(index),
            Some((VAR_INSTDIR | VAR_EXEDIR | VAR_TEMP | VAR_PLUGINSDIR, _))
        ) || s.starts_with(b"\\\\")
            || (s.len() >= 2 && s[0].is_ascii_alphabetic() && s[1] == b':')
    }
}

/// NSIS's shell folders by CSIDL (`Source/build.cpp`'s table), as 7-Zip names them.
fn csidl(c: u8) -> Option<&'static str> {
    Some(match c {
        0x00 | 0x10 | 0x19 => "DESKTOP",
        0x01 => "INTERNET",
        0x02 | 0x17 => "SMPROGRAMS",
        0x03 => "CONTROLS",
        0x04 => "PRINTERS",
        0x05 | 0x2E => "DOCUMENTS",
        0x06 | 0x1F => "FAVORITES",
        0x07 | 0x18 => "SMSTARTUP",
        0x08 => "RECENT",
        0x09 => "SENDTO",
        0x0A => "BITBUCKET",
        0x0B | 0x16 => "STARTMENU",
        0x0D | 0x35 => "MUSIC",
        0x0E | 0x37 => "VIDEOS",
        0x11 => "DRIVES",
        0x12 => "NETWORK",
        0x13 => "NETHOOD",
        0x14 => "FONTS",
        0x15 | 0x2D => "TEMPLATES",
        0x1A | 0x23 => "APPDATA",
        0x1B => "PRINTHOOD",
        0x1C => "LOCALAPPDATA",
        0x1D | 0x1E => "ALTSTARTUP",
        0x20 => "INTERNET_CACHE",
        0x21 => "COOKIES",
        0x22 => "HISTORY",
        0x24 => "WINDIR",
        0x25 => "SYSDIR",
        0x26 => "PROGRAM_FILES",
        0x27 | 0x36 => "PICTURES",
        0x28 => "PROFILE",
        0x29 => "SYSTEMX86",
        0x2A => "PROGRAM_FILESX86",
        0x2B => "PROGRAM_FILES_COMMON",
        0x2C => "PROGRAM_FILES_COMMONX8",
        0x2F | 0x30 => "ADMINTOOLS",
        0x31 => "CONNECTIONS",
        0x38 => "RESOURCES",
        0x39 => "RESOURCES_LOCALIZED",
        0x3A => "COMMON_OEM_LINKS",
        0x3B => "CDBURN_AREA",
        0x3D => "COMPUTERSNEARME",
        _ => return None,
    })
}

/// Which NSIS wrote the strings: Unicode tables start with an empty UTF-16 string. NSIS 3
/// shows in a string that starts with a variable whose number has its marker bits set (7-Zip's
/// test); a Unicode table without one but with Park's codes is Park's.
fn kind(s: &[u8]) -> Strings {
    let unicode = s.len() >= 2 && s[0] == 0 && s[1] == 0;
    if unicode {
        let w: Vec<u16> = s
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let nsis3 = w
            .windows(3)
            .any(|x| x[0] == 0 && x[1] == 3 && x[2] & 0x8080 == 0x8080);
        let park = w.iter().any(|&c| (0xE000..=0xE003).contains(&c));
        if !nsis3 && park {
            Strings::ParkUnicode
        } else {
            Strings::Nsis3Unicode
        }
    } else if s
        .windows(3)
        .any(|x| x[0] == 0 && x[1] == 3 && x[2] & 0x80 != 0)
    {
        Strings::Nsis3Ansi
    } else {
        Strings::Nsis2Ansi
    }
}

/// One instruction: its number and six parameters.
fn instruction(h: &[u8], at: usize) -> [u32; 7] {
    let mut c = [0u32; 7];
    for (k, v) in c.iter_mut().enumerate() {
        *v = le32(h, at + 4 * k).unwrap_or(0);
    }
    c
}

/// Reads the header: its blocks, strings and instructions.
pub(super) fn parse(h: &[u8], max_entries: u64) -> Result<Parsed> {
    // Flags, then eight blocks (pages, sections, instructions, strings, language tables,
    // colours, font, data), each an offset and a count; a 64-bit installer's offsets take 8
    // bytes.
    let is64 = h.len() >= 4 + 12 * 8 && (0..8).all(|k| le32(h, 8 + 12 * k) == Some(0));
    let bh = if is64 { 12 } else { 8 };
    let block = |k: usize| -> Option<(usize, usize)> {
        let p = 4 + bh * k;
        Some((le32(h, p)? as usize, le32(h, p + bh - 4)? as usize))
    };
    let short = || bad("the header is cut short");
    let (ent_off, ent_num) = block(2).ok_or_else(short)?;
    let (str_off, _) = block(3).ok_or_else(short)?;
    let (lang_off, _) = block(4).ok_or_else(short)?;
    if str_off > h.len() || lang_off > h.len() || lang_off < str_off.saturating_add(2) {
        return Err(bad("the header's string table is out of place"));
    }
    if ent_num
        .checked_mul(28)
        .and_then(|n| n.checked_add(ent_off))
        .is_none_or(|e| e > h.len())
    {
        return Err(bad(format!(
            "the header's {ent_num} instructions run past its end"
        )));
    }
    let s = &h[str_off..lang_off];
    let mut t = Table {
        s,
        kind: kind(s),
        nsis225: false,
        nsis200: false,
    };
    let ins = |k: usize| instruction(h, ent_off + 28 * k);

    // NSIS 2.25 and older: `$_OUTDIR` and `$HWNDPARENT` have other numbers (7-Zip's test).
    if t.kind == Strings::Nsis2Ansi {
        for k in 0..ent_num {
            let c = ins(k);
            let p = &c[1..];
            if c[0] == EW_GETDLGITEM && t.is_var(p[1], VAR_HWNDPARENT_225) {
                t.nsis225 = true;
                if p[0] == VAR_SPEC_OUTDIR_225 {
                    t.nsis200 = true;
                    break;
                }
            } else if c[0] == EW_ASSIGNVAR
                && p[0] == VAR_SPEC_OUTDIR_225
                && p[2] == 0
                && p[3] == 0
                && t.is_var(p[1], VAR_OUTDIR)
            {
                t.nsis225 = true;
            }
        }
    }

    // Park's builds number instructions from `RegisterDLL` on one or two later (its font
    // instructions), and its Unicode builds two more from `FileSeek` on. A `WriteUninstaller`
    // whose second name is `$INSTDIR\` and its first shows by how many.
    let mut fonts = 0u32;
    let park = t.kind == Strings::ParkUnicode;
    if park || t.kind == Strings::Nsis2Ansi {
        let wide = if park { 2 } else { 0 };
        'find: for k in 0..ent_num {
            let c = ins(k);
            let p = &c[1..];
            let Some(extra) = c[0].checked_sub(EW_WRITEUNINSTALLER + wide) else {
                continue;
            };
            if extra > 2 || p[4] != 0 || p[5] != 0 || p[0] <= 1 || p[3] <= 1 {
                continue;
            }
            let (Some(name), Some(alt)) = (t.string(p[0]), t.string(p[3])) else {
                continue;
            };
            let mut want = b"$INSTDIR\\".to_vec();
            want.extend_from_slice(&name);
            if alt == want {
                fonts = extra;
                break 'find;
            }
        }
    }
    let canonical = |raw: u32| -> u32 {
        if raw < EW_REGISTERDLL || fonts == 0 && !park {
            return raw;
        }
        let a = raw.saturating_sub(fonts);
        if park && a >= 58 {
            return a.saturating_sub(2);
        }
        a
    };

    let spec_outdir_var = if t.nsis225 {
        VAR_SPEC_OUTDIR_225
    } else {
        VAR_SPEC_OUTDIR
    };
    let mut prefix: Vec<u8> = b"$INSTDIR".to_vec();
    let mut spec_outdir: Vec<u8> = Vec::new();
    let mut items: Vec<Item> = Vec::new();
    let mut names = 0usize;
    let join = |prefix: &[u8], index: u32, name: Vec<u8>, t: &Table<'_>| -> Vec<u8> {
        if t.absolute(index, &name) {
            name
        } else {
            let mut p = prefix.to_vec();
            if !p.is_empty() && !p.ends_with(b"\\") {
                p.push(b'\\');
            }
            p.extend_from_slice(&name);
            p
        }
    };
    for k in 0..ent_num {
        let c = ins(k);
        let p = &c[1..];
        let before = items.len();
        match canonical(c[0]) {
            EW_CREATEDIR if p[1] != 0 => {
                let Some(mut s) = t.string(p[0]) else {
                    continue;
                };
                match t.leading_var(p[0]) {
                    Some((v, _)) if v == spec_outdir_var => {
                        let rest = s.split_off(spec_outdir_var_len(&t, v));
                        s = [spec_outdir.as_slice(), rest.as_slice()].concat();
                    }
                    Some((VAR_OUTDIR, _)) => {
                        let rest = s.split_off(b"$OUTDIR".len());
                        s = [prefix.as_slice(), rest.as_slice()].concat();
                    }
                    _ => {}
                }
                if s.len() > MAX_PATH {
                    return Err(bad(format!(
                        "an output folder is longer than {MAX_PATH} bytes"
                    )));
                }
                prefix = s;
            }
            EW_ASSIGNVAR if p[0] == spec_outdir_var => {
                spec_outdir.clear();
                if t.is_var(p[1], VAR_OUTDIR) && p[2] == 0 && p[3] == 0 {
                    spec_outdir.clone_from(&prefix);
                }
            }
            EW_EXTRACTFILE => {
                let mut index = p[1];
                // Library.nsh's InstallLib extracts to `$R0`, a temporary name; the library's
                // own name was put in `$R4` 28 instructions before (26 in its old form).
                if t.is_var(index, VAR_R0) {
                    let back = if k > 1 && ins(k - 1)[0] == EW_NOP {
                        26
                    } else {
                        28
                    };
                    if k > back {
                        let a = ins(k - back);
                        if a[0] == EW_ASSIGNVAR && a[1] == VAR_R4 && a[3] == 0 && a[4] == 0 {
                            index = a[2];
                        }
                    }
                }
                let Some(name) = t.string(index) else {
                    continue;
                };
                let name = join(&prefix, index, name, &t);
                let ft = u64::from(p[3]) | (u64::from(p[4]) << 32);
                items.push(Item {
                    name,
                    pos: p[2],
                    kind: ItemKind::File,
                    // 7-Zip's test for a time that's set.
                    mtime: (p[4] > 0x0100_0000 && p[4] < 0xFF00_0000).then_some(ft),
                    attrib: None,
                });
            }
            EW_SETFILEATTRIBUTES => {
                // Right after the `File` it's for.
                if k > 0 {
                    let prev = ins(k - 1);
                    if prev[0] == EW_EXTRACTFILE
                        && prev[2] == p[0]
                        && let Some(last) = items.last_mut()
                    {
                        last.attrib = Some(p[1]);
                    }
                }
            }
            EW_WRITEUNINSTALLER => {
                if p[0] == 0 || p[4] != 0 || p[5] != 0 {
                    continue;
                }
                let Some(mut name) = t.string(p[0]) else {
                    continue;
                };
                // NSIS 2.29 and on: `$INSTDIR\` and the name, used when the name isn't
                // absolute.
                if p[3] != 0
                    && !t.absolute(p[0], &name)
                    && let Some(alt) = t.string(p[3])
                {
                    name = alt;
                }
                items.push(Item {
                    name,
                    pos: p[1],
                    kind: ItemKind::Uninstaller { patch: p[2] != 0 },
                    mtime: None,
                    attrib: None,
                });
            }
            EW_FOPEN if p[2] == CREATE_ALWAYS && p[1] == GENERIC_WRITE => {
                if k + 1 < ent_num {
                    let next = ins(k + 1);
                    if canonical(next[0]) == EW_FCLOSE
                        && next[1] == p[0]
                        && let Some(name) = t.string(p[3])
                    {
                        let name = join(&prefix, p[3], name, &t);
                        items.push(Item {
                            name,
                            pos: 0,
                            kind: ItemKind::Empty,
                            mtime: None,
                            attrib: None,
                        });
                    }
                }
            }
            _ => continue,
        }
        let Some(last) = items.last().filter(|_| items.len() > before) else {
            continue;
        };
        if last.name.len() > MAX_PATH {
            return Err(bad(format!(
                "a file's name is longer than {MAX_PATH} bytes"
            )));
        }
        names += last.name.len();
        if names > MAX_NAMES {
            return Err(Error::limit(format!(
                "nsis: the installer's names take more than {} MiB",
                MAX_NAMES >> 20
            )));
        }
        if items.len() as u64 > max_entries {
            return Err(Error::limit(format!(
                "nsis: the installer has more than {max_entries} files (limit `max_entries`)"
            )));
        }
    }

    // As 7-Zip lists them: by data position, empty files first; a name repeated at one
    // position once.
    for it in &mut items {
        for b in &mut it.name {
            if *b == b'\\' {
                *b = b'/';
            }
        }
        if it.name.len() > 9 && it.name[..9].eq_ignore_ascii_case(b"$INSTDIR/") {
            it.name.drain(..9);
            while it.name.first() == Some(&b'/') {
                it.name.remove(0);
            }
        }
    }
    items.sort_by(|a, b| {
        a.pos.cmp(&b.pos).then_with(|| {
            let ea = a.kind == ItemKind::Empty;
            let eb = b.kind == ItemKind::Empty;
            eb.cmp(&ea).then_with(|| a.name.cmp(&b.name))
        })
    });
    items.dedup_by(|b, a| a.kind != ItemKind::Empty && a.pos == b.pos && a.name == b.name);
    Ok(Parsed {
        strings: t.kind,
        is64,
        instructions: ent_num,
        items,
    })
}

/// The bytes `$_OUTDIR` (or its NSIS 2.25 number's name) takes in a decoded string.
fn spec_outdir_var_len(t: &Table<'_>, v: u32) -> usize {
    t.var_name(v).len()
}
