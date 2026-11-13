//! NSIS installers made by hand, for BeeZip's tests, fuzzing seeds and malicious corpus
//! (docs/M10.md §8): the layouts makensis 3 doesn't write any more (NSIS 2's ANSI strings and
//! stored blocks, Jim Park's Unicode strings and instruction numbers, LZMA with the x86 filter,
//! a stored header before compressed records), and broken ones. The smallest PE file there is
//! stands for the installer's program, so detection finds the installer at its overlay; the
//! header has the blocks BeeZip reads and nothing else.

use std::io::Write;

use flate2::{Compression, write::DeflateEncoder};

use super::{FIRST_LEN, SIGNATURE};

/// Which NSIS's strings to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strings {
    Nsis2Ansi,
    Nsis3Ansi,
    Nsis3Unicode,
    ParkUnicode,
}

/// How a stream or record is compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Deflate,
    /// NSIS 2's: stored blocks with no NLEN.
    Nsis2Deflate,
    /// `filter`: the byte before the properties, and BCJ x86 when it's 1.
    Lzma {
        filter: Option<bool>,
    },
}

/// What the installer does, as instructions.
#[derive(Debug, Clone)]
pub enum Op<'a> {
    /// `SetOutPath`.
    SetOutPath(&'a [u8]),
    /// `File`: a name and data; identical data is stored once.
    File(&'a [u8], &'a [u8]),
    /// `File` of a name, with its data at the position given, wherever that is.
    FileAt(&'a [u8], u32),
    /// `WriteUninstaller`: its name, `$INSTDIR\`'s form of it, the uninstaller's data, and
    /// icon patches to the stub (offset, bytes).
    WriteUninstaller {
        name: &'a [u8],
        alt: Option<&'a [u8]>,
        data: &'a [u8],
        patches: Vec<(u32, Vec<u8>)>,
    },
    /// `FileOpen $0 name w` then `FileClose $0`.
    EmptyFile(&'a [u8]),
    /// `StrCpy $var value`.
    Assign(u32, &'a [u8]),
    /// `SetFileAttributes name attributes`, right after its `File`.
    Attributes(&'a [u8], u32),
    Nop,
    /// An instruction as given, its strings by index.
    Raw([u32; 7]),
}

/// How to lay the installer out. The default is makensis 3's: Unicode, solid LZMA, a CRC.
#[derive(Debug, Clone)]
pub struct Layout {
    pub strings: Strings,
    pub solid: bool,
    pub method: Method,
    /// Non-solid: the header compressed, as makensis does, or stored (MuMu's tools).
    pub header_compressed: bool,
    /// The stub before the first header: a multiple of 512, or 0 for bare data.
    pub stub: usize,
    pub crc: bool,
    pub uninstaller: bool,
    pub is64: bool,
    /// Park's instruction numbers: its font instructions (0 to 2).
    pub park_fonts: u32,
    /// The FILETIME each `File` has.
    pub mtime: u64,
    /// The LZMA dictionary.
    pub dict: u32,
    /// Lengths to state for records, by their index in data order, instead of their own.
    pub lengths: Vec<(usize, u32)>,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            strings: Strings::Nsis3Unicode,
            solid: true,
            method: Method::Lzma { filter: None },
            header_compressed: true,
            stub: 4096,
            crc: true,
            uninstaller: false,
            is64: false,
            park_fonts: 0,
            // 2026-01-01T00:00:00Z.
            mtime: 134_116_992_000_000_000,
            dict: 1 << 20,
            lengths: Vec::new(),
        }
    }
}

/// Variables by name, as NSIS numbers them.
fn var(name: &str) -> Option<u32> {
    let internal = [
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
    if let Some(k) = internal.iter().position(|v| *v == name) {
        return Some(20 + k as u32);
    }
    let (r, digits) = match name.strip_prefix('R') {
        Some(d) => (10, d),
        None => (0, name),
    };
    (digits.len() == 1)
        .then(|| digits.parse::<u32>().ok().map(|d| r + d))
        .flatten()
}

/// Shell folders by name, by CSIDL.
fn shell(name: &str) -> Option<u8> {
    Some(match name {
        "SYSDIR" => 0x25,
        "APPDATA" => 0x1A,
        "WINDIR" => 0x24,
        "DESKTOP" => 0x10,
        _ => return None,
    })
}

/// A string as `kind` stores it: `$NAME` for variables and folders.
fn encode(text: &[u8], kind: Strings) -> Vec<u16> {
    let unicode = matches!(kind, Strings::Nsis3Unicode | Strings::ParkUnicode);
    // Units: bytes for ANSI, UTF-16 for Unicode.
    let mut out: Vec<u16> = Vec::new();
    let push_text = |out: &mut Vec<u16>, t: &[u8]| {
        if unicode {
            for u in String::from_utf8_lossy(t).encode_utf16() {
                let special = match kind {
                    Strings::Nsis3Unicode => u <= 4,
                    _ => (0xE000..=0xE003).contains(&u),
                };
                if special {
                    out.push(if kind == Strings::ParkUnicode {
                        0xE000
                    } else {
                        4
                    });
                }
                out.push(u);
            }
        } else {
            for &b in t {
                let special = match kind {
                    Strings::Nsis2Ansi => b >= 252,
                    _ => b <= 4,
                };
                if special {
                    out.push(if kind == Strings::Nsis2Ansi { 252 } else { 4 });
                }
                out.push(u16::from(b));
            }
        }
    };
    let mut i = 0;
    let mut plain = 0;
    while i < text.len() {
        if text[i] != b'$' {
            i += 1;
            continue;
        }
        let len = text[i + 1..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
            .count();
        // The longest name that's a variable or folder.
        let found = (1..=len).rev().find_map(|n| {
            let name = std::str::from_utf8(&text[i + 1..i + 1 + n]).ok()?;
            var(name)
                .map(|v| (n, Ok(v)))
                .or_else(|| shell(name).map(|s| (n, Err(s))))
        });
        let Some((n, what)) = found else {
            i += 1;
            continue;
        };
        push_text(&mut out, &text[plain..i]);
        match (what, kind) {
            (Ok(v), Strings::ParkUnicode) => out.extend([0xE001, v as u16 | 0x8000]),
            (Ok(v), Strings::Nsis3Unicode) => {
                out.extend([3, ((v & 0x7F) | ((v >> 7) & 0x7F) << 8) as u16 | 0x8080]);
            }
            (Ok(v), _) => {
                let code = if kind == Strings::Nsis2Ansi { 253 } else { 3 };
                out.extend([
                    code,
                    (v & 0x7F) as u16 | 0x80,
                    ((v >> 7) & 0x7F) as u16 | 0x80,
                ]);
            }
            (Err(s), Strings::ParkUnicode) => {
                out.extend([0xE002, u16::from(s) | u16::from(s) << 8])
            }
            (Err(s), Strings::Nsis3Unicode) => out.extend([2, u16::from(s) | u16::from(s) << 8]),
            (Err(s), _) => {
                let code = if kind == Strings::Nsis2Ansi { 254 } else { 2 };
                out.extend([code, u16::from(s), u16::from(s)]);
            }
        }
        i += 1 + n;
        plain = i;
    }
    push_text(&mut out, &text[plain..]);
    out.push(0);
    out
}

/// The string table, each string stored once.
struct Table {
    kind: Strings,
    units: Vec<u16>,
    index: Vec<(Vec<u8>, u32)>,
}

impl Table {
    fn new(kind: Strings) -> Self {
        // An empty string first, as makensis writes.
        Self {
            kind,
            units: vec![0],
            index: vec![(Vec::new(), 0)],
        }
    }

    fn add(&mut self, s: &[u8]) -> u32 {
        if let Some((_, i)) = self.index.iter().find(|(t, _)| t == s) {
            return *i;
        }
        let at = self.units.len() as u32;
        self.units.extend(encode(s, self.kind));
        self.index.push((s.to_vec(), at));
        at
    }

    fn bytes(&self) -> Vec<u8> {
        match self.kind {
            Strings::Nsis3Unicode | Strings::ParkUnicode => {
                self.units.iter().flat_map(|u| u.to_le_bytes()).collect()
            }
            _ => self.units.iter().map(|&u| u as u8).collect(),
        }
    }
}

/// Raw deflate, zlib's form.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::best());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

/// Deflate as NSIS 2's makensis could write it: stored blocks with LEN and no NLEN.
pub fn nsis2_deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let blocks: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(30_000).collect()
    };
    for (i, b) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        out.extend_from_slice(&(b.len() as u16).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// NSIS's LZMA: the properties, then the stream with an end marker; the x86 filter's byte
/// first when asked.
pub fn lzma(data: &[u8], filter: Option<bool>, dict: u32) -> Vec<u8> {
    let mut opts = lzma_rust2::LzmaOptions::with_preset(6);
    opts.dict_size = dict;
    let mut out = Vec::new();
    if let Some(bcj) = filter {
        out.push(u8::from(bcj));
    }
    out.push(opts.get_props());
    out.extend_from_slice(&dict.to_le_bytes());
    let Ok(mut w) = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &opts, true) else {
        return out;
    };
    if filter == Some(true) {
        let mut b = lzma_rust2::filter::bcj::BcjWriter::new_x86(&mut w, 0);
        let _ = b.write_all(data);
        let _ = b.finish();
    } else {
        let _ = w.write_all(data);
    }
    if let Ok(stream) = w.finish() {
        out.extend_from_slice(&stream);
    }
    out
}

fn compress(data: &[u8], method: Method, dict: u32) -> Vec<u8> {
    match method {
        Method::Deflate => deflate(data),
        Method::Nsis2Deflate => nsis2_deflate(data),
        Method::Lzma { filter } => lzma(data, filter, dict),
    }
}

/// A stub of `len` bytes: a PE header with one section that runs to its end, where the
/// overlay starts (`detect::pe_overlay`). Under 512 bytes, zeros.
pub fn stub(len: usize) -> Vec<u8> {
    let mut s = vec![0u8; len];
    if len < 512 {
        return s;
    }
    s[..2].copy_from_slice(b"MZ");
    s[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    s[0x40..0x44].copy_from_slice(b"PE\0\0");
    // i386, one section, no optional header.
    s[0x44..0x46].copy_from_slice(&0x14Cu16.to_le_bytes());
    s[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    let section = 0x58;
    s[section..section + 8].copy_from_slice(b".text\0\0\0");
    s[section + 16..section + 20].copy_from_slice(&(len as u32).to_le_bytes());
    s
}

fn put(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// The installer `ops` describe, under `layout`.
pub fn nsis(ops: &[Op<'_>], layout: &Layout) -> Vec<u8> {
    let mut t = Table::new(layout.strings);
    let park = layout.strings == Strings::ParkUnicode;
    let fonts = layout.park_fonts;
    let wide = if park { 2 } else { 0 };
    // The data records: each distinct piece of data once.
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut pos_of: Vec<(Vec<u8>, u32)> = Vec::new();
    let mut next_pos = 0u32;
    let record_len = |data: &[u8]| -> u32 {
        if layout.solid {
            data.len() as u32
        } else {
            compress(data, layout.method, layout.dict).len() as u32
        }
    };
    let mut add = |data: &[u8], dedupe: bool| -> u32 {
        if dedupe && let Some((_, p)) = pos_of.iter().find(|(d, _)| d == data) {
            return *p;
        }
        let p = next_pos;
        next_pos += 4 + record_len(data);
        records.push(data.to_vec());
        pos_of.push((data.to_vec(), p));
        p
    };
    let mut ins: Vec<[u32; 7]> = Vec::new();
    let lo = layout.mtime as u32;
    let hi = (layout.mtime >> 32) as u32;
    for op in ops {
        match op {
            Op::SetOutPath(p) => ins.push([11, t.add(p), 1, 0, 0, 0, 0]),
            Op::File(name, data) => {
                let pos = add(data, true);
                ins.push([20, 0, t.add(name), pos, lo, hi, 0]);
            }
            Op::FileAt(name, pos) => ins.push([20, 0, t.add(name), *pos, lo, hi, 0]),
            Op::WriteUninstaller {
                name,
                alt,
                data,
                patches,
            } => {
                let mut patch = Vec::new();
                for (off, bytes) in patches {
                    put(&mut patch, bytes.len() as u32);
                    put(&mut patch, *off);
                    patch.extend_from_slice(bytes);
                }
                let pos = if patch.is_empty() {
                    add(data, false)
                } else {
                    put(&mut patch, 0);
                    let p = add(&patch, false);
                    add(data, false);
                    p
                };
                let alt = alt.map_or(0, |a| t.add(a));
                ins.push([
                    62 + fonts + wide,
                    t.add(name),
                    pos,
                    u32::from(!patches.is_empty()),
                    alt,
                    0,
                    0,
                ]);
            }
            Op::EmptyFile(name) => {
                ins.push([55 + fonts, 0, 1 << 30, 2, t.add(name), 0, 0]);
                ins.push([54 + fonts, 0, 0, 0, 0, 0, 0]);
            }
            Op::Assign(v, value) => ins.push([25, *v, t.add(value), 0, 0, 0, 0]),
            Op::Attributes(name, a) => ins.push([10, t.add(name), *a, 0, 0, 0, 0]),
            Op::Nop => ins.push([2, 0, 0, 0, 0, 0, 0]),
            Op::Raw(r) => ins.push(*r),
        }
    }

    // The header: flags, eight blocks, then the instructions and the strings.
    let bh = if layout.is64 { 12 } else { 8 };
    let blocks_end = 4 + 8 * bh;
    let ent_at = blocks_end;
    let str_at = ent_at + 28 * ins.len();
    let strings = t.bytes();
    let lang_at = str_at + strings.len();
    let mut h = Vec::new();
    put(&mut h, 0);
    for k in 0..8 {
        let (off, num) = match k {
            2 => (ent_at, ins.len()),
            3 => (str_at, 0),
            4..=7 => (lang_at, 0),
            _ => (blocks_end, 0),
        };
        put(&mut h, off as u32);
        if layout.is64 {
            put(&mut h, 0);
        }
        put(&mut h, num as u32);
    }
    for i in &ins {
        for v in i {
            put(&mut h, *v);
        }
    }
    h.extend_from_slice(&strings);

    // The data.
    let stated = |k: usize, len: u32| {
        layout
            .lengths
            .iter()
            .find(|(i, _)| *i == k)
            .map_or(len, |(_, l)| *l)
    };
    let mut body = Vec::new();
    if layout.solid {
        let mut stream = Vec::new();
        put(&mut stream, h.len() as u32);
        stream.extend_from_slice(&h);
        for (k, r) in records.iter().enumerate() {
            put(&mut stream, stated(k, r.len() as u32));
            stream.extend_from_slice(r);
        }
        body = compress(&stream, layout.method, layout.dict);
    } else {
        if layout.header_compressed {
            let c = compress(&h, layout.method, layout.dict);
            put(&mut body, c.len() as u32 | 0x8000_0000);
            body.extend_from_slice(&c);
        } else {
            put(&mut body, h.len() as u32);
            body.extend_from_slice(&h);
        }
        for (k, r) in records.iter().enumerate() {
            let c = compress(r, layout.method, layout.dict);
            put(&mut body, stated(k, c.len() as u32) | 0x8000_0000);
            body.extend_from_slice(&c);
        }
    }

    let mut out = stub(layout.stub);
    let flags = u32::from(layout.uninstaller) | if layout.crc { 0 } else { 4 };
    put(&mut out, flags);
    out.extend_from_slice(SIGNATURE);
    put(&mut out, h.len() as u32);
    let arc = FIRST_LEN as usize + body.len() + if layout.crc { 4 } else { 0 };
    put(&mut out, arc as u32);
    out.extend_from_slice(&body);
    if layout.crc {
        let start = if layout.stub == 0 { 0 } else { 512 };
        let crc = crc32fast::hash(&out[start..]);
        put(&mut out, crc);
    }
    out
}
