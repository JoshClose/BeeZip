//! CHM files made by hand, for BeeZip's tests, fuzzing seeds and malicious corpus (docs/M9.md
//! §8). Section 1 is LZX in uncompressed blocks (one per reset interval, padded to whole 32 KiB
//! frames, as real compilers pad their last frame), so every field is the caller's to set or
//! break. Not a CHM compiler: there's no index, and no `#SYSTEM` unless a file of that name is
//! given.

/// A file to store: its name as the directory holds it (with its leading `/`), its section and
/// its data.
#[derive(Debug, Clone, Copy)]
pub struct File<'a> {
    pub name: &'a str,
    pub section: u64,
    pub data: &'a [u8],
}

/// A directory entry written as given, wherever it points.
#[derive(Debug, Clone)]
pub struct Raw {
    pub name: Vec<u8>,
    pub section: u64,
    pub offset: u64,
    pub length: u64,
}

/// How to lay the file out, and what to say about it. The defaults are a well-formed CHM as
/// Microsoft's compiler writes one.
#[derive(Debug, Clone)]
pub struct Layout {
    /// 3, or 2 (no content offset: section 0 follows the directory).
    pub itsf_version: u32,
    /// The directory after the content, with a content offset of 0 (7-Zip's help file).
    pub dir_at_end: bool,
    pub chunk_size: u32,
    /// What the directory header says its chunk size is; `None` is `chunk_size`.
    pub chunk_size_field: Option<u32>,
    /// What the directory header says is the first listing chunk; `None` is the real one.
    pub first_pmgl: Option<u32>,
    /// Leading `0x80` bytes on the first entry's name length (a long ENCINT).
    pub encint_padding: usize,
    pub section_names: Vec<String>,
    /// `Transform/List`, as UTF-16; its stated length is 38 bytes, as the compilers write it.
    pub transform: String,
    pub lzxc_magic: [u8; 4],
    /// 2 counts the reset interval and window in 32 KiB frames, 1 in bytes.
    pub lzxc_version: u32,
    /// In 32 KiB frames.
    pub reset_frames: u32,
    pub window_frames: u32,
    pub reset_version: u32,
    pub reset_entry_size: u32,
    pub reset_block: u64,
    /// Section 1's length as the reset table states it; `None` is the real one.
    pub uncompressed: Option<u64>,
    /// The reset table's entries; `None` is each frame's real first byte.
    pub reset_starts: Option<Vec<u64>>,
    /// More directory entries, as given.
    pub extra: Vec<Raw>,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            itsf_version: 3,
            dir_at_end: false,
            chunk_size: 0x1000,
            chunk_size_field: None,
            first_pmgl: None,
            encint_padding: 0,
            section_names: vec!["Uncompressed".to_owned(), "MSCompressed".to_owned()],
            transform: "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}".to_owned(),
            lzxc_magic: *b"LZXC",
            lzxc_version: 2,
            reset_frames: 2,
            window_frames: 2,
            reset_version: 2,
            reset_entry_size: 8,
            reset_block: 0x8000,
            uncompressed: None,
            reset_starts: None,
            extra: Vec::new(),
        }
    }
}

const FRAME: usize = 0x8000;

fn encint(out: &mut Vec<u8>, v: u64, padding: usize) {
    let mut groups = vec![(v & 0x7f) as u8];
    let mut v = v >> 7;
    while v != 0 {
        groups.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.extend(std::iter::repeat_n(0x80, padding));
    out.extend(groups.iter().rev());
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `data` as an LZX stream of uncompressed blocks, one per reset interval of `reset` frames,
/// padded to whole frames; and each frame's first byte.
fn lzx_stored(data: &[u8], reset: usize) -> (Vec<u8>, Vec<u64>) {
    let frames = data.len().div_ceil(FRAME);
    let mut out = Vec::new();
    let mut starts = Vec::new();
    let mut f = 0;
    while f < frames {
        let n = reset.max(1).min(frames - f);
        let size = (n * FRAME) as u32;
        starts.push(out.len() as u64);
        // No E8 translation (1 bit), an uncompressed block (3 bits), its size (24 bits); then
        // up to the next 16-bit word, the three repeated offsets and the bytes.
        let v = (3u32 << 28) | ((size & 0xff_ffff) << 4);
        out.extend_from_slice(&((v >> 16) as u16).to_le_bytes());
        out.extend_from_slice(&(v as u16).to_le_bytes());
        for _ in 0..3 {
            out.extend_from_slice(&1u32.to_le_bytes());
        }
        let first = out.len();
        let from = f * FRAME;
        let to = ((f + n) * FRAME).min(data.len());
        out.extend_from_slice(&data[from..to]);
        out.resize(first + n * FRAME, 0);
        for k in 1..n {
            starts.push((first + k * FRAME) as u64);
        }
        f += n;
    }
    (out, starts)
}

/// The CHM of `files`, laid out as `layout` says.
pub fn chm(files: &[File<'_>], layout: &Layout) -> Vec<u8> {
    let l = layout;
    // Section 1: the files' data end to end, then as LZX.
    let mut sec1 = Vec::new();
    let mut placed: Vec<(String, u64, u64, u64)> = Vec::new();
    for f in files.iter().filter(|f| f.section == 1) {
        placed.push((f.name.to_owned(), 1, sec1.len() as u64, f.data.len() as u64));
        sec1.extend_from_slice(f.data);
    }
    let (content, real_starts) = lzx_stored(&sec1, l.reset_frames as usize);
    let starts = l.reset_starts.clone().unwrap_or(real_starts);

    let unit = if l.lzxc_version == 1 { 0x8000 } else { 1 };
    let mut control = 6u32.to_le_bytes().to_vec();
    control.extend_from_slice(&l.lzxc_magic);
    for v in [
        l.lzxc_version,
        l.reset_frames * unit,
        l.window_frames * unit,
        1,
        0,
    ] {
        control.extend_from_slice(&v.to_le_bytes());
    }

    let mut reset = Vec::new();
    for v in [
        l.reset_version,
        starts.len() as u32,
        l.reset_entry_size,
        0x28,
    ] {
        reset.extend_from_slice(&v.to_le_bytes());
    }
    for v in [
        l.uncompressed.unwrap_or(sec1.len() as u64),
        content.len() as u64,
        l.reset_block,
    ] {
        reset.extend_from_slice(&v.to_le_bytes());
    }
    for s in &starts {
        reset.extend_from_slice(&s.to_le_bytes());
    }

    let mut names = Vec::new();
    for n in &l.section_names {
        names.extend_from_slice(&(n.encode_utf16().count() as u16).to_le_bytes());
        names.extend_from_slice(&utf16(n));
        names.extend_from_slice(&[0, 0]);
    }
    let mut namelist = (((names.len() + 4) / 2) as u16).to_le_bytes().to_vec();
    namelist.extend_from_slice(&(l.section_names.len() as u16).to_le_bytes());
    namelist.extend_from_slice(&names);

    let mut transform = utf16(&l.transform);
    transform.resize(38.max(transform.len()), 0);

    // Section 0: its files, then the streams that describe section 1, then section 1.
    let mut sec0 = Vec::new();
    let mut stored = |name: &str, data: &[u8], placed: &mut Vec<(String, u64, u64, u64)>| {
        placed.push((name.to_owned(), 0, sec0.len() as u64, data.len() as u64));
        sec0.extend_from_slice(data);
    };
    for f in files.iter().filter(|f| f.section == 0) {
        stored(f.name, f.data, &mut placed);
    }
    stored("::DataSpace/NameList", &namelist, &mut placed);
    stored(
        "::DataSpace/Storage/MSCompressed/ControlData",
        &control,
        &mut placed,
    );
    stored(
        "::DataSpace/Storage/MSCompressed/SpanInfo",
        &(sec1.len() as u64).to_le_bytes(),
        &mut placed,
    );
    stored(
        "::DataSpace/Storage/MSCompressed/Transform/List",
        &transform[..38],
        &mut placed,
    );
    stored(
        "::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable",
        &reset,
        &mut placed,
    );
    stored(
        "::DataSpace/Storage/MSCompressed/Content",
        &content,
        &mut placed,
    );
    // Files in other sections (none in a real CHM) point at nothing.
    for f in files.iter().filter(|f| f.section > 1) {
        placed.push((f.name.to_owned(), f.section, 0, f.data.len() as u64));
    }

    let hlen: u64 = if l.itsf_version >= 3 { 0x60 } else { 0x58 };
    // Section 0's offsets are from the content offset: 0 when the directory is last.
    let base = if l.dir_at_end { hlen + 0x18 } else { 0 };
    let mut entries: Vec<Raw> = vec![Raw {
        name: b"/".to_vec(),
        section: 0,
        offset: 0,
        length: 0,
    }];
    let mut folders = std::collections::BTreeSet::new();
    for (name, ..) in &placed {
        if !name.starts_with('/') {
            continue;
        }
        let mut at = 0;
        while let Some(i) = name[at + 1..].find('/') {
            at += 1 + i;
            folders.insert(name[..=at].to_owned());
        }
    }
    entries.extend(folders.into_iter().map(|f| Raw {
        name: f.into_bytes(),
        section: 0,
        offset: 0,
        length: 0,
    }));
    entries.extend(
        placed
            .into_iter()
            .map(|(name, section, offset, length)| Raw {
                name: name.into_bytes(),
                section,
                offset: if section == 0 { offset + base } else { offset },
                length,
            }),
    );
    entries.extend(l.extra.iter().cloned());
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    // Listing chunks, then an index chunk when there are several.
    let cs = l.chunk_size as usize;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut cur = Vec::new();
    let mut counts = Vec::new();
    let mut count = 0u16;
    for (i, e) in entries.iter().enumerate() {
        let mut b = Vec::new();
        encint(
            &mut b,
            e.name.len() as u64,
            if i == 0 { l.encint_padding } else { 0 },
        );
        b.extend_from_slice(&e.name);
        encint(&mut b, e.section, 0);
        encint(&mut b, e.offset, 0);
        encint(&mut b, e.length, 0);
        if !cur.is_empty() && 0x14 + cur.len() + b.len() + 2 > cs {
            chunks.push(std::mem::take(&mut cur));
            counts.push(count);
            count = 0;
        }
        cur.extend_from_slice(&b);
        count += 1;
    }
    chunks.push(cur);
    counts.push(count);
    let pmgl = chunks.len();
    let mut dir_chunks = Vec::new();
    for (i, (c, n)) in chunks.iter().zip(&counts).enumerate() {
        let mut ch = b"PMGL".to_vec();
        let free = cs.saturating_sub(0x14 + c.len()) as u32;
        ch.extend_from_slice(&free.to_le_bytes());
        ch.extend_from_slice(&0u32.to_le_bytes());
        let prev = if i == 0 { -1 } else { i as i32 - 1 };
        let next = if i + 1 == pmgl { -1 } else { i as i32 + 1 };
        ch.extend_from_slice(&prev.to_le_bytes());
        ch.extend_from_slice(&next.to_le_bytes());
        ch.extend_from_slice(c);
        ch.resize(cs.max(ch.len() + 2), 0);
        let at = ch.len() - 2;
        ch[at..].copy_from_slice(&n.to_le_bytes());
        dir_chunks.push(ch);
    }
    if pmgl > 1 {
        let mut ch = b"PMGI".to_vec();
        ch.extend_from_slice(&(cs as u32 - 8).to_le_bytes());
        ch.resize(cs, 0);
        dir_chunks.push(ch);
    }
    let mut dir = b"ITSP".to_vec();
    let root: i32 = if pmgl > 1 { pmgl as i32 } else { -1 };
    for v in [
        1u32,
        0x54,
        0x0a,
        l.chunk_size_field.unwrap_or(l.chunk_size),
        2,
        if pmgl > 1 { 2 } else { 1 },
    ] {
        dir.extend_from_slice(&v.to_le_bytes());
    }
    dir.extend_from_slice(&root.to_le_bytes());
    dir.extend_from_slice(&l.first_pmgl.unwrap_or(0).to_le_bytes());
    dir.extend_from_slice(&(pmgl as u32 - 1).to_le_bytes());
    dir.extend_from_slice(&(-1i32).to_le_bytes());
    dir.extend_from_slice(&(dir_chunks.len() as u32).to_le_bytes());
    dir.extend_from_slice(&0x409u32.to_le_bytes());
    dir.extend_from_slice(&[
        0x6a, 0x92, 0x02, 0x5d, 0x2e, 0x21, 0xd0, 0x11, 0x9d, 0xf9, 0x00, 0xa0, 0xc9, 0x22, 0xe6,
        0xec,
    ]);
    dir.extend_from_slice(&0x54u32.to_le_bytes());
    for _ in 0..3 {
        dir.extend_from_slice(&(-1i32).to_le_bytes());
    }
    for c in &dir_chunks {
        dir.extend_from_slice(c);
    }

    let dir_off = if l.dir_at_end {
        hlen + 0x18 + sec0.len() as u64
    } else {
        hlen + 0x18
    };
    let content_off = if l.dir_at_end {
        0
    } else {
        dir_off + dir.len() as u64
    };
    let total = hlen + 0x18 + dir.len() as u64 + sec0.len() as u64;
    let mut out = b"ITSF".to_vec();
    for v in [l.itsf_version, hlen as u32, 1, 0, 0x409] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    // {7C01FD10-7BAA-11D0-9E0C-00A0C922E6EC}, {7C01FD11-…}.
    for last in [0x10u8, 0x11] {
        out.extend_from_slice(&[
            last, 0xfd, 0x01, 0x7c, 0xaa, 0x7b, 0xd0, 0x11, 0x9e, 0x0c, 0x00, 0xa0, 0xc9, 0x22,
            0xe6, 0xec,
        ]);
    }
    for v in [hlen, 0x18, dir_off, dir.len() as u64] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    if l.itsf_version >= 3 {
        out.extend_from_slice(&content_off.to_le_bytes());
    }
    out.extend_from_slice(&0x1feu32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    if l.dir_at_end {
        out.extend_from_slice(&sec0);
        out.extend_from_slice(&dir);
    } else {
        out.extend_from_slice(&dir);
        out.extend_from_slice(&sec0);
    }
    out
}
