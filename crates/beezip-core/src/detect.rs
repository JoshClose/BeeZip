//! Format detection (docs/M1.md §3.3).
//!
//! 1. Read the first 64 KiB (and, for a file, the last 64 KiB + 22 bytes) into a [`Probe`].
//! 2. Every format and codec sniffs it. The highest [`Confidence`] wins and the extension
//!    breaks ties; a match on the extension alone is a `Guess`.
//! 3. When a codec wins, decode up to 64 KiB of its output and probe again, at most
//!    `max_layers` deep: `x.tar.zst` is `[zstd, tar]`, `notes.txt.gz` is `[gzip, stream]`.
//! 4. When nothing matches, `file-format` supplies a label such as "Portable Network Graphics".
//!    BeeZip's own sniffers decide everything else.

use std::{
    fmt,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use file_format::FileFormat;

use crate::{
    CodecId, Error, Limits, Result,
    codec::{codecs, strip_extension},
    format::{
        FormatId, cab::header_at as cab_header, formats, lzh::header_at as lzh_header,
        rar::signature as rar_signature, sevenz::start_header as sevenz_start_header, zip::is_sfx,
    },
    io::read_prefix,
    volume::{SetKind, VolumeReader, find_set},
};

/// How sure a sniffer is. `Guess` is an extension match only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Guess,
    /// Magic bytes only.
    Likely,
    /// Magic bytes plus a structural check, such as the tar header checksum.
    Certain,
}

impl Confidence {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Guess => "guess",
            Self::Likely => "likely",
            Self::Certain => "certain",
        }
    }
}

/// What sniffers look at.
#[derive(Debug, Clone, Copy, Default)]
pub struct Probe<'a> {
    /// The first bytes, up to [`HEAD_LEN`].
    pub head: &'a [u8],
    /// The last bytes, up to [`TAIL_LEN`], when they were read (the outer layer of a file).
    pub tail: &'a [u8],
    /// The total length, if known.
    pub len: Option<u64>,
    /// The file name, lowercased, for extension checks.
    pub name: Option<&'a str>,
}

/// How much of the start of a stream sniffers see.
pub const HEAD_LEN: usize = 64 * 1024;
/// How much of the end: a zip end-of-central-directory record with the longest comment.
pub const TAIL_LEN: usize = 64 * 1024 + 22;

/// One layer of a file: a codec, or the format at the bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LayerKind {
    Codec(CodecId),
    Format(FormatId),
}

impl LayerKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Codec(c) => c.name(),
            Self::Format(f) => f.name(),
        }
    }

    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Codec(c) => c.codec().extensions(),
            Self::Format(f) => f.format().extensions(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layer {
    pub kind: LayerKind,
    pub confidence: Confidence,
}

/// What a file is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Detection {
    /// Outermost first. When anything was recognised the last layer is a format: an archive,
    /// or the stream format for a compressed file that isn't one.
    pub layers: Vec<Layer>,
    /// A zip inside an executable.
    pub sfx: bool,
    /// `file-format`'s name for data that isn't an archive: the file itself when nothing
    /// matched, or the decoded content of a stream.
    pub label: Option<String>,
    /// Whether the file's extension fits the outermost layer.
    pub extension_agrees: bool,
    /// The parts of a volume set, first part first; just the file itself otherwise. Empty for
    /// data detected in memory.
    pub volumes: Vec<PathBuf>,
    /// `volumes` is a numbered set (`a.7z.001`…), detected and read as one joined file.
    pub joined: bool,
    /// Where the archive starts inside an SFX, when its reader must be shown it from there
    /// (7z); 0 otherwise. zip and UnRAR find the archive themselves.
    pub offset: u64,
}

impl Detection {
    pub fn codecs(&self) -> Vec<CodecId> {
        self.layers
            .iter()
            .filter_map(|l| match l.kind {
                LayerKind::Codec(c) => Some(c),
                LayerKind::Format(_) => None,
            })
            .collect()
    }

    pub fn format(&self) -> Option<FormatId> {
        self.layers.iter().find_map(|l| match l.kind {
            LayerKind::Format(f) => Some(f),
            LayerKind::Codec(_) => None,
        })
    }

    /// `"zstd → tar"`, or `"gzip"` for a bare compressed file. Empty when nothing matched.
    pub fn chain(&self) -> String {
        self.layers
            .iter()
            .filter(|l| l.kind != LayerKind::Format(FormatId::Stream))
            .map(|l| l.kind.name())
            .collect::<Vec<_>>()
            .join(" → ")
    }

    /// The archive format and codecs to open, or `UnsupportedFormat`.
    pub fn require_archive(&self) -> Result<(FormatId, Vec<CodecId>)> {
        match self.format() {
            Some(f) => Ok((f, self.codecs())),
            None => Err(Error::unsupported_format(match &self.label {
                Some(label) => format!("not an archive or compressed file ({label})"),
                None => "not an archive or compressed file".to_owned(),
            })),
        }
    }
}

impl fmt::Display for Detection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.chain())
    }
}

/// Detects a file on disk. Any part of a numbered volume set (`a.7z.002`) is detected as the
/// joined set: the head of part 1, the tail of the last part, and the name without `.001`
/// (docs/M3.md §3.5). A set of anything else is the one-entry stream view of the joined file.
pub fn detect_path(path: &Path, limits: &Limits) -> Result<Detection> {
    match find_set(path)? {
        Some(set) if set.kind == SetKind::Numbered => {
            let reader = VolumeReader::open(&set.parts)?;
            let len = reader.len();
            let tail = read_tail(&mut reader.reopen(), len)
                .map_err(|e| Error::io(format!("reading {}", path.display()), &e))?;
            let name = set.name.to_lowercase();
            let open = || -> io::Result<Box<dyn Read + Send>> { Ok(Box::new(reader.reopen())) };
            let mut det = detect_with(&open, &tail, Some(len), Some(name), None, limits)?;
            if det.format().is_none() {
                det.layers.push(Layer {
                    kind: LayerKind::Format(FormatId::Stream),
                    confidence: Confidence::Certain,
                });
            }
            det.volumes = set.parts;
            det.joined = true;
            Ok(det)
        }
        // RAR names its own volumes, and UnRAR opens them: detect the first part, and keep
        // the set only if it is a RAR.
        Some(set) => {
            let mut det = detect_file(&set.parts[0], limits)?;
            if det.format() == Some(FormatId::Rar) {
                det.volumes = set.parts;
                return Ok(det);
            }
            let mut det = detect_file(path, limits)?;
            det.volumes = vec![path.to_path_buf()];
            Ok(det)
        }
        None => {
            let mut det = detect_file(path, limits)?;
            det.volumes = vec![path.to_path_buf()];
            Ok(det)
        }
    }
}

fn detect_file(path: &Path, limits: &Limits) -> Result<Detection> {
    let mut file =
        File::open(path).map_err(|e| Error::io(format!("opening {}", path.display()), &e))?;
    let len = file
        .metadata()
        .map_err(|e| Error::io(format!("reading {}", path.display()), &e))?
        .len();
    let tail = read_tail(&mut file, len)
        .map_err(|e| Error::io(format!("reading {}", path.display()), &e))?;
    let sfx = overlay_archive(&mut file, len);
    let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase());
    let open = || -> io::Result<Box<dyn Read + Send>> { Ok(Box::new(File::open(path)?)) };
    detect_with(&open, &tail, Some(len), name, sfx, limits)
}

/// Detects data in memory, as the fuzzers do.
pub fn detect_bytes(data: &[u8], name: Option<&str>, limits: &Limits) -> Detection {
    let tail = &data[data.len().saturating_sub(TAIL_LEN)..];
    let sfx = overlay_archive(&mut Cursor::new(data), data.len() as u64);
    let open = || -> io::Result<Box<dyn Read + Send + '_>> { Ok(Box::new(Cursor::new(data))) };
    // Reading from memory can't fail with an I/O error.
    detect_with(
        &open,
        tail,
        Some(data.len() as u64),
        name.map(str::to_lowercase),
        sfx,
        limits,
    )
    .unwrap_or_default()
}

/// Where a PE image ends, from the section table in its head: the start of its overlay, which
/// is where 7-Zip's `7z.sfx` and WinRAR's SFX modules put the archive (docs/M3.md §3.5).
pub fn pe_overlay(head: &[u8]) -> Option<u64> {
    let u16_at = |i: usize| Some(u16::from_le_bytes([*head.get(i)?, *head.get(i + 1)?]));
    let u32_at = |i: usize| {
        Some(u32::from_le_bytes([
            *head.get(i)?,
            *head.get(i + 1)?,
            *head.get(i + 2)?,
            *head.get(i + 3)?,
        ]))
    };
    if !head.starts_with(b"MZ") {
        return None;
    }
    let pe = usize::try_from(u32_at(0x3C)?).ok()?;
    if head.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let sections = usize::from(u16_at(pe + 6)?);
    let optional = usize::from(u16_at(pe + 20)?);
    let table = pe + 24 + optional;
    let mut end = 0u64;
    for s in 0..sections.min(96) {
        let at = table + s * 40;
        let size = u64::from(u32_at(at + 16)?);
        let ptr = u64::from(u32_at(at + 20)?);
        end = end.max(ptr + size);
    }
    (end > 0).then_some(end)
}

/// An archive at the overlay of a PE file: its offset and its format layer. 7z, RAR, CAB and LHA
/// SFX modules put theirs there (docs/M5.md §5.5, §5.6).
fn overlay_archive<R: Read + Seek>(r: &mut R, len: u64) -> Option<(u64, Layer)> {
    r.seek(SeekFrom::Start(0)).ok()?;
    let head = read_prefix(r, HEAD_LEN);
    let at = pe_overlay(&head)?;
    if at.checked_add(32)? > len {
        return None;
    }
    r.seek(SeekFrom::Start(at)).ok()?;
    // An LHA header and its checksum, or a cabinet's header.
    let start = read_prefix(r, 4096);
    let _ = r.seek(SeekFrom::Start(0));
    let rest = len - at;
    let (kind, confidence) = sevenz_start_header(&start)
        .map(|c| (FormatId::SevenZ, c))
        .or_else(|| rar_signature(&start).map(|c| (FormatId::Rar, c)))
        .or_else(|| cab_header(&start, Some(rest)).map(|c| (FormatId::Cab, c)))
        .or_else(|| lzh_header(&start).map(|c| (FormatId::Lzh, c)))?;
    Some((
        at,
        Layer {
            kind: LayerKind::Format(kind),
            confidence,
        },
    ))
}

fn read_tail<R: Read + Seek>(file: &mut R, len: u64) -> io::Result<Vec<u8>> {
    let want = len.min(TAIL_LEN as u64);
    file.seek(SeekFrom::Start(len - want))?;
    let mut tail = Vec::new();
    file.take(want).read_to_end(&mut tail)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(tail)
}

type Opener<'s> = dyn Fn() -> io::Result<Box<dyn Read + Send + 's>> + 's;

fn detect_with<'s>(
    open: &Opener<'s>,
    tail: &[u8],
    len: Option<u64>,
    name: Option<String>,
    sfx: Option<(u64, Layer)>,
    limits: &Limits,
) -> Result<Detection> {
    let mut det = Detection::default();
    let mut codec_layers: Vec<CodecId> = Vec::new();
    let mut name = name;
    let outer_name = name.clone();

    loop {
        // A fresh stream through every codec found so far. A decoder that refuses to start
        // (over the memory limit, say) leaves nothing to probe.
        let head = match open_chain(open, &codec_layers, limits)? {
            Some(mut r) => read_prefix(&mut r, HEAD_LEN),
            None => Vec::new(),
        };
        let outer = codec_layers.is_empty();
        let probe = Probe {
            head: &head,
            tail: if outer { tail } else { &[] },
            // Inside a codec the length is only known when the whole output fit in the head.
            len: if outer {
                len
            } else {
                (head.len() < HEAD_LEN).then_some(head.len() as u64)
            },
            name: name.as_deref(),
        };

        // An extension alone doesn't stand against content file-format recognises: a PNG named
        // `a.zip` is a PNG.
        let best = best_match(&probe).filter(|l| {
            l.confidence > Confidence::Guess
                || FileFormat::from_bytes(&head) == FileFormat::ArbitraryBinaryData
        });
        match best {
            Some(
                layer @ Layer {
                    kind: LayerKind::Format(f),
                    ..
                },
            ) => {
                det.sfx = outer && f == FormatId::Zip && is_sfx(&probe);
                det.layers.push(layer);
                break;
            }
            Some(
                layer @ Layer {
                    kind: LayerKind::Codec(c),
                    ..
                },
            ) if codec_layers.len() < limits.max_layers => {
                det.layers.push(layer);
                codec_layers.push(c);
                name = name.and_then(|n| strip_extension(&n, c));
            }
            // An executable with an archive at its overlay: a 7z or RAR SFX.
            _ if outer && sfx.is_some() => {
                if let Some((offset, layer)) = sfx {
                    det.layers.push(layer);
                    det.sfx = true;
                    det.offset = offset;
                }
                break;
            }
            // Nothing recognised, or too deep: what's left is data.
            _ => {
                if !outer {
                    det.layers.push(Layer {
                        kind: LayerKind::Format(FormatId::Stream),
                        confidence: Confidence::Certain,
                    });
                }
                det.label = label(&head);
                break;
            }
        }
    }

    det.extension_agrees = extension_agrees(&det, outer_name.as_deref());
    Ok(det)
}

fn open_chain<'s>(
    open: &Opener<'s>,
    codecs: &[CodecId],
    limits: &Limits,
) -> Result<Option<Box<dyn Read + Send + 's>>> {
    let mut r = open().map_err(|e| Error::io("reading the file", &e))?;
    for c in codecs {
        r = match c.decoder(r, limits) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
    }
    Ok(Some(r))
}

/// The best layer for a probe: highest confidence, then an extension match, then the order
/// formats come before codecs.
fn best_match(probe: &Probe<'_>) -> Option<Layer> {
    let ext = |exts: &[&str]| {
        probe
            .name
            .is_some_and(|n| exts.iter().any(|e| n.ends_with(e)))
    };
    let mut candidates: Vec<(Confidence, bool, LayerKind)> = Vec::new();
    for f in formats() {
        let kind = LayerKind::Format(f.id());
        let by_ext = ext(f.extensions());
        if let Some(c) = f.sniff(probe) {
            candidates.push((c, by_ext, kind));
        } else if by_ext {
            candidates.push((Confidence::Guess, true, kind));
        }
    }
    for c in codecs() {
        let kind = LayerKind::Codec(c.id());
        let by_ext = ext(c.extensions());
        if let Some(conf) = c.sniff(probe) {
            candidates.push((conf, by_ext, kind));
        } else if by_ext && !probe.head.is_empty() {
            candidates.push((Confidence::Guess, true, kind));
        }
    }
    // `max_by_key` keeps the last maximum, so iterate in reverse to prefer earlier entries.
    candidates
        .into_iter()
        .rev()
        .max_by_key(|(conf, by_ext, _)| (*conf, *by_ext))
        .map(|(confidence, _, kind)| Layer { kind, confidence })
}

fn label(head: &[u8]) -> Option<String> {
    if head.is_empty() {
        return Some("Empty".to_owned());
    }
    Some(FileFormat::from_bytes(head).name().to_owned())
}

fn extension_agrees(det: &Detection, name: Option<&str>) -> bool {
    let Some(name) = name else {
        return true;
    };
    match det.layers.first() {
        Some(layer) if det.sfx => {
            name.ends_with(".exe") || layer.kind.extensions().iter().any(|e| name.ends_with(e))
        }
        Some(layer) => layer.kind.extensions().iter().any(|e| name.ends_with(e)),
        // Not an archive: the name shouldn't claim to be one, and should fit what it is.
        None => !formats()
            .map(|f| f.extensions())
            .chain(codecs().map(|c| c.extensions()))
            .flatten()
            .any(|e| name.ends_with(e)),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::EncodeOpts;

    fn compress(codec: CodecId, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut enc = codec
            .codec()
            .encoder(Box::new(&mut out), &EncodeOpts::default())
            .unwrap();
        enc.write_all(data).unwrap();
        enc.finish().unwrap();
        out
    }

    fn kinds(det: &Detection) -> Vec<LayerKind> {
        det.layers.iter().map(|l| l.kind).collect()
    }

    fn tar_header() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..5].copy_from_slice(b"a.txt");
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(b"00000000005");
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u32::from(b)
                }
            })
            .sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h.extend_from_slice(b"hello");
        h.resize(512 * 4, 0);
        h
    }

    #[test]
    fn compressed_tar_is_two_layers() {
        let tar = tar_header();
        let det = detect_bytes(
            &compress(CodecId::Zstd, &tar),
            Some("x.tar.zst"),
            &Limits::default(),
        );
        assert_eq!(
            kinds(&det),
            [
                LayerKind::Codec(CodecId::Zstd),
                LayerKind::Format(FormatId::Tar)
            ]
        );
        assert_eq!(det.chain(), "zstd → tar");
        assert!(det.extension_agrees);
        assert_eq!(det.layers[1].confidence, Confidence::Certain);
    }

    #[test]
    fn bare_compressed_file_is_a_stream() {
        let det = detect_bytes(
            &compress(CodecId::Gzip, b"just some notes\n"),
            Some("notes.txt.gz"),
            &Limits::default(),
        );
        assert_eq!(
            kinds(&det),
            [
                LayerKind::Codec(CodecId::Gzip),
                LayerKind::Format(FormatId::Stream)
            ]
        );
        assert_eq!(det.chain(), "gzip");
        assert_eq!(det.label.as_deref(), Some("Plain Text"));
    }

    #[test]
    fn nesting_stops_at_max_layers() {
        let mut data = b"inner".to_vec();
        for _ in 0..5 {
            data = compress(CodecId::Gzip, &data);
        }
        let det = detect_bytes(&data, Some("x.gz"), &Limits::default());
        assert_eq!(det.codecs(), [CodecId::Gzip; 4]);
        assert_eq!(det.format(), Some(FormatId::Stream));
    }

    #[test]
    fn non_archives_get_a_label() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        let det = detect_bytes(png, Some("a.png"), &Limits::default());
        assert!(det.layers.is_empty());
        assert_eq!(det.label.as_deref(), Some("Portable Network Graphics"));
        assert!(det.extension_agrees);
        assert!(det.require_archive().is_err());

        let det = detect_bytes(png, Some("a.zip"), &Limits::default());
        assert!(!det.extension_agrees);
    }

    #[test]
    fn extension_alone_is_a_guess() {
        let garbage = [0u8, 1, 2, 3, 0xFF, 0xFE, 0x80, 0x81, 7, 9];
        let det = detect_bytes(&garbage, Some("x.tar"), &Limits::default());
        assert_eq!(
            det.layers,
            [Layer {
                kind: LayerKind::Format(FormatId::Tar),
                confidence: Confidence::Guess
            }]
        );
    }

    #[test]
    fn magic_beats_the_extension() {
        let det = detect_bytes(
            &compress(CodecId::Xz, b"data"),
            Some("mislabelled.gz"),
            &Limits::default(),
        );
        assert_eq!(det.codecs(), [CodecId::Xz]);
        assert!(!det.extension_agrees);
    }

    #[test]
    #[cfg(windows)]
    fn explorer_is_an_executable_not_an_archive() {
        let exe = Path::new(r"C:\Windows\explorer.exe");
        let det = detect_path(exe, &Limits::default()).unwrap();
        assert!(det.layers.is_empty(), "{det:?}");
        assert_eq!(det.label.as_deref(), Some("Portable Executable"));
        assert!(!det.sfx);
    }

    #[test]
    fn empty_input() {
        let det = detect_bytes(b"", None, &Limits::default());
        assert!(det.layers.is_empty());
        assert_eq!(det.label.as_deref(), Some("Empty"));
    }
}
