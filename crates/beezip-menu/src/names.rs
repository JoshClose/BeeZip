//! Names: which files BeeZip reads, the stem an archive is extracted under, and which parts make
//! one volume set. Extensions match ASCII case-insensitively, so byte offsets in the lowercased
//! name are offsets in the original too.

use crate::gen_exts::{CODECS, FORMATS, TAR_SHORTHANDS};

fn is_sep(c: char) -> bool {
    c == '\\' || c == '/'
}

/// The last component of a path: `C:\a\b.zip` → `b.zip`. Trailing separators are ignored, and
/// the root of a drive has none (`C:\` → `""`).
pub fn file_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches(is_sep);
    match trimmed.rfind(is_sep) {
        Some(i) => &trimmed[i + 1..],
        None if trimmed.ends_with(':') => "",
        None => trimmed,
    }
}

/// The path without its last component: `C:\a\b.zip` → `C:\a`, `C:\b.zip` → `C:`.
pub(crate) fn parent(path: &str) -> &str {
    let trimmed = path.trim_end_matches(is_sep);
    match trimmed.rfind(is_sep) {
        Some(i) => &trimmed[..i],
        None => "",
    }
}

/// `(base, number)` for `base.NNN`, three digits or more: a numbered volume (`a.7z.001`).
fn numbered(name: &str) -> Option<(&str, u64)> {
    let (base, digits) = name.rsplit_once('.')?;
    if base.is_empty() || digits.len() < 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((base, digits.parse().ok()?))
}

/// The stem of `stem.partN.rar`.
fn rar_part(name: &str) -> Option<&str> {
    let lower = name.to_ascii_lowercase();
    let without = lower.strip_suffix(".rar")?;
    let at = without.rfind(".part")?;
    let digits = &without[at + 5..];
    if at == 0 || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(&name[..at])
}

/// `(stem, index)` for an old-style RAR volume: `stem.rar` is 0, `stem.r00` 1, `stem.s00` 101…
fn rar_old(name: &str) -> Option<(&str, u64)> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    let ext = ext.to_ascii_lowercase();
    if ext == "rar" {
        return Some((stem, 0));
    }
    match ext.as_bytes() {
        [letter @ b'r'..=b'z', tens, ones] if tens.is_ascii_digit() && ones.is_ascii_digit() => {
            let n = u64::from(letter - b'r') * 100 + u64::from((tens - b'0') * 10 + (ones - b'0'));
            Some((stem, n + 1))
        }
        _ => None,
    }
}

/// The longest of `exts` that `lower` ends with and is longer than: `.zip` alone has no stem.
fn longest<'e>(lower: &str, exts: impl IntoIterator<Item = &'e &'e str>) -> Option<&'e str> {
    exts.into_iter()
        .copied()
        .filter(|e| lower.len() > e.len() && lower.ends_with(e))
        .max_by_key(|e| e.len())
}

/// Whether BeeZip reads a file of this name: an archive format's or a codec's extension
/// (`.zip`, `.tar.zst`, `.gz`), or a volume of a set (`.7z.002`, `.part2.rar`, `.r01`).
pub fn is_archive(name: &str) -> bool {
    if let Some((_, n)) = numbered(name) {
        return n >= 1;
    }
    if rar_old(name).is_some() {
        return true;
    }
    longest(&name.to_ascii_lowercase(), FORMATS.iter().chain(CODECS)).is_some()
}

/// The name an archive is extracted under, without its archive and codec extensions:
/// `a.tar.zst` → `a`, `a.7z.001` → `a`, `a.part1.rar` → `a`, `notes.txt.gz` → `notes.txt`.
/// A name that is only an extension stays (`.zip`); an empty one is `archive`.
pub fn archive_stem(name: &str) -> String {
    let nonempty = |s: &str| {
        if s.is_empty() {
            "archive".to_owned()
        } else {
            s.to_owned()
        }
    };
    let mut name = name;
    if let Some((base, _)) = numbered(name) {
        // A numbered set is named after the joined file: `a.7z.001` → `a.7z`.
        name = base;
    } else if let Some(stem) = rar_part(name) {
        return nonempty(stem);
    } else if let Some((stem, index)) = rar_old(name)
        && index > 0
    {
        return nonempty(stem);
    }
    let mut name = name.to_owned();
    loop {
        let lower = name.to_ascii_lowercase();
        if let Some(ext) = longest(&lower, CODECS) {
            let stem = &name[..name.len() - ext.len()];
            name = if TAR_SHORTHANDS.contains(&ext) {
                format!("{stem}.tar")
            } else {
                stem.to_owned()
            };
            continue;
        }
        match longest(&lower, FORMATS.iter().chain(TAR_SHORTHANDS)) {
            Some(ext) => name.truncate(name.len() - ext.len()),
            None => break,
        }
    }
    nonempty(&name)
}

/// A key that the parts of one volume set share: the folder, and the name without its part
/// number, lowercased. `C:\x\a.7z.001` and `C:\x\a.7z.002` give the same key.
pub fn volume_key(path: &str) -> String {
    let name = file_name(path);
    let set = if let Some((base, _)) = numbered(name) {
        base.to_owned()
    } else if let Some(stem) = rar_part(name) {
        format!("{stem}.rar")
    } else if let Some((stem, _)) = rar_old(name) {
        format!("{stem}.rar")
    } else {
        name.to_owned()
    };
    format!("{}\\{}", parent(path), set)
        .replace('/', "\\")
        .to_lowercase()
}
