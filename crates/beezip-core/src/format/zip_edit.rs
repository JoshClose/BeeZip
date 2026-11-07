//! Editing a zip without the zip crate's raw copy, whose copies are corrupt for ZipCrypto and
//! LZMA entries (docs/M5.md §3.3, §16): kept entries are copied byte for byte, their central
//! records too with the local header's new offset, and renamed ones get the new name in UTF-8.
//! New entries are written by the zip crate after them; its central directory is read back and
//! merged with the kept records. Nothing here names `zip::`.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::{Error, Result, io::write_error};

pub const CENTRAL: &[u8; 4] = b"PK\x01\x02";
const LOCAL: &[u8; 4] = b"PK\x03\x04";
const EOCD: &[u8; 4] = b"PK\x05\x06";
const ZIP64_EOCD: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
/// Flag bit 11: the name and comment are UTF-8.
const UTF8_FLAG: u16 = 1 << 11;
const ZIP64_EXTRA: u16 = 0x0001;
/// Info-ZIP's Unicode Path extra, which overrides the name; a renamed entry drops it.
const UNICODE_PATH: u16 = 0x7075;
/// Info-ZIP's Unicode Comment extra.
const UNICODE_COMMENT: u16 = 0x6375;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn damaged(what: &str) -> Error {
    Error::corrupt(format!("zip: {what}"))
}

/// Extra fields without those of `drop`'s ids. A field that claims more than is there ends the
/// list, as readers treat it.
fn without_extras(mut extra: &[u8], drop: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(extra.len());
    while extra.len() >= 4 {
        let id = u16_at(extra, 0);
        let size = usize::from(u16_at(extra, 2));
        let Some(field) = extra.get(..4 + size) else {
            break;
        };
        if !drop.contains(&id) {
            out.extend_from_slice(field);
        }
        extra = &extra[4 + size..];
    }
    out
}

fn len16(n: usize, what: &str) -> Result<u16> {
    u16::try_from(n).map_err(|_| Error::invalid_args(format!("a zip {what} is over 65 535 bytes")))
}

/// A local header (`head`: the fixed part, name and extra fields) with a new UTF-8 name, flag
/// bit 11 set and the Unicode Path extra dropped.
pub fn renamed_local(head: &[u8], name: &str) -> Result<Vec<u8>> {
    if head.len() < 30 || &head[..4] != LOCAL {
        return Err(damaged("a local header is missing"));
    }
    let name_len = usize::from(u16_at(head, 26));
    let extra_len = usize::from(u16_at(head, 28));
    let extra = head
        .get(30 + name_len..30 + name_len + extra_len)
        .ok_or_else(|| damaged("a local header is cut short"))?;
    let extra = without_extras(extra, &[UNICODE_PATH]);
    let mut out = head[..30].to_vec();
    let flags = u16_at(&out, 6) | UTF8_FLAG;
    put_u16(&mut out, 6, flags);
    put_u16(&mut out, 26, len16(name.len(), "name")?);
    put_u16(&mut out, 28, len16(extra.len(), "header's extra fields")?);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&extra);
    Ok(out)
}

/// One central directory record, as bytes, that can be renamed and moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CentralRecord(pub Vec<u8>);

impl CentralRecord {
    /// The record at the start of `b`, and its length.
    pub fn parse(b: &[u8]) -> Result<(Self, usize)> {
        if b.len() < 46 || &b[..4] != CENTRAL {
            return Err(damaged("a central directory record is missing"));
        }
        let len = 46
            + usize::from(u16_at(b, 28))
            + usize::from(u16_at(b, 30))
            + usize::from(u16_at(b, 32));
        let rec = b
            .get(..len)
            .ok_or_else(|| damaged("a central directory record is cut short"))?;
        Ok((Self(rec.to_vec()), len))
    }

    fn name_len(&self) -> usize {
        usize::from(u16_at(&self.0, 28))
    }

    fn extra_len(&self) -> usize {
        usize::from(u16_at(&self.0, 30))
    }

    fn extra(&self) -> &[u8] {
        let at = 46 + self.name_len();
        &self.0[at..at + self.extra_len()]
    }

    fn comment(&self) -> &[u8] {
        let at = 46 + self.name_len() + self.extra_len();
        &self.0[at..]
    }

    pub fn flags(&self) -> u16 {
        u16_at(&self.0, 8)
    }

    /// Rebuilds the record from its parts.
    fn rebuild(&mut self, name: &[u8], extra: &[u8], comment: &[u8]) -> Result<()> {
        let mut out = self.0[..46].to_vec();
        put_u16(&mut out, 28, len16(name.len(), "name")?);
        put_u16(&mut out, 30, len16(extra.len(), "record's extra fields")?);
        put_u16(&mut out, 32, len16(comment.len(), "comment")?);
        out.extend_from_slice(name);
        out.extend_from_slice(extra);
        out.extend_from_slice(comment);
        self.0 = out;
        Ok(())
    }

    /// The new name in UTF-8 with flag bit 11, and without the Unicode Path extra. A comment
    /// that was in the code page (`comment` decoded, `None` to keep the bytes) is written in
    /// UTF-8 too, since the flag covers it; the Unicode Comment extra goes with it.
    pub fn rename(&mut self, name: &str, comment: Option<&str>) -> Result<()> {
        let mut drop = vec![UNICODE_PATH];
        if comment.is_some() {
            drop.push(UNICODE_COMMENT);
        }
        let extra = without_extras(self.extra(), &drop);
        let comment = match comment {
            Some(c) => c.as_bytes().to_vec(),
            None => self.comment().to_vec(),
        };
        self.rebuild(name.as_bytes(), &extra, &comment)?;
        let flags = self.flags() | UTF8_FLAG;
        put_u16(&mut self.0, 8, flags);
        Ok(())
    }

    /// Where the Zip64 extra's local header offset is, as (start of the extra field's data,
    /// offset of the value in it): after the sizes whose 32-bit fields say they are there.
    fn zip64_offset_slot(&self) -> Option<(usize, usize)> {
        let base = 46 + self.name_len();
        let mut extra = self.extra();
        let mut at = base;
        while extra.len() >= 4 {
            let id = u16_at(extra, 0);
            let size = usize::from(u16_at(extra, 2));
            if extra.len() < 4 + size {
                return None;
            }
            if id == ZIP64_EXTRA {
                let mut slot = 0;
                if u32_at(&self.0, 24) == u32::MAX {
                    slot += 8;
                }
                if u32_at(&self.0, 20) == u32::MAX {
                    slot += 8;
                }
                return (slot + 8 <= size).then_some((at + 4, slot));
            }
            at += 4 + size;
            extra = &extra[4 + size..];
        }
        None
    }

    /// The local header's offset: the 32-bit field, or its Zip64 extra.
    pub fn offset(&self) -> Option<u64> {
        let off = u32_at(&self.0, 42);
        if off != u32::MAX {
            return Some(u64::from(off));
        }
        let (data, slot) = self.zip64_offset_slot()?;
        Some(u64_at(&self.0, data + slot))
    }

    /// Points the record at a local header at `offset`, in the 32-bit field when it fits and
    /// the record doesn't already use its Zip64 extra; otherwise in the Zip64 extra, which is
    /// added or extended as needed. The disk number is set to the first disk.
    pub fn set_offset(&mut self, offset: u64) -> Result<()> {
        put_u16(&mut self.0, 34, 0);
        let uses_zip64 = u32_at(&self.0, 42) == u32::MAX;
        if !uses_zip64 {
            if let Ok(o) = u32::try_from(offset)
                && o != u32::MAX
            {
                put_u32(&mut self.0, 42, o);
                return Ok(());
            }
        } else if let Some((data, slot)) = self.zip64_offset_slot() {
            self.0[data + slot..data + slot + 8].copy_from_slice(&offset.to_le_bytes());
            return Ok(());
        }
        // The offset goes into a Zip64 extra: after the sizes it holds, before a disk number.
        put_u32(&mut self.0, 42, u32::MAX);
        let usize64 = u32_at(&self.0, 24) == u32::MAX;
        let csize64 = u32_at(&self.0, 20) == u32::MAX;
        let mut values: Vec<u64> = Vec::new();
        let mut rest = self.extra().to_vec();
        let mut others = Vec::new();
        let mut found = false;
        while rest.len() >= 4 {
            let id = u16_at(&rest, 0);
            let size = usize::from(u16_at(&rest, 2));
            let Some(field) = rest.get(..4 + size).map(<[u8]>::to_vec) else {
                break;
            };
            if id == ZIP64_EXTRA && !found {
                found = true;
                let body = &field[4..];
                let mut at = 0;
                for present in [usize64, csize64] {
                    if present && at + 8 <= body.len() {
                        values.push(u64_at(body, at));
                        at += 8;
                    }
                }
            } else {
                others.extend_from_slice(&field);
            }
            rest.drain(..4 + size);
        }
        if !found {
            // No extra yet: the sizes are in the 32-bit fields, so none go in it.
            if usize64 || csize64 {
                return Err(damaged("a Zip64 record has no Zip64 extra"));
            }
        }
        values.push(offset);
        let mut field = Vec::with_capacity(4 + 8 * values.len());
        field.extend_from_slice(&ZIP64_EXTRA.to_le_bytes());
        field.extend_from_slice(&len16(8 * values.len(), "Zip64 extra")?.to_le_bytes());
        for v in values {
            field.extend_from_slice(&v.to_le_bytes());
        }
        field.extend_from_slice(&others);
        let name = self.0[46..46 + self.name_len()].to_vec();
        let comment = self.comment().to_vec();
        self.rebuild(&name, &field, &comment)?;
        // The version needed to extract: 4.5 for Zip64.
        if u16_at(&self.0, 6) & 0xFF < 45 {
            let v = (u16_at(&self.0, 6) & 0xFF00) | 45;
            put_u16(&mut self.0, 6, v);
        }
        Ok(())
    }
}

/// Splits a central directory into its records.
pub fn records(mut cd: &[u8]) -> Result<Vec<CentralRecord>> {
    let mut out = Vec::new();
    while !cd.is_empty() {
        let (rec, len) = CentralRecord::parse(cd)?;
        out.push(rec);
        cd = &cd[len..];
    }
    Ok(out)
}

/// Where a zip's central directory is and how big, from its end records: `(offset, size)`.
/// Only for zips BeeZip's writer made, whose comment is empty, so the end record is last.
pub fn find_directory<R: Read + Seek>(r: &mut R, len: u64) -> Result<(u64, u64)> {
    let io = |e: io::Error| Error::io("reading the zip being written", &e);
    if len < 22 {
        return Err(damaged("the new entries' end record is missing"));
    }
    let mut eocd = [0u8; 22];
    r.seek(SeekFrom::Start(len - 22)).map_err(io)?;
    r.read_exact(&mut eocd).map_err(io)?;
    if &eocd[..4] != EOCD {
        return Err(damaged("the new entries' end record is missing"));
    }
    let size = u32_at(&eocd, 12);
    let offset = u32_at(&eocd, 16);
    if size != u32::MAX && offset != u32::MAX && u16_at(&eocd, 10) != u16::MAX {
        return Ok((u64::from(offset), u64::from(size)));
    }
    // Zip64: the locator before the end record names the Zip64 end record.
    if len < 22 + 20 {
        return Err(damaged("the new entries' Zip64 locator is missing"));
    }
    let mut loc = [0u8; 20];
    r.seek(SeekFrom::Start(len - 42)).map_err(io)?;
    r.read_exact(&mut loc).map_err(io)?;
    if &loc[..4] != ZIP64_LOCATOR {
        return Err(damaged("the new entries' Zip64 locator is missing"));
    }
    let mut rec = [0u8; 56];
    r.seek(SeekFrom::Start(u64_at(&loc, 8))).map_err(io)?;
    r.read_exact(&mut rec).map_err(io)?;
    if &rec[..4] != ZIP64_EOCD {
        return Err(damaged("the new entries' Zip64 end record is missing"));
    }
    Ok((u64_at(&rec, 48), u64_at(&rec, 40)))
}

/// Writes the central directory and the end records at `w`'s position, which is `start`:
/// the Zip64 end record and locator when the count, the directory's size or its offset need
/// them. `comment` is the archive comment's bytes, as they were.
pub fn write_directory<W: Write>(
    w: &mut W,
    start: u64,
    recs: &[CentralRecord],
    comment: &[u8],
) -> Result<u64> {
    let werr = |e: io::Error| write_error(&e);
    let mut size = 0u64;
    for r in recs {
        w.write_all(&r.0).map_err(werr)?;
        size += r.0.len() as u64;
    }
    let n = recs.len() as u64;
    let zip64 =
        n >= u64::from(u16::MAX) || size >= u64::from(u32::MAX) || start >= u64::from(u32::MAX);
    let mut end = start + size;
    if zip64 {
        let mut rec = Vec::with_capacity(56);
        rec.extend_from_slice(ZIP64_EOCD);
        rec.extend_from_slice(&44u64.to_le_bytes());
        rec.extend_from_slice(&45u16.to_le_bytes());
        rec.extend_from_slice(&45u16.to_le_bytes());
        rec.extend_from_slice(&0u32.to_le_bytes());
        rec.extend_from_slice(&0u32.to_le_bytes());
        rec.extend_from_slice(&n.to_le_bytes());
        rec.extend_from_slice(&n.to_le_bytes());
        rec.extend_from_slice(&size.to_le_bytes());
        rec.extend_from_slice(&start.to_le_bytes());
        let mut loc = Vec::with_capacity(20);
        loc.extend_from_slice(ZIP64_LOCATOR);
        loc.extend_from_slice(&0u32.to_le_bytes());
        loc.extend_from_slice(&end.to_le_bytes());
        loc.extend_from_slice(&1u32.to_le_bytes());
        w.write_all(&rec).map_err(werr)?;
        w.write_all(&loc).map_err(werr)?;
        end += 76;
    }
    let comment = &comment[..comment.len().min(usize::from(u16::MAX))];
    let mut eocd = Vec::with_capacity(22 + comment.len());
    eocd.extend_from_slice(EOCD);
    eocd.extend_from_slice(&0u16.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes());
    let n16 = u16::try_from(n).unwrap_or(u16::MAX);
    eocd.extend_from_slice(&n16.to_le_bytes());
    eocd.extend_from_slice(&n16.to_le_bytes());
    eocd.extend_from_slice(&u32::try_from(size).unwrap_or(u32::MAX).to_le_bytes());
    eocd.extend_from_slice(&u32::try_from(start).unwrap_or(u32::MAX).to_le_bytes());
    eocd.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    eocd.extend_from_slice(comment);
    w.write_all(&eocd).map_err(werr)?;
    Ok(end + eocd.len() as u64)
}

/// A window on a file that starts at `base`: the zip crate writes the new entries through it
/// as if they began the file, so their data is written once, in place.
pub struct OffsetView<F> {
    pub inner: F,
    pub base: u64,
}

impl<F: Write> Write for OffsetView<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<F: Read> Read for OffsetView<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<F: Seek> Seek for OffsetView<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let abs = match pos {
            SeekFrom::Start(n) => {
                SeekFrom::Start(self.base.checked_add(n).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "a seek past 2^64")
                })?)
            }
            other => other,
        };
        let at = self.inner.seek(abs)?;
        at.checked_sub(self.base).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "a seek before the new entries")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A central record with these 32-bit sizes and offset, and these extras.
    fn record(name: &str, csize: u32, usize: u32, offset: u32, extra: &[u8]) -> CentralRecord {
        let mut r = vec![0u8; 46];
        r[..4].copy_from_slice(CENTRAL);
        put_u16(&mut r, 6, 20);
        put_u32(&mut r, 20, csize);
        put_u32(&mut r, 24, usize);
        put_u16(&mut r, 28, name.len() as u16);
        put_u16(&mut r, 30, extra.len() as u16);
        put_u32(&mut r, 42, offset);
        r.extend_from_slice(name.as_bytes());
        r.extend_from_slice(extra);
        CentralRecord(r)
    }

    fn field(id: u16, body: &[u8]) -> Vec<u8> {
        let mut f = id.to_le_bytes().to_vec();
        f.extend_from_slice(&(body.len() as u16).to_le_bytes());
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn offsets_move_between_the_field_and_the_zip64_extra() {
        let ntfs = field(0x000A, &[0; 32]);
        let mut r = record("a.txt", 10, 20, 100, &ntfs);
        assert_eq!(r.offset(), Some(100));
        r.set_offset(5_000).unwrap();
        assert_eq!(r.offset(), Some(5_000));
        assert_eq!(r.0.len(), 46 + 5 + ntfs.len(), "no extra added");
        // Past 4 GiB the offset needs a Zip64 extra, which is added before the others.
        let big = 6u64 << 30;
        r.set_offset(big).unwrap();
        assert_eq!(r.offset(), Some(big));
        assert_eq!(u32_at(&r.0, 42), u32::MAX);
        assert_eq!(u16_at(&r.0, 6) & 0xFF, 45);
        assert!(r.extra().ends_with(&ntfs), "the NTFS extra stays");
        // And it stays there, even for a small offset.
        r.set_offset(7).unwrap();
        assert_eq!(r.offset(), Some(7));
        assert_eq!(u32_at(&r.0, 42), u32::MAX);
    }

    #[test]
    fn a_zip64_extra_with_sizes_gets_the_offset_after_them() {
        let mut body = Vec::new();
        body.extend_from_slice(&(5u64 << 30).to_le_bytes()); // uncompressed
        body.extend_from_slice(&(4u64 << 30).to_le_bytes()); // compressed
        let mut r = record("big.bin", u32::MAX, u32::MAX, 0, &field(1, &body));
        let big = 9u64 << 30;
        r.set_offset(big).unwrap();
        assert_eq!(r.offset(), Some(big));
        let extra = r.extra();
        assert_eq!(u16_at(extra, 2), 24);
        assert_eq!(u64_at(extra, 4), 5 << 30);
        assert_eq!(u64_at(extra, 12), 4 << 30);
        assert_eq!(u64_at(extra, 20), big);
    }

    #[test]
    fn a_rename_drops_the_unicode_path_and_sets_the_flag() {
        let unicode = field(UNICODE_PATH, b"\x01\0\0\0\0x");
        let ut = field(0x5455, &[1, 0, 0, 0, 0]);
        let mut extra = unicode.clone();
        extra.extend_from_slice(&ut);
        let mut r = record("old.txt", 1, 1, 0, &extra);
        r.rename("新しい/名前.txt", None).unwrap();
        assert_eq!(r.flags() & UTF8_FLAG, UTF8_FLAG);
        assert_eq!(&r.0[46..46 + r.name_len()], "新しい/名前.txt".as_bytes());
        assert_eq!(r.extra(), &ut[..]);
        let (again, len) = CentralRecord::parse(&r.0).unwrap();
        assert_eq!((again, len), (r.clone(), r.0.len()));
    }

    #[test]
    fn local_headers_rename() {
        let mut h = vec![0u8; 30];
        h[..4].copy_from_slice(LOCAL);
        let extra = field(UNICODE_PATH, b"\x01\0\0\0\0x");
        put_u16(&mut h, 26, 3);
        put_u16(&mut h, 28, extra.len() as u16);
        h.extend_from_slice(b"old");
        h.extend_from_slice(&extra);
        let new = renamed_local(&h, "ny.txt").unwrap();
        assert_eq!(new.len(), 30 + 6);
        assert_eq!(u16_at(&new, 6) & UTF8_FLAG, UTF8_FLAG);
        assert_eq!(&new[30..], b"ny.txt");
    }

    #[test]
    fn directories_read_back() {
        let recs = vec![record("a", 1, 1, 0, &[]), record("b", 1, 1, 50, &[])];
        let mut out = io::Cursor::new(vec![0u8; 80]);
        out.seek(SeekFrom::End(0)).unwrap();
        let end = write_directory(&mut out, 80, &recs, b"hi").unwrap();
        assert_eq!(end, out.get_ref().len() as u64);
        // With a comment the end record isn't last, so only the comment-less form is read back.
        let mut plain = io::Cursor::new(vec![0u8; 80]);
        plain.seek(SeekFrom::End(0)).unwrap();
        let end = write_directory(&mut plain, 80, &recs, b"").unwrap();
        let (at, size) = find_directory(&mut plain, end).unwrap();
        assert_eq!(at, 80);
        let cd = &plain.get_ref()[at as usize..(at + size) as usize];
        assert_eq!(records(cd).unwrap(), recs);
    }
}
