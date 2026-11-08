//! Debian packages (docs/M5.md §5.3), read only: an ar of `debian-binary`, `control.tar.*` and
//! `data.tar.*`.
//!
//! - **The listing** is what `dpkg-deb -R` unpacks: `data.tar`'s contents at the top (its root
//!   folder left out) and `control.tar`'s under `DEBIAN/`. `debian-binary` and any other member
//!   (a signature) aren't listed. Paths lose their leading `./`, and hard links their targets'.
//! - Both tars go through the codecs (gzip, xz, zstd, bzip2, lzma or none) in one pass over the
//!   ar, in its order, so the control files come first.
//! - **Not written:** building a package is `dpkg-deb`'s job; it checks the control fields.

use std::io::{self, BufReader, Read};

use super::{
    ArchiveFormat, ArchiveInfo, ArchiveReader, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, Selection,
    ar::{self, Members},
    link_target, normalize,
    tar::{Nested, walk_nested},
};
use crate::{
    CodecId, Ctx, Error, ErrorKind, Meter, MeteredCtx, Result,
    detect::{Confidence, Probe},
    io::BUF_SIZE,
    source::Source,
};

pub struct Deb;

impl ArchiveFormat for Deb {
    fn id(&self) -> FormatId {
        FormatId::Deb
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[".deb", ".udeb"]
    }

    /// An ar whose first member is `debian-binary`.
    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        let h = probe.head.strip_prefix(ar::MAGIC)?.get(..60)?;
        (h[58..60] == *b"`\n" && ar::is_deb_binary(&h[..16])).then_some(Confidence::Certain)
    }

    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            ..FormatCaps::default()
        }
    }
}

/// Which of the package's tars an entry is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Control,
    Data,
}

/// A member's part and codec, from its name: `data.tar.xz` is data under xz.
fn part(name: &[u8]) -> Result<Option<(Part, Option<CodecId>)>> {
    let (p, rest) = if let Some(rest) = name.strip_prefix(b"control.tar") {
        (Part::Control, rest)
    } else if let Some(rest) = name.strip_prefix(b"data.tar") {
        (Part::Data, rest)
    } else {
        return Ok(None);
    };
    let codec = match rest {
        b"" => None,
        b".gz" => Some(CodecId::Gzip),
        b".xz" => Some(CodecId::Xz),
        b".zst" => Some(CodecId::Zstd),
        b".bz2" => Some(CodecId::Bzip2),
        b".lzma" => Some(CodecId::Lzma),
        _ => {
            return Err(Error::unsupported_format(format!(
                "a package member `{}` BeeZip can't decode",
                String::from_utf8_lossy(name)
            )));
        }
    };
    Ok(Some((p, codec)))
}

/// `path` as `dpkg-deb -R` puts it: a control file under `DEBIAN/`, a data file at the top.
/// `None` for the data tar's root.
fn mapped(p: Part, path: &str) -> Option<String> {
    let n = normalize(path);
    let n = if n == "." { String::new() } else { n };
    match p {
        Part::Control if n.is_empty() => Some("DEBIAN".into()),
        Part::Control => Some(format!("DEBIAN/{n}")),
        Part::Data if n.is_empty() => None,
        Part::Data => Some(n),
    }
}

/// Where an entry comes from: its part, and its place among that tar's entries.
#[derive(Debug, Clone, Copy)]
struct From {
    part: Part,
    nth: usize,
}

pub struct DebReader {
    source: Source,
    entries: Vec<Entry>,
    from: Vec<From>,
    codecs: Vec<&'static str>,
    nested: Option<Nested>,
}

impl DebReader {
    /// Reads both tars once, for the listing.
    pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Self> {
        let mut r = Self {
            source,
            entries: Vec::new(),
            from: Vec::new(),
            codecs: Vec::new(),
            nested: None,
        };
        let mut entries = Vec::new();
        let mut from = Vec::new();
        let mut codecs = Vec::new();
        r.walk(
            &mut |p, nth, e, _, _| {
                entries.push(e.clone());
                from.push(From { part: p, nth });
                Ok(())
            },
            &mut |c| {
                if !codecs.contains(&c) {
                    codecs.push(c);
                }
            },
            cx,
        )?;
        r.entries = entries;
        r.from = from;
        r.codecs = codecs;
        Ok(r)
    }

    fn members(&self) -> Result<Members<Box<dyn Read + Send>>> {
        let r: Box<dyn Read + Send> = if self.source.codecs.is_empty() {
            Box::new(BufReader::with_capacity(BUF_SIZE, self.source.open_file()?))
        } else {
            self.source.open_stream()?
        };
        Members::new(r)
    }

    /// One pass over the package: `each` gets every listed entry (its id counted here), its
    /// part and place in that tar, and its data.
    #[allow(clippy::type_complexity)]
    fn walk(
        &self,
        each: &mut dyn FnMut(Part, usize, &Entry, &mut dyn Read, &mut dyn Ctx) -> Result<()>,
        codec_seen: &mut dyn FnMut(&'static str),
        cx: &mut dyn Ctx,
    ) -> Result<()> {
        let mut m = self.members()?;
        let first = m
            .next()?
            .ok_or_else(|| Error::corrupt("deb: the package is empty"))?;
        if first.name != b"debian-binary" {
            return Err(Error::corrupt(
                "deb: the package doesn't start with debian-binary",
            ));
        }
        let mut version = Vec::new();
        m.data()
            .take(64)
            .read_to_end(&mut version)
            .map_err(|e| crate::io::read_error(&e))?;
        if !version.starts_with(b"2.") {
            return Err(Error::unsupported_format(format!(
                "a package of format {}, where BeeZip reads 2.x",
                String::from_utf8_lossy(&version).trim()
            )));
        }
        let names = self.source.names;
        let limits = self.source.limits.clone();
        let mut id = 0usize;
        while let Some(member) = m.next()? {
            cx.check()?;
            let Some((p, codec)) = part(&member.name)? else {
                continue;
            };
            let mut r: Box<dyn Read + Send + '_> = Box::new(m.data());
            if let Some(c) = codec {
                codec_seen(c.name());
                r = c.decoder(r, &limits)?;
            }
            walk_nested(
                r,
                &names,
                &mut |mut e, data, cx| {
                    let Some(path) = mapped(p, &e.path) else {
                        return Ok(());
                    };
                    let nth = e.id;
                    limits.check_entries(id as u64 + 1)?;
                    e.id = id;
                    e.raw_path = path.as_bytes().to_vec();
                    e.path = if e.kind == EntryKind::Dir {
                        format!("{path}/")
                    } else {
                        path
                    };
                    if let EntryKind::Hardlink { target } = &e.kind {
                        e.kind = EntryKind::Hardlink {
                            target: mapped(p, target).unwrap_or_default(),
                        };
                    }
                    id += 1;
                    each(p, nth, &e, data, cx)
                },
                cx,
            )?;
        }
        Ok(())
    }
}

impl ArchiveReader for DebReader {
    fn format(&self) -> FormatId {
        FormatId::Deb
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn entries(&mut self, _: &mut dyn Ctx) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn info(&mut self, _: &mut dyn Ctx) -> Result<ArchiveInfo> {
        Ok(ArchiveInfo {
            format: FormatId::Deb,
            codecs: self.source.codecs.clone(),
            methods: self.codecs.iter().map(|&c| c.into()).collect(),
            comment: None,
            encryption: Encryption::None,
            solid: !self.codecs.is_empty(),
            sfx: false,
            volumes: self.source.volumes.len(),
            solid_blocks: None,
            encrypted_headers: false,
            locked: false,
            recovery_record: false,
            external: None,
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
        let source = &self.source;
        self.walk(
            &mut |_, _, e, data, cx| {
                if !sel.matches(e) {
                    return Ok(());
                }
                meter.entries_done = e.id as u64;
                meter.current = Some(e.path.clone());
                let mut mcx = MeteredCtx::new(cx, &meter);
                mcx.report();
                let mut data = source.guard(data);
                sink.entry(e, &mut data, &mut mcx)
            },
            &mut |_| {},
            cx,
        )?;
        meter.entries_done = self.entries.len() as u64;
        MeteredCtx::new(cx, &meter).report();
        Ok(())
    }

    fn open_entry(&mut self, id: usize, cx: &mut dyn Ctx) -> Result<Box<dyn Read + '_>> {
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no entry {id}")))?;
        let id = match &entry.kind {
            EntryKind::File => id,
            EntryKind::Hardlink { target } => link_target(&self.entries, entry)
                .map(|t| t.id)
                .ok_or_else(|| Error::corrupt(format!("hard link target `{target}` is missing")))?,
            _ => return Ok(Box::new(io::empty())),
        };
        let from = self.from[id];
        let mut m = self.members()?;
        let codec = loop {
            cx.check()?;
            let member = m
                .next()?
                .ok_or_else(|| Error::corrupt("deb: a member vanished on a second pass"))?;
            if let Some((p, codec)) = part(&member.name)?
                && p == from.part
            {
                break codec;
            }
        };
        let mut r: Box<dyn Read + Send> = Box::new(m.into_data());
        if let Some(c) = codec {
            r = c.decoder(r, &self.source.limits)?;
        }
        let names = self.source.names;
        let nested = self.nested.insert(Nested::new(r));
        let data = nested.open(from.nth, &names, cx)?;
        Ok(Box::new(self.source.guard(data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_mapped_as_dpkg_deb_unpacks_them() {
        assert_eq!(mapped(Part::Control, "./").as_deref(), Some("DEBIAN"));
        assert_eq!(
            mapped(Part::Control, "./md5sums").as_deref(),
            Some("DEBIAN/md5sums")
        );
        assert_eq!(mapped(Part::Data, "./"), None);
        assert_eq!(mapped(Part::Data, "."), None);
        assert_eq!(
            mapped(Part::Data, "./usr/bin/x").as_deref(),
            Some("usr/bin/x")
        );
        assert_eq!(mapped(Part::Data, "/etc/x").as_deref(), Some("etc/x"));
    }

    #[test]
    fn member_names_give_codecs() {
        assert_eq!(
            part(b"data.tar.zst").unwrap(),
            Some((Part::Data, Some(CodecId::Zstd)))
        );
        assert_eq!(part(b"control.tar").unwrap(), Some((Part::Control, None)));
        assert_eq!(part(b"_gpgbuilder").unwrap(), None);
        assert!(part(b"data.tar.lz4").is_err());
    }
}
