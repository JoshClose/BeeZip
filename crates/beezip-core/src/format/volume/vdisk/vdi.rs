//! VDI, VirtualBox's disk image, version 1.x, from public documentation of its header (never
//! VirtualBox's code, docs/M8.md §3.5): a block map of 32-bit entries (a block's index in the
//! data area, `0xFFFFFFFF` free, `0xFFFFFFFE` zero), then the blocks.
//!
//! - **Read:** dynamic and fixed images, with qemu's header (0x180 bytes) or VirtualBox's
//!   (0x190); blocks of any power of two from 512 bytes to 256 MiB, stored in any order, some
//!   discarded; a disk that isn't whole blocks long.
//! - **Differencing images** name their parent by uuid only: it's looked for among the `.vdi`
//!   files beside the child and in the folder above ([`Files::find_vdi`]), and is the one whose
//!   uuidCreate is the child's uuidLinkage. Its uuidModify must be the child's uuidParentModify
//!   when that's set, or it changed after the child was made.
//! - **An undo image** (VirtualBox 1.x's, written by none since) is read alone, as 7-Zip reads it
//!   (docs/M11.md §6.1): what it doesn't hold reads as zeros, and Info says so.
//! - **Refused** (`UnsupportedOperation`): version 0 headers, extra bytes before each block
//!   (`cbBlockExtra`: VirtualBox never writes them, and readers disagree on them).

use super::{Files, Got, Handle, Layer, Origin, le32, le64};
use crate::{Error, Result, backend::External};

const FREE: u32 = 0xFFFF_FFFF;
const ZERO: u32 = 0xFFFF_FFFE;
/// The largest block map read: 16 MiB maps 4 TiB of 1 MiB blocks.
const MAX_MAP: u64 = 64 << 20;

/// One VDI file.
pub struct Vdi {
    file: Handle,
    len: u64,
    block: u64,
    data: u64,
    map: Vec<u32>,
    kind: u32,
    create: [u8; 16],
    linkage: [u8; 16],
    allocated: u64,
}

fn uuid(b: &[u8]) -> [u8; 16] {
    b.try_into().unwrap_or_default()
}

/// A uuid as VirtualBox shows it (the GUID's little-endian layout).
fn show(u: &[u8; 16]) -> String {
    let g = super::guid(u);
    g[1..g.len() - 1].to_owned()
}

/// The first 512 bytes, checked as a VDI 1.x header.
fn head(file: &mut Handle) -> Result<Vec<u8>> {
    if file.len < 512 {
        return Err(Error::corrupt("vdi: the file is shorter than its header"));
    }
    let mut h = vec![0u8; 512];
    file.read_exact_at(0, &mut h, "vdi: the header")?;
    if le32(&h, 64) != 0xBEDA_107F {
        return Err(Error::corrupt("vdi: no signature"));
    }
    let version = le32(&h, 68);
    if version >> 16 != 1 {
        return Err(Error::unsupported(format!(
            "vdi: version {}.{}; BeeZip reads 1.x",
            version >> 16,
            version & 0xFFFF
        )));
    }
    let size = le32(&h, 72);
    if !(0x180..=0x1000).contains(&size) {
        return Err(Error::corrupt(format!("vdi: a header of {size} bytes")));
    }
    Ok(h)
}

impl Vdi {
    fn open(mut file: Handle) -> Result<Self> {
        let h = head(&mut file)?;
        let kind = le32(&h, 76);
        if !(1..=4).contains(&kind) {
            return Err(Error::corrupt(format!("vdi: image type {kind}")));
        }
        let off_blocks = u64::from(le32(&h, 340));
        let off_data = u64::from(le32(&h, 344));
        let len = le64(&h, 368);
        let block = u64::from(le32(&h, 376));
        let extra = le32(&h, 380);
        let count = u64::from(le32(&h, 384));
        if extra != 0 {
            return Err(Error::unsupported(format!(
                "vdi: blocks with {extra} extra bytes before them"
            )));
        }
        if !block.is_power_of_two() || !(512..=(256 << 20)).contains(&block) {
            return Err(Error::corrupt(format!("vdi: blocks of {block} bytes")));
        }
        if count < len.div_ceil(block) {
            return Err(Error::corrupt(format!(
                "vdi: {count} blocks can't hold a disk of {len} bytes"
            )));
        }
        let mut file = file;
        let raw = file.read_vec(off_blocks, count * 4, MAX_MAP, "vdi: the block map")?;
        let map: Vec<u32> = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        let allocated = map.iter().filter(|&&e| e < ZERO).count() as u64 * block;
        Ok(Self {
            file,
            len,
            block,
            data: off_data,
            map,
            kind,
            create: uuid(&h[392..408]),
            linkage: uuid(&h[424..440]),
            allocated,
        })
    }
}

impl Layer for Vdi {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(usize, Got)> {
        let b = off / self.block;
        let within = off % self.block;
        let n = buf
            .len()
            .min(usize::try_from(self.block - within).unwrap_or(usize::MAX));
        let e = *self
            .map
            .get(usize::try_from(b).unwrap_or(usize::MAX))
            .ok_or_else(|| Error::corrupt("vdi: a read past the block map"))?;
        match e {
            FREE => Ok((n, Got::Hole)),
            ZERO => Ok((n, Got::Zero)),
            slot => {
                let at = u64::from(slot)
                    .checked_mul(self.block)
                    .and_then(|x| x.checked_add(self.data))
                    .and_then(|x| x.checked_add(within))
                    .ok_or_else(|| Error::corrupt("vdi: a block's offset overflows"))?;
                self.file.read_exact_at(at, &mut buf[..n], "vdi: a block")?;
                Ok((n, Got::Data))
            }
        }
    }

    fn held_in(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len).min(self.len);
        if start >= end {
            return 0;
        }
        let (first, last) = (start / self.block, (end - 1) / self.block);
        let mut held = 0u64;
        for b in first..=last {
            let Some(&e) = self.map.get(usize::try_from(b).unwrap_or(usize::MAX)) else {
                break;
            };
            if e < ZERO {
                let (s, t) = (b * self.block, (b + 1) * self.block);
                held += t.min(end) - s.max(start);
            }
        }
        held
    }

    fn file_bytes(&self) -> u64 {
        self.file.len
    }

    fn properties(&self, out: &mut Vec<(&'static str, String)>) {
        let kind = match self.kind {
            1 => "Dynamic",
            2 => "Fixed",
            3 => "Undo",
            _ => "Differencing",
        };
        out.push(("Method", kind.into()));
        out.push(("Cluster Size", self.block.to_string()));
        out.push(("ID", show(&self.create)));
        if self.kind == 4 {
            out.push(("Parent ID", show(&self.linkage)));
        }
        out.push(("Allocated", self.allocated.to_string()));
    }

    fn notes(&self, out: &mut Vec<String>) {
        if self.kind == 3 {
            out.push(
                "vdi: an undo image, read alone: what it doesn't hold reads as zeros, not as \
                 the disk it was made over"
                    .to_owned(),
            );
        }
    }
}

/// The levels of the VDI `file` is, its parents' below it.
pub fn layers(file: Handle, origin: Origin, files: &mut Files) -> Result<Vec<Box<dyn Layer>>> {
    let mut file = file;
    let h = head(&mut file)?;
    let parent_modify = uuid(&h[440..456]);
    let v = Vdi::open(file)?;
    let (diff, linkage) = (v.kind == 4, v.linkage);
    let mut out: Vec<Box<dyn Layer>> = vec![Box::new(v)];
    if !diff {
        return Ok(out);
    }
    if linkage == [0; 16] {
        return Err(Error::corrupt(
            "vdi: a differencing image with no parent uuid",
        ));
    }
    let what = format!("the parent disk {{{}}}", show(&linkage));
    let is_it = |h: &mut Handle| head(h).is_ok_and(|hd| uuid(&hd[392..408]) == linkage);
    let parents = files.find_vdi(&origin, &what, is_it, |files, mut h, o| {
        let Ok(hd) = head(&mut h) else {
            return Ok(Err("not a VDI".into()));
        };
        let create = uuid(&hd[392..408]);
        if create != linkage {
            return Ok(Err(format!("its uuid is {}", show(&create))));
        }
        let modify = uuid(&hd[408..424]);
        if parent_modify != [0; 16] && modify != parent_modify {
            return Ok(Err(format!(
                "it has the uuid but was modified as {}, not {}: it changed after this disk \
                 was made",
                show(&modify),
                show(&parent_modify)
            )));
        }
        super::layers(Some(External::Vdi), h, o, files).map(Ok)
    })?;
    out.extend(parents);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{self, copy_into, digest, digest_of, dir, error_of, open_path};
    use crate::{ErrorKind, backend::External};

    const CHILD: &str = "Snapshots/{6d7a6970-6265-457a-8970-000000000411}.vdi";
    const GRANDCHILD: &str = "Snapshots/{6d7a6970-6265-457a-8970-000000000421}.vdi";

    #[test]
    fn every_vdi_fixture_reads_as_expected() {
        testing::check_all(&[".vdi"]);
    }

    #[test]
    fn a_differencing_chain_reads_as_virtualbox_lays_it_out() {
        // The grandchild's parent is beside it in Snapshots/, among its siblings; the child's,
        // in the folder above.
        let d = open_path(External::Vdi, &dir().join(GRANDCHILD)).unwrap();
        assert_eq!(d.depth(), 3);
        let p = d.properties();
        assert!(
            p.iter().any(|(k, v)| *k == "Parent"
                && v == "{6d7a6970-6265-457a-8970-000000000411}.vdi > d-base.vdi"),
            "{p:?}"
        );
        // Moved together into another folder, it still reads.
        let tmp = tempfile::tempdir().unwrap();
        copy_into(
            tmp.path(),
            &[
                ("d-base.vdi", "vm/d-base.vdi"),
                (CHILD, &format!("vm/{CHILD}")),
                (GRANDCHILD, &format!("vm/{GRANDCHILD}")),
            ],
        );
        let mut d = open_path(External::Vdi, &tmp.path().join("vm").join(GRANDCHILD)).unwrap();
        assert_eq!(digest(&mut d).unwrap(), digest_of(GRANDCHILD));
    }

    #[test]
    fn a_changed_parent_or_an_orphan_is_not_found_and_says_so() {
        let e = error_of(
            External::Vdi,
            &dir().join("Snapshots/{6d7a6970-6265-457a-8970-000000000431}.vdi"),
        );
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(
            e.message.contains("d-base.vdi (a .vdi in the folder above: it has the uuid but was modified as 6d7a6970-6265-457a-8970-000000000402, not 6d7a6970-6265-457a-8970-000000000499: it changed after this disk was made)"),
            "{e}"
        );
        let e = error_of(
            External::Vdi,
            &dir().join("Snapshots/{6d7a6970-6265-457a-8970-000000000441}.vdi"),
        );
        assert_eq!(e.kind, ErrorKind::NotFound, "{e}");
        assert!(
            e.message
                .contains("the parent disk {6d7a6970-6265-457a-8970-0000000004ff}"),
            "{e}"
        );
    }

    #[test]
    fn holdings_never_low() {
        let d = open_path(External::Vdi, &dir().join("d-vbox.vdi")).unwrap();
        // Blocks 0, 1, 3 and 6 of 64 KiB are stored; 2 is discarded.
        assert_eq!(d.held_in(0, d.len()), 4 << 16);
        assert_eq!(d.held_in(2 << 16, 1 << 16), 0);
        testing::holdings_never_low(&[".vdi"]);
    }

    #[test]
    fn mutated_vdis_never_panic() {
        testing::mutations(&[".vdi"], 24, 0x5EED_0003);
    }
}
