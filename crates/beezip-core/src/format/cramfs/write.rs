//! CramFS images made by hand, for BeeZip's tests, fuzzing seeds and malicious corpus
//! (docs/M10.md §8). Laid out as mkfs.cramfs lays an image out: the superblock and the root's
//! inode, every folder's run of inodes and names, then each file's and link's block pointers and
//! zlib blocks. [`Built`] says where every inode and pointer table is, so a test can break any
//! field afterwards and [`Built::seal`] the image again. Not mkfs.cramfs: names aren't sorted,
//! and identical files aren't stored once.

use std::io::Write;

use flate2::{Compression, write::ZlibEncoder};

use super::{
    BLK_DIRECT, BLK_UNCOMPRESSED, FLAG_EXT_PTRS, FLAG_HOLES, FLAG_SORTED, FLAG_V2, MAGIC, PAD,
    SIGNATURE,
};

/// A node and what's in it.
#[derive(Debug, Clone)]
pub struct Node<'a> {
    pub name: &'a [u8],
    /// With its type: `0o100644` for a file.
    pub mode: u16,
    pub uid: u16,
    pub gid: u8,
    pub what: What<'a>,
}

#[derive(Debug, Clone)]
pub enum What<'a> {
    Dir(Vec<Node<'a>>),
    /// A file's data, or a link's target.
    Data(&'a [u8]),
    /// A device's number, or nothing (0) for a FIFO or socket: the size field.
    Size(u32),
}

impl<'a> Node<'a> {
    pub fn dir(name: &'a [u8], children: Vec<Node<'a>>) -> Self {
        Self::new(name, 0o40755, What::Dir(children))
    }

    pub fn file(name: &'a [u8], data: &'a [u8]) -> Self {
        Self::new(name, 0o100_644, What::Data(data))
    }

    pub fn link(name: &'a [u8], target: &'a [u8]) -> Self {
        Self::new(name, 0o120_777, What::Data(target))
    }

    /// A device, FIFO or socket: `mode` with its type.
    pub fn special(name: &'a [u8], mode: u16, size: u32) -> Self {
        Self::new(name, mode, What::Size(size))
    }

    fn new(name: &'a [u8], mode: u16, what: What<'a>) -> Self {
        Self {
            name,
            mode,
            uid: 0,
            gid: 0,
            what,
        }
    }
}

/// How a block is stored with Linux 4.15's extended block pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext {
    /// zlib, the pointer its end, as without the flag.
    Plain,
    /// As it is, the pointer its end, flagged uncompressed.
    Stored,
    /// zlib after a 16-bit length, the pointer its start (shifted by 2), flagged direct.
    Direct,
    /// As it is, the pointer its start, flagged direct and uncompressed.
    DirectStored,
}

/// How to lay the image out. The default is mkfs.cramfs's: little-endian, 4 KiB blocks,
/// version 2 with its CRC.
#[derive(Debug, Clone)]
pub struct Layout {
    pub big_endian: bool,
    pub block_size: u32,
    /// A 512-byte boot block before the superblock (mkfs.cramfs `-p`).
    pub pad: bool,
    /// All-zero blocks as holes (mkfs.cramfs `-z`).
    pub holes: bool,
    /// Extended block pointers: each block's kind, by its index in its file, cycled. Empty is
    /// without the flag.
    pub ext: Vec<Ext>,
    /// Version 2: the CRC, edition and counts (mkfs.cramfs always writes it).
    pub version2: bool,
    /// More flags, as given.
    pub flags: u32,
    pub name: Vec<u8>,
    pub edition: u32,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            big_endian: false,
            block_size: 4096,
            pad: false,
            holes: false,
            ext: Vec::new(),
            version2: true,
            flags: 0,
            name: b"Compressed".to_vec(),
            edition: 0,
        }
    }
}

/// An inode's fields; `namelen` and `offset` in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inode {
    pub mode: u16,
    pub uid: u16,
    pub size: u32,
    pub gid: u8,
    pub namelen: u32,
    pub offset: u32,
}

/// The 12 bytes of an inode. A big-endian image packs the fields from the top bit; fields too
/// wide for theirs are cut, as mkfs.cramfs cuts a 256-byte name length to 0.
pub fn inode_bytes(i: &Inode, big_endian: bool) -> [u8; 12] {
    let (a, b, c) = if big_endian {
        (
            u32::from(i.mode) << 16 | u32::from(i.uid),
            (i.size & 0xFF_FFFF) << 8 | u32::from(i.gid),
            ((i.namelen / 4) & 0x3F) << 26 | ((i.offset / 4) & 0x3FF_FFFF),
        )
    } else {
        (
            u32::from(i.mode) | u32::from(i.uid) << 16,
            (i.size & 0xFF_FFFF) | u32::from(i.gid) << 24,
            ((i.namelen / 4) & 0x3F) | ((i.offset / 4) & 0x3FF_FFFF) << 6,
        )
    };
    let mut out = [0u8; 12];
    for (k, w) in [a, b, c].into_iter().enumerate() {
        let bytes = if big_endian {
            w.to_be_bytes()
        } else {
            w.to_le_bytes()
        };
        out[4 * k..4 * k + 4].copy_from_slice(&bytes);
    }
    out
}

/// The image, and where its parts are.
#[derive(Debug, Clone)]
pub struct Built {
    pub image: Vec<u8>,
    pub big_endian: bool,
    /// Where the superblock is: 0, or 512 after a boot block.
    pub base: usize,
    /// Each node's inode, by its path (`a/b`); the root's is `""`.
    pub inodes: Vec<(Vec<u8>, usize)>,
    /// Each file's and link's block pointers, by its path.
    pub tables: Vec<(Vec<u8>, usize)>,
}

impl Built {
    /// Where `path`'s inode is.
    pub fn inode_at(&self, path: &[u8]) -> usize {
        self.inodes
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, at)| *at)
            .unwrap_or_else(|| panic!("no node {}", String::from_utf8_lossy(path)))
    }

    /// Where `path`'s block pointers are.
    pub fn table_at(&self, path: &[u8]) -> usize {
        self.tables
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, at)| *at)
            .unwrap_or_else(|| panic!("no file {}", String::from_utf8_lossy(path)))
    }

    pub fn u32_at(&self, at: usize) -> u32 {
        let b: [u8; 4] = self.image[at..at + 4].try_into().unwrap_or_default();
        if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }

    pub fn set_u32(&mut self, at: usize, v: u32) {
        let b = if self.big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.image[at..at + 4].copy_from_slice(&b);
    }

    /// `path`'s inode, as stored.
    pub fn inode(&self, path: &[u8]) -> Inode {
        let at = self.inode_at(path);
        let (a, b, c) = (self.u32_at(at), self.u32_at(at + 4), self.u32_at(at + 8));
        if self.big_endian {
            Inode {
                mode: (a >> 16) as u16,
                uid: a as u16,
                size: b >> 8,
                gid: b as u8,
                namelen: (c >> 26) * 4,
                offset: (c & 0x3FF_FFFF) * 4,
            }
        } else {
            Inode {
                mode: a as u16,
                uid: (a >> 16) as u16,
                size: b & 0xFF_FFFF,
                gid: (b >> 24) as u8,
                namelen: (c & 0x3F) * 4,
                offset: (c >> 6) * 4,
            }
        }
    }

    /// Rewrites `path`'s inode.
    pub fn set_inode(&mut self, path: &[u8], f: impl FnOnce(&mut Inode)) {
        let at = self.inode_at(path);
        let mut i = self.inode(path);
        f(&mut i);
        self.image[at..at + 12].copy_from_slice(&inode_bytes(&i, self.big_endian));
    }

    /// The superblock's size and, for version 2, its CRC, set for the image as it now is.
    pub fn seal(&mut self) {
        let len = u32::try_from(self.image.len()).unwrap_or(u32::MAX);
        let base = self.base;
        self.set_u32(base + 4, len);
        if self.u32_at(base + 8) & FLAG_V2 != 0 {
            self.set_u32(base + 32, 0);
            let crc = crc32fast::hash(&self.image[base..]);
            self.set_u32(base + 32, crc);
        }
    }
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::best());
    let _ = z.write_all(data);
    z.finish().unwrap_or_default()
}

fn padded(name: &[u8]) -> usize {
    name.len().div_ceil(4) * 4
}

/// The image of `root`'s children under `layout`.
pub fn cramfs(root: &[Node<'_>], layout: &Layout) -> Built {
    let be = layout.big_endian;
    let base = if layout.pad { PAD as usize } else { 0 };
    let blk = layout.block_size.max(1) as usize;
    let mut b = Built {
        image: vec![0; base + 76],
        big_endian: be,
        base,
        inodes: vec![(Vec::new(), base + 64)],
        tables: Vec::new(),
    };

    // Every folder's run, breadth first: (the folder's inode, its path, its node, its children);
    // the root has no node of its own.
    type Run<'n, 'a> = (usize, Vec<u8>, Option<&'n Node<'a>>, &'n [Node<'a>]);
    let mut runs: Vec<Run<'_, '_>> = vec![(base + 64, Vec::new(), None, root)];
    let mut files: Vec<(usize, Vec<u8>, &Node<'_>)> = Vec::new();
    let mut nodes = 1u32;
    let mut i = 0;
    while i < runs.len() {
        let (dir_at, path, node, children) = runs[i].clone();
        i += 1;
        let start = b.image.len();
        for n in children {
            nodes += 1;
            let at = b.image.len();
            let mut full = path.clone();
            if !full.is_empty() {
                full.push(b'/');
            }
            full.extend_from_slice(n.name);
            b.image.extend_from_slice(&[0; 12]);
            b.image.extend_from_slice(n.name);
            b.image.resize(at + 12 + padded(n.name), 0);
            b.inodes.push((full.clone(), at));
            match &n.what {
                What::Dir(c) => runs.push((at, full, Some(n), c)),
                What::Data(_) => files.push((at, full, n)),
                // Devices, FIFOs and sockets: the size field only.
                What::Size(size) => b.image[at..at + 12].copy_from_slice(&inode_bytes(
                    &Inode {
                        mode: n.mode,
                        uid: n.uid,
                        size: *size,
                        gid: n.gid,
                        namelen: padded(n.name) as u32,
                        offset: 0,
                    },
                    be,
                )),
            }
        }
        let (offset, size) = if children.is_empty() {
            (0, 0)
        } else {
            (start as u32, (b.image.len() - start) as u32)
        };
        let (mode, uid, gid) = node.map_or((0o40755, 0, 0), |n| (n.mode, n.uid, n.gid));
        b.image[dir_at..dir_at + 12].copy_from_slice(&inode_bytes(
            &Inode {
                mode,
                uid,
                size,
                gid,
                namelen: node.map_or(0, |n| padded(n.name) as u32),
                offset,
            },
            be,
        ));
    }

    // The data: pointer tables and blocks.
    let ext = !layout.ext.is_empty();
    let mut blocks = 0u32;
    for (at, path, n) in files {
        let What::Data(d) = n.what else {
            continue;
        };
        while !b.image.len().is_multiple_of(4) {
            b.image.push(0);
        }
        let table = b.image.len();
        let count = d.len().div_ceil(blk);
        b.image.resize(table + 4 * count, 0);
        b.tables.push((path, table));
        for (k, chunk) in d.chunks(blk).enumerate() {
            blocks += 1;
            let kind = if ext {
                layout.ext[k % layout.ext.len()]
            } else {
                Ext::Plain
            };
            let ptr = match kind {
                Ext::Plain if layout.holes && chunk.iter().all(|&c| c == 0) => b.image.len() as u32,
                Ext::Plain => {
                    b.image.extend_from_slice(&zlib(chunk));
                    b.image.len() as u32
                }
                Ext::Stored => {
                    b.image.extend_from_slice(chunk);
                    b.image.len() as u32 | BLK_UNCOMPRESSED
                }
                Ext::Direct | Ext::DirectStored => {
                    while !b.image.len().is_multiple_of(4) {
                        b.image.push(0);
                    }
                    let start = b.image.len() as u32;
                    if kind == Ext::Direct {
                        let z = zlib(chunk);
                        let n = z.len() as u16;
                        let len = if be { n.to_be_bytes() } else { n.to_le_bytes() };
                        b.image.extend_from_slice(&len);
                        b.image.extend_from_slice(&z);
                        (start >> 2) | BLK_DIRECT
                    } else {
                        b.image.extend_from_slice(chunk);
                        (start >> 2) | BLK_DIRECT | BLK_UNCOMPRESSED
                    }
                }
            };
            b.set_u32(table + 4 * k, ptr);
        }
        b.image[at..at + 12].copy_from_slice(&inode_bytes(
            &Inode {
                mode: n.mode,
                uid: n.uid,
                size: d.len() as u32,
                gid: n.gid,
                namelen: padded(n.name) as u32,
                offset: if d.is_empty() { 0 } else { table as u32 },
            },
            be,
        ));
    }
    while !b.image.len().is_multiple_of(4) {
        b.image.push(0);
    }

    // The superblock.
    let mut flags = layout.flags;
    if layout.version2 {
        flags |= FLAG_V2 | FLAG_SORTED;
    }
    if layout.holes {
        flags |= FLAG_HOLES;
    }
    if ext {
        flags |= FLAG_EXT_PTRS;
    }
    b.set_u32(base, MAGIC);
    b.set_u32(base + 8, flags);
    b.image[base + 16..base + 32].copy_from_slice(SIGNATURE);
    if layout.version2 {
        b.set_u32(base + 36, layout.edition);
        b.set_u32(base + 40, blocks);
        b.set_u32(base + 44, nodes);
    }
    let name = &layout.name[..layout.name.len().min(16)];
    b.image[base + 48..base + 48 + name.len()].copy_from_slice(name);
    b.seal();
    b
}
