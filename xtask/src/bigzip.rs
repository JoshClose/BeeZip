//! `cargo xtask bigzip [PATH]`: a zip of 1 000 folders × 1 000 files, for trying the desktop's
//! browser at a million entries (docs/M3.md §8). The files hold 0–99 bytes, so sorting by size
//! has something to sort. Written by hand, stored, with ZIP64 end records for the entry count;
//! it takes a second rather than the minutes a million real files would.

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
};

use crate::codegen::workspace_root;

const FOLDERS: u32 = 1000;
const FILES: u32 = 1000;
/// 2026-01-01 00:00 in DOS form.
const DOS_DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;
const UTF8: u16 = 1 << 11;

struct Central {
    name: String,
    crc: u32,
    size: u32,
    offset: u32,
    dir: bool,
}

pub fn run(path: Option<&str>) -> anyhow::Result<()> {
    let path = path.map_or_else(|| workspace_root().join("target/bigzip.zip"), PathBuf::from);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut out = BufWriter::with_capacity(1 << 20, File::create(&path)?);
    let data = [b'x'; 100];
    let crcs: Vec<u32> = (0..100).map(|n| crc32fast::hash(&data[..n])).collect();
    let mut central = Vec::with_capacity(((FOLDERS + 1) * FILES) as usize);
    let mut offset: u64 = 0;

    let mut local = |out: &mut BufWriter<File>,
                     name: String,
                     size: usize,
                     dir: bool|
     -> anyhow::Result<Central> {
        let crc = if dir { 0 } else { crcs[size] };
        let mut h = Vec::with_capacity(30 + name.len());
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes()); // version needed
        h.extend_from_slice(&UTF8.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&0u16.to_le_bytes()); // time
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&(size as u32).to_le_bytes());
        h.extend_from_slice(&(size as u32).to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        out.write_all(&h)?;
        out.write_all(&data[..size])?;
        let entry = Central {
            name,
            crc,
            size: size as u32,
            offset: u32::try_from(offset)?,
            dir,
        };
        offset += (h.len() + size) as u64;
        Ok(entry)
    };

    for d in 0..FOLDERS {
        central.push(local(&mut out, format!("folder-{d:04}/"), 0, true)?);
        for f in 0..FILES {
            let size = ((d * 7 + f * 13) % 100) as usize;
            central.push(local(
                &mut out,
                format!("folder-{d:04}/file-{f:04}.txt"),
                size,
                false,
            )?);
        }
    }

    let cd_offset = offset;
    let mut cd_size: u64 = 0;
    for e in &central {
        let mut h = Vec::with_capacity(46 + e.name.len());
        h.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes()); // made by: MS-DOS, 2.0
        h.extend_from_slice(&20u16.to_le_bytes()); // version needed
        h.extend_from_slice(&UTF8.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.extend_from_slice(&e.crc.to_le_bytes());
        h.extend_from_slice(&e.size.to_le_bytes());
        h.extend_from_slice(&e.size.to_le_bytes());
        h.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        h.extend_from_slice(&[0; 2 + 2 + 2 + 2]); // extra, comment, disk, internal attributes
        h.extend_from_slice(&(if e.dir { 0x10u32 } else { 0x20 }).to_le_bytes());
        h.extend_from_slice(&e.offset.to_le_bytes());
        h.extend_from_slice(e.name.as_bytes());
        out.write_all(&h)?;
        cd_size += h.len() as u64;
    }

    let count = central.len() as u64;
    let zip64_eocd = cd_offset + cd_size;
    let mut tail = Vec::new();
    tail.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
    tail.extend_from_slice(&44u64.to_le_bytes());
    tail.extend_from_slice(&45u16.to_le_bytes());
    tail.extend_from_slice(&45u16.to_le_bytes());
    tail.extend_from_slice(&[0; 8]); // this disk, the central directory's disk
    tail.extend_from_slice(&count.to_le_bytes());
    tail.extend_from_slice(&count.to_le_bytes());
    tail.extend_from_slice(&cd_size.to_le_bytes());
    tail.extend_from_slice(&cd_offset.to_le_bytes());
    tail.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    tail.extend_from_slice(&0u32.to_le_bytes());
    tail.extend_from_slice(&zip64_eocd.to_le_bytes());
    tail.extend_from_slice(&1u32.to_le_bytes());
    tail.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    tail.extend_from_slice(&[0; 4]);
    tail.extend_from_slice(&0xFFFFu16.to_le_bytes());
    tail.extend_from_slice(&0xFFFFu16.to_le_bytes());
    tail.extend_from_slice(&u32::try_from(cd_size)?.to_le_bytes());
    tail.extend_from_slice(&u32::try_from(cd_offset)?.to_le_bytes());
    tail.extend_from_slice(&0u16.to_le_bytes());
    out.write_all(&tail)?;
    out.flush()?;
    println!("wrote {} ({count} entries)", path.display());
    Ok(())
}
