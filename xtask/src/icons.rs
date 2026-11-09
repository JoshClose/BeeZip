//! `cargo xtask icons [--check]`: the app's icons, in `apps/desktop/src-tauri/icons`, made from the
//! brand's sources in `packaging/brand`.
//!
//! - **`app-icon.svg`** (the logo, its cell filled white) makes every icon through
//!   `pnpm tauri icon`. Of what Tauri writes, only the files the app and the Windows 11 menu's
//!   package use are kept ([`FILES`]); its Android and iOS icons and its 64 px PNG are not.
//! - **`app-icon-16.svg`** (the bee alone, cropped to fill the square) is the 16 px image in
//!   `icon.ico`: at that size the cell's outline takes the edge pixels and leaves the bee about
//!   7 px wide.
//!
//! With `--check`, nothing is written: it fails if a committed icon differs from what the sources
//! make, as `codegen --check` does (CI runs it).

use std::io::Cursor;
use std::path::Path;

use anyhow::{Context, bail};

use crate::codegen::workspace_root;
use crate::dist::{check, pnpm};

const SOURCE: &str = "packaging/brand/app-icon.svg";
const SOURCE_16: &str = "packaging/brand/app-icon-16.svg";
const ICONS: &str = "apps/desktop/src-tauri/icons";

/// The icons kept: what `tauri.conf.json`'s `bundle.icon` names, `icon.png`, and the Windows
/// tiles (the sparse package takes `StoreLogo`, `Square44x44Logo` and `Square150x150Logo`).
pub const FILES: [&str; 16] = [
    "32x32.png",
    "128x128.png",
    "128x128@2x.png",
    "icon.icns",
    "icon.ico",
    "icon.png",
    "Square30x30Logo.png",
    "Square44x44Logo.png",
    "Square71x71Logo.png",
    "Square89x89Logo.png",
    "Square107x107Logo.png",
    "Square142x142Logo.png",
    "Square150x150Logo.png",
    "Square284x284Logo.png",
    "Square310x310Logo.png",
    "StoreLogo.png",
];

pub fn run(check_only: bool) -> anyhow::Result<()> {
    let root = workspace_root();
    let work = root.join("target").join("icons");
    if work.exists() {
        std::fs::remove_dir_all(&work).with_context(|| format!("emptying {}", work.display()))?;
    }
    let (all, small) = (work.join("all"), work.join("16"));
    std::fs::create_dir_all(&all)?;
    std::fs::create_dir_all(&small)?;
    tauri_icon(&root, &root.join(SOURCE), &all, None)?;
    tauri_icon(&root, &root.join(SOURCE_16), &small, Some(16))?;

    let ico = std::fs::read(all.join("icon.ico")).context("reading Tauri's icon.ico")?;
    let png16 = std::fs::read(small.join("16x16.png")).context("reading Tauri's 16x16.png")?;
    std::fs::write(all.join("icon.ico"), with_16(&ico, &png16)?)?;
    let icns = std::fs::read(all.join("icon.icns")).context("reading Tauri's icon.icns")?;
    std::fs::write(all.join("icon.icns"), sorted_icns(&icns)?)?;

    let dest = root.join(ICONS);
    let mut differ = Vec::new();
    for file in FILES {
        let made = std::fs::read(all.join(file))
            .with_context(|| format!("Tauri made no {file}: has `tauri icon` changed?"))?;
        let path = dest.join(file);
        if std::fs::read(&path).ok().as_deref() == Some(made.as_slice()) {
            continue;
        }
        if check_only {
            differ.push(file);
        } else {
            std::fs::write(&path, &made).with_context(|| format!("writing {}", path.display()))?;
            println!("wrote {ICONS}/{file}");
        }
    }
    if !differ.is_empty() {
        bail!(
            "{} differ from what packaging/brand makes: run `cargo xtask icons`",
            differ.join(", ")
        );
    }
    if check_only {
        println!("the icons are current");
    }
    Ok(())
}

/// `pnpm tauri icon` from `apps/desktop`: every icon, or with `size` only that PNG.
fn tauri_icon(root: &Path, source: &Path, out: &Path, size: Option<u32>) -> anyhow::Result<()> {
    let mut cmd = pnpm();
    cmd.current_dir(root.join("apps/desktop"))
        .args(["tauri", "icon"])
        .arg(source)
        .arg("-o")
        .arg(out);
    if let Some(size) = size {
        cmd.args(["-p", &size.to_string()]);
    }
    check(cmd.status(), "pnpm tauri icon")
}

/// `ico` with its 16×16 image replaced by `png16`, a 16×16 PNG, encoded as the `ico` crate
/// encodes Tauri's own images; the other images and their order are kept.
pub fn with_16(ico: &[u8], png16: &[u8]) -> anyhow::Result<Vec<u8>> {
    let dir = ico::IconDir::read(Cursor::new(ico)).context("reading icon.ico")?;
    let image = ico::IconImage::read_png(Cursor::new(png16)).context("reading the 16 px PNG")?;
    if (image.width(), image.height()) != (16, 16) {
        bail!(
            "the 16 px image is {}×{}, not 16×16",
            image.width(),
            image.height()
        );
    }
    let entry = ico::IconDirEntry::encode(&image)?;
    let mut out = ico::IconDir::new(ico::ResourceType::Icon);
    let mut replaced = false;
    for e in dir.entries() {
        if (e.width(), e.height()) == (16, 16) {
            out.add_entry(entry.clone());
            replaced = true;
        } else {
            out.add_entry(e.clone());
        }
    }
    if !replaced {
        bail!("icon.ico has no 16×16 image to replace");
    }
    let mut bytes = Vec::new();
    out.write(&mut bytes)?;
    Ok(bytes)
}

/// An `.icns` with its images in order of their type: Tauri writes them in a different order on
/// every run (the same images), which would make `--check` fail at random. Readers look images
/// up by type, so the order is free.
pub fn sorted_icns(icns: &[u8]) -> anyhow::Result<Vec<u8>> {
    let total = match icns {
        [b'i', b'c', b'n', b's', a, b, c, d, ..] => u32::from_be_bytes([*a, *b, *c, *d]) as usize,
        _ => bail!("icon.icns doesn't start with an icns header"),
    };
    if total != icns.len() {
        bail!("icon.icns says it's {total} bytes, but it's {}", icns.len());
    }
    let mut entries = Vec::new();
    let mut at = 8;
    while at < icns.len() {
        let Some(head) = icns.get(at..at + 8) else {
            bail!("icon.icns ends inside an image's header at byte {at}");
        };
        let len = u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize;
        let Some(entry) = icns.get(at..at + len).filter(|_| len >= 8) else {
            bail!("icon.icns has an image of {len} bytes at byte {at}, past its end");
        };
        entries.push(entry);
        at += len;
    }
    entries.sort_by_key(|e| &e[..4]);
    let mut out = Vec::with_capacity(icns.len());
    out.extend_from_slice(&icns[..8]);
    for e in entries {
        out.extend_from_slice(e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn icns_of(entries: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let body: Vec<u8> = entries
            .iter()
            .flat_map(|(t, d)| {
                let mut e = t.to_vec();
                e.extend_from_slice(&((d.len() + 8) as u32).to_be_bytes());
                e.extend_from_slice(d);
                e
            })
            .collect();
        let mut out = b"icns".to_vec();
        out.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn icns_images_are_put_in_type_order() {
        let shuffled = icns_of(&[(b"ic09", b"nine"), (b"is32", b"small"), (b"ic07", b"seven")]);
        let sorted = icns_of(&[(b"ic07", b"seven"), (b"ic09", b"nine"), (b"is32", b"small")]);
        assert_eq!(sorted_icns(&shuffled).unwrap(), sorted);
        assert_eq!(sorted_icns(&sorted).unwrap(), sorted);
        assert!(
            sorted_icns(b"icns\0\0\0\x09x").is_err(),
            "an image header cut short"
        );
        assert!(
            sorted_icns(&shuffled[..shuffled.len() - 1]).is_err(),
            "a wrong total"
        );
    }

    /// A one-colour square as an ICO entry, and as PNG bytes.
    fn square(size: u32, rgba: [u8; 4]) -> ico::IconImage {
        ico::IconImage::from_rgba_data(size, size, rgba.repeat((size * size) as usize))
    }
    fn png(image: &ico::IconImage) -> Vec<u8> {
        let mut out = Vec::new();
        image.write_png(&mut out).unwrap();
        out
    }
    fn ico_of(images: &[ico::IconImage]) -> Vec<u8> {
        let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
        for i in images {
            dir.add_entry(ico::IconDirEntry::encode(i).unwrap());
        }
        let mut out = Vec::new();
        dir.write(&mut out).unwrap();
        out
    }

    #[test]
    fn only_the_16_px_image_is_replaced() {
        let amber = [0xE0, 0xA2, 0x1A, 0xFF];
        let ink = [0x1F, 0x20, 0x23, 0xFF];
        let before = ico_of(&[square(16, amber), square(32, amber), square(256, amber)]);
        let after = with_16(&before, &png(&square(16, ink))).unwrap();
        let dir = ico::IconDir::read(Cursor::new(after)).unwrap();
        let sizes: Vec<u32> = dir.entries().iter().map(|e| e.width()).collect();
        assert_eq!(sizes, [16, 32, 256], "the same images, in the same order");
        assert_eq!(&dir.entries()[0].decode().unwrap().rgba_data()[..4], ink);
        assert_eq!(&dir.entries()[1].decode().unwrap().rgba_data()[..4], amber);
        assert_eq!(&dir.entries()[2].decode().unwrap().rgba_data()[..4], amber);
    }

    #[test]
    fn a_wrong_size_or_a_missing_16_is_refused() {
        let amber = [0xE0, 0xA2, 0x1A, 0xFF];
        let ico = ico_of(&[square(16, amber), square(32, amber)]);
        assert!(with_16(&ico, &png(&square(32, amber))).is_err());
        let no16 = ico_of(&[square(32, amber)]);
        assert!(with_16(&no16, &png(&square(16, amber))).is_err());
    }

    /// The committed icons: every file kept, and icon.ico with Tauri's sizes.
    #[test]
    fn the_committed_icon_has_every_size() {
        let bytes = std::fs::read(workspace_root().join(ICONS).join("icon.ico")).unwrap();
        let dir = ico::IconDir::read(Cursor::new(bytes)).unwrap();
        let mut sizes: Vec<u32> = dir.entries().iter().map(|e| e.width()).collect();
        sizes.sort_unstable();
        assert_eq!(sizes, [16, 24, 32, 48, 64, 256]);
        for file in FILES {
            assert!(workspace_root().join(ICONS).join(file).is_file(), "{file}");
        }
    }
}
