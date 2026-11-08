//! The malicious XAR and macOS package cases (docs/M6.md §10): a table of contents that
//! expands entities (a billion laughs), one that claims 4 GiB, a file whose data lies past the
//! end, and a traversal both in a XAR name and in a package payload's cpio. None has a table
//! checksum, so each fails for what it is, not for its checksum.

use std::io::Write;

use super::MTIME;

/// `(file name, bytes)` for each case.
pub fn corpus() -> anyhow::Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        ("billion-laughs.xar", xar(BILLION_LAUGHS, b"", None)?),
        (
            "toc-4gib.xar",
            xar(&toc(&file(1, "big.bin", 0, 4)), b"tiny", Some(4 << 30))?,
        ),
        (
            "heap-past-end.xar",
            xar(&toc(&file(1, "big.bin", 0, 1 << 20)), b"tiny", None)?,
        ),
        ("traversal.xar", traversal()?),
        ("traversal.pkg", pkg_traversal()?),
    ])
}

/// Nine levels of ten, used in a name: 10⁹ `a`s from a few hundred bytes, to a parser that
/// expands what a DOCTYPE declares.
const BILLION_LAUGHS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xar [
<!ENTITY a "aaaaaaaaaa">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
<!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
<!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
<!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">
<!ENTITY i "&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;">
]>
<xar>
 <toc>
  <file id="1">
   <name>&i;</name>
   <type>file</type>
  </file>
 </toc>
</xar>
"#;

/// [`MTIME`] as XAR writes times.
const XAR_MTIME: &str = "2026-01-01T00:00:00Z";

/// A stored file's `<file>` element, its data at `offset` in the heap, `length` long.
fn file(id: u32, name: &str, offset: u64, length: u64) -> String {
    format!(
        "<file id=\"{id}\"><data><length>{length}</length><offset>{offset}</offset>\
         <size>{length}</size><encoding style=\"application/octet-stream\"/></data>\
         <mtime>{XAR_MTIME}</mtime><mode>0644</mode><type>file</type><name>{name}</name></file>"
    )
}

fn toc(files: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar><toc>{files}</toc></xar>\n")
}

/// A XAR of a table of contents and a heap, without a table checksum. `claim` replaces the
/// table's unpacked length in the header.
fn xar(xml: &str, heap: &[u8], claim: Option<u64>) -> anyhow::Result<Vec<u8>> {
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(xml.as_bytes())?;
    let packed = z.finish()?;
    let mut out = b"xar!".to_vec();
    out.extend_from_slice(&28u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(packed.len() as u64).to_be_bytes());
    out.extend_from_slice(&claim.unwrap_or(xml.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&packed);
    out.extend_from_slice(heap);
    Ok(out)
}

/// `../evil.txt` as XAR names give it, a folder `..` holding `evil.txt`, beside `safe.txt`.
fn traversal() -> anyhow::Result<Vec<u8>> {
    let files = format!(
        "<file id=\"1\"><mtime>{XAR_MTIME}</mtime><mode>0755</mode><type>directory</type>\
         <name>..</name>{}</file>{}",
        file(2, "evil.txt", 0, 7),
        file(3, "safe.txt", 7, 4)
    );
    xar(&toc(&files), b"escapedsafe", None)
}

/// An odc cpio, as Apple's tools write a payload.
fn odc(members: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (ino, (name, mode, data)) in members.iter().enumerate() {
        out.extend_from_slice(
            format!(
                "070707{:06o}{ino:06o}{mode:06o}{:06o}{:06o}{:06o}{:06o}{MTIME:011o}{:06o}{:011o}",
                0,
                0,
                0,
                1,
                0,
                name.len() + 1,
                data.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(data);
    }
    out
}

/// A component package whose gzip'd payload holds `./../evil.txt` beside `./safe.txt`.
fn pkg_traversal() -> anyhow::Result<Vec<u8>> {
    let cpio = odc(&[
        (".", 0o040_755, b""),
        ("./../evil.txt", 0o100_644, b"escaped"),
        ("./safe.txt", 0o100_644, b"safe"),
        ("TRAILER!!!", 0, b""),
    ]);
    let mut gz = flate2::GzBuilder::new()
        .mtime(MTIME)
        .write(Vec::new(), flate2::Compression::default());
    gz.write_all(&cpio)?;
    let payload = gz.finish()?;
    let info = br#"<pkg-info identifier="com.example.evil" version="1"/>"#;
    let mut heap = payload.clone();
    heap.extend_from_slice(info);
    let files = format!(
        "{}{}",
        file(1, "Payload", 0, payload.len() as u64),
        file(2, "PackageInfo", payload.len() as u64, info.len() as u64)
    );
    xar(&toc(&files), &heap, None)
}
