//! Mark of the Web (docs/M1.md §3.5). If an archive came from the internet, Windows keeps a
//! `Zone.Identifier` stream on it. Explorer copies that stream to every file it extracts, which
//! keeps SmartScreen and Office Protected View aware of where the files came from; BeeZip does
//! the same.
//!
//! On macOS the mark is the `com.apple.quarantine` attribute instead ([`quarantine`]), which
//! these functions read and write there (docs/M6.md §8.3): the "zone" is then its record. Linux
//! has neither, so there is nothing to carry over.

use std::{io, path::Path};

use super::quarantine;

/// The archive's `Zone.Identifier` stream (its quarantine record on macOS), if it has one.
/// Always `None` elsewhere.
pub fn read_zone(archive: &Path) -> Option<Vec<u8>> {
    if cfg!(windows) {
        std::fs::read(stream_path(archive))
            .ok()
            .filter(|z| !z.is_empty())
    } else {
        quarantine::read(archive)
    }
}

/// The first `Zone.Identifier` among a volume set's parts, first part first (docs/M3.md §3.2):
/// parts downloaded separately may not all carry one.
pub fn read_zone_of(parts: &[std::path::PathBuf]) -> Option<Vec<u8>> {
    parts.iter().find_map(|p| read_zone(p))
}

/// Writes `zone` as `path`'s `Zone.Identifier` stream (its quarantine record on macOS). Does
/// nothing elsewhere.
pub fn write_zone(path: &Path, zone: &[u8]) -> io::Result<()> {
    if cfg!(windows) {
        std::fs::write(stream_path(path), zone)
    } else {
        quarantine::write(path, zone)
    }
}

fn stream_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(":Zone.Identifier");
    s.into()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn zone_streams_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.zip");
        std::fs::write(&file, b"zip").unwrap();
        assert_eq!(read_zone(&file), None);
        let zone = b"[ZoneTransfer]\r\nZoneId=3\r\n";
        write_zone(&file, zone).unwrap();
        assert_eq!(read_zone(&file).as_deref(), Some(&zone[..]));
        // The data stream is untouched.
        assert_eq!(std::fs::read(&file).unwrap(), b"zip");
    }
}
