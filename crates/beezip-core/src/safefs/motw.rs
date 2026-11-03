//! Mark of the Web (docs/M1.md §3.5). If an archive came from the internet, Windows keeps a
//! `Zone.Identifier` stream on it. Explorer copies that stream to every file it extracts, which
//! keeps SmartScreen and Office Protected View aware of where the files came from; BeeZip does
//! the same.

use std::{io, path::Path};

/// The archive's `Zone.Identifier` stream, if it has one. Always `None` off Windows.
pub fn read_zone(archive: &Path) -> Option<Vec<u8>> {
    if cfg!(windows) {
        std::fs::read(stream_path(archive))
            .ok()
            .filter(|z| !z.is_empty())
    } else {
        None
    }
}

/// Writes `zone` as `path`'s `Zone.Identifier` stream. Does nothing off Windows.
pub fn write_zone(path: &Path, zone: &[u8]) -> io::Result<()> {
    if cfg!(windows) {
        std::fs::write(stream_path(path), zone)
    } else {
        Ok(())
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
