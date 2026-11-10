//! MSI installers (docs/M7.md §8).

use super::ArchiveReader;
use crate::{Ctx, Error, Result, source::Source};

/// Opens a Windows Installer package. Patches, transforms and merge modules are
/// `UnsupportedOperation`, for 7-Zip to read when it's installed.
pub fn open(source: Source, cx: &mut dyn Ctx) -> Result<Box<dyn ArchiveReader>> {
    let _ = (source, cx);
    Err(Error::unsupported(
        "BeeZip's own MSI reader isn't built yet",
    ))
}
