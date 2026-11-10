//! FAT12/16/32 (docs/M7.md §4).

use super::{Device, FileSystem, VolumeOptions};
use crate::{Ctx, Error, Result};

/// The volume on `dev`.
pub fn open(dev: Device, opts: &VolumeOptions, cx: &mut dyn Ctx) -> Result<Box<dyn FileSystem>> {
    let _ = (dev, opts, cx);
    Err(Error::unsupported(
        "BeeZip's own FAT reader isn't built yet",
    ))
}
