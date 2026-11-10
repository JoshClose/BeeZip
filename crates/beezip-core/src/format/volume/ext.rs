//! ext2/3/4 (docs/M7.md §5).

use super::{Device, FileSystem, VolumeOptions};
use crate::{Ctx, Error, Result};

/// The volume on `dev`.
pub fn open(dev: Device, opts: &VolumeOptions, cx: &mut dyn Ctx) -> Result<Box<dyn FileSystem>> {
    let _ = (dev, opts, cx);
    Err(Error::unsupported(
        "BeeZip's own ext reader isn't built yet",
    ))
}
