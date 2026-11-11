//! Formats read through another program: the installed 7-Zip (docs/M6.md §3).
//!
//! BeeZip's own sniffers ([`sniff`]) claim the formats, so detection names them whether or not
//! 7-Zip is there. Opening one runs `7z l -slt` ([`slt`] parses it) and extracting streams
//! `7z x -so` into `FsSink` ([`sevenzip`]); nothing of 7-Zip's touches the disk, except an NSIS
//! installer's files, staged in a private folder.

pub mod find;
pub mod process;
pub mod sevenzip;
pub mod slt;
pub mod sniff;

use std::path::PathBuf;

use crate::{
    detect::{Confidence, Probe},
    format::{ArchiveFormat, FormatCaps, FormatId},
};

pub use find::{MIN_VERSION, SevenZip, find};
pub use sevenzip::SevenZipReader;

/// A format the 7-Zip backend reads. One [`FormatId::External`] carries it, so the wire names
/// and `formats.list` grow without a variant per format (docs/M6.md §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum External {
    /// WIM, ESD and SWM.
    Wim,
    Chm,
    /// MSI, MSP and MSM: a Compound File with an installer's root CLSID.
    Msi,
    /// An NSIS installer: an executable with NSIS's header at its overlay.
    Nsis,
    Vhdx,
    Vhd,
    Vmdk,
    Qcow2,
    Vdi,
    Fat,
    Ntfs,
    /// ext2, ext3 and ext4.
    Ext,
    /// HFS+ and HFSX, bare (a DMG is BeeZip's own).
    Hfs,
    Apfs,
    Cramfs,
    /// A partitioned disk. Ranked below the file systems and ISO, since those can hold a
    /// partition table too.
    Gpt,
    Mbr,
}

impl External {
    pub const ALL: [External; 17] = [
        Self::Wim,
        Self::Chm,
        Self::Msi,
        Self::Nsis,
        Self::Vhdx,
        Self::Vhd,
        Self::Vmdk,
        Self::Qcow2,
        Self::Vdi,
        Self::Fat,
        Self::Ntfs,
        Self::Ext,
        Self::Hfs,
        Self::Apfs,
        Self::Cramfs,
        Self::Gpt,
        Self::Mbr,
    ];

    /// The wire name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wim => "wim",
            Self::Chm => "chm",
            Self::Msi => "msi",
            Self::Nsis => "nsis",
            Self::Vhdx => "vhdx",
            Self::Vhd => "vhd",
            Self::Vmdk => "vmdk",
            Self::Qcow2 => "qcow2",
            Self::Vdi => "vdi",
            Self::Fat => "fat",
            Self::Ntfs => "ntfs",
            Self::Ext => "ext",
            Self::Hfs => "hfs",
            Self::Apfs => "apfs",
            Self::Cramfs => "cramfs",
            Self::Gpt => "gpt",
            Self::Mbr => "mbr",
        }
    }

    /// For people, and after "this" in messages ("Opening this WIM image needs 7-Zip…").
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Wim => "WIM image",
            Self::Chm => "CHM help file",
            Self::Msi => "Windows Installer package",
            Self::Nsis => "NSIS installer",
            Self::Vhdx => "VHDX disk image",
            Self::Vhd => "VHD disk image",
            Self::Vmdk => "VMDK disk image",
            Self::Qcow2 => "QCOW2 disk image",
            Self::Vdi => "VDI disk image",
            Self::Fat => "FAT image",
            Self::Ntfs => "NTFS image",
            Self::Ext => "ext2/3/4 image",
            Self::Hfs => "HFS+ image",
            Self::Apfs => "APFS image",
            Self::Cramfs => "CramFS image",
            Self::Gpt => "GPT disk image",
            Self::Mbr => "MBR disk image",
        }
    }

    /// Lowercase, with the dot. An NSIS installer is an `.exe`, which detection accepts for
    /// anything found at an executable's overlay, so it lists none: an extension alone must
    /// never make every executable an installer.
    pub const fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Wim => &[".wim", ".esd", ".swm"],
            Self::Chm => &[".chm"],
            Self::Msi => &[".msi", ".msp", ".msm"],
            Self::Nsis => &[],
            Self::Vhdx => &[".vhdx"],
            Self::Vhd => &[".vhd"],
            Self::Vmdk => &[".vmdk"],
            Self::Qcow2 => &[".qcow2", ".qcow"],
            Self::Vdi => &[".vdi"],
            Self::Fat => &[".img", ".ima"],
            Self::Ntfs => &[".img"],
            Self::Ext => &[".img", ".ext2", ".ext3", ".ext4"],
            Self::Hfs => &[".hfs", ".hfsx"],
            Self::Apfs => &[".apfs"],
            Self::Cramfs => &[".cramfs", ".img"],
            Self::Gpt | Self::Mbr => &[".img", ".raw"],
        }
    }

    /// The `Type` 7-Zip prints for the archive's outermost level when it opens this format.
    pub const fn seven_zip_type(self) -> &'static str {
        match self {
            Self::Wim => "wim",
            Self::Chm => "Chm",
            Self::Msi => "Compound",
            Self::Nsis => "Nsis",
            Self::Vhdx => "VHDX",
            Self::Vhd => "VHD",
            Self::Vmdk => "VMDK",
            Self::Qcow2 => "QCOW",
            Self::Vdi => "VDI",
            Self::Fat => "FAT",
            Self::Ntfs => "NTFS",
            Self::Ext => "Ext",
            Self::Hfs => "HFS",
            Self::Apfs => "APFS",
            Self::Cramfs => "CramFS",
            Self::Gpt => "GPT",
            Self::Mbr => "MBR",
        }
    }

    /// The format 7-Zip's `Type` names, if it's one of these.
    pub fn from_seven_zip_type(t: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.seven_zip_type().eq_ignore_ascii_case(t))
    }

    /// Explorer's menu offers BeeZip's archive items on these formats' extensions; none of
    /// them is associated (docs/M6.md §3.7). Windows mounts VHD(X) and installs MSIs, and
    /// `.img` and `.exe` are too broad.
    pub const fn in_menu(self) -> bool {
        matches!(
            self,
            Self::Wim | Self::Chm | Self::Vhd | Self::Vhdx | Self::Vmdk | Self::Qcow2 | Self::Vdi
        )
    }

    /// BeeZip reads it with its own code (docs/M7.md, docs/M8.md): the file systems,
    /// partitioned disks, virtual disks, MSI installers and WIM images. 7-Zip still reads what
    /// those readers don't support, when it's installed (an MSI patch, an NTFS volume of clusters
    /// over 64 KiB, a QCOW version 1, an ESD on Linux); the rest are 7-Zip's alone.
    pub const fn native(self) -> bool {
        matches!(
            self,
            Self::Wim
                | Self::Msi
                | Self::Vhd
                | Self::Vhdx
                | Self::Vmdk
                | Self::Qcow2
                | Self::Vdi
                | Self::Fat
                | Self::Ntfs
                | Self::Ext
                | Self::Hfs
                | Self::Apfs
                | Self::Gpt
                | Self::Mbr
        )
    }

    /// Whether `7z t` checks the files' data against checksums the format stores (WIM's
    /// SHA-1s). For the rest, testing means "7-Zip can decode it" (docs/M6.md §3.5).
    pub const fn checks_data(self) -> bool {
        matches!(self, Self::Wim)
    }

    pub fn format(self) -> &'static dyn ArchiveFormat {
        &FORMATS[self as usize]
    }
}

/// The [`ArchiveFormat`] of one [`External`].
#[derive(Debug)]
pub struct ExternalFormat(External);

static FORMATS: [ExternalFormat; 17] = [
    ExternalFormat(External::Wim),
    ExternalFormat(External::Chm),
    ExternalFormat(External::Msi),
    ExternalFormat(External::Nsis),
    ExternalFormat(External::Vhdx),
    ExternalFormat(External::Vhd),
    ExternalFormat(External::Vmdk),
    ExternalFormat(External::Qcow2),
    ExternalFormat(External::Vdi),
    ExternalFormat(External::Fat),
    ExternalFormat(External::Ntfs),
    ExternalFormat(External::Ext),
    ExternalFormat(External::Hfs),
    ExternalFormat(External::Apfs),
    ExternalFormat(External::Cramfs),
    ExternalFormat(External::Gpt),
    ExternalFormat(External::Mbr),
];

impl ArchiveFormat for ExternalFormat {
    fn id(&self) -> FormatId {
        FormatId::External(self.0)
    }

    fn extensions(&self) -> &'static [&'static str] {
        self.0.extensions()
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Confidence> {
        sniff::sniff(self.0, probe)
    }

    /// List and extract only: 7-Zip reads these, and BeeZip edits nothing it reads through
    /// 7-Zip. An NSIS installer is one solid stream.
    fn caps(&self) -> FormatCaps {
        FormatCaps {
            list: true,
            extract: true,
            random_access: self.0 != External::Nsis,
            ..FormatCaps::default()
        }
    }
}

/// What `archive.info` tells about an archive 7-Zip reads (docs/M6.md §3.5), or a disk or volume
/// BeeZip reads itself (docs/M7.md §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalInfo {
    /// The program that reads it: "7-Zip 26.00". `None` when it's BeeZip.
    pub backend: Option<String>,
    /// The formats opened, outermost first: `["vhdx", "gpt", "ntfs"]`.
    pub levels: Vec<String>,
    /// What the levels record: a volume's label, a WIM's images, a cluster size.
    pub properties: Vec<LevelProperty>,
    /// Things to know: an MSI's names are the installer's internal keys.
    pub notes: Vec<String>,
}

/// One fact a level records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelProperty {
    /// The level's format: `ntfs`.
    pub level: String,
    /// 7-Zip's name for it: `Label`, `Cluster Size`.
    pub name: String,
    pub value: String,
}

/// `[seven_zip]` in the config, as core takes it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SevenZipOptions {
    /// The 7-Zip to run; `None` finds one (docs/M6.md §3.1).
    pub path: Option<PathBuf>,
    /// `false` turns the backend off: its formats are still detected, and opening one is
    /// `BackendUnavailable`.
    pub enabled: bool,
}

impl Default for SevenZipOptions {
    fn default() -> Self {
        Self {
            path: None,
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_line_up() {
        for (i, k) in External::ALL.into_iter().enumerate() {
            assert_eq!(k as usize, i);
            assert_eq!(FORMATS[i].0, k);
            assert_eq!(External::from_seven_zip_type(k.seven_zip_type()), Some(k));
            assert_eq!(FormatId::from_name(k.name()), Some(FormatId::External(k)));
        }
    }
}
