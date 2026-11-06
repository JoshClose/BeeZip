//! The fixed CLSIDs of BeeZip's Explorer menu (docs/M4.md §4.1). One class factory in the DLL
//! serves all of them and tells the context from the CLSID:
//! - the **classic root**, registered under `HKCU\Software\Classes\CLSID` for the classic menu;
//! - the **modern root**, declared by the sparse package for the Windows 11 menu;
//! - **one per item**, used only when the classic menu isn't cascaded (`[shell] cascade = false`).
//!
//! They are `u128`s in the layout `windows_core::GUID::from_u128` takes, so this crate needs no
//! Windows API. Never change one: they are registry keys on users' machines.

use crate::Item;

/// The root of the classic menu ("BeeZip >" on Windows 10, and under "Show more options").
pub const CLASSIC_ROOT: u128 = 0xB788B651_F40D_446D_A601_2D23F9E0C37B;
/// The root of the Windows 11 menu, served from the package's COM surrogate.
pub const MODERN_ROOT: u128 = 0x03CB0FA0_5D6C_4547_9B65_956DE58D1AF2;

impl Item {
    /// The item's own CLSID: its top-level verb in the classic menu without the cascade, and its
    /// canonical name everywhere.
    pub const fn clsid(self) -> u128 {
        match self {
            Self::Open => 0xEA0379CD_D0D3_4A69_A9D2_583104EED7DC,
            Self::ExtractHere => 0x1F265446_4A9F_4104_8065_D1E18E5A0916,
            Self::ExtractFolder => 0x216EF4F2_4845_43D5_9689_D42749C642AA,
            Self::ExtractTo => 0xDC32BBAF_BE4F_4D27_AE56_9D12A74D127B,
            Self::Test => 0xCB0400CB_D815_4866_8B34_408E8A24E878,
            Self::AddZip => 0x58BEA0CF_36C1_4B73_9B1C_2B4D4DC3D889,
            Self::Add7z => 0xC664F93E_D79E_4D21_8819_7DE8E4E0DBD5,
            Self::AddTarZst => 0x137CEA41_C0CA_4C0F_8319_618AFA9B147F,
            Self::CompressTo => 0x87CFBAE8_22F4_4031_800D_BD90298CCCA4,
        }
    }

    /// The item whose CLSID this is.
    pub fn from_clsid(clsid: u128) -> Option<Self> {
        Self::ALL.into_iter().find(|i| i.clsid() == clsid)
    }
}

/// The registry form: `{B788B651-F40D-446D-A601-2D23F9E0C37B}`.
pub fn braced(clsid: u128) -> String {
    let h = format!("{clsid:032X}");
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn braced_form() {
        assert_eq!(
            braced(CLASSIC_ROOT),
            "{B788B651-F40D-446D-A601-2D23F9E0C37B}"
        );
    }

    #[test]
    fn every_clsid_is_distinct_and_maps_back() {
        let mut all: Vec<u128> = Item::ALL.iter().map(|i| i.clsid()).collect();
        all.extend([CLASSIC_ROOT, MODERN_ROOT]);
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
        for item in Item::ALL {
            assert_eq!(Item::from_clsid(item.clsid()), Some(item));
        }
        assert_eq!(Item::from_clsid(CLASSIC_ROOT), None);
    }
}
