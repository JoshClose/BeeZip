//! The settings mirror (docs/M4.md §5.4): `HKCU\Software\BeeZip\Shell`, which the DLL reads on
//! every right-click, since it never parses TOML. `shell.install` writes it, `settings.set`
//! keeps it in step with `[shell]`, and `shell.uninstall` removes it.
//!
//! | Value | Type | Meaning |
//! |---|---|---|
//! | `App` | REG_SZ | the `BeeZip.exe` a click starts |
//! | `Dll` | REG_SZ | the registered DLL |
//! | `Mode` | REG_SZ | `classic` or `modern` |
//! | `Hidden` | REG_MULTI_SZ | item ids left out |
//! | `Cascade` | REG_DWORD | classic menu only |
//! | `Log` | REG_DWORD | the DLL's debug log; set by hand, never written here |

use std::path::PathBuf;

use beezip_menu::Item;
use windows_registry::CURRENT_USER;

use super::{Hive, reg_error};
use crate::CmdError;

const KEY: &str = r"BeeZip\Shell";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub app: Option<PathBuf>,
    pub dll: Option<PathBuf>,
    pub mode: Option<String>,
    pub hidden: Vec<Item>,
    pub cascade: bool,
    pub log: bool,
}

pub fn read(hive: &Hive) -> Option<Mirror> {
    let key = CURRENT_USER.open(hive.key(KEY)).ok()?;
    let path = |name: &str| {
        key.get_string(name)
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    };
    Some(Mirror {
        app: path("App"),
        dll: path("Dll"),
        mode: key.get_string("Mode").ok().filter(|s| !s.is_empty()),
        hidden: key
            .get_multi_string("Hidden")
            .unwrap_or_default()
            .iter()
            .filter_map(|id| Item::from_id(id))
            .collect(),
        cascade: key.get_u32("Cascade").ok() != Some(0),
        log: key.get_u32("Log").is_ok_and(|v| v != 0),
    })
}

/// Writes every value but `Log`, which stays as it was.
pub fn write(hive: &Hive, m: &Mirror) -> Result<(), CmdError> {
    let err = |e: windows_result::Error| reg_error("writing BeeZip's menu settings", &e);
    let key = CURRENT_USER.create(hive.key(KEY)).map_err(err)?;
    let text = |p: &Option<PathBuf>| p.as_ref().map(|p| p.to_string_lossy().into_owned());
    key.set_string("App", text(&m.app).unwrap_or_default())
        .map_err(err)?;
    key.set_string("Dll", text(&m.dll).unwrap_or_default())
        .map_err(err)?;
    key.set_string("Mode", m.mode.as_deref().unwrap_or_default())
        .map_err(err)?;
    let hidden: Vec<&str> = m.hidden.iter().map(|i| i.id()).collect();
    key.set_multi_string("Hidden", &hidden).map_err(err)?;
    key.set_u32("Cascade", u32::from(m.cascade)).map_err(err)?;
    Ok(())
}

/// Updates only what `[shell]` sets: the hidden items and the cascade.
pub fn set_menu(hive: &Hive, hidden: &[Item], cascade: bool) -> Result<(), CmdError> {
    let err = |e: windows_result::Error| reg_error("writing BeeZip's menu settings", &e);
    let key = CURRENT_USER.create(hive.key(KEY)).map_err(err)?;
    let hidden: Vec<&str> = hidden.iter().map(|i| i.id()).collect();
    key.set_multi_string("Hidden", &hidden).map_err(err)?;
    key.set_u32("Cascade", u32::from(cascade)).map_err(err)?;
    Ok(())
}

/// Removes the key, and `HKCU\Software\BeeZip` when nothing else is in it.
pub fn remove(hive: &Hive) -> Result<bool, CmdError> {
    let removed = super::classic::remove_tree(&hive.key(KEY))?;
    super::classic::remove_if_empty(&hive.key("BeeZip"))?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_the_log_value() {
        let hive = Hive::test("mirror");
        assert_eq!(read(&hive), None);
        let m = Mirror {
            app: Some(r"C:\BeeZip\BeeZip.exe".into()),
            dll: Some(r"C:\BeeZip\beezip_shell_0.1.0.dll".into()),
            mode: Some("classic".into()),
            hidden: vec![Item::Test, Item::AddTarZst],
            cascade: false,
            log: false,
        };
        write(&hive, &m).unwrap();
        CURRENT_USER
            .create(hive.key(KEY))
            .unwrap()
            .set_u32("Log", 1)
            .unwrap();
        write(&hive, &m).unwrap();
        assert_eq!(read(&hive), Some(Mirror { log: true, ..m }));

        set_menu(&hive, &[], true).unwrap();
        let after = read(&hive).unwrap();
        assert!(after.hidden.is_empty() && after.cascade && after.app.is_some());

        assert!(remove(&hive).unwrap());
        assert_eq!(read(&hive), None);
        assert!(!remove(&hive).unwrap());
        let _ = CURRENT_USER.remove_tree(hive.base());
    }
}
