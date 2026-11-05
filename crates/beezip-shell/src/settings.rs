//! What the DLL reads from `HKCU\Software\BeeZip\Shell` (docs/M4.md §5.4), the mirror of
//! `config.toml`'s `[shell]` that `shell.install` and `settings.set` write. The DLL never parses
//! TOML. The key is read once for each object Explorer makes, which is once per menu, so a change
//! applies on the next right-click.

use std::path::PathBuf;

use beezip_menu::Item;

/// The key under `HKEY_CURRENT_USER`.
pub const KEY: &str = r"Software\BeeZip\Shell";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// `App`: the `BeeZip.exe` that `Invoke` starts.
    pub app: Option<PathBuf>,
    /// `Hidden`: the items left out.
    pub hidden: Vec<Item>,
    /// `Log`: append every call to `%LOCALAPPDATA%\BeeZip\shell.log`.
    pub log: bool,
    /// `Panic`, read in debug builds only: the method that panics on purpose (`tests/com.rs`).
    pub panic_in: Option<String>,
}

impl Settings {
    pub fn menu(&self) -> beezip_menu::Settings {
        beezip_menu::Settings {
            hidden: self.hidden.clone(),
        }
    }
}

/// The key to read. Debug builds take `BEEZIP_SHELL_KEY` instead, so tests never touch the real
/// one.
pub fn key_path() -> String {
    if cfg!(debug_assertions)
        && let Ok(key) = std::env::var("BEEZIP_SHELL_KEY")
        && !key.is_empty()
    {
        return key;
    }
    KEY.to_owned()
}

/// The settings now. A missing key or value is the default: everything shown, no log.
pub fn read() -> Settings {
    let Ok(key) = windows_registry::CURRENT_USER.open(key_path()) else {
        crate::log::set(false);
        return Settings::default();
    };
    let settings = Settings {
        app: key
            .get_string("App")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        hidden: key
            .get_multi_string("Hidden")
            .unwrap_or_default()
            .iter()
            .filter_map(|id| Item::from_id(id))
            .collect(),
        log: key.get_u32("Log").is_ok_and(|v| v != 0),
        panic_in: if cfg!(debug_assertions) {
            key.get_string("Panic").ok().filter(|s| !s.is_empty())
        } else {
            None
        },
    };
    crate::log::set(settings.log);
    settings
}
