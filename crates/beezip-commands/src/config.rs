//! `config.toml` (docs/M1.md §4.1): `%APPDATA%\BeeZip\config.toml`, or the file `BEEZIP_CONFIG`
//! names. A missing file means defaults and unknown keys only warn; a value of the wrong type
//! fails every command that needs the config, with `InvalidArgs` and the TOML line number.
//!
//! ```toml
//! [extract]
//! overwrite = "ask"          # ask | always | never | rename | newer
//! links = false
//! mark_of_the_web = "all"    # all | none
//! threads = 0                # zips and xz: 0 = one per core, 1 = one (docs/M6.md §6)
//!
//! [edit]                     # archive.add (docs/M5.md §7.1)
//! overwrite = "ask"          # an entry already there: ask | always | never | rename | newer
//!
//! [names]                    # names stored as bytes (docs/M5.md §6)
//! encoding = "auto"          # auto | utf-8 | cp437 | cp932 | …
//!
//! [create]
//! threads = 0                # 0 = one per core
//!
//! [levels]                   # per codec and zip method
//! zstd = 3
//!
//! [stream]
//! codec = "zstd"             # default for `beezip compress`
//!
//! [limits]
//! max_ratio = 10000
//! max_entries = 10000000
//! decoder_memory_mib = 1024  # no max_total_bytes = unlimited
//!
//! [mcp]                      # `beezip mcp` (docs/M2.md §4)
//! roots = ['C:\work']        # where it may write; `--root` replaces this list
//! read_only = false
//!
//! [shell]                    # Explorer's right-click menu (docs/M4.md §7.2)
//! cascade = true             # classic menu only: false puts each item at the top level
//! [shell.items]              # every item is shown unless set to false
//! test = false
//!
//! [jobs]
//! close_when_done = true     # a job window closes itself after a clean success
//!
//! [seven_zip]                # the 7-Zip that reads NSIS, CHM and CramFS (docs/M6.md §3)
//! path = 'C:\Tools\7z.exe'   # empty or missing: found in the registry, PATH or Program Files
//! enabled = true
//!
//! [desktop]
//! theme = "system"           # system | light | dark
//!
//! [updates]                  # the desktop app only; the CLI and MCP never check (docs/M6.md §8.2)
//! check = true               # look for a new release on GitHub at most once a day
//! ```
//!
//! The types here are also the wire shape `settings.get` returns, so they derive serde,
//! JsonSchema and ts-rs; their doc comments are the settings' descriptions.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use beezip_core::{Limits, limits::MIB};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::{
    CmdError,
    wire::{CodecName, NameEncoding, OverwritePolicy},
};

/// Every setting, as `config.toml` holds it. A missing key has its default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct Config {
    pub extract: ExtractConfig,
    pub edit: EditConfig,
    pub names: NamesConfig,
    pub create: CreateConfig,
    /// Default levels by codec name (`zstd`, `gzip`…) or zip and 7z method (`deflate`,
    /// `lzma2`…). A codec or method missing here uses its own default.
    pub levels: BTreeMap<String, i32>,
    pub stream: StreamConfig,
    pub limits: LimitsConfig,
    pub mcp: McpConfig,
    pub shell: ShellConfig,
    pub jobs: JobsConfig,
    pub desktop: DesktopConfig,
    pub seven_zip: SevenZipConfig,
    pub updates: UpdatesConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct McpConfig {
    /// Directories `beezip mcp` may write under, when no `--root` is given.
    pub roots: Vec<PathBuf>,
    /// Refuse every command that writes, as `--read-only` does.
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct ExtractConfig {
    /// What to do when a file being extracted already exists.
    pub overwrite: OverwritePolicy,
    /// Create the symbolic and hard links an archive holds. Off, they are skipped.
    pub links: bool,
    /// Whether extracted files keep the archive's "downloaded from the internet" mark.
    pub mark_of_the_web: MarkOfTheWeb,
    /// Threads for extracting zips and decoding xz. `0` is one per core; `1` uses one.
    pub threads: u32,
}

/// Changing archives in place (docs/M5.md §7).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct EditConfig {
    /// What to do when a file being added has the path of an entry already in the archive.
    pub overwrite: OverwritePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum MarkOfTheWeb {
    /// Copy the archive's `Zone.Identifier` to every extracted file, as Explorer does; on macOS
    /// its `com.apple.quarantine`, as Archive Utility does. Linux has no such mark.
    #[default]
    All,
    None,
}

/// How names stored as bytes are read: zip names without the UTF-8 flag, tar names outside pax
/// records, cpio, ar, LHA, ARJ, ACE, ZOO, ARC and squashfs names, CAB names without the UTF-8
/// flag, ISO names outside Joliet (docs/M5.md §6), FAT's short names, ext names, and MSI names in
/// code page 0 (docs/M7.md).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct NamesConfig {
    /// The encoding archives' names are read in, unless a command is given one. `auto` reads
    /// UTF-8 when a name is valid UTF-8, otherwise the system's code page.
    pub encoding: NameEncoding,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct CreateConfig {
    /// Threads for compressing. `0` is one per core.
    pub threads: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct StreamConfig {
    /// The codec `beezip compress` uses when none is given.
    pub codec: CodecName,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            codec: CodecName::Zstd,
        }
    }
}

/// Limits that stop zip bombs and runaway archives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct LimitsConfig {
    /// The most an archive may expand, as unpacked size over packed size.
    pub max_ratio: u64,
    /// The most entries an archive may hold.
    pub max_entries: u64,
    /// The most memory one decoder may use, in MiB.
    pub decoder_memory_mib: u64,
    /// The most bytes one job may unpack in all. None is unlimited.
    pub max_total_bytes: Option<u64>,
}

/// Explorer's right-click menu (docs/M4.md §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct ShellConfig {
    /// Show the items in a "BeeZip" submenu. Off, each is at the top level. Windows 11's own
    /// menu always shows a submenu; this is for the classic menu.
    pub cascade: bool,
    pub items: ShellItems,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            cascade: true,
            items: ShellItems::default(),
        }
    }
}

/// Which menu items Explorer shows. Every one is shown unless set to false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default, rename_all = "kebab-case")]
#[allow(clippy::struct_excessive_bools)]
pub struct ShellItems {
    /// "Open with BeeZip".
    pub open: bool,
    /// "Extract here".
    pub extract_here: bool,
    /// "Extract to "a\"".
    pub extract_folder: bool,
    /// "Extract to…".
    pub extract_to: bool,
    /// "Test archive".
    pub test: bool,
    /// "Add to "a.zip"".
    pub add_zip: bool,
    /// "Add to "a.7z"".
    pub add_7z: bool,
    /// "Add to "a.tar.zst"".
    pub add_tar_zst: bool,
    /// "Compress to…".
    pub compress_to: bool,
}

impl ShellItems {
    /// Whether `item` is shown.
    pub fn shows(&self, item: beezip_menu::Item) -> bool {
        use beezip_menu::Item;
        match item {
            Item::Open => self.open,
            Item::ExtractHere => self.extract_here,
            Item::ExtractFolder => self.extract_folder,
            Item::ExtractTo => self.extract_to,
            Item::Test => self.test,
            Item::AddZip => self.add_zip,
            Item::Add7z => self.add_7z,
            Item::AddTarZst => self.add_tar_zst,
            Item::CompressTo => self.compress_to,
        }
    }

    /// The items left out, in menu order: what the DLL reads as `Hidden`.
    pub fn hidden(&self) -> Vec<beezip_menu::Item> {
        beezip_menu::Item::ALL
            .into_iter()
            .filter(|i| !self.shows(*i))
            .collect()
    }
}

impl Default for ShellItems {
    fn default() -> Self {
        Self {
            open: true,
            extract_here: true,
            extract_folder: true,
            extract_to: true,
            test: true,
            add_zip: true,
            add_7z: true,
            add_tar_zst: true,
            compress_to: true,
        }
    }
}

/// The job windows Explorer's menu opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct JobsConfig {
    /// A job window closes itself after a clean success.
    pub close_when_done: bool,
}

impl Default for JobsConfig {
    fn default() -> Self {
        Self {
            close_when_done: true,
        }
    }
}

/// The installed 7-Zip, which reads CHM files, NSIS installers and CramFS for BeeZip (docs/M6.md
/// §3), and MSI patches and what BeeZip's own disk, MSI and WIM readers don't support
/// (docs/M7.md, docs/M8.md): an ESD on Linux and macOS, for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct SevenZipConfig {
    /// The 7-Zip console program to run (`7z.exe`, 25.01 or newer). Empty: BeeZip finds one in
    /// the registry, on PATH or in Program Files.
    pub path: Option<PathBuf>,
    /// Read those formats through 7-Zip. Off, they are still recognised, and opening one says
    /// that 7-Zip is turned off.
    pub enabled: bool,
}

impl Default for SevenZipConfig {
    fn default() -> Self {
        Self {
            path: None,
            enabled: true,
        }
    }
}

impl SevenZipConfig {
    /// As core takes it: an empty path means "find one".
    pub fn options(&self) -> beezip_core::SevenZipOptions {
        beezip_core::SevenZipOptions {
            path: self.path.clone().filter(|p| !p.as_os_str().is_empty()),
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct DesktopConfig {
    /// Light or dark, or as Windows is set.
    pub theme: Theme,
}

/// The desktop app's updates (docs/M6.md §8.2). The CLI and MCP never check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(default)]
pub struct UpdatesConfig {
    /// Look for a new release on GitHub when BeeZip starts, at most once a day. An update is
    /// only downloaded and installed when you click it.
    pub check: bool,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self { check: true }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum Theme {
    /// Follow Windows' light or dark mode.
    #[default]
    System,
    Light,
    Dark,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        let l = Limits::default();
        Self {
            max_ratio: l.max_ratio.unwrap_or(10_000),
            max_entries: l.max_entries.unwrap_or(10_000_000),
            decoder_memory_mib: l.decoder_memory / MIB,
            max_total_bytes: l.max_total_bytes,
        }
    }
}

impl Config {
    pub fn limits(&self) -> Limits {
        Limits {
            max_ratio: Some(self.limits.max_ratio),
            max_entries: Some(self.limits.max_entries),
            decoder_memory: self.limits.decoder_memory_mib.saturating_mul(MIB),
            max_total_bytes: self.limits.max_total_bytes,
            ..Limits::default()
        }
    }

    /// The configured default level for a codec or zip method, if any.
    pub fn level(&self, name: &str) -> Option<i32> {
        self.levels.get(name).copied()
    }

    /// Parses config text. Returns the config (or why it can't be used) and warnings about
    /// keys BeeZip doesn't know.
    pub fn parse(text: &str, origin: &Path) -> (Result<Self, CmdError>, Vec<String>) {
        let table: toml::Table = match toml::from_str(text) {
            Ok(t) => t,
            Err(e) => {
                let err = CmdError::invalid_args(format!("{}: {e}", origin.display()));
                return (Err(err), Vec::new());
            }
        };
        let warnings = unknown_keys(&table)
            .into_iter()
            .map(|k| format!("{}: unknown key `{k}` ignored", origin.display()))
            .collect();
        let config = toml::from_str::<Self>(text)
            .map_err(|e| CmdError::invalid_args(format!("{}: {e}", origin.display())));
        (config, warnings)
    }
}

/// Sections that are maps rather than fixed keys: `[levels]` takes any codec or method name.
pub const MAP_SECTIONS: &[&str] = &["levels"];

/// Every setting by dotted key (`extract.overwrite`, `shell.items.test`, `levels.zstd`), with
/// its value as JSON. `None` values (`limits.max_total_bytes` unset) are JSON null.
pub fn flatten(config: &Config) -> BTreeMap<String, Value> {
    fn walk(prefix: &str, value: Value, out: &mut BTreeMap<String, Value>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    walk(&format!("{prefix}{k}."), v, out);
                }
            }
            leaf => {
                out.insert(prefix.trim_end_matches('.').to_owned(), leaf);
            }
        }
    }
    let mut out = BTreeMap::new();
    // Plain structs, maps and enums: serialising them can't fail.
    walk(
        "",
        serde_json::to_value(config).unwrap_or(Value::Null),
        &mut out,
    );
    out
}

/// The fixed keys, dotted and sorted: every key but the entries of [`MAP_SECTIONS`].
pub fn known_keys() -> Vec<String> {
    flatten(&Config::default()).into_keys().collect()
}

fn unknown_keys(table: &toml::Table) -> Vec<String> {
    let known = known_keys();
    let mut out = Vec::new();
    walk_unknown("", table, &known, &mut out);
    out
}

fn walk_unknown(prefix: &str, table: &toml::Table, known: &[String], out: &mut Vec<String>) {
    for (key, value) in table {
        let path = format!("{prefix}{key}");
        if MAP_SECTIONS.contains(&path.as_str()) || known.contains(&path) {
            continue;
        }
        let section = format!("{path}.");
        if !known.iter().any(|k| k.starts_with(&section)) {
            out.push(path);
        } else if let Some(t) = value.as_table() {
            walk_unknown(&section, t, known, out);
        }
        // A section given a plain value is a type error, which parsing reports.
    }
}

/// Where the config lives: `BEEZIP_CONFIG`, else `<config dir>/BeeZip/config.toml`.
pub fn config_path() -> Option<PathBuf> {
    match std::env::var_os("BEEZIP_CONFIG") {
        Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => dirs::config_dir().map(|d| d.join("BeeZip").join("config.toml")),
    }
}

/// The config as the front ends load it when the process starts.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Result<Config, CmdError>,
    pub path: Option<PathBuf>,
    /// Whether the file exists. Without it, every setting has its default.
    pub exists: bool,
    pub warnings: Vec<String>,
}

impl Default for LoadedConfig {
    fn default() -> Self {
        Self {
            config: Ok(Config::default()),
            path: None,
            exists: false,
            warnings: Vec::new(),
        }
    }
}

/// Reads the config. A missing file is the defaults.
pub fn load() -> LoadedConfig {
    match config_path() {
        Some(path) => load_from(&path),
        None => LoadedConfig::default(),
    }
}

/// Reads the config at `path`. A missing file is the defaults.
pub fn load_from(path: &Path) -> LoadedConfig {
    let loaded = LoadedConfig {
        path: Some(path.to_path_buf()),
        ..LoadedConfig::default()
    };
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let (config, warnings) = Config::parse(&text, path);
            LoadedConfig {
                config,
                exists: true,
                warnings,
                ..loaded
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => loaded,
        Err(e) => LoadedConfig {
            config: Err(CmdError::invalid_args(format!(
                "could not read {}: {e}",
                path.display()
            ))),
            exists: true,
            ..loaded
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> (Result<Config, CmdError>, Vec<String>) {
        Config::parse(text, Path::new("config.toml"))
    }

    #[test]
    fn empty_is_defaults() {
        let (c, w) = parse("");
        assert_eq!(c.unwrap(), Config::default());
        assert!(w.is_empty());
        assert_eq!(Config::default().limits(), Limits::default());
    }

    #[test]
    fn the_documented_example_parses() {
        let text = r#"
[extract]
overwrite = "rename"
links = true
mark_of_the_web = "none"

[names]
encoding = "cp932"

[create]
threads = 4

[levels]
zstd = 19
deflate = 9

[stream]
codec = "gzip"

[limits]
max_ratio = 500
max_entries = 1000
decoder_memory_mib = 256

[mcp]
roots = ['C:\work', '/srv/drop']
read_only = true

[shell]
cascade = false
[shell.items]
test = false
add-tar-zst = false

[jobs]
close_when_done = false

[desktop]
theme = "dark"

[updates]
check = false
"#;
        let (c, w) = parse(text);
        let c = c.unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert!(!c.shell.cascade);
        assert!(!c.shell.items.test && !c.shell.items.add_tar_zst && c.shell.items.open);
        assert!(!c.jobs.close_when_done);
        assert_eq!(c.desktop.theme, Theme::Dark);
        assert!(!c.updates.check);
        assert_eq!(
            c.mcp.roots,
            [PathBuf::from(r"C:\work"), PathBuf::from("/srv/drop")]
        );
        assert!(c.mcp.read_only);
        assert_eq!(c.extract.overwrite, OverwritePolicy::Rename);
        assert!(c.extract.links);
        assert_eq!(c.extract.mark_of_the_web, MarkOfTheWeb::None);
        assert_eq!(c.create.threads, 4);
        assert_eq!(c.names.encoding, NameEncoding::Cp932);
        assert_eq!(c.level("zstd"), Some(19));
        assert_eq!(c.stream.codec, CodecName::Gzip);
        assert_eq!(c.limits().decoder_memory, 256 * MIB);
        assert_eq!(c.limits().max_ratio, Some(500));
    }

    #[test]
    fn unknown_keys_warn() {
        let (c, w) = parse("[extract]\nlinks = true\ncolour = 1\n[telemetry]\non = 1\n");
        assert!(c.is_ok());
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("extract.colour"), "{w:?}");

        let (c, w) = parse(
            "shell.flat = 1\n[shell.items]\ntest = false\nbogus = true\n[levels]\nanything = 3\n",
        );
        assert!(c.is_ok());
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("`shell.flat`"), "{w:?}");
        assert!(w[1].contains("`shell.items.bogus`"), "{w:?}");
        let (_, w) = parse("extract = 3\n");
        assert!(
            w.is_empty(),
            "a wrong type is an error, not a warning: {w:?}"
        );
    }

    #[test]
    fn keys_are_dotted_and_complete() {
        let keys = known_keys();
        for k in [
            "extract.overwrite",
            "limits.max_total_bytes",
            "mcp.roots",
            "shell.cascade",
            "shell.items.extract-here",
            "shell.items.add-7z",
            "jobs.close_when_done",
            "desktop.theme",
            "names.encoding",
            "updates.check",
        ] {
            assert!(keys.iter().any(|x| x == k), "{k} in {keys:?}");
        }
        assert!(!keys.iter().any(|k| k.starts_with("levels")), "{keys:?}");
        let mut c = Config::default();
        c.levels.insert("zstd".into(), 19);
        let flat = flatten(&c);
        assert_eq!(flat["levels.zstd"], 19);
        assert_eq!(flat["limits.max_total_bytes"], Value::Null);
        assert_eq!(flat["desktop.theme"], "system");
        assert_eq!(flat["names.encoding"], "auto");
        assert_eq!(flat["shell.items.test"], true);
        assert_eq!(flat["updates.check"], true);
    }

    #[test]
    fn shell_items_are_the_menus_items() {
        let mut keys: Vec<String> = known_keys()
            .into_iter()
            .filter_map(|k| k.strip_prefix("shell.items.").map(str::to_owned))
            .collect();
        let mut ids: Vec<String> = beezip_menu::Item::ALL
            .iter()
            .map(|i| i.id().to_owned())
            .collect();
        keys.sort();
        ids.sort();
        assert_eq!(keys, ids);
    }

    #[test]
    fn wrong_types_fail_with_the_line() {
        let (c, _) = parse("[extract]\n\nlinks = \"yes\"\n");
        let err = c.unwrap_err();
        assert_eq!(err.code, crate::ErrorCode::InvalidArgs);
        assert!(err.message.contains("line 3"), "{}", err.message);
    }
}
