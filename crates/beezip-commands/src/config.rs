//! `config.toml` (docs/M1.md §4.1): `%APPDATA%\BeeZip\config.toml`, or the file `BEEZIP_CONFIG`
//! names. A missing file means defaults and unknown keys only warn; a value of the wrong type
//! fails every command that needs the config, with `InvalidArgs` and the TOML line number.
//!
//! ```toml
//! [extract]
//! overwrite = "ask"          # ask | always | never | rename | newer
//! links = false
//! mark_of_the_web = "all"    # all | none
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
//! ```

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use beezip_core::{Limits, limits::MIB};
use serde::Deserialize;

use crate::{
    CmdError,
    wire::{CodecName, OverwritePolicy},
};

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub extract: ExtractConfig,
    pub create: CreateConfig,
    /// Default levels by codec name (`zstd`, `gzip`…) or zip method (`deflate`, `ppmd`…).
    pub levels: BTreeMap<String, i32>,
    pub stream: StreamConfig,
    pub limits: LimitsConfig,
    pub mcp: McpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// Directories `beezip mcp` may write under, when no `--root` is given.
    pub roots: Vec<PathBuf>,
    /// Refuse every command that writes, as `--read-only` does.
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct ExtractConfig {
    pub overwrite: OverwritePolicy,
    pub links: bool,
    pub mark_of_the_web: MarkOfTheWeb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkOfTheWeb {
    /// Copy the archive's `Zone.Identifier` to every extracted file, as Explorer does.
    #[default]
    All,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct CreateConfig {
    /// `0` is one per core.
    pub threads: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct StreamConfig {
    pub codec: CodecName,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            codec: CodecName::Zstd,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_ratio: u64,
    pub max_entries: u64,
    pub decoder_memory_mib: u64,
    pub max_total_bytes: Option<u64>,
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

const KNOWN: &[(&str, &[&str])] = &[
    ("extract", &["overwrite", "links", "mark_of_the_web"]),
    ("create", &["threads"]),
    ("levels", &[]),
    ("stream", &["codec"]),
    (
        "limits",
        &[
            "max_ratio",
            "max_entries",
            "decoder_memory_mib",
            "max_total_bytes",
        ],
    ),
    ("mcp", &["roots", "read_only"]),
];

fn unknown_keys(table: &toml::Table) -> Vec<String> {
    let mut out = Vec::new();
    for (section, value) in table {
        let Some((_, keys)) = KNOWN.iter().find(|(s, _)| s == section) else {
            out.push(section.clone());
            continue;
        };
        // `[levels]` takes any codec or method name.
        if section == "levels" {
            continue;
        }
        if let Some(t) = value.as_table() {
            out.extend(
                t.keys()
                    .filter(|k| !keys.contains(&k.as_str()))
                    .map(|k| format!("{section}.{k}")),
            );
        }
    }
    out
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
    pub warnings: Vec<String>,
}

impl Default for LoadedConfig {
    fn default() -> Self {
        Self {
            config: Ok(Config::default()),
            path: None,
            warnings: Vec::new(),
        }
    }
}

/// Reads the config. A missing file is the defaults.
pub fn load() -> LoadedConfig {
    let Some(path) = config_path() else {
        return LoadedConfig::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let (config, warnings) = Config::parse(&text, &path);
            LoadedConfig {
                config,
                path: Some(path),
                warnings,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LoadedConfig {
            path: Some(path),
            ..LoadedConfig::default()
        },
        Err(e) => LoadedConfig {
            config: Err(CmdError::invalid_args(format!(
                "could not read {}: {e}",
                path.display()
            ))),
            path: Some(path),
            warnings: Vec::new(),
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
"#;
        let (c, w) = parse(text);
        let c = c.unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            c.mcp.roots,
            [PathBuf::from(r"C:\work"), PathBuf::from("/srv/drop")]
        );
        assert!(c.mcp.read_only);
        assert_eq!(c.extract.overwrite, OverwritePolicy::Rename);
        assert!(c.extract.links);
        assert_eq!(c.extract.mark_of_the_web, MarkOfTheWeb::None);
        assert_eq!(c.create.threads, 4);
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
    }

    #[test]
    fn wrong_types_fail_with_the_line() {
        let (c, _) = parse("[extract]\n\nlinks = \"yes\"\n");
        let err = c.unwrap_err();
        assert_eq!(err.code, crate::ErrorCode::InvalidArgs);
        assert!(err.message.contains("line 3"), "{}", err.message);
    }
}
