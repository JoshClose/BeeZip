//! `settings.get`: every setting with its effective value, read from `config.toml` each time
//! (docs/M4.md §7.1).

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx, Surfaces,
    config::{self, Config, LoadedConfig},
};

/// Show every setting with its effective value: what config.toml sets, or the default.
///
/// The file is read each time, so edits made elsewhere show. Keys BeeZip doesn't know come
/// back in `warnings`; a file it can't use comes back as `error`, with the defaults.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct SettingsGetInput {}

/// The settings, and the file they live in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SettingsGetOutput {
    /// The settings file, or none on a system with no config folder.
    pub path: Option<PathBuf>,
    /// Whether the file exists. Without it, every setting has its default.
    pub exists: bool,
    /// Every setting, with its effective value.
    pub settings: Config,
    /// Keys BeeZip doesn't know, which it ignores.
    pub warnings: Vec<String>,
    /// Why the file can't be used, if it can't. `settings` then shows the defaults, and the
    /// commands that need the config fail until it's fixed.
    pub error: Option<String>,
}

pub struct SettingsGet;

impl Command for SettingsGet {
    const NAME: &'static str = "settings.get";
    const EFFECT: Effect = Effect::ReadOnly;
    // Hidden with `settings.set`, which could widen an assistant's own sandbox (docs/M4.md §14).
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "get",
        aliases: &[],
        group: Some("settings"),
    });

    type Input = SettingsGetInput;
    type Output = SettingsGetOutput;

    fn run(_: SettingsGetInput, cx: &mut JobCtx) -> Result<SettingsGetOutput, CmdError> {
        Ok(current(cx.config_path().as_deref()))
    }

    fn human(out: &SettingsGetOutput) -> Option<String> {
        Some(table(out))
    }

    fn access(_: &SettingsGetInput) -> Vec<Access> {
        config::config_path()
            .map(Access::Read)
            .into_iter()
            .collect()
    }
}

/// The settings in `path` as `settings.get` reports them.
pub(crate) fn current(path: Option<&Path>) -> SettingsGetOutput {
    let loaded = path.map_or_else(LoadedConfig::default, config::load_from);
    let (settings, error) = match loaded.config {
        Ok(c) => (c, None),
        Err(e) => (Config::default(), Some(e.message)),
    };
    SettingsGetOutput {
        path: loaded.path,
        exists: loaded.exists,
        settings,
        warnings: loaded.warnings,
        error,
    }
}

/// The path, then one `key  value` line per setting.
fn table(out: &SettingsGetOutput) -> String {
    let mut s = match &out.path {
        Some(p) if out.exists => p.display().to_string(),
        Some(p) => format!("{} (no file yet: these are the defaults)", p.display()),
        None => "no config folder on this system: these are the defaults".to_owned(),
    };
    if let Some(e) = &out.error {
        s.push_str(&format!(
            "\nthe file can't be used, so these are the defaults: {e}"
        ));
    }
    s.push('\n');
    let flat = config::flatten(&out.settings);
    let width = flat.keys().map(String::len).max().unwrap_or(0);
    for (k, v) in &flat {
        s.push_str(&format!("\n{k:width$}  {}", shown(v)));
    }
    if out.settings.levels.is_empty() {
        s.push_str(&format!("\n{:width$}  each codec's own", "levels.*"));
    }
    s
}

fn shown(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "none".to_owned(),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(shown).collect::<Vec<_>>().join(", ")
        ),
        v => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<SettingsGetInput>(
            &[],
            serde_json::json!({}),
        );
    }

    #[test]
    fn a_missing_file_is_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let out = current(Some(&path));
        assert!(!out.exists);
        assert_eq!(out.settings, Config::default());
        let text = table(&out);
        assert!(text.contains("no file yet"), "{text}");
        assert!(text.contains("\nextract.overwrite "), "{text}");
        assert!(text.contains("limits.max_total_bytes"), "{text}");
    }

    #[test]
    fn a_bad_file_is_the_defaults_and_its_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[extract]\nlinks = \"yes\"\n[nope]\n").unwrap();
        let out = current(Some(&path));
        assert!(out.exists);
        assert_eq!(out.settings, Config::default());
        assert!(out.error.as_deref().unwrap().contains("line 2"), "{out:?}");
        assert_eq!(out.warnings.len(), 1, "{out:?}");
    }
}
