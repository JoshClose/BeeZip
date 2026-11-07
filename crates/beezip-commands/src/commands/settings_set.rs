//! `settings.set`: edits `config.toml` in place, keeping its comments, order and layout
//! (docs/M4.md §7.1).
//!
//! The edits go into a `toml_edit` document of the current file. The whole result is parsed
//! again as a [`Config`] before anything is written, so a wrong type writes nothing. The file
//! is replaced through a partial file and a rename, and the engine's later jobs get the new
//! config (§7.3).

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write as _,
    path::Path,
    sync::{Mutex, PoisonError},
};

use clap::{Arg, ArgAction, ArgMatches, ValueEnum};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::{DocumentMut, Item, TableLike};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx, Surfaces,
    commands::{settings_get::SettingsGetOutput, util},
    config::{self, Config, MAP_SECTIONS},
    wire::{CodecName, MethodName},
};

/// Change settings in config.toml, keeping its comments and layout. The file is created if
/// it doesn't exist.
///
/// Keys are dotted, such as `extract.overwrite`, `shell.items.test` or `levels.zstd` (any
/// codec or method); `beezip settings get` lists them. Nothing is written unless the whole
/// file still reads: an unknown key or a value of the wrong type fails with `InvalidArgs`.
/// The app's later jobs use the new settings at once; other BeeZip processes read them when
/// they start.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct SettingsSetInput {
    /// The settings to change, by dotted key: `{"extract.overwrite": "rename",
    /// "levels.zstd": 19}`. On the command line, `KEY=VALUE`, with VALUE as TOML (`19`,
    /// `false`, `['C:\a']`); a bare word is a string. null resets the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(type = "Record<string, unknown>")]
    pub set: Option<BTreeMap<String, Value>>,
    /// Settings to put back to their defaults, by dotted key. Each is removed from the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset: Option<Vec<String>>,
}

/// The settings after the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SettingsSetOutput {
    #[serde(flatten)]
    pub current: SettingsGetOutput,
    /// The keys whose effective value changed.
    pub changed: Vec<String>,
}

pub struct SettingsSet;

impl Command for SettingsSet {
    const NAME: &'static str = "settings.set";
    const EFFECT: Effect = Effect::Writes;
    // An assistant that could set `[mcp] roots` could widen its own sandbox (docs/M4.md §14).
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "set",
        aliases: &[],
        group: Some("settings"),
    });

    type Input = SettingsSetInput;
    type Output = SettingsSetOutput;

    fn run(input: SettingsSetInput, cx: &mut JobCtx) -> Result<SettingsSetOutput, CmdError> {
        let path = cx.config_path().ok_or_else(|| {
            CmdError::new(
                ErrorCode::UnsupportedOperation,
                "this system has no config folder; set BEEZIP_CONFIG to a file",
            )
        })?;
        // `access()` can only name the default file; this is the one the engine reads.
        cx.policy()
            .check(Self::NAME, Self::EFFECT, &[Access::Write(path.clone())])?;
        let edits = edits(input)?;
        let new = {
            // One edit at a time, so two quick changes from the app can't lose one.
            static WRITING: Mutex<()> = Mutex::new(());
            let _guard = WRITING.lock().unwrap_or_else(PoisonError::into_inner);
            apply(&path, &edits)?
        };
        let changed = changed(&new.before, &new.after.settings);
        cx.replace_config(new.after.settings.clone());
        let mut current = new.after;
        // The installed menu reads `[shell]` from the registry (docs/M4.md §5.4). The file is
        // written by now, so a failure here is a warning rather than an error.
        if changed.iter().any(|k| k.starts_with("shell."))
            && let Err(e) = crate::shell::follow(cx.shell_hive(), &current.settings.shell)
        {
            current.warnings.push(format!(
                "Explorer's menu didn't take the change: {}",
                e.message
            ));
        }
        Ok(SettingsSetOutput { current, changed })
    }

    fn human(out: &SettingsSetOutput) -> Option<String> {
        let path = out
            .current
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        Some(if out.changed.is_empty() {
            format!("Nothing changed in {path}")
        } else {
            format!("Changed {} in {path}", out.changed.join(", "))
        })
    }

    fn access(_: &SettingsSetInput) -> Vec<Access> {
        config::config_path()
            .map(Access::Write)
            .into_iter()
            .collect()
    }
}

/// The line a missing file starts with.
const HEADER: &str = "# BeeZip's settings: `beezip settings get` lists them all, \
                      and `beezip settings set` changes them.\n";

/// One key to set, or to remove (`None`).
type Edit = (String, Option<toml_edit::Value>);

/// The input as checked edits, in order: the sets, then the resets.
fn edits(input: SettingsSetInput) -> Result<Vec<Edit>, CmdError> {
    let known = config::known_keys();
    let mut out = Vec::new();
    for (key, value) in input.set.unwrap_or_default() {
        check_key(&key, &known)?;
        let value = match value {
            Value::Null => None,
            v => Some(to_toml(&v).map_err(|e| {
                CmdError::invalid_args(format!("`{key}` can't be set to {v}: {e}"))
            })?),
        };
        out.push((key, value));
    }
    for key in input.reset.unwrap_or_default() {
        check_key(&key, &known)?;
        out.push((key, None));
    }
    Ok(out)
}

/// The names `levels.<name>` takes: every codec and every zip and 7z method.
fn level_names() -> BTreeSet<String> {
    fn names<T: ValueEnum + 'static>() -> impl Iterator<Item = String> {
        T::value_variants()
            .iter()
            .filter_map(|v| v.to_possible_value().map(|p| p.get_name().to_owned()))
    }
    names::<CodecName>().chain(names::<MethodName>()).collect()
}

fn check_key(key: &str, known: &[String]) -> Result<(), CmdError> {
    if known.iter().any(|k| k == key) {
        return Ok(());
    }
    let levels = level_names();
    let (section, _) = key.rsplit_once('.').unwrap_or(("", key));
    if MAP_SECTIONS.contains(&section) {
        let name = &key[section.len() + 1..];
        if levels.contains(name) {
            return Ok(());
        }
        let names = levels.into_iter().collect::<Vec<_>>().join(", ");
        return Err(CmdError::invalid_args(format!(
            "`{name}` isn't a codec or method; `{section}.NAME` takes one of {names}"
        ))
        .with_details(serde_json::json!({ "key": key })));
    }
    // The keys beside it, so a typo shows its neighbours.
    let prefix = format!("{section}.");
    let siblings: Vec<&str> = known
        .iter()
        .filter_map(|k| k.strip_prefix(&prefix))
        .collect();
    let hint = if section.is_empty() || siblings.is_empty() {
        "`beezip settings get` lists them all".to_owned()
    } else {
        format!("`[{section}]` has {}", siblings.join(", "))
    };
    Err(
        CmdError::invalid_args(format!("`{key}` isn't a setting; {hint}"))
            .with_details(serde_json::json!({ "key": key })),
    )
}

/// The file before and after the edits.
struct Applied {
    before: Config,
    after: SettingsGetOutput,
}

fn apply(path: &Path, edits: &[Edit]) -> Result<Applied, CmdError> {
    let (old_text, exists) = match std::fs::read_to_string(path) {
        Ok(t) => (t, true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(e) => {
            return Err(CmdError::new(
                ErrorCode::Io,
                format!("could not read {}: {e}", path.display()),
            ));
        }
    };
    let mut doc: DocumentMut = old_text.parse().map_err(|e| {
        CmdError::invalid_args(format!(
            "{} isn't valid TOML, so it can't be edited; fix it first: {e}",
            path.display()
        ))
    })?;
    for (key, value) in edits {
        edit(&mut doc, key, value.clone())?;
    }
    let mut text = doc.to_string();
    if !exists && !text.is_empty() {
        text.insert_str(0, HEADER);
    }

    let (parsed, warnings) = Config::parse(&text, path);
    let old = Config::parse(&old_text, path).0;
    let Ok(after) = parsed else {
        return Err(refused(&text, edits, old.is_ok()));
    };
    let before = old.unwrap_or_default();

    if text != old_text {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| {
                CmdError::new(
                    ErrorCode::Io,
                    format!("could not create {}: {e}", dir.display()),
                )
            })?;
        }
        util::write_atomically(path, |f| {
            f.write_all(text.as_bytes()).map_err(|e| {
                CmdError::new(
                    ErrorCode::Io,
                    format!("could not write {}: {e}", path.display()),
                )
            })
        })?;
    }
    Ok(Applied {
        before,
        after: SettingsGetOutput {
            path: Some(path.to_path_buf()),
            exists: exists || text != old_text,
            settings: after,
            warnings,
            error: None,
        },
    })
}

/// Why the edited file doesn't read, short enough to show beside a field: the edit's key and
/// the parser's message, without the file's path or the parser's snippet (those are for
/// `settings get`). If the file was already broken, that's the error to fix first.
fn refused(text: &str, edits: &[Edit], was_ok: bool) -> CmdError {
    let (message, line) = match toml::from_str::<Config>(text) {
        Err(e) => {
            let line = e
                .span()
                .map(|s| text[..s.start.min(text.len())].matches('\n').count() + 1);
            (e.message().to_owned(), line)
        }
        // `Config::parse` refused it, so this can't happen; say something true anyway.
        Ok(_) => ("the settings don't read".to_owned(), None),
    };
    let at = line.map(|l| format!(" (line {l})")).unwrap_or_default();
    let text = match edits {
        _ if !was_ok => {
            format!("config.toml has an error to fix first{at}: {message}. Nothing was written.")
        }
        [(key, Some(value))] => format!(
            "`{key}` can't be {}: {message}. Nothing was written.",
            value.to_string().trim()
        ),
        _ => format!("{message}{at}. Nothing was written."),
    };
    let keys: Vec<&str> = edits.iter().map(|(k, _)| k.as_str()).collect();
    CmdError::invalid_args(text).with_details(serde_json::json!({ "keys": keys, "line": line }))
}

/// Sets `key` (dotted) to `value`, or removes it. A value that replaces another keeps the
/// old one's comment and spacing; a new section is implicit, so `[shell.items]` comes
/// without an empty `[shell]` before it.
fn edit(doc: &mut DocumentMut, key: &str, value: Option<toml_edit::Value>) -> Result<(), CmdError> {
    let parts: Vec<&str> = key.split('.').collect();
    let Some((leaf, sections)) = parts.split_last() else {
        return Ok(());
    };
    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for (i, section) in sections.iter().enumerate() {
        if !table.contains_key(section) {
            if value.is_none() {
                return Ok(());
            }
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            table.insert(section, Item::Table(t));
        }
        table = table
            .get_mut(section)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| {
                CmdError::invalid_args(format!(
                    "`{}` in config.toml isn't a table, so `{key}` can't be set; fix or remove it",
                    parts[..=i].join(".")
                ))
            })?;
    }
    match value {
        None => {
            table.remove(leaf);
        }
        Some(new) => match table.get_mut(leaf) {
            Some(Item::Value(old)) => {
                let decor = old.decor().clone();
                *old = new;
                *old.decor_mut() = decor;
            }
            _ => {
                table.insert(leaf, Item::Value(new));
            }
        },
    }
    Ok(())
}

/// A JSON value as TOML. TOML has no null, and its integers are 64-bit signed.
fn to_toml(v: &Value) -> Result<toml_edit::Value, String> {
    Ok(match v {
        Value::Bool(b) => (*b).into(),
        Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => i.into(),
            (None, Some(_)) if n.is_u64() => return Err("too large for TOML".into()),
            (None, Some(f)) => f.into(),
            (None, None) => return Err("not a TOML number".into()),
        },
        Value::String(s) => s.as_str().into(),
        Value::Array(items) => {
            let mut array = toml_edit::Array::new();
            for item in items {
                array.push(to_toml(item)?);
            }
            toml_edit::Value::Array(array)
        }
        Value::Object(map) => {
            let mut table = toml_edit::InlineTable::new();
            for (k, item) in map {
                table.insert(k.as_str(), to_toml(item)?);
            }
            toml_edit::Value::InlineTable(table)
        }
        Value::Null => return Err("TOML has no null".into()),
    })
}

fn to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(items) => Value::Array(items.iter().map(to_json).collect()),
        toml::Value::Table(t) => {
            Value::Object(t.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
    }
}

/// A command line's VALUE: TOML, or a string when it isn't TOML (`rename`, `C:\work`).
pub(crate) fn value_from_cli(text: &str) -> Value {
    match toml::from_str::<toml::Table>(&format!("v = {text}")) {
        Ok(t) if t.len() == 1 => t.get("v").map_or(Value::Null, to_json),
        _ => Value::String(text.to_owned()),
    }
}

/// The VALUE that [`value_from_cli`] reads back as `v`: a string stays bare unless it would
/// read as something else. `None` for null, which a command line writes as `--reset`.
pub(crate) fn value_for_cli(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) if value_from_cli(s) == *v => Some(s.clone()),
        v => to_toml(v).ok().map(|t| t.to_string().trim().to_owned()),
    }
}

/// The keys whose value differs between the two.
fn changed(before: &Config, after: &Config) -> Vec<String> {
    let (a, b) = (config::flatten(before), config::flatten(after));
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    keys.into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect()
}

#[derive(Debug, Clone)]
struct Assignment(String, Value);

fn parse_assignment(s: &str) -> Result<Assignment, String> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| format!("`{s}` isn't KEY=VALUE"))?;
    let key = key.trim();
    if key.is_empty() {
        return Err(format!("`{s}` has no key"));
    }
    Ok(Assignment(key.to_owned(), value_from_cli(value)))
}

// By hand, not derived: the command line's `KEY=VALUE` words become the JSON's `set` object.
impl clap::FromArgMatches for SettingsSetInput {
    fn from_arg_matches(m: &ArgMatches) -> Result<Self, clap::Error> {
        let set: BTreeMap<String, Value> = m
            .get_many::<Assignment>("set")
            .into_iter()
            .flatten()
            .map(|Assignment(k, v)| (k.clone(), v.clone()))
            .collect();
        let reset: Vec<String> = m
            .get_many::<String>("reset")
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        Ok(Self {
            set: (!set.is_empty()).then_some(set),
            reset: (!reset.is_empty()).then_some(reset),
        })
    }

    fn update_from_arg_matches(&mut self, m: &ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(m)?;
        Ok(())
    }
}

impl clap::Args for SettingsSetInput {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        cmd.arg(
            Arg::new("set")
                .value_name("KEY=VALUE")
                .num_args(0..)
                .action(ArgAction::Append)
                .value_parser(parse_assignment)
                .help(
                    "Settings to change: VALUE is TOML (19, false, ['C:\\a']), \
                     or a bare word for a string",
                ),
        )
        .arg(
            Arg::new("reset")
                .long("reset")
                .value_name("KEY")
                .action(ArgAction::Append)
                .help("Put a setting back to its default; repeatable"),
        )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::{Engine, EngineOptions, NonInteractive, Policy, discard_events, registry};

    fn engine(path: &Path) -> Engine {
        let loaded = config::load_from(path);
        Engine::with_options(
            registry(),
            EngineOptions {
                // Never the real menu, which a developer may have installed.
                shell: crate::shell::Hive::test("settings"),
                ..EngineOptions::from_loaded(loaded, Policy::unrestricted())
            },
        )
    }

    fn run(engine: &Engine, name: &str, args: Value) -> Result<Value, CmdError> {
        engine
            .invoke(name, args, Arc::new(NonInteractive), discard_events())
            .unwrap()
            .join()
    }

    fn set(engine: &Engine, args: Value) -> Result<SettingsSetOutput, CmdError> {
        run(engine, "settings.set", args).map(|v| serde_json::from_value(v).unwrap())
    }

    const COMMENTED: &str = "\
# My settings
[extract]
overwrite = \"ask\"   # ask | always | never
links = false

[levels]
zstd = 3 # fast
";

    #[test]
    fn comments_and_order_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, COMMENTED).unwrap();
        let engine = engine(&path);
        let out = set(
            &engine,
            json!({ "set": { "extract.overwrite": "rename", "levels.zstd": 19, "desktop.theme": "dark" } }),
        )
        .unwrap();
        assert_eq!(
            out.changed,
            ["desktop.theme", "extract.overwrite", "levels.zstd"]
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "\
# My settings
[extract]
overwrite = \"rename\"   # ask | always | never
links = false

[levels]
zstd = 19 # fast

[desktop]
theme = \"dark\"
"
        );
        assert_eq!(out.current.settings.desktop.theme, config::Theme::Dark);
        assert!(out.current.exists);
    }

    #[test]
    fn a_new_file_gets_a_header_and_nested_sections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config.toml");
        let engine = engine(&path);
        let out = set(
            &engine,
            json!({ "set": { "shell.items.test": false, "mcp.roots": ["C:\\work"] } }),
        )
        .unwrap();
        assert_eq!(out.changed, ["mcp.roots", "shell.items.test"]);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(HEADER), "{text}");
        assert!(text.contains("[shell.items]\ntest = false"), "{text}");
        assert!(!text.contains("[shell]\n"), "{text}");
        let (c, w) = Config::parse(&text, &path);
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(c.unwrap().mcp.roots, [std::path::PathBuf::from(r"C:\work")]);
    }

    #[test]
    fn unknown_keys_and_wrong_types_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, COMMENTED).unwrap();
        let engine = engine(&path);

        let err = set(&engine, json!({ "set": { "extract.colour": 1 } })).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
        assert_eq!(
            err.message,
            "`extract.colour` isn't a setting; `[extract]` has links, mark_of_the_web, overwrite, threads"
        );
        assert_eq!(err.details.as_ref().unwrap()["key"], "extract.colour");
        let err = set(&engine, json!({ "set": { "shell.items.nope": 1 } })).unwrap_err();
        assert!(
            err.message.contains("has add-7z, add-tar-zst"),
            "{}",
            err.message
        );
        let err = set(&engine, json!({ "reset": ["telemetry"] })).unwrap_err();
        assert!(
            err.message.contains("settings get` lists them all"),
            "{}",
            err.message
        );
        let err = set(&engine, json!({ "set": { "levels.nope": 1 } })).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
        assert!(
            err.message.contains("takes one of brotli, bzip2"),
            "{}",
            err.message
        );

        let err = set(&engine, json!({ "set": { "extract.links": "yes" } })).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
        assert_eq!(
            err.message,
            "`extract.links` can't be \"yes\": invalid type: string \"yes\", expected a boolean. \
             Nothing was written."
        );
        assert_eq!(err.details.as_ref().unwrap()["line"], 4);
        let err = set(
            &engine,
            json!({ "set": { "extract.links": "yes", "create.threads": 2 } }),
        )
        .unwrap_err();
        assert!(
            err.message.ends_with("(line 4). Nothing was written."),
            "{}",
            err.message
        );
        let err = set(&engine, json!({ "set": { "desktop.theme": "purple" } })).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), COMMENTED);
    }

    #[test]
    fn reset_and_null_remove_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, COMMENTED).unwrap();
        let engine = engine(&path);
        let out = set(
            &engine,
            json!({ "set": { "extract.links": null }, "reset": ["levels.zstd", "jobs.close_when_done"] }),
        )
        .unwrap();
        assert_eq!(out.changed, ["levels.zstd"], "links was already false");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("links") && !text.contains("zstd"), "{text}");
        assert!(text.contains("overwrite = \"ask\"   # ask"), "{text}");
        assert!(!text.contains("[jobs]"), "a reset adds nothing: {text}");

        let again = set(&engine, json!({ "reset": ["levels.zstd"] })).unwrap();
        assert!(again.changed.is_empty());
    }

    #[test]
    fn the_engine_sees_the_new_value_in_the_next_job() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let engine = engine(&path);
        assert_eq!(engine.policy().limits.max_entries, Some(10_000_000));
        set(
            &engine,
            json!({ "set": { "limits.max_entries": 5, "create.threads": 2 } }),
        )
        .unwrap();
        let config = engine.config();
        assert_eq!(config.as_ref().as_ref().unwrap().create.threads, 2);
        assert_eq!(engine.policy().limits.max_entries, Some(5));

        let got: SettingsGetOutput =
            serde_json::from_value(run(&engine, "settings.get", json!({})).unwrap()).unwrap();
        assert_eq!(got.settings.create.threads, 2);
        assert_eq!(got.path.as_deref(), Some(path.as_path()));
    }

    #[test]
    fn a_bad_file_can_be_fixed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[extract]\nlinks = \"yes\"\n").unwrap();
        let engine = engine(&path);
        assert!(engine.config().is_err());
        let err = set(&engine, json!({ "set": { "create.threads": 2 } })).unwrap_err();
        assert!(
            err.message
                .starts_with("config.toml has an error to fix first (line 2): invalid type"),
            "{}",
            err.message
        );
        set(&engine, json!({ "set": { "extract.links": true } })).unwrap();
        assert!(engine.config().as_ref().as_ref().unwrap().extract.links);

        std::fs::write(&path, "[extract\n").unwrap();
        let err = set(&engine, json!({ "set": { "extract.links": true } })).unwrap_err();
        assert!(err.message.contains("isn't valid TOML"), "{}", err.message);
    }

    #[test]
    fn cli_values_are_toml_or_strings() {
        assert_eq!(value_from_cli("19"), json!(19));
        assert_eq!(value_from_cli("false"), json!(false));
        assert_eq!(value_from_cli("rename"), json!("rename"));
        assert_eq!(value_from_cli(r"C:\work"), json!(r"C:\work"));
        assert_eq!(
            value_from_cli(r"['C:\a', 'D:\b']"),
            json!([r"C:\a", r"D:\b"])
        );
        assert_eq!(value_from_cli("'19'"), json!("19"));
        assert_eq!(value_from_cli("1\nw = 2"), json!("1\nw = 2"));
        for v in [
            json!("rename"),
            json!("19"),
            json!("true"),
            json!(""),
            json!("it's \"x\" # y"),
            json!(r"C:\a b"),
            json!(19),
            json!(-2),
            json!(1.5),
            json!(true),
            json!([r"C:\a", "x y"]),
        ] {
            let text = value_for_cli(&v).unwrap();
            assert_eq!(value_from_cli(&text), v, "{text}");
        }
        assert_eq!(value_for_cli(&json!(null)), None);
    }

    #[test]
    fn the_command_line_builds_the_json() {
        use clap::{Args, FromArgMatches};
        let cmd = SettingsSetInput::augment_args(clap::Command::new("t").no_binary_name(true));
        let m = cmd
            .try_get_matches_from([
                "extract.overwrite=rename",
                "levels.zstd=19",
                r"mcp.roots=['C:\a']",
                "--reset",
                "jobs.close_when_done",
            ])
            .unwrap();
        let input = SettingsSetInput::from_arg_matches(&m).unwrap();
        assert_eq!(
            serde_json::to_value(&input).unwrap(),
            json!({
                "set": { "extract.overwrite": "rename", "levels.zstd": 19, "mcp.roots": [r"C:\a"] },
                "reset": ["jobs.close_when_done"],
            })
        );
        crate::commands::util::tests::cli_matches_json::<SettingsSetInput>(&[], json!({}));
        let cmd = SettingsSetInput::augment_args(clap::Command::new("t").no_binary_name(true));
        assert!(cmd.try_get_matches_from(["no-equals"]).is_err());
    }
}
