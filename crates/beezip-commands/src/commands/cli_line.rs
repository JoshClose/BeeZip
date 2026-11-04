//! `cli.line`: the `beezip …` line that runs a command with given arguments, for the desktop's
//! "Copy as CLI" (docs/M3.md §4.3). It walks the same clap definition the CLI parses with, so
//! it stays right as options are added.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::{CmdError, Command, Effect, JobCtx, JsonObject, Surfaces, registry::Entry};

/// The `beezip` command line that runs a command with these arguments. Passwords are left
/// out (`omitted` names them): the copied command asks for them in the terminal.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct CliLineInput {
    /// The command, by its dotted name (`archive.extract`).
    pub command: String,
    /// Its arguments, as the engine takes them.
    #[arg(skip)]
    #[serde(default)]
    #[ts(type = "Record<string, unknown>")]
    pub args: JsonObject,
    /// The shell to quote for [default: powershell].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<ShellName>,
    /// The program to start the line with [default: beezip].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CliLineOutput {
    pub line: String,
    /// Arguments left out of the line: the passwords.
    pub omitted: Vec<String>,
}

/// How `cli.line` quotes.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum ShellName {
    /// Single quotes, with `'` doubled.
    #[default]
    Powershell,
    /// Double quotes, with `"` escaped as the C runtime reads it.
    Cmd,
    /// Single quotes, with `'` written as `'\''`.
    Posix,
}

pub struct CliLine;

impl Command for CliLine {
    const NAME: &'static str = "cli.line";
    const EFFECT: Effect = Effect::ReadOnly;
    // An assistant gains nothing from it.
    const SURFACES: Surfaces = Surfaces::NO_MCP;

    type Input = CliLineInput;
    type Output = CliLineOutput;

    fn run(input: CliLineInput, _cx: &mut JobCtx) -> Result<CliLineOutput, CmdError> {
        let entry = crate::registry()
            .get(&input.command)
            .ok_or_else(|| CmdError::not_found(format!("no command named `{}`", input.command)))?;
        let shell = input.shell.unwrap_or_default();
        let program = input.program.as_deref().unwrap_or("beezip");
        let (words, omitted) = words(entry, &input.args)?;
        let mut line = quote_program(program, shell);
        for w in &words {
            line.push(' ');
            line.push_str(&quote(w, shell));
        }
        Ok(CliLineOutput { line, omitted })
    }

    fn human(out: &CliLineOutput) -> Option<String> {
        let mut s = out.line.clone();
        if !out.omitted.is_empty() {
            s.push_str(&format!(
                "\n(left out: {}; the command asks for it)",
                out.omitted.join(", ")
            ));
        }
        Some(s)
    }
}

/// The words after the program, and the arguments left out.
pub fn words(entry: &Entry, args: &JsonObject) -> Result<(Vec<String>, Vec<String>), CmdError> {
    let mut omitted = Vec::new();
    let secret = |name: &str| {
        entry
            .input_schema
            .get("properties")
            .and_then(|p| p.get(name))
            .is_some_and(|s| s.to_string().contains("#/$defs/Secret"))
    };
    let mut args: Vec<(&String, &Value)> = args.iter().filter(|(_, v)| !v.is_null()).collect();
    args.retain(|(k, _)| {
        let keep = !secret(k);
        if !keep {
            omitted.push((*k).clone());
        }
        keep
    });

    let Some(spec) = entry.cli else {
        // No subcommand of its own: `beezip run <name> --json '<args>'`.
        let json: JsonObject = args
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let json = serde_json::to_string(&json).map_err(|e| CmdError::internal(e.to_string()))?;
        let mut words = vec!["run".to_owned(), entry.name.to_owned()];
        if json != "{}" {
            words.extend(["--json".to_owned(), json]);
        }
        return Ok((words, omitted));
    };

    let cmd = entry.augment_args(clap::Command::new(spec.name));
    for (k, _) in &args {
        if !cmd.get_arguments().any(|a| a.get_id() == k.as_str()) {
            return Err(CmdError::invalid_args(format!(
                "`{}` has no argument `{k}`",
                entry.name
            )));
        }
    }
    let value = |id: &str| args.iter().find(|(k, _)| k.as_str() == id).map(|(_, v)| *v);
    let mut words = vec![spec.name.to_owned()];
    // Positionals first, in order; then flags.
    for arg in cmd.get_arguments().filter(|a| a.is_positional()) {
        let Some(v) = value(arg.get_id().as_str()) else {
            continue;
        };
        match v {
            Value::Array(items) => {
                for item in items {
                    words.push(scalar(arg.get_id().as_str(), item)?);
                }
            }
            v => words.push(scalar(arg.get_id().as_str(), v)?),
        }
    }
    for arg in cmd.get_arguments().filter(|a| !a.is_positional()) {
        let id = arg.get_id().as_str();
        let Some(v) = value(id) else { continue };
        let flag = match (arg.get_long(), arg.get_short()) {
            (Some(long), _) => format!("--{long}"),
            (None, Some(short)) => format!("-{short}"),
            (None, None) => continue,
        };
        let equals = arg.is_require_equals_set();
        let push = |words: &mut Vec<String>, s: String| {
            if equals {
                words.push(format!("{flag}={s}"));
            } else {
                words.push(flag.clone());
                words.push(s);
            }
        };
        match v {
            // `--smart` and `--smart=false`.
            Value::Bool(true) => words.push(flag.clone()),
            Value::Bool(false) => words.push(format!("{flag}=false")),
            Value::Array(items) => {
                for item in items {
                    push(&mut words, scalar(id, item)?);
                }
            }
            v => push(&mut words, scalar(id, v)?),
        }
    }
    Ok((words, omitted))
}

fn scalar(id: &str, v: &Value) -> Result<String, CmdError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(CmdError::invalid_args(format!(
            "`{id}` can't be written on a command line: {v}"
        ))),
    }
}

/// Characters every shell leaves alone.
fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=+\\".contains(c))
}

pub fn quote(s: &str, shell: ShellName) -> String {
    match shell {
        ShellName::Powershell if plain(s) && !s.starts_with('@') => s.to_owned(),
        ShellName::Powershell => format!("'{}'", s.replace('\'', "''")),
        ShellName::Posix if plain(s) && !s.contains('\\') => s.to_owned(),
        ShellName::Posix => format!("'{}'", s.replace('\'', r"'\''")),
        ShellName::Cmd if plain(s) => s.to_owned(),
        ShellName::Cmd => {
            // The C runtime's rules: backslashes before a quote are doubled, and the quote
            // escaped; trailing backslashes are doubled before the closing quote.
            let mut out = String::from('"');
            let mut slashes = 0;
            for c in s.chars() {
                match c {
                    '\\' => slashes += 1,
                    '"' => {
                        out.push_str(&"\\".repeat(slashes * 2 + 1));
                        out.push('"');
                        slashes = 0;
                    }
                    c => {
                        out.push_str(&"\\".repeat(slashes));
                        out.push(c);
                        slashes = 0;
                    }
                }
            }
            out.push_str(&"\\".repeat(slashes * 2));
            out.push('"');
            out
        }
    }
}

/// The program, quoted; PowerShell runs a quoted path only after `&`.
fn quote_program(program: &str, shell: ShellName) -> String {
    let q = quote(program, shell);
    if shell == ShellName::Powershell && q.starts_with('\'') {
        format!("& {q}")
    } else {
        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_agree() {
        crate::wire::tests::names_agree::<ShellName>();
    }

    /// A value for every property, from the schema: `flip` picks `false` for the booleans.
    fn sample(schema: &Value, defs: &Value, flip: bool) -> Option<Value> {
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            let name = r.rsplit('/').next()?;
            return sample(defs.get(name)?, defs, flip);
        }
        for key in ["anyOf", "oneOf"] {
            if let Some(alts) = schema.get(key).and_then(Value::as_array) {
                return alts.iter().find_map(|a| sample(a, defs, flip));
            }
        }
        if let Some(v) = schema.get("enum").and_then(Value::as_array) {
            return v.first().cloned();
        }
        if let Some(v) = schema.get("const") {
            return Some(v.clone());
        }
        let ty = match schema.get("type")? {
            Value::Array(t) => t.iter().filter_map(Value::as_str).find(|t| *t != "null")?,
            t => t.as_str()?,
        };
        match ty {
            "string" => Some(Value::from(r#"it's a \ "path" $x"#)),
            "integer" | "number" => Some(Value::from(3)),
            "boolean" => Some(Value::from(!flip)),
            "array" => {
                let item = sample(schema.get("items")?, defs, flip)?;
                let other = match &item {
                    Value::String(_) => Value::from("two words"),
                    v => v.clone(),
                };
                Some(Value::Array(vec![item, other]))
            }
            _ => None,
        }
    }

    /// Splits a line as sh does, for the quoting `posix` uses.
    fn split_posix(line: &str) -> Vec<String> {
        let (mut words, mut word, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            match (quoted, c) {
                (true, '\'') => quoted = false,
                (true, c) => word.push(c),
                (false, '\'') => (quoted, any) = (true, true),
                (false, '\\') => word.extend(chars.next()),
                (false, ' ') => {
                    if any || !word.is_empty() {
                        words.push(std::mem::take(&mut word));
                    }
                    any = false;
                }
                (false, c) => word.push(c),
            }
        }
        if any || !word.is_empty() {
            words.push(word);
        }
        words
    }

    #[test]
    fn every_command_round_trips() {
        for entry in crate::registry()
            .entries()
            .iter()
            .filter(|e| e.surfaces.cli)
        {
            let schema = Value::Object((*entry.input_schema).clone());
            let defs = schema.get("$defs").cloned().unwrap_or(Value::Null);
            for flip in [false, true] {
                let mut args = JsonObject::new();
                let props = schema["properties"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                for (k, s) in &props {
                    if let Some(v) = sample(s, &defs, flip) {
                        args.insert(k.clone(), v);
                    }
                }
                let input =
                    serde_json::json!({ "command": entry.name, "args": args, "shell": "posix" });
                let out: CliLineOutput = serde_json::from_value(
                    crate::Engine::new(crate::registry())
                        .invoke(
                            "cli.line",
                            input,
                            std::sync::Arc::new(crate::NonInteractive),
                            crate::discard_events(),
                        )
                        .unwrap()
                        .join()
                        .unwrap(),
                )
                .unwrap();
                let words = split_posix(&out.line);
                assert_eq!(words[0], "beezip");
                let parsed = match entry.cli {
                    Some(spec) => {
                        assert_eq!(words[1], spec.name, "{}", out.line);
                        let cmd = entry
                            .augment_args(clap::Command::new(spec.name))
                            .no_binary_name(true);
                        let m = cmd
                            .try_get_matches_from(&words[2..])
                            .unwrap_or_else(|e| panic!("{}: {e}", out.line));
                        entry.args_from_matches(&m).unwrap()
                    }
                    None => {
                        assert_eq!(words[1..3], ["run", entry.name], "{}", out.line);
                        words.get(4).map_or(Value::Object(JsonObject::new()), |j| {
                            serde_json::from_str(j).unwrap()
                        })
                    }
                };
                for k in &out.omitted {
                    args.remove(k);
                }
                assert_eq!(parsed, Value::Object(args), "{}", out.line);
            }
        }
    }

    #[test]
    fn passwords_are_left_out() {
        let entry = crate::registry().get("archive.extract").unwrap();
        let args =
            serde_json::json!({ "archive": r"C:\a b\x.7z", "dest": r"C:\out", "password": "p" });
        let (words, omitted) = words(entry, args.as_object().unwrap()).unwrap();
        assert_eq!(omitted, ["password"]);
        assert!(!words.iter().any(|w| w == "p" || w.contains("password")));
        let line = words
            .iter()
            .map(|w| quote(w, ShellName::Powershell))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(line, r"extract 'C:\a b\x.7z' --dest C:\out");
    }

    #[test]
    fn quoting() {
        use ShellName::*;
        assert_eq!(quote(r"C:\out", Powershell), r"C:\out");
        assert_eq!(quote(r"C:\a b\x.7z", Powershell), r"'C:\a b\x.7z'");
        assert_eq!(quote("it's", Powershell), "'it''s'");
        assert_eq!(quote("@x", Powershell), "'@x'");
        assert_eq!(quote("", Powershell), "''");
        assert_eq!(quote("a,b", Powershell), "'a,b'");
        assert_eq!(quote("it's", Posix), r"'it'\''s'");
        assert_eq!(quote(r"a\b", Posix), r"'a\b'");
        assert_eq!(quote("--level=5", Posix), "--level=5");
        assert_eq!(quote(r"C:\a b\", Cmd), r#""C:\a b\\""#);
        assert_eq!(quote(r#"say "hi""#, Cmd), r#""say \"hi\"""#);
        assert_eq!(quote("x", Cmd), "x");
        assert_eq!(
            quote_program(r"C:\Program Files\BeeZip\bin\beezip.exe", Powershell),
            r"& 'C:\Program Files\BeeZip\bin\beezip.exe'"
        );
        assert_eq!(quote_program("beezip", Powershell), "beezip");
    }
}
