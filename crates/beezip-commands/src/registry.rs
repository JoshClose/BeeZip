use std::{
    any::TypeId,
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ts_rs::{Config, TS, TypeVisitor};

use crate::{CliSpec, CmdError, Command, Effect, JobCtx, Surfaces};

pub type JsonObject = Map<String, Value>;

/// TypeScript declarations by type name, as produced by [`collect_ts`].
pub type TsDecls = BTreeMap<String, String>;

pub(crate) type RunFn = fn(Value, &mut JobCtx) -> Result<Value, CmdError>;

/// A registered command with its types erased, so every front end can treat all commands alike.
#[derive(Clone)]
pub struct Entry {
    pub name: &'static str,
    /// The doc comment on the command's input type, read once from its JSON schema.
    pub description: String,
    pub effect: Effect,
    pub surfaces: Surfaces,
    pub cli: Option<CliSpec>,
    pub input_schema: Arc<JsonObject>,
    pub output_schema: Arc<JsonObject>,
    pub(crate) run: RunFn,
    human: fn(&Value) -> Option<String>,
    augment_args: fn(clap::Command) -> clap::Command,
    args_from_matches: fn(&clap::ArgMatches) -> Result<Value, clap::Error>,
    ts_decls: fn(&Config, &mut TsDecls) -> Result<(), String>,
    ts_input: fn(&Config) -> String,
    ts_output: fn(&Config) -> String,
}

impl Entry {
    fn of<C: Command>() -> Self {
        let input_schema = schema_object::<C::Input>();
        let description = schema_description(&input_schema);
        Self {
            name: C::NAME,
            description,
            effect: C::EFFECT,
            surfaces: C::SURFACES,
            cli: C::CLI,
            input_schema: Arc::new(input_schema),
            output_schema: Arc::new(schema_object::<C::Output>()),
            run: run_erased::<C>,
            human: human_erased::<C>,
            augment_args: <C::Input as clap::Args>::augment_args,
            args_from_matches: args_from_matches::<C>,
            ts_decls: |cfg, out| {
                collect_ts::<C::Input>(cfg, out)?;
                collect_ts::<C::Output>(cfg, out)
            },
            ts_input: <C::Input as TS>::name,
            ts_output: <C::Output as TS>::name,
        }
    }

    /// Renders an output of this command for `--output human`, if the command has a rendering.
    pub fn human(&self, output: &Value) -> Option<String> {
        (self.human)(output)
    }

    /// Adds the input's arguments to a clap subcommand.
    pub fn augment_args(&self, cmd: clap::Command) -> clap::Command {
        (self.augment_args)(cmd)
    }

    /// Turns parsed subcommand arguments into the JSON input the engine takes.
    pub fn args_from_matches(&self, matches: &clap::ArgMatches) -> Result<Value, clap::Error> {
        (self.args_from_matches)(matches)
    }

    /// Adds the TypeScript declarations of the input and output types and everything they use.
    pub fn ts_decls(&self, cfg: &Config, out: &mut TsDecls) -> Result<(), String> {
        (self.ts_decls)(cfg, out)
    }

    /// TypeScript names of the input and output types.
    pub fn ts_names(&self, cfg: &Config) -> (String, String) {
        ((self.ts_input)(cfg), (self.ts_output)(cfg))
    }

    pub fn info(&self) -> CommandInfo {
        CommandInfo {
            name: self.name.to_owned(),
            description: self.description.clone(),
            effect: self.effect,
            surfaces: self.surfaces,
            cli: self.cli.map(|c| c.name.to_owned()),
        }
    }
}

/// A command as the front ends list it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CommandInfo {
    pub name: String,
    pub description: String,
    pub effect: Effect,
    pub surfaces: Surfaces,
    /// The generated `beezip` subcommand, if there is one.
    pub cli: Option<String>,
}

/// Every command, sorted by name.
#[derive(Default)]
pub struct Registry {
    entries: Vec<Entry>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a command.
    ///
    /// # Panics
    /// If the name or CLI name is already taken, or the name isn't lowercase `a.b` form.
    pub fn register<C: Command>(&mut self) -> &mut Self {
        assert!(
            C::NAME.contains('.')
                && C::NAME
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
            "command name `{}` must be lowercase `group.action`",
            C::NAME
        );
        if let Some(spec) = C::CLI {
            assert!(
                self.by_cli_name(spec.name).is_none(),
                "CLI name `{}` is used twice",
                spec.name
            );
        }
        match self.entries.binary_search_by(|e| e.name.cmp(C::NAME)) {
            Ok(_) => panic!("command `{}` is registered twice", C::NAME),
            Err(at) => self.entries.insert(at, Entry::of::<C>()),
        }
        self
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries
            .binary_search_by(|e| e.name.cmp(name))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Finds a command by its generated subcommand name or alias.
    pub fn by_cli_name(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| {
            e.cli
                .is_some_and(|c| c.name == name || c.aliases.contains(&name))
        })
    }

    /// All commands, sorted by name.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

fn run_erased<C: Command>(args: Value, cx: &mut JobCtx) -> Result<Value, CmdError> {
    let input: C::Input = serde_json::from_value(args)
        .map_err(|e| CmdError::invalid_args(format!("invalid arguments for `{}`: {e}", C::NAME)))?;
    let output = C::run(input, cx)?;
    serde_json::to_value(output).map_err(|e| {
        CmdError::internal(format!(
            "could not serialise the output of `{}`: {e}",
            C::NAME
        ))
    })
}

fn human_erased<C: Command>(output: &Value) -> Option<String> {
    let output = C::Output::deserialize(output).ok()?;
    C::human(&output)
}

fn args_from_matches<C: Command>(matches: &clap::ArgMatches) -> Result<Value, clap::Error> {
    let input = <C::Input as clap::FromArgMatches>::from_arg_matches(matches)?;
    serde_json::to_value(input)
        .map_err(|e| clap::Error::raw(clap::error::ErrorKind::ValueValidation, e))
}

fn schema_object<T: JsonSchema>() -> JsonObject {
    match schemars::schema_for!(T).to_value() {
        Value::Object(map) => map,
        _ => JsonObject::new(),
    }
}

/// The type's doc comment. schemars 1.x puts all of it in `description` (`title` is the type
/// name).
fn schema_description(schema: &JsonObject) -> String {
    schema
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Adds the declaration of `T` and of every exportable type it uses to `out`, keyed by name.
///
/// Builtins (strings, numbers, `Option`, `Vec`, ...) have no declaration and are skipped. Two
/// different declarations under one name are an error, since the generated file is flat.
pub fn collect_ts<T: TS + 'static + ?Sized>(cfg: &Config, out: &mut TsDecls) -> Result<(), String> {
    struct Collector<'a> {
        cfg: &'a Config,
        out: &'a mut TsDecls,
        seen: HashSet<TypeId>,
        clashes: Vec<String>,
    }

    impl TypeVisitor for Collector<'_> {
        fn visit<U: TS + 'static + ?Sized>(&mut self) {
            if !self.seen.insert(TypeId::of::<U>()) {
                return;
            }
            if U::output_path().is_some() {
                let name = U::ident(self.cfg);
                let decl = format!(
                    "{}export {}",
                    U::docs().unwrap_or_default(),
                    U::decl(self.cfg)
                );
                if let Some(prev) = self.out.insert(name.clone(), decl.clone())
                    && prev != decl
                {
                    self.clashes.push(name);
                }
            }
            U::visit_dependencies(self);
        }
    }

    let mut collector = Collector {
        cfg,
        out,
        seen: HashSet::new(),
        clashes: Vec::new(),
    };
    collector.visit::<T>();
    if collector.clashes.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "different types share the TypeScript name(s) {}",
            collector.clashes.join(", ")
        ))
    }
}
