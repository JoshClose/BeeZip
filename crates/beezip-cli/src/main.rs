//! `beezip`: the BeeZip command-line tool.
//!
//! Most subcommands are generated from the command registry (`generated.rs`). The built-ins are
//! the generic forms, `run`, `commands` and `schema`, plus `mcp`.

mod generated;
mod output;

use std::{io::Read, process::ExitCode, sync::Arc};

use beezip_commands::{CmdError, Engine, ErrorCode, NonInteractive, registry};
use clap::{Arg, ArgMatches, value_parser};
use serde_json::Value;

use crate::output::{Mode, Output};

fn cli() -> clap::Command {
    let root = clap::Command::new("beezip")
        .about("BeeZip: archives from the command line")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("output")
                .long("output")
                .global(true)
                .value_name("FORMAT")
                .value_parser(value_parser!(Mode))
                .default_value("human")
                .help("How to print results; ndjson streams every job event"),
        )
        .subcommand(
            clap::Command::new("run")
                .about("Run any command by name, with JSON arguments")
                .arg(Arg::new("name").required(true).value_name("COMMAND"))
                .arg(
                    Arg::new("json")
                        .long("json")
                        .value_name("JSON|@FILE|-")
                        .help("Arguments as a JSON object, @path to read them from a file, or - for stdin [default: {}]"),
                ),
        )
        .subcommand(clap::Command::new("commands").about("List every command"))
        .subcommand(
            clap::Command::new("schema")
                .about("Print a command's input and output JSON schemas")
                .arg(Arg::new("name").required(true).value_name("COMMAND")),
        )
        .subcommand(clap::Command::new("mcp").about("Serve BeeZip's tools over MCP on stdin/stdout"));
    generated::add_subcommands(root, registry())
}

fn main() -> ExitCode {
    let matches = cli().get_matches();
    let out = Output::new(
        matches
            .get_one::<Mode>("output")
            .copied()
            .unwrap_or_default(),
    );
    match dispatch(&matches, &out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            out.error(&err);
            ExitCode::from(err.exit_code())
        }
    }
}

fn dispatch(matches: &ArgMatches, out: &Output) -> Result<(), CmdError> {
    match matches.subcommand() {
        Some(("run", sub)) => {
            let name = sub.get_one::<String>("name").map_or("", String::as_str);
            let args = json_arg(sub.get_one::<String>("json").map(String::as_str))?;
            run(name, args, out)
        }
        Some(("commands", _)) => {
            out.commands(registry());
            Ok(())
        }
        Some(("schema", sub)) => {
            let name = sub.get_one::<String>("name").map_or("", String::as_str);
            let entry = registry()
                .get(name)
                .ok_or_else(|| CmdError::not_found(format!("no command named `{name}`")))?;
            out.schema(entry);
            Ok(())
        }
        Some(("mcp", _)) => beezip_mcp::serve_stdio_blocking(registry())
            .map_err(|e| CmdError::internal(format!("MCP server failed: {e:#}"))),
        Some((subcommand, sub)) => {
            let entry = registry()
                .by_cli_name(subcommand)
                .ok_or_else(|| CmdError::not_found(format!("no subcommand `{subcommand}`")))?;
            let args = entry.args_from_matches(sub).unwrap_or_else(|e| e.exit());
            run(entry.name, args, out)
        }
        None => Err(CmdError::invalid_args(
            "no subcommand given; see `beezip --help`",
        )),
    }
}

fn run(name: &str, args: Value, out: &Output) -> Result<(), CmdError> {
    let engine = Engine::new(registry());
    // Prompts fail with a hint until the TTY interactor arrives in M1.
    let job = engine.invoke(name, args, Arc::new(NonInteractive), out.event_sink())?;
    let output = job.join()?;
    out.result(registry().get(name), &output);
    Ok(())
}

/// Reads `--json`: a literal, `@path`, or `-` for stdin. Absent means `{}`.
fn json_arg(arg: Option<&str>) -> Result<Value, CmdError> {
    let text = match arg {
        None => return Ok(Value::Object(serde_json::Map::new())),
        Some("-") => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .map_err(|e| CmdError::new(ErrorCode::Io, format!("could not read stdin: {e}")))?;
            text
        }
        Some(arg) => match arg.strip_prefix('@') {
            Some(path) => std::fs::read_to_string(path).map_err(|e| {
                CmdError::new(ErrorCode::Io, format!("could not read `{path}`: {e}"))
            })?,
            None => arg.to_owned(),
        },
    };
    serde_json::from_str(&text)
        .map_err(|e| CmdError::invalid_args(format!("--json is not valid JSON: {e}")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_is_well_formed() {
        super::cli().debug_assert();
    }
}
