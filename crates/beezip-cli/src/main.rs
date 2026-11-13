//! `beezip`: the BeeZip command-line tool.
//!
//! Most subcommands are generated from the command registry (`generated.rs`). The built-ins are
//! the generic forms, `run`, `commands` and `schema`, plus `mcp`.

mod generated;
mod interact;
mod output;
mod progress;

use std::{
    io::{IsTerminal, Read},
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
};

use beezip_commands::{
    CancelToken, CmdError, Engine, EngineOptions, ErrorCode, Interactor, McpConfig, Policy, config,
    partial, registry,
};
use beezip_mcp::{BeeZipServer, McpOptions};
use clap::{Arg, ArgAction, ArgMatches, value_parser};
use serde_json::Value;

use crate::{
    interact::{CliNonInteractive, TtyInteractor},
    output::{Mode, Output},
};

fn cli() -> clap::Command {
    let root = clap::Command::new("beezip")
        // Fixed, so usage lines read `beezip`, not `beezip.exe`, on Windows.
        .bin_name("beezip")
        .about("BeeZip: archives from the command line")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("output-mode")
                .long("output")
                .global(true)
                .value_name("FORMAT")
                .value_parser(value_parser!(Mode))
                .default_value("human")
                .help_heading("Global options")
                .help("How to print results; ndjson streams every job event"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .global(true)
                .action(ArgAction::SetTrue)
                .help_heading("Global options")
                .help("No progress bars or info messages; warnings still print"),
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
        .subcommand(
            clap::Command::new("mcp")
                .about("Serve BeeZip's tools over MCP on stdin/stdout")
                .long_about(
                    "Serve BeeZip's tools over MCP on stdin/stdout.\n\n\
                     Commands that write files may only write under the --root directories \
                     (or `[mcp] roots` in config.toml). Without either, MCP clients can read \
                     archives but not write anything. See docs/MCP.md.",
                )
                .arg(
                    Arg::new("root")
                        .long("root")
                        .value_name("DIR")
                        .action(ArgAction::Append)
                        .value_parser(value_parser!(PathBuf))
                        .help("A directory commands may write under; repeatable. Replaces `[mcp] roots`"),
                )
                .arg(
                    Arg::new("read-only")
                        .long("read-only")
                        .action(ArgAction::SetTrue)
                        .help("Offer only the commands that don't write"),
                )
                .arg(
                    Arg::new("unrestricted")
                        .long("unrestricted")
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["root", "read-only"])
                        .help("Let commands write anywhere"),
                ),
        );
    generated::add_subcommands(root, registry())
}

fn main() -> ExitCode {
    let matches = cli().get_matches();
    let mode = matches
        .get_one::<Mode>("output-mode")
        .copied()
        .unwrap_or_default();
    let quiet = matches.get_flag("quiet");
    let out = Output::new(mode, quiet, std::io::stderr().is_terminal());
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
        Some(("mcp", sub)) => mcp(sub, out),
        Some((subcommand, sub)) => {
            // `beezip settings get`: the group, then the command's own subcommand.
            let (group, name, sub) = match sub.subcommand() {
                Some((name, inner)) if generated::is_group(subcommand) => {
                    (Some(subcommand), name, inner)
                }
                _ => (None, subcommand, sub),
            };
            let entry = registry().by_cli_name(group, name).ok_or_else(|| {
                let words = group.into_iter().chain([name]).collect::<Vec<_>>();
                CmdError::not_found(format!("no subcommand `{}`", words.join(" ")))
            })?;
            let args = entry.args_from_matches(sub).unwrap_or_else(|e| e.exit());
            run(entry.name, args, out)
        }
        None => Err(CmdError::invalid_args(
            "no subcommand given; see `beezip --help`",
        )),
    }
}

/// The running job's cancel token, for the Ctrl+C handler.
static CURRENT: Mutex<Option<CancelToken>> = Mutex::new(None);
static PRESSES: AtomicU32 = AtomicU32::new(0);

/// The first Ctrl+C cancels the job (it removes its partial file and exits 130). The second
/// exits at once: `process::exit` runs no destructors, so it deletes every partial file first
/// (docs/M3.md §3.7).
fn install_ctrl_c() {
    let _ = ctrlc::set_handler(|| {
        let token = CURRENT.lock().ok().and_then(|t| t.clone());
        match (PRESSES.fetch_add(1, Ordering::SeqCst), token) {
            (0, Some(token)) => {
                eprintln!("\ncancelling… (Ctrl+C again to quit at once)");
                token.cancel();
            }
            _ => {
                partial::abandon_all();
                std::process::exit(i32::from(ErrorCode::Cancelled.exit_code()))
            }
        }
    });
}

/// `beezip mcp`: the flags win over `[mcp]` in the config (docs/M2.md §4). Warnings go to
/// stderr; stdout carries the protocol.
fn mcp(sub: &ArgMatches, out: &Output) -> Result<(), CmdError> {
    let loaded = config::load();
    for w in &loaded.warnings {
        out.warn(w);
    }
    let config = match &loaded.config {
        Ok(c) => c.mcp.clone(),
        Err(e) => {
            out.warn(&format!("{}; `[mcp]` settings are ignored", e.message));
            McpConfig::default()
        }
    };
    let mut roots: Vec<PathBuf> = sub
        .get_many::<PathBuf>("root")
        .map(|r| r.cloned().collect())
        .unwrap_or_default();
    if roots.is_empty() {
        roots = config.roots;
    }
    let options = McpOptions {
        roots,
        read_only: sub.get_flag("read-only") || config.read_only,
        unrestricted: sub.get_flag("unrestricted"),
        ..McpOptions::default()
    };
    let engine = Engine::with_options(
        registry(),
        EngineOptions::from_loaded(loaded, Policy::unrestricted()),
    );
    let server = BeeZipServer::new(engine, &options)?;
    beezip_mcp::serve_stdio_blocking(server)
        .map_err(|e| CmdError::internal(format!("MCP server failed: {e:#}")))
}

fn run(name: &str, args: Value, out: &Output) -> Result<(), CmdError> {
    // The config is read once, when the process starts (docs/M1.md §4.1).
    let loaded = config::load();
    for w in &loaded.warnings {
        out.warn(w);
    }
    let engine = Engine::with_options(
        registry(),
        EngineOptions::from_loaded(loaded, Policy::unrestricted()),
    );
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let interactor: Arc<dyn Interactor> = if interactive {
        Arc::new(TtyInteractor::new(out.bars()))
    } else {
        Arc::new(CliNonInteractive)
    };
    install_ctrl_c();
    let job = engine.invoke(name, args, interactor, out.event_sink())?;
    if let Ok(mut current) = CURRENT.lock() {
        *current = Some(job.cancel_token());
    }
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
