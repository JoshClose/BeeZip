//! Repo tasks, run as `cargo xtask <task>` (alias in `.cargo/config.toml`).

mod bigzip;
mod codegen;
mod dist;
mod fixtures;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <task>

  codegen               regenerate apps/desktop/src/gen/commands.ts from the command registry
  codegen --check       fail if the committed file is out of date
  gen-fixtures          regenerate the malicious corpus in tests/fixtures/malicious
  gen-fixtures --check  fail if the committed corpus is out of date
  dist [--debug]        build the Windows installer (target/dist/{release,debug}/bundle/nsis)
  bigzip [PATH]         write a zip of a million entries [default: target/bigzip.zip]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["codegen"] => codegen::run(false),
        ["codegen", "--check"] => codegen::run(true),
        ["gen-fixtures"] => fixtures::run(false),
        ["gen-fixtures", "--check"] => fixtures::run(true),
        ["dist"] => dist::run(false),
        ["dist", "--debug"] => dist::run(true),
        ["bigzip"] => bigzip::run(None),
        ["bigzip", path] => bigzip::run(Some(path)),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
