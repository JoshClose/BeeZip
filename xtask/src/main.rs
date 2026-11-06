//! Repo tasks, run as `cargo xtask <task>` (alias in `.cargo/config.toml`).

mod bigzip;
mod codegen;
mod dist;
mod fixtures;
mod shell;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <task>

  codegen               regenerate commands.ts and beezip-menu's gen_exts.rs from the registry
  codegen --check       fail if the committed file is out of date
  gen-fixtures          regenerate the malicious corpus in tests/fixtures/malicious
  gen-fixtures --check  fail if the committed corpus is out of date
  dist [--debug] [--version V]
                        build the Windows installer (target/dist/{release,debug}/bundle/nsis)
                        as version V [default: the workspace's]
  shell [--remove]      register this tree's Explorer menu (the classic one) for you, with the
                        debug DLL and beezip-desktop; --remove takes it away
  bigzip [PATH]         write a zip of a million entries [default: target/bigzip.zip]";

/// `[--debug] [--version V]`, in any order.
fn dist_args<'a>(args: &[&'a str]) -> Option<(bool, Option<&'a str>)> {
    let (mut debug, mut version) = (false, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--debug" => debug = true,
            "--version" => version = Some(*it.next()?),
            _ => return None,
        }
    }
    Some((debug, version))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["codegen"] => codegen::run(false),
        ["codegen", "--check"] => codegen::run(true),
        ["gen-fixtures"] => fixtures::run(false),
        ["gen-fixtures", "--check"] => fixtures::run(true),
        ["dist", rest @ ..] => match dist_args(rest) {
            Some((debug, version)) => dist::run(debug, version),
            None => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        },
        ["shell"] | ["shell", "--mode", "classic"] => shell::run(false),
        ["shell", "--remove"] => shell::run(true),
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
