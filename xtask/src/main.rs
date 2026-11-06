//! Repo tasks, run as `cargo xtask <task>` (alias in `.cargo/config.toml`).

mod bigzip;
mod codegen;
mod devcert;
mod dist;
mod fixtures;
mod shell;
mod sparse;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <task>

  codegen               regenerate commands.ts and beezip-menu's gen_exts.rs from the registry
  codegen --check       fail if the committed file is out of date
  gen-fixtures          regenerate the malicious corpus in tests/fixtures/malicious
  gen-fixtures --check  fail if the committed corpus is out of date
  dist [--debug] [--version V] [--sign-dev]
                        build the Windows installer (target/dist/{release,debug}/bundle/nsis)
                        as version V [default: the workspace's]; --sign-dev adds Windows 11's
                        menu as a package signed with the dev-cert certificate
  dev-cert              make (or reuse) the \"CN=BeeZip Dev\" code-signing certificate for
                        --sign-dev, and print the elevated command that trusts it
  shell [--mode classic|modern] [--remove]
                        register this tree's Explorer menu for you, with the debug DLL and
                        beezip-desktop [default: classic]; modern is Windows 11's menu, as a
                        development package (Developer Mode); --remove takes it away
  bigzip [PATH]         write a zip of a million entries [default: target/bigzip.zip]";

/// `dist`'s flags, in any order.
#[derive(Debug, Default, PartialEq, Eq)]
struct DistArgs<'a> {
    debug: bool,
    version: Option<&'a str>,
    sign_dev: bool,
}

fn dist_args<'a>(args: &[&'a str]) -> Option<DistArgs<'a>> {
    let mut out = DistArgs::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--debug" => out.debug = true,
            "--sign-dev" => out.sign_dev = true,
            "--version" => out.version = Some(*it.next()?),
            _ => return None,
        }
    }
    Some(out)
}

/// `shell`'s flags: `--mode classic|modern`, `--remove`.
fn shell_args(args: &[&str]) -> Option<(shell::Mode, bool)> {
    let (mut mode, mut remove) = (shell::Mode::Classic, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--remove" => remove = true,
            "--mode" => {
                mode = match *it.next()? {
                    "classic" => shell::Mode::Classic,
                    "modern" => shell::Mode::Modern,
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    Some((mode, remove))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let usage = || {
        eprintln!("{USAGE}");
        ExitCode::from(2)
    };
    let result = match args.as_slice() {
        ["codegen"] => codegen::run(false),
        ["codegen", "--check"] => codegen::run(true),
        ["gen-fixtures"] => fixtures::run(false),
        ["gen-fixtures", "--check"] => fixtures::run(true),
        ["dist", rest @ ..] => match dist_args(rest) {
            Some(d) => dist::run(d.debug, d.version, d.sign_dev),
            None => return usage(),
        },
        ["dev-cert"] => devcert::run(),
        ["shell", rest @ ..] => match shell_args(rest) {
            Some((mode, remove)) => shell::run(mode, remove),
            None => return usage(),
        },
        ["bigzip"] => bigzip::run(None),
        ["bigzip", path] => bigzip::run(Some(path)),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_in_any_order() {
        assert_eq!(
            dist_args(&["--sign-dev", "--version", "0.1.1", "--debug"]),
            Some(DistArgs {
                debug: true,
                version: Some("0.1.1"),
                sign_dev: true
            })
        );
        assert_eq!(dist_args(&["--version"]), None);
        assert_eq!(
            shell_args(&["--remove"]),
            Some((shell::Mode::Classic, true))
        );
        assert_eq!(
            shell_args(&["--mode", "modern"]),
            Some((shell::Mode::Modern, false))
        );
        assert_eq!(shell_args(&["--mode", "fancy"]), None);
    }
}
