//! `cargo xtask shell [--mode classic|modern] [--remove]`: this tree's Explorer menu, for the
//! developer (docs/M4.md §9).
//!
//! 1. It builds the DLL, the CLI and `beezip-desktop` (debug).
//! 2. It copies the DLL to `target/shell/beezip_shell_<n>.dll`, a new name each time, so a
//!    rebuild never fights the copy an Explorer window (or the surrogate) still has loaded.
//! 3. For `--mode modern`, it writes the package's manifest, naming that copy, and its logos to
//!    `target/shell/sparse/`.
//! 4. It runs `beezip shell install` with that copy and `target/debug/beezip-desktop.exe`, which
//!    deletes the older copies it can. `modern` registers the unsigned package under Developer
//!    Mode (`--dev`), with `target/shell` as its external location.
//!
//! `--remove` runs `beezip shell uninstall`. A click starts the debug app, which needs
//! `pnpm dev` serving the page.

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};

use crate::codegen::workspace_root;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Classic,
    Modern,
}

pub fn run(mode: Mode, remove: bool) -> anyhow::Result<()> {
    let root = workspace_root();
    let debug = root.join("target/debug");
    let cli = debug.join("beezip.exe");
    if remove {
        if !cli.is_file() {
            bail!("{} isn't built: cargo build -p beezip-cli", cli.display());
        }
        return beezip(&cli, &["shell", "uninstall"]);
    }

    println!("building the DLL, the CLI and beezip-desktop (debug)");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(&root)
        .args([
            "build",
            "--locked",
            "-p",
            "beezip-shell",
            "-p",
            "beezip-cli",
        ])
        .args(["-p", "beezip-desktop"])
        .status()
        .context("starting cargo build")?;
    if !status.success() {
        bail!("cargo build failed: {status}");
    }

    let dir = root.join("target/shell");
    std::fs::create_dir_all(&dir)?;
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let name = format!("beezip_shell_{n}.dll");
    let dll = dir.join(&name);
    std::fs::copy(debug.join("beezip_shell.dll"), &dll)
        .with_context(|| format!("copying the DLL to {}", dll.display()))?;
    let app = debug.join("beezip-desktop.exe");
    let (dll, app) = (dll.to_string_lossy(), app.to_string_lossy());
    let mut args = vec!["shell", "install", "--dll", &dll, "--app", &app];
    let sparse = dir.join("sparse");
    let sparse_text = sparse.to_string_lossy();
    match mode {
        Mode::Classic => args.extend(["--mode", "classic"]),
        Mode::Modern => {
            crate::sparse::stage(&root, &sparse, env!("CARGO_PKG_VERSION"), &name)?;
            args.extend(["--mode", "modern", "--dev", "--package", &sparse_text]);
        }
    }
    beezip(&cli, &args)?;
    println!("a click starts {app}: run `pnpm --dir apps/desktop dev` first");
    Ok(())
}

fn beezip(cli: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cli)
        .args(args)
        .status()
        .with_context(|| format!("starting {}", cli.display()))?;
    if !status.success() {
        bail!("beezip {} failed: {status}", args.join(" "));
    }
    Ok(())
}
