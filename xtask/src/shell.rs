//! `cargo xtask shell [--remove]`: this tree's Explorer menu, for the developer (docs/M4.md §9).
//!
//! 1. It builds the DLL, the CLI and `beezip-desktop` (debug).
//! 2. It copies the DLL to `target/shell/beezip_shell_<n>.dll`, a new name each time, so a
//!    rebuild never fights the copy an Explorer window still has loaded.
//! 3. It runs `beezip shell install --mode classic` with that copy and
//!    `target/debug/beezip-desktop.exe`, which deletes the older copies it can.
//!
//! `--remove` runs `beezip shell uninstall`. A click starts the debug app, which needs
//! `pnpm dev` serving the page. The Windows 11 menu (`--mode modern`) comes with its package.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};

use crate::codegen::workspace_root;

pub fn run(remove: bool) -> anyhow::Result<()> {
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
    let dll = dir.join(format!("beezip_shell_{n}.dll"));
    std::fs::copy(debug.join("beezip_shell.dll"), &dll)
        .with_context(|| format!("copying the DLL to {}", dll.display()))?;
    let app = debug.join("beezip-desktop.exe");
    beezip(
        &cli,
        &[
            "shell",
            "install",
            "--mode",
            "classic",
            "--dll",
            &dll.to_string_lossy(),
            "--app",
            &app.to_string_lossy(),
        ],
    )?;
    println!(
        "a click starts {}: run `pnpm --dir apps/desktop dev` first",
        app.display()
    );
    Ok(())
}

fn beezip(cli: &std::path::Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cli)
        .args(args)
        .status()
        .with_context(|| format!("starting {}", cli.display()))?;
    if !status.success() {
        bail!("beezip {} failed: {status}", args.join(" "));
    }
    Ok(())
}
