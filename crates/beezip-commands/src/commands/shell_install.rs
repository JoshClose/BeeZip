//! `shell.install` and `shell.uninstall` (docs/M4.md §5.5): add BeeZip's Explorer menu, or take
//! it away. The installer runs both; so do the settings page and `xtask shell`.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::shell_status::{ShellStatusOutput, status};
use crate::config::ShellConfig;
use crate::shell::Hive;
use crate::{CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx, Surfaces};

/// Which menu `shell.install` registers.
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
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum InstallMode {
    /// The best this Windows can have.
    #[default]
    Auto,
    /// HKCU keys: Windows 10's menu, and "Show more options" on Windows 11.
    Classic,
    /// Windows 11's own menu, from BeeZip's package.
    Modern,
}

/// Add BeeZip to Explorer's right-click menu, or repair it. It registers the menu for this
/// user (no admin), writes the settings the menu reads, and deletes DLLs older versions left.
///
/// Running it again repairs the menu, and moves it to another DLL or app.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ShellInstallInput {
    /// Which menu [default: auto]. `auto` registers the classic menu, which is Windows 10's
    /// menu and "Show more options" on Windows 11.
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<InstallMode>,
    /// The menu's DLL [default: the beezip_shell DLL in BeeZip's install folder].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dll: Option<PathBuf>,
    /// The BeeZip.exe a click starts [default: the one in BeeZip's install folder].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ShellInstallOutput {
    /// The menu now.
    pub status: ShellStatusOutput,
    /// What was done, in words.
    pub actions: Vec<String>,
    /// Why `auto` gave this Windows the classic menu rather than its own, when it did.
    pub fallback: Option<String>,
}

pub struct ShellInstall;

impl Command for ShellInstall {
    const NAME: &'static str = "shell.install";
    const EFFECT: Effect = Effect::System;
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "install",
        aliases: &[],
        group: Some("shell"),
    });

    type Input = ShellInstallInput;
    type Output = ShellInstallOutput;

    fn run(input: ShellInstallInput, cx: &mut JobCtx) -> Result<ShellInstallOutput, CmdError> {
        let shell = cx.config().map(|c| c.shell.clone()).unwrap_or_default();
        install(cx.shell_hive(), input, &shell, cx.shell_app())
    }

    fn human(out: &ShellInstallOutput) -> Option<String> {
        Some(lines(&out.actions, out.fallback.as_deref()))
    }
}

/// Remove BeeZip from Explorer's right-click menu: both registrations, the settings the menu
/// reads, and the menu's DLL files where Explorer lets go of them. config.toml is left alone.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct ShellUninstallInput {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ShellUninstallOutput {
    /// What was done, in words. Empty when there was no menu.
    pub actions: Vec<String>,
}

pub struct ShellUninstall;

impl Command for ShellUninstall {
    const NAME: &'static str = "shell.uninstall";
    const EFFECT: Effect = Effect::System;
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "uninstall",
        aliases: &[],
        group: Some("shell"),
    });

    type Input = ShellUninstallInput;
    type Output = ShellUninstallOutput;

    fn run(_: ShellUninstallInput, cx: &mut JobCtx) -> Result<ShellUninstallOutput, CmdError> {
        uninstall(cx.shell_hive())
    }

    fn human(out: &ShellUninstallOutput) -> Option<String> {
        Some(if out.actions.is_empty() {
            "BeeZip's menu wasn't installed".into()
        } else {
            lines(&out.actions, None)
        })
    }
}

fn lines(actions: &[String], fallback: Option<&str>) -> String {
    let mut out: Vec<String> = actions.to_vec();
    out.extend(fallback.map(str::to_owned));
    out.join("\n")
}

fn absolute(p: PathBuf) -> PathBuf {
    std::path::absolute(&p).unwrap_or(p)
}

/// `BeeZip.exe` in the install folder, unless that is the running program: in a development
/// build's `target\debug`, `BeeZip.exe` names the CLI's `beezip.exe` on a case-insensitive
/// file system.
fn installed_app(dir: &Path) -> Option<PathBuf> {
    let app = dir.join("BeeZip.exe");
    let this = std::env::current_exe().ok();
    let same = this.is_some_and(|e| {
        e.to_string_lossy()
            .eq_ignore_ascii_case(&app.to_string_lossy())
    });
    (app.is_file() && !same).then_some(app)
}

/// What `shell.install` registers, with the defaults filled in.
#[derive(Debug)]
struct Plan {
    dll: PathBuf,
    app: PathBuf,
}

/// `own_app` is the desktop app's own exe, when it is the one asking (the settings page).
fn plan(
    input: &ShellInstallInput,
    dir: Option<&Path>,
    own_app: Option<&Path>,
) -> Result<Plan, CmdError> {
    let missing = |what: &str, flag: &str| {
        let where_ = dir.map_or_else(|| "beside beezip".into(), |d| format!("in {}", d.display()));
        CmdError::not_found(format!("there's no {what} {where_}; pass {flag}"))
    };
    let dll = match &input.dll {
        Some(d) => absolute(d.clone()),
        None => dir
            .and_then(crate::shell::default_dll)
            .ok_or_else(|| missing("beezip_shell DLL", "--dll"))?,
    };
    if !dll.is_file() {
        return Err(CmdError::not_found(format!(
            "the menu's DLL, {}, isn't there",
            dll.display()
        )));
    }
    let app = match &input.app {
        Some(a) => absolute(a.clone()),
        None => own_app
            .map(Path::to_path_buf)
            .or_else(|| dir.and_then(installed_app))
            .ok_or_else(|| missing("BeeZip.exe", "--app"))?,
    };
    if !app.is_file() {
        return Err(CmdError::not_found(format!(
            "the app, {}, isn't there",
            app.display()
        )));
    }
    Ok(Plan { dll, app })
}

#[cfg(windows)]
pub(crate) fn install(
    hive: &Hive,
    input: ShellInstallInput,
    shell: &ShellConfig,
    own_app: Option<&Path>,
) -> Result<ShellInstallOutput, CmdError> {
    use crate::shell::{classic, files, mirror, system};

    let mode = input.mode.unwrap_or_default();
    if mode == InstallMode::Modern {
        return Err(CmdError::new(
            ErrorCode::UnsupportedOperation,
            "this BeeZip has only the classic menu; Windows 11's own menu needs BeeZip's \
             package, which it doesn't include",
        ));
    }
    let fallback = (mode == InstallMode::Auto && system::build().is_some_and(|b| b >= 22_000))
        .then(|| {
            "Windows 11's own menu needs BeeZip's package, which this build doesn't include, \
             so BeeZip is under \"Show more options\""
                .to_owned()
        });
    let plan = plan(&input, crate::shell::install_dir().as_deref(), own_app)?;
    let hidden = shell.items.hidden();
    mirror::write(
        hive,
        &mirror::Mirror {
            app: Some(plan.app.clone()),
            dll: Some(plan.dll.clone()),
            mode: Some("classic".into()),
            hidden: hidden.clone(),
            cascade: shell.cascade,
            log: false,
        },
    )?;
    let mut actions = classic::register(hive, &plan.dll, shell.cascade, &hidden)?;
    if let Some(dir) = plan.dll.parent() {
        actions.extend(files::clean(hive, dir, Some(&plan.dll))?);
    }
    Ok(ShellInstallOutput {
        status: status(hive)?,
        actions,
        fallback,
    })
}

#[cfg(windows)]
pub(crate) fn uninstall(hive: &Hive) -> Result<ShellUninstallOutput, CmdError> {
    use crate::shell::{classic, files, mirror};

    // The DLL's folder, from what was registered, before the keys go.
    let dll = classic::read(hive)
        .and_then(|k| k.dll)
        .or_else(|| mirror::read(hive).and_then(|m| m.dll));
    let mut actions = classic::unregister(hive)?;
    if mirror::remove(hive)? {
        actions.push("removed the menu's settings".into());
    }
    if let Some(dir) = dll.as_deref().and_then(Path::parent) {
        actions.extend(files::clean(hive, dir, None)?);
    }
    Ok(ShellUninstallOutput { actions })
}

#[cfg(not(windows))]
pub(crate) fn install(
    _: &Hive,
    _: ShellInstallInput,
    _: &ShellConfig,
    _: Option<&Path>,
) -> Result<ShellInstallOutput, CmdError> {
    Err(crate::shell::unsupported())
}

#[cfg(not(windows))]
pub(crate) fn uninstall(_: &Hive) -> Result<ShellUninstallOutput, CmdError> {
    Err(crate::shell::unsupported())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::config::ShellItems;

    #[test]
    fn install_repair_and_uninstall() {
        let hive = Hive::test("install");
        let dir = tempfile::tempdir().unwrap();
        let dll = dir.path().join("beezip_shell_0.1.1.dll");
        let old = dir.path().join("beezip_shell_0.1.0.dll");
        let app = dir.path().join("BeeZip.exe");
        for f in [&dll, &old, &app] {
            std::fs::write(f, "").unwrap();
        }
        let input = ShellInstallInput {
            mode: Some(InstallMode::Classic),
            dll: Some(dll.clone()),
            app: Some(app.clone()),
        };
        let shell = ShellConfig {
            cascade: true,
            items: ShellItems {
                test: false,
                ..ShellItems::default()
            },
        };
        let out = install(&hive, input.clone(), &shell, None).unwrap();
        assert_eq!(out.fallback, None);
        assert!(
            out.actions[0].starts_with("registered the classic menu"),
            "{out:?}"
        );
        assert!(
            out.actions.iter().any(|a| a.starts_with("deleted")),
            "{out:?}"
        );
        assert!(!old.exists());
        let s = &out.status;
        assert_eq!(s.mode, Some(super::super::shell_status::ShellMode::Classic));
        assert_eq!(s.app.as_deref(), Some(&*app));
        assert_eq!(s.hidden, [beezip_menu::Item::Test]);
        assert!(s.problems.is_empty(), "{:?}", s.problems);
        let keys = s.classic.as_ref().unwrap();
        assert!(keys.cascade && keys.dll_exists);

        // A DLL that has gone is a problem the status names.
        std::fs::remove_file(&dll).unwrap();
        let s = status(&hive).unwrap();
        assert_eq!(s.problems.len(), 1, "{:?}", s.problems);
        assert!(install(&hive, input, &shell, None).is_err());

        let out = uninstall(&hive).unwrap();
        assert!(
            out.actions.iter().any(|a| a.contains("settings")),
            "{out:?}"
        );
        let s = status(&hive).unwrap();
        assert_eq!(s.mode, None);
        assert!(s.problems.is_empty());
        assert!(uninstall(&hive).unwrap().actions.is_empty());
        let _ = windows_registry::CURRENT_USER.remove_tree(hive.base());
    }

    #[test]
    fn modern_is_refused_until_the_package_exists() {
        let input = ShellInstallInput {
            mode: Some(InstallMode::Modern),
            ..ShellInstallInput::default()
        };
        let err = install(&Hive::test("modern"), input, &ShellConfig::default(), None).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedOperation);
    }
}
