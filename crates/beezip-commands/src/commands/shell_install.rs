//! `shell.install` and `shell.uninstall` (docs/M4.md §5.5): add BeeZip's Explorer menu, or take
//! it away. The installer runs both; so do the settings page and `xtask shell`.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::shell_status::ShellStatusOutput;
#[cfg(windows)]
use super::shell_status::status;
#[cfg(windows)]
use crate::ErrorCode;
use crate::config::ShellConfig;
use crate::shell::Hive;
use crate::{CliSpec, CmdError, Command, Effect, JobCtx, Surfaces};

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
/// user (no admin), writes the settings the menu reads, removes the other kind of menu, and
/// deletes DLLs older versions left.
///
/// Running it again repairs the menu, and moves it to another DLL or app.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ShellInstallInput {
    /// Which menu [default: auto]. `auto` gives Windows 11 its own menu when BeeZip's package
    /// can be registered, and the classic menu otherwise, with the reason.
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<InstallMode>,
    /// Register Windows 11's menu from the unsigned package, as a development package. Needs
    /// Developer Mode, and no certificate.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<bool>,
    /// The menu's DLL [default: the beezip_shell DLL in BeeZip's install folder].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dll: Option<PathBuf>,
    /// The BeeZip.exe a click starts [default: the one in BeeZip's install folder].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<PathBuf>,
    /// Windows 11's package: a signed .msix, or with --dev a folder holding AppxManifest.xml
    /// [default: beezip-sparse.msix, or with --dev the sparse folder, in BeeZip's install folder].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PathBuf>,
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

#[cfg(windows)]
fn absolute(p: PathBuf) -> PathBuf {
    std::path::absolute(&p).unwrap_or(p)
}

/// `BeeZip.exe` in the install folder, unless that is the running program: in a development
/// build's `target\debug`, `BeeZip.exe` names the CLI's `beezip.exe` on a case-insensitive
/// file system.
#[cfg(windows)]
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
#[cfg(windows)]
#[derive(Debug)]
struct Plan {
    dll: PathBuf,
    app: PathBuf,
}

/// `own_app` is the desktop app's own exe, when it is the one asking (the settings page).
#[cfg(windows)]
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

/// The first Windows 11 build. Windows 10 keeps the classic menu under `auto` (docs/M4.md §5.3).
#[cfg(windows)]
const WINDOWS_11: u32 = 22_000;
/// Windows 10 2004, the first with packages that have an external location.
#[cfg(windows)]
const EXTERNAL_LOCATION: u32 = 19_041;

/// Where Windows 11's menu would come from, or why it can't: the reason is a sentence `auto`
/// gives back as its fallback, and an explicit `modern` as its error.
#[cfg(windows)]
fn modern_source(
    input: &ShellInstallInput,
    dll: &Path,
    dir: Option<&Path>,
) -> Result<crate::shell::package::Source, String> {
    use crate::shell::package::{MANIFEST, Source, manifest_dll};
    use crate::shell::{MSIX, SPARSE, system};

    if system::build().is_some_and(|b| b < EXTERNAL_LOCATION) {
        return Err(
            "Windows 11's menu needs BeeZip's package, and this Windows is older than \
                    Windows 10 2004, which can't register it"
                .into(),
        );
    }
    let in_dir = |name: &str| dir.map(|d| d.join(name));
    if input.dev != Some(true) {
        let msix = input.package.clone().map(absolute).or_else(|| in_dir(MSIX));
        return match msix {
            Some(p) if p.is_dir() => Err(format!(
                "{} is an unsigned package, which registers only as a development package \
                 (--dev, under Developer Mode)",
                p.display()
            )),
            Some(p) if p.is_file() => Ok(Source::Msix(p)),
            _ => {
                let unsigned = in_dir(SPARSE).is_some_and(|d| d.join(MANIFEST).is_file());
                let dev = if unsigned && system::developer_mode() {
                    "; with Developer Mode on, `beezip shell install --mode modern --dev` \
                     registers the unsigned one"
                } else {
                    ""
                };
                Err(format!(
                    "this BeeZip has no signed package for Windows 11's menu{dev}"
                ))
            }
        };
    }
    if !system::developer_mode() {
        return Err(
            "a development package needs Developer Mode (Settings → System → For \
                    developers)"
                .into(),
        );
    }
    let folder = match input
        .package
        .clone()
        .map(absolute)
        .or_else(|| in_dir(SPARSE))
    {
        Some(p)
            if p.is_file()
                && p.file_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case(MANIFEST)) =>
        {
            p.parent().map(Path::to_path_buf).unwrap_or(p)
        }
        Some(p) if p.is_file() => {
            return Err(format!(
                "{} is a file; --dev registers a folder holding {MANIFEST}",
                p.display()
            ));
        }
        Some(p) => p,
        None => {
            return Err(format!(
                "there's no {SPARSE} folder beside beezip; pass --package"
            ));
        }
    };
    let text = std::fs::read_to_string(folder.join(MANIFEST))
        .map_err(|e| format!("can't read {}: {e}", folder.join(MANIFEST).display()))?;
    let named = manifest_dll(&text);
    let file = dll.file_name().map(|n| n.to_string_lossy().into_owned());
    if !named
        .as_deref()
        .zip(file.as_deref())
        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return Err(format!(
            "{}'s manifest names {}, but the DLL is {}",
            folder.display(),
            named.as_deref().unwrap_or("no DLL"),
            dll.display()
        ));
    }
    Ok(Source::Manifest(folder))
}

#[cfg(windows)]
pub(crate) fn install(
    hive: &Hive,
    input: ShellInstallInput,
    shell: &ShellConfig,
    own_app: Option<&Path>,
) -> Result<ShellInstallOutput, CmdError> {
    use crate::shell::{classic, files, mirror, package, system};

    let mode = input.mode.unwrap_or_default();
    if input.dev == Some(true) && mode == InstallMode::Classic {
        return Err(CmdError::invalid_args(
            "--dev is for Windows 11's menu; the classic menu has no package",
        ));
    }
    let dir = crate::shell::install_dir();
    let plan = plan(&input, dir.as_deref(), own_app)?;
    let hidden = shell.items.hidden();
    let write_mirror = |mode: &str| {
        mirror::write(
            hive,
            &mirror::Mirror {
                app: Some(plan.app.clone()),
                dll: Some(plan.dll.clone()),
                mode: Some(mode.into()),
                hidden: hidden.clone(),
                cascade: shell.cascade,
                log: false,
            },
        )
    };
    let want_modern = match mode {
        InstallMode::Classic => false,
        InstallMode::Modern => true,
        InstallMode::Auto => {
            input.dev == Some(true) || system::build().is_some_and(|b| b >= WINDOWS_11)
        }
    };
    let external = plan.dll.parent().unwrap_or(Path::new("."));

    let mut actions = Vec::new();
    let mut fallback = None;
    let mut modern = false;
    if want_modern {
        let because = |why: String| format!("{why}, so BeeZip is under \"Show more options\"");
        match modern_source(&input, &plan.dll, dir.as_deref()) {
            Ok(source) => {
                // The settings first: the surrogate reads them as soon as Explorer asks.
                write_mirror("modern")?;
                match package::register(hive, &source, external) {
                    Ok(done) => {
                        actions.push(done);
                        modern = true;
                    }
                    Err(e) if mode == InstallMode::Auto => {
                        fallback = Some(because(format!(
                            "Windows 11's menu couldn't be registered: {}",
                            e.message
                        )));
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(why) if mode == InstallMode::Auto => fallback = Some(because(why)),
            Err(why) => return Err(CmdError::new(ErrorCode::UnsupportedOperation, why)),
        }
    }
    if modern {
        actions.extend(classic::unregister(hive)?);
    } else {
        write_mirror("classic")?;
        actions.extend(classic::register(hive, &plan.dll, shell.cascade, &hidden)?);
        for old in package::find(hive)? {
            package::remove(hive, &old.full_name)?;
            actions.push(format!("removed Windows 11's menu ({})", old.full_name));
        }
    }
    actions.extend(files::clean(hive, external, Some(&plan.dll))?);
    Ok(ShellInstallOutput {
        status: status(hive)?,
        actions,
        fallback,
    })
}

#[cfg(windows)]
pub(crate) fn uninstall(hive: &Hive) -> Result<ShellUninstallOutput, CmdError> {
    use crate::shell::{classic, files, mirror, package};

    // The DLLs' folders, from what was registered, before it goes.
    let packages = package::find(hive)?;
    let dirs: Vec<PathBuf> = [
        classic::read(hive).and_then(|k| k.dll),
        mirror::read(hive).and_then(|m| m.dll),
    ]
    .into_iter()
    .flatten()
    .filter_map(|d| d.parent().map(Path::to_path_buf))
    .chain(packages.iter().filter_map(|p| p.external.clone()))
    .fold(Vec::new(), |mut all, d| {
        if !all.iter().any(|a: &PathBuf| crate::shell::same_path(a, &d)) {
            all.push(d);
        }
        all
    });

    let mut actions = classic::unregister(hive)?;
    for p in &packages {
        package::remove(hive, &p.full_name)?;
        actions.push(format!("removed Windows 11's menu ({})", p.full_name));
    }
    if mirror::remove(hive)? {
        actions.push("removed the menu's settings".into());
    }
    for dir in dirs {
        actions.extend(files::clean(hive, &dir, None)?);
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
            ..ShellInstallInput::default()
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

    /// A DLL and an app in a temporary install folder.
    fn layout() -> (tempfile::TempDir, ShellInstallInput) {
        let dir = tempfile::tempdir().expect("a temporary folder");
        let dll = dir.path().join("beezip_shell_0.1.0.dll");
        let app = dir.path().join("BeeZip.exe");
        for f in [&dll, &app] {
            std::fs::write(f, "").expect("a stand-in file");
        }
        let input = ShellInstallInput {
            dll: Some(dll),
            app: Some(app),
            ..ShellInstallInput::default()
        };
        (dir, input)
    }

    #[test]
    fn modern_without_a_package_says_why() {
        let (_dir, input) = layout();
        let input = ShellInstallInput {
            mode: Some(InstallMode::Modern),
            ..input
        };
        let hive = Hive::test("modern");
        let err = install(&hive, input, &ShellConfig::default(), None).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedOperation);
        assert!(err.message.contains("no signed package"), "{}", err.message);
        assert_eq!(crate::shell::mirror::read(&hive), None, "nothing written");
    }

    #[test]
    fn modern_refuses_a_folder_without_dev_and_dev_refuses_classic() {
        let (dir, input) = layout();
        let input = ShellInstallInput {
            mode: Some(InstallMode::Modern),
            package: Some(dir.path().to_path_buf()),
            ..input
        };
        let hive = Hive::test("modern-folder");
        let err = install(&hive, input.clone(), &ShellConfig::default(), None).unwrap_err();
        assert!(err.message.contains("--dev"), "{}", err.message);

        let classic = ShellInstallInput {
            mode: Some(InstallMode::Classic),
            dev: Some(true),
            ..input
        };
        let err = install(&hive, classic, &ShellConfig::default(), None).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
    }

    /// `auto` with a package it can't register (a test's hive has none) gives the classic menu,
    /// and says why, on Windows 11; Windows 10 gets the classic menu without trying.
    #[test]
    fn auto_falls_back_to_classic() {
        let (dir, input) = layout();
        let msix = dir.path().join("beezip-sparse.msix");
        std::fs::write(&msix, "").unwrap();
        let input = ShellInstallInput {
            package: Some(msix),
            ..input
        };
        let hive = Hive::test("auto");
        let out = install(&hive, input, &ShellConfig::default(), None).unwrap();
        let windows_11 = crate::shell::system::build().is_some_and(|b| b >= WINDOWS_11);
        match &out.fallback {
            Some(why) => {
                assert!(windows_11);
                assert!(why.contains("couldn't be registered"), "{why}");
                assert!(why.ends_with("under \"Show more options\""), "{why}");
            }
            None => assert!(!windows_11),
        }
        assert_eq!(
            out.status.mode,
            Some(super::super::shell_status::ShellMode::Classic)
        );
        let mirror = crate::shell::mirror::read(&hive).unwrap();
        assert_eq!(mirror.mode.as_deref(), Some("classic"));
        uninstall(&hive).unwrap();
        let _ = windows_registry::CURRENT_USER.remove_tree(hive.base());
    }
}
