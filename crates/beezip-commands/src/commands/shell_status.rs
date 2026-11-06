//! `shell.status` (docs/M4.md §5.5): what Explorer's menu has in place, and what is wrong with it.

use std::path::PathBuf;

use beezip_menu::Item;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::shell::Hive;
use crate::{CliSpec, CmdError, Command, Effect, JobCtx, Surfaces};

/// Show how BeeZip's Explorer menu is registered: the Windows build, the menu in place and its
/// keys, the app a click starts, the hidden items, and any problem, such as a DLL that has gone.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct ShellStatusInput {}

/// One way of registering the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "lowercase")]
pub enum ShellMode {
    /// HKCU keys: Windows 10's menu, and "Show more options" on Windows 11.
    Classic,
    /// The sparse package: Windows 11's own menu.
    Modern,
}

/// The classic menu's keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ClassicKeys {
    /// The DLL the keys name.
    pub dll: Option<PathBuf>,
    /// Whether that DLL exists.
    pub dll_exists: bool,
    /// A "BeeZip" submenu, rather than each item at the top level.
    pub cascade: bool,
    /// The verbs, as `*\shell\BeeZip`.
    pub verbs: Vec<String>,
}

/// The package behind Windows 11's menu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PackageInfo {
    /// The package's full name: `BeeZip_<version>_neutral__<publisher hash>`.
    pub full_name: String,
    /// Registered from the unsigned manifest under Developer Mode, not from a signed package.
    pub development: bool,
    /// The folder the package's DLL is in, its external location.
    pub external_location: Option<PathBuf>,
    /// The DLL the package names.
    pub dll: Option<PathBuf>,
    /// Whether that DLL exists.
    pub dll_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ShellStatusOutput {
    /// Windows' build number (19045 is Windows 10 22H2; Windows 11 starts at 22000).
    pub windows_build: Option<u32>,
    /// Whether Developer Mode is on, which lets an unsigned package register.
    pub developer_mode: bool,
    /// The registration in place, if any.
    pub mode: Option<ShellMode>,
    /// The classic menu's keys, if there are any.
    pub classic: Option<ClassicKeys>,
    /// Windows 11's package, if it is registered.
    pub package: Option<PackageInfo>,
    /// The `BeeZip.exe` a click starts.
    pub app: Option<PathBuf>,
    /// The items left out of the menu.
    pub hidden: Vec<Item>,
    /// The classic menu's submenu setting.
    pub cascade: bool,
    /// What is wrong, in words: a DLL or app that has gone, keys without settings.
    pub problems: Vec<String>,
}

pub struct ShellStatus;

impl Command for ShellStatus {
    const NAME: &'static str = "shell.status";
    const EFFECT: Effect = Effect::ReadOnly;
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "status",
        aliases: &[],
        group: Some("shell"),
    });

    type Input = ShellStatusInput;
    type Output = ShellStatusOutput;

    fn run(_: ShellStatusInput, cx: &mut JobCtx) -> Result<ShellStatusOutput, CmdError> {
        status(cx.shell_hive())
    }

    fn human(out: &ShellStatusOutput) -> Option<String> {
        Some(human(out))
    }
}

#[cfg(windows)]
pub(crate) fn status(hive: &Hive) -> Result<ShellStatusOutput, CmdError> {
    use crate::shell::{classic, mirror, package, system};

    let keys = classic::read(hive);
    let mirror = mirror::read(hive);
    let mut problems = Vec::new();
    let package = package::find(hive)?.into_iter().next().map(|p| {
        let dll = p.dll();
        let dll_exists = dll.as_ref().is_some_and(|d| d.is_file());
        if !dll_exists {
            problems.push(match &dll {
                Some(d) => format!(
                    "Windows 11's menu is served from {}, which isn't there: `beezip shell \
                     install` repairs it",
                    d.display()
                ),
                None => format!(
                    "{} doesn't say where the menu's DLL is: `beezip shell install` repairs it",
                    p.full_name
                ),
            });
        }
        PackageInfo {
            full_name: p.full_name,
            development: p.development,
            external_location: p.external,
            dll,
            dll_exists,
        }
    });
    let classic = keys.map(|k| {
        let dll_exists = k.dll.as_ref().is_some_and(|d| d.is_file());
        match &k.dll {
            Some(dll) if !dll_exists => problems.push(format!(
                "the menu's DLL, {}, isn't there: `beezip shell install` puts it back",
                dll.display()
            )),
            None => problems.push(
                "the menu's verbs are there without their DLL: `beezip shell install` repairs them"
                    .into(),
            ),
            Some(_) => {}
        }
        ClassicKeys {
            dll: k.dll,
            dll_exists,
            cascade: k.cascade,
            verbs: k.verbs,
        }
    });
    let registered = classic.is_some() || package.is_some();
    if classic.is_some() && package.is_some() {
        problems.push(
            "both menus are registered, so BeeZip shows twice under \"Show more options\": \
             `beezip shell install` keeps one"
                .into(),
        );
    }
    if let Some(app) = mirror.as_ref().and_then(|m| m.app.as_ref())
        && registered
        && !app.is_file()
    {
        problems.push(format!(
            "a click starts {}, which isn't there",
            app.display()
        ));
    }
    if registered && mirror.is_none() {
        problems.push(
            "the menu is registered without its settings: `beezip shell install` repairs it".into(),
        );
    }
    let mode = if package.is_some() {
        Some(ShellMode::Modern)
    } else {
        classic.as_ref().map(|_| ShellMode::Classic)
    };
    Ok(ShellStatusOutput {
        windows_build: system::build(),
        developer_mode: system::developer_mode(),
        mode,
        app: mirror.as_ref().and_then(|m| m.app.clone()),
        hidden: mirror
            .as_ref()
            .map(|m| m.hidden.clone())
            .unwrap_or_default(),
        cascade: mirror.as_ref().is_none_or(|m| m.cascade),
        classic,
        package,
        problems,
    })
}

#[cfg(not(windows))]
pub(crate) fn status(_: &Hive) -> Result<ShellStatusOutput, CmdError> {
    Err(crate::shell::unsupported())
}

fn human(out: &ShellStatusOutput) -> String {
    let mut lines = Vec::new();
    let windows = match out.windows_build {
        Some(b) if b >= 22_000 => format!("Windows 11 (build {b})"),
        Some(b) => format!("Windows 10 (build {b})"),
        None => "Windows (build unknown)".into(),
    };
    let dev = if out.developer_mode {
        ", Developer Mode on"
    } else {
        ""
    };
    lines.push(format!("windows    {windows}{dev}"));
    lines.push(format!(
        "menu       {}",
        match (out.mode, &out.package) {
            (Some(ShellMode::Classic), _) => "classic",
            (Some(ShellMode::Modern), Some(p)) if p.development => {
                "Windows 11 (a development package)"
            }
            (Some(ShellMode::Modern), _) => "Windows 11",
            (None, _) => "not installed",
        }
    ));
    if let Some(p) = &out.package {
        lines.push(format!("package    {}", p.full_name));
        let dll = p
            .dll
            .as_ref()
            .map_or_else(|| "unknown".into(), |d| d.display().to_string());
        let missing = if p.dll_exists { "" } else { " (missing)" };
        lines.push(format!("dll        {dll}{missing}"));
    }
    if let Some(c) = &out.classic {
        let dll = c
            .dll
            .as_ref()
            .map_or_else(|| "none".into(), |d| d.display().to_string());
        let missing = if c.dll_exists { "" } else { " (missing)" };
        lines.push(format!("dll        {dll}{missing}"));
        lines.push(format!(
            "layout     {}",
            if c.cascade {
                "a \"BeeZip\" submenu"
            } else {
                "items at the top level"
            }
        ));
    }
    if let Some(app) = &out.app {
        lines.push(format!("app        {}", app.display()));
    }
    if !out.hidden.is_empty() {
        let ids: Vec<&str> = out.hidden.iter().map(|i| i.id()).collect();
        lines.push(format!("hidden     {}", ids.join(", ")));
    }
    for p in &out.problems {
        lines.push(format!("problem    {p}"));
    }
    lines.join("\n")
}
