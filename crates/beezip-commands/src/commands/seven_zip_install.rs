//! `seven_zip.install` (docs/M6.md §3.8): install 7-Zip with winget, or update one too old, so
//! BeeZip can open the formats it leaves to 7-Zip. 7-Zip is never bundled; winget fetches 7-Zip's
//! own installer and checks its hash, and the installer asks for administrator rights.

use std::path::{Path, PathBuf};

use beezip_core::{
    SevenZipOptions,
    backend::{find, find::Missing},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::formats_list::{SevenZipFix, SevenZipStatus};
use crate::{
    CliSpec, CmdError, Command, Config, Effect, ErrorCode, JobCtx, LogLevel, Progress, Surfaces,
    winget::{self, Line, Outcome, Verb, Watch},
};

/// Install 7-Zip with winget, or update one older than 25.01, so BeeZip can open MSI
/// patches, transforms and merge modules. winget downloads 7-Zip's own
/// installer and checks its hash; the installer asks for administrator rights. Windows only:
/// elsewhere, get 7-Zip 25.01 or newer (on Linux and macOS, 7-Zip's own `7zz`) from
/// https://7-zip.org/download.html.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct SevenZipInstallInput {}

/// What `seven_zip.install` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "lowercase")]
pub enum SevenZipAction {
    Installed,
    Updated,
    /// The 7-Zip installed was new enough already.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SevenZipInstallOutput {
    pub action: SevenZipAction,
    /// 7-Zip as BeeZip finds it now, under the settings: a path set there, or 7-Zip turned off,
    /// still wins over the 7-Zip installed.
    pub status: SevenZipStatus,
}

pub struct SevenZipInstall;

impl Command for SevenZipInstall {
    const NAME: &'static str = "seven_zip.install";
    const EFFECT: Effect = Effect::System;
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "install",
        aliases: &[],
        group: Some("7zip"),
    });

    type Input = SevenZipInstallInput;
    type Output = SevenZipInstallOutput;

    fn run(_: SevenZipInstallInput, cx: &mut JobCtx) -> Result<SevenZipInstallOutput, CmdError> {
        let opts = super::util::seven_zip(cx);
        install(&opts, winget::find(), cx)
    }

    fn human(out: &SevenZipInstallOutput) -> Option<String> {
        Some(said(out))
    }
}

fn said(out: &SevenZipInstallOutput) -> String {
    let s = &out.status;
    match (&s.name, &s.path) {
        (Some(name), Some(path)) => {
            let at = path.display();
            match out.action {
                SevenZipAction::Installed => format!("Installed {name} at {at}."),
                SevenZipAction::Updated => format!("Updated to {name} at {at}."),
                SevenZipAction::None => format!("{name} at {at} is new enough; nothing to do."),
            }
        }
        _ => {
            let done = match out.action {
                SevenZipAction::Installed => "Installed 7-Zip",
                SevenZipAction::Updated => "Updated 7-Zip",
                SevenZipAction::None => "7-Zip is installed and new enough",
            };
            let why = s.problem.as_deref().unwrap_or("its settings");
            format!("{done}, but BeeZip doesn't use it: {why}.")
        }
    }
}

/// A command line's error for want of 7-Zip, with how to get it from there: `beezip 7zip
/// install`, when winget can install or update it (docs/M6.md §3.8). The app shows its button
/// instead, and MCP has no install. `config` is the one the command ran with.
pub fn with_cli_hint(command: &str, mut err: CmdError, config: Option<&Config>) -> CmdError {
    if err.code != ErrorCode::BackendUnavailable
        || !err.message.contains("7-Zip")
        || command == SevenZipInstall::NAME
    {
        return err;
    }
    let opts = config.map(|c| c.seven_zip.options()).unwrap_or_default();
    let does = match SevenZipStatus::find(&opts).fix {
        Some(SevenZipFix::Install) => "installs",
        Some(SevenZipFix::Update) => "updates",
        _ => return err,
    };
    err.message
        .push_str(&format!(" `beezip 7zip install` {does} it with winget."));
    err
}

/// The error for a machine winget can't help: not Windows, or no winget.
fn manual(why: &str) -> CmdError {
    CmdError::new(
        ErrorCode::UnsupportedOperation,
        format!(
            "{why}. Get 7-Zip {} or newer from {}{}.",
            winget::min_version(),
            winget::DOWNLOAD_URL,
            if cfg!(windows) {
                ""
            } else {
                " (7-Zip's own 7zz: distributions' packages are usually older)"
            }
        ),
    )
    .with_details(serde_json::json!({ "url": winget::DOWNLOAD_URL }))
}

/// Sends winget's lines to the job: each status line to the log and as the progress text, a
/// progress bar's figures after the last one.
struct ToJob<'a> {
    cx: &'a mut JobCtx,
    last: String,
}

impl Watch for ToJob<'_> {
    fn cancelled(&self) -> bool {
        self.cx.is_cancelled()
    }

    fn line(&mut self, line: &Line) {
        let current = match line {
            Line::Status(s) => {
                self.cx.log(LogLevel::Info, s.clone());
                self.last.clone_from(s);
                s.clone()
            }
            Line::Bar(figures) if self.last.is_empty() => figures.clone(),
            Line::Bar(figures) => format!("{}: {figures}", self.last),
        };
        self.cx.progress(Progress {
            current: Some(current),
            ..Progress::default()
        });
    }

    /// The job's progress goes out at most every 100 ms, holding what comes between: the last
    /// line of a burst goes out once winget pauses, rather than with its next line.
    fn idle(&mut self) {
        self.cx.flush_progress();
    }
}

/// What winget is asked for: an update when the 7-Zip installed is too old, an install
/// otherwise; nothing when it's new enough. Settings aside: the machine's 7-Zip is what winget
/// changes.
fn verb(installed: &Result<beezip_core::backend::SevenZip, Missing>) -> Option<Verb> {
    match installed {
        Ok(_) => None,
        Err(Missing::TooOld(_)) => Some(Verb::Upgrade),
        Err(_) => Some(Verb::Install),
    }
}

pub(crate) fn install(
    opts: &SevenZipOptions,
    winget: Option<PathBuf>,
    cx: &mut JobCtx,
) -> Result<SevenZipInstallOutput, CmdError> {
    let machine = SevenZipOptions::default();
    let before = find(&machine);
    let Some(mut verb) = verb(&before) else {
        return Ok(SevenZipInstallOutput {
            action: SevenZipAction::None,
            status: SevenZipStatus::find(opts),
        });
    };
    if !cfg!(windows) && winget.is_none() {
        return Err(manual("Installing 7-Zip with winget is for Windows"));
    }
    let Some(winget) = winget else {
        return Err(manual("winget isn't on this Windows"));
    };
    let mut outcome = run(&winget, verb, cx)?;
    if verb == Verb::Upgrade && outcome == Outcome::NoPackage {
        if let Err(Missing::TooOld(z)) = &before {
            cx.log(
                LogLevel::Info,
                format!(
                    "winget doesn't know the 7-Zip at {}, so it installs 7-Zip beside it.",
                    z.exe.display()
                ),
            );
        }
        verb = Verb::Install;
        outcome = run(&winget, verb, cx)?;
    }
    match outcome {
        Outcome::Done | Outcome::Restart | Outcome::Nothing => {}
        Outcome::NoPackage => {
            return Err(CmdError::new(
                ErrorCode::UnsupportedOperation,
                format!(
                    "winget has no 7-Zip ({}) in its winget source. Get 7-Zip from {}.",
                    winget::PACKAGE,
                    winget::DOWNLOAD_URL
                ),
            )
            .with_details(serde_json::json!({ "url": winget::DOWNLOAD_URL })));
        }
        Outcome::Declined => {
            let message = "The administrator prompt was declined, so 7-Zip wasn't installed.";
            cx.log(LogLevel::Warn, message);
            return Err(CmdError::new(ErrorCode::Cancelled, message));
        }
        Outcome::Failed(e) => return Err(e),
    }
    match find(&machine) {
        Ok(_) => Ok(SevenZipInstallOutput {
            action: match verb {
                Verb::Install => SevenZipAction::Installed,
                Verb::Upgrade => SevenZipAction::Updated,
            },
            status: SevenZipStatus::find(opts),
        }),
        Err(m) => {
            let restart = if outcome == Outcome::Restart {
                " Windows needs a restart to finish installing it."
            } else {
                ""
            };
            Err(CmdError::new(
                ErrorCode::BackendUnavailable,
                format!(
                    "winget finished, but BeeZip still finds no 7-Zip it can use: {}.{restart}",
                    m.reason()
                ),
            ))
        }
    }
}

/// One winget run, reported to the job. A cancel kills winget and says what may go on.
fn run(winget: &Path, verb: Verb, cx: &mut JobCtx) -> Result<Outcome, CmdError> {
    let mut watch = ToJob {
        cx,
        last: String::new(),
    };
    match winget::run(winget, &verb.args(), &mut watch) {
        Ok(exit) => Ok(winget::outcome(verb, exit.code, &exit.lines)),
        Err(e) if e.code == ErrorCode::Cancelled => {
            watch.cx.log(
                LogLevel::Warn,
                "Stopped winget. If 7-Zip's installer had already started, it may still finish.",
            );
            Err(e)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(name: Option<&str>, problem: Option<&str>) -> SevenZipStatus {
        SevenZipStatus {
            name: name.map(Into::into),
            path: name.map(|_| PathBuf::from(r"C:\Program Files\7-Zip\7z.exe")),
            found_in: name.map(|_| "registry".into()),
            problem: problem.map(Into::into),
            min_version: "25.01".into(),
            fix: None,
        }
    }

    #[test]
    fn what_it_says() {
        let out = |action, status| SevenZipInstallOutput { action, status };
        assert_eq!(
            said(&out(
                SevenZipAction::Installed,
                status(Some("7-Zip 26.06"), None)
            )),
            r"Installed 7-Zip 26.06 at C:\Program Files\7-Zip\7z.exe."
        );
        assert_eq!(
            said(&out(
                SevenZipAction::Updated,
                status(Some("7-Zip 26.06"), None)
            )),
            r"Updated to 7-Zip 26.06 at C:\Program Files\7-Zip\7z.exe."
        );
        assert_eq!(
            said(&out(
                SevenZipAction::None,
                status(None, Some("turned off in Settings"))
            )),
            "7-Zip is installed and new enough, but BeeZip doesn't use it: turned off in Settings."
        );
    }

    #[test]
    fn what_winget_is_asked() {
        let old = beezip_core::backend::SevenZip {
            exe: PathBuf::from("7z.exe"),
            name: "7-Zip 23.01".into(),
            version: Some((23, 1)),
            found_in: "registry",
        };
        assert_eq!(verb(&Ok(old.clone())), None);
        assert_eq!(verb(&Err(Missing::TooOld(old))), Some(Verb::Upgrade));
        assert_eq!(
            verb(&Err(Missing::NotFound { configured: None })),
            Some(Verb::Install)
        );
        let unusable = Missing::Unusable {
            exe: PathBuf::from("7z.exe"),
            why: "it printed no banner".into(),
        };
        assert_eq!(verb(&Err(unusable)), Some(Verb::Install));
    }

    /// Only 7-Zip's errors get the hint, and never the install's own.
    #[test]
    fn the_hint_is_for_7_zips_errors() {
        let other = CmdError::new(
            ErrorCode::BackendUnavailable,
            "this build reads no RAR archives",
        );
        assert_eq!(with_cli_hint("archive.list", other.clone(), None), other);
        let corrupt = CmdError::new(ErrorCode::Corrupt, "7-Zip says: Data Error");
        assert_eq!(
            with_cli_hint("archive.test", corrupt.clone(), None),
            corrupt
        );
        let own = CmdError::new(
            ErrorCode::BackendUnavailable,
            "winget finished, but BeeZip still finds no 7-Zip it can use: not found.",
        );
        assert_eq!(with_cli_hint(SevenZipInstall::NAME, own.clone(), None), own);
    }

    #[test]
    fn manual_points_to_the_download_page() {
        let e = manual("winget isn't on this Windows");
        assert_eq!(e.code, ErrorCode::UnsupportedOperation);
        assert!(
            e.message
                .starts_with("winget isn't on this Windows. Get 7-Zip 25.01 or newer from https://7-zip.org/download.html"),
            "{}",
            e.message
        );
        assert_eq!(e.details.unwrap()["url"], winget::DOWNLOAD_URL);
    }
}
