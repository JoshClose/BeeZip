use std::path::PathBuf;

use beezip_core::{
    CodecId, FormatCaps, FormatId,
    format::{
        cab::CabMethod, caps_for, sevenz::SevenZMethod, squashfs::SquashfsMethod, zip::ZipMethod,
    },
    ops::ArchiveKind,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{CliSpec, CmdError, Command, Effect, JobCtx};

/// List the archive formats and codecs BeeZip reads and writes, with their capabilities,
/// methods, levels and threading.
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct FormatsListInput {}

/// A level range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct LevelRange {
    pub min: i32,
    pub max: i32,
    pub default: i32,
}

impl From<beezip_core::Levels> for LevelRange {
    fn from(l: beezip_core::Levels) -> Self {
        Self {
            min: l.min,
            max: l.max,
            default: l.default,
        }
    }
}

/// What BeeZip offers for a format in this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Caps {
    pub list: bool,
    pub extract: bool,
    pub create: bool,
    pub append: bool,
    pub delete: bool,
    pub rename: bool,
    pub encrypt: bool,
    pub encrypt_headers: bool,
    pub solid: bool,
    /// The format has volume sets of its own (7z's, RAR's). A numbered split (`a.zip.001`)
    /// works for every format regardless.
    pub volumes: bool,
    /// An entry can be read without decoding the ones before it.
    pub random_access: bool,
}

impl From<FormatCaps> for Caps {
    fn from(c: FormatCaps) -> Self {
        Self {
            list: c.list,
            extract: c.extract,
            create: c.create,
            append: c.append,
            delete: c.delete,
            rename: c.rename,
            encrypt: c.encrypt,
            encrypt_headers: c.encrypt_headers,
            solid: c.solid,
            volumes: c.volumes,
            random_access: c.random_access,
        }
    }
}

/// A compression method BeeZip writes, with its level range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MethodInfo {
    pub id: String,
    pub levels: Option<LevelRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct FormatInfo {
    pub id: String,
    pub name: String,
    pub extensions: Vec<String>,
    pub caps: Caps,
    /// Methods for new archives (zip and 7z).
    pub methods: Vec<MethodInfo>,
    /// Encryption for new archives.
    pub encryption: Vec<String>,
    /// The program that reads it, for the formats BeeZip leaves to one: `7-zip`. `null` for
    /// BeeZip's own, which include the disks, file systems and installers it reads since
    /// docs/M7.md.
    pub backend: Option<String>,
    /// Whether it opens here: false while its backend is missing, too old or turned off.
    pub available: bool,
    /// Explorer's menu offers BeeZip's items on its extensions. The 7-Zip formats' `.img`,
    /// `.exe` and `.msi` are left out (docs/M6.md §3.7).
    pub menu: bool,
}

/// The 7-Zip that reads the formats BeeZip leaves to it (docs/M6.md §3.1), as found under the
/// settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SevenZipStatus {
    /// "7-Zip 26.00"; `null` when there's none to run.
    pub name: Option<String>,
    pub path: Option<PathBuf>,
    /// Where it was found: `settings`, `registry`, `PATH` or `Program Files`.
    pub found_in: Option<String>,
    /// Why there's none to run: not found, too old, turned off.
    pub problem: Option<String>,
    /// The oldest version BeeZip runs: `25.01`.
    pub min_version: String,
    /// What would give BeeZip a 7-Zip to run: `install` or `update` it with winget
    /// (`seven_zip.install`), or `download` it from 7-zip.org where there's no winget. `null`
    /// when there's one to run, when it's turned off, or when the trouble is the path in the
    /// settings, which installing wouldn't change.
    pub fix: Option<SevenZipFix>,
}

/// How to get a 7-Zip BeeZip can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "lowercase")]
pub enum SevenZipFix {
    /// None is installed: `winget install`.
    Install,
    /// The one installed is older than 25.01: `winget upgrade`.
    Update,
    /// No winget (or not Windows): 7-zip.org's download page.
    Download,
}

impl SevenZipFix {
    /// The fix for `found`, under `opts`, with or without winget.
    pub fn choose(
        opts: &beezip_core::SevenZipOptions,
        found: &Result<beezip_core::backend::SevenZip, beezip_core::backend::find::Missing>,
        winget: bool,
    ) -> Option<Self> {
        use beezip_core::backend::find::Missing;
        let Err(missing) = found else { return None };
        if !opts.enabled || opts.path.is_some() {
            return None;
        }
        Some(match missing {
            _ if !winget => Self::Download,
            Missing::TooOld(_) => Self::Update,
            _ => Self::Install,
        })
    }
}

impl SevenZipStatus {
    /// What `find` says under `opts`.
    pub fn find(opts: &beezip_core::SevenZipOptions) -> Self {
        let found = beezip_core::backend::find(opts);
        let fix = SevenZipFix::choose(opts, &found, crate::winget::find().is_some());
        Self::from_found(found, fix)
    }

    /// The status for what `find` returned.
    pub fn from_found(
        found: Result<beezip_core::backend::SevenZip, beezip_core::backend::find::Missing>,
        fix: Option<SevenZipFix>,
    ) -> Self {
        let (major, minor) = beezip_core::backend::MIN_VERSION;
        let min_version = format!("{major}.{minor:02}");
        match found {
            Ok(z) => Self {
                name: Some(z.name),
                path: Some(z.exe),
                found_in: Some(z.found_in.to_owned()),
                problem: None,
                min_version,
                fix: None,
            },
            Err(m) => Self {
                name: None,
                path: None,
                found_in: None,
                problem: Some(m.reason()),
                min_version,
                fix,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CodecInfo {
    pub id: String,
    pub name: String,
    pub extensions: Vec<String>,
    pub levels: Option<LevelRange>,
    /// Multithreaded compression.
    pub threads: bool,
    /// Recognised by its content. Raw deflate has no magic and is never detected.
    pub detected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct FormatsListOutput {
    pub formats: Vec<FormatInfo>,
    pub codecs: Vec<CodecInfo>,
    /// The `--format` names `archive.create` accepts: `zip`, `tar`, `tar.gz`…
    pub create: Vec<String>,
    /// The 7-Zip found, which the formats with `backend: "7-zip"` need.
    pub seven_zip: SevenZipStatus,
}

pub struct FormatsList;

impl Command for FormatsList {
    const NAME: &'static str = "formats.list";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "formats",
        aliases: &[],
        group: None,
    });

    type Input = FormatsListInput;
    type Output = FormatsListOutput;

    fn run(_: FormatsListInput, cx: &mut JobCtx) -> Result<FormatsListOutput, CmdError> {
        let seven_zip = SevenZipStatus::find(&crate::commands::util::seven_zip(cx));
        let formats = FormatId::ALL
            .into_iter()
            .map(|f| {
                let method = |id: &str, levels: Option<beezip_core::Levels>| MethodInfo {
                    id: id.into(),
                    levels: levels.map(Into::into),
                };
                FormatInfo {
                    id: f.name().into(),
                    name: f.display_name().into(),
                    extensions: f
                        .format()
                        .extensions()
                        .iter()
                        .map(|e| (*e).into())
                        .collect(),
                    caps: caps_for(f, &[]).into(),
                    methods: match f {
                        FormatId::Zip => ZipMethod::ALL
                            .into_iter()
                            .map(|m| method(m.name(), m.levels()))
                            .collect(),
                        FormatId::SevenZ => SevenZMethod::ALL
                            .into_iter()
                            .map(|m| method(m.name(), m.levels()))
                            .collect(),
                        FormatId::Cab => CabMethod::ALL
                            .into_iter()
                            .map(|m| method(m.name(), None))
                            .collect(),
                        FormatId::Squashfs => SquashfsMethod::ALL
                            .into_iter()
                            .map(|m| method(m.name(), m.levels()))
                            .collect(),
                        _ => Vec::new(),
                    },
                    encryption: match f {
                        FormatId::Zip => vec!["aes256".into(), "zipcrypto".into()],
                        FormatId::SevenZ => vec!["aes256".into()],
                        _ => Vec::new(),
                    },
                    backend: f
                        .external()
                        .filter(|k| !k.native())
                        .map(|_| "7-zip".to_owned()),
                    available: f.external().is_none_or(beezip_core::External::native)
                        || seven_zip.name.is_some(),
                    menu: f.external().is_none_or(beezip_core::External::in_menu),
                }
            })
            .collect();
        let codecs = CodecId::ALL
            .into_iter()
            .map(|c| {
                let codec = c.codec();
                CodecInfo {
                    id: c.name().into(),
                    name: c.display_name().into(),
                    extensions: codec.extensions().iter().map(|e| (*e).into()).collect(),
                    levels: codec.levels().map(Into::into),
                    threads: codec.threads(),
                    detected: c != CodecId::Deflate,
                }
            })
            .collect();
        Ok(FormatsListOutput {
            formats,
            codecs,
            create: ArchiveKind::all().map(ArchiveKind::name).collect(),
            seven_zip,
        })
    }

    fn human(out: &FormatsListOutput) -> Option<String> {
        let yes = |b: bool| if b { "yes" } else { "-" };
        let mut s = String::from("Archive formats\n");
        s.push_str(&format!(
            "  {:<8} {:<16} {:<5} {:<7} {:<6} {:<8} {:<6}  {}\n",
            "ID", "NAME", "LIST", "EXTRACT", "CREATE", "ENCRYPT", "RANDOM", "EXTENSIONS"
        ));
        for f in out.formats.iter().filter(|f| f.backend.is_none()) {
            s.push_str(&format!(
                "  {:<8} {:<16} {:<5} {:<7} {:<6} {:<8} {:<6}  {}\n",
                f.id,
                f.name,
                yes(f.caps.list),
                yes(f.caps.extract),
                yes(f.caps.create),
                yes(f.caps.encrypt),
                yes(f.caps.random_access),
                f.extensions.join(" ")
            ));
        }
        let z = &out.seven_zip;
        s.push_str(&match (&z.name, &z.path, &z.problem) {
            (Some(name), Some(path), _) => {
                format!(
                    "\nRead through {name} ({}), list and extract\n",
                    path.display()
                )
            }
            (_, _, problem) => format!(
                "\nRead through 7-Zip {} or newer, list and extract: {}\n",
                z.min_version,
                problem.as_deref().unwrap_or("not found")
            ),
        });
        for f in out.formats.iter().filter(|f| f.backend.is_some()) {
            let exts = if f.extensions.is_empty() {
                "(an installer program)".to_owned()
            } else {
                f.extensions.join(" ")
            };
            s.push_str(&format!("  {:<8} {:<26} {}\n", f.id, f.name, exts));
        }
        for f in out.formats.iter().filter(|f| !f.methods.is_empty()) {
            let methods: Vec<String> = f
                .methods
                .iter()
                .map(|m| match m.levels {
                    Some(l) => format!("{} ({}-{}, {})", m.id, l.min, l.max, l.default),
                    None => m.id.clone(),
                })
                .collect();
            s.push_str(&format!("  {} methods: {}\n", f.id, methods.join(", ")));
        }
        s.push_str("\nCodecs\n");
        s.push_str(&format!(
            "  {:<8} {:<18} {:<12} {:<7}  {}\n",
            "ID", "NAME", "LEVELS", "THREADS", "EXTENSIONS"
        ));
        for c in &out.codecs {
            let levels = c
                .levels
                .map(|l| format!("{}-{} ({})", l.min, l.max, l.default))
                .unwrap_or_else(|| "-".into());
            let ext = if c.detected {
                c.extensions.join(" ")
            } else {
                "(never detected)".into()
            };
            s.push_str(&format!(
                "  {:<8} {:<18} {:<12} {:<7}  {}\n",
                c.id,
                c.name,
                levels,
                yes(c.threads),
                ext
            ));
        }
        s.push_str(&format!("\nCreate as: {}", out.create.join(", ")));
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<FormatsListInput>(
            &[],
            serde_json::json!({}),
        );
    }

    /// Install or update with winget, the download page without it, and nothing when the
    /// trouble is a setting.
    #[test]
    fn the_fix_for_each_kind_of_missing() {
        use beezip_core::{
            SevenZipOptions,
            backend::{SevenZip, find::Missing},
        };
        let old = SevenZip {
            exe: PathBuf::from("7z.exe"),
            name: "7-Zip 23.01".into(),
            version: Some((23, 1)),
            found_in: "registry",
        };
        let none = Missing::NotFound { configured: None };
        let unusable = Missing::Unusable {
            exe: PathBuf::from("7z.exe"),
            why: "it printed no banner".into(),
        };
        let opts = SevenZipOptions::default();
        let fix =
            |found: Result<SevenZip, Missing>, winget| SevenZipFix::choose(&opts, &found, winget);
        assert_eq!(fix(Ok(old.clone()), true), None);
        assert_eq!(fix(Err(none.clone()), true), Some(SevenZipFix::Install));
        assert_eq!(fix(Err(unusable), true), Some(SevenZipFix::Install));
        assert_eq!(
            fix(Err(Missing::TooOld(old.clone())), true),
            Some(SevenZipFix::Update)
        );
        assert_eq!(fix(Err(none.clone()), false), Some(SevenZipFix::Download));
        assert_eq!(
            fix(Err(Missing::TooOld(old)), false),
            Some(SevenZipFix::Download)
        );

        let off = SevenZipOptions {
            enabled: false,
            ..SevenZipOptions::default()
        };
        assert_eq!(
            SevenZipFix::choose(&off, &Err(Missing::Disabled), true),
            None
        );
        let set = SevenZipOptions {
            path: Some(PathBuf::from("Z:/nowhere/7z.exe")),
            ..SevenZipOptions::default()
        };
        let there = Err(Missing::NotFound {
            configured: set.path.clone(),
        });
        assert_eq!(SevenZipFix::choose(&set, &there, true), None);
    }
}
