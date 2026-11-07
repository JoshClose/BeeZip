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

    fn run(_: FormatsListInput, _: &mut JobCtx) -> Result<FormatsListOutput, CmdError> {
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
        })
    }

    fn human(out: &FormatsListOutput) -> Option<String> {
        let yes = |b: bool| if b { "yes" } else { "-" };
        let mut s = String::from("Archive formats\n");
        s.push_str(&format!(
            "  {:<8} {:<16} {:<5} {:<7} {:<6} {:<8} {:<6}  {}\n",
            "ID", "NAME", "LIST", "EXTRACT", "CREATE", "ENCRYPT", "RANDOM", "EXTENSIONS"
        ));
        for f in &out.formats {
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
}
