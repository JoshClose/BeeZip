use beezip_core::{
    CodecId, FormatCaps, FormatId,
    format::{caps_for, zip::ZipMethod},
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

/// A zip compression method BeeZip writes.
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
    /// Methods for new archives (zip only).
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
    });

    type Input = FormatsListInput;
    type Output = FormatsListOutput;

    fn run(_: FormatsListInput, _: &mut JobCtx) -> Result<FormatsListOutput, CmdError> {
        let formats = FormatId::ALL
            .into_iter()
            .map(|f| {
                let zip = f == FormatId::Zip;
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
                    methods: if zip {
                        ZipMethod::ALL
                            .into_iter()
                            .map(|m| MethodInfo {
                                id: m.name().into(),
                                levels: m.levels().map(Into::into),
                            })
                            .collect()
                    } else {
                        Vec::new()
                    },
                    encryption: if zip {
                        vec!["aes256".into(), "zipcrypto".into()]
                    } else {
                        Vec::new()
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
        let zip_methods: Vec<String> = out
            .formats
            .iter()
            .flat_map(|f| &f.methods)
            .map(|m| match m.levels {
                Some(l) => format!("{} ({}-{}, {})", m.id, l.min, l.max, l.default),
                None => m.id.clone(),
            })
            .collect();
        s.push_str(&format!("  zip methods: {}\n", zip_methods.join(", ")));
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
