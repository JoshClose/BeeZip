use std::{io::Read, path::PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::{
    keys_create::made,
    keys_list::{info, keys_dir, store},
};
use crate::{
    CliSpec, CmdError, Command, Effect, JobCtx, Surfaces, commands::util::absolute, crypt::KeyInfo,
    policy::Access, wire::Secret,
};

/// Add a key: a private key (`AGE-SECRET-KEY-…`, `BZSIG-SECRET-KEY-1…`, or an age identity
/// file) becomes yours; a public key (`age1…`, `age1pq1…`, `bzsig1…`) becomes a contact's.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct KeysImportInput {
    /// What to call it.
    pub name: String,
    /// The key as text.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<Secret>,
    /// Or a file that holds it.
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
}

/// A key file is a line or a few; anything much larger isn't one.
const FILE_MAX: u64 = 1 << 20;

pub struct KeysImport;

impl Command for KeysImport {
    const NAME: &'static str = "keys.import";
    const EFFECT: Effect = Effect::Writes;
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "import",
        aliases: &[],
        group: Some("keys"),
    });

    type Input = KeysImportInput;
    type Output = KeyInfo;

    fn run(input: KeysImportInput, cx: &mut JobCtx) -> Result<KeyInfo, CmdError> {
        let text = match (&input.text, &input.file) {
            (Some(text), None) => text.expose().to_owned(),
            (None, Some(file)) => {
                let path = absolute(file);
                let f = std::fs::File::open(&path).map_err(|e| {
                    let e = CmdError::from(beezip_core::Error::from(e));
                    CmdError::new(e.code, format!("{}: {}", path.display(), e.message))
                })?;
                let mut text = String::new();
                f.take(FILE_MAX).read_to_string(&mut text).map_err(|_| {
                    CmdError::invalid_args(format!(
                        "{} isn't a key file: it isn't text",
                        path.display()
                    ))
                })?;
                text
            }
            _ => {
                return Err(CmdError::invalid_args(
                    "give the key with `text` or with `file`, not both",
                ));
            }
        };
        Ok(info(store(cx)?.import(&input.name, &text)?))
    }

    fn human(out: &KeyInfo) -> Option<String> {
        Some(made(out, "Added"))
    }

    fn access(input: &KeysImportInput) -> Vec<Access> {
        let mut access: Vec<Access> = keys_dir().map(Access::Write).into_iter().collect();
        if let Some(file) = &input.file {
            access.push(Access::Read(absolute(file)));
        }
        access
    }
}
