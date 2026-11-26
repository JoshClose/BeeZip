use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use beezip_core::format::bhive::{
    BhiveWriteOptions,
    crypt::{Labelled, Protection, SlotKind},
};

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx, Surfaces,
    commands::util::not_built,
    crypt::{StrengthName, WayIn},
    protect::{self, WaysArgs},
    wire::Secret,
};

/// Change who can open an encrypted `.bhive`, without recompressing it: add ways in, remove
/// them, or make a new file key, which seals every cell again and rebuilds every slot.
/// Removing a way in isn't revoking it: someone who opened the archive before could have kept
/// its key; a new key is what shuts them out of later versions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct ArchiveProtectInput {
    /// The archive.
    pub archive: PathBuf,
    /// The password or recovery key that opens it, if none of your keys does.
    #[arg(short, long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Add a password.
    #[arg(long, value_name = "PASSWORD")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_password: Option<Secret>,
    /// Add a recovery key, shown once in the output.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<bool>,
    /// Add public keys: `age1…`, `age1pq1…`, or a contact's name.
    #[arg(long, value_name = "KEY")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    /// Add certificates: a thumbprint in your stores, or a certificate file.
    #[arg(long, value_name = "CERT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_cert: Option<Vec<String>>,
    /// Add this PC (a key in its TPM). Windows only; needs another way in that works
    /// elsewhere.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_pc: Option<bool>,
    /// A PIN for the This PC key, which the TPM protects against guessing.
    #[arg(long, value_name = "PIN")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_pc_pin: Option<Secret>,
    /// Add a security key or Windows Hello: Windows asks for a touch. Windows only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_key: Option<bool>,
    /// How hard an added password makes guessing [default: standard].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strength: Option<StrengthName>,
    /// Remove these ways in, by slot, as `archive.protection` lists them.
    #[arg(long, value_name = "SLOT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<Vec<u32>>,
    /// Make a new file key: every cell sealed again, every slot rebuilt. A password slot is
    /// rebuilt with `add_password`, a recovery key is new, a security key needs a touch.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_key: Option<bool>,
    /// With `new_key`, rebuild these ways in, by slot, although their keys or certificates
    /// aren't among your keys and contacts. What the archive says of whose they are is a claim
    /// anyone who could open it could have changed: check each in `archive.protection` first.
    #[arg(long, value_name = "SLOT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<Vec<u32>>,
}

impl ArchiveProtectInput {
    fn ways(&self) -> WaysArgs<'_> {
        WaysArgs {
            password: self.add_password.as_ref(),
            recovery_key: self.recovery_key.unwrap_or(false),
            to: self.to.as_deref().unwrap_or_default(),
            to_cert: self.to_cert.as_deref().unwrap_or_default(),
            this_pc: self.this_pc.unwrap_or(false),
            this_pc_pin: self.this_pc_pin.as_ref(),
            security_key: self.security_key.unwrap_or(false),
            strength: self.strength,
            kept: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArchiveProtectOutput {
    pub ways: Vec<WayIn>,
    pub post_quantum: bool,
    /// A recovery key that was added: shown this once, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub recovery_key: Option<Secret>,
}

pub struct ArchiveProtect;

impl Command for ArchiveProtect {
    const NAME: &'static str = "archive.protect";
    const EFFECT: Effect = Effect::Destructive;
    // Not over MCP: it may make recovery keys and touch devices, and it can lock people out.
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "protect",
        aliases: &[],
        group: None,
    });

    type Input = ArchiveProtectInput;
    type Output = ArchiveProtectOutput;

    fn access(input: &ArchiveProtectInput) -> Vec<Access> {
        vec![Access::Write(input.archive.clone())]
    }

    fn run(input: ArchiveProtectInput, cx: &mut JobCtx) -> Result<ArchiveProtectOutput, CmdError> {
        let remove = input.remove.clone().unwrap_or_default();
        let new_key = input.new_key.unwrap_or(false);
        let confirm = input.confirm.clone().unwrap_or_default();
        let ways = input.ways();
        if ways.is_empty() && remove.is_empty() && !new_key {
            return Err(CmdError::invalid_args(
                "nothing to change: add a way in, remove one (`remove`), or make a new key \
                 (`new_key`)",
            ));
        }
        if !confirm.is_empty() && !new_key {
            return Err(CmdError::invalid_args(
                "`confirm` is for `new_key`: the ways in it rebuilds",
            ));
        }
        let threads = cx.config()?.create.threads;
        let mut made: Vec<Labelled> = Vec::new();
        let mut recovery_key = None;
        protect::rewrite_bhive(
            &input.archive,
            input.password.as_ref(),
            cx,
            |path, reader, cx| {
                let Some(unlocked) = reader.unlocked().cloned() else {
                    return Err(CmdError::invalid_args(format!(
                        "{} isn't encrypted: `archive.convert` with a password or a key \
                         encrypts it",
                        input.archive.display()
                    )));
                };
                let slots = protect::slots(path, Some(reader))?.unwrap_or_default();
                for r in remove.iter().chain(&confirm) {
                    if !slots.iter().any(|s| s.index == *r) {
                        return Err(CmdError::invalid_args(format!(
                            "the archive has no slot {r}; `archive.protection` lists them"
                        )));
                    }
                }
                if !new_key {
                    // Kept: the file key and every slot not removed, byte for byte.
                    let _ = unlocked;
                    return Err(not_built(
                        "adding and removing ways in while keeping the file key (pass \
                         `new_key` to rebuild them all)",
                    ));
                }
                let (recipients, key) = rebuilt(&input, &slots, &remove, &confirm, cx)?;
                protect::leaves_the_machine(&recipients)?;
                made = recipients.clone();
                recovery_key = key;
                Ok(BhiveWriteOptions {
                    threads,
                    protection: Some(Protection::New(recipients)),
                    ..BhiveWriteOptions::default()
                })
            },
        )?;
        let ways = protect::ways_of(&made);
        Ok(ArchiveProtectOutput {
            post_quantum: protect::post_quantum(&ways),
            ways,
            recovery_key,
        })
    }

    fn human(out: &ArchiveProtectOutput) -> Option<String> {
        let mut s = protect::protection_text(&crate::commands::ArchiveProtectionOutput {
            encrypted: true,
            ways: out.ways.clone(),
            post_quantum: out.post_quantum,
        })
        .trim_start()
        .to_owned();
        if let Some(key) = &out.recovery_key {
            s.push_str(&crate::commands::archive_create::recovery_key_text(key));
        }
        Some(s)
    }
}

/// Every way in "New key" writes (docs/M14.md §3): each slot kept is rebuilt with fresh
/// randomness, its recipient taken from the archive's description of it only when it is one
/// of your keys or contacts, or `confirm` names it; then the ways in the input adds.
fn rebuilt(
    input: &ArchiveProtectInput,
    slots: &[protect::Slot],
    remove: &[u32],
    confirm: &[u32],
    cx: &mut JobCtx,
) -> Result<(Vec<Labelled>, Option<Secret>), CmdError> {
    let store = cx.key_store();
    let strength = input.strength.unwrap_or_default().into();
    let mut out = Vec::new();
    let mut recovery_key = None;
    let mut password_used = false;
    let mut unconfirmed: Vec<WayIn> = Vec::new();
    for slot in slots.iter().filter(|s| !remove.contains(&s.index)) {
        let label = slot.description.label.clone();
        match slot.kind {
            SlotKind::Password => {
                let password = input.add_password.as_ref().ok_or_else(|| {
                    CmdError::invalid_args(format!(
                        "slot {} is a password: pass it (or a new one) as `add_password` to \
                         keep it with the new key, or `remove` it",
                        slot.index
                    ))
                })?;
                password_used = true;
                out.push(protect::password_recipient(
                    password.expose(),
                    strength,
                    label,
                ));
            }
            SlotKind::RecoveryKey => {
                if recovery_key.is_none() {
                    let (made, shown) = protect::new_recovery_key(cx)?;
                    recovery_key = Some(shown);
                    out.push(made);
                }
            }
            SlotKind::Fido2 => out.push(protect::rebuild_security_key(slot, cx)?),
            _ => {
                let Some(recipient) = protect::described_recipient(slot)? else {
                    continue;
                };
                if protect::known_recipient(slot, &store) || confirm.contains(&slot.index) {
                    out.push(Labelled { recipient, label });
                } else {
                    unconfirmed.push(protect::way_in(slot));
                }
            }
        }
    }
    if !unconfirmed.is_empty() {
        let list: Vec<String> = unconfirmed
            .iter()
            .map(|w| {
                let who = w
                    .recipient
                    .clone()
                    .or_else(|| w.label.clone())
                    .unwrap_or_else(|| "a key".into());
                format!("slot {} ({who})", w.slot)
            })
            .collect();
        return Err(CmdError::new(
            ErrorCode::InvalidArgs,
            format!(
                "a new key would be given to keys that aren't among your keys or contacts: {}. \
                 What the archive says of them could have been changed by anyone who could open \
                 it. Check each with `archive.protection`, then pass `confirm` with its slot, or \
                 `remove` it.",
                list.join(", ")
            ),
        )
        .with_details(serde_json::json!({ "unconfirmed": unconfirmed })));
    }
    // The ways the input adds; a password given already rebuilt the password slots.
    let added = WaysArgs {
        password: if password_used {
            None
        } else {
            input.add_password.as_ref()
        },
        recovery_key: input.recovery_key.unwrap_or(false) && recovery_key.is_none(),
        strength: if password_used { None } else { input.strength },
        kept: !out.is_empty(),
        ..input.ways()
    };
    let added = protect::ways(&added, cx)?;
    out.extend(added.recipients);
    Ok((out, recovery_key.or(added.recovery_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveProtectInput>(
            &["a.bhive", "--new-key", "--confirm", "2", "--remove", "1"],
            serde_json::json!({ "archive": "a.bhive", "new_key": true, "confirm": [2], "remove": [1] }),
        );
    }
}
