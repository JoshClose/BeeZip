use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use beezip_core::format::bhive::{
    BhiveWriteOptions,
    crypt::{Labelled, Protection, Recipient, SlotKind, envelope::Unlocked},
};

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx, LogLevel, Surfaces,
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
    /// Add a security key: Windows asks for a touch. Windows only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_key: Option<bool>,
    /// Add Windows Hello (a face, a fingerprint or its PIN). It works only on this PC, so it
    /// needs another way in that works elsewhere. Windows only.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_hello: Option<bool>,
    /// How hard an added password makes guessing [default: standard].
    #[arg(long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strength: Option<StrengthName>,
    /// Remove these ways in, by slot, as `archive.protection` lists them.
    #[arg(long, value_name = "SLOT")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<Vec<u32>>,
    /// Make a new file key: every cell sealed again, every slot rebuilt. A password slot is
    /// rebuilt with `add_password` (one password slot), a recovery key is new, a security key or
    /// Windows Hello needs a touch.
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
            windows_hello: self.windows_hello.unwrap_or(false),
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
        let mut kept: Vec<WayIn> = Vec::new();
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
                    // Kept: the file key and every slot not removed, byte for byte; the
                    // contents, and so their signatures, stay as they are.
                    let mut ways = changed(&input, &unlocked, &slots, &remove, cx)?;
                    ways.make_devices(cx)?;
                    kept = kept_ways(&unlocked, &slots, &remove);
                    made = ways.recipients.clone();
                    recovery_key = ways.recovery_key;
                    return Ok(BhiveWriteOptions {
                        threads,
                        protection: Some(Protection::Change {
                            from: unlocked,
                            remove: remove.iter().map(|&r| r as usize).collect(),
                            add: ways.recipients,
                        }),
                        ..BhiveWriteOptions::default()
                    });
                }
                // The contents stay the same, so the writer carries their signatures over.
                let mut ways = rebuilt(&input, &slots, &remove, &confirm, cx)?;
                // Last, once everything else has been checked.
                ways.make_devices(cx)?;
                let recipients = ways.recipients;
                made = recipients.clone();
                recovery_key = ways.recovery_key;
                Ok(BhiveWriteOptions {
                    threads,
                    protection: Some(Protection::New(recipients)),
                    ..BhiveWriteOptions::default()
                })
            },
        )?;
        // The slots kept come first, then the ones made, as the key block has them.
        let mut ways = kept;
        let first = ways.len() as u32;
        ways.extend(protect::ways_of(&made).into_iter().map(|mut w| {
            w.slot += first;
            w
        }));
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

/// The ways in an archive keeps when its file key stays, numbered as the new key block has
/// them: each slot not removed, in order, with what its description says.
fn kept_ways(unlocked: &Unlocked, slots: &[protect::Slot], remove: &[u32]) -> Vec<WayIn> {
    let mut out = Vec::new();
    let mut next = 0;
    for i in 0..unlocked.kinds().len() as u32 {
        if remove.contains(&i) {
            continue;
        }
        // A slot of a kind this BeeZip doesn't know is kept too, unlisted.
        if let Some(slot) = slots.iter().find(|s| s.index == i) {
            let mut w = protect::way_in(slot);
            w.slot = next;
            out.push(w);
        }
        next += 1;
    }
    out
}

/// Whether a slot kept opens the archive away from this PC (decision 11): any but This PC and
/// Windows Hello.
fn leaves_this_pc(slot: &protect::Slot) -> bool {
    if slot.kind == SlotKind::Fido2 {
        return protect::security_key_device(slot).is_ok_and(|d| !d.machine_bound());
    }
    !slot.description.machine_bound
}

/// The ways in that adding makes while the archive keeps its file key and the slots not
/// removed (docs/M14.md §3), devices still to ask. What is left must open it away from this PC.
fn changed(
    input: &ArchiveProtectInput,
    unlocked: &Unlocked,
    slots: &[protect::Slot],
    remove: &[u32],
    cx: &mut JobCtx,
) -> Result<protect::Ways, CmdError> {
    let left = unlocked.kinds().len().saturating_sub(remove.len());
    let known_left: Vec<&protect::Slot> = slots
        .iter()
        .filter(|s| !remove.contains(&s.index))
        .collect();
    // A kind this BeeZip doesn't know counts as a way in that works elsewhere, as for core.
    let leaves = left > known_left.len() || known_left.iter().any(|s| leaves_this_pc(s));
    let ways = protect::ways(
        &WaysArgs {
            kept: leaves,
            ..input.ways()
        },
        cx,
    )?;
    let added = !ways.recipients.is_empty() || !ways.devices.is_empty();
    if left == 0 && !added {
        return Err(CmdError::invalid_args(
            "that would leave the archive with no way in",
        ));
    }
    if !leaves {
        if !added {
            return Err(CmdError::invalid_args(
                "every way in left would work only on this PC, so the archive would be lost \
                 with it. Keep or add a password, a recovery key or someone's key.",
            ));
        }
        protect::leaves_the_machine(&ways.recipients, &ways.devices)?;
    }
    // Decision 12: a password beside other people's keys, when this change puts them together.
    let key = |s: &protect::Slot| match s.kind {
        SlotKind::X25519 | SlotKind::XWing | SlotKind::Rsa | SlotKind::EcP384 => true,
        SlotKind::EcP256 => !s.description.machine_bound,
        _ => false,
    };
    let has_password = known_left.iter().any(|s| s.kind == SlotKind::Password);
    let has_key = known_left.iter().any(|s| key(s));
    let adds_password = input.add_password.is_some();
    let adds_key = input.to.as_ref().is_some_and(|t| !t.is_empty())
        || input.to_cert.as_ref().is_some_and(|t| !t.is_empty());
    if (adds_password && (has_key || adds_key)) || (adds_key && has_password) {
        protect::warn_password_beside_keys(cx);
    }
    Ok(ways)
}

/// Every way in "New key" writes (docs/M14.md §3), devices still to ask: each slot kept is
/// rebuilt with fresh randomness, its recipient taken from the archive's description of it
/// only when it names one of your keys or contacts or a This PC key this PC has, or `confirm`
/// names it; then the ways in the input adds. Nothing is asked of a device here, and a
/// recovery key is made only once every recipient has been accepted.
fn rebuilt(
    input: &ArchiveProtectInput,
    slots: &[protect::Slot],
    remove: &[u32],
    confirm: &[u32],
    cx: &mut JobCtx,
) -> Result<protect::Ways, CmdError> {
    let store = cx.key_store().ok();
    let this_pc = cx.this_pc_keys();
    let strength = input.strength.unwrap_or_default().into();
    let mut ways = protect::Ways::default();
    let mut passwords: Vec<&protect::Slot> = Vec::new();
    let mut recovery = false;
    let mut unconfirmed: Vec<WayIn> = Vec::new();
    for slot in slots.iter().filter(|s| !remove.contains(&s.index)) {
        let label = slot.description.label.clone();
        match slot.kind {
            SlotKind::Password => passwords.push(slot),
            SlotKind::RecoveryKey => recovery = true,
            SlotKind::Fido2 => ways.devices.push(protect::security_key_device(slot)?),
            _ => {
                let Some(recipient) = protect::described_recipient(slot)? else {
                    continue;
                };
                if protect::known_recipient(slot, store.as_ref(), &this_pc)
                    || confirm.contains(&slot.index)
                {
                    ways.recipients.push(Labelled { recipient, label });
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
    // One password slot, from `add_password`: its old password can't be read back.
    if let Some(first) = passwords.first() {
        let password = input.add_password.as_ref().ok_or_else(|| {
            CmdError::invalid_args(format!(
                "slot {} is a password: pass it (or a new one) as `add_password` to keep it with \
                 the new key, or `remove` it",
                first.index
            ))
        })?;
        ways.recipients.push(protect::password_recipient(
            password.expose(),
            strength,
            first.description.label.clone(),
        ));
        if passwords.len() > 1 {
            let others: Vec<String> = passwords[1..].iter().map(|s| s.index.to_string()).collect();
            cx.log(
                LogLevel::Warn,
                format!(
                    "slots {} were passwords too: the new key has one password slot, with the \
                     password given",
                    others.join(", ")
                ),
            );
        }
    }
    // The ways the input adds; a password given already rebuilt the password slot.
    let added = WaysArgs {
        password: if passwords.is_empty() {
            input.add_password.as_ref()
        } else {
            None
        },
        recovery_key: input.recovery_key.unwrap_or(false) && !recovery,
        strength: if passwords.is_empty() {
            input.strength
        } else {
            None
        },
        kept: !ways.recipients.is_empty() || !ways.devices.is_empty(),
        ..input.ways()
    };
    let added = protect::ways(&added, cx)?;
    ways.recipients.extend(added.recipients);
    ways.devices.extend(added.devices);
    ways.recovery_key = added.recovery_key;
    if recovery {
        let (made, shown) = protect::new_recovery_key(cx)?;
        ways.recipients.push(made);
        ways.recovery_key = Some(shown);
    }
    // Decision 12, on every way in the new key has.
    let password = ways
        .recipients
        .iter()
        .any(|l| l.recipient.kind() == SlotKind::Password);
    let others = ways.recipients.iter().any(|l| {
        matches!(
            l.recipient,
            Recipient::X25519(_)
                | Recipient::XWing(_)
                | Recipient::Rsa { .. }
                | Recipient::Ec {
                    machine_bound: false,
                    ..
                }
        )
    });
    if password && others {
        protect::warn_password_beside_keys(cx);
    }
    ways.check()?;
    Ok(ways)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{
        Engine, EngineOptions, EventSink, JobEvent, NonInteractive, Registry,
        protect::{Description, Device, Slot},
    };

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<ArchiveProtectInput>(
            &["a.bhive", "--new-key", "--confirm", "2", "--remove", "1"],
            serde_json::json!({ "archive": "a.bhive", "new_key": true, "confirm": [2], "remove": [1] }),
        );
    }

    fn slot(index: u32, kind: SlotKind, public: Vec<u8>, description: Description) -> Slot {
        Slot {
            index,
            kind,
            public,
            description,
        }
    }

    fn x25519(index: u32, key: u8) -> Slot {
        slot(
            index,
            SlotKind::X25519,
            Vec::new(),
            Description {
                label: Some(format!("key {key}")),
                public_key: Some(vec![key; 32]),
                ..Description::default()
            },
        )
    }

    fn password(index: u32) -> Slot {
        slot(
            index,
            SlotKind::Password,
            Vec::new(),
            Description::default(),
        )
    }

    /// A security key's slot (flags 2) or Windows Hello's (flags 3), with credential `aa bb`.
    fn fido2(index: u32, flags: u8) -> Slot {
        slot(
            index,
            SlotKind::Fido2,
            vec![flags, 0, 2, 0, 0xAA, 0xBB],
            Description::default(),
        )
    }

    /// The slots of one case, and the input that rebuilds them.
    fn case(name: &str) -> (Vec<Slot>, ArchiveProtectInput) {
        let mut input = ArchiveProtectInput {
            archive: "a.bhive".into(),
            password: None,
            add_password: Some(Secret::new("new")),
            recovery_key: None,
            to: None,
            to_cert: None,
            this_pc: None,
            this_pc_pin: None,
            security_key: None,
            windows_hello: None,
            strength: None,
            remove: None,
            new_key: Some(true),
            confirm: None,
        };
        let slots = match name {
            "two passwords and a key" => vec![password(0), password(1), x25519(2, 9)],
            "unconfirmed first" => vec![
                slot(0, SlotKind::RecoveryKey, Vec::new(), Description::default()),
                fido2(1, 3),
                x25519(2, 9),
            ],
            "devices" => vec![fido2(0, 3), fido2(1, 2), password(2)],
            "hello alone" => {
                input.add_password = None;
                vec![fido2(0, 3), password(1)]
            }
            "no password given" => {
                input.add_password = None;
                vec![password(0), x25519(1, 9)]
            }
            other => panic!("no case {other}"),
        };
        (slots, input)
    }

    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
    struct RebuildInput {
        #[arg(long)]
        case: String,
        #[arg(long)]
        confirm: Vec<u32>,
        #[arg(long)]
        remove: Vec<u32>,
    }

    struct TestRebuild;

    impl Command for TestRebuild {
        const NAME: &'static str = "test.rebuild";
        const EFFECT: Effect = Effect::ReadOnly;
        type Input = RebuildInput;
        type Output = Vec<String>;

        /// What "New key" would write for the case: each way in, then each device to ask.
        fn run(input: RebuildInput, cx: &mut JobCtx) -> Result<Vec<String>, CmdError> {
            let (slots, protect) = case(&input.case);
            let ways = rebuilt(&protect, &slots, &input.remove, &input.confirm, cx)?;
            let mut out: Vec<String> = ways
                .recipients
                .iter()
                .map(|l| {
                    format!(
                        "{:?} {}",
                        l.recipient.kind(),
                        l.label.clone().unwrap_or_default()
                    )
                })
                .collect();
            out.extend(ways.devices.iter().map(|d| match d {
                Device::ThisPc(_) => "this pc".to_owned(),
                Device::Fido2 {
                    hello, credential, ..
                } => format!("fido2 hello={hello} credential={credential:02x?}"),
            }));
            Ok(out)
        }
    }

    fn rebuild(args: serde_json::Value) -> (Result<serde_json::Value, CmdError>, Vec<String>) {
        let mut r = Registry::new();
        r.register::<TestRebuild>();
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::with_options(
            Box::leak(Box::new(r)),
            EngineOptions {
                config_path: Some(dir.path().join("config.toml")),
                ..EngineOptions::default()
            },
        );
        let logs = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&logs);
        let sink: EventSink = Arc::new(move |e| {
            if let JobEvent::Log { message, .. } = e {
                seen.lock().unwrap().push(message);
            }
        });
        let r = engine
            .invoke("test.rebuild", args, Arc::new(NonInteractive), sink)
            .unwrap()
            .join();
        let logs = logs.lock().unwrap().clone();
        (r, logs)
    }

    #[test]
    fn new_key_rebuilds_one_password_and_only_confirmed_keys() {
        // A key nobody confirmed: refused, and listed.
        let (r, _) = rebuild(serde_json::json!({
            "case": "two passwords and a key", "confirm": [], "remove": []
        }));
        let e = r.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
        assert!(e.message.contains("slot 2"), "{}", e.message);
        assert_eq!(e.details.unwrap()["unconfirmed"][0]["slot"], 2);

        // Confirmed: the key, then one password slot from `add_password`, with a warning for
        // the second password and for a password beside someone's key (decision 12).
        let (r, logs) = rebuild(serde_json::json!({
            "case": "two passwords and a key", "confirm": [2], "remove": []
        }));
        assert_eq!(
            r.unwrap(),
            serde_json::json!(["X25519 key 9", "Password Password"])
        );
        assert!(
            logs.iter()
                .any(|l| l.contains("slots 1 were passwords too")),
            "{logs:?}"
        );
        assert!(
            logs.iter().any(|l| l.contains("your password opens")),
            "{logs:?}"
        );

        // Removed instead: no key, no warning about one.
        let (r, logs) = rebuild(serde_json::json!({
            "case": "two passwords and a key", "confirm": [], "remove": [1, 2]
        }));
        assert_eq!(r.unwrap(), serde_json::json!(["Password Password"]));
        assert!(
            !logs.iter().any(|l| l.contains("your password opens")),
            "{logs:?}"
        );

        // A password slot needs `add_password`.
        let (r, _) = rebuild(serde_json::json!({
            "case": "no password given", "confirm": [1], "remove": []
        }));
        let e = r.unwrap_err();
        assert!(e.message.contains("slot 0 is a password"), "{}", e.message);
    }

    #[test]
    fn new_key_asks_nothing_before_every_key_is_accepted() {
        // The recovery key isn't made and no device is listed before the unconfirmed key is
        // refused.
        let (r, _) = rebuild(serde_json::json!({
            "case": "unconfirmed first", "confirm": [], "remove": []
        }));
        let e = r.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs, "{e:?}");
        assert!(e.details.is_some());

        // Devices are listed to ask last, each with its own credential; Windows Hello's by its
        // PRF flag.
        let (r, _) = rebuild(serde_json::json!({ "case": "devices", "confirm": [], "remove": [] }));
        assert_eq!(
            r.unwrap(),
            serde_json::json!([
                "Password Password",
                "fido2 hello=true credential=Some([aa, bb])",
                "fido2 hello=false credential=Some([aa, bb])",
            ])
        );
        // Windows Hello alone would work only here (decision 11).
        let (r, _) =
            rebuild(serde_json::json!({ "case": "hello alone", "confirm": [], "remove": [1] }));
        let e = r.unwrap_err();
        assert!(e.message.contains("only on this PC"), "{}", e.message);
    }
}
