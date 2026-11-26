//! Answering prompts in a terminal (docs/M1.md §5). When stdin and stderr are both terminals,
//! passwords are asked for with a hidden prompt and overwrites with a menu; the progress bar
//! is hidden while asking. Otherwise `NonInteractive` answers, with a hint about which flag
//! to pass.

use std::sync::Arc;

use beezip_commands::{
    CmdError, ErrorCode, Interactor, JobId, OverwriteChoice, Prompt, PromptReply,
    crypt::{SlotKindName, UnlockReply, UnlockWay},
};
use dialoguer::{Confirm, Password, Select, theme::ColorfulTheme};

use crate::progress::Bars;

pub struct TtyInteractor {
    bars: Arc<Bars>,
}

impl TtyInteractor {
    pub fn new(bars: Arc<Bars>) -> Self {
        Self { bars }
    }
}

const CHOICES: [(&str, OverwriteChoice); 5] = [
    ("Replace", OverwriteChoice::Replace),
    ("Replace all", OverwriteChoice::ReplaceAll),
    ("Skip", OverwriteChoice::Skip),
    ("Skip all", OverwriteChoice::SkipAll),
    ("Rename the new file", OverwriteChoice::Rename),
];

impl Interactor for TtyInteractor {
    fn prompt(&self, _job: JobId, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        let theme = ColorfulTheme::default();
        self.bars.suspend(|| match prompt {
            Prompt::Password { entry } => {
                let what = entry
                    .as_deref()
                    .map_or("the archive".to_owned(), |e| format!("`{e}`"));
                match Password::with_theme(&theme)
                    .with_prompt(format!("Password for {what}"))
                    .interact()
                {
                    Ok(password) => Ok(PromptReply::Password { password }),
                    Err(_) => Ok(PromptReply::Cancel),
                }
            }
            Prompt::Overwrite { path, archive } => {
                let items: Vec<&str> = CHOICES.iter().map(|(label, _)| *label).collect();
                let question = match archive {
                    Some(a) => format!("{path} is already in {a}"),
                    None => format!("{path} already exists"),
                };
                match Select::with_theme(&theme)
                    .with_prompt(question)
                    .items(&items)
                    .default(0)
                    .interact_opt()
                {
                    Ok(Some(i)) => Ok(PromptReply::Overwrite {
                        choice: CHOICES[i].1,
                    }),
                    Ok(None) | Err(_) => Ok(PromptReply::Cancel),
                }
            }
            Prompt::Unlock { ways, attempt } => unlock(&theme, ways, *attempt),
        })
    }

    fn spend_memory(&self, _job: JobId, need_mib: u64, total_mib: u64) -> bool {
        let theme = ColorfulTheme::default();
        self.bars.suspend(|| {
            Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Its password takes {need_mib} MiB of memory to check, more than half of \
                     this PC's {total_mib} MiB. Check it anyway?"
                ))
                .default(false)
                .interact()
                .unwrap_or(false)
        })
    }
}

/// A way into an encrypted `.bhive`, as the menu offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    Password,
    RecoveryKey,
    Slot(u32),
}

/// What the Unlock menu offers for `ways`: a password, a recovery key, and each way in a key
/// or device here fits (docs/M14.md §8). A device is only used when it is chosen.
fn unlock_choices(ways: &[UnlockWay]) -> Vec<(String, Way)> {
    let has = |kind| ways.iter().any(|w| w.kind == kind);
    let mut items = Vec::new();
    if has(SlotKindName::Password) {
        items.push(("Type the password".to_owned(), Way::Password));
    }
    if has(SlotKindName::RecoveryKey) {
        items.push(("Type the recovery key".to_owned(), Way::RecoveryKey));
    }
    for w in ways.iter().filter(|w| w.here) {
        let what = match w.kind {
            SlotKindName::Password | SlotKindName::RecoveryKey => continue,
            SlotKindName::PublicKey | SlotKindName::PostQuantumKey => "your key",
            SlotKindName::RsaCertificate | SlotKindName::EcP384 => "your certificate",
            SlotKindName::EcP256 => "your certificate, or This PC",
            SlotKindName::SecurityKey => "a security key or Windows Hello",
        };
        items.push((format!("Use {what} (slot {})", w.slot), Way::Slot(w.slot)));
    }
    items
}

fn unlock(
    theme: &ColorfulTheme,
    ways: &[UnlockWay],
    attempt: u32,
) -> Result<PromptReply, CmdError> {
    if attempt > 0 {
        eprintln!("That didn't open it.");
    }
    let items = unlock_choices(ways);
    let way = match items.as_slice() {
        [] => {
            return Err(CmdError::new(
                ErrorCode::KeyRequired,
                "the archive opens only with a key or a device, and none here fits; pass \
                 --identity with its key file",
            ));
        }
        [(_, way)] => *way,
        _ => {
            let labels: Vec<&str> = items.iter().map(|(l, _)| l.as_str()).collect();
            match Select::with_theme(theme)
                .with_prompt("The archive is encrypted")
                .items(&labels)
                .default(0)
                .interact_opt()
            {
                Ok(Some(i)) => items[i].1,
                Ok(None) | Err(_) => return Ok(PromptReply::Cancel),
            }
        }
    };
    let secret = |prompt: &str| Password::with_theme(theme).with_prompt(prompt).interact();
    let answer = match way {
        Way::Password => match secret("Password") {
            Ok(password) => UnlockReply::Password { password },
            Err(_) => return Ok(PromptReply::Cancel),
        },
        Way::RecoveryKey => match secret("Recovery key (48 digits)") {
            Ok(key) => UnlockReply::RecoveryKey { key },
            Err(_) => return Ok(PromptReply::Cancel),
        },
        Way::Slot(slot) => UnlockReply::Slot { slot },
    };
    Ok(PromptReply::Unlock { answer })
}

/// With nobody at a terminal, prompts fail with a hint about the flag to pass instead.
pub struct CliNonInteractive;

impl Interactor for CliNonInteractive {
    fn prompt(&self, _job: JobId, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        Err(match prompt {
            Prompt::Password { entry } => {
                let what = entry
                    .as_deref()
                    .map_or("the archive".to_owned(), |e| format!("`{e}`"));
                CmdError::new(
                    ErrorCode::PasswordRequired,
                    format!("{what} needs a password; pass --password (-p)"),
                )
                .with_details(serde_json::json!({ "param": "password" }))
            }
            Prompt::Overwrite { path, archive } => CmdError::new(
                ErrorCode::Conflict,
                match archive {
                    Some(a) => format!(
                        "`{path}` is already in {a}; pass --overwrite always|never|rename|newer"
                    ),
                    None => format!(
                        "`{path}` already exists; pass --overwrite always|never|rename|newer"
                    ),
                },
            ),
            Prompt::Unlock { .. } => CmdError::new(
                ErrorCode::KeyRequired,
                "the archive is encrypted; pass --password with its password or recovery key, \
                 or --identity with a key file",
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn way(slot: u32, kind: SlotKindName, here: bool) -> UnlockWay {
        UnlockWay { slot, kind, here }
    }

    #[test]
    fn the_unlock_menu_offers_what_fits() {
        let ways = [
            way(0, SlotKindName::Password, false),
            way(1, SlotKindName::RecoveryKey, false),
            way(2, SlotKindName::PostQuantumKey, true),
            way(3, SlotKindName::SecurityKey, true),
            way(4, SlotKindName::RsaCertificate, false),
            way(5, SlotKindName::Password, false),
        ];
        let items: Vec<Way> = unlock_choices(&ways).into_iter().map(|(_, w)| w).collect();
        assert_eq!(
            items,
            [Way::Password, Way::RecoveryKey, Way::Slot(2), Way::Slot(3)]
        );
        assert!(unlock_choices(&[way(0, SlotKindName::EcP256, false)]).is_empty());
    }

    #[test]
    fn nobody_at_the_terminal() {
        let e = CliNonInteractive
            .prompt(
                1,
                1,
                &Prompt::Unlock {
                    ways: vec![way(0, SlotKindName::Password, false)],
                    attempt: 0,
                },
            )
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::KeyRequired);
        assert_eq!(e.exit_code(), 15);
    }
}
