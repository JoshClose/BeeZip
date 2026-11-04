//! Answering prompts in a terminal (docs/M1.md §5). When stdin and stderr are both terminals,
//! passwords are asked for with a hidden prompt and overwrites with a menu; the progress bar
//! is hidden while asking. Otherwise `NonInteractive` answers, with a hint about which flag
//! to pass.

use std::sync::Arc;

use beezip_commands::{
    CmdError, ErrorCode, Interactor, JobId, OverwriteChoice, Prompt, PromptReply,
};
use dialoguer::{Password, Select, theme::ColorfulTheme};

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
            Prompt::Overwrite { path } => {
                let items: Vec<&str> = CHOICES.iter().map(|(label, _)| *label).collect();
                match Select::with_theme(&theme)
                    .with_prompt(format!("{path} already exists"))
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
        })
    }
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
            Prompt::Overwrite { path } => CmdError::new(
                ErrorCode::Conflict,
                format!("`{path}` already exists; pass --overwrite always|never|rename|newer"),
            ),
        })
    }
}
