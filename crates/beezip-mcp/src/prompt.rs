//! A job's questions as MCP elicitation forms, and the answers back (docs/M2.md §3.3).
//!
//! Only overwrite questions are elicited. Form-mode elicitation "MUST NOT" ask for passwords,
//! so a password prompt is always answered with `PasswordRequired`, and the model asks the
//! user itself.

use beezip_commands::{CmdError, ErrorCode, OverwriteChoice, Prompt, PromptReply};
use rmcp::model::{ElicitRequestParams, ElicitResult, ElicitationAction, ElicitationSchema};
use serde_json::{Value, json};

/// The `inputRequests` key an overwrite question goes under.
pub const OVERWRITE_KEY: &str = "overwrite";

const CHOICES: [(&str, &str, OverwriteChoice); 5] = [
    ("replace", "Replace it", OverwriteChoice::Replace),
    (
        "replace_all",
        "Replace it and every other existing file",
        OverwriteChoice::ReplaceAll,
    ),
    ("skip", "Keep the existing file", OverwriteChoice::Skip),
    (
        "skip_all",
        "Keep it and every other existing file",
        OverwriteChoice::SkipAll,
    ),
    (
        "rename",
        "Keep both: give the new file another name",
        OverwriteChoice::Rename,
    ),
];

/// The answer to a password prompt over MCP.
pub fn password_required() -> CmdError {
    CmdError::new(
        ErrorCode::PasswordRequired,
        "a password is required; ask the user for it and pass it as the `password` argument \
         (BeeZip doesn't ask for passwords over MCP)",
    )
    .with_details(json!({ "param": "password" }))
}

/// The answer to a question nobody can be asked: the client has no form elicitation.
pub fn unanswerable(prompt: &Prompt) -> CmdError {
    match prompt {
        Prompt::Password { .. } => password_required(),
        Prompt::Overwrite {
            path,
            archive: None,
        } => CmdError::new(
            ErrorCode::Conflict,
            format!(
                "`{path}` already exists; pass `overwrite` (always, never, rename or newer) to \
                 say what to do with existing files"
            ),
        ),
        Prompt::Overwrite {
            path,
            archive: Some(archive),
        } => CmdError::new(
            ErrorCode::Conflict,
            format!(
                "`{path}` is already in {archive}; pass `overwrite` (always, never, rename or \
                 newer) to say what to do with entries already there"
            ),
        ),
    }
}

/// The elicitation form for a question, or `None` for one that is never elicited.
pub fn form(prompt: &Prompt) -> Option<ElicitRequestParams> {
    let Prompt::Overwrite { path, archive } = prompt else {
        return None;
    };
    let message = match archive {
        Some(a) => format!("`{path}` is already in {a}. Replace it?"),
        None => format!("`{path}` already exists. Replace it?"),
    };
    Some(ElicitRequestParams::FormElicitationParams {
        meta: None,
        message,
        requested_schema: overwrite_schema(),
    })
}

fn overwrite_schema() -> ElicitationSchema {
    let one_of: Vec<Value> = CHOICES
        .iter()
        .map(|(id, title, _)| json!({ "const": id, "title": title }))
        .collect();
    let schema = json!({
        "type": "object",
        "properties": {
            "choice": {
                "type": "string",
                "title": "The file already exists",
                "oneOf": one_of,
                "default": "skip",
            }
        },
        "required": ["choice"],
    });
    let Value::Object(schema) = schema else {
        unreachable!("json! of an object literal is an object")
    };
    ElicitationSchema::from_json_schema(schema)
        .unwrap_or_else(|e| unreachable!("the overwrite schema is a valid elicitation schema: {e}"))
}

/// The job's reply to an elicitation answer. `None` means the answer didn't fit the form, so
/// the question should be asked again.
pub fn reply(prompt: &Prompt, answer: &ElicitResult) -> Option<PromptReply> {
    let Prompt::Overwrite { .. } = prompt else {
        return Some(PromptReply::Cancel);
    };
    match answer.action {
        ElicitationAction::Accept => {
            let choice = answer.content.as_ref()?.get("choice")?.as_str()?;
            let (_, _, choice) = CHOICES.iter().find(|(id, _, _)| *id == choice)?;
            Some(PromptReply::Overwrite { choice: *choice })
        }
        // Declining to say what to do with a file in the way stops the job, as cancelling does.
        _ => Some(PromptReply::Cancel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overwrite() -> Prompt {
        Prompt::Overwrite {
            path: "C:\\out\\a.txt".to_owned(),
            archive: None,
        }
    }

    #[test]
    fn an_entry_already_in_an_archive_says_so() {
        let p = Prompt::Overwrite {
            path: "docs/a.txt".to_owned(),
            archive: Some("a.zip".to_owned()),
        };
        let Some(ElicitRequestParams::FormElicitationParams { message, .. }) = form(&p) else {
            panic!("an overwrite question has a form");
        };
        assert_eq!(message, "`docs/a.txt` is already in a.zip. Replace it?");
        assert!(unanswerable(&p).message.contains("is already in a.zip"));
    }

    #[test]
    fn the_overwrite_form_is_one_titled_choice() {
        let Some(ElicitRequestParams::FormElicitationParams {
            message,
            requested_schema,
            ..
        }) = form(&overwrite())
        else {
            panic!("an overwrite question has a form");
        };
        assert!(message.contains("a.txt"), "{message}");
        let schema = serde_json::to_value(&requested_schema).unwrap();
        assert_eq!(schema["required"], json!(["choice"]));
        let choice = &schema["properties"]["choice"];
        assert_eq!(choice["default"], "skip");
        let ids: Vec<&str> = choice["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["const"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            ["replace", "replace_all", "skip", "skip_all", "rename"]
        );
    }

    #[test]
    fn passwords_are_never_elicited() {
        let prompt = Prompt::Password { entry: None };
        assert!(form(&prompt).is_none());
        let err = unanswerable(&prompt);
        assert_eq!(err.code, ErrorCode::PasswordRequired);
        assert_eq!(err.details, Some(json!({ "param": "password" })));
    }

    #[test]
    fn answers_become_replies() {
        let accept =
            |content: Value| ElicitResult::new(ElicitationAction::Accept).with_content(content);
        assert_eq!(
            reply(&overwrite(), &accept(json!({ "choice": "replace_all" }))),
            Some(PromptReply::Overwrite {
                choice: OverwriteChoice::ReplaceAll
            })
        );
        assert_eq!(
            reply(&overwrite(), &accept(json!({ "choice": "rename" }))),
            Some(PromptReply::Overwrite {
                choice: OverwriteChoice::Rename
            })
        );
        // An answer that doesn't fit the form is asked again.
        assert_eq!(
            reply(&overwrite(), &accept(json!({ "choice": "burn" }))),
            None
        );
        assert_eq!(reply(&overwrite(), &accept(json!({}))), None);
        assert_eq!(
            reply(&overwrite(), &ElicitResult::new(ElicitationAction::Accept)),
            None
        );
        for action in [ElicitationAction::Decline, ElicitationAction::Cancel] {
            assert_eq!(
                reply(&overwrite(), &ElicitResult::new(action)),
                Some(PromptReply::Cancel)
            );
        }
    }

    #[test]
    fn without_elicitation_the_error_names_the_argument() {
        let err = unanswerable(&overwrite());
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.message.contains("`overwrite`"), "{}", err.message);
    }
}
