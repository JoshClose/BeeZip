use std::path::{Path, PathBuf};

use beezip_keys::identity::{KeyEntry, KeyKind, Store};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CliSpec, CmdError, Command, Effect, JobCtx, Surfaces,
    crypt::{KeyInfo, KeyKindName},
    policy::Access,
};

/// List your keys (for opening archives and for signing them) and your contacts' public keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
pub struct KeysListInput {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct KeysListOutput {
    pub keys: Vec<KeyInfo>,
}

pub struct KeysList;

impl Command for KeysList {
    const NAME: &'static str = "keys.list";
    const EFFECT: Effect = Effect::ReadOnly;
    // The CLI and the desktop's Settings → Keys; the MCP server opens with your keys by name
    // but doesn't manage them (docs/M14.md §8).
    const SURFACES: Surfaces = Surfaces::NO_MCP;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "list",
        aliases: &["ls"],
        group: Some("keys"),
    });

    type Input = KeysListInput;
    type Output = KeysListOutput;

    fn run(_: KeysListInput, cx: &mut JobCtx) -> Result<KeysListOutput, CmdError> {
        let keys = store(cx)?.list()?.into_iter().map(info).collect();
        Ok(KeysListOutput { keys })
    }

    fn human(out: &KeysListOutput) -> Option<String> {
        if out.keys.is_empty() {
            return Some(
                "No keys yet. Make one with `beezip keys create NAME`, or add one with \
                 `beezip keys import NAME --file FILE`."
                    .into(),
            );
        }
        let width = out
            .keys
            .iter()
            .map(|k| k.name.chars().count())
            .max()
            .unwrap_or(0);
        let mut s = String::new();
        for k in &out.keys {
            let whose = if k.own { "yours" } else { "contact" };
            let pad = width - k.name.chars().count();
            s.push_str(&format!(
                "{}{}  {:<12}  {:<7}  {}  {}\n",
                k.name,
                " ".repeat(pad),
                kind_label(k.kind),
                whose,
                k.fingerprint,
                short(&k.public),
            ));
        }
        s.pop();
        Some(s)
    }

    fn access(_: &KeysListInput) -> Vec<Access> {
        keys_dir().map(Access::Read).into_iter().collect()
    }
}

/// Your keys' store: the `keys` folder beside `config.toml`, in BeeZip's settings folder
/// (docs/M14.md §6). `BEEZIP_CONFIG` moves both.
pub(crate) fn store(cx: &JobCtx) -> Result<Store, CmdError> {
    let path = cx.config_path().ok_or_else(|| {
        CmdError::invalid_args(
            "this system has no settings folder for your keys; set BEEZIP_CONFIG to a file in \
             the folder to use",
        )
    })?;
    Ok(Store::new(settings_dir(&path)))
}

fn settings_dir(config: &Path) -> PathBuf {
    match config.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The store's folder, for `access`, which has no job to ask.
pub(crate) fn keys_dir() -> Option<PathBuf> {
    crate::config::config_path().map(|p| settings_dir(&p).join("keys"))
}

pub(crate) fn info(e: KeyEntry) -> KeyInfo {
    KeyInfo {
        name: e.name,
        kind: kind_name(e.kind),
        public: e.public,
        fingerprint: e.fingerprint,
        own: e.own,
        created: e.created,
    }
}

pub(crate) const fn kind_name(kind: KeyKind) -> KeyKindName {
    match kind {
        KeyKind::X25519 => KeyKindName::Classic,
        KeyKind::XWing => KeyKindName::PostQuantum,
        KeyKind::Signing => KeyKindName::Signing,
    }
}

pub(crate) const fn kind_label(kind: KeyKindName) -> &'static str {
    match kind {
        KeyKindName::PostQuantum => "post-quantum",
        KeyKindName::Classic => "classic",
        KeyKindName::Signing => "signing",
    }
}

/// A public key cut to its start and end: post-quantum ones run to 1,959 characters.
fn short(public: &str) -> String {
    if public.len() <= 40 {
        return public.to_owned();
    }
    format!("{}…{}", &public[..24], &public[public.len() - 8..])
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use serde_json::{Value, json};

    use super::*;
    use crate::{
        Engine, EngineOptions, ErrorCode, NonInteractive, Policy, discard_events, registry,
    };

    /// An engine whose settings folder, and so whose keys, are a test's own; its keys are
    /// deleted when it is dropped, so the system keeps nothing of a test's (the Keychain).
    pub(crate) struct Keys {
        pub engine: Engine,
        pub dir: tempfile::TempDir,
    }

    impl Keys {
        pub(crate) fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let engine = Engine::with_options(
                registry(),
                EngineOptions {
                    config_path: Some(dir.path().join("config.toml")),
                    shell: crate::shell::Hive::test("keys"),
                    ..EngineOptions::from_config(Ok(Default::default()), Policy::unrestricted())
                },
            );
            Self { engine, dir }
        }

        pub(crate) fn run(&self, name: &str, args: Value) -> Result<Value, CmdError> {
            self.engine
                .invoke(name, args, Arc::new(NonInteractive), discard_events())
                .unwrap()
                .join()
        }

        pub(crate) fn store(&self) -> Store {
            Store::new(self.dir.path().to_path_buf())
        }
    }

    impl Drop for Keys {
        fn drop(&mut self) {
            let store = self.store();
            for e in store.list().unwrap_or_default() {
                let _ = store.delete(&e.name);
            }
        }
    }

    #[test]
    fn every_key_command_through_the_engine() {
        let k = Keys::new();
        let empty: KeysListOutput =
            serde_json::from_value(k.run("keys.list", json!({})).unwrap()).unwrap();
        assert!(empty.keys.is_empty());
        assert!(KeysList::human(&empty).unwrap().contains("No keys yet"));

        let made: KeyInfo =
            serde_json::from_value(k.run("keys.create", json!({ "name": "Mine" })).unwrap())
                .unwrap();
        assert_eq!(
            made.kind,
            KeyKindName::PostQuantum,
            "post-quantum by default"
        );
        assert!(made.public.starts_with("age1pq1"));
        assert!(made.own);
        let classic: KeyInfo = serde_json::from_value(
            k.run("keys.create", json!({ "name": "Old", "kind": "classic" }))
                .unwrap(),
        )
        .unwrap();
        assert!(classic.public.starts_with("age1"));

        let public = k.run("keys.export", json!({ "name": "Mine" })).unwrap();
        assert_eq!(public["text"], json!(made.public));
        let secret = k
            .run("keys.export", json!({ "name": "Mine", "secret": true }))
            .unwrap();
        let secret = secret["text"].as_str().unwrap().to_owned();
        assert!(secret.starts_with("AGE-SECRET-KEY-PQ-1"));

        // Imported elsewhere, from text and from a file, it is the same key.
        let other = Keys::new();
        let again: KeyInfo = serde_json::from_value(
            other
                .run("keys.import", json!({ "name": "Backup", "text": secret }))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(again.public, made.public);
        let file = other.dir.path().join("friend.txt");
        std::fs::write(&file, format!("# Friend's key\n{}\n", classic.public)).unwrap();
        let friend: KeyInfo = serde_json::from_value(
            other
                .run("keys.import", json!({ "name": "Friend", "file": file }))
                .unwrap(),
        )
        .unwrap();
        assert!(!friend.own);
        let list: KeysListOutput =
            serde_json::from_value(other.run("keys.list", json!({})).unwrap()).unwrap();
        assert_eq!(list.keys, vec![again, friend]);
        let table = KeysList::human(&list).unwrap();
        assert!(table.contains("Backup  post-quantum  yours"), "{table}");
        assert!(table.contains("Friend  classic       contact"), "{table}");

        let deleted = k.run("keys.delete", json!({ "name": "Mine" })).unwrap();
        assert_eq!(deleted["deleted"], json!("Mine"));
        let list: KeysListOutput =
            serde_json::from_value(k.run("keys.list", json!({})).unwrap()).unwrap();
        assert_eq!(list.keys.len(), 1);
    }

    #[test]
    fn refusals() {
        let k = Keys::new();
        k.run("keys.create", json!({ "name": "Mine" })).unwrap();
        let e = k.run("keys.create", json!({ "name": "mine" })).unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        let e = k
            .run("keys.import", json!({ "name": "X", "text": "age1nope" }))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
        let e = k.run("keys.import", json!({ "name": "X" })).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
        let e = k
            .run(
                "keys.import",
                json!({ "name": "X", "text": "a", "file": "b" }),
            )
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
        let e = k
            .run(
                "keys.import",
                json!({ "name": "X", "file": k.dir.path().join("missing.txt") }),
            )
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
        let e = k
            .run("keys.export", json!({ "name": "Nobody" }))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
        let e = k
            .run("keys.delete", json!({ "name": "Nobody" }))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }

    #[test]
    fn long_keys_are_shortened_in_the_table() {
        let s = short(&format!("age1pq1{}", "q".repeat(1952)));
        assert_eq!(s.chars().count(), 24 + 1 + 8);
        assert_eq!(short("age1short"), "age1short");
    }
}
