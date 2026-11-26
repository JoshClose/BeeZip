//! Encrypted and signed `.bhive` in the commands layer (docs/M14.md §8, §11): how a job answers
//! an encrypted archive's Unlock request, and the rules the commands keep before core or
//! `beezip-keys` is reached. Until PRs A, C, D, E and H are in, core's and `beezip-keys`'
//! halves are stubs; these tests need neither.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use beezip_commands::{
    CmdError, Command, Effect, Engine, EngineOptions, ErrorCode, EventSink, Interactor, JobCtx,
    JobId, NonInteractive, Policy, Prompt, PromptReply, Registry,
    crypt::{SlotKindName, UnlockReply},
    registry,
};
use beezip_core::format::bhive::crypt::{SlotKind, UnlockAnswer, UnlockRequest, WayInfo};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fx(name: &str) -> String {
    fixtures().join(name).display().to_string()
}

/// Answers prompts from a list, and keeps what it was asked.
#[derive(Default)]
struct Scripted {
    replies: Mutex<Vec<PromptReply>>,
    asked: Mutex<Vec<Prompt>>,
}

impl Scripted {
    fn new(replies: Vec<PromptReply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into_iter().rev().collect()),
            asked: Mutex::new(Vec::new()),
        })
    }
}

impl Interactor for Scripted {
    fn prompt(&self, _job: JobId, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        self.asked.lock().unwrap().push(prompt.clone());
        self.replies
            .lock()
            .unwrap()
            .pop()
            .ok_or_else(|| CmdError::new(ErrorCode::KeyRequired, "no more replies"))
    }
}

/// Asks the job's context to unlock an archive with these ways in, `asks` times, as core's
/// reader does when an answer fails: what came back each time.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
struct UnlockInput {
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    kinds: Vec<u8>,
    #[arg(long)]
    here: Vec<u32>,
    #[arg(long)]
    asks: u32,
}

struct TestUnlock;

impl Command for TestUnlock {
    const NAME: &'static str = "test.unlock";
    const EFFECT: Effect = Effect::ReadOnly;
    type Input = UnlockInput;
    type Output = Vec<String>;

    fn run(input: UnlockInput, cx: &mut JobCtx) -> Result<Vec<String>, CmdError> {
        cx.set_password(input.password.map(Into::into).as_ref());
        let ways: Vec<WayInfo> = input
            .kinds
            .iter()
            .enumerate()
            .map(|(i, &k)| WayInfo {
                slot: i as u32,
                kind: SlotKind::from_id(k).unwrap(),
                here: input.here.contains(&(i as u32)),
            })
            .collect();
        let mut out = Vec::new();
        for attempt in 0..input.asks {
            let request = UnlockRequest {
                ways: ways.clone(),
                attempt,
            };
            let answer = beezip_core::Ctx::unlock(cx, &request)?;
            out.push(match answer {
                UnlockAnswer::Password(p) => format!("password {p}"),
                UnlockAnswer::RecoveryKey(k) => format!("recovery {k}"),
                UnlockAnswer::Way(s) => format!("slot {s}"),
            });
        }
        Ok(out)
    }
}

fn unlock(args: Value, interactor: Arc<dyn Interactor>) -> Result<Value, CmdError> {
    let mut r = Registry::new();
    r.register::<TestUnlock>();
    let engine = Engine::new(Box::leak(Box::new(r)));
    let sink: EventSink = Arc::new(|_| {});
    engine
        .invoke("test.unlock", args, interactor, sink)
        .unwrap()
        .join()
}

const RECOVERY: &str = "111111-222222-333333-444444-555555-666666-777777-888888";

#[test]
fn the_inputs_password_is_tried_first() {
    let none = Scripted::new(vec![]);
    let r = unlock(
        json!({ "password": "pw", "kinds": [1, 3], "here": [], "asks": 1 }),
        none.clone(),
    )
    .unwrap();
    assert_eq!(r, json!(["password pw"]));
    assert!(none.asked.lock().unwrap().is_empty());

    // 48 digits, with a recovery-key slot: a recovery key first, then a password.
    let r = unlock(
        json!({ "password": RECOVERY, "kinds": [1, 2], "here": [], "asks": 2 }),
        none.clone(),
    )
    .unwrap();
    assert_eq!(
        r,
        json!([
            format!("recovery {RECOVERY}"),
            format!("password {RECOVERY}")
        ])
    );
    // Without a password slot it is only tried as a recovery key.
    let e = unlock(
        json!({ "password": RECOVERY, "kinds": [2], "here": [], "asks": 2 }),
        Arc::new(NonInteractive),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::WrongPassword);
}

#[test]
fn the_unlock_prompt_lists_the_ways_in_and_takes_each_answer() {
    let replies = vec![
        PromptReply::Unlock {
            answer: UnlockReply::RecoveryKey {
                key: RECOVERY.into(),
            },
        },
        PromptReply::Unlock {
            answer: UnlockReply::Slot { slot: 2 },
        },
        // A front end that knows only passwords.
        PromptReply::Password {
            password: "typed".into(),
        },
    ];
    let s = Scripted::new(replies);
    let r = unlock(
        json!({ "kinds": [1, 2, 4], "here": [2], "asks": 3 }),
        s.clone(),
    )
    .unwrap();
    assert_eq!(
        r,
        json!([format!("recovery {RECOVERY}"), "slot 2", "password typed"])
    );
    let asked = s.asked.lock().unwrap();
    assert_eq!(asked.len(), 3);
    let Prompt::Unlock { ways, attempt } = &asked[1] else {
        panic!("{:?}", asked[1]);
    };
    assert_eq!(*attempt, 1);
    let kinds: Vec<(u32, SlotKindName, bool)> =
        ways.iter().map(|w| (w.slot, w.kind, w.here)).collect();
    assert_eq!(
        kinds,
        [
            (0, SlotKindName::Password, false),
            (1, SlotKindName::RecoveryKey, false),
            (2, SlotKindName::PostQuantumKey, true),
        ]
    );
}

#[test]
fn nobody_to_ask() {
    // The first ask: the front end's error, with the ways in.
    let e = unlock(
        json!({ "kinds": [3, 6], "here": [], "asks": 1 }),
        Arc::new(NonInteractive),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::KeyRequired);
    assert_eq!(e.exit_code(), 15);
    assert_eq!(
        e.details.unwrap()["ways"],
        json!([
            { "slot": 0, "kind": "public-key", "here": false },
            { "slot": 1, "kind": "ec-p256", "here": false },
        ])
    );
    // A later one: what was given was wrong.
    let e = unlock(
        json!({ "password": "wrong", "kinds": [1], "here": [], "asks": 2 }),
        Arc::new(NonInteractive),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::WrongPassword);
}

#[test]
fn prompts_stop_after_three() {
    let pw = || PromptReply::Unlock {
        answer: UnlockReply::Password {
            password: "no".into(),
        },
    };
    let s = Scripted::new(vec![pw(), pw(), pw(), pw()]);
    let e = unlock(json!({ "kinds": [1], "here": [], "asks": 4 }), s.clone()).unwrap_err();
    assert_eq!(e.code, ErrorCode::WrongPassword);
    assert_eq!(s.asked.lock().unwrap().len(), 3);
    let s = Scripted::new(vec![PromptReply::Cancel]);
    let e = unlock(json!({ "kinds": [1], "here": [], "asks": 1 }), s).unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
}

fn run_as(policy: Policy, name: &str, args: Value) -> Result<Value, CmdError> {
    let engine = Engine::with_options(
        registry(),
        EngineOptions {
            policy,
            ..EngineOptions::default()
        },
    );
    let sink: EventSink = Arc::new(|_| {});
    engine
        .invoke(name, args, Arc::new(NonInteractive), sink)
        .unwrap()
        .join()
}

fn run(name: &str, args: Value) -> Result<Value, CmdError> {
    run_as(Policy::unrestricted(), name, args)
}

fn unattended() -> Policy {
    Policy {
        unattended: true,
        ..Policy::unrestricted()
    }
}

#[test]
fn a_bhives_options_are_refused_for_other_formats() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.zip").display().to_string();
    let src = fx("bhive/README.md");
    for (option, value) in [
        ("to", json!(["age1example"])),
        ("to_cert", json!(["alice.cer"])),
        ("recovery_key", json!(true)),
        ("this_pc", json!(true)),
        ("security_key", json!(true)),
        ("strength", json!("strong")),
        ("sign", json!(["me"])),
    ] {
        let e = run(
            "archive.create",
            json!({ "output": out, "inputs": [src], option: value }),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs, "{option}: {}", e.message);
        assert!(e.message.contains(option), "{option}: {}", e.message);
    }
    assert!(!dir.path().join("a.zip").exists());
}

#[test]
fn ways_in_are_checked_before_anything_is_made() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.bhive").display().to_string();
    let src = fx("bhive/README.md");
    let create = |extra: Value| {
        let mut args = json!({ "output": out, "inputs": [src] });
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        run("archive.create", args).unwrap_err()
    };
    // This PC alone would lose the archive with the PC (decision 11).
    let e = create(json!({ "this_pc": true }));
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(e.message.contains("only way in"), "{}", e.message);
    let e = create(json!({ "strength": "strong" }));
    assert!(
        e.message.contains("`strength` is for a password"),
        "{}",
        e.message
    );
    let e = create(json!({ "password": "pw", "this_pc_pin": "1234" }));
    assert!(e.message.contains("this_pc"), "{}", e.message);
    let e = create(json!({ "password": "" }));
    assert!(e.message.contains("empty"), "{}", e.message);
    // `encryption` is zip's.
    let e = create(json!({ "password": "pw", "encryption": "aes256" }));
    assert!(
        e.message.contains("`encryption` is for zip"),
        "{}",
        e.message
    );
    assert!(!dir.path().join("a.bhive").exists());
}

#[test]
fn nobody_there_no_devices_recovery_keys_or_signatures() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.bhive").display().to_string();
    let src = fx("bhive/README.md");
    for (option, value) in [
        ("recovery_key", json!(true)),
        ("this_pc", json!(true)),
        ("security_key", json!(true)),
        ("sign", json!(["me"])),
    ] {
        let e = run_as(
            unattended(),
            "archive.create",
            json!({ "output": out, "inputs": [src], "password": "pw", option: value }),
        )
        .unwrap_err();
        assert_eq!(
            e.code,
            ErrorCode::UnsupportedOperation,
            "{option}: {}",
            e.message
        );
        assert!(e.message.contains(option), "{option}: {}", e.message);
    }
    assert!(!dir.path().join("a.bhive").exists());
}

#[test]
fn an_unencrypted_bhive_has_no_ways_in_and_no_signature() {
    let small = fx("bhive/spec-small.bhive");
    let r = run("archive.protection", json!({ "archive": small })).unwrap();
    assert_eq!(
        r,
        json!({ "encrypted": false, "ways": [], "post_quantum": false })
    );
    let info = run("archive.info", json!({ "archive": small })).unwrap();
    assert!(info.get("protection").is_none(), "{info}");
    assert!(info.get("signatures").is_none(), "{info}");
    let e = run("archive.verify", json!({ "archive": small })).unwrap_err();
    assert_eq!(e.code, ErrorCode::SignatureRequired);
    assert_eq!(e.exit_code(), 16);
    assert!(e.message.contains("isn't signed"), "{}", e.message);

    let e = run(
        "archive.protection",
        json!({ "archive": fx("thirdparty/7z-deflate.zip") }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
}

#[test]
fn a_signed_bhive_reports_its_signature() {
    // docs/bhive.md §13.6. Whether it checks is PR H's; that it is reported is this PR's.
    let signed = fx("bhive-m14/spec-signed.bhive");
    let info = run("archive.info", json!({ "archive": signed })).unwrap();
    let sigs = info["signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 1, "{info}");
    let test = run("archive.test", json!({ "archive": signed })).unwrap();
    assert_eq!(test["signatures"].as_array().unwrap().len(), 1, "{test}");
}

#[test]
fn protect_and_sign_need_something_to_do() {
    let small = fx("bhive/spec-small.bhive");
    let e = run("archive.protect", json!({ "archive": small })).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(e.message.contains("nothing to change"), "{}", e.message);
    let e = run(
        "archive.protect",
        json!({ "archive": small, "confirm": [0], "remove": [1] }),
    )
    .unwrap_err();
    assert!(
        e.message.contains("`confirm` is for `new_key`"),
        "{}",
        e.message
    );
    let e = run("archive.sign", json!({ "archive": small })).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(e.message.contains("nothing to do"), "{}", e.message);

    // An unencrypted archive has no ways in to change; the archive is left as it was.
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("small.bhive");
    std::fs::copy(fixtures().join("bhive/spec-small.bhive"), &copy).unwrap();
    let before = std::fs::read(&copy).unwrap();
    let e = run(
        "archive.protect",
        json!({ "archive": copy, "new_key": true, "add_password": "pw" }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(e.message.contains("isn't encrypted"), "{}", e.message);
    assert_eq!(std::fs::read(&copy).unwrap(), before);
}

#[test]
fn the_surfaces_m14_turns_on() {
    let r = registry();
    let on = |name: &str| r.get(name).unwrap().surfaces;
    for name in ["archive.protection", "archive.verify", "certificates.list"] {
        assert!(on(name).cli && on(name).gui && on(name).mcp, "{name}");
    }
    // Never over MCP: a signature says you made it; protect may lock people out and touch
    // devices (docs/M14.md decisions 15 and 27).
    for name in ["archive.sign", "archive.protect"] {
        assert!(on(name).cli && on(name).gui && !on(name).mcp, "{name}");
    }
}
