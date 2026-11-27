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
    JobEvent, JobId, KeyStub, LogLevel, NonInteractive, Policy, Prompt, PromptReply, Registry,
    SystemKeys,
    crypt::{SlotKindName, UnlockReply},
    registry,
    wire::Secret,
};
use beezip_core::format::bhive::crypt::{
    KEY_ID_LEN, KeySource, SlotKind, SlotSecret, SlotView, UnlockAnswer, UnlockRequest, WayInfo,
};
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
    /// The ways in that need a PIN BeeZip asks for.
    #[arg(long)]
    #[serde(default)]
    pins: Vec<u32>,
    /// Why the way in the last answer chose didn't open it, from the second ask on.
    #[arg(long)]
    #[serde(default)]
    failed: Option<String>,
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
                needs_pin: input.pins.contains(&(i as u32)),
            })
            .collect();
        let mut out = Vec::new();
        for attempt in 0..input.asks {
            let request = UnlockRequest {
                ways: ways.clone(),
                attempt,
                failed: input.failed.clone().filter(|_| attempt > 0),
            };
            let answer = beezip_core::Ctx::unlock(cx, &request)?;
            out.push(match answer {
                UnlockAnswer::Password(p) => format!("password {p}"),
                UnlockAnswer::RecoveryKey(k) => format!("recovery {k}"),
                UnlockAnswer::Way { slot, pin: None } => format!("slot {slot}"),
                UnlockAnswer::Way {
                    slot,
                    pin: Some(pin),
                } => format!("slot {slot} with PIN {}", pin.as_str()),
            });
        }
        Ok(out)
    }
}

fn unlock(args: Value, interactor: Arc<dyn Interactor>) -> Result<Value, CmdError> {
    let mut r = Registry::new();
    r.register::<TestUnlock>();
    let (engine, _dir) = engine_in(
        Box::leak(Box::new(r)),
        Policy::unrestricted(),
        SystemKeys::Off,
    );
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
    // Any separators: dots, tabs.
    let dotted = RECOVERY.replace('-', ".\t");
    let r = unlock(
        json!({ "password": dotted, "kinds": [2], "here": [], "asks": 1 }),
        none.clone(),
    )
    .unwrap();
    assert_eq!(r, json!([format!("recovery {dotted}")]));
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
            answer: UnlockReply::Slot { slot: 2, pin: None },
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
    let Prompt::Unlock { ways, attempt, .. } = &asked[1] else {
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

/// A This PC key whose PIN BeeZip asks for: the prompt says which way in needs it, and why the
/// way in last chosen failed; the reply's PIN reaches core. A reply without one, an older front
/// end's, still parses.
#[test]
fn a_pin_goes_with_the_reply() {
    let old: UnlockReply = serde_json::from_value(json!({ "way": "slot", "slot": 1 })).unwrap();
    assert_eq!(old, UnlockReply::Slot { slot: 1, pin: None });
    let with = UnlockReply::Slot {
        slot: 1,
        pin: Some(Secret::new("4821")),
    };
    assert_eq!(format!("{with:?}"), "Slot(1, PIN ***)");
    assert_eq!(
        serde_json::to_value(&with).unwrap(),
        json!({ "way": "slot", "slot": 1, "pin": "4821" })
    );
    let s = Scripted::new(vec![
        PromptReply::Unlock { answer: with },
        PromptReply::Unlock { answer: old },
    ]);
    let r = unlock(
        json!({ "kinds": [1, 6], "here": [1], "pins": [1], "failed": "the PIN is wrong", "asks": 2 }),
        s.clone(),
    )
    .unwrap();
    assert_eq!(r, json!(["slot 1 with PIN 4821", "slot 1"]));
    let asked = s.asked.lock().unwrap();
    let Prompt::Unlock { ways, failed, .. } = &asked[0] else {
        panic!("{:?}", asked[0]);
    };
    assert_eq!(*failed, None);
    let pins: Vec<bool> = ways.iter().map(|w| w.needs_pin).collect();
    assert_eq!(pins, [false, true]);
    // On the wire, only a way in that needs a PIN says so, and only a failure is sent.
    let wire = serde_json::to_value(&asked[1]).unwrap();
    assert_eq!(
        wire,
        json!({
            "kind": "Unlock",
            "ways": [
                { "slot": 0, "kind": "password", "here": false },
                { "slot": 1, "kind": "ec-p256", "here": true, "needs_pin": true },
            ],
            "attempt": 1,
            "failed": "the PIN is wrong",
        })
    );
    assert!(
        serde_json::to_value(&asked[0])
            .unwrap()
            .get("failed")
            .is_none()
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
    // A password or a recovery key would open it: a password is required, as for a zip,
    // whatever other ways in it has.
    for kinds in [json!([1]), json!([3, 2])] {
        let e = unlock(
            json!({ "kinds": kinds, "here": [], "asks": 1 }),
            Arc::new(NonInteractive),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::PasswordRequired, "{kinds}");
        assert_eq!(e.exit_code(), 6);
        let details = e.details.unwrap();
        assert_eq!(details["param"], "password");
        assert!(details["ways"].is_array(), "{details}");
    }
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
    run_logged(policy, name, args).0
}

/// Runs a command, with what it logged.
fn run_logged(policy: Policy, name: &str, args: Value) -> (Result<Value, CmdError>, Vec<String>) {
    let (engine, _dir) = engine_in(registry(), policy, SystemKeys::Off);
    let logs = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&logs);
    let sink: EventSink = Arc::new(move |e| {
        if let JobEvent::Log {
            level: LogLevel::Warn,
            message,
        } = e
        {
            seen.lock().unwrap().push(message);
        }
    });
    let r = engine
        .invoke(name, args, Arc::new(NonInteractive), sink)
        .unwrap()
        .join();
    let logs = logs.lock().unwrap().clone();
    (r, logs)
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

/// An engine whose settings folder is a fresh temporary one, so no test reads or writes the
/// user's keys, contacts or certificates; `keys` stands in for the system's.
fn engine_in(
    registry: &'static Registry,
    policy: Policy,
    keys: SystemKeys,
) -> (Engine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::with_options(
        registry,
        EngineOptions {
            policy,
            config_path: Some(dir.path().join("config.toml")),
            system_keys: keys,
            ..EngineOptions::default()
        },
    );
    (engine, dir)
}

/// A key source standing in for the system's: it has the key of every X25519 slot, and keeps
/// whether each secret asked for needed a device.
struct Offers(Arc<Mutex<Vec<bool>>>);

impl KeySource for Offers {
    fn offers(&mut self, slot: &SlotView<'_>) -> bool {
        slot.kind == SlotKind::X25519
    }

    fn secret(
        &mut self,
        slot: &SlotView<'_>,
        device: bool,
    ) -> beezip_core::Result<Option<SlotSecret>> {
        self.0.lock().unwrap().push(device);
        Ok((slot.kind == SlotKind::X25519)
            .then(|| SlotSecret::Shared(zeroize::Zeroizing::new(vec![1; 32]))))
    }
}

#[derive(Default)]
struct Stub(Arc<Mutex<Vec<bool>>>);

impl KeyStub for Stub {
    fn sources(&self, _window: Option<isize>) -> Vec<Box<dyn KeySource + Send>> {
        vec![Box::new(Offers(Arc::clone(&self.0)))]
    }
}

/// Asks the job's key source about one slot of `kind`, as core's reader does, then, with
/// `unlock`, for an answer to a password slot: what came back.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
struct KeysInput {
    #[arg(long)]
    kind: u8,
    #[arg(long)]
    unlock: bool,
}

struct TestKeys;

impl Command for TestKeys {
    const NAME: &'static str = "test.keys";
    const EFFECT: Effect = Effect::ReadOnly;
    type Input = KeysInput;
    type Output = Value;

    fn run(input: KeysInput, cx: &mut JobCtx) -> Result<Value, CmdError> {
        let key_id = [0u8; KEY_ID_LEN];
        let view = SlotView {
            index: 0,
            kind: SlotKind::from_id(input.kind).unwrap(),
            key_id: &key_id,
            framed: &[],
            public: &[],
            commitment: &[0; 32],
        };
        let source = beezip_core::Ctx::key_source(cx).unwrap();
        let offered = source.offers(&view);
        let secret = source.secret(&view, false)?.is_some();
        let answer = if input.unlock {
            let request = UnlockRequest {
                ways: vec![WayInfo {
                    slot: 0,
                    kind: SlotKind::Password,
                    here: false,
                    needs_pin: false,
                }],
                attempt: 0,
                failed: None,
            };
            Some(format!("{:?}", beezip_core::Ctx::unlock(cx, &request)?))
        } else {
            None
        };
        Ok(json!({
            "offered": offered,
            "secret": secret,
            "cached": !cx.password_used(),
            "answer": answer,
        }))
    }
}

fn keys(
    policy: Policy,
    keys: SystemKeys,
    args: Value,
    interactor: Arc<dyn Interactor>,
) -> Result<Value, CmdError> {
    let mut r = Registry::new();
    r.register::<TestKeys>();
    let (engine, _dir) = engine_in(Box::leak(Box::new(r)), policy, keys);
    engine
        .invoke("test.keys", args, interactor, Arc::new(|_| {}))
        .unwrap()
        .join()
}

#[test]
fn keys_come_from_your_store_key_files_then_the_system() {
    let stub = Stub::default();
    let asked = Arc::clone(&stub.0);
    let system = SystemKeys::Stub(Arc::new(stub));
    let r = keys(
        Policy::unrestricted(),
        system.clone(),
        json!({ "kind": 3, "unlock": false }),
        Arc::new(NonInteractive),
    )
    .unwrap();
    // The system's source has the key; silently, without a device. An archive a key was
    // looked for never goes back to the archive cache.
    assert_eq!(r["offered"], json!(true), "{r}");
    assert_eq!(r["secret"], json!(true), "{r}");
    assert_eq!(r["cached"], json!(false), "{r}");
    assert_eq!(*asked.lock().unwrap(), [false]);

    // Nobody there (MCP): no system source is tried at all (decision 15).
    asked.lock().unwrap().clear();
    let r = keys(
        unattended(),
        system,
        json!({ "kind": 3, "unlock": false }),
        Arc::new(NonInteractive),
    )
    .unwrap();
    assert_eq!(r["offered"], json!(false), "{r}");
    assert_eq!(r["secret"], json!(false), "{r}");
    assert!(asked.lock().unwrap().is_empty());

    // An engine made without a front end reaches no system source either.
    let r = keys(
        Policy::unrestricted(),
        SystemKeys::Off,
        json!({ "kind": 3, "unlock": false }),
        Arc::new(NonInteractive),
    )
    .unwrap();
    assert_eq!(r["offered"], json!(false), "{r}");
}

/// Keeps the window each job's system sources were made for.
struct Windows(Arc<Mutex<Vec<Option<isize>>>>);

impl KeyStub for Windows {
    fn sources(&self, window: Option<isize>) -> Vec<Box<dyn KeySource + Send>> {
        self.0.lock().unwrap().push(window);
        Vec::new()
    }
}

/// The window a front end gives a job reaches the system's key sources, which parent Windows'
/// PIN and security-key dialogs to it: the engine's (the CLI's console) or the job's own (the
/// desktop's window that started it). MCP's jobs make no system source at all.
#[test]
fn the_jobs_window_reaches_the_systems_key_sources() {
    let seen: Arc<Mutex<Vec<Option<isize>>>> = Arc::default();
    let system = SystemKeys::Stub(Arc::new(Windows(Arc::clone(&seen))));
    let args = json!({ "kind": 3, "unlock": false });
    let console = Policy {
        window: Some(0x0c11),
        ..Policy::unrestricted()
    };
    keys(
        console,
        system.clone(),
        args.clone(),
        Arc::new(NonInteractive),
    )
    .unwrap();
    keys(
        Policy::unrestricted(),
        system.clone(),
        args.clone(),
        Arc::new(NonInteractive),
    )
    .unwrap();
    assert_eq!(*seen.lock().unwrap(), [Some(0x0c11), None]);

    // Per job, as the desktop starts them: the engine's policy with the window.
    seen.lock().unwrap().clear();
    let mut r = Registry::new();
    r.register::<TestKeys>();
    let (engine, _dir) = engine_in(
        Box::leak(Box::new(r)),
        Policy::unrestricted(),
        system.clone(),
    );
    for window in [Some(0x0a11), Some(0x0b22)] {
        let policy = Arc::new(Policy {
            window,
            ..Policy::clone(&engine.policy())
        });
        engine
            .invoke_with_policy(
                "test.keys",
                args.clone(),
                Arc::new(NonInteractive),
                Arc::new(|_| {}),
                policy,
            )
            .unwrap()
            .join()
            .unwrap();
    }
    assert_eq!(*seen.lock().unwrap(), [Some(0x0a11), Some(0x0b22)]);

    // Nobody there: no source, whatever the window.
    seen.lock().unwrap().clear();
    let mcp = Policy {
        window: Some(0x0d33),
        ..unattended()
    };
    keys(mcp, system, args, Arc::new(NonInteractive)).unwrap();
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn a_key_file_that_cant_be_read_is_the_error() {
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy {
        identities: vec![dir.path().join("missing.pem")],
        ..Policy::unrestricted()
    };
    let asked = Scripted::new(vec![]);
    let e = keys(
        policy,
        SystemKeys::Off,
        json!({ "kind": 1, "unlock": true }),
        asked.clone(),
    )
    .unwrap_err();
    // Not "a password is needed": the file given is what failed, and nobody was asked.
    assert!(
        !matches!(
            e.code,
            ErrorCode::KeyRequired | ErrorCode::PasswordRequired | ErrorCode::WrongPassword
        ),
        "{e:?}"
    );
    assert!(asked.asked.lock().unwrap().is_empty());
}

#[test]
fn an_encrypted_zip_converts_into_an_encrypted_bhive() {
    // Core's rule for an encrypted source sees the .bhive's ways in. Until PR A writes
    // encrypted archives this reaches its writer and stops there; never "pass new_password".
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bhive");
    // `decrypt` with a way in contradicts itself.
    let e = run(
        "archive.convert",
        json!({
            "archive": fx("thirdparty/7z-aes256.zip"), "output": out, "password": "beezip",
            "decrypt": true, "to": ["age1x"],
        }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(
        e.message
            .ends_with("leave out `new_password` and the other ways in"),
        "{}",
        e.message
    );
    let r = run(
        "archive.convert",
        json!({
            "archive": fx("thirdparty/7z-aes256.zip"), "output": out, "password": "beezip",
            "new_password": "pw2",
        }),
    );
    r.unwrap();
    assert!(encrypted(&out));
    let listed = run(
        "archive.list",
        json!({ "archive": out, "password": "pw2", "flat": true }),
    )
    .unwrap();
    assert!(!listed["entries"].as_array().unwrap().is_empty());
}

#[test]
fn an_encrypted_bhive_is_never_written_in_the_clear() {
    // Converted without new ways in, or edited, an encrypted .bhive keeps its slots.
    let sealed = fixtures().join("bhive-m14/spec-sealed.bhive");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bhive");
    run(
        "archive.convert",
        json!({ "archive": sealed, "output": out, "password": "honey" }),
    )
    .unwrap();
    assert!(encrypted(&out));
    let copy = dir.path().join("copy.bhive");
    std::fs::copy(&sealed, &copy).unwrap();
    let new = dir.path().join("new.txt");
    std::fs::write(&new, "new").unwrap();
    run(
        "archive.add",
        json!({ "archive": copy, "inputs": [new], "password": "honey" }),
    )
    .unwrap();
    assert!(encrypted(&copy));
    let listed = run(
        "archive.list",
        json!({ "archive": copy, "password": "honey", "flat": true }),
    )
    .unwrap();
    assert!(
        listed["entries"].to_string().contains("new.txt"),
        "{listed}"
    );
}

#[test]
fn a_change_that_drops_signatures_says_so_first() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("signed.bhive");
    std::fs::copy(fixtures().join("bhive-m14/spec-signed.bhive"), &copy).unwrap();
    let entries = run("archive.list", json!({ "archive": copy })).unwrap();
    let first = entries["entries"][0]["path"].as_str().unwrap().to_owned();
    let (r, logs) = run_logged(
        Policy::unrestricted(),
        "archive.remove",
        json!({ "archive": copy, "entries": [first] }),
    );
    assert!(
        logs.iter()
            .any(|l| l.contains("is signed") && l.contains("sign it again")),
        "{r:?} {logs:?}"
    );
    // Converting it says so too; an unsigned archive says nothing.
    let out = dir.path().join("out.zip");
    let (_, logs) = run_logged(
        Policy::unrestricted(),
        "archive.convert",
        json!({ "archive": fx("bhive-m14/spec-signed.bhive"), "output": out }),
    );
    assert!(
        logs.iter().any(|l| l.contains("can't go into a zip")),
        "{logs:?}"
    );
    let out = dir.path().join("small.zip");
    let (_, logs) = run_logged(
        Policy::unrestricted(),
        "archive.convert",
        json!({ "archive": fx("bhive/spec-small.bhive"), "output": out }),
    );
    assert!(!logs.iter().any(|l| l.contains("is signed")), "{logs:?}");
}

#[test]
fn verify_needs_a_signer_you_know() {
    // Valid or not (PR H checks it), nobody here knows the signer, and no `require_signer`
    // names them: not verified.
    let e = run(
        "archive.verify",
        json!({ "archive": fx("bhive-m14/spec-signed.bhive") }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::SignatureRequired, "{e:?}");
    assert_eq!(e.exit_code(), 16);
}

#[test]
fn windows_hello_alone_is_refused_before_anything_is_asked() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("a.bhive").display().to_string();
    let src = fx("bhive/README.md");
    let e = run(
        "archive.create",
        json!({ "output": out, "inputs": [src], "windows_hello": true }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(
        e.message.contains("Windows Hello can't be the only way in"),
        "{}",
        e.message
    );
    let e = run(
        "archive.create",
        json!({ "output": out, "inputs": [src], "this_pc": true, "windows_hello": true }),
    )
    .unwrap_err();
    assert!(e.message.contains("only way in"), "{}", e.message);
    // A device's way into an archive whose output is in the way: the conflict first, and no
    // device is asked.
    std::fs::write(&out, "in the way").unwrap();
    let e = run(
        "archive.create",
        json!({ "output": out, "inputs": [src], "password": "pw", "security_key": true }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict, "{e:?}");
}

/// Whether the `.bhive` at `path` says in its header that it is encrypted.
fn encrypted(path: &Path) -> bool {
    use beezip_core::format::bhive::layout;
    let bytes = std::fs::read(path).unwrap();
    layout::check_header(&bytes[..16]).unwrap() & layout::FEATURE_ENCRYPTED != 0
}

/// The example keys of age's specification: an X25519 identity and recipient, an X-Wing
/// identity and recipient.
fn age_examples() -> Vec<String> {
    let text = std::fs::read_to_string(fixtures().join("keys/age-spec-examples.txt")).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// Each slot's bytes, and the key id, from the key block of the `.bhive` at `path`.
fn key_block(path: &Path) -> (Vec<Vec<u8>>, [u8; 16]) {
    use beezip_core::format::bhive::crypt::envelope::KeyBlock;
    let mut file = std::fs::File::open(path).unwrap();
    let mut header = [0u8; 16];
    std::io::Read::read_exact(&mut file, &mut header).unwrap();
    let block = KeyBlock::read(&header, &mut file).unwrap();
    let slots = block
        .slots
        .iter()
        .map(|(_, range)| block.bytes[range.clone()].to_vec())
        .collect();
    (slots, block.key_id)
}

#[test]
fn new_key_changes_every_slot_and_add_keeps_them() {
    let keys = age_examples();
    let dir = tempfile::tempdir().unwrap();
    let identities = dir.path().join("identities.txt");
    std::fs::write(&identities, format!("{}\n{}\n", keys[0], keys[2])).unwrap();
    let policy = Policy {
        identities: vec![identities],
        ..Policy::unrestricted()
    };
    let archive = dir.path().join("a.bhive");
    run_as(
        policy.clone(),
        "archive.create",
        json!({
            "output": archive, "inputs": [fixtures().join("bhive/README.md")],
            "to": [keys[1], keys[3]], "sign": [],
        }),
    )
    .unwrap();
    let (before, key_id) = key_block(&archive);
    assert_eq!(before.len(), 2);

    // Neither key is among anyone's keys or contacts here: each must be confirmed.
    let e = run_as(
        policy.clone(),
        "archive.protect",
        json!({ "archive": archive, "new_key": true }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert_eq!(
        e.details.unwrap()["unconfirmed"].as_array().unwrap().len(),
        2
    );
    assert_eq!(key_block(&archive).0, before, "nothing changed");

    let out = run_as(
        policy.clone(),
        "archive.protect",
        json!({ "archive": archive, "new_key": true, "confirm": [0, 1] }),
    )
    .unwrap();
    assert_eq!(out["ways"].as_array().unwrap().len(), 2);
    assert_eq!(out["post_quantum"], false);
    let (after, new_id) = key_block(&archive);
    assert_ne!(new_id, key_id);
    assert_eq!(after.len(), 2);
    for (old, new) in before.iter().zip(&after) {
        assert_ne!(old, new, "every slot is rebuilt");
    }
    // Each identity still opens it.
    for key in [&keys[0], &keys[2]] {
        let one = dir.path().join("one.txt");
        std::fs::write(&one, key).unwrap();
        let p = Policy {
            identities: vec![one],
            ..Policy::unrestricted()
        };
        run_as(p, "archive.test", json!({ "archive": archive })).unwrap();
    }

    // Removing a way in keeps the file key and the other slot byte for byte.
    let out = run_as(
        policy.clone(),
        "archive.protect",
        json!({ "archive": archive, "remove": [0] }),
    )
    .unwrap();
    assert_eq!(out["ways"].as_array().unwrap().len(), 1);
    assert_eq!(out["post_quantum"], true);
    let (kept, kept_id) = key_block(&archive);
    assert_eq!(kept_id, new_id);
    assert_eq!(kept, vec![after[1].clone()]);
    // The last way in can't go.
    let e = run_as(
        policy,
        "archive.protect",
        json!({ "archive": archive, "remove": [0] }),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs, "{e:?}");
    assert!(e.message.contains("no way in"), "{}", e.message);
}

/// The test keys and certificates of `beezip-keys` (its `files/testdata`, published on purpose).
fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../beezip-keys/src/files/testdata")
        .join(name)
}

/// Engines over one settings folder, so that several share one set of keys and contacts; each
/// with the key files given (`--identity`).
struct At<'a>(&'a Path);

impl At<'_> {
    fn engine(&self, identities: &[&str]) -> Engine {
        Engine::with_options(
            registry(),
            EngineOptions {
                policy: Policy {
                    identities: identities.iter().map(|f| testdata(f)).collect(),
                    ..Policy::unrestricted()
                },
                config_path: Some(self.0.join("config.toml")),
                system_keys: SystemKeys::Off,
                ..EngineOptions::default()
            },
        )
    }

    /// Runs a command with `identities`, with the warnings it logged.
    fn run(
        &self,
        identities: &[&str],
        name: &str,
        args: Value,
    ) -> (Result<Value, CmdError>, Vec<String>) {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&logs);
        let sink: EventSink = Arc::new(move |e| {
            if let JobEvent::Log {
                level: LogLevel::Warn,
                message,
            } = e
            {
                seen.lock().unwrap().push(message);
            }
        });
        let r = self
            .engine(identities)
            .invoke(name, args, Arc::new(NonInteractive), sink)
            .unwrap()
            .join();
        let logs = logs.lock().unwrap().clone();
        (r, logs)
    }

    fn ok(&self, identities: &[&str], name: &str, args: Value) -> Value {
        self.run(identities, name, args).0.unwrap()
    }

    fn err(&self, identities: &[&str], name: &str, args: Value) -> CmdError {
        self.run(identities, name, args).0.unwrap_err()
    }
}

/// Someone's certificate as a contact (docs/M14.md §6): added from a PEM file, a DER file and
/// pasted PEM; encrypted to by name and opened with its key file; known as the signer of what
/// its key signs; named by `require_signer`; and a slot for it is rebuilt by "New key" without
/// asking. On every system, with key files only.
#[test]
fn a_certificate_contact_is_encrypted_to_and_known_as_a_signer() {
    let settings = tempfile::tempdir().unwrap();
    let at = At(settings.path());
    let work = tempfile::tempdir().unwrap();
    let input = fixtures().join("bhive/README.md");

    let bob = at.ok(
        &[],
        "keys.import",
        json!({ "name": "Bob", "file": testdata("rsa.crt") }),
    );
    assert_eq!(bob["kind"], "certificate", "{bob}");
    assert_eq!(bob["own"], false);
    assert_eq!(bob["subject"], "BeeZip test rsa");
    assert_eq!(bob["issuer"], "BeeZip test rsa");
    assert!(bob["not_after"].as_i64().unwrap() > 4_000_000_000);
    assert!(
        bob["public"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    // The same certificate in DER is already Bob.
    let e = at.err(
        &[],
        "keys.import",
        json!({ "name": "Bob again", "file": testdata("rsa.der") }),
    );
    assert_eq!(e.code, ErrorCode::Conflict);
    // P-384 in DER, written from its PEM; pasted PEM.
    let p384 = beezip_core::format::bhive::crypt::cert::parse(
        &std::fs::read(testdata("p384.crt")).unwrap(),
    )
    .unwrap();
    let der = work.path().join("carol.cer");
    std::fs::write(&der, &p384.der).unwrap();
    at.ok(&[], "keys.import", json!({ "name": "Carol", "file": der }));
    let pem = std::fs::read_to_string(testdata("rsa-expired.crt")).unwrap();
    at.ok(&[], "keys.import", json!({ "name": "Old", "text": pem }));
    at.ok(
        &[],
        "keys.import",
        json!({ "name": "Ecdsa", "file": testdata("p256-ecdsa.crt") }),
    );
    let exported = at.ok(&[], "keys.export", json!({ "name": "Bob" }));
    assert_eq!(exported["text"], bob["public"]);
    let e = at.err(&[], "keys.export", json!({ "name": "Bob", "secret": true }));
    assert_eq!(e.code, ErrorCode::InvalidArgs);

    // Encrypted to Bob and Carol by name; each one's key file opens it, and nothing else does.
    let archive = work.path().join("a.bhive");
    at.ok(
        &[],
        "archive.create",
        json!({ "output": archive, "inputs": [input], "to": ["Bob", "Carol"] }),
    );
    assert!(encrypted(&archive));
    for key in ["rsa.key", "p384.key"] {
        at.ok(&[key], "archive.test", json!({ "archive": archive }));
    }
    let e = at.err(&["p256.key"], "archive.test", json!({ "archive": archive }));
    assert_eq!(e.code, ErrorCode::KeyRequired);
    let ways = at.ok(
        &["rsa.key"],
        "archive.protection",
        json!({ "archive": archive }),
    );
    let labels: Vec<&str> = ways["ways"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["Bob", "Carol"], "{ways}");
    assert_eq!(ways["ways"][0]["fingerprint"], bob["fingerprint"], "{ways}");
    // Both are contacts, so a new key rebuilds their slots without asking.
    let (before, _) = key_block(&archive);
    at.ok(
        &["rsa.key"],
        "archive.protect",
        json!({ "archive": archive, "new_key": true }),
    );
    let (after, _) = key_block(&archive);
    assert_eq!(after.len(), 2);
    assert_ne!(after, before);
    at.ok(&["p384.key"], "archive.test", json!({ "archive": archive }));

    // An expired contact is encrypted to with a warning; an ECDSA one can't be, and says why.
    let (r, warned) = at.run(
        &[],
        "archive.create",
        json!({ "output": work.path().join("old.bhive"), "inputs": [input], "to": ["Old"] }),
    );
    r.unwrap();
    assert!(
        warned
            .iter()
            .any(|w| w.contains("Old's certificate has expired")),
        "{warned:?}"
    );
    let e = at.err(
        &[],
        "archive.create",
        json!({ "output": work.path().join("ecdsa.bhive"), "inputs": [input], "to": ["Ecdsa"] }),
    );
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(e.message.contains("ECDSA"), "{}", e.message);

    // Signed with Bob's key file: the signature is Bob's, and `require_signer` takes his name.
    let signed = work.path().join("s.bhive");
    at.ok(
        &[],
        "archive.create",
        json!({ "output": signed, "inputs": [input], "sign": [testdata("rsa.crt")] }),
    );
    let info = at.ok(&[], "archive.info", json!({ "archive": signed }));
    let s = &info["signatures"][0];
    assert_eq!(s["trust"], "contact", "{info}");
    assert_eq!(s["signer"], "Bob");
    // A signature's fingerprint is of its signer bytes; its certificate's is Bob's, as his
    // contact and his way into an archive show it.
    assert_ne!(s["fingerprint"], bob["fingerprint"]);
    assert_eq!(s["certificate_fingerprint"], bob["fingerprint"], "{info}");
    at.ok(&[], "archive.verify", json!({ "archive": signed }));
    at.ok(
        &[],
        "archive.verify",
        json!({ "archive": signed, "require_signer": ["Bob"] }),
    );
    let e = at.err(
        &[],
        "archive.verify",
        json!({ "archive": signed, "require_signer": ["Carol"] }),
    );
    assert_eq!(e.code, ErrorCode::SignatureRequired);

    // Gone as a contact, the signer is a stranger again.
    at.ok(&[], "keys.delete", json!({ "name": "Bob" }));
    let info = at.ok(&[], "archive.info", json!({ "archive": signed }));
    assert_eq!(info["signatures"][0]["trust"], "unknown", "{info}");
}

/// A `.pfx` given to open or to sign: on Windows (in memory) and macOS (in a keychain of its
/// own) it is opened with its password asked for; on Linux it is refused with what to do
/// instead, before anything is asked.
#[test]
fn a_pfx_opens_and_signs_on_windows_and_macos_and_is_refused_elsewhere() {
    let settings = tempfile::tempdir().unwrap();
    let at = At(settings.path());
    let work = tempfile::tempdir().unwrap();
    let input = fixtures().join("bhive/README.md");
    let archive = work.path().join("a.bhive");
    at.ok(
        &[],
        "archive.create",
        json!({ "output": archive, "inputs": [input], "to_cert": [testdata("rsa.crt")] }),
    );
    // Its password is asked for, and nobody is here to type it. The 3DES files are what every
    // macOS reads, as Windows does.
    let opened = at.err(
        &["rsa-3des.pfx"],
        "archive.test",
        json!({ "archive": archive }),
    );
    if cfg!(not(any(windows, target_os = "macos"))) {
        assert_eq!(opened.code, ErrorCode::UnsupportedOperation, "{opened:?}");
        assert!(
            opened.message.contains("openssl pkcs12"),
            "{}",
            opened.message
        );
        let e = at.err(
            &[],
            "archive.create",
            json!({
                "output": work.path().join("s.bhive"), "inputs": [input],
                "sign": [testdata("p256-3des.pfx")],
            }),
        );
        assert_eq!(e.code, ErrorCode::UnsupportedOperation, "{e:?}");
        return;
    }
    assert_eq!(opened.code, ErrorCode::PasswordRequired, "{opened:?}");
    assert!(
        opened.message.contains("under a password"),
        "{}",
        opened.message
    );
    // Someone types the password: a wrong one is asked for again, the right one opens it.
    let replies = |n: usize| {
        let mut r = vec![
            PromptReply::Password {
                password: "comb".into(),
            };
            n - 1
        ];
        r.push(PromptReply::Password {
            password: "honey".into(),
        });
        Scripted::new(r)
    };
    let asked = replies(2);
    at.engine(&["rsa-3des.pfx"])
        .invoke(
            "archive.test",
            json!({ "archive": archive }),
            asked.clone(),
            Arc::new(|_| {}),
        )
        .unwrap()
        .join()
        .unwrap();
    let prompts = asked.asked.lock().unwrap().clone();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(
        matches!(&prompts[0], Prompt::Password { entry: Some(e) } if e.contains("rsa-3des.pfx")),
        "{prompts:?}"
    );
    // Signing with one asks for its password the same way.
    let signed = work.path().join("s.bhive");
    at.engine(&[])
        .invoke(
            "archive.create",
            json!({ "output": signed, "inputs": [input], "sign": [testdata("p256-3des.pfx")] }),
            replies(1),
            Arc::new(|_| {}),
        )
        .unwrap()
        .join()
        .unwrap();
    let info = at.ok(&[], "archive.info", json!({ "archive": signed }));
    assert_eq!(info["signatures"][0]["status"], "valid", "{info}");
    assert_eq!(info["signatures"][0]["algorithm"], "ecdsa-p256");
    // On Windows, one whose password is empty needs nobody.
    if cfg!(windows) {
        at.ok(
            &[],
            "archive.create",
            json!({
                "output": work.path().join("e.bhive"), "inputs": [input],
                "sign": [testdata("p256-ecdsa.pfx")],
            }),
        );
    }
}

/// An edit of an encrypted, signed `.bhive` says first that its signatures drop, as one in the
/// clear does (docs/M14.md §11): core says so once it has opened the archive, so its key is
/// asked for once. Signing again as it edits says nothing.
#[test]
fn an_edit_of_an_encrypted_signed_bhive_says_its_signatures_drop() {
    let settings = tempfile::tempdir().unwrap();
    let at = At(settings.path());
    let work = tempfile::tempdir().unwrap();
    let input = work.path().join("a.txt");
    std::fs::write(&input, "honey").unwrap();
    let new = work.path().join("new.txt");
    std::fs::write(&new, "new").unwrap();
    let signer = testdata("rsa.crt");
    let with = |mut args: Value, extra: &Value| {
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        args
    };
    // Encrypted to a password, and to a certificate whose key file opens it.
    let cases: [(Value, Value, &[&str]); 2] = [
        (
            json!({ "password": "pw" }),
            json!({ "password": "pw" }),
            &[],
        ),
        (json!({ "to_cert": [signer] }), json!({}), &["rsa.key"]),
    ];
    for (n, (way, opens, keys)) in cases.into_iter().enumerate() {
        let archive = work.path().join(format!("s{n}.bhive"));
        at.ok(
            keys,
            "archive.create",
            with(
                json!({ "output": archive, "inputs": [input], "sign": [signer] }),
                &way,
            ),
        );
        assert!(encrypted(&archive));
        let edits = [
            (
                "archive.add",
                json!({ "archive": archive, "inputs": [new] }),
            ),
            (
                "archive.rename",
                json!({ "archive": archive, "from": "new.txt", "to": "renamed.txt" }),
            ),
            (
                "archive.remove",
                json!({ "archive": archive, "entries": ["renamed.txt"] }),
            ),
        ];
        for (i, (name, args)) in edits.into_iter().enumerate() {
            if i > 0 {
                // Signed again, so that each edit has a signature to drop.
                at.ok(
                    keys,
                    "archive.sign",
                    with(json!({ "archive": archive, "sign": [signer] }), &opens),
                );
            }
            let (r, logs) = at.run(keys, name, with(args, &opens));
            r.unwrap_or_else(|e| panic!("{name}: {e:?}"));
            let said: Vec<&String> = logs.iter().filter(|l| l.contains("is signed")).collect();
            assert_eq!(said.len(), 1, "{name} {way}: {logs:?}");
            assert!(said[0].contains("sign it again"), "{said:?}");
            assert!(encrypted(&archive));
            let info = at.ok(
                keys,
                "archive.info",
                with(json!({ "archive": archive }), &opens),
            );
            assert!(
                info["signatures"].as_array().is_none_or(Vec::is_empty),
                "{name}: {info}"
            );
        }
        // Signed again as it is edited: the new signature replaces the old, and nothing is said.
        at.ok(
            keys,
            "archive.sign",
            with(json!({ "archive": archive, "sign": [signer] }), &opens),
        );
        let (r, logs) = at.run(
            keys,
            "archive.add",
            with(
                json!({ "archive": archive, "inputs": [new], "sign": [signer] }),
                &opens,
            ),
        );
        r.unwrap();
        assert!(!logs.iter().any(|l| l.contains("is signed")), "{logs:?}");
        let info = at.ok(
            keys,
            "archive.info",
            with(json!({ "archive": archive }), &opens),
        );
        assert_eq!(info["signatures"].as_array().unwrap().len(), 1, "{info}");
    }
}

/// A conversion that drops a signed `.bhive`'s signatures says so first, encrypted or not: one
/// that chooses entries, a level or another format (docs/M14.md §11). Core says so once it has
/// opened the source. A `.bhive` copied whole into a `.bhive` keeps them, and says nothing.
#[test]
fn a_conversion_that_drops_signatures_says_so_encrypted_or_not() {
    let settings = tempfile::tempdir().unwrap();
    let at = At(settings.path());
    let work = tempfile::tempdir().unwrap();
    let inputs = [work.path().join("a.txt"), work.path().join("b.txt")];
    std::fs::write(&inputs[0], "honey").unwrap();
    std::fs::write(&inputs[1], "comb").unwrap();
    let signer = testdata("rsa.crt");
    let with = |mut args: Value, extra: &Value| {
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        args
    };
    // In the clear, encrypted to a password, and to a certificate whose key file opens it.
    let cases: [(Value, Value, &[&str]); 3] = [
        (json!({}), json!({}), &[]),
        (
            json!({ "password": "pw" }),
            json!({ "password": "pw" }),
            &[],
        ),
        (json!({ "to_cert": [signer] }), json!({}), &["rsa.key"]),
    ];
    for (n, (way, opens, keys)) in cases.into_iter().enumerate() {
        let source = work.path().join(format!("s{n}.bhive"));
        at.ok(
            keys,
            "archive.create",
            with(
                json!({ "output": source, "inputs": inputs, "sign": [signer] }),
                &way,
            ),
        );
        let said = |name: &str, args: Value| {
            let (r, logs) = at.run(keys, "archive.convert", with(args, &opens));
            r.unwrap_or_else(|e| panic!("{name} {way}: {e:?}"));
            logs.into_iter()
                .filter(|l| l.contains("is signed"))
                .collect::<Vec<_>>()
        };
        let out = |name: &str| work.path().join(format!("{n}-{name}"));
        let changes = [
            (
                "picked.bhive",
                json!({ "entries": ["a.txt"] }),
                "won't carry over",
            ),
            ("fast.bhive", json!({ "level": "fast" }), "won't carry over"),
            (
                "plain.zip",
                json!({ "decrypt": n > 0 }),
                "can't go into a zip",
            ),
        ];
        for (name, extra, why) in changes {
            let args = with(json!({ "archive": source, "output": out(name) }), &extra);
            let warned = said(name, args);
            assert_eq!(warned.len(), 1, "{name} {way}: {warned:?}");
            assert!(warned[0].contains(why), "{name} {way}: {warned:?}");
        }
        // Copied whole, as it is stored: its signature comes with it, and nothing is said.
        let copy = out("copy.bhive");
        let warned = said("copy", json!({ "archive": source, "output": copy }));
        assert!(warned.is_empty(), "{way}: {warned:?}");
        assert_eq!(encrypted(&copy), n > 0);
        let info = at.ok(
            keys,
            "archive.info",
            with(json!({ "archive": copy }), &opens),
        );
        assert_eq!(info["signatures"][0]["status"], "valid", "{info}");
    }
}

/// What the desktop's main window runs its tabs' jobs under: archives kept unlocked.
fn keeping() -> Policy {
    Policy {
        keep_unlocked: true,
        ..Policy::unrestricted()
    }
}

/// Runs `name` on `engine` under `policy`, with what it sent as events.
fn run_on(
    engine: &Engine,
    policy: &Policy,
    name: &str,
    args: Value,
    interactor: Arc<dyn Interactor>,
) -> (Result<Value, CmdError>, Vec<JobEvent>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let sink: EventSink = Arc::new(move |e| seen.lock().unwrap().push(e));
    let r = engine
        .invoke_with_policy(name, args, interactor, sink, Arc::new(policy.clone()))
        .unwrap()
        .join();
    let events = events.lock().unwrap().clone();
    (r, events)
}

/// The sealed example of bhive.md §11, under the password "honey", copied into `dir`.
fn sealed_in(dir: &Path, name: &str) -> PathBuf {
    let archive = dir.join(name);
    std::fs::copy(fixtures().join("bhive-m14/spec-sealed.bhive"), &archive).unwrap();
    archive
}

fn honey() -> PromptReply {
    PromptReply::Unlock {
        answer: UnlockReply::Password {
            password: "honey".into(),
        },
    }
}

/// A tab's archive, unlocked once through the Unlock prompt, opens for every later job on it
/// without asking: a listing, a test, an extraction, an edit (which keeps its slots), and a
/// listing after the edit. A copy elsewhere isn't unlocked, and closing the tab locks it again
/// (docs/M14.md §8).
#[test]
fn a_tab_keeps_its_archive_unlocked_until_it_closes() {
    let dir = tempfile::tempdir().unwrap();
    let archive = sealed_in(dir.path(), "a.bhive");
    let (engine, _cfg) = engine_in(registry(), Policy::unrestricted(), SystemKeys::Off);
    let tab = keeping();
    let list = || json!({ "archive": archive, "flat": true });
    let asked = Scripted::new(vec![honey()]);
    let (r, _) = run_on(&engine, &tab, "archive.list", list(), asked.clone());
    r.unwrap();
    assert_eq!(asked.asked.lock().unwrap().len(), 1);
    assert_eq!(engine.unlocks().len(), 1);

    let nobody = Scripted::new(vec![]);
    let new = dir.path().join("new.txt");
    std::fs::write(&new, "new").unwrap();
    let out = dir.path().join("out");
    for (name, args) in [
        ("archive.list", list()),
        ("archive.test", json!({ "archive": archive })),
        (
            "archive.extract",
            json!({ "archive": archive, "dest": out }),
        ),
        (
            "archive.add",
            json!({ "archive": archive, "inputs": [new] }),
        ),
        ("archive.list", list()),
    ] {
        let (r, events) = run_on(&engine, &tab, name, args, nobody.clone());
        // The example's link is refused, and the rest extracted.
        let out = match r {
            Err(e) if e.code == ErrorCode::Unsafe => e.details.unwrap(),
            r => r.unwrap_or_else(|e| panic!("{name}: {e:?}")),
        };
        assert!(
            !events.iter().any(|e| matches!(e, JobEvent::Prompt { .. })),
            "{name} asked"
        );
        if name == "archive.list" {
            assert!(out["entries"].is_array(), "{out}");
        }
    }
    assert!(nobody.asked.lock().unwrap().is_empty());
    assert!(encrypted(&archive));
    let (listed, _) = run_on(&engine, &tab, "archive.list", list(), nobody.clone());
    assert!(listed.unwrap()["entries"].to_string().contains("new.txt"));

    // A copy of it elsewhere asks, as any archive does.
    let copy = dir.path().join("copy.bhive");
    std::fs::copy(&archive, &copy).unwrap();
    let (r, _) = run_on(
        &engine,
        &tab,
        "archive.list",
        json!({ "archive": copy }),
        Arc::new(NonInteractive),
    );
    assert_eq!(r.unwrap_err().code, ErrorCode::PasswordRequired);

    // The tab closes: what unlocked it is wiped, and the next job asks again.
    assert_eq!(engine.unlocks().forget(&archive), 1);
    assert!(engine.unlocks().is_empty());
    let (r, _) = run_on(
        &engine,
        &tab,
        "archive.list",
        list(),
        Arc::new(NonInteractive),
    );
    assert_eq!(r.unwrap_err().code, ErrorCode::PasswordRequired);
}

/// The CLI and MCP keep nothing: a job given the password opens the archive, and the next one
/// without it is asked for it, as before.
#[test]
fn the_cli_and_mcp_keep_nothing_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let archive = sealed_in(dir.path(), "a.bhive");
    for policy in [Policy::unrestricted(), unattended()] {
        assert!(!policy.keep_unlocked);
        let (engine, _cfg) = engine_in(registry(), policy.clone(), SystemKeys::Off);
        let (r, _) = run_on(
            &engine,
            &policy,
            "archive.list",
            json!({ "archive": archive, "password": "honey" }),
            Arc::new(NonInteractive),
        );
        r.unwrap();
        // Through the Unlock prompt too.
        let (r, _) = run_on(
            &engine,
            &policy,
            "archive.list",
            json!({ "archive": archive }),
            Scripted::new(vec![honey()]),
        );
        r.unwrap();
        assert!(engine.unlocks().is_empty());
        let (r, _) = run_on(
            &engine,
            &policy,
            "archive.list",
            json!({ "archive": archive }),
            Arc::new(NonInteractive),
        );
        assert_eq!(r.unwrap_err().code, ErrorCode::PasswordRequired);
    }
}

/// An interactor that refuses every prompt at once (a drag-out's): no `Prompt` event goes out,
/// and the job fails as with nobody to ask; it waits on nothing.
struct Refusing;

impl Interactor for Refusing {
    fn prompt(&self, job: JobId, id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        NonInteractive.prompt(job, id, prompt)
    }

    fn shows_prompts(&self) -> bool {
        false
    }
}

#[test]
fn an_interactor_that_shows_no_prompts_fails_without_one() {
    let dir = tempfile::tempdir().unwrap();
    let archive = sealed_in(dir.path(), "a.bhive");
    let (engine, _cfg) = engine_in(registry(), Policy::unrestricted(), SystemKeys::Off);
    let args = json!({ "archive": archive, "dest": dir.path().join("out") });
    let (r, events) = run_on(
        &engine,
        &keeping(),
        "archive.extract",
        args.clone(),
        Arc::new(Refusing),
    );
    let e = r.unwrap_err();
    assert_eq!(e.code, ErrorCode::PasswordRequired, "{e:?}");
    assert!(e.details.unwrap()["ways"].is_array());
    assert!(
        !events.iter().any(|e| matches!(e, JobEvent::Prompt { .. })),
        "{events:?}"
    );
    // Unlocked by the tab first, it opens.
    let (r, _) = run_on(
        &engine,
        &keeping(),
        "archive.list",
        json!({ "archive": archive }),
        Scripted::new(vec![honey()]),
    );
    r.unwrap();
    let (r, _) = run_on(
        &engine,
        &keeping(),
        "archive.extract",
        args,
        Arc::new(Refusing),
    );
    // The example's link is refused, and the rest extracted.
    assert_eq!(r.unwrap_err().details.unwrap()["files"], 2);
}
