use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use beezip_core::format::bhive::crypt::{KeySource, SlotKind, UnlockAnswer, UnlockRequest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CmdError, ErrorCode,
    cache::ArchiveCache,
    config::Config,
    engine::{EditGuard, EditLocks, Live},
    policy::Policy,
    wire::Secret,
};

pub type JobId = u64;

/// Job progress. Byte counts come from the compressed input, so they are reliable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Progress {
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub entries_done: u64,
    pub entries_total: Option<u64>,
    /// The entry being processed.
    pub current: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum LogLevel {
    Info,
    Warn,
}

/// A question a job needs answered before it can continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind")]
pub enum Prompt {
    Password {
        entry: Option<String>,
    },
    /// A file in the way: on disk, or, with `archive`, an entry of that archive (`archive.add`).
    Overwrite {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        archive: Option<String>,
    },
    /// An encrypted `.bhive` and how it can be opened (docs/M14.md §8): a password, a recovery
    /// key, or one of its ways in that this machine has. `attempt` counts the answers that
    /// failed.
    Unlock {
        ways: Vec<crate::crypt::UnlockWay>,
        attempt: u32,
    },
}

/// A front end's answer to a `Prompt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind")]
pub enum PromptReply {
    Password { password: String },
    Overwrite { choice: OverwriteChoice },
    Unlock { answer: crate::crypt::UnlockReply },
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum OverwriteChoice {
    Replace,
    ReplaceAll,
    Skip,
    SkipAll,
    Rename,
}

/// Everything a job reports, in order: `Started`, then any `Progress`, `Log`, `Prompt` or
/// `Partial`, then exactly one of `Finished`, `Failed` or `Cancelled`. A `Partial` is a piece
/// of the output ready before the job ends (`bench.run` sends each cell as it finishes);
/// `Finished` still carries the whole output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "type")]
pub enum JobEvent {
    Started { job: JobId },
    Progress(Progress),
    Log { level: LogLevel, message: String },
    Prompt { id: u64, prompt: Prompt },
    Partial { output: serde_json::Value },
    Finished { output: serde_json::Value },
    Failed { error: CmdError },
    Cancelled,
}

/// Receives a job's events. It is called on the job's thread.
pub type EventSink = Arc<dyn Fn(JobEvent) + Send + Sync>;

/// An [`EventSink`] that drops every event.
pub fn discard_events() -> EventSink {
    Arc::new(|_| {})
}

/// Answers prompts. Each front end does it its own way: a TTY prompt, `cmd_respond` or MCP
/// elicitation.
pub trait Interactor: Send + Sync {
    /// `job` says which job asks: a GUI answers through `cmd_respond(job, id, reply)`.
    fn prompt(&self, job: JobId, id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError>;

    /// Called just before the `Prompt` event goes out, so a reply can't arrive before the
    /// interactor is ready for it. A GUI makes its reply slot here.
    fn expect(&self, _job: JobId, _id: u64) {}

    /// Whether to let a password slot's Argon2 use `need_mib` of this machine's `total_mib`,
    /// more than half of it (docs/M14.md §5). With nobody to ask it says no, and the slot is
    /// left untried.
    fn spend_memory(&self, _job: JobId, _need_mib: u64, _total_mib: u64) -> bool {
        false
    }
}

/// An [`Interactor`] with nobody to ask: every prompt fails with a hint about which argument to
/// pass instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct NonInteractive;

impl Interactor for NonInteractive {
    fn prompt(&self, _job: JobId, _id: u64, prompt: &Prompt) -> Result<PromptReply, CmdError> {
        Err(match prompt {
            Prompt::Password { .. } => CmdError::new(
                ErrorCode::PasswordRequired,
                "a password is required; pass it as the `password` argument",
            ),
            Prompt::Overwrite {
                path,
                archive: None,
            } => CmdError::new(
                ErrorCode::Conflict,
                format!("`{path}` already exists; pass an `overwrite` policy"),
            ),
            Prompt::Overwrite {
                path,
                archive: Some(archive),
            } => CmdError::new(
                ErrorCode::Conflict,
                format!("`{path}` is already in {archive}; pass an `overwrite` policy"),
            ),
            Prompt::Unlock { .. } => CmdError::new(
                ErrorCode::KeyRequired,
                "the archive is encrypted; pass a password, a recovery key or a key to open it",
            ),
        })
    }
}

/// Where a job looks for keys besides your own and the key files given (docs/M14.md §6, §8).
#[derive(Clone, Default)]
pub enum SystemKeys {
    /// None: an engine made without a front end, such as a test's, reaches no system store.
    #[default]
    Off,
    /// This machine's: Windows' certificate stores, smart cards, TPM and This PC keys, security
    /// keys and Windows Hello; the macOS Keychain. An unattended job (MCP) uses none of them.
    Real,
    /// A test's own, in their place.
    Stub(Arc<dyn KeyStub>),
}

impl std::fmt::Debug for SystemKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Off => "SystemKeys::Off",
            Self::Real => "SystemKeys::Real",
            Self::Stub(_) => "SystemKeys::Stub",
        })
    }
}

/// A test's stand-in for this machine's keys.
pub trait KeyStub: Send + Sync {
    /// The key sources a job tries after your keys and the key files given, made for each job.
    fn sources(&self) -> Vec<Box<dyn KeySource + Send>>;

    /// The SubjectPublicKeyInfos of this machine's This PC keys.
    fn this_pc(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

/// A cancellation flag shared by a job and whoever started it. Jobs check it between buffers.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Progress goes out at most this often; the last update always goes out.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// How many times a job asks for a password before giving up with `WrongPassword`.
pub const PASSWORD_PROMPTS: u32 = 3;

/// A running command's view of its job.
pub struct JobCtx {
    id: JobId,
    cancel: CancelToken,
    sink: EventSink,
    interactor: Arc<dyn Interactor>,
    next_prompt: u64,
    policy: Arc<Policy>,
    /// The engine's config when the job started; `settings.set` changes only later jobs'.
    config: Arc<Result<Config, CmdError>>,
    live: Arc<Live>,
    last_progress: Option<Instant>,
    pending_progress: Option<Progress>,
    /// The password given in the input, or the last one a prompt supplied.
    password: Option<String>,
    password_prompts: u32,
    /// A password reached the reader, which may keep it; the archive cache won't take it back.
    password_used: bool,
    cache: Option<Arc<ArchiveCache>>,
    locks: Arc<EditLocks>,
    /// What the input's password may open an encrypted `.bhive` as, still to try: a recovery
    /// key, a password (docs/M14.md §8).
    typed: Vec<UnlockAnswer>,
    unlock_prompts: u32,
    /// Your keys, the key files given, the system's certificates and devices; made when an
    /// encrypted archive first needs them.
    keys: Option<beezip_keys::Sources>,
    /// Why a key file given couldn't be read, reported when a key is needed.
    key_error: Option<CmdError>,
    /// The ways into the last encrypted archive an Unlock prompt couldn't be answered for, as
    /// `details.ways`.
    unlock_ways: Option<serde_json::Value>,
    /// The This PC keys this job made, deleted again if it fails.
    made_this_pc: Vec<String>,
}

impl JobCtx {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: JobId,
        cancel: CancelToken,
        sink: EventSink,
        interactor: Arc<dyn Interactor>,
        policy: Arc<Policy>,
        live: Arc<Live>,
        cache: Option<Arc<ArchiveCache>>,
        locks: Option<Arc<EditLocks>>,
    ) -> Self {
        Self {
            id,
            cancel,
            sink,
            interactor,
            next_prompt: 0,
            policy,
            config: live.config(),
            live,
            last_progress: None,
            pending_progress: None,
            password: None,
            password_prompts: 0,
            password_used: false,
            cache,
            locks: locks.unwrap_or_default(),
            typed: Vec::new(),
            unlock_prompts: 0,
            keys: None,
            key_error: None,
            unlock_ways: None,
            made_this_pc: Vec::new(),
        }
    }

    /// Notes a This PC key made for the archive being written: if the job then fails, the key
    /// opens nothing and is deleted ([`JobCtx::failed`]).
    pub fn made_this_pc(&mut self, name: String) {
        self.made_this_pc.push(name);
    }

    /// The job failed: the This PC keys it made are deleted, since no archive has them.
    pub(crate) fn failed(&mut self) {
        for name in std::mem::take(&mut self.made_this_pc) {
            #[cfg(windows)]
            if let Err(e) = beezip_keys::cng::delete_this_pc(&name) {
                self.log(
                    LogLevel::Warn,
                    format!(
                        "the This PC key {name} made for it couldn't be deleted: {}",
                        e.message
                    ),
                );
            }
            #[cfg(not(windows))]
            let _ = name;
        }
    }

    /// `e` with the ways into the archive nothing opened, for an error that says so
    /// (`KeyRequired`, `PasswordRequired`) and doesn't list them already.
    pub(crate) fn with_ways(&mut self, e: CmdError) -> CmdError {
        // No key here opened it, and a key file given couldn't be read: that is why.
        if e.code == ErrorCode::KeyRequired
            && let Some(k) = self.key_error.take()
        {
            return k;
        }
        let wants = matches!(e.code, ErrorCode::KeyRequired | ErrorCode::PasswordRequired);
        match (self.unlock_ways.take(), wants) {
            (Some(ways), true) => {
                let mut details = e.details.clone().unwrap_or_else(|| serde_json::json!({}));
                if let Some(d) = details.as_object_mut() {
                    d.entry("ways").or_insert(ways);
                }
                e.with_details(details)
            }
            _ => e,
        }
    }

    /// Your keys and contacts, in the settings folder beside the engine's `config.toml`
    /// (docs/M14.md §6). Only a front end's engine has one ([`crate::EngineOptions::from_loaded`],
    /// or a test's own `config_path`): an engine without, such as a test's, reaches nobody's
    /// keys, and no folder others can write to stands in for it.
    pub fn key_store(&self) -> Result<beezip_keys::identity::Store, CmdError> {
        let config = self.live.path().ok_or_else(|| {
            CmdError::new(
                ErrorCode::UnsupportedOperation,
                "there is no settings folder for your keys here; set BEEZIP_CONFIG to a file in \
                 the folder to use",
            )
        })?;
        let dir = match config.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => PathBuf::from("."),
        };
        Ok(beezip_keys::identity::Store::new(dir))
    }

    /// The SubjectPublicKeyInfos of this machine's This PC keys, which "New key" may rebuild a
    /// slot for without asking (docs/M14.md §3).
    pub fn this_pc_keys(&self) -> Vec<Vec<u8>> {
        match self.live.system_keys() {
            SystemKeys::Off => Vec::new(),
            SystemKeys::Stub(stub) => stub.this_pc(),
            #[cfg(windows)]
            SystemKeys::Real => beezip_keys::cng::this_pc()
                .into_iter()
                .map(|(_, spki)| spki)
                .collect(),
            #[cfg(not(windows))]
            SystemKeys::Real => Vec::new(),
        }
    }

    /// The key sources an encrypted `.bhive` is opened with: your keys first, then the key
    /// files given (`--identity`), then the system's certificate stores and devices. An
    /// unattended job (MCP) gets no system source: nobody is there to type a PIN or touch a
    /// device (decision 15).
    fn sources(&mut self) -> beezip_keys::Sources {
        let mut sources = beezip_keys::Sources::default();
        match self
            .key_store()
            .and_then(|store| store.source_with_problems().map_err(CmdError::from))
        {
            Ok((own, problems)) => {
                sources.push(own);
                // So that an archive none of your keys opened says why.
                for p in problems {
                    self.log(LogLevel::Warn, p.message);
                }
            }
            Err(e) => self.log(
                LogLevel::Warn,
                format!("your keys aren't available: {}", e.message),
            ),
        }
        for path in self.policy.identities.clone() {
            match self.key_file(&path) {
                Ok(files) => sources.push(files),
                Err(e) => {
                    self.key_error = Some(e);
                    break;
                }
            }
        }
        match self.live.system_keys().clone() {
            SystemKeys::Off => {}
            _ if self.policy.unattended => {}
            SystemKeys::Stub(stub) => {
                for s in stub.sources() {
                    sources.push(s);
                }
            }
            SystemKeys::Real => {
                for s in self.system_sources() {
                    sources.push(s);
                }
            }
        }
        sources
    }

    /// This machine's certificate stores and devices. One that this system lacks, or that isn't
    /// built yet, is left out.
    fn system_sources(&self) -> Vec<Box<dyn KeySource + Send>> {
        let found: Vec<(&str, beezip_core::Result<Box<dyn KeySource + Send>>)> = vec![
            #[cfg(windows)]
            ("Windows' certificate keys", beezip_keys::cng::source()),
            #[cfg(windows)]
            ("security keys", beezip_keys::webauthn::source(None)),
            #[cfg(target_os = "macos")]
            ("the Keychain", beezip_keys::mac::source()),
        ];
        let mut out = Vec::new();
        for (what, source) in found {
            match source {
                Ok(s) => out.push(s),
                Err(e) if e.kind == beezip_core::ErrorKind::UnsupportedOperation => {}
                Err(e) => self.log(
                    LogLevel::Warn,
                    format!("{what} aren't available: {}", e.message),
                ),
            }
        }
        out
    }

    /// The key file at `path` (`--identity`): an age identity file (`AGE-SECRET-KEY-…`
    /// lines), or a PEM or DER private key, which under a password asks for it, without echo,
    /// up to [`PASSWORD_PROMPTS`] times.
    fn key_file(&mut self, path: &Path) -> Result<Box<dyn KeySource + Send>, CmdError> {
        use beezip_core::ErrorKind;
        let in_file = |e: beezip_core::Error| {
            let e = CmdError::from(e);
            CmdError::new(e.code, format!("{}: {}", path.display(), e.message))
        };
        let bytes = std::fs::read(path)
            .map_err(|e| in_file(beezip_core::Error::io("reading the key file", &e)))?;
        if let Ok(text) = std::str::from_utf8(&bytes)
            && text
                .lines()
                .any(|l| l.trim().starts_with("AGE-SECRET-KEY-"))
        {
            return beezip_keys::identity::identity_file(text).map_err(in_file);
        }
        let mut passphrase: Option<String> = None;
        let mut asked = 0;
        loop {
            match beezip_keys::files::source(&[path], passphrase.as_deref()) {
                Ok(source) => return Ok(source),
                Err(e)
                    if matches!(
                        e.kind,
                        ErrorKind::PasswordRequired | ErrorKind::WrongPassword
                    ) && asked < PASSWORD_PROMPTS =>
                {
                    asked += 1;
                    let reply = self.prompt(Prompt::Password {
                        entry: Some(format!("the key file {}", path.display())),
                    });
                    match reply {
                        Ok(PromptReply::Password { password }) => passphrase = Some(password),
                        Ok(PromptReply::Cancel) => return Err(CmdError::cancelled()),
                        Ok(other) => {
                            return Err(CmdError::invalid_args(format!(
                                "expected a password, got {other:?}"
                            )));
                        }
                        Err(asking) if asking.code != ErrorCode::PasswordRequired => {
                            return Err(asking);
                        }
                        Err(_) => {
                            return Err(CmdError::new(
                                if e.kind == ErrorKind::WrongPassword {
                                    ErrorCode::WrongPassword
                                } else {
                                    ErrorCode::PasswordRequired
                                },
                                format!(
                                    "the key file {} is under a password; run the command in a \
                                     terminal to type it",
                                    path.display()
                                ),
                            ));
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// What the input's password may be, for the ways in an archive has: a recovery key when
    /// it reads as one (48 digits, with any separators, docs/bhive.md §12.5), a password, or
    /// both in turn. Last first.
    fn typed_answers(&self, request: &UnlockRequest) -> Vec<UnlockAnswer> {
        let Some(given) = &self.password else {
            return Vec::new();
        };
        let has = |kind| request.ways.iter().any(|w| w.kind == kind);
        let mut answers = Vec::new();
        let digits = given.chars().filter(char::is_ascii_digit).count();
        let recovery = digits == 48
            && given
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_punctuation() || c.is_ascii_whitespace());
        if recovery && has(SlotKind::RecoveryKey) {
            answers.push(UnlockAnswer::RecoveryKey(given.clone()));
        }
        if has(SlotKind::Password) || answers.is_empty() {
            answers.push(UnlockAnswer::Password(given.clone()));
        }
        answers.reverse();
        answers
    }

    /// The ways in, as an error's `details.ways` lists them.
    fn ways_details(request: &UnlockRequest) -> serde_json::Value {
        let ways: Vec<serde_json::Value> = request
            .ways
            .iter()
            .map(|w| {
                serde_json::json!({
                    "slot": w.slot,
                    "kind": crate::crypt::SlotKindName::from(w.kind),
                    "here": w.here,
                })
            })
            .collect();
        serde_json::json!({ "ways": ways })
    }

    /// Waits until no other job of this engine is editing the archive at `path` (canonical),
    /// then holds it until the guard drops (docs/M5.md §7.7).
    pub fn edit_lock(&self, path: &Path) -> Result<EditGuard, CmdError> {
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let cancel = self.cancel.clone();
        self.locks
            .acquire(path, &|| cancel.is_cancelled(), &mut || {
                self.log(
                    LogLevel::Info,
                    format!("Waiting for another change to {name}"),
                );
            })
    }

    pub fn id(&self) -> JobId {
        self.id
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The engine's archive cache; `None` for a job run without an engine.
    pub fn cache(&self) -> Option<&Arc<ArchiveCache>> {
        self.cache.as_ref()
    }

    /// Whether a password reached the reader during this job.
    pub fn password_used(&self) -> bool {
        self.password_used
    }

    /// The config, or the error that made it unusable (a value of the wrong type).
    pub fn config(&self) -> Result<&Config, CmdError> {
        self.config.as_ref().as_ref().map_err(Clone::clone)
    }

    /// The `config.toml` the engine's config came from: the one `settings.*` read and write.
    pub fn config_path(&self) -> Option<PathBuf> {
        self.live
            .path()
            .cloned()
            .or_else(crate::config::config_path)
    }

    /// Where Explorer's menu is registered: the real registry, or a test's own key.
    pub(crate) fn shell_hive(&self) -> &crate::shell::Hive {
        self.live.shell()
    }

    /// The desktop app's own exe, when the desktop app runs this job.
    pub(crate) fn shell_app(&self) -> Option<&Path> {
        self.live.shell_app()
    }

    /// Gives every later job `config`, and the engine's limits its `[limits]`. This job keeps
    /// the config it started with.
    pub(crate) fn replace_config(&self, config: Config) {
        self.live.replace(config);
    }

    /// The password the input gave, tried before anyone is asked.
    pub fn set_password(&mut self, password: Option<&Secret>) {
        self.password = password.map(|p| p.expose().to_owned());
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// `Err(Cancelled)` once the job has been cancelled; use it with `?` between buffers.
    pub fn check_cancelled(&self) -> Result<(), CmdError> {
        if self.is_cancelled() {
            Err(CmdError::cancelled())
        } else {
            Ok(())
        }
    }

    /// Reports progress, at most every 100 ms. Updates in between are held, and the engine
    /// sends the last one before the job's final event.
    pub fn progress(&mut self, progress: Progress) {
        let now = Instant::now();
        let due = self
            .last_progress
            .is_none_or(|t| now.duration_since(t) >= PROGRESS_INTERVAL);
        if due {
            self.last_progress = Some(now);
            self.pending_progress = None;
            (self.sink)(JobEvent::Progress(progress));
        } else {
            self.pending_progress = Some(progress);
        }
    }

    /// Sends a held progress update, if there is one.
    pub fn flush_progress(&mut self) {
        if let Some(p) = self.pending_progress.take() {
            self.last_progress = Some(Instant::now());
            (self.sink)(JobEvent::Progress(p));
        }
    }

    pub fn log(&self, level: LogLevel, message: impl Into<String>) {
        (self.sink)(JobEvent::Log {
            level,
            message: message.into(),
        });
    }

    /// Sends a piece of the output before the job ends, as a `Partial` event.
    pub fn partial(&self, output: serde_json::Value) {
        (self.sink)(JobEvent::Partial { output });
    }

    /// Emits a `Prompt` event, then blocks until the front end answers.
    pub fn prompt(&mut self, prompt: Prompt) -> Result<PromptReply, CmdError> {
        self.next_prompt += 1;
        let id = self.next_prompt;
        self.interactor.expect(self.id, id);
        (self.sink)(JobEvent::Prompt {
            id,
            prompt: prompt.clone(),
        });
        self.interactor.prompt(self.id, id, &prompt)
    }
}

/// The adapter core reaches the job through (docs/M1.md §3.1).
impl beezip_core::Ctx for JobCtx {
    fn is_cancelled(&self) -> bool {
        JobCtx::is_cancelled(self)
    }

    fn progress(&mut self, p: &beezip_core::Progress) {
        JobCtx::progress(
            self,
            Progress {
                bytes_done: p.bytes_done,
                bytes_total: p.bytes_total,
                entries_done: p.entries_done,
                entries_total: p.entries_total,
                current: p.current.clone(),
            },
        );
    }

    fn warn(&mut self, message: String) {
        self.log(LogLevel::Warn, message);
    }

    /// The input's password first; then up to [`PASSWORD_PROMPTS`] prompts. A prompt that
    /// works is kept for the rest of the job. With nobody to ask, a missing password is
    /// `PasswordRequired` and a wrong one `WrongPassword`.
    fn password(&mut self, entry: Option<&str>, attempt: u32) -> beezip_core::Result<String> {
        use beezip_core::{Error, ErrorKind};
        if attempt == 0
            && let Some(pw) = &self.password
        {
            self.password_used = true;
            return Ok(pw.clone());
        }
        if self.password_prompts >= PASSWORD_PROMPTS {
            return Err(Error::new(ErrorKind::WrongPassword, "wrong password"));
        }
        let reply = self.prompt(Prompt::Password {
            entry: entry.map(str::to_owned),
        });
        match reply {
            Ok(PromptReply::Password { password }) => {
                self.password_prompts += 1;
                self.password_used = true;
                self.password = Some(password.clone());
                Ok(password)
            }
            Ok(PromptReply::Cancel) => Err(Error::cancelled()),
            Ok(other) => Err(Error::invalid_args(format!(
                "expected a password, got {other:?}"
            ))),
            Err(e) if e.code == ErrorCode::PasswordRequired && attempt > 0 => Err(Error::new(
                ErrorKind::WrongPassword,
                "wrong password; pass the right one as the `password` argument",
            )),
            Err(e) => Err(e.into()),
        }
    }

    fn overwrite(&mut self, existing: &Path) -> beezip_core::Result<beezip_core::OverwriteChoice> {
        self.ask_overwrite(existing.display().to_string(), None)
    }

    /// The input's password first, as a recovery key or a password (or both, in turn); then
    /// up to [`PASSWORD_PROMPTS`] Unlock prompts, which list the ways in. With nobody to ask,
    /// a first ask fails as the front end says (`KeyRequired`, or `PasswordRequired` over
    /// MCP) with `details.ways`, and a later one is `WrongPassword`. An encrypted archive never
    /// goes back to the archive cache.
    fn unlock(&mut self, request: &UnlockRequest) -> beezip_core::Result<UnlockAnswer> {
        use beezip_core::{Error, ErrorKind};

        use crate::crypt::{UnlockReply, UnlockWay};
        self.password_used = true;
        // Kept for the job's error too: core may go on to say only that no key fit.
        if let Some(e) = &self.key_error {
            return Err(e.clone().into());
        }
        if request.attempt == 0 {
            self.typed = self.typed_answers(request);
        }
        if let Some(answer) = self.typed.pop() {
            return Ok(answer);
        }
        if self.unlock_prompts >= PASSWORD_PROMPTS {
            return Err(Error::new(
                ErrorKind::WrongPassword,
                "nothing given opens the archive: a wrong password or recovery key",
            ));
        }
        let ways = request
            .ways
            .iter()
            .map(|w| UnlockWay {
                slot: w.slot,
                kind: w.kind.into(),
                here: w.here,
            })
            .collect();
        let reply = self.prompt(Prompt::Unlock {
            ways,
            attempt: request.attempt,
        });
        match reply {
            Ok(PromptReply::Unlock { answer }) => {
                self.unlock_prompts += 1;
                Ok(match answer {
                    UnlockReply::Password { password } => {
                        self.password = Some(password.clone());
                        UnlockAnswer::Password(password)
                    }
                    UnlockReply::RecoveryKey { key } => UnlockAnswer::RecoveryKey(key),
                    UnlockReply::Slot { slot } => UnlockAnswer::Way(slot),
                })
            }
            // A front end that knows only passwords.
            Ok(PromptReply::Password { password }) => {
                self.unlock_prompts += 1;
                self.password = Some(password.clone());
                Ok(UnlockAnswer::Password(password))
            }
            Ok(PromptReply::Cancel) => Err(Error::cancelled()),
            Ok(other) => Err(Error::invalid_args(format!(
                "expected a way into the archive, got {other:?}"
            ))),
            Err(e)
                if request.attempt > 0
                    && matches!(e.code, ErrorCode::PasswordRequired | ErrorCode::KeyRequired) =>
            {
                Err(Error::new(
                    ErrorKind::WrongPassword,
                    "nothing given opens the archive: a wrong password or recovery key, and no \
                     key here fits",
                ))
            }
            Err(e) => {
                self.unlock_ways = Some(Self::ways_details(request)["ways"].clone());
                Err(e.into())
            }
        }
    }

    /// Your keys, the key files given and the system's; asked for only by an encrypted
    /// archive, which then never goes back to the archive cache, opened by a key or not.
    fn key_source(&mut self) -> Option<&mut dyn KeySource> {
        self.password_used = true;
        if self.keys.is_none() {
            let sources = self.sources();
            self.keys = Some(sources);
        }
        self.keys.as_mut().map(|s| s as &mut dyn KeySource)
    }

    /// Asks the front end before a password slot's Argon2 takes more than half this machine's
    /// memory (docs/M14.md §5); an unattended job (MCP) never spends it.
    fn spend_memory(&mut self, need: u64, total: u64) -> beezip_core::Result<bool> {
        if self.policy.unattended {
            return Ok(false);
        }
        self.check_cancelled()?;
        Ok(self
            .interactor
            .spend_memory(self.id, need >> 20, total >> 20))
    }

    fn overwrite_entry(
        &mut self,
        archive: &Path,
        entry: &str,
    ) -> beezip_core::Result<beezip_core::OverwriteChoice> {
        let name = archive.file_name().map_or_else(
            || archive.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        self.ask_overwrite(entry.to_owned(), Some(name))
    }
}

impl JobCtx {
    /// Asks about a file in the way, or an entry already in `archive`.
    fn ask_overwrite(
        &mut self,
        path: String,
        archive: Option<String>,
    ) -> beezip_core::Result<beezip_core::OverwriteChoice> {
        use beezip_core::{Error, OverwriteChoice as C};
        let reply = self.prompt(Prompt::Overwrite { path, archive });
        match reply {
            Ok(PromptReply::Overwrite { choice }) => Ok(match choice {
                OverwriteChoice::Replace => C::Replace,
                OverwriteChoice::ReplaceAll => C::ReplaceAll,
                OverwriteChoice::Skip => C::Skip,
                OverwriteChoice::SkipAll => C::SkipAll,
                OverwriteChoice::Rename => C::Rename,
            }),
            Ok(PromptReply::Cancel) => Err(Error::cancelled()),
            Ok(other) => Err(Error::invalid_args(format!(
                "expected an overwrite choice, got {other:?}"
            ))),
            Err(e) => Err(e.into()),
        }
    }
}
