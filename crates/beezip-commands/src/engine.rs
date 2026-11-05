use std::{
    collections::HashMap,
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::{
    CancelToken, CmdError, ErrorCode, EventSink, Interactor, JobCtx, JobEvent, JobId, Registry,
    cache::ArchiveCache,
    config::{Config, LoadedConfig},
    policy::Policy,
    registry::RunFn,
};

/// Runs commands as jobs. Cheap to clone; clones share the job table.
///
/// Each job runs on its own thread: jobs are few and long, and the codecs bring their own
/// threads (docs/M1.md §11).
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

struct Inner {
    registry: &'static Registry,
    next_id: AtomicU64,
    jobs: Mutex<HashMap<JobId, Running>>,
    live: Arc<Live>,
    cache: Arc<ArchiveCache>,
}

/// The config and policy jobs start with. A job takes a snapshot of both when it starts;
/// `settings.set` replaces them for the jobs after it (docs/M4.md §7.3).
pub(crate) struct Live {
    config: RwLock<Arc<Result<Config, CmdError>>>,
    policy: RwLock<Arc<Policy>>,
    /// The file the config came from, which `settings.*` read and write.
    path: Option<PathBuf>,
}

impl Live {
    pub(crate) fn config(&self) -> Arc<Result<Config, CmdError>> {
        Arc::clone(&self.config.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    /// The new config, and the policy's limits from its `[limits]`.
    pub(crate) fn replace(&self, config: Config) {
        let mut policy = Policy::clone(&self.policy());
        policy.limits = config.limits();
        *self.policy.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(policy);
        *self.config.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(Ok(config));
    }
}

/// What the front ends set up once: the config (as loaded when the process started) and the
/// policy every job runs under.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// The config, or why it can't be used; commands that need it fail with that error.
    pub config: Result<Config, CmdError>,
    pub policy: Policy,
    /// The file the config came from. `settings.get` and `settings.set` use it; without one
    /// they use [`crate::config::config_path`].
    pub config_path: Option<PathBuf>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            config: Ok(Config::default()),
            policy: Policy::unrestricted(),
            config_path: None,
        }
    }
}

impl EngineOptions {
    /// The loaded config, with the policy's limits taken from its `[limits]`.
    pub fn from_config(config: Result<Config, CmdError>, mut policy: Policy) -> Self {
        if let Ok(c) = &config {
            policy.limits = c.limits();
        }
        Self {
            config,
            policy,
            config_path: None,
        }
    }

    /// [`EngineOptions::from_config`] with the file it came from.
    pub fn from_loaded(loaded: LoadedConfig, policy: Policy) -> Self {
        Self {
            config_path: loaded.path,
            ..Self::from_config(loaded.config, policy)
        }
    }
}

struct Running {
    command: &'static str,
    cancel: CancelToken,
}

/// A running job, as `Engine::jobs` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct JobInfo {
    pub id: JobId,
    pub command: String,
}

impl Inner {
    fn jobs(&self) -> MutexGuard<'_, HashMap<JobId, Running>> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Engine {
    /// An engine with the default config and an unrestricted policy.
    pub fn new(registry: &'static Registry) -> Self {
        Self::with_options(registry, EngineOptions::default())
    }

    pub fn with_options(registry: &'static Registry, options: EngineOptions) -> Self {
        Self {
            inner: Arc::new(Inner {
                registry,
                next_id: AtomicU64::new(1),
                jobs: Mutex::new(HashMap::new()),
                live: Arc::new(Live {
                    config: RwLock::new(Arc::new(options.config)),
                    policy: RwLock::new(Arc::new(options.policy)),
                    path: options.config_path,
                }),
                cache: Arc::new(ArchiveCache::new()),
            }),
        }
    }

    pub fn registry(&self) -> &'static Registry {
        self.inner.registry
    }

    /// The archives `archive.list`, `archive.info` and `entry.read` keep open between jobs.
    pub fn cache(&self) -> &ArchiveCache {
        &self.inner.cache
    }

    /// The policy jobs run under unless [`Engine::invoke_with_policy`] names another. Its
    /// limits follow `[limits]` when `settings.set` changes them.
    pub fn policy(&self) -> Arc<Policy> {
        self.inner.live.policy()
    }

    /// The config the next job starts with, or why it can't be used.
    pub fn config(&self) -> Arc<Result<Config, CmdError>> {
        self.inner.live.config()
    }

    /// Starts `name` with JSON `args` on a new job.
    ///
    /// Fails straight away only if there is no such command. Everything else, including
    /// arguments that don't deserialise, is reported through the job's events and
    /// [`JobHandle::join`], so front ends handle every failure in one place.
    pub fn invoke(
        &self,
        name: &str,
        args: Value,
        interactor: Arc<dyn Interactor>,
        sink: EventSink,
    ) -> Result<JobHandle, CmdError> {
        let policy = self.inner.live.policy();
        self.invoke_with_policy(name, args, interactor, sink, policy)
    }

    /// [`Engine::invoke`] under `policy` instead of the engine's. MCP builds one per call,
    /// since the client's roots can change during a session.
    pub fn invoke_with_policy(
        &self,
        name: &str,
        args: Value,
        interactor: Arc<dyn Interactor>,
        sink: EventSink,
        policy: Arc<Policy>,
    ) -> Result<JobHandle, CmdError> {
        let entry = self
            .inner
            .registry
            .get(name)
            .ok_or_else(|| CmdError::not_found(format!("no command named `{name}`")))?;
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancelToken::new();
        self.inner.jobs().insert(
            id,
            Running {
                command: entry.name,
                cancel: cancel.clone(),
            },
        );

        let run = entry.run;
        let inner = Arc::clone(&self.inner);
        let job_cancel = cancel.clone();
        let thread = std::thread::Builder::new()
            .name(format!("job-{id}"))
            .spawn(move || {
                let job = JobSetup {
                    id,
                    run,
                    cancel: job_cancel,
                    sink,
                    interactor,
                    policy,
                };
                execute(&inner, job, args)
            })
            .map_err(|e| {
                self.inner.jobs().remove(&id);
                CmdError::internal(format!("could not start a job thread: {e}"))
            })?;
        Ok(JobHandle { id, cancel, thread })
    }

    /// Requests cancellation. `false` if no such job is running.
    pub fn cancel(&self, id: JobId) -> bool {
        match self.inner.jobs().get(&id) {
            Some(job) => {
                job.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Whether job `id` was cancelled, or has ended.
    pub fn is_cancelled(&self, id: JobId) -> bool {
        self.inner
            .jobs()
            .get(&id)
            .is_none_or(|job| job.cancel.is_cancelled())
    }

    /// The running jobs, oldest first.
    pub fn jobs(&self) -> Vec<JobInfo> {
        let mut jobs: Vec<JobInfo> = self
            .inner
            .jobs()
            .iter()
            .map(|(&id, job)| JobInfo {
                id,
                command: job.command.to_owned(),
            })
            .collect();
        jobs.sort_by_key(|j| j.id);
        jobs
    }
}

/// Everything a job thread needs besides its arguments.
struct JobSetup {
    id: JobId,
    run: RunFn,
    cancel: CancelToken,
    sink: EventSink,
    interactor: Arc<dyn Interactor>,
    policy: Arc<Policy>,
}

fn execute(inner: &Inner, job: JobSetup, args: Value) -> Result<Value, CmdError> {
    let JobSetup {
        id,
        run,
        cancel,
        sink,
        interactor,
        policy,
    } = job;
    sink(JobEvent::Started { job: id });
    let mut cx = JobCtx::new(
        id,
        cancel.clone(),
        Arc::clone(&sink),
        interactor,
        policy,
        Arc::clone(&inner.live),
        Some(Arc::clone(&inner.cache)),
    );
    let result = if cancel.is_cancelled() {
        Err(CmdError::cancelled())
    } else {
        // A panic in a command (a decoder bug, say) must not take down the GUI or the MCP server.
        panic::catch_unwind(AssertUnwindSafe(|| run(args, &mut cx))).unwrap_or_else(|payload| {
            Err(CmdError::internal(format!(
                "command panicked: {}",
                panic_message(payload.as_ref())
            )))
        })
    };
    // The last progress update always goes out, before the final event.
    cx.flush_progress();
    inner.jobs().remove(&id);
    sink(match &result {
        Ok(output) => JobEvent::Finished {
            output: output.clone(),
        },
        Err(e) if e.code == ErrorCode::Cancelled => JobEvent::Cancelled,
        Err(e) => JobEvent::Failed { error: e.clone() },
    });
    result
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s
    } else {
        "unknown panic payload"
    }
}

/// A started job. Dropping it detaches the job, which keeps running.
pub struct JobHandle {
    id: JobId,
    cancel: CancelToken,
    thread: JoinHandle<Result<Value, CmdError>>,
}

impl JobHandle {
    pub fn id(&self) -> JobId {
        self.id
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Blocks until the job ends and returns its output.
    pub fn join(self) -> Result<Value, CmdError> {
        self.thread.join().unwrap_or_else(|payload| {
            Err(CmdError::internal(format!(
                "job thread panicked: {}",
                panic_message(payload.as_ref())
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;
    use crate::{Command, Effect, NonInteractive, registry};

    /// Panics, to test that the engine contains it.
    #[derive(Debug, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
    struct PanicsInput {}

    struct Panics;

    impl Command for Panics {
        const NAME: &'static str = "test.panics";
        const EFFECT: Effect = Effect::ReadOnly;
        type Input = PanicsInput;
        type Output = ();

        fn run(_: PanicsInput, _: &mut JobCtx) -> Result<(), CmdError> {
            panic!("boom");
        }
    }

    fn engine_with_panics() -> Engine {
        let mut reg = Registry::new();
        reg.register::<Panics>();
        Engine::new(Box::leak(Box::new(reg)))
    }

    /// Runs a job to completion and returns its result and every event it emitted.
    fn run(engine: &Engine, name: &str, args: Value) -> (Result<Value, CmdError>, Vec<JobEvent>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = Arc::clone(&events);
        let sink: EventSink = Arc::new(move |e| sink_events.lock().unwrap().push(e));
        let result = engine
            .invoke(name, args, Arc::new(NonInteractive), sink)
            .unwrap()
            .join();
        let events = events.lock().unwrap().clone();
        (result, events)
    }

    #[test]
    fn registry_lookup() {
        assert!(registry().get("app.version").is_some());
        assert!(registry().get("app.nope").is_none());
        assert_eq!(
            registry().by_cli_name(None, "version").unwrap().name,
            "app.version"
        );
        assert_eq!(
            registry()
                .by_cli_name(Some("settings"), "set")
                .unwrap()
                .name,
            "settings.set"
        );
        assert!(registry().by_cli_name(None, "set").is_none());
        assert!(
            registry()
                .by_cli_name(Some("settings"), "version")
                .is_none()
        );
    }

    #[test]
    fn every_command_is_documented_and_takes_an_object() {
        for entry in registry().entries() {
            assert!(
                !entry.description.is_empty(),
                "{} has no doc comment",
                entry.name
            );
            assert_eq!(
                entry.input_schema.get("type"),
                Some(&json!("object")),
                "{}",
                entry.name
            );
        }
    }

    #[test]
    fn unknown_command_is_not_found() {
        let engine = Engine::new(registry());
        let err = engine
            .invoke(
                "no.such",
                json!({}),
                Arc::new(NonInteractive),
                crate::discard_events(),
            )
            .err()
            .unwrap();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[test]
    fn app_version_runs() {
        let (result, events) = run(&Engine::new(registry()), "app.version", json!({}));
        let output = result.unwrap();
        assert_eq!(output["version"], env!("CARGO_PKG_VERSION"));
        assert!(matches!(events.first(), Some(JobEvent::Started { .. })));
        assert_eq!(events.last(), Some(&JobEvent::Finished { output }));
    }

    #[test]
    fn unknown_fields_are_invalid_args() {
        let (result, events) = run(&Engine::new(registry()), "app.version", json!({"bogus": 1}));
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
        assert_eq!(events.last(), Some(&JobEvent::Failed { error: err }));
    }

    #[test]
    fn panic_becomes_internal() {
        let engine = engine_with_panics();
        let (result, events) = run(&engine, "test.panics", json!({}));
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert!(err.message.contains("boom"), "{}", err.message);
        assert_eq!(events.last(), Some(&JobEvent::Failed { error: err }));
        assert!(engine.jobs().is_empty());
    }
}
