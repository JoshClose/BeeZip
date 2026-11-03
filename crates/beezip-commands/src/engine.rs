use std::{
    collections::HashMap,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
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
    registry::RunFn,
};

/// Runs commands as jobs. Cheap to clone; clones share the job table.
///
/// M0 runs each job on its own thread. A blocking worker pool replaces that once commands do
/// real work.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

struct Inner {
    registry: &'static Registry,
    next_id: AtomicU64,
    jobs: Mutex<HashMap<JobId, Running>>,
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
    pub fn new(registry: &'static Registry) -> Self {
        Self {
            inner: Arc::new(Inner {
                registry,
                next_id: AtomicU64::new(1),
                jobs: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn registry(&self) -> &'static Registry {
        self.inner.registry
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
            .spawn(move || execute(&inner, id, run, args, job_cancel, sink, interactor))
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

fn execute(
    inner: &Inner,
    id: JobId,
    run: RunFn,
    args: Value,
    cancel: CancelToken,
    sink: EventSink,
    interactor: Arc<dyn Interactor>,
) -> Result<Value, CmdError> {
    sink(JobEvent::Started { job: id });
    let mut cx = JobCtx::new(id, cancel.clone(), Arc::clone(&sink), interactor);
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
            registry().by_cli_name("version").unwrap().name,
            "app.version"
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
