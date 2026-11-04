//! The BeeZip MCP server (docs/M2.md).
//!
//! `ServerHandler` is implemented by hand rather than with rmcp's `#[tool]` macros: `list_tools`
//! and `call_tool` walk the command registry, so a new command needs no MCP-specific code
//! (PLAN §1, Front ends).
//!
//! - **Sandbox:** writes go only under `--root` directories, narrowed by the client's roots
//!   where it still shares them ([`sandbox`]).
//! - **Progress** goes out as `notifications/progress` when the request has a `progressToken`.
//! - **Cancellation:** `notifications/cancelled` cancels the job.
//! - **Questions:** overwrite questions are elicited. Protocol 2026-07-28 forbids requests to
//!   the client, so the job is parked and an `InputRequiredResult` goes back. The client's
//!   retry carries the answer and resumes the job. Older sessions get a plain
//!   `elicitation/create`. Passwords are never elicited ([`prompt`]).

mod call;
mod prompt;
mod sandbox;

use std::{
    borrow::Cow,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use beezip_commands::{
    CmdError, Effect, Engine, Entry, JsonObject, Policy, Prompt, PromptReply, Registry,
    policy::display_path,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ElicitRequest,
        ElicitRequestParams, ElicitResult, Implementation, InputRequest, InputRequests,
        InputRequiredResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
        ServerConfig, Tool, ToolAnnotations,
    },
    service::{NotificationContext, RequestContext},
};
use serde_json::Value;
use tokio::sync::oneshot;

use crate::{
    call::{Answer, Job, Next, Reporter},
    sandbox::Sandbox,
};

/// The most entries one `archive_list` call returns.
pub const MAX_LIST_ENTRIES: u64 = 500;
/// The most bytes one `entry_read` call returns.
pub const MAX_READ_BYTES: u64 = 256 * 1024;
/// How long a job waiting on an answer stays parked for the client's retry.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// How long a write waits for the client's `roots/list` answer.
const ROOTS_TIMEOUT: Duration = Duration::from_secs(10);

/// How `beezip mcp` was started.
#[derive(Debug, Clone)]
pub struct McpOptions {
    /// Directories commands may write under (`--root`, or `[mcp] roots`).
    pub roots: Vec<PathBuf>,
    /// Refuse, and don't list, every command that writes.
    pub read_only: bool,
    /// Write anywhere.
    pub unrestricted: bool,
    pub prompt_timeout: Duration,
}

impl Default for McpOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            read_only: false,
            unrestricted: false,
            prompt_timeout: PROMPT_TIMEOUT,
        }
    }
}

/// The MCP tool name for a command: `archive.extract` becomes `archive_extract`, since some
/// clients reject dots in tool names.
pub fn tool_name(command: &str) -> String {
    command.replace('.', "_")
}

/// The MCP tool for every command the MCP surface exposes, sorted by name.
pub fn tools(registry: &Registry) -> Vec<Tool> {
    registry
        .entries()
        .iter()
        .filter(|e| e.surfaces.mcp)
        .map(tool)
        .collect()
}

fn tool(entry: &Entry) -> Tool {
    let annotations = ToolAnnotations::new()
        .read_only(entry.effect == Effect::ReadOnly)
        .destructive(entry.effect == Effect::Destructive)
        .open_world(false);
    Tool::new(
        tool_name(entry.name),
        entry.description.clone(),
        Arc::clone(&entry.input_schema),
    )
    .with_raw_output_schema(Arc::clone(&entry.output_schema))
    .with_annotations(annotations)
}

/// A job and the call it belongs to, which a retry must repeat.
struct Call {
    job: Job,
    tool: Cow<'static, str>,
    args: Option<JsonObject>,
}

/// A job waiting for an MRTR retry to bring the answer to its question.
struct Parked {
    call: Call,
    prompt: Prompt,
    reply: oneshot::Sender<Answer>,
}

type ParkedJobs = Arc<Mutex<HashMap<String, Parked>>>;

fn lock(parked: &ParkedJobs) -> MutexGuard<'_, HashMap<String, Parked>> {
    parked.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct BeeZipServer {
    engine: Engine,
    /// The engine's policy with MCP's caps; each call adds the sandbox's roots.
    base: Policy,
    sandbox: Sandbox,
    prompt_timeout: Duration,
    parked: ParkedJobs,
}

impl BeeZipServer {
    /// Fails if a root doesn't exist.
    pub fn new(engine: Engine, options: &McpOptions) -> Result<Self, CmdError> {
        let sandbox = Sandbox::new(&options.roots, options.read_only, options.unrestricted)?;
        let mut base = engine.policy().clone();
        base.max_list_entries = Some(MAX_LIST_ENTRIES);
        base.max_read_bytes = Some(MAX_READ_BYTES);
        Ok(Self {
            engine,
            base,
            sandbox,
            prompt_timeout: options.prompt_timeout,
            parked: ParkedJobs::default(),
        })
    }

    /// Whether this server offers `entry` as a tool. `--read-only` drops the ones that write.
    fn offers(&self, entry: &Entry) -> bool {
        entry.surfaces.mcp && !(self.sandbox.read_only() && entry.effect != Effect::ReadOnly)
    }

    fn find(&self, tool: &str) -> Option<&'static Entry> {
        self.engine
            .registry()
            .entries()
            .iter()
            .find(|e| self.offers(e) && tool_name(e.name) == tool)
    }

    fn instructions(&self) -> String {
        let cwd = std::env::current_dir()
            .map(|d| display_path(&d))
            .unwrap_or_else(|_| "unknown".to_owned());
        format!(
            "BeeZip lists, tests, extracts and creates archives (zip, 7z, tar, and tar \
             compressed with gzip, zstd, xz and others), reads RAR, and compresses single \
             files. Any part of a split archive (`a.7z.002`, `a.part3.rar`) opens the whole \
             set.\n\
             - Pass absolute paths. Relative ones resolve against the server's working \
             directory, {cwd}.\n\
             - {writes}\n\
             - archive_list returns at most {MAX_LIST_ENTRIES} entries per call: while \
             `has_more` is true, call it again with a larger `offset`. entry_read returns at \
             most {read_kib} KiB per call: continue from `offset + bytes_read` until `eof` is \
             true.\n\
             - BeeZip never asks for passwords. After a PasswordRequired error, ask the user \
             for the password and call again with `password`.\n\
             - A file already in the way is a Conflict error unless `overwrite` is given \
             (always, never, rename or newer). Clients that support elicitation ask the user \
             instead.\n\
             - Errors come back with isError set and structured content `{{code, message, \
             details}}`. The `code` is stable.",
            writes = self.sandbox.describe(),
            read_kib = MAX_READ_BYTES / 1024,
        )
    }

    async fn start(
        &self,
        request: CallToolRequestParams,
        cx: &RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let Some(entry) = self.find(&request.name) else {
            return Err(ErrorData::invalid_params(
                format!("unknown tool `{}`", request.name),
                None,
            ));
        };
        let writes = entry.effect != Effect::ReadOnly;
        if writes && shares_roots(cx) && self.sandbox.needs_client_roots() {
            self.fetch_client_roots(cx).await;
        }
        let policy = match self.sandbox.policy(&self.base, writes) {
            Ok(p) => p,
            Err(err) => return Ok(error_result(&err).into()),
        };
        let args = Value::Object(request.arguments.clone().unwrap_or_default());
        let job = match Job::start(&self.engine, entry.name, args, policy) {
            Ok(job) => job,
            Err(err) => return Ok(error_result(&err).into()),
        };
        let call = Call {
            job,
            tool: request.name,
            args: request.arguments,
        };
        Ok(self.drive(call, cx).await)
    }

    /// An MRTR retry: hand the answer to the parked job and drive it on.
    async fn resume(
        &self,
        request: CallToolRequestParams,
        state: &str,
        cx: &RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let Some(parked) = lock(&self.parked).remove(state) else {
            let err = CmdError::invalid_args(
                "this call's `requestState` is unknown, already used or expired; call the tool \
                 again without it",
            );
            return Ok(error_result(&err).into());
        };
        if parked.call.tool != request.name || parked.call.args != request.arguments {
            // Not the retry; the real one can still come.
            lock(&self.parked).insert(state.to_owned(), parked);
            let err = CmdError::invalid_args(
                "this `requestState` belongs to another call; retry with the tool and arguments \
                 of the call that returned it",
            );
            return Ok(error_result(&err).into());
        }
        let Parked {
            call,
            prompt,
            reply,
        } = parked;
        let answer = request
            .input_responses
            .as_ref()
            .and_then(|r| r.get(prompt::OVERWRITE_KEY))
            .and_then(|v| serde_json::from_value::<ElicitResult>(v.clone()).ok())
            .and_then(|a| prompt::reply(&prompt, &a));
        match (answer, prompt::form(&prompt)) {
            (Some(answer), _) => {
                let _ = reply.send(Ok(answer));
                Ok(self.drive(call, cx).await)
            }
            // A missing or unusable answer: ask again.
            (None, Some(form)) => Ok(self.park(call, prompt, reply, form).into()),
            (None, None) => {
                let _ = reply.send(Err(prompt::unanswerable(&prompt)));
                Ok(self.drive(call, cx).await)
            }
        }
    }

    /// Runs the call's job until it ends, answering its questions on the way.
    async fn drive(&self, mut call: Call, cx: &RequestContext<RoleServer>) -> CallToolResponse {
        let mut reporter = Reporter::new(cx);
        loop {
            let (prompt, reply) = match call.job.next(&mut reporter, &cx.ct).await {
                Next::Done(result) => return tool_result(result).into(),
                Next::Question { prompt, reply } => (prompt, reply),
            };
            let form = prompt::form(&prompt);
            match (asking(cx), form) {
                (Asking::Mrtr, Some(form)) => return self.park(call, prompt, reply, form).into(),
                (Asking::Request, Some(form)) => match ask(cx, &prompt, form).await {
                    Some(answer) => {
                        let _ = reply.send(answer);
                    }
                    None => {
                        call.job.cancel();
                        return tool_result(Err(CmdError::cancelled())).into();
                    }
                },
                _ => {
                    let _ = reply.send(Err(prompt::unanswerable(&prompt)));
                }
            }
        }
    }

    /// Parks the job until the client retries with the answer, or `prompt_timeout` passes.
    fn park(
        &self,
        call: Call,
        prompt: Prompt,
        reply: oneshot::Sender<Answer>,
        form: ElicitRequestParams,
    ) -> InputRequiredResult {
        // Only a handle: the state itself stays here, so there is nothing to tamper with.
        let state = uuid::Uuid::new_v4().to_string();
        lock(&self.parked).insert(
            state.clone(),
            Parked {
                call,
                prompt,
                reply,
            },
        );
        let parked = Arc::clone(&self.parked);
        let ttl = self.prompt_timeout;
        let key = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            let expired = lock(&parked).remove(&key);
            // Dropping the reply ends the job as cancelled, and it removes its partial files.
            if let Some(p) = expired {
                p.call.job.cancel();
            }
        });
        let mut requests = InputRequests::new();
        requests.insert(
            prompt::OVERWRITE_KEY.to_owned(),
            InputRequest::Elicitation(ElicitRequest::new(form)),
        );
        InputRequiredResult::new(Some(requests), Some(state))
    }

    #[allow(
        deprecated,
        reason = "roots are deprecated in 2026-07-28; older clients have them"
    )]
    async fn fetch_client_roots(&self, cx: &RequestContext<RoleServer>) {
        match tokio::time::timeout(ROOTS_TIMEOUT, cx.peer.list_roots()).await {
            Ok(Ok(list)) => self
                .sandbox
                .set_client_roots(list.roots.iter().map(|r| r.uri.as_str())),
            failed => {
                let why = match failed {
                    Ok(Err(e)) => e.to_string(),
                    _ => "no answer".to_owned(),
                };
                eprintln!(
                    "beezip mcp: the client's roots/list failed ({why}); writes are confined to \
                     --root alone"
                );
                self.sandbox.set_client_roots([]);
            }
        }
    }
}

/// How a question can reach the user.
enum Asking {
    /// The client has no form elicitation.
    No,
    /// A plain `elicitation/create` request (protocol 2025-11-25 and older).
    Request,
    /// An `InputRequiredResult` and a retry (2026-07-28 on).
    Mrtr,
}

fn modern(cx: &RequestContext<RoleServer>) -> bool {
    cx.protocol_version().is_some_and(|v| !v.has_initialize())
}

fn asking(cx: &RequestContext<RoleServer>) -> Asking {
    let form = cx
        .client_capabilities()
        .and_then(|c| c.elicitation)
        // An empty `elicitation` object means form mode.
        .is_some_and(|e| e.form.is_some() || e.url.is_none());
    match (form, modern(cx)) {
        (false, _) => Asking::No,
        (true, false) => Asking::Request,
        (true, true) => Asking::Mrtr,
    }
}

/// Whether the client shares roots: only sessions from before 2026-07-28 can.
#[allow(
    deprecated,
    reason = "roots are deprecated in 2026-07-28; older clients have them"
)]
fn shares_roots(cx: &RequestContext<RoleServer>) -> bool {
    !modern(cx) && cx.client_capabilities().is_some_and(|c| c.roots.is_some())
}

/// Asks over `elicitation/create`, again if the answer doesn't fit. `None` if the call was
/// cancelled meanwhile.
async fn ask(
    cx: &RequestContext<RoleServer>,
    prompt: &Prompt,
    form: ElicitRequestParams,
) -> Option<Answer> {
    for _ in 0..3 {
        let result = tokio::select! {
            r = cx.peer.create_elicitation(form.clone()) => r,
            () = cx.ct.cancelled() => return None,
        };
        match result {
            Ok(answer) => {
                if let Some(reply) = prompt::reply(prompt, &answer) {
                    return Some(Ok(reply));
                }
            }
            Err(_) => return Some(Err(prompt::unanswerable(prompt))),
        }
    }
    Some(Ok(PromptReply::Cancel))
}

fn tool_result(result: Result<Value, CmdError>) -> CallToolResult {
    match result {
        Ok(output) => CallToolResult::structured(output),
        Err(err) => error_result(&err),
    }
}

/// `isError`, with the `CmdError` as structured content and as text. Clients skip the output
/// schema when `isError` is set.
fn error_result(err: &CmdError) -> CallToolResult {
    CallToolResult::structured_error(serde_json::to_value(err).unwrap_or(Value::Null))
}

impl ServerHandler for BeeZipServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("beezip", env!("CARGO_PKG_VERSION")))
            .with_instructions(self.instructions())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self
            .engine
            .registry()
            .entries()
            .iter()
            .filter(|e| self.offers(e))
            .map(tool)
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        cx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        match request.request_state.clone() {
            Some(state) => self.resume(request, &state, &cx).await,
            None => self.start(request, &cx).await,
        }
    }

    async fn on_roots_list_changed(&self, _cx: NotificationContext<RoleServer>) {
        self.sandbox.client_roots_changed();
    }
}

/// Serves MCP over stdin/stdout until the client disconnects.
pub async fn serve_stdio(server: BeeZipServer) -> anyhow::Result<()> {
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// [`serve_stdio`] on a current-thread tokio runtime. `beezip mcp` is the only CLI path that
/// starts tokio. Jobs still running when the client goes are cancelled, so they clean up.
pub fn serve_stdio_blocking(server: BeeZipServer) -> anyhow::Result<()> {
    let engine = server.engine.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(serve_stdio(server));
    for job in engine.jobs() {
        engine.cancel(job.id);
    }
    runtime.shutdown_timeout(Duration::from_secs(10));
    result
}
