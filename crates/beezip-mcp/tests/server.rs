//! The MCP server in-process, driven by an rmcp client over an in-memory pipe (docs/M2.md §6).
//!
//! The registry is the real one plus three test commands: `test.ask` asks overwrite
//! questions, `test.wait` reports progress until it is done or cancelled, and `test.write`
//! writes a file where it is told to.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use beezip_commands::{
    Access, CmdError, Command, Effect, Engine, JobCtx, Progress, Prompt, PromptReply, Registry,
    commands::register_all, policy::display_path,
};
use beezip_mcp::{BeeZipServer, MAX_LIST_ENTRIES, MAX_READ_BYTES, McpOptions};
use rmcp::{
    ClientHandler, ErrorData, ServiceExt,
    model::{
        CallToolRequest, CallToolRequestParams, CallToolResponse, CallToolResult,
        ClientCapabilities, ClientConfig, ClientRequest, ElicitRequestParams, ElicitResult,
        ElicitationAction, Implementation, InputRequiredResult, ProgressNotificationParam,
        ProtocolVersion,
    },
    service::{
        ClientLifecycleMode, ClientServiceExt, NotificationContext, PeerRequestOptions,
        RequestContext, RoleClient, RunningService,
    },
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

// ---------------------------------------------------------------------------------------------
// Test commands

/// Asks whether to replace `path`, `times` times, and returns the answers.
#[derive(Debug, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
struct AskInput {
    path: String,
    #[arg(long)]
    #[serde(default)]
    times: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, TS)]
struct AskOutput {
    answers: Vec<String>,
}

struct Ask;

impl Command for Ask {
    const NAME: &'static str = "test.ask";
    const EFFECT: Effect = Effect::ReadOnly;
    type Input = AskInput;
    type Output = AskOutput;

    fn run(input: AskInput, cx: &mut JobCtx) -> Result<AskOutput, CmdError> {
        let mut answers = Vec::new();
        for _ in 0..input.times.unwrap_or(1) {
            match cx.prompt(Prompt::Overwrite {
                path: input.path.clone(),
            })? {
                PromptReply::Overwrite { choice } => answers.push(format!("{choice:?}")),
                _ => return Err(CmdError::cancelled()),
            }
        }
        Ok(AskOutput { answers })
    }
}

/// Reports progress `steps` times, 120 ms apart (until cancelled if unset; 30 s at most).
#[derive(Debug, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
struct WaitInput {
    #[arg(long)]
    #[serde(default)]
    steps: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, TS)]
struct WaitOutput {
    steps: u64,
}

struct Wait;

impl Command for Wait {
    const NAME: &'static str = "test.wait";
    const EFFECT: Effect = Effect::ReadOnly;
    type Input = WaitInput;
    type Output = WaitOutput;

    fn run(input: WaitInput, cx: &mut JobCtx) -> Result<WaitOutput, CmdError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut done = 0;
        while input.steps.is_none_or(|s| done < s) && Instant::now() < deadline {
            cx.check_cancelled()?;
            done += 1;
            cx.progress(Progress {
                bytes_done: done,
                bytes_total: input.steps,
                entries_done: done,
                ..Progress::default()
            });
            std::thread::sleep(Duration::from_millis(120));
        }
        Ok(WaitOutput { steps: done })
    }
}

/// Writes `ok` to `path`.
#[derive(Debug, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
struct WriteInput {
    path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, TS)]
struct WriteOutput {
    written: bool,
}

struct Write;

impl Command for Write {
    const NAME: &'static str = "test.write";
    const EFFECT: Effect = Effect::Writes;
    type Input = WriteInput;
    type Output = WriteOutput;

    fn access(input: &WriteInput) -> Vec<Access> {
        vec![Access::Write(input.path.clone())]
    }

    fn run(input: WriteInput, _cx: &mut JobCtx) -> Result<WriteOutput, CmdError> {
        std::fs::write(&input.path, "ok").map_err(|e| CmdError::internal(e.to_string()))?;
        Ok(WriteOutput { written: true })
    }
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut r = Registry::new();
        register_all(&mut r);
        r.register::<Ask>().register::<Wait>().register::<Write>();
        r
    })
}

// ---------------------------------------------------------------------------------------------
// The client

#[derive(Default)]
struct Seen {
    /// Elicitation answers to give, in order; `decline` once they run out.
    answers: Mutex<VecDeque<ElicitResult>>,
    /// The messages of the elicitations asked.
    asked: Mutex<Vec<String>>,
    /// The roots to share, as URIs.
    roots: Mutex<Vec<String>>,
    progress: Mutex<Vec<f64>>,
}

#[derive(Clone, Default)]
struct TestClient {
    elicitation: bool,
    roots: bool,
    seen: Arc<Seen>,
}

impl TestClient {
    fn new() -> Self {
        Self::default()
    }

    fn eliciting(mut self, answers: impl IntoIterator<Item = ElicitResult>) -> Self {
        self.elicitation = true;
        self.seen.answers.lock().unwrap().extend(answers);
        self
    }

    fn with_roots(mut self, roots: &[&Path]) -> Self {
        self.roots = true;
        *self.seen.roots.lock().unwrap() = roots.iter().map(|r| uri(r)).collect();
        self
    }

    fn asked(&self) -> Vec<String> {
        self.seen.asked.lock().unwrap().clone()
    }

    fn progress(&self) -> Vec<f64> {
        self.seen.progress.lock().unwrap().clone()
    }
}

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        let mut caps = serde_json::Map::new();
        if self.elicitation {
            caps.insert("elicitation".to_owned(), json!({ "form": {} }));
        }
        if self.roots {
            caps.insert("roots".to_owned(), json!({ "listChanged": true }));
        }
        let caps: ClientCapabilities = serde_json::from_value(Value::Object(caps)).unwrap();
        ClientConfig::new(caps, Implementation::new("beezip-test", "0"))
    }

    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        _cx: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        if let ElicitRequestParams::FormElicitationParams { message, .. } = &request {
            self.seen.asked.lock().unwrap().push(message.clone());
        }
        let next = self.seen.answers.lock().unwrap().pop_front();
        Ok(next.unwrap_or_else(|| ElicitResult::new(ElicitationAction::Decline)))
    }

    #[allow(deprecated, reason = "roots are what older clients use")]
    async fn list_roots(
        &self,
        _cx: RequestContext<RoleClient>,
    ) -> Result<rmcp::model::ListRootsResult, ErrorData> {
        let roots = self.seen.roots.lock().unwrap().clone();
        Ok(rmcp::model::ListRootsResult::new(
            roots.into_iter().map(rmcp::model::Root::new).collect(),
        ))
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _cx: NotificationContext<RoleClient>,
    ) {
        self.seen.progress.lock().unwrap().push(params.progress);
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers

struct Harness {
    engine: Engine,
    client: RunningService<RoleClient, TestClient>,
}

/// A server with `options`, and `client` connected to it: over `initialize` (2025-11-25), or
/// with the 2026-07-28 lifecycle when `modern`.
async fn connect(options: McpOptions, client: TestClient, modern: bool) -> Harness {
    let engine = Engine::new(registry());
    let server = BeeZipServer::new(engine.clone(), &options).unwrap();
    let (server_end, client_end) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_end).await {
            let _ = running.waiting().await;
        }
    });
    let client = if modern {
        client
            .serve_with_lifecycle(
                client_end,
                ClientLifecycleMode::Discover {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                },
            )
            .await
            .unwrap()
    } else {
        client.serve(client_end).await.unwrap()
    };
    Harness { engine, client }
}

fn rooted(root: &Path) -> McpOptions {
    McpOptions {
        roots: vec![root.to_path_buf()],
        ..McpOptions::default()
    }
}

fn call(tool: &str, args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(tool.to_owned()).with_arguments(args.as_object().unwrap().clone())
}

fn output(result: &CallToolResult) -> &Value {
    assert_eq!(result.is_error, Some(false), "{result:?}");
    result.structured_content.as_ref().unwrap()
}

/// The error's `code` and `message`.
fn error(result: &CallToolResult) -> (String, String) {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    let e = result.structured_content.as_ref().unwrap();
    (
        e["code"].as_str().unwrap().to_owned(),
        e["message"].as_str().unwrap().to_owned(),
    )
}

fn complete(response: CallToolResponse) -> CallToolResult {
    match response {
        CallToolResponse::Complete(r) => r,
        other => panic!("expected a complete result, got {other:?}"),
    }
}

fn input_required(response: CallToolResponse) -> InputRequiredResult {
    match response {
        CallToolResponse::InputRequired(r) => r,
        other => panic!("expected input_required, got {other:?}"),
    }
}

fn accept(choice: &str) -> ElicitResult {
    ElicitResult::new(ElicitationAction::Accept).with_content(json!({ "choice": choice }))
}

/// A retry of `first` with `state`, answering the overwrite question with `choice`.
fn retry(
    first: &CallToolRequestParams,
    state: &str,
    choice: Option<&str>,
) -> CallToolRequestParams {
    let mut p = first.clone();
    p.request_state = Some(state.to_owned());
    p.input_responses = choice.map(|c| {
        BTreeMap::from([(
            "overwrite".to_owned(),
            serde_json::to_value(accept(c)).unwrap(),
        )])
    });
    p
}

/// A path as a `file://` URI, as clients send roots.
fn uri(path: &Path) -> String {
    url::Url::from_file_path(display_path(path))
        .unwrap()
        .to_string()
}

/// A temporary directory, canonical, with `a/` and `b/` inside.
fn sandbox() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::create_dir(root.join("a")).unwrap();
    std::fs::create_dir(root.join("b")).unwrap();
    (dir, root)
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .display()
        .to_string()
}

// ---------------------------------------------------------------------------------------------
// Questions

#[tokio::test]
async fn legacy_sessions_elicit_overwrite_questions() {
    let client = TestClient::new().eliciting([accept("replace_all")]);
    let h = connect(McpOptions::default(), client.clone(), false).await;

    let r = h
        .client
        .call_tool(call("test_ask", json!({ "path": "C:\\out\\a.txt" })))
        .await
        .unwrap();
    assert_eq!(output(&r)["answers"], json!(["ReplaceAll"]));
    assert!(client.asked()[0].contains("a.txt"), "{:?}", client.asked());

    // Declining stops the job.
    let r = h
        .client
        .call_tool(call("test_ask", json!({ "path": "b.txt" })))
        .await
        .unwrap();
    assert_eq!(error(&r).0, "Cancelled");
}

#[tokio::test]
async fn without_elicitation_a_question_is_a_conflict() {
    for modern in [false, true] {
        let h = connect(McpOptions::default(), TestClient::new(), modern).await;
        let r = h
            .client
            .call_tool(call("test_ask", json!({ "path": "a.txt" })))
            .await
            .unwrap();
        let (code, message) = error(&r);
        assert_eq!(code, "Conflict", "modern: {modern}");
        assert!(message.contains("`overwrite`"), "{message}");
    }
}

#[tokio::test]
async fn mrtr_parks_the_job_until_the_retry() {
    // rmcp's client drives the rounds itself.
    let client = TestClient::new().eliciting([accept("skip"), accept("rename")]);
    let h = connect(McpOptions::default(), client.clone(), true).await;
    let r = h
        .client
        .call_tool(call("test_ask", json!({ "path": "a.txt", "times": 2 })))
        .await
        .unwrap();
    assert_eq!(output(&r)["answers"], json!(["Skip", "Rename"]));
    assert_eq!(client.asked().len(), 2);

    // By hand.
    let first = call("test_ask", json!({ "path": "a.txt" }));
    let ir = input_required(h.client.call_tool_once(first.clone()).await.unwrap());
    let state = ir.request_state.clone().unwrap();
    assert!(ir.input_requests.unwrap().contains_key("overwrite"));
    assert_eq!(h.engine.jobs().len(), 1, "the job waits, parked");

    // A retry with other arguments is refused; the job stays parked.
    let mut other = retry(&first, &state, Some("replace"));
    other.arguments = Some(json!({ "path": "b.txt" }).as_object().unwrap().clone());
    let (code, _) = error(&complete(h.client.call_tool_once(other).await.unwrap()));
    assert_eq!(code, "InvalidArgs");

    // No answer: the question again, under a new handle. The old one is used up.
    let again = input_required(
        h.client
            .call_tool_once(retry(&first, &state, None))
            .await
            .unwrap(),
    );
    let state2 = again.request_state.unwrap();
    assert_ne!(state2, state);
    let (code, _) = error(&complete(
        h.client
            .call_tool_once(retry(&first, &state, Some("replace")))
            .await
            .unwrap(),
    ));
    assert_eq!(code, "InvalidArgs");

    let r = complete(
        h.client
            .call_tool_once(retry(&first, &state2, Some("replace")))
            .await
            .unwrap(),
    );
    assert_eq!(output(&r)["answers"], json!(["Replace"]));
    wait_until("the job to end", || h.engine.jobs().is_empty()).await;
}

#[tokio::test]
async fn a_parked_job_expires_without_its_retry() {
    let options = McpOptions {
        prompt_timeout: Duration::from_millis(200),
        ..McpOptions::default()
    };
    let h = connect(options, TestClient::new().eliciting([]), true).await;
    let first = call("test_ask", json!({ "path": "a.txt" }));
    let ir = input_required(h.client.call_tool_once(first.clone()).await.unwrap());
    assert_eq!(h.engine.jobs().len(), 1);
    wait_until("the parked job to expire", || h.engine.jobs().is_empty()).await;

    let late = retry(&first, &ir.request_state.unwrap(), Some("replace"));
    let (code, message) = error(&complete(h.client.call_tool_once(late).await.unwrap()));
    assert_eq!(code, "InvalidArgs");
    assert!(message.contains("expired"), "{message}");
}

#[tokio::test]
async fn passwords_are_never_elicited() {
    let client = TestClient::new().eliciting([accept("replace")]);
    let h = connect(McpOptions::default(), client.clone(), false).await;
    let archive = fixture("thirdparty/7z-aes256.zip");

    let r = h
        .client
        .call_tool(call("archive_test", json!({ "archive": archive })))
        .await
        .unwrap();
    assert_eq!(error(&r).0, "PasswordRequired");
    assert_eq!(
        r.structured_content.unwrap()["details"],
        json!({ "param": "password" })
    );
    assert!(client.asked().is_empty());

    let r = h
        .client
        .call_tool(call(
            "archive_test",
            json!({ "archive": archive, "password": "beezip" }),
        ))
        .await
        .unwrap();
    output(&r);
}

// ---------------------------------------------------------------------------------------------
// Progress and cancellation

#[tokio::test]
async fn progress_reaches_the_client() {
    let client = TestClient::new();
    let h = connect(McpOptions::default(), client.clone(), false).await;
    let r = h
        .client
        .call_tool(call("test_wait", json!({ "steps": 4 })))
        .await
        .unwrap();
    assert_eq!(output(&r)["steps"], 4);
    wait_until("four progress notifications", || {
        client.progress().len() >= 4
    })
    .await;
    let mut seen = client.progress();
    seen.sort_by(f64::total_cmp);
    assert_eq!(seen, [1.0, 2.0, 3.0, 4.0]);
}

#[tokio::test]
async fn cancelling_a_call_cancels_its_job() {
    let client = TestClient::new();
    let h = connect(McpOptions::default(), client.clone(), false).await;
    let request =
        ClientRequest::CallToolRequest(CallToolRequest::new(call("test_wait", json!({}))));
    let handle = h
        .client
        .peer()
        .send_cancellable_request(request, PeerRequestOptions::no_options())
        .await
        .unwrap();
    wait_until("progress", || !client.progress().is_empty()).await;
    assert_eq!(h.engine.jobs().len(), 1);
    handle.cancel(Some("test".to_owned())).await.unwrap();
    wait_until("the job to end", || h.engine.jobs().is_empty()).await;
}

// ---------------------------------------------------------------------------------------------
// The sandbox

#[tokio::test]
async fn client_roots_narrow_writes() {
    let (_dir, root) = sandbox();
    let client = TestClient::new().with_roots(&[&root.join("a")]);
    let h = connect(rooted(&root), client.clone(), false).await;
    let write = |p: PathBuf| call("test_write", json!({ "path": p }));

    let r = h.client.call_tool(write(root.join("a/x"))).await.unwrap();
    output(&r);
    let r = h.client.call_tool(write(root.join("b/x"))).await.unwrap();
    let (code, message) = error(&r);
    assert_eq!(code, "OutsideSandbox");
    assert!(
        message.ends_with(&display_path(&root.join("a"))),
        "{message}"
    );

    // The client shares nothing now, and says so: --root alone applies.
    client.seen.roots.lock().unwrap().clear();
    h.client.notify_roots_list_changed().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = h.client.call_tool(write(root.join("b/x"))).await.unwrap();
        if r.is_error == Some(false) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the new roots never applied: {r:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read_to_string(root.join("b/x")).unwrap(), "ok");
}

#[tokio::test]
async fn modern_sessions_have_no_client_roots() {
    let (_dir, root) = sandbox();
    let client = TestClient::new().with_roots(&[&root.join("a")]);
    let h = connect(rooted(&root), client, true).await;
    let r = h
        .client
        .call_tool(call("test_write", json!({ "path": root.join("b/x") })))
        .await
        .unwrap();
    output(&r);
}

#[tokio::test]
async fn without_roots_writes_say_how_to_allow_them() {
    let (_dir, root) = sandbox();
    let h = connect(McpOptions::default(), TestClient::new(), false).await;
    let r = h
        .client
        .call_tool(call("test_write", json!({ "path": root.join("x") })))
        .await
        .unwrap();
    let (code, message) = error(&r);
    assert_eq!(code, "OutsideSandbox");
    assert!(message.contains("--root"), "{message}");
    let instructions = h.client.peer_info().unwrap().instructions.clone().unwrap();
    assert!(instructions.contains("without `--root`"), "{instructions}");

    // Unrestricted: anywhere.
    let anywhere = McpOptions {
        unrestricted: true,
        ..McpOptions::default()
    };
    let h = connect(anywhere, TestClient::new(), false).await;
    let r = h
        .client
        .call_tool(call("test_write", json!({ "path": root.join("x") })))
        .await
        .unwrap();
    output(&r);
}

#[tokio::test]
async fn read_only_offers_no_write_tools() {
    let (_dir, root) = sandbox();
    let options = McpOptions {
        roots: vec![root.clone()],
        read_only: true,
        ..McpOptions::default()
    };
    let h = connect(options, TestClient::new(), false).await;
    let names: Vec<String> = h
        .client
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name.into_owned())
        .collect();
    assert!(names.contains(&"archive_list".to_owned()), "{names:?}");
    for writer in [
        "archive_extract",
        "archive_create",
        "stream_compress",
        "test_write",
    ] {
        assert!(!names.contains(&writer.to_owned()), "{writer} in {names:?}");
    }
    let refused = h
        .client
        .call_tool(call("test_write", json!({ "path": root.join("x") })))
        .await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(!root.join("x").exists());
}

#[tokio::test]
async fn instructions_name_the_roots() {
    let (_dir, root) = sandbox();
    let h = connect(rooted(&root), TestClient::new(), false).await;
    let instructions = h.client.peer_info().unwrap().instructions.clone().unwrap();
    assert!(
        instructions.contains(&display_path(&root)),
        "{instructions}"
    );
    assert!(instructions.contains("500"), "{instructions}");
}

// ---------------------------------------------------------------------------------------------
// Paging

#[tokio::test]
async fn pages_and_reads_are_capped() {
    let (_dir, root) = sandbox();
    let src = root.join("a");
    for i in 0..600 {
        std::fs::write(src.join(format!("f{i:03}.txt")), "x").unwrap();
    }
    let big = vec![b'z'; 300 * 1024];
    std::fs::write(src.join("big.bin"), &big).unwrap();
    let h = connect(rooted(&root), TestClient::new(), false).await;
    let zip = root.join("b/many.zip");
    let r = h
        .client
        .call_tool(call(
            "archive_create",
            json!({ "output": zip, "inputs": [src] }),
        ))
        .await
        .unwrap();
    output(&r);

    let r = h
        .client
        .call_tool(call(
            "archive_list",
            json!({ "archive": zip, "flat": true, "limit": 1000 }),
        ))
        .await
        .unwrap();
    let page = output(&r);
    assert_eq!(
        page["entries"].as_array().unwrap().len() as u64,
        MAX_LIST_ENTRIES
    );
    assert_eq!(page["has_more"], true);
    assert!(page["total"].as_u64().unwrap() > 600, "{}", page["total"]);

    let r = h
        .client
        .call_tool(call(
            "entry_read",
            json!({ "archive": zip, "entry": "a/big.bin", "max_bytes": 1 << 20, "encoding": "base64" }),
        ))
        .await
        .unwrap();
    let read = output(&r);
    assert_eq!(read["bytes_read"], MAX_READ_BYTES);
    assert_eq!(read["eof"], false);
}
