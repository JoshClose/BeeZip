//! `beezip mcp` driven by the rmcp client over stdio, as an MCP host would run it
//! (docs/M2.md §6).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult, ProgressNotificationParam, ProtocolVersion},
    service::{ClientLifecycleMode, ClientServiceExt, NotificationContext, RunningService},
    transport::TokioChildProcess,
};
use serde_json::{Value, json};

fn server(args: &[&std::ffi::OsStr]) -> std::io::Result<TokioChildProcess> {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_beezip"));
    cmd.arg("mcp")
        .args(args)
        // The tests don't read the user's config.
        .env("BEEZIP_CONFIG", "no-such-beezip-config.toml");
    TokioChildProcess::new(cmd)
}

/// Records progress notifications.
#[derive(Clone, Default)]
struct Client {
    progress: Arc<Mutex<Vec<f64>>>,
}

impl ClientHandler for Client {
    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _cx: NotificationContext<RoleClient>,
    ) {
        self.progress.lock().unwrap().push(params.progress);
    }
}

async fn connect(args: &[&std::ffi::OsStr]) -> anyhow::Result<RunningService<RoleClient, Client>> {
    Ok(Client::default().serve(server(args)?).await?)
}

fn call(tool: &str, args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(tool.to_owned()).with_arguments(args.as_object().unwrap().clone())
}

fn error(result: &CallToolResult) -> (String, String) {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    let e = result.structured_content.as_ref().unwrap();
    (
        e["code"].as_str().unwrap().to_owned(),
        e["message"].as_str().unwrap().to_owned(),
    )
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// A path as BeeZip's messages print it: canonical, without `\\?\`.
fn shown(path: &Path) -> String {
    let s = std::fs::canonicalize(path).unwrap().display().to_string();
    s.strip_prefix(r"\\?\").map_or(s.clone(), str::to_owned)
}

#[tokio::test]
async fn tools_list_has_app_version() -> anyhow::Result<()> {
    let client = ().serve(server(&[])?).await?;

    let info = client.peer_info().expect("initialized");
    assert_eq!(
        info.server_info.as_ref().map(|s| s.name.as_str()),
        Some("beezip")
    );

    let tools = client.list_all_tools().await?;
    let tool = tools
        .iter()
        .find(|t| t.name == "app_version")
        .expect("app_version is listed");
    let annotations = tool.annotations.as_ref().expect("annotations");
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(tool.input_schema.get("type"), Some(&"object".into()));
    assert!(tool.output_schema.is_some());
    assert!(
        tool.description
            .as_deref()
            .is_some_and(|d| d.contains("version"))
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn call_app_version() -> anyhow::Result<()> {
    let client = ().serve(server(&[])?).await?;

    let result = client
        .call_tool(CallToolRequestParams::new("app_version"))
        .await?;
    assert_eq!(result.is_error, Some(false));
    let output = result.structured_content.expect("structured content");
    assert_eq!(output["version"], env!("CARGO_PKG_VERSION"));

    let result = client
        .call_tool(call("app_version", json!({ "bogus": 1 })))
        .await?;
    assert_eq!(error(&result).0, "InvalidArgs");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn extracts_inside_the_root_only() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let client = connect(&["--root".as_ref(), root.path().as_os_str()]).await?;
    let archive = fixture("thirdparty/7z-copy.zip");

    let dest = root.path().join("out");
    let result = client
        .call_tool(call(
            "archive_extract",
            json!({ "archive": archive, "dest": dest }),
        ))
        .await?;
    assert_eq!(result.is_error, Some(false), "{result:?}");
    assert!(dest.join("tree/hello.txt").is_file());
    let progress = client.service().progress.lock().unwrap().clone();
    assert!(!progress.is_empty(), "no progress notifications");

    let result = client
        .call_tool(call(
            "archive_extract",
            json!({ "archive": archive, "dest": outside.path().join("out") }),
        ))
        .await?;
    let (code, message) = error(&result);
    assert_eq!(code, "OutsideSandbox");
    assert!(message.contains(&shown(root.path())), "{message}");
    assert!(!outside.path().join("out").exists());

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn without_a_root_nothing_is_written() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let client = connect(&[]).await?;
    let result = client
        .call_tool(call(
            "archive_extract",
            json!({ "archive": fixture("thirdparty/7z-copy.zip"), "dest": dir.path() }),
        ))
        .await?;
    let (code, message) = error(&result);
    assert_eq!(code, "OutsideSandbox");
    assert!(message.contains("--root"), "{message}");
    assert!(std::fs::read_dir(dir.path())?.next().is_none());

    // Reading still works.
    let result = client
        .call_tool(call(
            "archive_list",
            json!({ "archive": fixture("thirdparty/7z-copy.zip") }),
        ))
        .await?;
    assert_eq!(result.is_error, Some(false), "{result:?}");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn read_only_lists_no_write_tools() -> anyhow::Result<()> {
    let client = connect(&["--read-only".as_ref()]).await?;
    let names: Vec<String> = client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.into_owned())
        .collect();
    assert!(names.contains(&"archive_list".to_owned()), "{names:?}");
    assert!(!names.contains(&"archive_extract".to_owned()), "{names:?}");
    assert!(!names.contains(&"stream_compress".to_owned()), "{names:?}");
    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn the_2026_07_28_lifecycle_works() -> anyhow::Result<()> {
    let client = ()
        .serve_with_lifecycle(
            server(&[])?,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let tools = client.list_all_tools().await?;
    assert!(tools.iter().any(|t| t.name == "archive_info"));
    let result = client
        .call_tool(call(
            "archive_info",
            json!({ "archive": fixture("thirdparty/7z-copy.zip") }),
        ))
        .await?;
    assert_eq!(result.is_error, Some(false), "{result:?}");
    client.cancel().await?;
    Ok(())
}

#[test]
fn a_missing_root_fails_at_startup() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_beezip"))
        .args(["mcp", "--root", "no-such-beezip-dir"])
        .env("BEEZIP_CONFIG", "no-such-beezip-config.toml")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no-such-beezip-dir"), "{stderr}");
}
