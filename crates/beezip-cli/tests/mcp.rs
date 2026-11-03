//! `beezip mcp` driven by the rmcp client over stdio, as an MCP host would run it.

use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};

fn server() -> std::io::Result<TokioChildProcess> {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_beezip"));
    cmd.arg("mcp");
    TokioChildProcess::new(cmd)
}

#[tokio::test]
async fn tools_list_has_app_version() -> anyhow::Result<()> {
    let client = ().serve(server()?).await?;

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
    let client = ().serve(server()?).await?;

    let result = client
        .call_tool(CallToolRequestParams::new("app_version"))
        .await?;
    assert_eq!(result.is_error, Some(false));
    let output = result.structured_content.expect("structured content");
    assert_eq!(output["version"], env!("CARGO_PKG_VERSION"));

    let mut bogus = CallToolRequestParams::new("app_version");
    bogus.arguments = Some(
        serde_json::json!({ "bogus": 1 })
            .as_object()
            .cloned()
            .unwrap(),
    );
    let result = client.call_tool(bogus).await?;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(result.structured_content.unwrap()["code"], "InvalidArgs");

    client.cancel().await?;
    Ok(())
}
