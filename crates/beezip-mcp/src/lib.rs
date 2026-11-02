//! The BeeZip MCP server.
//!
//! `ServerHandler` is implemented by hand rather than with rmcp's `#[tool]` macros: `list_tools`
//! and `call_tool` walk the command registry, so a new command needs no MCP-specific code
//! (PLAN §1, Front ends).
//!
//! M0 scope: every MCP-visible command is listed, but only read-only commands can be called.
//! Anything that writes is refused until the M2 sandbox policy exists.

use std::sync::Arc;

use beezip_commands::{
    CmdError, Effect, Engine, Entry, ErrorCode, NonInteractive, Registry, discard_events,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
    },
    service::RequestContext,
};
use serde_json::Value;

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

pub struct BeeZipServer {
    engine: Engine,
}

impl BeeZipServer {
    pub fn new(registry: &'static Registry) -> Self {
        Self {
            engine: Engine::new(registry),
        }
    }

    fn find(&self, tool: &str) -> Option<&'static Entry> {
        self.engine
            .registry()
            .entries()
            .iter()
            .find(|e| e.surfaces.mcp && tool_name(e.name) == tool)
    }
}

fn error_result(err: &CmdError) -> CallToolResult {
    CallToolResult::structured_error(serde_json::to_value(err).unwrap_or(Value::Null))
}

impl ServerHandler for BeeZipServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("beezip", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "BeeZip archive tools. Errors come back as structured content with a stable \
                 `code` (NotFound, InvalidArgs, ...) and a `message`.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(tools(
            self.engine.registry(),
        )))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        cx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let Some(entry) = self.find(&request.name) else {
            return Err(ErrorData::invalid_params(
                format!("unknown tool `{}`", request.name),
                None,
            ));
        };
        if entry.effect != Effect::ReadOnly {
            let err = CmdError::new(
                ErrorCode::UnsupportedOperation,
                format!(
                    "`{}` changes files, and BeeZip's MCP server is read-only until the sandbox \
                     policy lands",
                    entry.name
                ),
            );
            return Ok(error_result(&err).into());
        }

        let args = Value::Object(request.arguments.unwrap_or_default());
        let job =
            match self
                .engine
                .invoke(entry.name, args, Arc::new(NonInteractive), discard_events())
            {
                Ok(job) => job,
                Err(err) => return Ok(error_result(&err).into()),
            };
        let cancel = job.cancel_token();
        let joined = tokio::task::spawn_blocking(move || job.join());
        let result = tokio::select! {
            joined = joined => joined.unwrap_or_else(|e| Err(CmdError::internal(e.to_string()))),
            () = cx.ct.cancelled() => {
                cancel.cancel();
                Err(CmdError::cancelled())
            }
        };
        Ok(match result {
            Ok(output) => CallToolResult::structured(output),
            Err(err) => error_result(&err),
        }
        .into())
    }
}

/// Serves MCP over stdin/stdout until the client disconnects.
pub async fn serve_stdio(registry: &'static Registry) -> anyhow::Result<()> {
    let service = BeeZipServer::new(registry)
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}

/// [`serve_stdio`] on a current-thread tokio runtime. `beezip mcp` is the only CLI path that
/// starts tokio.
pub fn serve_stdio_blocking(registry: &'static Registry) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve_stdio(registry))
}
