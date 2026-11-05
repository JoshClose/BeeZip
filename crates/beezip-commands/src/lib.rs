//! The BeeZip command registry and job engine.
//!
//! Every operation is a [`Command`] with one input type and one output type. The CLI, the MCP
//! server and the desktop app all look commands up in the same [`Registry`] and run them through
//! the same [`Engine`], so a new command needs no front-end code (PLAN §1).

pub mod cache;
mod command;
pub mod commands;
pub mod config;
mod engine;
mod error;
mod job;
pub mod policy;
mod registry;
pub mod wire;

use std::sync::OnceLock;

/// Partial files, process-wide: a front end that must exit at once calls
/// [`partial::abandon_all`] first (docs/M3.md §3.7).
pub use beezip_core::safefs::partial;
pub use command::{CLI_GROUPS, CliSpec, Command, Effect, Surfaces};
pub use config::{Config, LoadedConfig, McpConfig, Theme};
pub use engine::{Engine, EngineOptions, JobHandle, JobInfo};
pub use error::{CmdError, ErrorCode};
pub use job::{
    CancelToken, EventSink, Interactor, JobCtx, JobEvent, JobId, LogLevel, NonInteractive,
    OverwriteChoice, PASSWORD_PROMPTS, Progress, Prompt, PromptReply, discard_events,
};
pub use policy::{Access, Policy};
pub use registry::{CommandInfo, Entry, JsonObject, Registry, TsDecls, collect_ts};

/// The registry of every BeeZip command. An explicit list, built on first use.
pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = Registry::new();
        commands::register_all(&mut registry);
        registry
    })
}
