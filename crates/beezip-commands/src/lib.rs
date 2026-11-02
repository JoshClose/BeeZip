//! The BeeZip command registry and job engine.
//!
//! Every operation is a [`Command`] with one input type and one output type. The CLI, the MCP
//! server and the desktop app all look commands up in the same [`Registry`] and run them through
//! the same [`Engine`], so a new command needs no front-end code (PLAN §1).

mod command;
pub mod commands;
mod engine;
mod error;
mod job;
mod registry;

use std::sync::OnceLock;

pub use command::{CliSpec, Command, Effect, Surfaces};
pub use engine::{Engine, JobHandle, JobInfo};
pub use error::{CmdError, ErrorCode};
pub use job::{
    CancelToken, EventSink, Interactor, JobCtx, JobEvent, JobId, LogLevel, NonInteractive,
    OverwriteChoice, Progress, Prompt, PromptReply, discard_events,
};
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
