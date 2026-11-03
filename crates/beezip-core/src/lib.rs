//! BeeZip archive engine.
//!
//! Synchronous and front-end agnostic: format detection, codecs, readers and writers, and the
//! safe-extraction rules all live here. Core has no serde, schemars or ts-rs: `beezip-commands`
//! owns every wire type and converts (docs/M1.md §3.1).

pub mod ctx;
pub mod error;
pub mod io;
pub mod limits;
pub mod time;

pub use ctx::{Ctx, Meter, MeteredCtx, OverwriteChoice, Progress, SimpleCtx};
pub use error::{Error, ErrorKind, Result};
pub use limits::Limits;
