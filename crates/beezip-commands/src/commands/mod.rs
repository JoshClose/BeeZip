//! The commands. Each one is registered in [`register_all`]; nothing else needs to change for
//! it to appear in the CLI, the MCP server and the desktop app.

mod app_version;

pub use app_version::{AppVersion, AppVersionInput, AppVersionOutput};

use crate::Registry;

pub(crate) fn register_all(registry: &mut Registry) {
    registry.register::<AppVersion>();
}
