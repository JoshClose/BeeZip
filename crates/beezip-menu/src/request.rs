//! The job request (docs/M4.md §3.3): what a click on the menu writes to
//! `%TEMP%\BeeZip\jobs\<random>.json` before it starts `BeeZip.exe --job <file>`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::Item;

/// The request format this build writes and reads.
pub const REQUEST_VERSION: u32 = 1;

/// Plan what a click on BeeZip's Explorer menu does: the steps for the item clicked and the
/// selected paths, as the desktop app runs them when the menu starts it with `--job`. Archives
/// in one volume set become one step; a path that has gone fails only its own step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wire", derive(schemars::JsonSchema, ts_rs::TS, clap::Args))]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    /// The request format: 1.
    #[cfg_attr(
        feature = "wire",
        arg(long = "request-version", hide = true, default_value_t = REQUEST_VERSION)
    )]
    pub version: u32,
    /// The item clicked.
    #[cfg_attr(feature = "wire", arg(value_enum))]
    pub item: Item,
    /// The selected files and folders, absolute.
    #[cfg_attr(feature = "wire", arg(required = true))]
    pub paths: Vec<PathBuf>,
}

impl JobRequest {
    pub fn new(item: Item, paths: Vec<PathBuf>) -> Self {
        Self {
            version: REQUEST_VERSION,
            item,
            paths,
        }
    }

    /// The request as the job file holds it.
    ///
    /// # Errors
    /// If a path isn't valid Unicode, which JSON can't carry.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    /// Reads a job file's text. Another version, or anything but a request, is an error.
    ///
    /// # Errors
    /// The reason, for the person who clicked.
    pub fn parse(text: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("it isn't JSON: {e}"))?;
        match value.get("version").and_then(serde_json::Value::as_u64) {
            Some(v) if v == u64::from(REQUEST_VERSION) => {}
            Some(v) => {
                return Err(format!(
                    "it is version {v}, and this BeeZip reads version {REQUEST_VERSION}"
                ));
            }
            None => return Err("it has no version".into()),
        }
        serde_json::from_value(value).map_err(|e| format!("it isn't a job request: {e}"))
    }
}
