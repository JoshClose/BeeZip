use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ts_rs::TS;

use crate::{CmdError, JobCtx, policy::Access};

/// What a command may do to the outside world. It drives the MCP hints, the sandbox and the
/// UI's confirmation dialogs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum Effect {
    ReadOnly,
    Writes,
    Destructive,
    /// Changes system state outside any archive, such as Explorer registration.
    System,
}

/// The front ends that expose a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Surfaces {
    pub cli: bool,
    pub gui: bool,
    pub mcp: bool,
}

impl Surfaces {
    pub const ALL: Self = Self {
        cli: true,
        gui: true,
        mcp: true,
    };
    /// GUI and CLI only, as for `entry.open` and `shell.*`.
    pub const NO_MCP: Self = Self {
        cli: true,
        gui: true,
        mcp: false,
    };
}

/// The generated `beezip` subcommand for a command, e.g. `extract` with alias `x`, or `get`
/// in group `settings` for `beezip settings get`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CliSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    /// The subcommand it nests under, one of [`CLI_GROUPS`].
    pub group: Option<&'static str>,
}

impl CliSpec {
    /// The words after `beezip`: `["extract"]`, or `["settings", "get"]`.
    pub fn words(&self) -> Vec<&'static str> {
        self.group.into_iter().chain([self.name]).collect()
    }
}

/// The subcommands that group others, with their one-line help.
pub const CLI_GROUPS: &[(&str, &str)] = &[
    (
        "settings",
        "Show and change BeeZip's settings (config.toml)",
    ),
    ("shell", "BeeZip's Explorer menu: what a click on it does"),
];

/// A command: one input type and one output type, shared by every front end.
///
/// The doc comment on `Input` is the command's description everywhere: the clap help, the MCP
/// tool description and the TypeScript docs.
pub trait Command: Send + Sync + 'static {
    /// Dotted name, e.g. `"archive.extract"`.
    const NAME: &'static str;
    const EFFECT: Effect;
    const SURFACES: Surfaces = Surfaces::ALL;
    const CLI: Option<CliSpec> = None;

    type Input: Serialize + DeserializeOwned + JsonSchema + clap::Args + TS + 'static;
    type Output: Serialize + DeserializeOwned + JsonSchema + TS + 'static;

    fn run(input: Self::Input, cx: &mut JobCtx) -> Result<Self::Output, CmdError>;

    /// A short rendering for the CLI's `--output human`. `None` prints pretty JSON.
    fn human(_output: &Self::Output) -> Option<String> {
        None
    }

    /// The paths this input reads and writes. The engine checks them against the job's
    /// `Policy` before `run` (docs/M1.md §4.1).
    fn access(_input: &Self::Input) -> Vec<Access> {
        Vec::new()
    }
}
