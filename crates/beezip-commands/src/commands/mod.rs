//! The commands. Each one is registered in [`register_all`]; nothing else needs to change for
//! it to appear in the CLI, the MCP server and the desktop app.

mod app_version;
mod archive_add;
mod archive_convert;
mod archive_create;
mod archive_extract;
mod archive_info;
mod archive_list;
mod archive_remove;
mod archive_rename;
mod archive_test;
mod bench_run;
mod cli_line;
pub(crate) mod edit;
mod entry_open;
mod entry_read;
mod file_detect;
mod formats_list;
pub(crate) mod listing;
mod settings_get;
mod settings_set;
mod shell_install;
mod shell_plan;
mod shell_status;
mod stream_compress;
mod stream_decompress;
pub(crate) mod util;

pub use app_version::{AppVersion, AppVersionInput, AppVersionOutput};
pub use archive_add::{ArchiveAdd, ArchiveAddInput};
pub use archive_convert::{
    ArchiveConvert, ArchiveConvertInput, ArchiveConvertOutput, ConvertSkipped,
};
pub use archive_create::{ArchiveCreate, ArchiveCreateInput, ArchiveCreateOutput};
pub use archive_extract::{
    ArchiveExtract, ArchiveExtractInput, ArchiveExtractOutput, PlannedEntry, RenamedInfo,
    SkippedInfo,
};
pub use archive_info::{ArchiveInfo, ArchiveInfoInput, ArchiveInfoOutput, EncryptionState};
pub use archive_list::{ArchiveList, ArchiveListInput, ArchiveListOutput};
pub use archive_remove::{ArchiveRemove, ArchiveRemoveInput};
pub use archive_rename::{ArchiveRename, ArchiveRenameInput};
pub use archive_test::{ArchiveTest, ArchiveTestInput, ArchiveTestOutput};
pub use bench_run::{
    BenchCell, BenchCellSpec, BenchGrid, BenchGridName, BenchRun, BenchRunInput, BenchRunOutput,
    BenchSample,
};
pub use cli_line::{CliLine, CliLineInput, CliLineOutput, ShellName};
pub use edit::{Change, ChangeAction, EditOutput};
pub use entry_open::{EntryOpen, EntryOpenInput, EntryOpenOutput, open_root};
pub use entry_read::{EntryRead, EntryReadInput, EntryReadOutput};
pub use file_detect::{FileDetect, FileDetectInput, FileDetectOutput, LayerInfo};
pub use formats_list::{
    Caps, CodecInfo, FormatInfo, FormatsList, FormatsListInput, FormatsListOutput, LevelRange,
    MethodInfo,
};
pub use settings_get::{SettingsGet, SettingsGetInput, SettingsGetOutput};
pub use settings_set::{SettingsSet, SettingsSetInput, SettingsSetOutput};
pub use shell_install::{
    InstallMode, ShellInstall, ShellInstallInput, ShellInstallOutput, ShellUninstall,
    ShellUninstallInput, ShellUninstallOutput,
};
pub use shell_plan::{Existing, ShellPlan, ShellPlanOutput, Step};
pub use shell_status::{ClassicKeys, ShellMode, ShellStatus, ShellStatusInput, ShellStatusOutput};
pub use stream_compress::{StreamCompress, StreamCompressInput, StreamCompressOutput};
pub use stream_decompress::{StreamDecompress, StreamDecompressInput, StreamDecompressOutput};

use crate::Registry;

/// Registers every BeeZip command. [`crate::registry`] is built with it; tests that need the
/// real commands next to their own use it too.
pub fn register_all(registry: &mut Registry) {
    registry
        .register::<AppVersion>()
        .register::<FormatsList>()
        .register::<FileDetect>()
        .register::<ArchiveInfo>()
        .register::<ArchiveList>()
        .register::<EntryRead>()
        .register::<ArchiveTest>()
        .register::<ArchiveExtract>()
        .register::<ArchiveCreate>()
        .register::<ArchiveAdd>()
        .register::<ArchiveRemove>()
        .register::<ArchiveRename>()
        .register::<ArchiveConvert>()
        .register::<EntryOpen>()
        .register::<StreamCompress>()
        .register::<StreamDecompress>()
        .register::<BenchRun>()
        .register::<CliLine>()
        .register::<SettingsGet>()
        .register::<SettingsSet>()
        .register::<ShellPlan>()
        .register::<ShellStatus>()
        .register::<ShellInstall>()
        .register::<ShellUninstall>();
}
