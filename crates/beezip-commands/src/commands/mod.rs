//! The commands. Each one is registered in [`register_all`]; nothing else needs to change for
//! it to appear in the CLI, the MCP server and the desktop app.

mod app_version;
mod archive_create;
mod archive_extract;
mod archive_info;
mod archive_list;
mod archive_test;
mod entry_read;
mod file_detect;
mod formats_list;
mod stream_compress;
mod stream_decompress;
pub(crate) mod util;

pub use app_version::{AppVersion, AppVersionInput, AppVersionOutput};
pub use archive_create::{ArchiveCreate, ArchiveCreateInput, ArchiveCreateOutput};
pub use archive_extract::{
    ArchiveExtract, ArchiveExtractInput, ArchiveExtractOutput, PlannedEntry, RenamedInfo,
    SkippedInfo,
};
pub use archive_info::{ArchiveInfo, ArchiveInfoInput, ArchiveInfoOutput, EncryptionState};
pub use archive_list::{ArchiveList, ArchiveListInput, ArchiveListOutput};
pub use archive_test::{ArchiveTest, ArchiveTestInput, ArchiveTestOutput};
pub use entry_read::{EntryRead, EntryReadInput, EntryReadOutput};
pub use file_detect::{FileDetect, FileDetectInput, FileDetectOutput, LayerInfo};
pub use formats_list::{
    Caps, CodecInfo, FormatInfo, FormatsList, FormatsListInput, FormatsListOutput, LevelRange,
    MethodInfo,
};
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
        .register::<StreamCompress>()
        .register::<StreamDecompress>();
}
