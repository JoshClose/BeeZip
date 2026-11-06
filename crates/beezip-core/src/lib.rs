//! BeeZip archive engine.
//!
//! Synchronous and front-end agnostic: format detection, codecs, readers and writers, and the
//! safe-extraction rules all live here. Core has no serde, schemars or ts-rs: `beezip-commands`
//! owns every wire type and converts (docs/M1.md §3.1).

pub mod codec;
pub mod ctx;
pub mod detect;
pub mod error;
pub mod format;
pub mod io;
pub mod limits;
pub mod names;
pub mod ops;
pub mod safefs;
pub mod sinks;
pub mod source;
pub mod time;
pub mod volume;

pub use codec::{Codec, CodecId, EncodeOpts, FinishWrite, Levels};
pub use ctx::{Ctx, Meter, MeteredCtx, OverwriteChoice, Progress, SimpleCtx};
pub use detect::{Confidence, Detection, Layer, LayerKind, Probe, detect_bytes, detect_path};
pub use error::{Error, ErrorKind, Result};
pub use format::{
    ArchiveInfo, ArchiveReader, ArchiveWriter, Encryption, Entry, EntryKind, EntrySink, FormatCaps,
    FormatId, NewEntry, NewKind, Selection,
};
pub use limits::Limits;
pub use names::{NameDecoding, NameEncoding, SystemPage};
pub use ops::{ArchiveKind, CreateOptions, CreateReport, WriteSpec};
pub use safefs::{ExtractReport, FsOptions, FsSink, OverwritePolicy, SkipReason};
pub use sinks::{NullSink, TestReport, TestSink};
pub use source::{OpenOptions, Opened, open};
