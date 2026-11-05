use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};

use beezip_core::{
    CodecId, EncodeOpts, Meter, MeteredCtx,
    io::{BUF_SIZE, Counter, CountingReader, copy},
};
use filetime::FileTime;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::util::{absolute, check_output, level, write_atomically},
    wire::{CodecName, human_size, ratio},
};

/// Compress one file with a single-stream codec (`a.txt` → `a.txt.zst`). The output keeps the
/// input's modification time; the input is left in place.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct StreamCompressInput {
    /// The file to compress.
    pub input: PathBuf,
    /// Where to write [default: the input's name plus the codec's extension].
    #[arg(short = 'o', long = "out", value_name = "PATH")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
    /// The codec [default: from config, zstd].
    #[arg(short, long, value_enum)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<CodecName>,
    /// The compression level; `formats.list` shows each codec's range.
    #[arg(short, long, allow_negative_numbers = true)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<i32>,
    /// Compression threads for codecs that have them; 0 is one per core [default: from config].
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<u32>,
    /// Replace the output if it exists.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StreamCompressOutput {
    pub input: PathBuf,
    pub output: PathBuf,
    pub codec: CodecName,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// `bytes_out / bytes_in`.
    pub ratio: f64,
}

/// `<input><ext>`, with the codec's first extension (`.zst`, `.gz`…; `.deflate` for raw deflate).
pub fn default_output(input: &Path, codec: CodecId) -> PathBuf {
    let ext = codec
        .codec()
        .extensions()
        .first()
        .copied()
        .unwrap_or(".deflate");
    let mut s = input.as_os_str().to_owned();
    s.push(ext);
    s.into()
}

pub struct StreamCompress;

impl Command for StreamCompress {
    const NAME: &'static str = "stream.compress";
    const EFFECT: Effect = Effect::Writes;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "compress",
        aliases: &[],
        group: None,
    });

    type Input = StreamCompressInput;
    type Output = StreamCompressOutput;

    fn access(input: &StreamCompressInput) -> Vec<Access> {
        let codec = input.codec.unwrap_or(CodecName::Zstd).id();
        let output = input
            .output
            .clone()
            .unwrap_or_else(|| default_output(&input.input, codec));
        vec![Access::Read(input.input.clone()), Access::Write(output)]
    }

    fn run(input: StreamCompressInput, cx: &mut JobCtx) -> Result<StreamCompressOutput, CmdError> {
        let config = cx.config()?.clone();
        let codec_name = input.codec.unwrap_or(config.stream.codec);
        let codec = codec_name.id();
        let src = absolute(&input.input);
        let meta = std::fs::metadata(&src).map_err(|e| {
            CmdError::from(beezip_core::Error::io(
                format!("reading {}", src.display()),
                &e,
            ))
        })?;
        if !meta.is_file() {
            return Err(CmdError::invalid_args(format!(
                "`{}` isn't a file; use `archive.create` for folders",
                input.input.display()
            )));
        }
        // Reported as the user wrote it; written to the absolute path.
        let shown = input
            .output
            .clone()
            .unwrap_or_else(|| default_output(&input.input, codec));
        let output = absolute(&shown);
        if output == src {
            return Err(CmdError::invalid_args("the output is the input"));
        }
        let opts = EncodeOpts {
            level: level(input.level, codec.name(), cx)?,
            threads: input.threads.unwrap_or(config.create.threads),
            size_hint: Some(meta.len()),
            size_exact: true,
            gzip_name: src.file_name().map(|n| n.to_string_lossy().into_owned()),
            gzip_mtime: meta.modified().ok(),
            ..EncodeOpts::default()
        };
        // Argument errors before the file system's.
        opts.resolve_level(codec, codec.codec().levels())?;
        check_output(&output, input.overwrite.unwrap_or(false))?;

        let counter = Counter::new();
        let mut meter = Meter::new(counter.clone(), Some(meta.len()));
        meter.current = Some(input.input.display().to_string());
        write_atomically(&output, |file| {
            let source = File::open(&src).map_err(|e| {
                CmdError::from(beezip_core::Error::io(
                    format!("reading {}", src.display()),
                    &e,
                ))
            })?;
            let mut reader =
                BufReader::with_capacity(BUF_SIZE, CountingReader::new(source, counter.clone()));
            let out = Box::new(BufWriter::with_capacity(BUF_SIZE, file));
            let mut enc = codec.codec().encoder(out, &opts)?;
            let mut mcx = MeteredCtx::new(cx, &meter);
            copy(&mut reader, &mut enc, &mut mcx)?;
            enc.finish()
                .map_err(|e| CmdError::from(beezip_core::io::write_error(&e)))?;
            mcx.report();
            Ok(())
        })?;
        if let Ok(t) = meta.modified() {
            let _ = filetime::set_file_mtime(&output, FileTime::from_system_time(t));
        }
        let bytes_out = std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0);
        Ok(StreamCompressOutput {
            input: input.input,
            output: shown,
            codec: codec_name,
            bytes_in: counter.get(),
            bytes_out,
            ratio: ratio(counter.get(), bytes_out),
        })
    }

    fn human(out: &StreamCompressOutput) -> Option<String> {
        Some(format!(
            "{} -> {}: {} -> {} ({:.0}%)",
            out.input.display(),
            out.output.display(),
            human_size(out.bytes_in),
            human_size(out.bytes_out),
            out.ratio * 100.0
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<StreamCompressInput>(
            &["a.txt"],
            serde_json::json!({ "input": "a.txt" }),
        );
        crate::commands::util::tests::cli_matches_json::<StreamCompressInput>(
            &["a.txt", "-c", "gzip", "-l", "9", "--overwrite"],
            serde_json::json!({ "input": "a.txt", "codec": "gzip", "level": 9, "overwrite": true }),
        );
    }

    #[test]
    fn default_names() {
        assert_eq!(
            default_output(Path::new("a.txt"), CodecId::Zstd),
            PathBuf::from("a.txt.zst")
        );
        assert_eq!(
            default_output(Path::new("a"), CodecId::Deflate),
            PathBuf::from("a.deflate")
        );
    }
}
