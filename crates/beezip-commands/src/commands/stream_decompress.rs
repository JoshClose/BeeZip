use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use beezip_core::{
    CodecId, LayerKind, Meter, MeteredCtx,
    codec::{strip_extension, xz_decoder_mt},
    detect_path,
    io::{BUF_SIZE, Counter, CountingReader, copy},
    limits::{Budget, Guarded, RatioGuard},
};
use filetime::FileTime;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, ErrorCode, JobCtx,
    commands::util::{absolute, check_output, write_atomically},
    wire::{CodecName, human_size},
};

/// Decompress a compressed file, one codec layer per call: `a.tar.zst` → `a.tar`, `a.tgz` →
/// `a.tar`, `notes.txt.gz` → `notes.txt`. The output keeps the input's modification time; the
/// input is left in place.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct StreamDecompressInput {
    /// The compressed file.
    pub input: PathBuf,
    /// Where to write [default: the input's name without the codec's extension, or
    /// `<name>.out`].
    #[arg(short = 'o', long = "out", value_name = "PATH")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
    /// Replace the output if it exists.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StreamDecompressOutput {
    pub input: PathBuf,
    pub output: PathBuf,
    /// The codec layer that was removed.
    pub codec: CodecName,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// The input's name without `codec`'s extension; `.tgz` and friends become `.tar`. A name
/// without the extension gets `.out`.
pub fn default_output(input: &Path, codec: CodecId) -> PathBuf {
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let out = strip_extension(&name, codec).unwrap_or_else(|| format!("{name}.out"));
    input.with_file_name(out)
}

pub struct StreamDecompress;

impl Command for StreamDecompress {
    const NAME: &'static str = "stream.decompress";
    const EFFECT: Effect = Effect::Writes;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "decompress",
        aliases: &[],
        group: None,
    });

    type Input = StreamDecompressInput;
    type Output = StreamDecompressOutput;

    fn access(input: &StreamDecompressInput) -> Vec<Access> {
        let mut a = vec![Access::Read(input.input.clone())];
        // Without `output`, the output sits next to the input.
        let out = input
            .output
            .clone()
            .unwrap_or_else(|| input.input.with_extension("out"));
        a.push(Access::Write(out));
        a
    }

    fn run(
        input: StreamDecompressInput,
        cx: &mut JobCtx,
    ) -> Result<StreamDecompressOutput, CmdError> {
        let limits = cx.policy().limits.clone();
        let src = absolute(&input.input);
        let det = detect_path(&src, &limits)?;
        let Some(LayerKind::Codec(codec)) = det.layers.first().map(|l| l.kind) else {
            let what = det
                .format()
                .map(|f| format!("a {} archive; use `archive.extract`", f.name()))
                .or_else(|| det.label.clone())
                .unwrap_or_else(|| "not compressed".into());
            return Err(CmdError::new(
                ErrorCode::UnsupportedFormat,
                format!(
                    "`{}` isn't a compressed file ({what})",
                    input.input.display()
                ),
            ));
        };
        // Reported as the user wrote it; written to the absolute path.
        let shown = input
            .output
            .clone()
            .unwrap_or_else(|| default_output(&input.input, codec));
        let output = absolute(&shown);
        if output == src {
            return Err(CmdError::invalid_args("the output is the input"));
        }
        check_output(&output, input.overwrite.unwrap_or(false))?;
        let meta = std::fs::metadata(&src).map_err(|e| {
            CmdError::from(beezip_core::Error::io(
                format!("reading {}", src.display()),
                &e,
            ))
        })?;

        // xz decodes on `[extract] threads`; a config that can't be read gives one per core.
        let threads = cx.config().ok().map_or(0, |c| c.extract.threads);
        let counter = Counter::new();
        let mut meter = Meter::new(counter.clone(), Some(meta.len()));
        meter.current = Some(input.input.display().to_string());
        let mut bytes_out = 0;
        write_atomically(&output, |file| {
            let open = || {
                File::open(&src).map_err(|e| {
                    CmdError::from(beezip_core::Error::io(
                        format!("reading {}", src.display()),
                        &e,
                    ))
                })
            };
            let mt = match codec {
                CodecId::Xz if threads != 1 => xz_decoder_mt(open()?, &limits, threads, &counter),
                _ => None,
            };
            let dec = match mt {
                Some(dec) => dec,
                None => {
                    let raw = Box::new(BufReader::with_capacity(
                        BUF_SIZE,
                        CountingReader::new(open()?, counter.clone()),
                    ));
                    codec.decoder(raw, &limits)?
                }
            };
            let mut data = Guarded::new(
                dec,
                RatioGuard::new(&counter, &limits),
                Budget::new(&limits),
            );
            let mut mcx = MeteredCtx::new(cx, &meter);
            bytes_out = copy(&mut data, file, &mut mcx)?;
            mcx.report();
            Ok(())
        })?;
        if let Ok(t) = meta.modified() {
            let _ = filetime::set_file_mtime(&output, FileTime::from_system_time(t));
        }
        Ok(StreamDecompressOutput {
            input: input.input,
            output: shown,
            codec: CodecName::from_id(codec),
            bytes_in: counter.get(),
            bytes_out,
        })
    }

    fn human(out: &StreamDecompressOutput) -> Option<String> {
        Some(format!(
            "{} -> {}: {} -> {}",
            out.input.display(),
            out.output.display(),
            human_size(out.bytes_in),
            human_size(out.bytes_out)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<StreamDecompressInput>(
            &["a.zst"],
            serde_json::json!({ "input": "a.zst" }),
        );
    }

    #[test]
    fn default_names() {
        let d = |p: &str, c| default_output(Path::new(p), c);
        assert_eq!(d("a.tar.zst", CodecId::Zstd), PathBuf::from("a.tar"));
        assert_eq!(d("a.tgz", CodecId::Gzip), PathBuf::from("a.tar"));
        assert_eq!(d("notes.txt.gz", CodecId::Gzip), PathBuf::from("notes.txt"));
        assert_eq!(d("mystery", CodecId::Xz), PathBuf::from("mystery.out"));
    }
}
