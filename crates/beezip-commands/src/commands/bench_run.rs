use std::{path::PathBuf, str::FromStr, time::Instant};

use beezip_core::bench::{self, Bench, Cell, CellReport, Grid};
use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    Access, CliSpec, CmdError, Command, Effect, JobCtx,
    commands::util::absolute,
    wire::{ByteSize, CodecName, human_size, ratio},
};

/// Benchmark the codecs: compress and decompress a sample in memory with each codec at the
/// levels and thread counts of a grid, and report the size, the speed and the memory each way.
/// Every round trip is checked against the sample; one that doesn't match fails its cell, not
/// the run. Each cell is also sent as a `Partial` job event as it finishes, and a cancelled
/// run returns the cells it finished. Nothing is written.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, clap::Args, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct BenchRunInput {
    /// The file to take the sample from, read as 16 slices spread across it [default: BeeZip's
    /// built-in sample: seeded text, JSON, code, binary tables and 10 % random bytes].
    #[arg(value_name = "FILE")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<PathBuf>,
    /// The cells to run: `default` (gzip 1/6/9, bzip2 9, xz 1/6/9, zstd 1/3/9/19, lz4, brotli
    /// 5/9, snappy and lzop, one thread each), `full` (every codec at every level), `threads`
    /// (zstd 3 and 9, xz 1 and 6, at 1, 4 and all threads), or a list of cells. On the command
    /// line a list is `codec[:level[:threads]]`, comma-separated: `zstd:3,zstd:19:0,lz4`, where
    /// threads 0 is one per core [default: default].
    #[arg(short, long, value_name = "GRID")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grid: Option<BenchGrid>,
    /// The sample's size: bytes, or a size such as `64m`, at most 1 GiB [default: 8 MiB; 64
    /// MiB for `threads`].
    #[arg(long, value_name = "SIZE")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<ByteSize>,
}

/// A named grid, or a list of cells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(untagged)]
pub enum BenchGrid {
    Named(BenchGridName),
    Cells(Vec<BenchCellSpec>),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum BenchGridName {
    /// The levels people pick, one thread each: 16 cells, about 10 seconds.
    Default,
    /// Every codec at every level, and the threaded codecs on 4 and all threads: a few minutes.
    Full,
    /// zstd and xz on 1, 4 and all threads, on a 64 MiB sample: about a minute.
    Threads,
}

impl BenchGridName {
    fn grid(self) -> Grid {
        match self {
            Self::Default => Grid::Default,
            Self::Full => Grid::Full,
            Self::Threads => Grid::Threads,
        }
    }
}

/// One cell of a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(deny_unknown_fields)]
#[ts(optional_fields)]
pub struct BenchCellSpec {
    pub codec: CodecName,
    /// [default: the codec's own default level]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<i32>,
    /// For the codecs that have threads; 0 is one per core [default: 1].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<u32>,
}

impl FromStr for BenchGrid {
    type Err = String;

    /// `default`, `full`, `threads`, or `zstd:3,xz:6:0,lz4`.
    fn from_str(s: &str) -> Result<Self, String> {
        if let Ok(name) = <BenchGridName as ValueEnum>::from_str(s, false) {
            return Ok(Self::Named(name));
        }
        let bad = |why: String| {
            format!("{why}; a grid is default, full, threads, or cells such as zstd:3,xz:6:0,lz4")
        };
        let mut cells = Vec::new();
        for item in s.split(',').map(str::trim) {
            let mut parts = item.split(':');
            let codec = parts.next().unwrap_or_default();
            let codec = <CodecName as ValueEnum>::from_str(codec, true)
                .map_err(|_| bad(format!("`{codec}` isn't a codec")))?;
            let mut number = |what: &str| -> Result<Option<String>, String> {
                match parts.next() {
                    None | Some("") => Ok(None),
                    Some(p) if p.parse::<i64>().is_ok() => Ok(Some(p.to_owned())),
                    Some(p) => Err(bad(format!("`{p}` in `{item}` isn't a {what}"))),
                }
            };
            let level = number("level")?
                .map(|l| l.parse().map_err(|_| bad(format!("`{l}` isn't a level"))))
                .transpose()?;
            let threads = number("thread count")?
                .map(|t| {
                    t.parse()
                        .map_err(|_| bad(format!("`{t}` isn't a thread count")))
                })
                .transpose()?;
            if parts.next().is_some() {
                return Err(bad(format!("`{item}` has too many parts")));
            }
            cells.push(BenchCellSpec {
                codec,
                level,
                threads,
            });
        }
        Ok(Self::Cells(cells))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct BenchRunOutput {
    pub sample: BenchSample,
    /// Logical CPUs: what "all threads" is.
    pub cpus: u32,
    /// The cells that ran, in order.
    pub cells: Vec<BenchCell>,
    /// The whole run, the sample's reading included.
    pub total_ms: u64,
    /// The job was cancelled: `cells` holds the ones that finished.
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct BenchSample {
    /// The file, as given, or `built-in`.
    pub source: String,
    pub bytes: u64,
}

/// One codec at one level and thread count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct BenchCell {
    pub codec: CodecName,
    /// `null` for codecs without levels.
    pub level: Option<i32>,
    /// 1 for codecs without threads.
    pub threads: u32,
    pub packed_bytes: u64,
    /// `packed_bytes / sample bytes`, the share of the sample that remains: 0.25 is a quarter
    /// of its size. 0 if compressing failed.
    pub ratio: f64,
    /// Megabytes (10⁶ bytes) of the sample per second; 0 if that way failed.
    pub compress_mbps: f64,
    pub decompress_mbps: f64,
    /// Bytes: the growth of the process's private bytes while that way ran, sampled every
    /// millisecond, so C code's allocations count. Other jobs running at the same time count
    /// too. 0 where the platform gives no figure (macOS).
    pub compress_mem: u64,
    pub decompress_mem: u64,
    /// The whole cell, both ways.
    pub ms: u64,
    /// Why the cell failed: the codec's error, or a round trip that didn't match the sample.
    pub error: Option<String>,
}

impl BenchCell {
    fn from_report(r: &CellReport, sample_bytes: u64) -> Self {
        Self {
            codec: CodecName::from_id(r.cell.codec),
            level: r.cell.level,
            threads: r.cell.threads,
            packed_bytes: r.packed_bytes,
            ratio: if r.compress_time.is_some() {
                ratio(sample_bytes, r.packed_bytes)
            } else {
                0.0
            },
            compress_mbps: CellReport::mbps(sample_bytes, r.compress_time),
            decompress_mbps: CellReport::mbps(sample_bytes, r.decompress_time),
            compress_mem: r.compress_mem,
            decompress_mem: r.decompress_mem,
            ms: millis(r.elapsed),
            error: r.error.as_ref().map(|e| e.message.clone()),
        }
    }
}

fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

pub struct BenchRun;

impl Command for BenchRun {
    const NAME: &'static str = "bench.run";
    const EFFECT: Effect = Effect::ReadOnly;
    const CLI: Option<CliSpec> = Some(CliSpec {
        name: "bench",
        aliases: &[],
        group: None,
    });

    type Input = BenchRunInput;
    type Output = BenchRunOutput;

    fn access(input: &BenchRunInput) -> Vec<Access> {
        input.sample.iter().cloned().map(Access::Read).collect()
    }

    fn run(input: BenchRunInput, cx: &mut JobCtx) -> Result<BenchRunOutput, CmdError> {
        let started = Instant::now();
        let (cells, default_bytes) = match &input.grid {
            None => (Grid::Default.cells(), Grid::Default.sample_bytes()),
            Some(BenchGrid::Named(name)) => (name.grid().cells(), name.grid().sample_bytes()),
            Some(BenchGrid::Cells(list)) => {
                if list.is_empty() {
                    return Err(CmdError::invalid_args("the grid has no cells"));
                }
                let cells = list
                    .iter()
                    .map(|c| Cell::new(c.codec.id(), c.level, c.threads.unwrap_or(1)))
                    .collect::<Result<Vec<_>, _>>()?;
                (cells, bench::DEFAULT_BYTES)
            }
        };
        let bytes = input.bytes.as_ref().map_or(default_bytes, ByteSize::bytes);
        if bytes == 0 || bytes > bench::MAX_BYTES {
            return Err(CmdError::invalid_args(format!(
                "`bytes` is {}; it must be from 1 byte to {}",
                human_size(bytes),
                human_size(bench::MAX_BYTES)
            )));
        }
        let (sample, source) = match &input.sample {
            Some(path) => (
                bench::file_sample(&absolute(path), bytes)?,
                path.display().to_string(),
            ),
            None => (
                // At most MAX_BYTES, checked above.
                bench::builtin_sample(usize::try_from(bytes).unwrap_or(usize::MAX)),
                "built-in".to_owned(),
            ),
        };
        if sample.is_empty() {
            return Err(CmdError::invalid_args(format!("`{source}` is empty")));
        }
        let sample_bytes = sample.len() as u64;
        let limits = cx.policy().limits.clone();
        let mut bench = Bench::new(&sample, cells, limits);
        let mut done = Vec::new();
        while let Some(report) = bench.next_cell(cx) {
            let cell = BenchCell::from_report(&report, sample_bytes);
            // So the desktop's chart fills in as the run goes.
            if let Ok(v) = serde_json::to_value(&cell) {
                cx.partial(v);
            }
            done.push(cell);
        }
        Ok(BenchRunOutput {
            sample: BenchSample {
                source,
                bytes: sample_bytes,
            },
            cpus: bench.cpus(),
            cells: done,
            total_ms: millis(started.elapsed()),
            cancelled: bench.cancelled(),
        })
    }

    fn human(out: &BenchRunOutput) -> Option<String> {
        let mut s = format!(
            "Sample: {}, {}. {} logical CPUs.\n\n",
            out.sample.source,
            human_size(out.sample.bytes),
            out.cpus
        );
        s.push_str(&format!(
            "{:<8}  {:>5}  {:>7}  {:>6}  {:>13}  {:>15}  {:>12}  {:>14}  {:>7}\n",
            "codec",
            "level",
            "threads",
            "size",
            "compress MB/s",
            "decompress MB/s",
            "compress mem",
            "decompress mem",
            "ms"
        ));
        for c in &out.cells {
            let level = c.level.map_or_else(|| "-".to_owned(), |l| l.to_string());
            let threads = if c.threads > 1 && c.threads == out.cpus {
                "all".to_owned()
            } else {
                c.threads.to_string()
            };
            let codec = serde_json::to_value(c.codec)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            s.push_str(&format!("{codec:<8}  {level:>5}  {threads:>7}  "));
            match &c.error {
                Some(e) => s.push_str(&format!("failed: {e}\n")),
                None => s.push_str(&format!(
                    "{:>5.1}%  {:>13.1}  {:>15.1}  {:>12}  {:>14}  {:>7}\n",
                    c.ratio * 100.0,
                    c.compress_mbps,
                    c.decompress_mbps,
                    human_size(c.compress_mem),
                    human_size(c.decompress_mem),
                    c.ms
                )),
            }
        }
        let n = out.cells.len();
        let cells = if n == 1 { "cell" } else { "cells" };
        let secs = out.total_ms as f64 / 1000.0;
        s.push('\n');
        if out.cancelled {
            s.push_str(&format!("Cancelled after {n} {cells}, {secs:.1} s."));
        } else {
            s.push_str(&format!("{n} {cells} in {secs:.1} s."));
        }
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matches_json() {
        crate::commands::util::tests::cli_matches_json::<BenchRunInput>(&[], serde_json::json!({}));
        crate::commands::util::tests::cli_matches_json::<BenchRunInput>(
            &["big.iso", "--grid", "full", "--bytes", "64m"],
            serde_json::json!({ "sample": "big.iso", "grid": "full", "bytes": "64m" }),
        );
        crate::commands::util::tests::cli_matches_json::<BenchRunInput>(
            &["-g", "zstd:3,xz:6:0,lz4,gzip::4"],
            serde_json::json!({ "grid": [
                { "codec": "zstd", "level": 3 },
                { "codec": "xz", "level": 6, "threads": 0 },
                { "codec": "lz4" },
                { "codec": "gzip", "threads": 4 },
            ] }),
        );
    }

    #[test]
    fn grids_parse() {
        assert_eq!(
            "threads".parse::<BenchGrid>(),
            Ok(BenchGrid::Named(BenchGridName::Threads))
        );
        for bad in ["nope", "zstd:x", "zstd:3:y", "zstd:3:1:2", ""] {
            let err = bad.parse::<BenchGrid>().unwrap_err();
            assert!(err.contains("a grid is default"), "{bad}: {err}");
        }
        crate::wire::tests::names_agree::<BenchGridName>();
    }

    #[test]
    fn human_shows_failures_and_cancels() {
        let cell = BenchCell {
            codec: CodecName::Xz,
            level: Some(6),
            threads: 8,
            packed_bytes: 1 << 20,
            ratio: 0.125,
            compress_mbps: 3.25,
            decompress_mbps: 150.0,
            compress_mem: 90 << 20,
            decompress_mem: 9 << 20,
            ms: 2600,
            error: None,
        };
        let failed = BenchCell {
            codec: CodecName::Lz4,
            level: None,
            threads: 1,
            error: Some("the round trip doesn't match the sample from byte 7".to_owned()),
            ..cell.clone()
        };
        let out = BenchRunOutput {
            sample: BenchSample {
                source: "built-in".to_owned(),
                bytes: 8 << 20,
            },
            cpus: 8,
            cells: vec![cell, failed],
            total_ms: 2700,
            cancelled: true,
        };
        let text = BenchRun::human(&out).unwrap();
        assert!(
            text.starts_with("Sample: built-in, 8.0 MiB. 8 logical CPUs."),
            "{text}"
        );
        assert!(text.contains("xz            6      all   12.5%"), "{text}");
        assert!(text.contains("90.0 MiB"), "{text}");
        assert!(
            text.contains("lz4           -        1  failed: the round trip"),
            "{text}"
        );
        assert!(text.ends_with("Cancelled after 2 cells, 2.7 s."), "{text}");
    }
}
