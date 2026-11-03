//! How `beezip` prints results, errors and job events for each `--output` mode.

use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use beezip_commands::{CmdError, Entry, EventSink, JobEvent, LogLevel, Registry};
use serde_json::{Value, json};

use crate::progress::Bars;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// Text for people.
    #[default]
    Human,
    /// One JSON document on stdout: the output, or `{"error": {...}}`.
    Json,
    /// Every job event as a JSON line on stdout, ending with `Finished`, `Failed` or `Cancelled`.
    Ndjson,
}

pub struct Output {
    mode: Mode,
    /// `--quiet`: no progress bars or info lines; warnings still print.
    quiet: bool,
    /// Whether a terminal event has been printed in ndjson mode.
    ended: Arc<AtomicBool>,
    bars: Arc<Bars>,
}

/// Writes a line to stdout. A closed pipe (`beezip ... | head`) is not an error.
fn print(line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

fn to_json(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|e| json!({ "serialize_error": e.to_string() }).to_string())
}

fn to_pretty_json(value: &impl serde::Serialize) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("<could not serialise: {e}>"))
}

impl Output {
    /// Progress bars draw when `bars` is set: human mode, stderr a terminal, not quiet.
    pub fn new(mode: Mode, quiet: bool, bars: bool) -> Self {
        Self {
            mode,
            quiet,
            ended: Arc::new(AtomicBool::new(false)),
            bars: Arc::new(Bars::new(bars && mode == Mode::Human && !quiet)),
        }
    }

    pub fn bars(&self) -> Arc<Bars> {
        Arc::clone(&self.bars)
    }

    /// The job event sink for this mode. Called on the job's thread.
    pub fn event_sink(&self) -> EventSink {
        let mode = self.mode;
        let quiet = self.quiet;
        let ended = Arc::clone(&self.ended);
        let bars = Arc::clone(&self.bars);
        Arc::new(move |event| match (mode, &event) {
            (Mode::Ndjson, _) => {
                if matches!(
                    event,
                    JobEvent::Finished { .. } | JobEvent::Failed { .. } | JobEvent::Cancelled
                ) {
                    ended.store(true, Ordering::SeqCst);
                }
                print(&to_json(&event));
            }
            (_, JobEvent::Log { level, message }) => {
                let level = match level {
                    LogLevel::Info if quiet => return,
                    LogLevel::Info => "info",
                    LogLevel::Warn => "warning",
                };
                bars.suspend(|| eprintln!("{level}: {message}"));
            }
            (_, JobEvent::Progress(p)) => bars.update(p),
            (_, JobEvent::Finished { .. } | JobEvent::Failed { .. } | JobEvent::Cancelled) => {
                bars.finish();
            }
            _ => {}
        })
    }

    /// A warning from outside a job, such as the config's.
    pub fn warn(&self, message: &str) {
        eprintln!("warning: {message}");
    }

    /// Prints a successful command output.
    pub fn result(&self, entry: Option<&Entry>, output: &Value) {
        match self.mode {
            Mode::Human => print(
                &entry
                    .and_then(|e| e.human(output))
                    .unwrap_or_else(|| to_pretty_json(output)),
            ),
            Mode::Json => print(&to_json(output)),
            // Already printed as the `Finished` event.
            Mode::Ndjson => {}
        }
    }

    pub fn error(&self, err: &CmdError) {
        match self.mode {
            Mode::Human => eprintln!("error[{:?}]: {}", err.code, err.message),
            Mode::Json => print(&to_json(&json!({ "error": err }))),
            Mode::Ndjson => {
                // Failures before the job started (unknown command, bad --json) have no event yet.
                if !self.ended.load(Ordering::SeqCst) {
                    print(&to_json(&JobEvent::Failed { error: err.clone() }));
                }
            }
        }
    }

    pub fn commands(&self, registry: &Registry) {
        let infos: Vec<_> = registry.entries().iter().map(Entry::info).collect();
        match self.mode {
            Mode::Human => {
                let width = infos.iter().map(|i| i.name.len()).max().unwrap_or(0);
                for info in &infos {
                    let summary = info.description.lines().next().unwrap_or_default();
                    let effect = format!("{:?}", info.effect);
                    print(&format!("{:width$}  {effect:<11}  {summary}", info.name));
                }
            }
            Mode::Json => print(&to_json(&infos)),
            Mode::Ndjson => infos.iter().for_each(|i| print(&to_json(i))),
        }
    }

    pub fn schema(&self, entry: &Entry) {
        let schema = json!({
            "name": entry.name,
            "description": entry.description,
            "effect": entry.effect,
            "input": *entry.input_schema,
            "output": *entry.output_schema,
        });
        match self.mode {
            Mode::Human => print(&to_pretty_json(&schema)),
            Mode::Json | Mode::Ndjson => print(&to_json(&schema)),
        }
    }
}
