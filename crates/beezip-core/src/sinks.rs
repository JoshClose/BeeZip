//! The sinks that don't write files: [`TestSink`] for `archive.test` and [`NullSink`] for the
//! fuzzers. (`FsSink`, which does, is in `safefs`.)

use std::io::Read;

use crate::{
    Ctx, Error, ErrorKind, Result,
    format::{Entry, EntrySink},
    io::drain,
    safefs::REPORT_CAP,
};

/// An entry that failed its test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryError {
    pub path: String,
    pub kind: ErrorKind,
    pub message: String,
}

/// What `archive.test` found. `errors` is capped at [`REPORT_CAP`]; `errors_total` counts all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestReport {
    pub entries: u64,
    pub bytes: u64,
    pub errors: Vec<EntryError>,
    pub errors_total: u64,
}

impl TestReport {
    pub fn ok(&self) -> bool {
        self.errors_total == 0
    }

    pub fn record(&mut self, path: &str, err: &Error) {
        self.errors_total += 1;
        if self.errors.len() < REPORT_CAP {
            self.errors.push(EntryError {
                path: path.to_owned(),
                kind: err.kind,
                message: err.message.clone(),
            });
        }
    }
}

/// Errors that stop a whole job rather than failing one entry.
/// Passwords stop it too: 7z and RAR data has no password check, so a wrong password shows as
/// a failing entry, and the reader has to see it to ask again.
fn fatal(e: &Error) -> bool {
    matches!(
        e.kind,
        ErrorKind::Cancelled
            | ErrorKind::LimitExceeded
            | ErrorKind::Io
            | ErrorKind::PasswordRequired
            | ErrorKind::WrongPassword
    )
}

/// Reads every entry to the end, which checks its CRC or the codec's checksum, and records the
/// entries that fail instead of stopping at the first.
#[derive(Debug, Default)]
pub struct TestSink {
    pub report: TestReport,
}

impl EntrySink for TestSink {
    fn entry(&mut self, entry: &Entry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        match drain(data, cx) {
            Ok(n) => {
                self.report.entries += 1;
                self.report.bytes += n;
                Ok(())
            }
            Err(e) if fatal(&e) => Err(e),
            Err(e) => {
                self.report.entries += 1;
                self.report.record(&entry.path, &e);
                Ok(())
            }
        }
    }
}

/// Reads and discards, ignoring damaged entries. For the fuzzers.
#[derive(Debug, Default)]
pub struct NullSink {
    pub entries: u64,
    pub bytes: u64,
}

impl EntrySink for NullSink {
    fn entry(&mut self, _: &Entry, data: &mut dyn Read, cx: &mut dyn Ctx) -> Result<()> {
        self.entries += 1;
        match drain(data, cx) {
            Ok(n) => {
                self.bytes += n;
                Ok(())
            }
            Err(e) if fatal(&e) => Err(e),
            Err(_) => Ok(()),
        }
    }
}
