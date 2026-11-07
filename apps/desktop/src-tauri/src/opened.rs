//! Entries opened with their apps (docs/M5.md §8.3). Each file `entry.open` extracts and
//! launches for the main window is noted here with its size and time. When the main window gets
//! the focus back, the files are checked, and each one that changed reaches the page as an
//! `entry-changed` event, which asks whether to put it back in its archive.
//!
//! The page tells Rust to forget a closed tab's files with the `opened-forget` event. The files
//! themselves stay, since an editor may still have them; `entry.open` sweeps them after a day.

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
    time::SystemTime,
};

use beezip_commands::{EventSink, JobEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The event a changed file reaches the page as.
pub const ENTRY_CHANGED: &str = "entry-changed";

/// The event the page sends when a tab closes: `{ "paths": [...] }`, the files to forget.
pub const OPENED_FORGET: &str = "opened-forget";

/// A file that changed since it was opened, as the page gets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryChanged {
    /// The archive it came from, as `entry.open` was given it.
    pub archive: PathBuf,
    /// The entry, as `entry.open` was given it.
    pub entry: String,
    /// The extracted file.
    pub path: PathBuf,
}

/// What the page sends with [`OPENED_FORGET`].
#[derive(Debug, Deserialize)]
pub struct Forget {
    pub paths: Vec<PathBuf>,
}

/// What a file looked like when it was last seen.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    size: u64,
    modified: Option<SystemTime>,
}

impl Stamp {
    fn of(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            size: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

#[derive(Debug)]
struct Record {
    file: EntryChanged,
    stamp: Stamp,
}

/// The files opened from the main window's tabs.
#[derive(Debug, Default)]
pub struct Opened(Mutex<Vec<Record>>);

impl Opened {
    fn records(&self) -> MutexGuard<'_, Vec<Record>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes a file `entry.open` just extracted, as it is now. Opening the same file again
    /// starts over from what it is then.
    pub fn note(&self, archive: PathBuf, entry: String, path: PathBuf) {
        let Ok(stamp) = Stamp::of(&path) else {
            return;
        };
        let mut records = self.records();
        records.retain(|r| r.file.path != path);
        records.push(Record {
            file: EntryChanged {
                archive,
                entry,
                path,
            },
            stamp,
        });
    }

    /// Forgets these files: their tab closed.
    pub fn forget(&self, paths: &[PathBuf]) {
        self.records().retain(|r| !paths.contains(&r.file.path));
    }

    /// The files that changed since they were last seen, each reported once per change. Files
    /// that are gone are forgotten.
    pub fn changed(&self) -> Vec<EntryChanged> {
        let mut changed = Vec::new();
        self.records()
            .retain_mut(|r| match Stamp::of(&r.file.path) {
                Ok(now) => {
                    if now != r.stamp {
                        r.stamp = now;
                        changed.push(r.file.clone());
                    }
                    true
                }
                Err(e) => e.kind() != std::io::ErrorKind::NotFound,
            });
        changed
    }

    /// How many files are noted, for tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.records().len()
    }

    /// `sink`, noting the file when an `entry.open` job with these arguments finishes. Entries
    /// opened as tabs (`launch: false`) aren't noted: no app edits them.
    pub fn watch(self: &std::sync::Arc<Self>, args: &Value, sink: EventSink) -> EventSink {
        let launched = args.get("launch").and_then(Value::as_bool).unwrap_or(true);
        let (Some(archive), Some(entry)) = (
            args.get("archive").and_then(Value::as_str),
            args.get("entry").and_then(Value::as_str),
        ) else {
            return sink;
        };
        if !launched {
            return sink;
        }
        let (archive, entry) = (PathBuf::from(archive), entry.to_owned());
        let opened = std::sync::Arc::clone(self);
        std::sync::Arc::new(move |event: JobEvent| {
            if let JobEvent::Finished { output } = &event
                && let Some(path) = output.get("path").and_then(Value::as_str)
            {
                opened.note(archive.clone(), entry.clone(), PathBuf::from(path));
            }
            sink(event);
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use serde_json::json;

    use super::*;

    fn set_modified(path: &Path, t: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    #[test]
    fn a_changed_file_is_reported_once_per_change() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("readme.txt");
        std::fs::write(&file, "one").unwrap();
        let opened = Opened::default();
        opened.note("C:\\a.zip".into(), "docs/readme.txt".into(), file.clone());
        assert!(opened.changed().is_empty(), "unchanged");

        std::fs::write(&file, "one, two").unwrap();
        let want = EntryChanged {
            archive: "C:\\a.zip".into(),
            entry: "docs/readme.txt".into(),
            path: file.clone(),
        };
        assert_eq!(opened.changed(), std::slice::from_ref(&want));
        assert!(opened.changed().is_empty(), "already reported");

        // The same size, a new time: an editor saved it again.
        let later = SystemTime::now() + Duration::from_secs(60);
        set_modified(&file, later);
        assert_eq!(opened.changed(), [want]);
        assert!(opened.changed().is_empty());
    }

    #[test]
    fn gone_and_forgotten_files_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, "a").unwrap();
        std::fs::write(&b, "b").unwrap();
        let opened = Opened::default();
        opened.note("x.zip".into(), "a.txt".into(), a.clone());
        opened.note("x.zip".into(), "b.txt".into(), b.clone());
        // Opening it again replaces the record.
        opened.note("x.zip".into(), "a.txt".into(), a.clone());
        assert_eq!(opened.len(), 2);

        std::fs::remove_file(&a).unwrap();
        assert!(opened.changed().is_empty());
        assert_eq!(opened.len(), 1, "a is gone");

        opened.forget(std::slice::from_ref(&b));
        std::fs::write(&b, "changed").unwrap();
        assert!(opened.changed().is_empty());
        assert_eq!(opened.len(), 0);

        // A file that can't be read isn't noted.
        opened.note("x.zip".into(), "c.txt".into(), dir.path().join("c.txt"));
        assert_eq!(opened.len(), 0);
    }

    #[test]
    fn only_launched_entries_are_watched() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "a").unwrap();
        let opened = Arc::new(Opened::default());
        let seen = Arc::new(Mutex::new(0));
        let count = Arc::clone(&seen);
        let sink: EventSink = Arc::new(move |_| *count.lock().unwrap() += 1);
        let finished = JobEvent::Finished {
            output: json!({ "path": file, "launched": true }),
        };

        let args = json!({ "archive": "C:\\a.zip", "entry": "a.txt" });
        opened.watch(&args, Arc::clone(&sink))(finished.clone());
        assert_eq!(opened.len(), 1);
        assert_eq!(*seen.lock().unwrap(), 1, "the page still gets the event");

        // Opened as a tab, or failed: nothing to watch.
        opened.forget(std::slice::from_ref(&file));
        let tab = json!({ "archive": "C:\\a.zip", "entry": "a.txt", "launch": false });
        opened.watch(&tab, Arc::clone(&sink))(finished);
        opened.watch(&args, Arc::clone(&sink))(JobEvent::Cancelled);
        assert_eq!(opened.len(), 0);
        assert_eq!(*seen.lock().unwrap(), 3);
    }
}
