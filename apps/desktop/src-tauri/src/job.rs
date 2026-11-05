//! Job mode (docs/M4.md §6.2): `BeeZip.exe --job <file>`, started by a click on the Explorer
//! menu. The request file is read, checked and deleted, `shell.plan` turns it into steps, and
//! each step goes to the window that carries it out: a new job window for the `run` steps, the
//! main window for the rest.

use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use beezip_commands::{
    CmdError, Engine, NonInteractive,
    commands::{ShellPlanOutput, Step},
    discard_events,
};
use beezip_menu::JobRequest;
use serde::Serialize;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::open::{self, OpenDialog};

/// The largest request file BeeZip reads.
pub const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

/// Request files older than this are swept away at startup: BeeZip wasn't there to read them.
pub const MAX_REQUEST_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// The size of a job window, in logical pixels: enough for a prompt over the progress.
const JOB_WINDOW: (f64, f64) = (480.0, 260.0);
const JOB_WINDOW_MIN: (f64, f64) = (400.0, 220.0);

/// Where the menu writes requests: `%TEMP%\BeeZip\jobs`.
pub fn jobs_dir() -> PathBuf {
    std::env::temp_dir().join("BeeZip").join("jobs")
}

/// Reads the request in `file`, which must be a file of at most [`MAX_REQUEST_BYTES`] in `dir`,
/// and deletes it. A file anywhere else is refused and left alone.
pub fn read_request(file: &Path, dir: &Path) -> Result<JobRequest, CmdError> {
    let refused = |why: String| CmdError::invalid_args(format!("BeeZip can't run this job: {why}"));
    let canonical = std::fs::canonicalize(file).map_err(|e| {
        refused(format!(
            "its request `{}` can't be read: {e}",
            file.display()
        ))
    })?;
    let in_dir =
        std::fs::canonicalize(dir).is_ok_and(|dir| canonical.parent().is_some_and(|p| p == dir));
    if !in_dir {
        return Err(refused(format!(
            "`{}` isn't in {}, where Explorer's menu writes its requests",
            file.display(),
            dir.display()
        )));
    }
    let result = read_checked(&canonical).map_err(refused);
    // Once read, or found unusable, it has served its purpose.
    let _ = std::fs::remove_file(&canonical);
    result
}

fn read_checked(file: &Path) -> Result<JobRequest, String> {
    let meta = std::fs::metadata(file).map_err(|e| format!("its request can't be read: {e}"))?;
    if !meta.is_file() {
        return Err("its request isn't a file".into());
    }
    if meta.len() > MAX_REQUEST_BYTES {
        return Err(format!(
            "its request is {} bytes, more than the {MAX_REQUEST_BYTES} a request may be",
            meta.len()
        ));
    }
    let mut text = String::new();
    std::fs::File::open(file)
        .and_then(|f| f.take(MAX_REQUEST_BYTES + 1).read_to_string(&mut text))
        .map_err(|e| format!("its request can't be read: {e}"))?;
    JobRequest::parse(&text).map_err(|e| format!("its request can't be used: {e}"))
}

/// Deletes the request files in `dir` last changed before `now - max_age`. Returns how many.
pub fn sweep(dir: &Path, now: SystemTime, max_age: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter(|e| {
            e.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age > max_age))
        })
        .filter(|e| std::fs::remove_file(e.path()).is_ok())
        .count()
}

/// A request's steps, sorted by the window that takes them.
#[derive(Debug, Default, PartialEq)]
pub struct Routed {
    /// `run` and `failed` steps, in order, for one job window.
    pub job: Vec<Step>,
    /// Archives to open in the main window.
    pub open: Vec<PathBuf>,
    /// A dialog for the main window. Only one can show; a later one wins.
    pub dialog: Option<OpenDialog>,
}

pub fn route(steps: Vec<Step>) -> Routed {
    let mut routed = Routed::default();
    for step in steps {
        match step {
            Step::Run { .. } | Step::Failed { .. } => routed.job.push(step),
            Step::Open { paths } => routed.open.extend(paths),
            Step::ExtractDialog { archive } => {
                routed.dialog = Some(OpenDialog::Extract {
                    paths: vec![archive],
                });
            }
            Step::CreateDialog { inputs } => {
                routed.dialog = Some(OpenDialog::Create { paths: inputs });
            }
        }
    }
    routed
}

/// The steps for a request file: the plan, or one failed step saying why there is none.
pub fn plan(engine: &Engine, file: &Path) -> Vec<Step> {
    let failed = |error: CmdError| {
        vec![Step::Failed {
            title: "Explorer's menu request".into(),
            error,
        }]
    };
    let request = match read_request(file, &jobs_dir()) {
        Ok(r) => r,
        Err(e) => return failed(e),
    };
    let args = match serde_json::to_value(&request) {
        Ok(v) => v,
        Err(e) => return failed(CmdError::internal(e.to_string())),
    };
    let planned = engine
        .invoke(
            "shell.plan",
            args,
            Arc::new(NonInteractive),
            discard_events(),
        )
        .and_then(|job| job.join())
        .and_then(|out| {
            serde_json::from_value::<ShellPlanOutput>(out)
                .map_err(|e| CmdError::internal(format!("shell.plan's output: {e}")))
        });
    match planned {
        Ok(out) => out.steps,
        Err(e) => failed(e),
    }
}

/// What a job window's page finds in `window.__BEEZIP__.job`.
#[derive(Debug, Serialize)]
pub struct JobStartup {
    pub steps: Vec<Step>,
    /// `[jobs] close_when_done`: close after a clean success.
    pub close_when_done: bool,
}

static NEXT_JOB_WINDOW: AtomicU64 = AtomicU64::new(1);

/// Opens a job window, `job-<n>`, for these steps.
pub fn create_job_window(app: &AppHandle, steps: Vec<Step>) -> tauri::Result<()> {
    let n = NEXT_JOB_WINDOW.fetch_add(1, Ordering::Relaxed);
    let title = match steps.as_slice() {
        [Step::Run { title, .. } | Step::Failed { title, .. }] => title.clone(),
        _ => "BeeZip".to_owned(),
    };
    let close_when_done = app
        .state::<Engine>()
        .config()
        .as_ref()
        .as_ref()
        .map_or(true, |c| c.jobs.close_when_done);
    let script = open::startup_script(
        app,
        Vec::new(),
        None,
        Some(JobStartup {
            steps,
            close_when_done,
        }),
    );
    WebviewWindowBuilder::new(
        app,
        format!("job-{n}"),
        WebviewUrl::App("index.html".into()),
    )
    .title(title)
    .inner_size(JOB_WINDOW.0, JOB_WINDOW.1)
    .min_inner_size(JOB_WINDOW_MIN.0, JOB_WINDOW_MIN.1)
    .center()
    .focused(true)
    .initialization_script(script)
    .build()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use beezip_commands::ErrorCode;
    use beezip_menu::Item;

    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    const REQUEST: &str = r#"{"version":1,"item":"test","paths":["C:\\a.zip"]}"#;

    #[test]
    fn a_request_in_the_folder_is_read_once() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(dir.path(), "x.json", REQUEST);
        let req = read_request(&file, dir.path()).unwrap();
        assert_eq!(req.item, Item::Test);
        assert!(!file.exists(), "deleted once read");
        let err = read_request(&file, dir.path()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
    }

    #[test]
    fn a_request_elsewhere_is_refused_and_left_alone() {
        let jobs = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let file = write(other.path(), "x.json", REQUEST);
        let err = read_request(&file, jobs.path()).unwrap_err();
        assert!(err.message.contains("isn't in"), "{}", err.message);
        assert!(file.exists());
        // Nor in a folder under it.
        std::fs::create_dir(jobs.path().join("sub")).unwrap();
        let nested = write(&jobs.path().join("sub"), "x.json", REQUEST);
        assert!(read_request(&nested, jobs.path()).is_err());
        assert!(nested.exists());
    }

    #[test]
    fn big_or_foreign_requests_are_refused_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.json");
        std::fs::File::create(&big)
            .unwrap()
            .set_len(MAX_REQUEST_BYTES + 1)
            .unwrap();
        let err = read_request(&big, dir.path()).unwrap_err();
        assert!(err.message.contains("more than"), "{}", err.message);
        assert!(!big.exists());

        let v2 = write(
            dir.path(),
            "v2.json",
            r#"{"version":2,"item":"test","paths":[]}"#,
        );
        let err = read_request(&v2, dir.path()).unwrap_err();
        assert!(err.message.contains("version 2"), "{}", err.message);
        assert!(!v2.exists());

        let junk = write(dir.path(), "junk.json", "not json");
        assert!(read_request(&junk, dir.path()).is_err());
        assert!(!junk.exists());
    }

    #[test]
    fn old_requests_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let old = write(dir.path(), "old.json", REQUEST);
        let new = write(dir.path(), "new.json", REQUEST);
        let other = write(dir.path(), "notes.txt", "");
        let two_days = SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60);
        for f in [&old, &other] {
            std::fs::File::options()
                .write(true)
                .open(f)
                .unwrap()
                .set_modified(two_days)
                .unwrap();
        }
        assert_eq!(sweep(dir.path(), SystemTime::now(), MAX_REQUEST_AGE), 1);
        assert!(!old.exists() && new.exists() && other.exists());
        assert_eq!(
            sweep(&dir.path().join("none"), SystemTime::now(), MAX_REQUEST_AGE),
            0
        );
    }

    #[test]
    fn steps_go_to_their_windows() {
        let run = |title: &str| Step::Run {
            title: title.into(),
            command: "archive.test".into(),
            args: serde_json::json!({}),
            existing: None,
        };
        let failed = Step::Failed {
            title: "gone.zip".into(),
            error: CmdError::not_found("gone"),
        };
        let routed = route(vec![
            failed.clone(),
            Step::Open {
                paths: vec!["a.zip".into()],
            },
            run("one"),
            Step::ExtractDialog {
                archive: "b.zip".into(),
            },
            run("two"),
            Step::Open {
                paths: vec!["c.zip".into()],
            },
        ]);
        assert_eq!(routed.job, [failed, run("one"), run("two")]);
        assert_eq!(
            routed.open,
            [PathBuf::from("a.zip"), PathBuf::from("c.zip")]
        );
        assert_eq!(
            routed.dialog,
            Some(OpenDialog::Extract {
                paths: vec!["b.zip".into()]
            })
        );
        let routed = route(vec![Step::CreateDialog {
            inputs: vec!["x".into()],
        }]);
        assert!(routed.job.is_empty() && routed.open.is_empty());
        assert_eq!(
            routed.dialog,
            Some(OpenDialog::Create {
                paths: vec!["x".into()]
            })
        );
    }
}
