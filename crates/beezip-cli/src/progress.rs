//! Progress bars on stderr, driven by the job's `Progress` events (docs/M1.md §5). Only in
//! human mode, when stderr is a terminal and `--quiet` isn't set.

use std::{sync::Mutex, time::Duration};

use beezip_commands::Progress;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

pub struct Bars {
    enabled: bool,
    bar: Mutex<Option<ProgressBar>>,
}

const BYTES: &str = "{spinner:.green} {bytes:>10}/{total_bytes:<10} {binary_bytes_per_sec:>12} ETA {eta:>4} [{bar:30.cyan/blue}] {wide_msg}";
const UNKNOWN: &str = "{spinner:.green} {bytes:>10} {binary_bytes_per_sec:>12} {wide_msg}";

impl Bars {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            bar: Mutex::new(None),
        }
    }

    fn bar(&self) -> std::sync::MutexGuard<'_, Option<ProgressBar>> {
        self.bar
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn update(&self, p: &Progress) {
        if !self.enabled {
            return;
        }
        let mut slot = self.bar();
        let bar = slot.get_or_insert_with(|| {
            let bar = ProgressBar::with_draw_target(p.bytes_total, ProgressDrawTarget::stderr());
            let template = if p.bytes_total.is_some() {
                BYTES
            } else {
                UNKNOWN
            };
            if let Ok(style) = ProgressStyle::with_template(template) {
                bar.set_style(style.progress_chars("=> "));
            }
            bar.enable_steady_tick(Duration::from_millis(120));
            bar
        });
        if let Some(total) = p.bytes_total {
            bar.set_length(total);
        }
        bar.set_position(p.bytes_done);
        let entries = match (p.entries_done, p.entries_total) {
            (done, Some(total)) if total > 1 => format!("{done}/{total} "),
            _ => String::new(),
        };
        bar.set_message(format!("{entries}{}", p.current.as_deref().unwrap_or("")));
    }

    /// Runs `f` with the bar hidden, for prompts and log lines.
    pub fn suspend<R>(&self, f: impl FnOnce() -> R) -> R {
        let bar = self.bar().clone();
        match bar {
            Some(bar) => bar.suspend(f),
            None => f(),
        }
    }

    pub fn finish(&self) {
        if let Some(bar) = self.bar().take() {
            bar.finish_and_clear();
        }
    }
}
