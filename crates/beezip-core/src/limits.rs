//! Bomb limits (docs/M1.md §3.5). Declared sizes are never trusted: every check counts bytes
//! that were actually produced.

use std::io::{self, Read};

use crate::{Error, Result, io::Counter};

/// Limits for one job. The defaults are the CLI's and GUI's; MCP gets stricter ones in M2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum output:input ratio per entry, checked once the entry has produced
    /// [`Limits::ratio_grace`] bytes. `None` turns the check off.
    pub max_ratio: Option<u64>,
    pub ratio_grace: u64,
    /// Maximum bytes produced by the whole job.
    pub max_total_bytes: Option<u64>,
    pub max_entries: Option<u64>,
    /// Codec layers detection unwraps. Deeper layers are treated as data.
    pub max_layers: usize,
    /// Memory a decoder may allocate, in bytes (xz/lzma/lzip dictionaries, zstd windows).
    pub decoder_memory: u64,
}

pub const MIB: u64 = 1024 * 1024;

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_ratio: Some(10_000),
            ratio_grace: 64 * MIB,
            max_total_bytes: None,
            max_entries: Some(10_000_000),
            max_layers: 4,
            decoder_memory: 1024 * MIB,
        }
    }
}

impl Limits {
    /// No limits at all except the decoder memory, for trusted input in tests.
    pub fn unlimited() -> Self {
        Self {
            max_ratio: None,
            max_total_bytes: None,
            max_entries: None,
            ..Self::default()
        }
    }

    /// `decoder_memory` in KiB, as lzma-rust2 takes it.
    pub fn decoder_memory_kib(&self) -> u32 {
        u32::try_from(self.decoder_memory / 1024).unwrap_or(u32::MAX)
    }

    /// The largest zstd window (log2) that fits in `decoder_memory`: at most 30 (1 GiB), at
    /// least 10, which is zstd's minimum.
    pub fn zstd_window_log_max(&self) -> u32 {
        let fits = 63 - self.decoder_memory.max(1).leading_zeros();
        fits.clamp(10, 31)
    }

    pub fn check_entries(&self, count: u64) -> Result<()> {
        match self.max_entries {
            Some(max) if count > max => Err(Error::limit(format!(
                "the archive has more than {max} entries (limit `max_entries`)"
            ))),
            _ => Ok(()),
        }
    }
}

/// Counts what a job produces against `max_total_bytes`. Clones share the count.
#[derive(Debug, Clone, Default)]
pub struct Budget {
    produced: Counter,
    max_total: Option<u64>,
}

impl Budget {
    pub fn new(limits: &Limits) -> Self {
        Self {
            produced: Counter::new(),
            max_total: limits.max_total_bytes,
        }
    }

    pub fn produced(&self) -> u64 {
        self.produced.get()
    }

    fn add(&self, n: u64) -> Result<()> {
        self.produced.add(n);
        match self.max_total {
            Some(max) if self.produced.get() > max => Err(Error::limit(format!(
                "the job produced more than {max} bytes (limit `max_total_bytes`)"
            ))),
            _ => Ok(()),
        }
    }
}

/// The ratio check for one entry: output so far against the compressed input consumed since
/// the entry started, measured by the counter on the archive file.
#[derive(Debug, Clone)]
pub struct RatioGuard {
    input: Counter,
    input_start: u64,
    output: u64,
    max_ratio: Option<u64>,
    grace: u64,
}

impl RatioGuard {
    pub fn new(input: &Counter, limits: &Limits) -> Self {
        Self {
            input: input.clone(),
            input_start: input.get(),
            output: 0,
            max_ratio: limits.max_ratio,
            grace: limits.ratio_grace,
        }
    }

    pub fn add(&mut self, n: u64) -> Result<()> {
        self.output += n;
        let Some(max) = self.max_ratio else {
            return Ok(());
        };
        if self.output <= self.grace {
            return Ok(());
        }
        let consumed = self.input.get().saturating_sub(self.input_start).max(1);
        if self.output / consumed > max {
            return Err(Error::limit(format!(
                "an entry expands more than {max}:1 ({} bytes from {consumed}; limit `max_ratio`)",
                self.output
            )));
        }
        Ok(())
    }
}

/// An entry's data with the ratio and total-size checks applied to every read. A failed check
/// surfaces as an `io::Error` carrying the `LimitExceeded` error, which the copy loop recovers.
pub struct Guarded<R> {
    inner: R,
    ratio: RatioGuard,
    budget: Budget,
}

impl<R: Read> Guarded<R> {
    pub fn new(inner: R, ratio: RatioGuard, budget: Budget) -> Self {
        Self {
            inner,
            ratio,
            budget,
        }
    }
}

impl<R: Read> Read for Guarded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.ratio.add(n as u64).map_err(Error::into_io)?;
        self.budget.add(n as u64).map_err(Error::into_io)?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn ratio_guard_trips_after_the_grace() {
        let input = Counter::new();
        let limits = Limits {
            max_ratio: Some(10),
            ratio_grace: 100,
            ..Limits::default()
        };
        let mut g = RatioGuard::new(&input, &limits);
        input.add(5);
        g.add(100).unwrap(); // 20:1, but still within the grace
        assert!(g.add(1).is_err()); // past the grace: 101 / 5 > 10

        let mut ok = RatioGuard::new(&input, &limits);
        input.add(50);
        ok.add(400).unwrap(); // 8:1
    }

    #[test]
    fn guarded_reader_reports_limit_exceeded() {
        let input = Counter::new();
        input.add(1);
        let limits = Limits {
            max_ratio: Some(2),
            ratio_grace: 0,
            ..Limits::default()
        };
        let data = [0u8; 100];
        let mut r = Guarded::new(
            &data[..],
            RatioGuard::new(&input, &limits),
            Budget::new(&limits),
        );
        let err = r.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(Error::from(err).kind, ErrorKind::LimitExceeded);
    }

    #[test]
    fn budget_caps_total_output() {
        let limits = Limits {
            max_total_bytes: Some(10),
            ..Limits::default()
        };
        let b = Budget::new(&limits);
        b.add(10).unwrap();
        assert!(b.add(1).is_err());
    }

    #[test]
    fn zstd_window_fits_memory() {
        assert_eq!(Limits::default().zstd_window_log_max(), 30);
        let small = Limits {
            decoder_memory: 8 * MIB,
            ..Limits::default()
        };
        assert_eq!(small.zstd_window_log_max(), 23);
    }
}
