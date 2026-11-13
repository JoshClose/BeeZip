//! Timestamps: DOS (local, 2 s), NTFS (UTC, 100 ns) and Unix (UTC, 1 s) <-> `SystemTime`
//! (docs/M1.md §3.6).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// Seconds from 1601-01-01 (the NTFS epoch) to 1970-01-01.
const NTFS_TO_UNIX_SECS: u64 = 11_644_473_600;

/// `secs` (and `nanos`) since the Unix epoch. Times before 1970 are allowed.
pub fn from_unix(secs: i64, nanos: u32) -> Option<SystemTime> {
    let nanos = Duration::from_nanos(u64::from(nanos.min(999_999_999)));
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs.unsigned_abs()) + nanos)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))?
            .checked_add(nanos)
    }
}

/// `2024-05-06 07:08:09.1234567Z`, UTC, as 7-Zip's `-slt` listing writes times and the fixture
/// records keep them (with a space for RFC 3339's `T`): no fraction or up to nine digits of one,
/// and an optional `Z`. For the tests that compare times with those records.
#[doc(hidden)]
pub fn parse_utc(s: &str) -> Option<SystemTime> {
    let b = s.trim().as_bytes();
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b' '
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |at: usize, len: usize| -> Option<i64> {
        let d = b.get(at..at + len)?;
        d.iter()
            .all(u8::is_ascii_digit)
            .then(|| d.iter().fold(0i64, |n, &c| n * 10 + i64::from(c - b'0')))
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, se) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &b[19..];
    let mut nanos = 0u32;
    if let Some(frac) = rest.strip_prefix(b".") {
        let digits = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        for (i, &c) in frac[..digits].iter().take(9).enumerate() {
            nanos += u32::from(c - b'0') * 10u32.pow(8 - i as u32);
        }
        rest = &frac[digits..];
    }
    if !(rest.is_empty() || rest == b"Z") {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let (yy, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    from_unix(days * 86_400 + h * 3600 + mi * 60 + se, nanos)
}

/// Whole seconds since the Unix epoch, rounded down.
pub fn to_unix(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            if d.subsec_nanos() > 0 {
                -secs - 1
            } else {
                -secs
            }
        }
    }
}

/// An NTFS `FILETIME`: 100 ns ticks since 1601-01-01 UTC.
pub fn from_ntfs(ticks: u64) -> Option<SystemTime> {
    let secs = ticks / 10_000_000;
    let nanos = u32::try_from((ticks % 10_000_000) * 100).ok()?;
    let unix = i64::try_from(secs).ok()? - i64::try_from(NTFS_TO_UNIX_SECS).ok()?;
    from_unix(unix, nanos)
}

pub fn to_ntfs(t: SystemTime) -> u64 {
    let base = UNIX_EPOCH - Duration::from_secs(NTFS_TO_UNIX_SECS);
    t.duration_since(base)
        .map(|d| u64::try_from(d.as_nanos() / 100).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// An MS-DOS date and time as stored in zip headers: local time, 2-second steps, 1980–2107.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DosTime {
    pub date: u16,
    pub time: u16,
}

/// The UTC offset in force at `t` on this machine. Falls back to UTC where the platform can't
/// say safely, as on multi-threaded Unix processes.
fn local_offset_at(t: OffsetDateTime) -> UtcOffset {
    UtcOffset::local_offset_at(t).unwrap_or(UtcOffset::UTC)
}

/// The UTC offset in force at a local time. The offset at the local time read as UTC is only a
/// guess, wrong for the hours after a change (in Chicago, 03:30 on the morning summer time ends
/// would read as 02:30 CST): the offset at the guessed instant is the one that applies, and a
/// second look settles it. A local time that happens twice (the hour repeated when summer time
/// ends) reads as one of the two.
fn offset_of_local(local: PrimitiveDateTime) -> UtcOffset {
    let guess = local_offset_at(local.assume_utc());
    local_offset_at(local.assume_offset(guess))
}

/// A DOS time, read as local time at that date.
pub fn from_dos(dos: DosTime) -> Option<SystemTime> {
    let year = 1980 + i32::from(dos.date >> 9);
    let month = Month::try_from(u8::try_from((dos.date >> 5) & 0x0F).ok()?).ok()?;
    let day = u8::try_from(dos.date & 0x1F).ok()?;
    let hour = u8::try_from(dos.time >> 11).ok()?;
    let minute = u8::try_from((dos.time >> 5) & 0x3F).ok()?;
    let second = u8::try_from((dos.time & 0x1F) * 2).ok()?;
    let local = PrimitiveDateTime::new(
        Date::from_calendar_date(year, month, day).ok()?,
        Time::from_hms(hour, minute, second.min(59)).ok()?,
    );
    Some(local.assume_offset(offset_of_local(local)).into())
}

/// Reads DOS times like [`from_dos`], remembering the UTC offset of recent dates and hours:
/// looking the offset up is most of the cost, and a zip's entries often share a few dates (a
/// million entries took 0.3 s without it, docs/M5.md §4). The offset is taken at the start of
/// the hour, so only a zone that changes its offset in the middle of an hour reads differently.
pub struct DosClock {
    slots: [Option<(u32, UtcOffset)>; 64],
}

impl Default for DosClock {
    fn default() -> Self {
        Self { slots: [None; 64] }
    }
}

impl DosClock {
    pub fn read(&mut self, dos: DosTime) -> Option<SystemTime> {
        let year = 1980 + i32::from(dos.date >> 9);
        let month = Month::try_from(u8::try_from((dos.date >> 5) & 0x0F).ok()?).ok()?;
        let day = u8::try_from(dos.date & 0x1F).ok()?;
        let hour = u8::try_from(dos.time >> 11).ok()?;
        let minute = u8::try_from((dos.time >> 5) & 0x3F).ok()?;
        let second = u8::try_from((dos.time & 0x1F) * 2).ok()?;
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let local =
            PrimitiveDateTime::new(date, Time::from_hms(hour, minute, second.min(59)).ok()?);
        let key = (u32::from(dos.date) << 5) | u32::from(hour);
        let slot = &mut self.slots[(key ^ (key >> 6)) as usize % 64];
        let offset = match *slot {
            Some((k, offset)) if k == key => offset,
            _ => {
                let start = PrimitiveDateTime::new(date, Time::from_hms(hour, 0, 0).ok()?);
                let offset = offset_of_local(start);
                *slot = Some((key, offset));
                offset
            }
        };
        Some(local.assume_offset(offset).into())
    }
}

/// `t` as a local DOS time, rounded down to 2 seconds. `None` outside 1980–2107.
pub fn to_dos(t: SystemTime) -> Option<DosTime> {
    let utc = OffsetDateTime::from(t);
    let local = utc.to_offset(local_offset_at(utc));
    let year = local.year();
    if !(1980..=2107).contains(&year) {
        return None;
    }
    let date = (u16::try_from(year - 1980).ok()? << 9)
        | (u16::from(u8::from(local.month())) << 5)
        | u16::from(local.day());
    let time = (u16::from(local.hour()) << 11)
        | (u16::from(local.minute()) << 5)
        | u16::from(local.second() / 2);
    Some(DosTime { date, time })
}

/// RFC 3339 in UTC, whole seconds: `2026-11-02T14:03:00Z`. This is the wire format.
pub fn rfc3339(t: SystemTime) -> String {
    let secs = to_unix(t);
    let dt = OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every half hour of 2024–2026 goes to a DOS time and back unchanged, through both readers,
    /// except in the hour repeated when summer time ends, where the local time names two
    /// instants and the DOS fields still come back the same. (Reading the offset at the local
    /// time as if it were UTC got the hours after each change wrong, in a zone that has them.)
    #[test]
    fn dos_times_round_trip_across_summer_time() {
        let start = 1_704_067_200i64; // 2024-01-01T00:00:00Z
        let mut clock = DosClock::default();
        let mut repeated = 0;
        for step in 0..(3 * 365 * 48) {
            let t = from_unix(start + step * 1800, 0).unwrap();
            let dos = to_dos(t).unwrap();
            for back in [from_dos(dos).unwrap(), clock.read(dos).unwrap()] {
                assert_eq!(to_dos(back), Some(dos), "{}", rfc3339(t));
                let off = to_unix(back) - to_unix(t);
                if off != 0 {
                    assert_eq!(off.abs(), 3600, "{} read as {}", rfc3339(t), rfc3339(back));
                    repeated += 1;
                }
            }
        }
        // Two half hours a year, each through two readers.
        assert!(repeated <= 3 * 2 * 2, "{repeated} times read back wrong");
    }

    #[test]
    fn unix_round_trip() {
        for secs in [0, 1, 1_700_000_000, -1, -86_400] {
            assert_eq!(to_unix(from_unix(secs, 0).unwrap()), secs);
        }
        // Rounds down, also before the epoch.
        assert_eq!(to_unix(from_unix(-2, 500_000_000).unwrap()), -2);
        assert_eq!(to_unix(from_unix(5, 999_999_999).unwrap()), 5);
    }

    #[test]
    fn ntfs_round_trip() {
        let t = from_unix(1_700_000_000, 123_456_700).unwrap();
        assert_eq!(from_ntfs(to_ntfs(t)), Some(t));
        assert_eq!(to_ntfs(UNIX_EPOCH), NTFS_TO_UNIX_SECS * 10_000_000);
    }

    #[test]
    fn dos_round_trip_to_two_seconds() {
        let t = from_unix(1_700_000_001, 0).unwrap();
        let dos = to_dos(t).unwrap();
        let back = from_dos(dos).unwrap();
        assert_eq!(to_unix(back), 1_700_000_000);
        assert_eq!(to_dos(from_unix(0, 0).unwrap()), None);
        assert_eq!(to_dos(from_unix(4_500_000_000, 0).unwrap()), None);
    }

    #[test]
    fn the_clock_reads_dos_times_as_from_dos_does() {
        let mut clock = DosClock::default();
        for secs in (1_600_000_000..1_800_000_000).step_by(7_777_777) {
            let dos = to_dos(from_unix(secs, 0).unwrap()).unwrap();
            assert_eq!(clock.read(dos), from_dos(dos), "{secs}");
            assert_eq!(clock.read(dos), from_dos(dos), "{secs}, cached");
        }
        assert_eq!(clock.read(DosTime { date: 0, time: 0 }), None);
    }

    #[test]
    fn rfc3339_is_utc_seconds() {
        let t = from_unix(1_793_628_180, 999).unwrap();
        assert_eq!(rfc3339(t), "2026-11-02T14:03:00Z");
    }
}
