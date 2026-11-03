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
    let offset = local_offset_at(local.assume_utc());
    Some(local.assume_offset(offset).into())
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
    fn rfc3339_is_utc_seconds() {
        let t = from_unix(1_793_628_180, 999).unwrap();
        assert_eq!(rfc3339(t), "2026-11-02T14:03:00Z");
    }
}
