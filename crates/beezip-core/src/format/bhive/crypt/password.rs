//! Slot kind 1, a password (bhive.md §12.5): Argon2id of the password in NFC.
//!
//! Argon2's lanes run on rayon's threads (`argon2`'s `parallel` feature): Standard takes about
//! 0.3 s on 4 threads here, against 0.9 s on one (docs/M14.md §5).

use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::{MadeSlot, SlotSecret, SlotView, Strength, prim};
use crate::{Error, ErrorKind, Result, format::bhive::layout::bad};

/// The public part's length: version, reserved, memory, passes, lanes, salt.
pub const PUBLIC_LEN: usize = 48;
/// Readers refuse more (bhive.md §12.5).
pub const MAX_MEMORY_KIB: u32 = 4 << 20;
pub const MAX_PASSES: u32 = 16;
pub const MAX_LANES: u32 = 16;
/// Argon2's version, the public part's first byte.
pub const VERSION: u8 = 0x13;

/// A password slot's cost and salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
    pub salt: [u8; 32],
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl Cost {
    /// The public part that says this cost.
    pub fn public(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(PUBLIC_LEN);
        p.extend_from_slice(&[VERSION, 0, 0, 0]);
        p.extend_from_slice(&self.memory_kib.to_le_bytes());
        p.extend_from_slice(&self.passes.to_le_bytes());
        p.extend_from_slice(&self.lanes.to_le_bytes());
        p.extend_from_slice(&self.salt);
        p
    }

    /// The cost a public part says, checked against the limits.
    pub fn parse(public: &[u8]) -> Result<Self> {
        check(public)?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&public[16..48]);
        Ok(Self {
            memory_kib: word(public, 4),
            passes: word(public, 8),
            lanes: word(public, 12),
            salt,
        })
    }
}

/// Argon2id of `password` in NFC, as UTF-8 (bhive.md §12.5).
pub fn argon2id(password: &str, cost: &Cost) -> Result<Zeroizing<Vec<u8>>> {
    let nfc: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    let params = Params::new(cost.memory_kib, cost.passes, cost.lanes, Some(32))
        .map_err(|e| Error::invalid_args(format!("bhive: Argon2's cost: {e}")))?;
    let mut out = Zeroizing::new(vec![0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(nfc.as_bytes(), &cost.salt, &mut out)
        .map_err(|e| match e {
            argon2::Error::OutOfMemory => Error::limit(format!(
                "bhive: a password slot needs {} MiB of memory, which isn't free",
                cost.memory_kib / 1024
            )),
            e => Error::new(ErrorKind::Io, format!("bhive: Argon2 failed: {e}")),
        })?;
    Ok(out)
}

/// A new slot's public part (a fresh salt, the strength's cost) and Argon2id's output.
pub fn make(password: &Zeroizing<String>, strength: Strength) -> Result<MadeSlot> {
    let (memory_kib, passes, lanes) = strength.cost();
    let cost = Cost {
        memory_kib,
        passes,
        lanes,
        salt: prim::random()?,
    };
    let public = cost.public();
    // What a reader would refuse is never written.
    check(&public).map_err(|e| Error::invalid_args(e.message))?;
    Ok(MadeSlot {
        secret: SlotSecret::Shared(argon2id(password, &cost)?),
        public,
        recipient_key: Vec::new(),
    })
}

/// Argon2id of `password` with the slot's salt and cost.
pub fn secret(slot: &SlotView<'_>, password: &str) -> Result<SlotSecret> {
    let cost = Cost::parse(slot.public)?;
    Ok(SlotSecret::Shared(argon2id(password, &cost)?))
}

/// The bytes of memory Argon2 needs for this slot, to ask before spending more than half the
/// machine's (docs/M14.md §5).
pub fn memory(public: &[u8]) -> Option<u64> {
    Cost::parse(public)
        .ok()
        .map(|c| u64::from(c.memory_kib) * 1024)
}

/// Length and limits (bhive.md §12.5, §12.10). Reserved bytes are ignored.
pub fn check(public: &[u8]) -> Result<()> {
    if public.len() != PUBLIC_LEN {
        return Err(bad(format!(
            "a password slot's public part is {} bytes, not {PUBLIC_LEN}",
            public.len()
        )));
    }
    if public[0] != VERSION {
        return Err(bad(format!(
            "a password slot names Argon2 version {:#x}, not 0x13",
            public[0]
        )));
    }
    let (memory, passes, lanes) = (word(public, 4), word(public, 8), word(public, 12));
    if !(1..=MAX_LANES).contains(&lanes) {
        return Err(bad(format!("a password slot with {lanes} lanes (1 to 16)")));
    }
    if !(1..=MAX_PASSES).contains(&passes) {
        return Err(bad(format!(
            "a password slot with {passes} passes (1 to 16)"
        )));
    }
    if memory > MAX_MEMORY_KIB || memory < 8 * lanes {
        return Err(bad(format!(
            "a password slot asks for {memory} KiB of memory (8 KiB a lane to 4 GiB)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(memory: u32, passes: u32, lanes: u32) -> Vec<u8> {
        Cost {
            memory_kib: memory,
            passes,
            lanes,
            salt: [1; 32],
        }
        .public()
    }

    #[test]
    fn the_limits_are_the_specifications() {
        assert!(check(&public(256, 2, 4)).is_ok());
        assert!(check(&public(MAX_MEMORY_KIB, 16, 16)).is_ok());
        assert!(check(&public(32, 1, 4)).is_ok());
        for (m, t, p) in [
            (MAX_MEMORY_KIB + 1, 2, 4),
            (31, 2, 4),
            (256, 0, 4),
            (256, 17, 4),
            (256, 2, 0),
            (256, 2, 17),
        ] {
            assert!(check(&public(m, t, p)).is_err(), "{m} {t} {p}");
        }
        let mut v = public(256, 2, 4);
        v[0] = 0x10;
        assert!(check(&v).is_err());
        assert!(check(&v[..47]).is_err());
        let mut r = public(256, 2, 4);
        r[1] = 9;
        assert!(check(&r).is_ok());
        assert_eq!(memory(&public(256, 2, 4)), Some(256 * 1024));
    }

    #[test]
    fn standard_and_strong_are_within_the_limits() {
        for s in [Strength::Standard, Strength::Strong] {
            let (m, t, p) = s.cost();
            assert!(check(&public(m, t, p)).is_ok());
        }
    }

    /// Standard's real cost on 4 lanes, alone: about 0.3 s here when the lanes run on threads,
    /// 0.9 s when they don't (docs/M14.md §5). `cargo test -- --ignored lanes`.
    #[test]
    #[ignore = "takes 1 GiB and a second; run alone to time it"]
    fn lanes_run_on_threads() {
        let (memory_kib, passes, lanes) = Strength::Standard.cost();
        let cost = Cost {
            memory_kib,
            passes,
            lanes,
            salt: [3; 32],
        };
        let t = std::time::Instant::now();
        argon2id("correct horse", &cost).unwrap();
        let four = t.elapsed();
        let t = std::time::Instant::now();
        let one = Cost { lanes: 1, ..cost };
        argon2id("correct horse", &one).unwrap();
        let single = t.elapsed();
        eprintln!("4 lanes: {four:?}, 1 lane: {single:?}");
        assert!(four * 2 < single, "the lanes didn't run at once");
    }
}
