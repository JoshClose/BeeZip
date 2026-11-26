//! Slot kind 2, a recovery key (bhive.md §12.5): 16 random bytes shown as 48 digits, as
//! BitLocker's: 8 groups of 6, each a multiple of 11 so that a typo shows.

use zeroize::Zeroizing;

use super::{MadeSlot, SlotSecret, SlotView, prim};
use crate::{Error, Result, format::bhive::layout::bad};

/// The public part: a salt.
pub const PUBLIC_LEN: usize = 32;
/// A group is at most this, exclusive: 65,536 × 11.
const GROUP_END: u32 = 720_896;

/// A new recovery key.
pub fn generate() -> Result<Zeroizing<[u8; 16]>> {
    Ok(Zeroizing::new(prim::random()?))
}

/// The key as people see it: 8 groups of 6 digits joined by hyphens.
pub fn format(key: &[u8; 16]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(55));
    for i in 0..8 {
        let group = (u32::from(key[2 * i]) + 256 * u32::from(key[2 * i + 1])) * 11;
        if i > 0 {
            s.push('-');
        }
        s.push_str(&format!("{group:06}"));
    }
    s
}

fn not_a_key(why: &str) -> Error {
    Error::invalid_args(format!("that isn't a recovery key: {why}"))
}

/// The key from what someone typed: any separators, 48 digits, each group a multiple of 11 and
/// under 720,896.
pub fn parse(text: &str) -> Result<Zeroizing<[u8; 16]>> {
    let digits: Zeroizing<Vec<u8>> = Zeroizing::new(
        text.bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect(),
    );
    if digits.len() != 48 {
        return Err(not_a_key(&format!(
            "it has {} digits, not 48",
            digits.len()
        )));
    }
    if text.chars().any(char::is_alphabetic) {
        return Err(not_a_key("it has letters"));
    }
    let mut key = Zeroizing::new([0u8; 16]);
    for (i, group) in digits.chunks(6).enumerate() {
        let value = group.iter().fold(0u32, |n, &d| n * 10 + u32::from(d));
        if value % 11 != 0 || value >= GROUP_END {
            return Err(not_a_key(&format!("group {} is mistyped", i + 1)));
        }
        let k = (value / 11).to_le_bytes();
        key[2 * i] = k[0];
        key[2 * i + 1] = k[1];
    }
    Ok(key)
}

/// A slot for `key`, with a fresh salt.
pub fn make(key: &Zeroizing<[u8; 16]>) -> Result<MadeSlot> {
    let salt: [u8; PUBLIC_LEN] = prim::random()?;
    Ok(MadeSlot {
        public: salt.to_vec(),
        secret: SlotSecret::Shared(Zeroizing::new(key.to_vec())),
        recipient_key: Vec::new(),
    })
}

/// The secret from what someone typed.
pub fn secret(slot: &SlotView<'_>, typed: &str) -> Result<SlotSecret> {
    check(slot.public)?;
    let key = parse(typed)?;
    Ok(SlotSecret::Shared(Zeroizing::new(key.to_vec())))
}

pub fn check(public: &[u8]) -> Result<()> {
    if public.len() != PUBLIC_LEN {
        return Err(bad(format!(
            "a recovery-key slot's public part is {} bytes, not {PUBLIC_LEN}",
            public.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_their_digits() {
        for _ in 0..64 {
            let k = generate().unwrap();
            let shown = format(&k);
            assert_eq!(shown.len(), 55);
            assert_eq!(*parse(&shown).unwrap(), *k);
            // Any separators, or none.
            let bare: String = shown.chars().filter(char::is_ascii_digit).collect();
            assert_eq!(*parse(&bare).unwrap(), *k);
            assert_eq!(*parse(&shown.replace('-', " ")).unwrap(), *k);
        }
        assert_eq!(*format(&[0xff; 16]), "720885-".repeat(7) + "720885");
        assert_eq!(*format(&[0; 16]), "000000-".repeat(7) + "000000");
    }

    #[test]
    fn typos_are_refused() {
        let good = "000011-".repeat(7) + "000011";
        assert!(parse(&good).is_ok());
        // Not a multiple of 11.
        assert!(parse(&("000012-".repeat(7) + "000011")).is_err());
        // 720,896 is 65,536 × 11: one past the largest group.
        assert!(parse(&("720896-".repeat(7) + "000011")).is_err());
        assert!(parse(&good[..54]).is_err());
        assert!(parse(&(good.clone() + "1")).is_err());
        assert!(parse(&good.replacen('-', "a", 1)).is_err());
    }
}
