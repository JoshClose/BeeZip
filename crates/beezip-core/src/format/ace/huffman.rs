//! ACE's Huffman trees: code widths stored in the stream, themselves coded with a small tree of
//! widths, and turned into codes in the order ACE's own quicksort leaves them.

use std::io::Read;

use super::{bits::BitReader, header::bad};
use crate::Result;

/// The widths of a tree's code widths, and the longest of those.
const WIDTH_WIDTH_BITS: u32 = 3;
const MAX_WIDTH_WIDTH: u8 = (1 << WIDTH_WIDTH_BITS) - 1;

/// A tree as a table: every code of `max_width` bits, its symbol, and each symbol's width.
pub struct Tree {
    codes: Vec<u16>,
    widths: Vec<u8>,
    max_width: u8,
}

impl Tree {
    pub fn read_symbol<R: Read>(&self, bs: &mut BitReader<R>) -> Result<u16> {
        let code = bs.peek(u32::from(self.max_width))? as usize;
        let sym = *self
            .codes
            .get(code)
            .ok_or_else(|| bad("a Huffman code that isn't in its tree"))?;
        // Every symbol in the table has a width: `make` puts only those there.
        let width = self.widths.get(usize::from(sym)).copied().unwrap_or(0);
        bs.skip(u32::from(width))?;
        Ok(sym)
    }
}

/// Sorts `keys` from the largest down, moving `values` with them, exactly as ACE does: the
/// codes depend on where equal keys end up, which a stable sort would change.
fn quicksort(keys: &mut [u8], values: &mut [u16]) {
    if keys.len() > 1 {
        sort_range(keys, values, 0, keys.len() - 1);
    }
}

fn sort_range(keys: &mut [u8], values: &mut [u16], left: usize, right: usize) {
    // Hoare's partition around the last key. Each scan stops at the latest at an element the
    // other one left behind, so neither leaves `left..=right`; `r` may end one below `left`.
    let pivot = keys[right];
    let (mut l, mut r) = (left, right as isize);
    loop {
        while keys[l] > pivot {
            l += 1;
        }
        while keys[r as usize] < pivot {
            r -= 1;
        }
        if l as isize <= r {
            keys.swap(l, r as usize);
            values.swap(l, r as usize);
            l += 1;
            r -= 1;
        }
        if l as isize >= r {
            break;
        }
    }
    if (left as isize) < r {
        let r = r as usize;
        if left + 1 < r {
            sort_range(keys, values, left, r);
        } else if keys[left] < keys[r] {
            keys.swap(left, r);
            values.swap(left, r);
        }
    }
    if right > l {
        if l + 1 < right {
            sort_range(keys, values, l, right);
        } else if keys[l] < keys[right] {
            keys.swap(l, right);
            values.swap(l, right);
        }
    }
}

/// The tree whose symbols have `widths` (0 for unused ones).
fn make(mut widths: Vec<u8>, max_width: u8) -> Result<Tree> {
    let mut symbols: Vec<u16> = (0..widths.len() as u16).collect();
    let mut sorted = widths.clone();
    quicksort(&mut sorted, &mut symbols);
    let mut used = sorted.iter().take_while(|&&w| w != 0).count();
    // A tree of one symbol, or of none, still takes a bit per symbol.
    if used < 2 {
        if let Some(&first) = symbols.first() {
            widths[usize::from(first)] = 1;
        }
        used = used.max(1).min(symbols.len());
    }
    let max_codes = 1usize << max_width;
    let mut codes = Vec::with_capacity(max_codes);
    for (&sym, &width) in symbols[..used].iter().zip(&sorted[..used]).rev() {
        if width > max_width {
            return Err(bad("a Huffman code is longer than its tree allows"));
        }
        let repeat = 1usize << (max_width - width);
        if codes.len() + repeat > max_codes {
            return Err(bad("a Huffman tree has more codes than fit"));
        }
        codes.extend(std::iter::repeat_n(sym, repeat));
    }
    Ok(Tree {
        codes,
        widths,
        max_width,
    })
}

/// Reads a tree of at most `num_codes` symbols whose codes are at most `max_width` bits.
pub fn read_tree<R: Read>(bs: &mut BitReader<R>, max_width: u8, num_codes: usize) -> Result<Tree> {
    let num_widths = (bs.read(9)? as usize + 1).min(num_codes + 1);
    let lower = bs.read(4)? as u8;
    let upper = bs.read(4)? as u8;
    let mut width_widths = Vec::with_capacity(usize::from(upper) + 1);
    for _ in 0..=upper {
        width_widths.push(bs.read(WIDTH_WIDTH_BITS)? as u8);
    }
    let width_tree = make(width_widths, MAX_WIDTH_WIDTH)?;

    let mut widths = Vec::with_capacity(num_widths);
    while widths.len() < num_widths {
        let sym = width_tree.read_symbol(bs)?;
        if sym < u16::from(upper) {
            widths.push(sym as u8);
        } else {
            // A run of 4–19 repeats.
            let run = (bs.read(4)? as usize + 4).min(num_widths - widths.len());
            widths.resize(widths.len() + run, 0);
        }
    }
    // Each width is stored as its difference from the one before, modulo `upper`.
    if upper > 0 {
        for i in 1..widths.len() {
            widths[i] = (widths[i] + widths[i - 1]) % upper;
        }
    }
    for w in &mut widths {
        if *w > 0 {
            *w += lower;
        }
    }
    make(widths, max_width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quicksort_matches_acefile() {
        // acefile's `Huffman._quicksort` doctest.
        let mut k = [1u8, 0, 0, 1, 2, 0, 0];
        let mut v: Vec<u16> = (0..7).collect();
        quicksort(&mut k, &mut v);
        assert_eq!(k, [2, 1, 1, 0, 0, 0, 0]);
        assert_eq!(v, [4, 0, 3, 5, 6, 2, 1]);
    }

    #[test]
    fn quicksort_survives_any_keys() {
        let mut x = 0x2545_f491_u32;
        for len in 1..300usize {
            let mut keys: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    (x % 13) as u8
                })
                .collect();
            let mut values: Vec<u16> = (0..len as u16).collect();
            let before = keys.clone();
            quicksort(&mut keys, &mut values);
            assert!(keys.windows(2).all(|w| w[0] >= w[1]), "{len}");
            assert!(
                values
                    .iter()
                    .zip(&keys)
                    .all(|(&v, &k)| before[v as usize] == k)
            );
        }
        let mut same = vec![5u8; 285];
        let mut values: Vec<u16> = (0..285).collect();
        quicksort(&mut same, &mut values);
        let mut sorted = values.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..285).collect::<Vec<u16>>());
    }

    #[test]
    fn trees_from_widths() {
        // As acefile builds them: the codes of the widest symbols come last.
        let t = make(vec![2, 3, 3, 4, 5, 4, 5, 4, 3, 3], 7).unwrap();
        assert_eq!(t.codes.len(), 128);
        assert!(t.codes[..32].iter().all(|&c| c == 0));
        // One symbol, or none, still decodes with one bit.
        let one = make(vec![0, 3, 0], 7).unwrap();
        assert_eq!(one.widths, [0, 1, 0]);
        assert_eq!(one.codes, vec![1; 16]);
        let none = make(vec![0, 0], 7).unwrap();
        assert_eq!(none.codes.len(), 128);
        assert!(make(vec![8, 1], 7).is_err(), "too wide");
        assert!(make(vec![1, 1, 1], 7).is_err(), "too many codes");
    }
}
