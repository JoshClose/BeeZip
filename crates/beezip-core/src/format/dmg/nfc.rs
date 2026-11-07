//! Composing HFS+'s names again. HFS+ stores every name decomposed (its own variant of NFD:
//! `é` as `e` and a combining acute), so a `café.txt` that went in composed would come out as a
//! different name on Windows, beside the original. Listing names composed puts them back.
//!
//! The table is HFS+'s own decomposition run backwards: every character it decomposes into two
//! or more maps back from what it becomes, built once from the decomposer the caller gives (so
//! this file doesn't name the crate that has it). Two characters that decompose alike map back
//! to the lower one, which is the one NFC uses (`ά` U+03AC, not the Greek-extended U+1F71), and
//! the characters NFC never composes to (the script-specific exclusions and the decompositions
//! that start with a combining mark) are left out. Hangul syllables, which HFS+ decomposes by
//! arithmetic, are composed by arithmetic. Composing then takes the longest sequence the table
//! has at each place, which gives NFC's result for anything HFS+ decomposed.

use std::{collections::HashMap, sync::OnceLock};

struct Table {
    map: HashMap<Vec<char>, char>,
    longest: usize,
}

static TABLE: OnceLock<Table> = OnceLock::new();

/// Characters NFC doesn't compose to, apart from singletons, which never get into the table: the
/// script-specific exclusions and the decompositions starting with a non-starter, in the BMP
/// (Unicode's CompositionExclusions.txt).
const EXCLUDED: &[(u32, u32)] = &[
    (0x0344, 0x0344),
    (0x0958, 0x095F),
    (0x09DC, 0x09DD),
    (0x09DF, 0x09DF),
    (0x0A33, 0x0A33),
    (0x0A36, 0x0A36),
    (0x0A59, 0x0A5B),
    (0x0A5E, 0x0A5E),
    (0x0B5C, 0x0B5D),
    (0x0F43, 0x0F43),
    (0x0F4D, 0x0F4D),
    (0x0F52, 0x0F52),
    (0x0F57, 0x0F57),
    (0x0F5C, 0x0F5C),
    (0x0F69, 0x0F69),
    (0x0F73, 0x0F73),
    (0x0F75, 0x0F76),
    (0x0F78, 0x0F78),
    (0x0F81, 0x0F81),
    (0x0F93, 0x0F93),
    (0x0F9D, 0x0F9D),
    (0x0FA2, 0x0FA2),
    (0x0FA7, 0x0FA7),
    (0x0FAC, 0x0FAC),
    (0x0FB9, 0x0FB9),
    (0x2ADC, 0x2ADC),
    (0xFB1D, 0xFB1D),
    (0xFB1F, 0xFB1F),
    (0xFB2A, 0xFB36),
    (0xFB38, 0xFB3C),
    (0xFB3E, 0xFB3E),
    (0xFB40, 0xFB41),
    (0xFB43, 0xFB44),
    (0xFB46, 0xFB4E),
];

/// Ranges with nothing to decompose, skipped while building: CJK ideographs, Hangul syllables
/// (composed by arithmetic), surrogates and private use.
const SKIPPED: &[(u32, u32)] = &[(0x3400, 0x9FFF), (0xAC00, 0xDFFF), (0xE000, 0xF8FF)];

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;

fn in_ranges(c: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|&(a, b)| (a..=b).contains(&c))
}

fn build(decompose: fn(&str) -> String) -> Table {
    let mut map: HashMap<Vec<char>, char> = HashMap::new();
    let mut longest = 0;
    for u in 0xC0..=0xFFFDu32 {
        if in_ranges(u, SKIPPED) || in_ranges(u, EXCLUDED) {
            continue;
        }
        let Some(c) = char::from_u32(u) else {
            continue;
        };
        let d: Vec<char> = decompose(c.encode_utf8(&mut [0; 4])).chars().collect();
        if d.len() < 2 {
            continue;
        }
        longest = longest.max(d.len());
        // Increasing order, so the first in is the lower of two that decompose alike.
        map.entry(d).or_insert(c);
    }
    Table { map, longest }
}

/// `name` composed, using `decompose` (HFS+'s decomposition) to build the table the first time.
pub fn compose(name: &str, decompose: fn(&str) -> String) -> String {
    if name.is_ascii() {
        return name.to_owned();
    }
    let table = TABLE.get_or_init(|| build(decompose));
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len());
    let mut i = 0;
    'next: while i < chars.len() {
        let c = chars[i] as u32;
        // A leading consonant and a vowel, and maybe a trailing consonant: one syllable.
        if (L_BASE..L_BASE + L_COUNT).contains(&c)
            && let Some(&v) = chars.get(i + 1)
            && (V_BASE..V_BASE + V_COUNT).contains(&(v as u32))
        {
            let mut s = S_BASE + ((c - L_BASE) * V_COUNT + (v as u32 - V_BASE)) * T_COUNT;
            let mut n = 2;
            if let Some(&t) = chars.get(i + 2)
                && (T_BASE + 1..T_BASE + T_COUNT).contains(&(t as u32))
            {
                s += t as u32 - T_BASE;
                n = 3;
            }
            if let Some(h) = char::from_u32(s) {
                out.push(h);
                i += n;
                continue;
            }
        }
        for k in (2..=table.longest.min(chars.len() - i)).rev() {
            if let Some(&composed) = table.map.get(&chars[i..i + k]) {
                out.push(composed);
                i += k;
                continue 'next;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}
