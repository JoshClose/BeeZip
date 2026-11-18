//! The coders of a cell (docs/bhive.md §4.2): stored, one zstd frame, or one raw LZMA2 stream;
//! and what each level does with a cell (docs/M13.md §4).

use std::{
    io::{Read, Write},
    sync::atomic::{AtomicBool, Ordering},
};

use lzma_rust2::{Lzma2Options, Lzma2Reader, Lzma2Writer, LzmaOptions};

use super::layout::{Cell, Coder, bad, checksum, lzma2_dict, lzma2_param, sums};
use crate::{Error, Limits, Result};

/// The five levels (docs/M13.md decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Level {
    /// A bundle: nothing compressed, nothing shared.
    None,
    /// zstd 3 in 4 MiB cells.
    Fast,
    /// zstd 6 in 8 MiB cells.
    #[default]
    Balanced,
    /// LZMA2 at xz's preset 6 in 16 MiB cells; cells that zstd 3 can't shrink by 2 % are stored.
    High,
    /// LZMA2 at xz's preset 9 in 64 MiB cells.
    Max,
}

impl Level {
    pub const ALL: [Level; 5] = [
        Self::None,
        Self::Fast,
        Self::Balanced,
        Self::High,
        Self::Max,
    ];

    pub const fn number(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Fast => 1,
            Self::Balanced => 2,
            Self::High => 3,
            Self::Max => 4,
        }
    }

    pub fn from_number(n: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|l| i64::from(l.number()) == n)
    }

    /// The lowercase name the CLI and the settings use.
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::High => "high",
            Self::Max => "max",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.name() == name)
    }

    /// The most raw bytes of a cell.
    pub const fn cell_size(self) -> u32 {
        match self {
            Self::None | Self::Fast => 4 << 20,
            Self::Balanced => 8 << 20,
            Self::High => 16 << 20,
            Self::Max => 64 << 20,
        }
    }

    /// Whether repeated chunks are stored once: from Fast up (decisions 5 and 6).
    pub const fn shares(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The zstd level of the index and the journals. They are compressed at None too: names
    /// are a few percent of a tree of small files, and a bundle should be the size of its files.
    pub(super) const fn index_level(self) -> i32 {
        match self {
            Self::None => 3,
            Self::Fast | Self::Balanced => 6,
            Self::High => 15,
            Self::Max => 19,
        }
    }

    fn lzma_preset(self) -> Option<u32> {
        match self {
            Self::High => Some(6),
            Self::Max => Some(9),
            _ => None,
        }
    }

    /// What compressing one cell of `raw` bytes holds at once: the cell, room for its output,
    /// and the encoder's own tables. xz's preset 9 takes 674 MiB for these; the writer keeps
    /// only as many cells in flight as fit its budget (docs/M13.md §3).
    pub(super) fn memory(self, raw: usize) -> u64 {
        let encoder = match self.lzma_preset() {
            Some(preset) => u64::from(lzma_options(preset, raw).get_memory_usage()) * 1024,
            None if self == Self::None => 0,
            None => 16 << 20,
        };
        2 * raw as u64 + encoder
    }
}

/// xz's preset with the dictionary no larger than the cell: a dictionary beyond the data buys
/// nothing, and a reader allocates it.
fn lzma_options(preset: u32, raw: usize) -> LzmaOptions {
    let mut o = LzmaOptions::with_preset(preset);
    let fit = u32::try_from(raw.max(64 << 10).next_power_of_two()).unwrap_or(u32::MAX);
    o.dict_size = lzma2_dict(lzma2_param(o.dict_size.min(fit)));
    o
}

/// A cell as it goes into the file. `data` is `None` for a stored cell: its raw bytes.
#[derive(Debug)]
pub(super) struct Coded {
    pub coder: Coder,
    pub param: u8,
    pub data: Option<Vec<u8>>,
}

const STORED: Coded = Coded {
    coder: Coder::Stored,
    param: 0,
    data: None,
};

fn zstd_error(e: &std::io::Error) -> Error {
    Error::new(crate::ErrorKind::Io, format!("bhive: zstd: {e}"))
}

/// Compresses a cell as `level` does. `stop` ends an LZMA2 encode early, with `Cancelled`.
pub(super) fn encode(raw: &[u8], level: Level, stop: &AtomicBool) -> Result<Coded> {
    if raw.is_empty() {
        return Ok(STORED);
    }
    // What isn't smaller by a sixty-fourth is stored: reading it back is then a copy.
    let worth = |packed: usize| packed < raw.len() - raw.len() / 64;
    match level {
        Level::None => Ok(STORED),
        Level::Fast | Level::Balanced => {
            let zstd_level = if level == Level::Fast { 3 } else { 6 };
            let out = zstd::bulk::compress(raw, zstd_level).map_err(|e| zstd_error(&e))?;
            Ok(if worth(out.len()) {
                Coded {
                    coder: Coder::Zstd,
                    param: 0,
                    data: Some(out),
                }
            } else {
                STORED
            })
        }
        Level::High | Level::Max => {
            if level == Level::High {
                // The probe (decision 8): what zstd 3 can't shrink by 2 % is already compressed,
                // and LZMA2 would spend its time on it for a few percent.
                let probe = zstd::bulk::compress(raw, 3).map_err(|e| zstd_error(&e))?;
                if probe.len() >= raw.len() - raw.len() / 50 {
                    return Ok(STORED);
                }
            }
            let preset = level.lzma_preset().unwrap_or(6);
            let options = lzma_options(preset, raw.len());
            let param = lzma2_param(options.dict_size);
            let mut w = Lzma2Writer::new(
                Vec::with_capacity(raw.len() / 3),
                Lzma2Options {
                    lzma_options: options,
                    chunk_size: None,
                },
            );
            // In pieces, so a cancelled job doesn't wait for a whole cell: at preset 9 that is
            // most of a minute.
            for piece in raw.chunks(1 << 20) {
                if stop.load(Ordering::Relaxed) {
                    return Err(Error::cancelled());
                }
                w.write_all(piece)
                    .map_err(|e| Error::new(crate::ErrorKind::Io, format!("bhive: LZMA2: {e}")))?;
            }
            let out = w
                .finish()
                .map_err(|e| Error::new(crate::ErrorKind::Io, format!("bhive: LZMA2: {e}")))?;
            let keep = if level == Level::Max {
                out.len() < raw.len()
            } else {
                worth(out.len())
            };
            Ok(if keep {
                Coded {
                    coder: Coder::Lzma2,
                    param,
                    data: Some(out),
                }
            } else {
                STORED
            })
        }
    }
}

/// One zstd frame, decoded to exactly `raw` bytes: a cell's, a journal's or the index's.
pub(super) fn unzstd(stored: &[u8], raw: usize, what: &str) -> Result<Vec<u8>> {
    // Exactly one frame, and not a skippable one: zstd would decode any number of them.
    let one_frame = stored.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])
        && zstd::zstd_safe::find_frame_compressed_size(stored).is_ok_and(|n| n == stored.len());
    if !one_frame {
        return Err(bad(format!("{what} isn't one zstd frame")));
    }
    // Into a buffer of the raw length: a frame that holds more fails, without a window of its
    // own being allocated.
    let out = zstd::bulk::decompress(stored, raw)
        .map_err(|e| bad(format!("{what} doesn't decode ({e})")))?;
    if out.len() != raw {
        return Err(bad(format!(
            "{what} decodes to {} bytes, not its {raw}",
            out.len()
        )));
    }
    Ok(out)
}

/// The cell's raw bytes from its stored ones, checked against its length and checksum. The
/// memory it takes is checked against `decoder_memory` first.
pub(super) fn decode(
    cell: &Cell,
    number: u32,
    stored: Vec<u8>,
    limits: &Limits,
) -> Result<Vec<u8>> {
    let need = cell.memory();
    if need > limits.decoder_memory {
        return Err(Error::limit(format!(
            "bhive: cell {number} needs {} MiB to decode (limit `decoder_memory`)",
            need.div_ceil(1 << 20)
        )));
    }
    let what = format!("cell {number}");
    let raw_len = cell.raw as usize;
    let raw = match cell.coder {
        Coder::Stored => stored,
        Coder::Zstd => unzstd(&stored, raw_len, &what)?,
        Coder::Lzma2 => {
            let mut r = Lzma2Reader::new(&stored[..], lzma2_dict(cell.param), None);
            let mut out = Vec::with_capacity(raw_len);
            // One byte past the raw length shows a stream that holds more.
            (&mut r)
                .take(raw_len as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| bad(format!("{what} doesn't decode ({e})")))?;
            if out.len() != raw_len {
                return Err(bad(format!(
                    "{what} decodes to {} bytes or more, not its {raw_len}",
                    out.len()
                )));
            }
            if !r.into_inner().is_empty() {
                return Err(bad(format!("{what} has bytes after its LZMA2 stream")));
            }
            out
        }
    };
    if raw.len() != raw_len {
        return Err(bad(format!(
            "{what} holds {} bytes, not its {raw_len}",
            raw.len()
        )));
    }
    if !sums(checksum(&raw), cell.checksum) {
        return Err(bad(format!("{what} fails its checksum")));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorKind, format::bhive::chunk::tests::noise};

    fn text(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| b"the quick brown bee "[i % 20] ^ ((i / 977) as u8 & 3))
            .collect()
    }

    fn cell_of(raw: &[u8], coded: &Coded) -> (Cell, Vec<u8>) {
        let data = coded.data.clone().unwrap_or_else(|| raw.to_vec());
        let cell = Cell {
            offset: 64,
            stored: data.len() as u32,
            raw: raw.len() as u32,
            coder: coded.coder,
            param: coded.param,
            checksum: checksum(raw),
        };
        (cell, data)
    }

    #[test]
    fn every_level_round_trips_a_cell() {
        let stop = AtomicBool::new(false);
        let raw = text(300_000);
        for level in Level::ALL {
            let coded = encode(&raw, level, &stop).unwrap();
            let want = match level {
                Level::None => Coder::Stored,
                Level::Fast | Level::Balanced => Coder::Zstd,
                Level::High | Level::Max => Coder::Lzma2,
            };
            assert_eq!(coded.coder, want, "{level:?}");
            let (cell, data) = cell_of(&raw, &coded);
            cell.check().unwrap();
            assert_eq!(decode(&cell, 0, data, &Limits::default()).unwrap(), raw);
        }
    }

    #[test]
    fn what_does_not_shrink_is_stored() {
        let stop = AtomicBool::new(false);
        let raw = noise(200_000, 5);
        for level in Level::ALL {
            let coded = encode(&raw, level, &stop).unwrap();
            assert_eq!(coded.coder, Coder::Stored, "{level:?}");
        }
        assert_eq!(encode(&[], Level::Max, &stop).unwrap().coder, Coder::Stored);
    }

    #[test]
    fn the_dictionary_is_no_larger_than_the_cell() {
        let stop = AtomicBool::new(false);
        let raw = text(300_000);
        let coded = encode(&raw, Level::Max, &stop).unwrap();
        assert_eq!(lzma2_dict(coded.param), 512 << 10);
        assert_eq!(lzma_options(9, 64 << 20).dict_size, 64 << 20);
        assert_eq!(lzma_options(6, 64 << 20).dict_size, 8 << 20);
        // Preset 9 on a full cell is what bounds the cells in flight.
        assert!(Level::Max.memory(64 << 20) > 600 << 20);
        assert!(Level::Fast.memory(4 << 20) < 32 << 20);
    }

    #[test]
    fn a_damaged_cell_is_corrupt() {
        let stop = AtomicBool::new(false);
        let raw = text(100_000);
        let limits = Limits::default();
        for level in [Level::None, Level::Balanced, Level::High] {
            let coded = encode(&raw, level, &stop).unwrap();
            let (cell, data) = cell_of(&raw, &coded);
            // A flipped byte, a short stream, bytes after it, a wrong length, a wrong checksum.
            let mut flipped = data.clone();
            let at = flipped.len() / 2;
            flipped[at] ^= 0x40;
            let mut longer = data.clone();
            longer.push(0);
            let cases = [
                (cell, flipped),
                (cell, data[..data.len() - 1].to_vec()),
                (cell, longer),
                (
                    Cell {
                        raw: cell.raw - 1,
                        ..cell
                    },
                    data.clone(),
                ),
                (
                    Cell {
                        raw: cell.raw + 1,
                        ..cell
                    },
                    data.clone(),
                ),
                (
                    Cell {
                        checksum: cell.checksum ^ 1,
                        ..cell
                    },
                    data.clone(),
                ),
            ];
            for (i, (c, d)) in cases.into_iter().enumerate() {
                let e = decode(&c, 3, d, &limits).unwrap_err();
                assert_eq!(e.kind, ErrorKind::Corrupt, "{level:?} case {i}: {e}");
                assert!(e.message.contains("cell 3"), "{e}");
            }
        }
    }

    #[test]
    fn a_cell_over_the_memory_limit_is_refused_before_it_is_decoded() {
        let cell = Cell {
            offset: 64,
            stored: 10,
            raw: 200 << 20,
            coder: Coder::Lzma2,
            param: 32,
            checksum: 0,
        };
        assert_eq!(cell.memory(), (200 << 20) + (256 << 20));
        let limits = Limits {
            decoder_memory: 64 << 20,
            ..Limits::default()
        };
        let e = decode(&cell, 0, vec![0; 10], &limits).unwrap_err();
        assert_eq!(e.kind, ErrorKind::LimitExceeded);
    }

    #[test]
    fn two_frames_are_not_a_cell() {
        let raw = text(50_000);
        let mut two = zstd::bulk::compress(&raw[..25_000], 3).unwrap();
        two.extend(zstd::bulk::compress(&raw[25_000..], 3).unwrap());
        let e = unzstd(&two, raw.len(), "cell 0").unwrap_err();
        assert!(e.message.contains("one zstd frame"), "{e}");
        // A skippable frame alone, and one before a real frame.
        let mut skip = vec![0x50, 0x2A, 0x4D, 0x18, 4, 0, 0, 0, 1, 2, 3, 4];
        assert!(unzstd(&skip, 0, "x").is_err());
        skip.extend(zstd::bulk::compress(&raw, 3).unwrap());
        assert!(unzstd(&skip, raw.len(), "x").is_err());
    }

    #[test]
    fn levels_have_names_and_numbers() {
        for l in Level::ALL {
            assert_eq!(Level::from_number(i64::from(l.number())), Some(l));
            assert_eq!(Level::from_name(l.name()), Some(l));
        }
        assert_eq!(Level::from_number(5), None);
        assert_eq!(Level::default(), Level::Balanced);
    }
}
