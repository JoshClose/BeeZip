//! Names stored as bytes in a legacy code page (docs/M5.md §6).
//!
//! Formats that mark a name as UTF-8 (zip's flag bit 11, tar's pax records) are read as UTF-8.
//! Every other name goes through [`NameDecoding`]: "auto" reads a name that is valid UTF-8 as
//! UTF-8, since macOS and Linux tools often leave zip's flag off, and anything else in the
//! system's OEM code page for zip (as Explorer and 7-Zip do) or its ANSI code page for the other
//! formats. A chosen encoding applies to every name not marked as UTF-8. Nothing is guessed
//! from the bytes.
//!
//! Core doesn't know the system's code pages: `beezip-commands` reads them from the registry
//! and puts them in [`NameDecoding`]. The defaults, 437 and 1252, are what a US system has.

use encoding_rs::Encoding;

/// The encodings a name can be read in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NameEncoding {
    /// UTF-8 when marked or valid, otherwise the system's code page.
    #[default]
    Auto,
    Utf8,
    /// DOS Latin US, zip's original code page.
    Cp437,
    /// DOS Latin 1 (Western Europe).
    Cp850,
    /// DOS Latin 2 (Central Europe).
    Cp852,
    /// DOS Cyrillic (Russian).
    Cp866,
    /// Thai.
    Cp874,
    /// Japanese (Shift-JIS).
    Cp932,
    /// Simplified Chinese (GBK).
    Cp936,
    /// Korean.
    Cp949,
    /// Traditional Chinese (Big5).
    Cp950,
    /// Windows Central Europe.
    Cp1250,
    /// Windows Cyrillic.
    Cp1251,
    /// Windows Western Europe.
    Cp1252,
    /// Windows Greek.
    Cp1253,
    /// Windows Turkish.
    Cp1254,
    /// Windows Hebrew.
    Cp1255,
    /// Windows Arabic.
    Cp1256,
    /// Windows Baltic.
    Cp1257,
    /// Windows Vietnamese.
    Cp1258,
    Koi8R,
    Koi8U,
    /// Latin-1: every byte is the code point of the same number.
    Iso8859_1,
    Iso8859_2,
    Iso8859_5,
    Iso8859_7,
    EucJp,
    Gb18030,
}

impl NameEncoding {
    pub const ALL: [NameEncoding; 28] = [
        Self::Auto,
        Self::Utf8,
        Self::Cp437,
        Self::Cp850,
        Self::Cp852,
        Self::Cp866,
        Self::Cp874,
        Self::Cp932,
        Self::Cp936,
        Self::Cp949,
        Self::Cp950,
        Self::Cp1250,
        Self::Cp1251,
        Self::Cp1252,
        Self::Cp1253,
        Self::Cp1254,
        Self::Cp1255,
        Self::Cp1256,
        Self::Cp1257,
        Self::Cp1258,
        Self::Koi8R,
        Self::Koi8U,
        Self::Iso8859_1,
        Self::Iso8859_2,
        Self::Iso8859_5,
        Self::Iso8859_7,
        Self::EucJp,
        Self::Gb18030,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Utf8 => "utf-8",
            Self::Cp437 => "cp437",
            Self::Cp850 => "cp850",
            Self::Cp852 => "cp852",
            Self::Cp866 => "cp866",
            Self::Cp874 => "cp874",
            Self::Cp932 => "cp932",
            Self::Cp936 => "cp936",
            Self::Cp949 => "cp949",
            Self::Cp950 => "cp950",
            Self::Cp1250 => "cp1250",
            Self::Cp1251 => "cp1251",
            Self::Cp1252 => "cp1252",
            Self::Cp1253 => "cp1253",
            Self::Cp1254 => "cp1254",
            Self::Cp1255 => "cp1255",
            Self::Cp1256 => "cp1256",
            Self::Cp1257 => "cp1257",
            Self::Cp1258 => "cp1258",
            Self::Koi8R => "koi8-r",
            Self::Koi8U => "koi8-u",
            Self::Iso8859_1 => "iso-8859-1",
            Self::Iso8859_2 => "iso-8859-2",
            Self::Iso8859_5 => "iso-8859-5",
            Self::Iso8859_7 => "iso-8859-7",
            Self::EucJp => "euc-jp",
            Self::Gb18030 => "gb18030",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.name() == name)
    }

    /// The Windows code page it is, for every encoding but `Auto`.
    pub const fn code_page(self) -> Option<u16> {
        Some(match self {
            Self::Auto => return None,
            Self::Utf8 => UTF8,
            Self::Cp437 => 437,
            Self::Cp850 => 850,
            Self::Cp852 => 852,
            Self::Cp866 => 866,
            Self::Cp874 => 874,
            Self::Cp932 => 932,
            Self::Cp936 => 936,
            Self::Cp949 => 949,
            Self::Cp950 => 950,
            Self::Cp1250 => 1250,
            Self::Cp1251 => 1251,
            Self::Cp1252 => 1252,
            Self::Cp1253 => 1253,
            Self::Cp1254 => 1254,
            Self::Cp1255 => 1255,
            Self::Cp1256 => 1256,
            Self::Cp1257 => 1257,
            Self::Cp1258 => 1258,
            Self::Koi8R => 20866,
            Self::Koi8U => 21866,
            Self::Iso8859_1 => LATIN1,
            Self::Iso8859_2 => 28592,
            Self::Iso8859_5 => 28595,
            Self::Iso8859_7 => 28597,
            Self::EucJp => 51932,
            Self::Gb18030 => 54936,
        })
    }
}

const UTF8: u16 = 65001;
const LATIN1: u16 = 28591;
/// What "auto" uses when the system's code page is one BeeZip can't decode.
const OEM_FALLBACK: u16 = 437;
const ANSI_FALLBACK: u16 = 1252;

/// Which of the system's code pages "auto" falls back to for a format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPage {
    /// Zip: names written by DOS-era tools and Explorer.
    Oem,
    /// Tar, cpio, CAB and the rest.
    Ansi,
}

/// How names stored as bytes are read: the encoding chosen, and the system's code pages "auto"
/// falls back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameDecoding {
    pub encoding: NameEncoding,
    /// The system's OEM code page (`OEMCP`), for zip.
    pub oem: u16,
    /// The system's ANSI code page (`ACP`), for the other formats.
    pub ansi: u16,
}

impl Default for NameDecoding {
    fn default() -> Self {
        Self {
            encoding: NameEncoding::Auto,
            oem: OEM_FALLBACK,
            ansi: ANSI_FALLBACK,
        }
    }
}

impl NameDecoding {
    /// A name as stored. `utf8` says the format marks it as UTF-8.
    pub fn decode(&self, raw: &[u8], utf8: bool, page: SystemPage) -> String {
        if utf8 {
            return String::from_utf8_lossy(raw).into_owned();
        }
        match self.encoding.code_page() {
            None => match std::str::from_utf8(raw) {
                Ok(s) => s.to_owned(),
                Err(_) => match page {
                    SystemPage::Oem => decode_page(raw, self.oem, OEM_FALLBACK),
                    SystemPage::Ansi => decode_page(raw, self.ansi, ANSI_FALLBACK),
                },
            },
            Some(cp) => decode_page(raw, cp, OEM_FALLBACK),
        }
    }

    /// A name stored in the Windows code page `cp` that the format itself declares (an MSI's
    /// string pool, docs/M7.md §8.1). Code page 0, "neutral", is the system's ANSI code page, as
    /// Windows reads it: it goes through [`NameDecoding::decode`] like any name stored as bytes.
    /// A code page BeeZip doesn't know is read in the system's ANSI code page too.
    pub fn decode_in(&self, raw: &[u8], cp: u32) -> String {
        match u16::try_from(cp) {
            Ok(cp) if cp != 0 && Self::knows(cp) => decode_page(raw, cp, ANSI_FALLBACK),
            _ => self.decode(raw, false, SystemPage::Ansi),
        }
    }

    /// Whether BeeZip decodes `cp` itself rather than falling back.
    pub fn knows(cp: u16) -> bool {
        matches!(cp, UTF8 | LATIN1)
            || oem_cp::code_table::DECODING_TABLE_CP_MAP.contains_key(&cp)
            || whatwg(cp).is_some()
    }
}

/// `raw` in code page `cp`, or in `fallback` when BeeZip doesn't know `cp`. Bytes a code page
/// leaves undefined become U+FFFD.
fn decode_page(raw: &[u8], cp: u16, fallback: u16) -> String {
    if raw.is_ascii() {
        // Every page here reads ASCII as ASCII.
        return raw.iter().map(|&b| char::from(b)).collect();
    }
    let cp = if NameDecoding::knows(cp) {
        cp
    } else {
        fallback
    };
    match cp {
        UTF8 => String::from_utf8_lossy(raw).into_owned(),
        LATIN1 => raw.iter().map(|&b| char::from(b)).collect(),
        _ => {
            // The DOS pages from oem_cp, which encoding_rs lacks (it has 866 and 874, which
            // oem_cp's tables match).
            if let Some(table) = oem_cp::code_table::DECODING_TABLE_CP_MAP.get(&cp) {
                return table.decode_string_lossy(raw);
            }
            match whatwg(cp) {
                Some(enc) => enc.decode_without_bom_handling(raw).0.into_owned(),
                None => String::from_utf8_lossy(raw).into_owned(),
            }
        }
    }
}

/// The encoding_rs encoding for a Windows code page, where it has one.
fn whatwg(cp: u16) -> Option<&'static Encoding> {
    use encoding_rs as e;
    Some(match cp {
        866 => e::IBM866,
        874 => e::WINDOWS_874,
        932 => e::SHIFT_JIS,
        936 => e::GBK,
        949 | 51949 => e::EUC_KR,
        950 => e::BIG5,
        1250 => e::WINDOWS_1250,
        1251 => e::WINDOWS_1251,
        1252 => e::WINDOWS_1252,
        1253 => e::WINDOWS_1253,
        1254 => e::WINDOWS_1254,
        1255 => e::WINDOWS_1255,
        1256 => e::WINDOWS_1256,
        1257 => e::WINDOWS_1257,
        1258 => e::WINDOWS_1258,
        10000 => e::MACINTOSH,
        10007 => e::X_MAC_CYRILLIC,
        20866 => e::KOI8_R,
        21866 => e::KOI8_U,
        28592 => e::ISO_8859_2,
        28593 => e::ISO_8859_3,
        28594 => e::ISO_8859_4,
        28595 => e::ISO_8859_5,
        28596 => e::ISO_8859_6,
        28597 => e::ISO_8859_7,
        28598 => e::ISO_8859_8,
        28603 => e::ISO_8859_13,
        28605 => e::ISO_8859_15,
        20932 | 51932 => e::EUC_JP,
        54936 => e::GB18030,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(encoding: NameEncoding) -> NameDecoding {
        NameDecoding {
            encoding,
            ..NameDecoding::default()
        }
    }

    #[test]
    fn names_round_trip() {
        for e in NameEncoding::ALL {
            assert_eq!(NameEncoding::from_name(e.name()), Some(e));
        }
        assert_eq!(NameEncoding::from_name("cp1259"), None);
        // Every encoding offered can be decoded.
        for e in NameEncoding::ALL
            .into_iter()
            .filter_map(NameEncoding::code_page)
        {
            assert!(NameDecoding::knows(e), "{e}");
        }
    }

    #[test]
    fn auto_reads_utf8_then_the_system_page() {
        let auto = NameDecoding::default();
        assert_eq!(
            auto.decode("résumé.txt".as_bytes(), false, SystemPage::Oem),
            "résumé.txt"
        );
        // 0x82 is é in CP437, and ‚ in Windows-1252.
        assert_eq!(
            auto.decode(b"r\x82sum\x82", false, SystemPage::Oem),
            "résumé"
        );
        assert_eq!(
            auto.decode(b"r\x82sum\x82", false, SystemPage::Ansi),
            "r‚sum‚"
        );
        // A Japanese system reads zip names in Shift-JIS: 日本 is 93 FA 96 7B.
        let jp = NameDecoding {
            oem: 932,
            ansi: 932,
            ..auto
        };
        assert_eq!(
            jp.decode(b"\x93\xFA\x96\x7B.txt", false, SystemPage::Oem),
            "日本.txt"
        );
        // A code page BeeZip doesn't know falls back to 437 (OEM) or 1252 (ANSI).
        let odd = NameDecoding {
            oem: 1,
            ansi: 1,
            ..auto
        };
        assert_eq!(odd.decode(b"\x82", false, SystemPage::Oem), "é");
        assert_eq!(odd.decode(b"\xE9", false, SystemPage::Ansi), "é");
    }

    #[test]
    fn a_chosen_encoding_applies_to_every_unmarked_name() {
        // Shift-JIS whose bytes happen to be valid UTF-8 are still read as Shift-JIS.
        assert_eq!(
            with(NameEncoding::Cp932).decode("é".as_bytes(), false, SystemPage::Oem),
            "ﾃｩ"
        );
        // ...but a name the format marks as UTF-8 stays UTF-8.
        assert_eq!(
            with(NameEncoding::Cp932).decode("é".as_bytes(), true, SystemPage::Oem),
            "é"
        );
        // Shift-JIS's trail byte 0x5C isn't a backslash: 表 is 95 5C.
        assert_eq!(
            with(NameEncoding::Cp932).decode(b"\x95\x5C", false, SystemPage::Oem),
            "表"
        );
        assert_eq!(
            with(NameEncoding::Cp866).decode(b"\x8F\xE0\xA8\xA2\xA5\xE2", false, SystemPage::Oem),
            "Привет"
        );
        assert_eq!(
            with(NameEncoding::Cp936).decode(b"\xD6\xD0\xCE\xC4", false, SystemPage::Oem),
            "中文"
        );
        // True Latin-1, not the Windows-1252 that WHATWG gives the label.
        assert_eq!(
            with(NameEncoding::Iso8859_1).decode(b"\x80\xE9", false, SystemPage::Ansi),
            "\u{80}é"
        );
        assert_eq!(
            with(NameEncoding::Cp1252).decode(b"\x80\xE9", false, SystemPage::Ansi),
            "€é"
        );
        assert_eq!(
            with(NameEncoding::Utf8).decode(b"a\xFFb", false, SystemPage::Ansi),
            "a\u{FFFD}b"
        );
    }

    #[test]
    fn a_declared_code_page_wins_and_neutral_is_the_systems() {
        let auto = NameDecoding::default();
        // café in Windows-1252, and in UTF-8.
        assert_eq!(auto.decode_in(b"caf\xE9.txt", 1252), "café.txt");
        assert_eq!(auto.decode_in("café.txt".as_bytes(), 65001), "café.txt");
        // Code page 0 is the system's ANSI page: 1252 here, 1251 on a Russian system.
        assert_eq!(auto.decode_in(b"caf\xE9.txt", 0), "café.txt");
        let ru = NameDecoding { ansi: 1251, ..auto };
        assert_eq!(ru.decode_in(b"\xCF\xF0\xE8", 0), "При");
        assert_eq!(ru.decode_in(b"caf\xE9", 1252), "café");
        // One BeeZip doesn't know reads as the system's page.
        assert_eq!(ru.decode_in(b"\xCF", 77_777), "П");
    }
}
