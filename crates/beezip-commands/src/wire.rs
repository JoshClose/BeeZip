//! Wire types shared by several commands. Core has no serde, so these are the stable shapes the
//! CLI, MCP and the GUI see, converted from core types (docs/M1.md §3.1, §4.2).
//!
//! Enums derive `clap::ValueEnum` and serde with the same names; a test checks they agree.

use std::fmt;

use beezip_core::{
    CodecId, Entry, EntryKind,
    format::{
        cab::CabMethod,
        sevenz::SevenZMethod,
        squashfs::SquashfsMethod,
        zip::{ZipEncryption, ZipMethod},
    },
    ops::ArchiveKind,
    safefs, time,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// What to do when a file to be written already exists.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum OverwritePolicy {
    /// Ask (in a terminal or the app); fail with `Conflict` when nobody can be asked.
    #[default]
    Ask,
    Always,
    Never,
    /// Write `name (1).ext` instead.
    Rename,
    /// Replace only if the entry is newer.
    Newer,
}

impl From<OverwritePolicy> for safefs::OverwritePolicy {
    fn from(p: OverwritePolicy) -> Self {
        match p {
            OverwritePolicy::Ask => Self::Ask,
            OverwritePolicy::Always => Self::Always,
            OverwritePolicy::Never => Self::Never,
            OverwritePolicy::Rename => Self::Rename,
            OverwritePolicy::Newer => Self::Newer,
        }
    }
}

/// The archive kinds `archive.create` writes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
pub enum ArchiveFormatName {
    #[serde(rename = "zip")]
    #[value(name = "zip")]
    Zip,
    #[serde(rename = "7z")]
    #[value(name = "7z")]
    SevenZ,
    #[serde(rename = "tar")]
    #[value(name = "tar")]
    Tar,
    #[serde(rename = "tar.gz")]
    #[value(name = "tar.gz")]
    TarGz,
    #[serde(rename = "tar.bz2")]
    #[value(name = "tar.bz2")]
    TarBz2,
    #[serde(rename = "tar.xz")]
    #[value(name = "tar.xz")]
    TarXz,
    #[serde(rename = "tar.lzma")]
    #[value(name = "tar.lzma")]
    TarLzma,
    #[serde(rename = "tar.lz")]
    #[value(name = "tar.lz")]
    TarLz,
    #[serde(rename = "tar.zst")]
    #[value(name = "tar.zst")]
    TarZst,
    #[serde(rename = "tar.lz4")]
    #[value(name = "tar.lz4")]
    TarLz4,
    #[serde(rename = "tar.br")]
    #[value(name = "tar.br")]
    TarBr,
    #[serde(rename = "tar.sz")]
    #[value(name = "tar.sz")]
    TarSz,
    #[serde(rename = "tar.Z")]
    #[value(name = "tar.Z")]
    TarZ,
    #[serde(rename = "tar.lzo")]
    #[value(name = "tar.lzo")]
    TarLzo,
    #[serde(rename = "cpio")]
    #[value(name = "cpio")]
    Cpio,
    #[serde(rename = "cpio.gz")]
    #[value(name = "cpio.gz")]
    CpioGz,
    #[serde(rename = "cpio.bz2")]
    #[value(name = "cpio.bz2")]
    CpioBz2,
    #[serde(rename = "cpio.xz")]
    #[value(name = "cpio.xz")]
    CpioXz,
    #[serde(rename = "cpio.lzma")]
    #[value(name = "cpio.lzma")]
    CpioLzma,
    #[serde(rename = "cpio.lz")]
    #[value(name = "cpio.lz")]
    CpioLz,
    #[serde(rename = "cpio.zst")]
    #[value(name = "cpio.zst")]
    CpioZst,
    #[serde(rename = "cpio.lz4")]
    #[value(name = "cpio.lz4")]
    CpioLz4,
    #[serde(rename = "cpio.br")]
    #[value(name = "cpio.br")]
    CpioBr,
    #[serde(rename = "cpio.sz")]
    #[value(name = "cpio.sz")]
    CpioSz,
    #[serde(rename = "cpio.Z")]
    #[value(name = "cpio.Z")]
    CpioZ,
    #[serde(rename = "cpio.lzo")]
    #[value(name = "cpio.lzo")]
    CpioLzo,
    #[serde(rename = "ar")]
    #[value(name = "ar")]
    Ar,
    #[serde(rename = "cab")]
    #[value(name = "cab")]
    Cab,
    #[serde(rename = "iso")]
    #[value(name = "iso")]
    Iso,
    #[serde(rename = "squashfs")]
    #[value(name = "squashfs")]
    Squashfs,
    #[serde(rename = "dmg")]
    #[value(name = "dmg")]
    Dmg,
}

impl ArchiveFormatName {
    pub fn kind(self) -> ArchiveKind {
        let tar = |c| ArchiveKind::Tar(Some(c));
        let cpio = |c| ArchiveKind::Cpio(Some(c));
        match self {
            Self::Zip => ArchiveKind::Zip,
            Self::SevenZ => ArchiveKind::SevenZ,
            Self::Tar => ArchiveKind::Tar(None),
            Self::TarGz => tar(CodecId::Gzip),
            Self::TarBz2 => tar(CodecId::Bzip2),
            Self::TarXz => tar(CodecId::Xz),
            Self::TarLzma => tar(CodecId::Lzma),
            Self::TarLz => tar(CodecId::Lzip),
            Self::TarZst => tar(CodecId::Zstd),
            Self::TarLz4 => tar(CodecId::Lz4),
            Self::TarBr => tar(CodecId::Brotli),
            Self::TarSz => tar(CodecId::Snappy),
            Self::TarZ => tar(CodecId::Compress),
            Self::TarLzo => tar(CodecId::Lzop),
            Self::Cpio => ArchiveKind::Cpio(None),
            Self::CpioGz => cpio(CodecId::Gzip),
            Self::CpioBz2 => cpio(CodecId::Bzip2),
            Self::CpioXz => cpio(CodecId::Xz),
            Self::CpioLzma => cpio(CodecId::Lzma),
            Self::CpioLz => cpio(CodecId::Lzip),
            Self::CpioZst => cpio(CodecId::Zstd),
            Self::CpioLz4 => cpio(CodecId::Lz4),
            Self::CpioBr => cpio(CodecId::Brotli),
            Self::CpioSz => cpio(CodecId::Snappy),
            Self::CpioZ => cpio(CodecId::Compress),
            Self::CpioLzo => cpio(CodecId::Lzop),
            Self::Ar => ArchiveKind::Ar,
            Self::Cab => ArchiveKind::Cab,
            Self::Iso => ArchiveKind::Iso,
            Self::Squashfs => ArchiveKind::Squashfs,
            Self::Dmg => ArchiveKind::Dmg,
        }
    }

    pub fn from_kind(kind: ArchiveKind) -> Self {
        <Self as clap::ValueEnum>::value_variants()
            .iter()
            .copied()
            .find(|v| v.kind() == kind)
            .unwrap_or(Self::Zip)
    }

    pub fn name(self) -> String {
        self.kind().name()
    }
}

/// A single-stream codec.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum CodecName {
    Gzip,
    Zlib,
    Deflate,
    Bzip2,
    Xz,
    Lzma,
    Lzip,
    Zstd,
    Lz4,
    Brotli,
    Snappy,
    /// Unix `compress` (`.Z`).
    Compress,
    Lzop,
}

impl CodecName {
    pub fn id(self) -> CodecId {
        match self {
            Self::Gzip => CodecId::Gzip,
            Self::Zlib => CodecId::Zlib,
            Self::Deflate => CodecId::Deflate,
            Self::Bzip2 => CodecId::Bzip2,
            Self::Xz => CodecId::Xz,
            Self::Lzma => CodecId::Lzma,
            Self::Lzip => CodecId::Lzip,
            Self::Zstd => CodecId::Zstd,
            Self::Lz4 => CodecId::Lz4,
            Self::Brotli => CodecId::Brotli,
            Self::Snappy => CodecId::Snappy,
            Self::Compress => CodecId::Compress,
            Self::Lzop => CodecId::Lzop,
        }
    }

    pub fn from_id(id: CodecId) -> Self {
        <Self as clap::ValueEnum>::value_variants()
            .iter()
            .copied()
            .find(|v| v.id() == id)
            .unwrap_or(Self::Zstd)
    }
}

/// A zip compression method BeeZip writes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum ZipMethodName {
    Store,
    Deflate,
    Bzip2,
    Zstd,
    Xz,
    Ppmd,
}

impl ZipMethodName {
    pub fn method(self) -> ZipMethod {
        match self {
            Self::Store => ZipMethod::Store,
            Self::Deflate => ZipMethod::Deflate,
            Self::Bzip2 => ZipMethod::Bzip2,
            Self::Zstd => ZipMethod::Zstd,
            Self::Xz => ZipMethod::Xz,
            Self::Ppmd => ZipMethod::Ppmd,
        }
    }
}

/// A 7z compression method BeeZip writes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum SevenZMethodName {
    Lzma2,
    Lzma,
    Ppmd,
    Bzip2,
    Deflate,
    Copy,
}

impl SevenZMethodName {
    pub fn method(self) -> SevenZMethod {
        match self {
            Self::Lzma2 => SevenZMethod::Lzma2,
            Self::Lzma => SevenZMethod::Lzma,
            Self::Ppmd => SevenZMethod::Ppmd,
            Self::Bzip2 => SevenZMethod::Bzip2,
            Self::Deflate => SevenZMethod::Deflate,
            Self::Copy => SevenZMethod::Copy,
        }
    }
}

/// A compression method for `archive.create`: zip's (`store`, `deflate`, `bzip2`, `zstd`,
/// `xz`, `ppmd`), 7z's (`lzma2`, `lzma`, `ppmd`, `bzip2`, `deflate`, `copy`), a cabinet's
/// (`store`, `mszip`) or a squashfs image's (`gzip`, `xz`, `zstd`, `lz4`, `lzo`). One flag takes
/// them all; [`MethodName::zip`], [`MethodName::sevenz`], [`MethodName::cab`] and
/// [`MethodName::squashfs`] say which a format accepts, so `store` can't reach a 7z.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum MethodName {
    Store,
    Deflate,
    Bzip2,
    Zstd,
    Xz,
    Ppmd,
    Lzma2,
    Lzma,
    Copy,
    Mszip,
    Gzip,
    Lz4,
    Lzo,
}

impl MethodName {
    pub fn zip(self) -> Option<ZipMethodName> {
        Some(match self {
            Self::Store => ZipMethodName::Store,
            Self::Deflate => ZipMethodName::Deflate,
            Self::Bzip2 => ZipMethodName::Bzip2,
            Self::Zstd => ZipMethodName::Zstd,
            Self::Xz => ZipMethodName::Xz,
            Self::Ppmd => ZipMethodName::Ppmd,
            Self::Lzma2
            | Self::Lzma
            | Self::Copy
            | Self::Mszip
            | Self::Gzip
            | Self::Lz4
            | Self::Lzo => return None,
        })
    }

    pub fn sevenz(self) -> Option<SevenZMethodName> {
        Some(match self {
            Self::Lzma2 => SevenZMethodName::Lzma2,
            Self::Lzma => SevenZMethodName::Lzma,
            Self::Ppmd => SevenZMethodName::Ppmd,
            Self::Bzip2 => SevenZMethodName::Bzip2,
            Self::Deflate => SevenZMethodName::Deflate,
            Self::Copy => SevenZMethodName::Copy,
            Self::Store
            | Self::Zstd
            | Self::Xz
            | Self::Mszip
            | Self::Gzip
            | Self::Lz4
            | Self::Lzo => return None,
        })
    }

    pub fn cab(self) -> Option<CabMethod> {
        match self {
            Self::Store => Some(CabMethod::Store),
            Self::Mszip => Some(CabMethod::Mszip),
            _ => None,
        }
    }

    pub fn squashfs(self) -> Option<SquashfsMethod> {
        match self {
            Self::Gzip => Some(SquashfsMethod::Gzip),
            Self::Xz => Some(SquashfsMethod::Xz),
            Self::Zstd => Some(SquashfsMethod::Zstd),
            Self::Lz4 => Some(SquashfsMethod::Lz4),
            Self::Lzo => Some(SquashfsMethod::Lzo),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Deflate => "deflate",
            Self::Bzip2 => "bzip2",
            Self::Zstd => "zstd",
            Self::Xz => "xz",
            Self::Ppmd => "ppmd",
            Self::Lzma2 => "lzma2",
            Self::Lzma => "lzma",
            Self::Copy => "copy",
            Self::Mszip => "mszip",
            Self::Gzip => "gzip",
            Self::Lz4 => "lz4",
            Self::Lzo => "lzo",
        }
    }
}

/// How a zip with a password is encrypted.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum EncryptionName {
    /// AES-256, the default.
    Aes256,
    /// The legacy scheme, for tools such as Windows Explorer that can't read AES. Weak.
    Zipcrypto,
}

impl EncryptionName {
    pub fn encryption(self) -> ZipEncryption {
        match self {
            Self::Aes256 => ZipEncryption::Aes256,
            Self::Zipcrypto => ZipEncryption::ZipCrypto,
        }
    }
}

/// How names stored as bytes are read (docs/M5.md §6): zip names without the UTF-8 flag, tar
/// names outside pax records, cpio, ar, LHA and squashfs names, CAB names without the UTF-8 flag, ISO names outside Joliet. `auto` reads them as UTF-8 when they are valid UTF-8, otherwise in
/// the system's code page (the OEM one for zip, as Explorer reads them). The others are code
/// pages: `cp932` is Japanese (Shift-JIS), `cp936` Simplified Chinese (GBK), `cp949` Korean,
/// `cp950` Traditional Chinese (Big5), `cp866` and `cp1251` Cyrillic, `cp437` and `cp850` DOS.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
pub enum NameEncoding {
    #[default]
    #[serde(rename = "auto")]
    #[value(name = "auto")]
    Auto,
    #[serde(rename = "utf-8")]
    #[value(name = "utf-8")]
    Utf8,
    #[serde(rename = "cp437")]
    #[value(name = "cp437")]
    Cp437,
    #[serde(rename = "cp850")]
    #[value(name = "cp850")]
    Cp850,
    #[serde(rename = "cp852")]
    #[value(name = "cp852")]
    Cp852,
    #[serde(rename = "cp866")]
    #[value(name = "cp866")]
    Cp866,
    #[serde(rename = "cp874")]
    #[value(name = "cp874")]
    Cp874,
    #[serde(rename = "cp932")]
    #[value(name = "cp932")]
    Cp932,
    #[serde(rename = "cp936")]
    #[value(name = "cp936")]
    Cp936,
    #[serde(rename = "cp949")]
    #[value(name = "cp949")]
    Cp949,
    #[serde(rename = "cp950")]
    #[value(name = "cp950")]
    Cp950,
    #[serde(rename = "cp1250")]
    #[value(name = "cp1250")]
    Cp1250,
    #[serde(rename = "cp1251")]
    #[value(name = "cp1251")]
    Cp1251,
    #[serde(rename = "cp1252")]
    #[value(name = "cp1252")]
    Cp1252,
    #[serde(rename = "cp1253")]
    #[value(name = "cp1253")]
    Cp1253,
    #[serde(rename = "cp1254")]
    #[value(name = "cp1254")]
    Cp1254,
    #[serde(rename = "cp1255")]
    #[value(name = "cp1255")]
    Cp1255,
    #[serde(rename = "cp1256")]
    #[value(name = "cp1256")]
    Cp1256,
    #[serde(rename = "cp1257")]
    #[value(name = "cp1257")]
    Cp1257,
    #[serde(rename = "cp1258")]
    #[value(name = "cp1258")]
    Cp1258,
    #[serde(rename = "koi8-r")]
    #[value(name = "koi8-r")]
    Koi8R,
    #[serde(rename = "koi8-u")]
    #[value(name = "koi8-u")]
    Koi8U,
    #[serde(rename = "iso-8859-1")]
    #[value(name = "iso-8859-1")]
    Iso8859_1,
    #[serde(rename = "iso-8859-2")]
    #[value(name = "iso-8859-2")]
    Iso8859_2,
    #[serde(rename = "iso-8859-5")]
    #[value(name = "iso-8859-5")]
    Iso8859_5,
    #[serde(rename = "iso-8859-7")]
    #[value(name = "iso-8859-7")]
    Iso8859_7,
    #[serde(rename = "euc-jp")]
    #[value(name = "euc-jp")]
    EucJp,
    #[serde(rename = "gb18030")]
    #[value(name = "gb18030")]
    Gb18030,
}

impl From<NameEncoding> for beezip_core::NameEncoding {
    fn from(e: NameEncoding) -> Self {
        match e {
            NameEncoding::Auto => Self::Auto,
            NameEncoding::Utf8 => Self::Utf8,
            NameEncoding::Cp437 => Self::Cp437,
            NameEncoding::Cp850 => Self::Cp850,
            NameEncoding::Cp852 => Self::Cp852,
            NameEncoding::Cp866 => Self::Cp866,
            NameEncoding::Cp874 => Self::Cp874,
            NameEncoding::Cp932 => Self::Cp932,
            NameEncoding::Cp936 => Self::Cp936,
            NameEncoding::Cp949 => Self::Cp949,
            NameEncoding::Cp950 => Self::Cp950,
            NameEncoding::Cp1250 => Self::Cp1250,
            NameEncoding::Cp1251 => Self::Cp1251,
            NameEncoding::Cp1252 => Self::Cp1252,
            NameEncoding::Cp1253 => Self::Cp1253,
            NameEncoding::Cp1254 => Self::Cp1254,
            NameEncoding::Cp1255 => Self::Cp1255,
            NameEncoding::Cp1256 => Self::Cp1256,
            NameEncoding::Cp1257 => Self::Cp1257,
            NameEncoding::Cp1258 => Self::Cp1258,
            NameEncoding::Koi8R => Self::Koi8R,
            NameEncoding::Koi8U => Self::Koi8U,
            NameEncoding::Iso8859_1 => Self::Iso8859_1,
            NameEncoding::Iso8859_2 => Self::Iso8859_2,
            NameEncoding::Iso8859_5 => Self::Iso8859_5,
            NameEncoding::Iso8859_7 => Self::Iso8859_7,
            NameEncoding::EucJp => Self::EucJp,
            NameEncoding::Gb18030 => Self::Gb18030,
        }
    }
}

/// How `entry.read` returns data.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
    TS,
    clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum TextEncoding {
    /// UTF-8, with invalid bytes replaced (and `lossy` set).
    #[default]
    Text,
    Hex,
    Base64,
}

/// A size in bytes: a number, or a string with a unit such as `100m`, `4g` or `700MB`. The
/// units are powers of 1024, as with 7-Zip's `-v`: `k`, `m`, `g` and `t`, with or without `b`
/// or `ib`. A string is kept as written, so it reads back the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, TS)]
#[serde(untagged)]
pub enum ByteSize {
    Bytes(u64),
    Text(String),
}

impl ByteSize {
    pub fn bytes(&self) -> u64 {
        match self {
            Self::Bytes(n) => *n,
            // Checked when it was parsed.
            Self::Text(s) => parse_size(s).unwrap_or(0),
        }
    }
}

/// `100m` → 104 857 600. `None` for anything that isn't a size.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let shift = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        "t" | "tb" | "tib" => 40,
        _ => return None,
    };
    if num.is_empty() || num.matches('.').count() > 1 {
        return None;
    }
    if !num.contains('.') {
        return num.parse::<u64>().ok()?.checked_mul(1u64 << shift);
    }
    let v: f64 = num.parse().ok()?;
    let bytes = (v * (1u64 << shift) as f64).round();
    (bytes.is_finite() && bytes >= 0.0 && bytes < u64::MAX as f64).then_some(bytes as u64)
}

impl std::str::FromStr for ByteSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(n) = s.parse::<u64>() {
            return Ok(Self::Bytes(n));
        }
        match parse_size(s) {
            Some(_) => Ok(Self::Text(s.to_owned())),
            None => Err(format!(
                "`{s}` isn't a size; use bytes or a unit such as 100m, 4g or 700MB"
            )),
        }
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = ByteSize;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a number of bytes, or a size such as \"100m\"")
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<ByteSize, E> {
                Ok(ByteSize::Bytes(n))
            }
            fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<ByteSize, E> {
                u64::try_from(n)
                    .map(ByteSize::Bytes)
                    .map_err(|_| E::custom("a size can't be negative"))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<ByteSize, E> {
                match parse_size(s) {
                    Some(_) => Ok(ByteSize::Text(s.to_owned())),
                    None => Err(E::custom(format!(
                        "`{s}` isn't a size; use bytes or a unit such as 100m, 4g or 700MB"
                    ))),
                }
            }
        }
        d.deserialize_any(V)
    }
}

/// A password. A plain string on the wire; `Debug` prints `***`, so it never reaches a log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::str::FromStr for Secret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKindName {
    File,
    Dir,
    Symlink,
    Hardlink,
    Other,
}

/// One entry, as `archive.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EntryInfo {
    /// Index in archive order, for `entry.read --index`. `None` for a folder that has no entry
    /// of its own but holds entries.
    pub id: Option<u64>,
    /// `/`-separated, as stored.
    pub path: String,
    pub kind: EntryKindName,
    pub size: Option<u64>,
    pub packed_size: Option<u64>,
    /// RFC 3339, UTC.
    pub modified: Option<String>,
    pub crc32: Option<u32>,
    pub method: Option<String>,
    pub encrypted: bool,
    /// A link's target.
    pub target: Option<String>,
}

impl EntryInfo {
    pub fn from_entry(e: &Entry) -> Self {
        let (kind, target) = match &e.kind {
            EntryKind::File => (EntryKindName::File, None),
            EntryKind::Dir => (EntryKindName::Dir, None),
            EntryKind::Symlink { target } => (EntryKindName::Symlink, Some(target.clone())),
            EntryKind::Hardlink { target } => (EntryKindName::Hardlink, Some(target.clone())),
            EntryKind::Other => (EntryKindName::Other, None),
        };
        Self {
            id: Some(e.id as u64),
            path: e.path.clone(),
            kind,
            size: e.size,
            packed_size: e.packed_size,
            modified: e.modified.map(time::rfc3339),
            crc32: e.crc32,
            method: e.method.as_deref().map(str::to_owned),
            encrypted: e.encrypted,
            target,
        }
    }

    /// A folder implied by the paths under it.
    pub fn implied_dir(path: String) -> Self {
        Self {
            id: None,
            path,
            kind: EntryKindName::Dir,
            size: None,
            packed_size: None,
            modified: None,
            crc32: None,
            method: None,
            encrypted: false,
            target: None,
        }
    }
}

/// Size as people read it: `1.5 MiB`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

/// `out / in`, the share of the original that remains: 0.25 means a quarter of the size.
pub fn ratio(bytes_in: u64, bytes_out: u64) -> f64 {
    if bytes_in == 0 {
        1.0
    } else {
        bytes_out as f64 / bytes_in as f64
    }
}

/// An RFC 3339 UTC time as local time for people: `2026-11-02 08:03`.
pub fn local_time(rfc3339: &str) -> String {
    use ::time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
    let Ok(t) = OffsetDateTime::parse(rfc3339, &Rfc3339) else {
        return rfc3339.to_owned();
    };
    let offset = UtcOffset::local_offset_at(t).unwrap_or(UtcOffset::UTC);
    let t = t.to_offset(offset);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use clap::ValueEnum;

    use super::*;

    /// Every variant's clap name is its serde name.
    pub(crate) fn names_agree<T: ValueEnum + Serialize>() {
        for v in T::value_variants() {
            let clap = v.to_possible_value().unwrap().get_name().to_owned();
            let serde = serde_json::to_value(v).unwrap();
            assert_eq!(serde.as_str(), Some(clap.as_str()));
        }
    }

    #[test]
    fn enum_names_agree() {
        names_agree::<OverwritePolicy>();
        names_agree::<ArchiveFormatName>();
        names_agree::<CodecName>();
        names_agree::<ZipMethodName>();
        names_agree::<SevenZMethodName>();
        names_agree::<MethodName>();
        for m in <MethodName as clap::ValueEnum>::value_variants() {
            assert_eq!(serde_json::to_value(m).unwrap(), m.name());
            let zip = m.zip().map(|z| serde_json::to_value(z).unwrap());
            let sz = m.sevenz().map(|s| serde_json::to_value(s).unwrap());
            let cab = m.cab().map(|c| serde_json::Value::from(c.name()));
            let sq = m.squashfs().map(|c| serde_json::Value::from(c.name()));
            assert!(zip.is_some() || sz.is_some() || cab.is_some() || sq.is_some());
            for v in zip.into_iter().chain(sz).chain(cab).chain(sq) {
                assert_eq!(v, m.name());
            }
        }
        names_agree::<EncryptionName>();
        names_agree::<NameEncoding>();
        for e in <NameEncoding as clap::ValueEnum>::value_variants() {
            let core = beezip_core::NameEncoding::from(*e);
            assert_eq!(serde_json::to_value(e).unwrap(), core.name());
        }
        names_agree::<TextEncoding>();
    }

    #[test]
    fn archive_format_names_match_core() {
        for v in ArchiveFormatName::value_variants() {
            assert_eq!(serde_json::to_value(v).unwrap(), v.name());
            assert_eq!(ArchiveFormatName::from_kind(v.kind()), *v);
        }
        assert_eq!(
            ArchiveFormatName::value_variants().len(),
            ArchiveKind::all().count()
        );
        for c in CodecName::value_variants() {
            assert_eq!(serde_json::to_value(c).unwrap(), c.id().name());
        }
    }

    #[test]
    fn secrets_stay_out_of_debug() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "***");
        assert_eq!(serde_json::to_value(&s).unwrap(), "hunter2");
    }

    #[test]
    fn byte_sizes() {
        assert_eq!(parse_size("100m"), Some(100 << 20));
        assert_eq!(parse_size("4g"), Some(4 << 30));
        assert_eq!(parse_size("700MB"), Some(700 << 20));
        assert_eq!(parse_size("1.5KiB"), Some(1536));
        assert_eq!(parse_size("12345"), Some(12345));
        assert_eq!(parse_size(" 2 k "), Some(2048));
        for bad in ["", "m", "1.2.3m", "10x", "-1", "99999999999t"] {
            assert_eq!(parse_size(bad), None, "{bad}");
        }
        let from_json: ByteSize = serde_json::from_value(serde_json::json!("100m")).unwrap();
        assert_eq!(from_json.bytes(), 100 << 20);
        assert_eq!(serde_json::to_value(&from_json).unwrap(), "100m");
        let n: ByteSize = serde_json::from_value(serde_json::json!(4096)).unwrap();
        assert_eq!(n, ByteSize::Bytes(4096));
        assert!(serde_json::from_value::<ByteSize>(serde_json::json!("lots")).is_err());
        assert!(serde_json::from_value::<ByteSize>(serde_json::json!(-5)).is_err());
        assert_eq!("2048".parse::<ByteSize>(), Ok(ByteSize::Bytes(2048)));
        assert!("2q".parse::<ByteSize>().is_err());
    }

    #[test]
    fn sizes_and_ratios() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert!((ratio(200, 50) - 0.25).abs() < 1e-9);
    }
}
