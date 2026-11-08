//! `7z l -slt` and 7-Zip's messages, read (docs/M6.md §3.3).
//!
//! **The listing** (7-Zip 25.01 to 26.00, with `-sccUTF-8 -slmu -slsl`): a banner, then a `--`
//! block per archive level, the outermost first: `Path`, `Type`, the level's errors (an
//! `ERRORS:` or `WARNINGS:` group of flags, `ERROR = …`, `WARNING = …`), `Physical Size`, then
//! the handler's own keys. Between two levels a `----` block describes the item of the outer
//! level that the inner one opens. A line of ten dashes starts the entries of the innermost
//! level, a block each, ended by a blank line; `Warnings: N` and `Errors: N` close the listing.
//!
//! - **Values on several lines.** In level and `----` blocks, a value with a line break in it
//!   (a VMDK's descriptor, a zip's comment, a GPT partition's name) is printed as `Key = `, a
//!   line `{`, its lines as they are, blank ones too, and a line `}`. 7-Zip escapes nothing in
//!   it, so a `}` ends the value only when the next line can follow one (a separator, a blank
//!   line, a key the block doesn't have yet): a PE's nested data directories and a comment's own
//!   braces stay in the value, and nothing else in it is read as structure.
//! - **Entries.** Each handler prints a fixed set of keys on every entry, even empty ones; the
//!   parser learns them from the first entry. 7-Zip turns a `\n` in an entry's value into `_`,
//!   so a name can't start a line, but `\r`, tabs and escapes come through (HFS+ names a folder
//!   `.HFS+ Private Directory Data\r`): lines are split on `\n` only, and lose one `\r` when
//!   7-Zip ends its lines with `\r\n`, as it does on Windows.
//! - **What text in an archive can't do.** After the first entry only its keys start a field,
//!   and a key already in the block doesn't start another, so text inside a value can't forge a
//!   field. A level's comment with a line `}` followed by a separator or a new key can still
//!   imitate the listing: it can add levels after the real first one, and if it imitates
//!   entries, the real `----------` or a real level after them gives it away and the listing is
//!   refused as `Corrupt`.
//! - **Bounds.** A line, a value, a block's keys, the levels and their text, the messages and
//!   the names kept are capped, and entries count against `max_entries` as they come. The
//!   parser reads as 7-Zip writes and holds one block of text at a time: install.esd's 473 MB
//!   listing of 904 344 entries keeps only the entries.

use std::{
    borrow::Cow,
    collections::HashSet,
    io::{BufRead, Read},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    Ctx, Error, ErrorKind, Limits, NameDecoding, Result,
    format::{Entry, EntryKind},
    names::SystemPage,
};

/// The longest line read.
const MAX_LINE: usize = 1 << 20;
/// The longest value, with the lines it runs on to (a VMDK's descriptor).
const MAX_VALUE: usize = 1 << 20;
/// Keys in one block. 7-Zip's handlers print fewer than 40.
const MAX_KEYS: usize = 256;
/// Archive levels. 7-Zip opens a few inside each other (VHDX > GPT > NTFS).
const MAX_LEVELS: usize = 64;
/// The text of every level and `----` block and message in a listing, together.
const MAX_HEADERS: usize = 16 << 20;
/// The entries' names and link targets, together. A listing repeats a folder's name in every
/// path under it, so a small image with a deep tree can list far more text than it holds.
const MAX_NAMES: usize = 1 << 30;
/// Lines read between checks for cancellation.
const CHECK_EVERY: u64 = 1024;

/// One archive level's properties (`Path`, `Type`, `Physical Size`, the handler's own keys).
/// Each key comes once; a value on several lines keeps its line breaks (`\n`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Level {
    pub props: Vec<(String, String)>,
}

impl Level {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.props
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// 7-Zip's name for the level's format (`Type`).
    pub fn type_name(&self) -> &str {
        self.get("Type").unwrap_or("")
    }
}

/// An entry as 7-Zip listed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub entry: Entry,
    /// The path exactly as 7-Zip printed it, when `entry.path` differs (a name decoded from
    /// bytes that weren't UTF-8, a CramFS name 7-Zip decoded from the OEM code page): what
    /// selects it on 7-Zip's command line.
    pub listed: Option<Box<str>>,
}

impl Item {
    /// The path as 7-Zip printed it.
    pub fn listed(&self) -> &str {
        self.listed.as_deref().unwrap_or(&self.entry.path)
    }
}

/// A whole listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// The outermost first.
    pub levels: Vec<Level>,
    pub items: Vec<Item>,
    /// What the listing itself says went wrong: an `ERRORS:` group's flags (`Headers Error`,
    /// `Unexpected end of archive`), `ERROR = …`, `ERROR: …` and `Open ERROR: …` lines.
    pub errors: Vec<String>,
    /// The same for warnings (`There are data after the end of archive`, `Checksum error`).
    pub warnings: Vec<String>,
}

impl Listing {
    /// The listing's own errors and warnings, to weigh with what 7-Zip said on stderr
    /// ([`Messages::extend`]).
    pub fn messages(&self) -> Messages {
        Messages {
            errors: self.errors.clone(),
            warnings: self.warnings.clone(),
            entries: Vec::new(),
        }
    }
}

/// Reads a listing as 7-Zip writes it, counting entries against `max_entries` as they come and
/// checking `cx` for cancellation.
pub fn parse(
    out: &mut dyn BufRead,
    names: &NameDecoding,
    limits: &Limits,
    cx: &mut dyn Ctx,
) -> Result<Listing> {
    let mut p = Parser::new(names, limits);
    let mut buf = Vec::new();
    let mut lines = 0u64;
    loop {
        buf.clear();
        let n = Read::take(&mut *out, MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(|e| Error::io("reading 7-Zip's listing", &e))?;
        if n == 0 {
            break;
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        } else if buf.len() > MAX_LINE {
            return Err(Error::corrupt(
                "7-Zip's listing has a line longer than 1 MiB",
            ));
        }
        // 7-Zip's first line is blank: whether it ends in `\r\n` says how they all end.
        if *p.crlf.get_or_insert(buf.last() == Some(&b'\r')) && buf.last() == Some(&b'\r') {
            buf.pop();
        }
        lines += 1;
        if lines.is_multiple_of(CHECK_EVERY) {
            cx.check()?;
        }
        p.line(&String::from_utf8_lossy(&buf))?;
    }
    p.finish()
}

/// Which part of the listing a line is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    /// Before the first `--`: the banner, `Listing archive:`, and why it didn't open.
    Banner,
    Level,
    /// A `----` block: the outer level's item that the next level opens.
    Parent,
    Entries,
}

/// Where a line that goes on from the one before it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Open {
    /// Nowhere: it's dropped.
    Nothing,
    /// The block's last value.
    Value,
    /// An `ERROR = ` (`true`) or `WARNING = ` message.
    Message(bool),
}

/// The entry being read: each key once, the values one after another in `text`.
#[derive(Debug, Default)]
struct EntryBlock {
    /// A key's index in [`Parser::keys`], and where its value starts in `text`.
    fields: Vec<(u16, usize)>,
    text: String,
}

impl EntryBlock {
    fn get(&self, key: Option<u16>) -> Option<&str> {
        let key = key?;
        let n = self.fields.iter().position(|&(k, _)| k == key)?;
        let end = self.fields.get(n + 1).map_or(self.text.len(), |f| f.1);
        self.text.get(self.fields[n].1..end)
    }

    fn clear(&mut self) {
        self.fields.clear();
        self.text.clear();
    }
}

/// Where the keys an entry is built from are in the entries' keys.
#[derive(Debug, Default, Clone, Copy)]
struct Known {
    path: Option<u16>,
    folder: Option<u16>,
    size: Option<u16>,
    packed: Option<u16>,
    modified: Option<u16>,
    crc: Option<u16>,
    encrypted: Option<u16>,
    method: Option<u16>,
    attributes: Option<u16>,
    mode: Option<u16>,
    symlink: Option<u16>,
    link: Option<u16>,
    hard_link: Option<u16>,
    block: Option<u16>,
    /// The innermost level is a CHM, whose folders have neither a flag nor a mode.
    chm: bool,
    /// The innermost level is a CramFS and 7-Zip is 7-Zip for Windows, which decodes its names
    /// from the OEM code page (7zz decodes them from the locale's, UTF-8).
    oem_names: bool,
}

impl Known {
    fn new(keys: &[Box<str>], innermost: Option<&Level>, windows: bool) -> Self {
        let find = |name: &str| keys.iter().position(|k| &**k == name).map(|n| n as u16);
        Self {
            path: find("Path"),
            folder: find("Folder"),
            size: find("Size"),
            packed: find("Packed Size"),
            modified: find("Modified"),
            crc: find("CRC"),
            encrypted: find("Encrypted"),
            method: find("Method"),
            attributes: find("Attributes"),
            mode: find("Mode"),
            symlink: find("Symbolic Link"),
            link: find("Link"),
            hard_link: find("Hard Link"),
            block: find("Block"),
            chm: innermost.is_some_and(|l| l.type_name().eq_ignore_ascii_case("Chm")),
            oem_names: windows
                && innermost.is_some_and(|l| l.type_name().eq_ignore_ascii_case("CramFS")),
        }
    }
}

struct Parser<'a> {
    names: &'a NameDecoding,
    limits: &'a Limits,
    /// Whether 7-Zip ends its lines with `\r\n`, as 7-Zip for Windows does; set by the first.
    crlf: Option<bool>,
    listing: Listing,
    section: Section,
    /// The level or `----` block being read.
    props: Vec<(String, String)>,
    entry: EntryBlock,
    /// The entries' keys, in the first entry's order.
    keys: Vec<Box<str>>,
    /// Set when the first entry ends; from then on only `keys` start a field.
    known: Option<Known>,
    open: Open,
    /// The message being read, while `open` is [`Open::Message`].
    message: String,
    /// In an `ERRORS:` (`true`) or `WARNINGS:` group of flags.
    group: Option<bool>,
    /// The open value is empty, so a line `{` starts it on the lines after.
    may_brace: bool,
    /// In a value on several lines, between its `{` and `}`.
    braced: bool,
    /// The value on several lines has had a line.
    started: bool,
    /// The last line was a `}`: the value's end if the next line can follow a value.
    closing: bool,
    /// The text kept from level blocks and messages.
    headers: usize,
    /// The text kept in entries' names and link targets.
    name_bytes: usize,
}

impl<'a> Parser<'a> {
    fn new(names: &'a NameDecoding, limits: &'a Limits) -> Self {
        Self {
            names,
            limits,
            crlf: None,
            listing: Listing::default(),
            section: Section::Banner,
            props: Vec::new(),
            entry: EntryBlock::default(),
            keys: Vec::new(),
            known: None,
            open: Open::Nothing,
            message: String::new(),
            group: None,
            may_brace: false,
            braced: false,
            started: false,
            closing: false,
            headers: 0,
            name_bytes: 0,
        }
    }

    fn line(&mut self, line: &str) -> Result<()> {
        if self.braced {
            if !std::mem::take(&mut self.closing) {
                return self.braced_line(line);
            }
            if !self.ends_value(line) {
                // The `}` was the value's own.
                self.braced_text("}")?;
                return self.braced_line(line);
            }
            self.braced = false;
        }
        if std::mem::take(&mut self.may_brace) && line == "{" {
            self.braced = true;
            self.started = false;
            return Ok(());
        }
        match line {
            "--" | "----" | "----------" => return self.separator(line.len()),
            "" => {
                self.end_message();
                self.group = None;
                self.open = Open::Nothing;
                if self.section == Section::Entries {
                    self.end_entry()?;
                }
                return Ok(());
            }
            "ERRORS:" | "WARNINGS:" => {
                self.end_message();
                self.group = Some(line == "ERRORS:");
                self.open = Open::Nothing;
                return Ok(());
            }
            _ => {}
        }
        if let Some((error, msg)) = message_line(line) {
            self.end_message();
            self.open = Open::Nothing;
            return self.say(error, msg);
        }
        let kv = key_value(line);
        if let Some(error) = self.group {
            // A group holds flags; the next `key = value` line ends it.
            if kv.is_none() {
                self.end_message();
                return self.say(error, line);
            }
            self.group = None;
        }
        match kv {
            Some((key, value)) => self.property(line, key, value),
            None => self.append(line, true),
        }
    }

    /// A line of a value on several lines. A `}` waits for the next line to say whether it ends
    /// the value: braces in it nest (a PE's data directories), and a comment can hold any line.
    fn braced_line(&mut self, line: &str) -> Result<()> {
        if line == "}" {
            self.closing = true;
            return Ok(());
        }
        self.braced_text(line)
    }

    fn braced_text(&mut self, line: &str) -> Result<()> {
        let newline = std::mem::replace(&mut self.started, true);
        self.append(line, newline)
    }

    /// Whether `line` can come after a value on several lines: what starts a field or a block
    /// in the block the value is in, or ends that block.
    fn ends_value(&self, line: &str) -> bool {
        match line {
            "" | "--" | "----" | "----------" | "ERRORS:" | "WARNINGS:" => true,
            _ => key_value(line).is_some_and(|(key, _)| {
                key == "ERROR"
                    || key == "WARNING"
                    || key_like(key) && !self.props.iter().any(|(k, _)| k == key)
            }),
        }
    }

    fn separator(&mut self, dashes: usize) -> Result<()> {
        self.end_message();
        self.end_block()?;
        self.group = None;
        self.open = Open::Nothing;
        if self.section == Section::Entries {
            // 7-Zip prints every level before the entries: text in a value imitated them.
            return Err(Error::corrupt(
                "7-Zip's listing goes on after its entries, so a comment in the archive \
                 imitated it",
            ));
        }
        self.section = match dashes {
            2 => Section::Level,
            4 => Section::Parent,
            _ => Section::Entries,
        };
        Ok(())
    }

    /// A `key = value` line: a new field, or a line that goes on from the last one.
    fn property(&mut self, line: &str, key: &str, value: &str) -> Result<()> {
        let between_entries = self.section != Section::Entries || self.entry.fields.is_empty();
        if between_entries && (key == "ERROR" || key == "WARNING") {
            self.end_message();
            self.count_headers(value.len())?;
            self.message.clear();
            self.message.push_str(value);
            self.open = Open::Message(key == "ERROR");
            self.may_brace = value.is_empty();
            return Ok(());
        }
        match self.section {
            Section::Banner => self.append(line, true),
            Section::Level | Section::Parent => {
                if !key_like(key) || self.props.iter().any(|(k, _)| k == key) {
                    return self.append(line, true);
                }
                if self.props.len() >= MAX_KEYS {
                    return Err(Error::corrupt(format!(
                        "a level in 7-Zip's listing has more than {MAX_KEYS} properties"
                    )));
                }
                self.end_message();
                self.count_headers(key.len() + value.len())?;
                self.props.push((key.to_owned(), value.to_owned()));
                self.open = Open::Value;
                self.may_brace = value.is_empty();
                Ok(())
            }
            Section::Entries => self.entry_field(line, key, value),
        }
    }

    fn entry_field(&mut self, line: &str, key: &str, value: &str) -> Result<()> {
        let at = self.keys.iter().position(|k| &**k == key);
        let new = match at {
            Some(n) => !self.entry.fields.iter().any(|f| usize::from(f.0) == n),
            // Only the first entry adds keys.
            None => self.known.is_none() && key_like(key),
        };
        if !new {
            return self.append(line, true);
        }
        let at = match at {
            Some(n) => n,
            None if self.keys.len() >= MAX_KEYS => {
                return Err(Error::corrupt(format!(
                    "the entries in 7-Zip's listing have more than {MAX_KEYS} properties"
                )));
            }
            None => {
                self.keys.push(key.into());
                self.keys.len() - 1
            }
        };
        self.end_message();
        self.entry.fields.push((at as u16, self.entry.text.len()));
        self.entry.text.push_str(value);
        self.open = Open::Value;
        Ok(())
    }

    /// Adds `text` to the open value, on a new line when `newline`.
    fn append(&mut self, text: &str, newline: bool) -> Result<()> {
        let extra = text.len() + usize::from(newline);
        let len = match self.open {
            Open::Nothing => return Ok(()),
            Open::Message(_) => self.message.len(),
            Open::Value => match self.section {
                Section::Entries => {
                    let start = self.entry.fields.last().map_or(0, |f| f.1);
                    self.entry.text.len() - start
                }
                _ => self.props.last().map_or(0, |(_, v)| v.len()),
            },
        };
        if len + extra > MAX_VALUE {
            return Err(Error::corrupt(
                "7-Zip's listing has a value longer than 1 MiB",
            ));
        }
        let to = match (self.open, self.section) {
            (Open::Message(_), _) => &mut self.message,
            (_, Section::Entries) => &mut self.entry.text,
            _ => match self.props.last_mut() {
                Some((_, v)) => v,
                None => return Ok(()),
            },
        };
        if newline {
            to.push('\n');
        }
        to.push_str(text);
        if self.section != Section::Entries || matches!(self.open, Open::Message(_)) {
            self.count_headers(extra)?;
        }
        Ok(())
    }

    /// Ends an `ERROR = ` or `WARNING = ` message, if one is open.
    fn end_message(&mut self) {
        if let Open::Message(error) = self.open {
            self.open = Open::Nothing;
            let msg = std::mem::take(&mut self.message);
            let list = if error {
                &mut self.listing.errors
            } else {
                &mut self.listing.warnings
            };
            list.push(msg);
        }
    }

    /// A message that is a whole line.
    fn say(&mut self, error: bool, msg: &str) -> Result<()> {
        self.count_headers(msg.len())?;
        let list = if error {
            &mut self.listing.errors
        } else {
            &mut self.listing.warnings
        };
        list.push(msg.to_owned());
        Ok(())
    }

    fn count_headers(&mut self, n: usize) -> Result<()> {
        self.headers += n;
        if self.headers > MAX_HEADERS {
            return Err(Error::corrupt(
                "7-Zip's listing has more than 16 MiB of levels and messages",
            ));
        }
        Ok(())
    }

    fn end_block(&mut self) -> Result<()> {
        match self.section {
            Section::Level if !self.props.is_empty() => {
                if self.listing.levels.len() >= MAX_LEVELS {
                    return Err(Error::corrupt(format!(
                        "7-Zip's listing has more than {MAX_LEVELS} levels"
                    )));
                }
                let props = std::mem::take(&mut self.props);
                self.listing.levels.push(Level { props });
            }
            Section::Entries => self.end_entry()?,
            _ => self.props.clear(),
        }
        Ok(())
    }

    fn end_entry(&mut self) -> Result<()> {
        if self.entry.fields.is_empty() {
            return Ok(());
        }
        let known = match self.known {
            Some(k) => k,
            None => *self.known.insert(Known::new(
                &self.keys,
                self.listing.levels.last(),
                self.crlf == Some(true),
            )),
        };
        let id = self.listing.items.len();
        self.limits.check_entries(id as u64 + 1)?;
        let item = item(id, &self.entry, &known, self.names);
        self.entry.clear();
        self.name_bytes += item_text(&item);
        if self.name_bytes > MAX_NAMES {
            return Err(Error::limit("7-Zip's listing has more than 1 GiB of names"));
        }
        self.listing.items.push(item);
        Ok(())
    }

    fn finish(mut self) -> Result<Listing> {
        if self.braced && !self.closing {
            return Err(Error::corrupt(
                "7-Zip's listing ends inside a value on several lines",
            ));
        }
        self.end_message();
        self.end_block()?;
        if let Some(k) = self.known
            && k.folder.is_none()
            && k.mode.is_none()
        {
            folders_by_children(&mut self.listing.items);
        }
        Ok(self.listing)
    }
}

/// A plausible key: what 7-Zip prints before ` = `.
fn key_like(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 48
        && k.starts_with(|c: char| c.is_ascii_alphanumeric())
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_.()/+:".contains(c))
}

/// `key = value`; 7-Zip prints `key = ` for an empty value.
fn key_value(line: &str) -> Option<(&str, &str)> {
    line.split_once(" = ")
        .or_else(|| line.strip_suffix(" =").map(|k| (k, "")))
}

/// A message on a line of its own: whether it's an error, and what it says.
fn message_line(line: &str) -> Option<(bool, &str)> {
    if let Some(m) = line
        .strip_prefix("ERROR: ")
        .or_else(|| line.strip_prefix("Open ERROR: "))
    {
        Some((true, m))
    } else if let Some(m) = line
        .strip_prefix("WARNING: ")
        .or_else(|| line.strip_prefix("Open WARNING: "))
    {
        Some((false, m))
    } else if line.starts_with("Warning: ") {
        // `Warning: The archive is open with offset`.
        Some((false, line))
    } else {
        None
    }
}

/// The bytes of an entry's text that stay in memory.
fn item_text(i: &Item) -> usize {
    let target = match &i.entry.kind {
        EntryKind::Symlink { target } | EntryKind::Hardlink { target } => target.len(),
        _ => 0,
    };
    i.entry.path.len() + i.entry.raw_path.len() + target + i.listed.as_ref().map_or(0, |l| l.len())
}

/// When there's neither a `Folder` nor a `Mode` key (partitions, NSIS, a CHM read in
/// low-level mode), a 0-byte entry with something under it is a folder.
fn folders_by_children(items: &mut [Item]) {
    let mut parents: HashSet<&str> = HashSet::new();
    for i in items.iter() {
        let mut p = i.entry.path.as_str();
        while let Some(at) = p.rfind('/') {
            p = &p[..at];
            if !parents.insert(p) {
                break;
            }
        }
    }
    let folders: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, i)| {
            i.entry.kind == EntryKind::File
                && i.entry.size.unwrap_or(0) == 0
                && parents.contains(i.entry.path.trim_end_matches('/'))
        })
        .map(|(n, _)| n)
        .collect();
    for n in folders {
        items[n].entry.kind = EntryKind::Dir;
    }
}

/// An entry from its properties.
fn item(id: usize, b: &EntryBlock, k: &Known, names: &NameDecoding) -> Item {
    let listed = b.get(k.path).unwrap_or("");
    let attrs = b
        .get(k.attributes)
        .map(Attributes::parse)
        .unwrap_or_default();
    let mode = b
        .get(k.mode)
        .and_then(|m| parse_mode(m.split(' ').next().unwrap_or("")))
        .or(attrs.mode);
    let file_type = mode.map(|m| m & 0o170000);
    let size = b.get(k.size).and_then(|v| v.trim().parse::<u64>().ok());
    let method = b.get(k.method).filter(|m| !m.is_empty());
    let folder = match b.get(k.folder) {
        Some(f) => f == "+",
        None => {
            file_type == Some(0o040000)
                || attrs.dos.is_some_and(|a| a & 0x10 != 0)
                // ChmHandler names no method and no block for a folder.
                || k.chm
                    && size == Some(0)
                    && method.is_none()
                    && b.get(k.block).is_some_and(str::is_empty)
        }
    };
    let target = |key: Option<u16>| b.get(key).filter(|t| !t.is_empty());
    let kind = if let Some(t) = target(k.hard_link) {
        EntryKind::Hardlink {
            target: decode(t, names).replace('\\', "/"),
        }
    } else if let Some(t) = target(k.symlink).or_else(|| target(k.link)) {
        EntryKind::Symlink {
            target: decode(t, names).into_owned(),
        }
    } else if file_type == Some(0o120000) {
        EntryKind::Symlink {
            target: String::new(),
        }
    } else if folder {
        EntryKind::Dir
    } else if matches!(file_type, Some(0o020000 | 0o060000 | 0o010000 | 0o140000)) {
        EntryKind::Other
    } else {
        EntryKind::File
    };

    let raw = match unmap(listed) {
        Some(raw) => Some((raw, SystemPage::Ansi)),
        None if k.oem_names => from_oem(listed, names).map(|raw| (raw, SystemPage::Oem)),
        None => None,
    };
    let path = match &raw {
        Some((raw, page)) => names.decode(raw, false, *page),
        None => listed.to_owned(),
    };
    let mut e = Entry::new(id, path, kind);
    if let Some((raw, _)) = raw {
        e.raw_path = raw;
    }
    e.size = size;
    e.packed_size = b.get(k.packed).and_then(|v| v.trim().parse::<u64>().ok());
    e.modified = b.get(k.modified).and_then(parse_time);
    e.crc32 = b
        .get(k.crc)
        .filter(|c| (1..=8).contains(&c.len()))
        .and_then(|c| u32::from_str_radix(c, 16).ok());
    e.encrypted = b.get(k.encrypted) == Some("+");
    e.method = method.map(intern);
    e.unix_mode = mode;
    e.dos_attrs = attrs.dos;
    Item {
        listed: (e.path != listed).then(|| listed.into()),
        entry: e,
    }
}

/// Whether 7-Zip wrote `c` for a byte of a name that isn't UTF-8 (the byte plus 0xEF00).
fn is_mapped(c: char) -> bool {
    ('\u{EF80}'..='\u{EFFF}').contains(&c)
}

/// The bytes behind a name 7-Zip printed with bytes mapped to U+EF80–U+EFFF; `None` when it
/// has none.
fn unmap(listed: &str) -> Option<Vec<u8>> {
    if !listed.chars().any(is_mapped) {
        return None;
    }
    let mut raw = Vec::with_capacity(listed.len());
    for c in listed.chars() {
        if is_mapped(c) {
            raw.push((u32::from(c) - 0xEF00) as u8);
        } else {
            raw.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        }
    }
    Some(raw)
}

/// The bytes behind a name 7-Zip decoded from the system's OEM code page (CramFS: `bee-🐝.txt`
/// is listed as `bee-≡ƒÉ¥.txt` under code page 437), when that page is one byte a character.
fn from_oem(listed: &str, names: &NameDecoding) -> Option<Vec<u8>> {
    if listed.is_ascii() {
        return None;
    }
    let table = oem_cp::code_table::ENCODING_TABLE_CP_MAP.get(&names.oem)?;
    oem_cp::encode_string_checked(listed, table)
}

/// A name or link target, with mapped bytes decoded as `names` says.
fn decode<'s>(listed: &'s str, names: &NameDecoding) -> Cow<'s, str> {
    match unmap(listed) {
        Some(raw) => Cow::Owned(names.decode(&raw, false, SystemPage::Ansi)),
        None => Cow::Borrowed(listed),
    }
}

/// Method names, interned: an archive's entries share a few, and a static name costs nothing
/// per entry. At most 256 are kept for the life of the process; past that each
/// entry owns its name.
fn intern(name: &str) -> Cow<'static, str> {
    static INTERNED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    const MAX_INTERNED: usize = 256;
    let mut interned = INTERNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(s) = interned.iter().find(|s| **s == name) {
        return Cow::Borrowed(s);
    }
    if interned.len() < MAX_INTERNED && name.len() <= 64 {
        let s: &'static str = Box::leak(name.to_owned().into_boxed_str());
        interned.push(s);
        return Cow::Borrowed(s);
    }
    Cow::Owned(name.to_owned())
}

/// `2024-05-06 07:08:09.1234567Z`, UTC (`-slmu`): no fraction (FAT, HFS) or up to nine digits
/// of one (100 ns for NTFS and WIM, 1 ns for ext4 and APFS), and 7-Zip 24.03 and later add a
/// `Z`.
pub fn parse_time(s: &str) -> Option<SystemTime> {
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
    let secs = days * 86_400 + h * 3600 + mi * 60 + se;
    let nanos = Duration::from_nanos(u64::from(nanos));
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs.unsigned_abs()) + nanos)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))?
            .checked_add(nanos)
    }
}

/// A unix mode as 7-Zip prints it: `drwxr-xr-x`, `-rwsr-xr-x`, `lrwxrwxrwx`, `?rw-r--r--` for
/// a type it doesn't know.
fn parse_mode(m: &str) -> Option<u32> {
    let b = m.as_bytes();
    if b.len() != 10 {
        return None;
    }
    let mut mode = match b[0] {
        b'-' => 0o100000,
        b'd' => 0o040000,
        b'l' => 0o120000,
        b'c' => 0o020000,
        b'b' => 0o060000,
        b'p' => 0o010000,
        b's' => 0o140000,
        b'?' => 0,
        _ => return None,
    };
    for (i, &c) in b[1..].iter().enumerate() {
        let bit = 1 << (8 - i);
        mode |= match (i, c) {
            (_, b'-') => 0,
            (_, c) if c == b"rwx"[i % 3] => bit,
            (2, b's') => 0o4000 | bit,
            (2, b'S') => 0o4000,
            (5, b's') => 0o2000 | bit,
            (5, b'S') => 0o2000,
            (8, b't') => 0o1000 | bit,
            (8, b'T') => 0o1000,
            _ => return None,
        };
    }
    Some(mode)
}

/// An `Attributes` value: Windows attribute letters, then the attributes' high bits in hex when
/// any are set, then a unix mode when the archive stored one (`A -rw-r--r--`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Attributes {
    dos: Option<u32>,
    mode: Option<u32>,
}

impl Attributes {
    /// 7-Zip's letters for bits 0 to 15 (`g_WinAttribChars`): `8` a volume label, `d` a
    /// device, `s` sparse, `L` a reparse point, `V` bit 15.
    const LETTERS: &'static [u8; 16] = b"RHS8DAdNTsLCOIEV";

    fn parse(value: &str) -> Self {
        let mut words = value.split(' ');
        let letters = words.next().unwrap_or("");
        let mut dos = (!letters.is_empty()).then_some(0u32);
        for c in letters.bytes() {
            if let Some(bit) = Self::LETTERS.iter().position(|&l| l == c) {
                dos = dos.map(|d| d | 1 << bit);
            }
        }
        let mut mode = None;
        for w in words {
            if w.len() == 8
                && let Ok(high) = u32::from_str_radix(w, 16)
            {
                dos = Some(dos.unwrap_or(0) | high);
            } else if let Some(m) = parse_mode(w) {
                mode = Some(m);
            }
        }
        Self { dos, mode }
    }
}

/// One entry's error, from `7z t` or `7z x`: `ERROR: CRC Failed : path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMessage {
    pub path: String,
    pub kind: ErrorKind,
    pub message: String,
}

/// What 7-Zip said on stderr (`-bse2`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Messages {
    /// What went wrong with the archive, in order: the flags of an `ERRORS:` group, `ERROR:`,
    /// `Open ERROR:` and `System ERROR:` messages and the lines after them (which can be the
    /// archive's path), and a command line error on one line.
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    /// Entries that failed, in the order 7-Zip read them.
    pub entries: Vec<EntryMessage>,
}

/// The messages that name an entry (`SetExtractErrorMessage` in 7-Zip), and what each means.
const ENTRY_MESSAGES: &[(&str, ErrorKind)] = &[
    (
        "Data Error in encrypted file. Wrong password?",
        ErrorKind::WrongPassword,
    ),
    (
        "CRC Failed in encrypted file. Wrong password?",
        ErrorKind::WrongPassword,
    ),
    ("Wrong password", ErrorKind::WrongPassword),
    ("CRC Failed", ErrorKind::Corrupt),
    ("Data Error", ErrorKind::Corrupt),
    ("Unsupported Method", ErrorKind::UnsupportedOperation),
    ("Unavailable data", ErrorKind::Corrupt),
    ("Unexpected end of data", ErrorKind::Corrupt),
    (
        "There are some data after the end of the payload data",
        ErrorKind::Corrupt,
    ),
    ("Is not archive", ErrorKind::UnsupportedFormat),
    ("Headers Error", ErrorKind::Corrupt),
    ("Dangerous link path was ignored", ErrorKind::Unsafe),
];

/// Which lines go with the one before them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    None,
    /// `ERRORS:`'s flags, or what follows `ERROR: <archive>` and `System ERROR:`.
    Errors,
    Warnings,
    /// `Command Line Error:`, then what was wrong over a few lines; `true` once one came.
    CommandLine(bool),
}

/// Reads 7-Zip's stderr. Lines are split on `\n` only, as in the listing: a `\r` in a name stays
/// in the name.
pub fn messages(stderr: &[u8]) -> Messages {
    let text = String::from_utf8_lossy(stderr);
    let crlf = text.find('\n').is_some_and(|n| text[..n].ends_with('\r'));
    let mut m = Messages::default();
    let mut group = Group::None;
    for line in text.split('\n') {
        let line = match line.strip_suffix('\r') {
            Some(l) if crlf => l,
            _ => line,
        };
        m.line(line, &mut group);
    }
    m
}

impl Messages {
    fn line(&mut self, line: &str, group: &mut Group) {
        match line {
            "" => {
                *group = Group::None;
                return;
            }
            "ERRORS:" | "System ERROR:" => {
                *group = Group::Errors;
                return;
            }
            "WARNINGS:" => {
                *group = Group::Warnings;
                return;
            }
            "Command Line Error:" => {
                *group = Group::CommandLine(false);
                return;
            }
            _ => {}
        }
        let (rest, flagged) = match line.strip_prefix("ERROR: ") {
            Some(rest) => (rest, true),
            None => (line, false),
        };
        if let Some(e) = entry_message(rest) {
            self.entries.push(e);
            return;
        }
        if flagged {
            // `ERROR: <archive> : <why>` from `l`; `ERROR: <archive>` then why, from `t` and
            // `x`; `ERROR: <why>` then the path, for a file that isn't there.
            let why = match rest.rsplit_once(" : ") {
                Some((_, why)) if known(why).is_some() => why,
                _ => rest,
            };
            self.errors.push(why.to_owned());
            *group = Group::Errors;
            return;
        }
        if let Some(m) = line
            .strip_prefix("Open ERROR: ")
            .or_else(|| line.strip_prefix("ERROR = "))
        {
            self.errors.push(m.to_owned());
        } else if let Some(m) = line
            .strip_prefix("Open WARNING: ")
            .or_else(|| line.strip_prefix("WARNING: "))
            .or_else(|| line.strip_prefix("WARNING = "))
        {
            self.warnings.push(m.to_owned());
        } else {
            match *group {
                Group::Errors => self.errors.push(line.to_owned()),
                Group::Warnings => self.warnings.push(line.to_owned()),
                // `Unknown switch:` then `-x` on the next line: one message.
                Group::CommandLine(true) => {
                    if let Some(last) = self.errors.last_mut() {
                        last.push(' ');
                        last.push_str(line);
                    }
                }
                Group::CommandLine(false) => {
                    self.errors.push(line.to_owned());
                    *group = Group::CommandLine(true);
                }
                // `Break signaled`, and anything else 7-Zip says that reads as a reason.
                Group::None => {
                    if known(line).is_some() {
                        self.errors.push(line.to_owned());
                    }
                }
            }
        }
    }

    /// Adds `other`'s messages after these (a listing's own, from [`Listing::messages`]).
    pub fn extend(&mut self, other: Messages) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
        self.entries.extend(other.entries);
    }

    /// The job's error, from these messages and the exit code; `None` when 7-Zip succeeded
    /// (code 0, or 1 for warnings) and named no error.
    ///
    /// The kind is the most telling one any message has: a wrong password first (the caller
    /// asks again), then a missing file, then damage (`Unexpected end of archive` says more
    /// than `Cannot open the file as [wim] archive`), then an unsupported method or format.
    pub fn error(&self, code: Option<i32>) -> Option<Error> {
        let failed = !self.errors.is_empty() || !self.entries.is_empty();
        let fixed = match code {
            Some(0 | 1) if !failed => return None,
            Some(7) => Some((
                ErrorKind::Io,
                "7-Zip refused its command line (exit code 7)",
            )),
            Some(8) => Some((ErrorKind::LimitExceeded, "7-Zip ran out of memory")),
            Some(255) => Some((ErrorKind::Cancelled, "7-Zip was stopped")),
            None => Some((ErrorKind::Io, "7-Zip was stopped")),
            Some(_) => None,
        };
        if let Some((kind, what)) = fixed {
            let message = match self.errors.first() {
                Some(why) => format!("{what}: {why}"),
                None => what.to_owned(),
            };
            return Some(Error::new(kind, message));
        }
        // The first message of the most telling kind; one BeeZip knows beats one it doesn't.
        let archive = self
            .errors
            .iter()
            .filter_map(|e| Some((known(e)?, None, e)));
        let entries = self.entries.iter().map(|e| (e.kind, Some(e), &e.message));
        let best = archive
            .chain(entries)
            .min_by_key(|(kind, _, _)| rank(*kind));
        let (kind, text) = match best {
            Some((kind, None, msg)) => (kind, msg.clone()),
            Some((kind, Some(e), _)) => match self.entries.len() - 1 {
                0 => (kind, format!("{}: {}", e.path, e.message)),
                n => (kind, format!("{}: {} (and {n} more)", e.path, e.message)),
            },
            None => match self
                .errors
                .iter()
                .find(|e| !is_path(e))
                .or(self.errors.first())
                .or(self.warnings.first())
            {
                Some(e) => (ErrorKind::Corrupt, e.clone()),
                None => (
                    ErrorKind::Corrupt,
                    format!("failed (exit code {})", code.unwrap_or(-1)),
                ),
            },
        };
        Some(Error::new(kind, format!("7-Zip: {text}")))
    }
}

/// `CRC Failed : path`, `Error #12 : path` (a result this 7-Zip has no words for).
fn entry_message(s: &str) -> Option<EntryMessage> {
    for &(msg, kind) in ENTRY_MESSAGES {
        if let Some(path) = s.strip_prefix(msg).and_then(|r| r.strip_prefix(" : ")) {
            return Some(EntryMessage {
                path: path.to_owned(),
                kind,
                message: msg.to_owned(),
            });
        }
    }
    let (num, path) = s.strip_prefix("Error #")?.split_once(" : ")?;
    (!num.is_empty() && num.bytes().all(|c| c.is_ascii_digit())).then(|| EntryMessage {
        path: path.to_owned(),
        kind: ErrorKind::Corrupt,
        message: format!("Error #{num}"),
    })
}

/// How telling a kind of error is; lower wins.
fn rank(kind: ErrorKind) -> u8 {
    match kind {
        ErrorKind::WrongPassword => 0,
        ErrorKind::NotFound => 1,
        ErrorKind::Cancelled => 2,
        ErrorKind::LimitExceeded => 3,
        ErrorKind::Unsafe => 4,
        ErrorKind::Io => 5,
        ErrorKind::Corrupt => 6,
        ErrorKind::UnsupportedOperation => 7,
        ErrorKind::UnsupportedFormat => 8,
        _ => 9,
    }
}

/// Whether `s` starts as an absolute path does (`C:/`, `C:\`, `/`, `\\`): the archive's, which
/// 7-Zip puts in its errors and whose words aren't a reason.
fn is_path(s: &str) -> bool {
    match s.as_bytes() {
        [b'/' | b'\\', ..] => true,
        [d, b':', b'/' | b'\\', ..] => d.is_ascii_alphabetic(),
        _ => false,
    }
}

/// What one of 7-Zip's messages means, when it's one BeeZip knows. System errors come in the
/// language of Windows, so only English ones are known.
fn known(msg: &str) -> Option<ErrorKind> {
    if is_path(msg) {
        return None;
    }
    let m = msg.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| m.contains(w));
    Some(if has(&["wrong password"]) {
        ErrorKind::WrongPassword
    } else if has(&["cannot find the", "no such file"]) {
        ErrorKind::NotFound
    } else if has(&["break signaled"]) {
        ErrorKind::Cancelled
    } else if has(&["not enough memory", "allocate", "out of memory"]) {
        ErrorKind::LimitExceeded
    } else if has(&["dangerous link"]) {
        ErrorKind::Unsafe
    } else if has(&[
        "access is denied",
        "permission denied",
        "cannot access the file",
        "command line error",
        "unknown switch",
    ]) {
        ErrorKind::Io
    } else if has(&[
        "unexpected end",
        "headers error",
        "data error",
        "crc failed",
        "crc error",
        "unavailable",
        "unconfirmed start",
        "data after the end",
        "checksum error",
    ]) {
        ErrorKind::Corrupt
    } else if has(&["unsupported method", "unsupported feature"]) {
        ErrorKind::UnsupportedOperation
    } else if has(&[
        "cannot open the file as",
        "can not open the file as",
        "is not archive",
    ]) {
        ErrorKind::UnsupportedFormat
    } else {
        return None;
    })
}

/// What one of 7-Zip's messages means; damage when BeeZip doesn't know it.
pub fn classify(msg: &str) -> ErrorKind {
    known(msg).unwrap_or(ErrorKind::Corrupt)
}

#[cfg(test)]
mod tests {
    //! Real output of 7-Zip 26.00 on Windows (`testdata/`, captured with the backend's switches;
    //! paths shortened to `C:/samples/`), and listings made up to attack the parser.

    use std::sync::{Arc, atomic::AtomicBool};

    use proptest::prelude::*;

    use super::*;
    use crate::SimpleCtx;

    fn read(text: &[u8]) -> Result<Listing> {
        parse(
            &mut &text[..],
            &NameDecoding::default(),
            &Limits::default(),
            &mut SimpleCtx::new(),
        )
    }

    fn listing(text: &[u8]) -> Listing {
        read(text).unwrap()
    }

    fn find<'a>(l: &'a Listing, path: &str) -> &'a Entry {
        &l.items
            .iter()
            .find(|i| i.entry.path == path)
            .unwrap_or_else(|| panic!("no `{path}` in the listing"))
            .entry
    }

    fn types(l: &Listing) -> Vec<&str> {
        l.levels.iter().map(Level::type_name).collect()
    }

    fn symlink(target: &str) -> EntryKind {
        EntryKind::Symlink {
            target: target.to_owned(),
        }
    }

    fn since_epoch(t: Option<SystemTime>) -> (u64, u32) {
        let d = t.unwrap().duration_since(UNIX_EPOCH).unwrap();
        (d.as_secs(), d.subsec_nanos())
    }

    /// `2024-05-06 07:08:09`, mtime.txt's time in the samples.
    const MTIME: u64 = 1_714_979_289;

    /// Nanoseconds as a `SystemTime` keeps them: in 100 ns steps on Windows.
    fn nanos(n: u32) -> u32 {
        if cfg!(windows) { n / 100 * 100 } else { n }
    }

    /// A made-up listing: the banner, the blocks given, and 7-Zip's line ends.
    fn made(blocks: &str) -> Vec<u8> {
        format!("\n7-Zip 26.00 (x64)\n\nListing archive: C:/a\n\n{blocks}")
            .replace('\n', "\r\n")
            .into_bytes()
    }

    /// Listings whose every `Path = ` line starts a level, a `----` block or an entry.
    const PLAIN: &[&[u8]] = &[
        include_bytes!("testdata/ext4.slt"),
        include_bytes!("testdata/ext4-evil.slt"),
        include_bytes!("testdata/ext4-evil2.slt"),
        include_bytes!("testdata/ntfs.slt"),
        include_bytes!("testdata/chm.slt"),
        include_bytes!("testdata/chm-truncated.slt"),
        include_bytes!("testdata/apfs.slt"),
        include_bytes!("testdata/hfs.slt"),
        include_bytes!("testdata/vhdx-gpt-ntfs.slt"),
        include_bytes!("testdata/vmdk-gpt.slt"),
        include_bytes!("testdata/msi.slt"),
        include_bytes!("testdata/pe-nsis.slt"),
        include_bytes!("testdata/nsis.slt"),
        include_bytes!("testdata/wim-links.slt"),
        include_bytes!("testdata/fat12.slt"),
        include_bytes!("testdata/cramfs.slt"),
        include_bytes!("testdata/cramfs-damaged.slt"),
        include_bytes!("testdata/zip-odd-names.slt"),
        include_bytes!("testdata/gpt-brace-name.slt"),
        include_bytes!("testdata/fat-named-vhdx.slt"),
    ];

    /// Listings with `Path = ` lines inside values on several lines.
    const FORGED: &[&[u8]] = &[
        include_bytes!("testdata/zip-comments.slt"),
        include_bytes!("testdata/gpt-forged-name.slt"),
    ];

    /// What 7-Zip said on stderr.
    const STDERR: &[&[u8]] = &[
        include_bytes!("testdata/7z-data-wrong-password.err"),
        include_bytes!("testdata/7z-headers-wrong-password-l.err"),
        include_bytes!("testdata/7z-headers-wrong-password-t.err"),
        include_bytes!("testdata/zip-aes-wrong-password.err"),
        include_bytes!("testdata/wim-crc.err"),
        include_bytes!("testdata/nsis-data.err"),
        include_bytes!("testdata/cramfs-headers.err"),
        include_bytes!("testdata/not-an-archive.err"),
        include_bytes!("testdata/wim-truncated.err"),
        include_bytes!("testdata/msi-truncated-l.err"),
        include_bytes!("testdata/qcow2-truncated.err"),
        include_bytes!("testdata/vhdx-truncated.err"),
        include_bytes!("testdata/chm-truncated.err"),
        include_bytes!("testdata/missing.err"),
        include_bytes!("testdata/bad-switch.err"),
        include_bytes!("testdata/zip-odd-names.err"),
    ];

    const SAMPLES: usize = PLAIN.len() + FORGED.len() + STDERR.len();

    /// Every sample, for the random tests.
    fn sample(n: usize) -> &'static [u8] {
        PLAIN
            .iter()
            .chain(FORGED)
            .chain(STDERR)
            .nth(n)
            .copied()
            .unwrap_or_default()
    }

    #[test]
    fn every_entry_of_every_listing() {
        for text in PLAIN {
            let l = listing(text);
            // A `Path` line per level and entry, and one in most `----` blocks.
            let paths = text
                .split(|&b| b == b'\n')
                .filter(|l| l.starts_with(b"Path = "))
                .count();
            let parents = text
                .windows(14)
                .filter(|w| w == b"\r\n----\r\nPath =")
                .count();
            assert_eq!(l.items.len() + l.levels.len() + parents, paths);
            for (n, i) in l.items.iter().enumerate() {
                assert_eq!(i.entry.id, n);
            }
        }
    }

    #[test]
    fn ext4() {
        let l = listing(include_bytes!("testdata/ext4.slt"));
        assert_eq!(types(&l), ["Ext"]);
        assert_eq!(l.levels[0].get("Label"), Some("BeeZipExt4"));
        assert_eq!(l.items.len(), 17);
        assert!(l.items.iter().all(|i| i.entry.modified.is_some()));
        let lost = find(&l, "lost+found");
        assert_eq!(
            (&lost.kind, lost.unix_mode),
            (&EntryKind::Dir, Some(0o40700))
        );
        let link = find(&l, "link-to-readme");
        assert_eq!(link.kind, symlink("readme.txt"));
        assert_eq!((link.size, link.unix_mode), (Some(10), Some(0o120777)));
        // A link to a folder: 7-Zip flags it a folder, and it's still a link.
        assert_eq!(find(&l, "sub/link-to-nested").kind, symlink("nested"));
        // Hard links are two files with the same inode.
        for p in ["hard-readme.txt", "readme.txt"] {
            assert_eq!(
                (&find(&l, p).kind, find(&l, p).size),
                (&EntryKind::File, Some(18))
            );
        }
        let journal = find(&l, "[SYS]/Journal");
        assert_eq!(
            (journal.size, journal.unix_mode),
            (Some(4_194_304), Some(0o100600))
        );
        assert_eq!(since_epoch(find(&l, "mtime.txt").modified), (MTIME, 0));
        assert_eq!(find(&l, "Ünïcödé dir/日本語.txt").size, Some(2));
        assert_eq!(find(&l, "bee-🐝.txt").raw_path, "bee-🐝.txt".as_bytes());
        assert!(l.items.iter().all(|i| i.listed.is_none()));
    }

    #[test]
    fn ext4_odd_names() {
        let l = listing(include_bytes!("testdata/ext4-evil.slt"));
        for p in [
            "...",
            "CON",
            "[x].txt",
            "a*b?.txt",
            "ads:like.txt",
            "aux.txt",
            // 7-Zip turns a `\` in a Linux name into `_`.
            "back_slash.txt",
            "ctl\u{1}x.txt",
            "trail ",
            "trail.",
            "dir/inside.txt",
            "[SYS]/Journal",
        ] {
            assert_eq!(find(&l, p).kind, EntryKind::File, "{p}");
        }
        assert_eq!(find(&l, "dirlink").kind, symlink("dir"));
        assert_eq!(find(&l, "escape-abs").kind, symlink("/etc/passwd"));
        assert_eq!(find(&l, "escape-drive").kind, symlink("C:/Windows/win.ini"));
        assert_eq!(
            find(&l, "escape-rel").kind,
            symlink("../../../../Windows/win.ini")
        );
    }

    #[test]
    fn ext4_names_that_arent_utf8_or_hold_line_breaks() {
        let l = listing(include_bytes!("testdata/ext4-evil2.slt"));
        assert_eq!(l.items.len(), 9);
        // `\r`, a tab and an escape stay in the name; the `\r\n` that ends the line goes.
        for p in ["cr\rcarriage.txt", "tab\there.txt", "esc\u{1b}[31mred.txt"] {
            assert_eq!(find(&l, p).kind, EntryKind::File, "{p:?}");
        }
        // A `\n` in a name became `_`: one entry, not a forged one.
        find(&l, "x__Path = forged.._.._out.txt_Folder = -_Size = 5");
        // Bytes FF FE, which aren't UTF-8, came as U+EFFF U+EFFE.
        let bad = l.items.iter().find(|i| i.listed.is_some()).unwrap();
        assert_eq!(bad.listed(), "bad\u{EFFF}\u{EFFE}utf8.txt");
        assert_eq!(bad.entry.raw_path, b"bad\xFF\xFEutf8.txt");
        assert_eq!(bad.entry.path, "badÿþutf8.txt");
        let shift_jis = NameDecoding {
            encoding: crate::NameEncoding::Cp932,
            ..NameDecoding::default()
        };
        let sjis = parse(
            &mut &include_bytes!("testdata/ext4-evil2.slt")[..],
            &shift_jis,
            &Limits::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        let bad = sjis.items.iter().find(|i| i.listed.is_some()).unwrap();
        assert_ne!(bad.entry.path, "badÿþutf8.txt");
        assert_eq!(bad.listed(), "bad\u{EFFF}\u{EFFE}utf8.txt");
    }

    #[test]
    fn ntfs() {
        let l = listing(include_bytes!("testdata/ntfs.slt"));
        assert_eq!(types(&l), ["NTFS"]);
        let mft = find(&l, "[SYSTEM]/$MFT");
        assert_eq!(
            (mft.size, mft.dos_attrs, mft.modified),
            (Some(79_872), Some(0x6), None)
        );
        assert!(find(&l, "[SYSTEM]/.").is_dir());
        assert_eq!(find(&l, "[SYSTEM]/$Extend").dos_attrs, Some(0x16));
        // 100 ns.
        assert_eq!(
            since_epoch(find(&l, "mtime.txt").modified),
            (MTIME, 123_456_700)
        );
        // ntfs-3g made its links Interix files, which 7-Zip lists as system files.
        let link = find(&l, "link-to-readme");
        assert_eq!((&link.kind, link.dos_attrs), (&EntryKind::File, Some(0x24)));
    }

    #[test]
    fn chm_folders_have_no_flag() {
        let l = listing(include_bytes!("testdata/chm.slt"));
        assert_eq!(types(&l), ["Chm"]);
        assert_eq!(l.items.len(), 103);
        // Folders with something in them, and two without.
        for p in [
            "cmdline",
            "fm/plugins/7-zip",
            "$WWAssociativeLinks",
            "$WWKeywordLinks",
        ] {
            assert!(find(&l, p).is_dir(), "{p}");
        }
        let itbits = find(&l, "#ITBITS");
        assert_eq!((&itbits.kind, itbits.size), (&EntryKind::File, Some(0)));
        assert_eq!(itbits.method.as_deref(), Some("LZX:17"));
        assert_eq!(l.items.iter().filter(|i| i.entry.is_dir()).count(), 9);
    }

    #[test]
    fn chm_read_low_level() {
        // A cut CHM: 7-Zip lists its raw names, `/` first, and the root as an empty name.
        let l = listing(include_bytes!("testdata/chm-truncated.slt"));
        assert_eq!(l.errors, ["Unexpected end of archive"]);
        assert_eq!(l.items[0].entry.path, "");
        assert!(l.items[0].entry.is_dir());
        let idx = find(&l, "/#IDXHDR");
        assert_eq!(
            (&idx.kind, idx.size, &idx.method),
            (&EntryKind::File, Some(4096), &None)
        );
    }

    #[test]
    fn apfs_and_hfs() {
        let l = listing(include_bytes!("testdata/apfs.slt"));
        assert_eq!(types(&l), ["APFS"]);
        let comment = l.levels[0].get("Comment").unwrap();
        assert!(comment.starts_with("block_size: 4096\nfs_index: 0\nvolume_name: BeeZip APFS\n"));
        assert!(comment.ends_with("modified_by[0]: apfs_kext (2811.160.7.702.4)\n  timestamp: 2026-11-07 04:00:53.952290124\n  last_xid: 4"));
        assert_eq!(comment.lines().count(), 22);
        assert_eq!(
            l.levels[0].get("ID"),
            Some("c93420ec14c14d54b5b50827dbdfb303")
        );
        // No `Folder` key: the mode says.
        assert!(find(&l, "sub/nested").is_dir());
        let link = find(&l, "link-to-readme");
        assert_eq!(link.kind, symlink("readme.txt"));
        // Nanoseconds.
        assert_eq!(since_epoch(link.modified).1, nanos(785_493_541));
        assert_eq!(link.method.as_deref(), Some("symlink"));

        let l = listing(include_bytes!("testdata/hfs.slt"));
        assert_eq!(types(&l), ["HFS"]);
        // HFS+ names its folder of hard links with a `\r` at the end.
        assert_eq!(
            find(&l, "BeeZip HFS/.HFS+ Private Directory Data\r").unix_mode,
            Some(0o41555)
        );
        // HFS lists no target: 7-Zip writes it as the link's data.
        assert_eq!(find(&l, "BeeZip HFS/link-to-readme").kind, symlink(""));
        assert_eq!(l.items.len(), 13);
    }

    #[test]
    fn disk_images_nest() {
        let l = listing(include_bytes!("testdata/vhdx-gpt-ntfs.slt"));
        assert_eq!(types(&l), ["VHDX", "GPT", "NTFS"]);
        let comment = l.levels[0].get("Comment").unwrap();
        assert!(comment.starts_with("VirtualDiskSize: 73400320\nPhysicalSize: 50331648\n"));
        assert!(comment.ends_with("\nFreeSpace: 4194304 (4 MiB)"));
        // The key after the comment is the level's own.
        assert_eq!(
            l.levels[0].get("ID"),
            Some("83fd2f8684d94f2eb71f7661fb8cedf1")
        );
        assert_eq!(l.levels[2].get("Path"), Some("0.ntfs.ntfs"));
        assert_eq!(l.items.len(), 30);

        // A VMDK's descriptor holds lines with ` = `: still one value.
        let l = listing(include_bytes!("testdata/vmdk-gpt.slt"));
        assert_eq!(types(&l), ["VMDK", "GPT"]);
        let vmdk = &l.levels[0];
        assert_eq!(vmdk.get("Name"), Some("gpt-fat-ext4.vmdk"));
        assert!(
            vmdk.get("Comment")
                .unwrap()
                .contains("\n\n# The Disk Data Base\n#DDB\n\nddb.virtualHWVersion = \"4\"\n")
        );
        assert!(vmdk.get("ddb.virtualHWVersion").is_none());
        let names: Vec<_> = l.items.iter().map(|i| i.entry.path.as_str()).collect();
        assert_eq!(names, ["0.data.fat", "1.linux.img"]);
        assert_eq!(find(&l, "0.data.fat").size, Some(67_108_864));
    }

    #[test]
    fn msi_and_nsis() {
        let l = listing(include_bytes!("testdata/msi.slt"));
        assert_eq!(types(&l), ["Compound", "Cab"]);
        let names: Vec<_> = l.items.iter().map(|i| i.entry.path.as_str()).collect();
        assert_eq!(names, ["readme", "empty", "big", "cjk"]);
        assert_eq!(find(&l, "big").method.as_deref(), Some("MSZip"));
        assert_eq!(find(&l, "readme").dos_attrs, Some(0x20));

        // An uninstaller: a PE whose comment nests braces, with errors in its level.
        let l = listing(include_bytes!("testdata/pe-nsis.slt"));
        assert_eq!(types(&l), ["PE", "Nsis"]);
        assert_eq!(l.errors, ["Unexpected end of archive"]);
        assert_eq!(l.warnings, ["Checksum error"]);
        assert_eq!(
            l.levels[0].get("Comment"),
            Some(
                "\nData Directories: 16\n{\nindex=1 name=IMPORT VA=0x39000 Size=5040\n\
                 index=2 name=RESOURCE VA=0x6F000 Size=93312\n\
                 index=4 name=SECURITY VA=0x2C1A608 Size=23976\n}"
            )
        );
        assert!(l.levels[0].get("WARNING").is_none());
        assert_eq!(
            l.levels[1].get("SubType"),
            Some("NSIS-3 Unicode (Uninstall)")
        );
        // The last file's size isn't in the script.
        assert_eq!(find(&l, "$PLUGINSDIR/LangDLL.dll").size, None);
        assert_eq!(find(&l, "$PLUGINSDIR/System.dll").modified, None);

        let l = listing(include_bytes!("testdata/nsis.slt"));
        assert_eq!(types(&l), ["Nsis"]);
        find(&l, "../outside/mtime.txt");
    }

    #[test]
    fn wim_links() {
        let l = listing(include_bytes!("testdata/wim-links.slt"));
        assert_eq!(types(&l), ["wim"]);
        assert!(
            l.levels[0]
                .get("Comment")
                .unwrap()
                .starts_with("<WIM><TOTALBYTES>")
        );
        // A directory symlink: a folder to 7-Zip, with 36 bytes of reparse data that `x -so`
        // writes.
        let dir_link = find(&l, "tree/sub/link-to-nested");
        assert_eq!(dir_link.kind, symlink("nested"));
        assert_eq!(
            (dir_link.size, dir_link.dos_attrs),
            (Some(36), Some(0x2410))
        );
        let link = find(&l, "tree/link-to-readme");
        assert_eq!((&link.kind, link.size), (&symlink("readme.txt"), Some(52)));
        assert_eq!(
            since_epoch(find(&l, "tree/mtime.txt").modified),
            (MTIME, 123_456_700)
        );
        assert_eq!(find(&l, "tree/big.bin").method.as_deref(), Some("Copy"));
        let total: u64 = l.items.iter().filter_map(|i| i.entry.size).sum();
        assert_eq!(
            Some(total),
            l.levels[0].get("Size").and_then(|s| s.parse().ok())
        );
    }

    #[test]
    fn fat_and_cramfs() {
        let l = listing(include_bytes!("testdata/fat12.slt"));
        assert_eq!(types(&l), ["FAT"]);
        // Two-second precision, no fraction.
        let m = find(&l, "mtime.txt");
        // FAT keeps local time, which 7-Zip read at this machine's offset (UTC-6).
        assert_eq!(since_epoch(m.modified), (MTIME - 1 + 6 * 3600, 0));
        assert_eq!(m.dos_attrs, Some(0x20));
        // Named `.vhdx`: 7-Zip tries VHDX first, says so, and opens it as what it is.
        let l = listing(include_bytes!("testdata/fat-named-vhdx.slt"));
        assert_eq!(types(&l), ["FAT"]);
        assert_eq!(l.warnings, ["Cannot open the file as [VHDX] archive"]);
        assert_eq!(l.items.len(), 4);

        // CramFS's names come from the OEM code page: `bee-🐝.txt` as `bee-≡ƒÉ¥.txt`.
        let l = listing(include_bytes!("testdata/cramfs.slt"));
        let bee = l
            .items
            .iter()
            .find(|i| i.entry.path == "bee-🐝.txt")
            .unwrap();
        assert_eq!(bee.listed(), "bee-≡ƒÉ¥.txt");
        assert_eq!(bee.entry.raw_path, "bee-🐝.txt".as_bytes());
        for p in ["名前.txt", "Ünïcödé dir", "café-ñandú.txt", "big.bin"] {
            find(&l, p);
        }
        // 7zz decodes them from the locale's code page, UTF-8: its `\n` line ends say so.
        let lf =
            String::from_utf8_lossy(include_bytes!("testdata/cramfs.slt")).replace("\r\n", "\n");
        let l = listing(lf.as_bytes());
        assert!(l.items.iter().all(|i| i.listed.is_none()));
        find(&l, "bee-≡ƒÉ¥.txt");

        let l = listing(include_bytes!("testdata/cramfs-damaged.slt"));
        assert_eq!(l.errors, ["Headers Error"]);
        assert_eq!(l.items.len(), 15);
    }

    #[test]
    fn comments_cant_forge_structure() {
        // A zip comment of lines that look like the listing, between `{` and `}`.
        let l = listing(include_bytes!("testdata/zip-comments.slt"));
        assert_eq!(types(&l), ["zip"]);
        assert_eq!(
            l.levels[0].get("Comment"),
            Some(
                "c1\nPath = forged.txt\nSize = 99\n\nPath = evil\nFolder = +\n}\n{\n\
                 ----------\n--\nType = Ext"
            )
        );
        // In an entry, 7-Zip writes the same text on one line.
        let names: Vec<_> = l.items.iter().map(|i| i.entry.path.as_str()).collect();
        assert_eq!(names, ["a.txt", "b.txt"]);

        // A GPT partition's name with `\n--\nPath = …` in it: a `----` block's value on
        // several lines, and the next level's path on one.
        let l = listing(include_bytes!("testdata/gpt-forged-name.slt"));
        assert_eq!(types(&l), ["GPT", "zip"]);
        assert_eq!(
            l.levels[1].get("Path"),
            Some("0.x_Type = Ext_--_Path = y.img")
        );
        assert_eq!(l.warnings, ["There are data after the end of archive"]);
        assert_eq!(l.items.len(), 1);
        let l = listing(include_bytes!("testdata/gpt-brace-name.slt"));
        assert_eq!(types(&l), ["GPT", "zip"]);
        assert_eq!(l.items.len(), 1);

        // Names with `\r`, a tab, an escape, U+2028, NEL, VT and FF in them.
        let l = listing(include_bytes!("testdata/zip-odd-names.slt"));
        assert_eq!(l.items.len(), 11);
        find(&l, "c\rERROR: Wrong password : d");
        find(&l, "e\r_ERROR: Wrong password : f");
        find(&l, "l\u{2028}ERROR: Wrong password : m");
    }

    #[test]
    fn a_comment_that_imitates_entries_is_refused() {
        let forged = made(
            "--\nPath = a\nType = VMDK\nComment = \n{\nok\n}\n\n----------\nPath = evil\n\
             Size = 1\n\n}\n----\nSize = 5\n--\nPath = a.mbr\nType = MBR\n\n----------\n\
             Path = 0.img\nSize = 5\n\n",
        );
        assert_eq!(read(&forged).unwrap_err().kind, ErrorKind::Corrupt);
        // Ending inside a value is refused too.
        let open = made("--\nPath = a\nType = VMDK\nComment = \n{\nok\n");
        assert_eq!(read(&open).unwrap_err().kind, ErrorKind::Corrupt);
        // A `}` at the very end closes the value.
        let closed = made("--\nPath = a\nType = VMDK\nComment = \n{\nok\n}");
        assert_eq!(listing(&closed).levels[0].get("Comment"), Some("ok"));
    }

    #[test]
    fn values_cant_start_fields() {
        let l = listing(&made(
            "--\nPath = a\nType = tar\n\n----------\nPath = one\nSize = 1\nComment = x\n\
             Size = 999\n\nPath = two\nEvil = 1\nSize = 2\nComment = \n\n",
        ));
        let one = &l.items[0].entry;
        assert_eq!((one.path.as_str(), one.size), ("one", Some(1)));
        // A key the first entry didn't have goes on from the value before it.
        let two = &l.items[1].entry;
        assert_eq!((two.path.as_str(), two.size), ("two\nEvil = 1", Some(2)));
        // A level's key twice: the second goes on from the value before it.
        let l = listing(&made("--\nPath = a\nType = A\nLabel = x\nType = B\n"));
        assert_eq!(l.levels[0].type_name(), "A");
        assert_eq!(l.levels[0].get("Label"), Some("x\nType = B"));
    }

    #[test]
    fn line_ends() {
        // 7zz on Linux ends lines with `\n` alone; a name can then end in `\r`.
        let crlf = include_bytes!("testdata/ext4.slt");
        let lf: Vec<u8> = String::from_utf8_lossy(crlf)
            .replace("\r\n", "\n")
            .into_bytes();
        assert_eq!(listing(&lf), listing(crlf));
        let l = listing(b"\n--\nPath = a\nType = Ext\n\n----------\nPath = x\r\nSize = 1\n\n");
        assert_eq!(l.items[0].entry.path, "x\r");
        let l = listing(&made(
            "--\nPath = a\nType = Ext\n\n----------\nPath = x\r\nSize = 1\n\n",
        ));
        assert_eq!(l.items[0].entry.path, "x\r");
        assert!(listing(b"").levels.is_empty());
    }

    #[test]
    fn bounds() {
        let long = vec![b'x'; MAX_LINE + 1];
        assert_eq!(read(&long).unwrap_err().kind, ErrorKind::Corrupt);
        // A value past 1 MiB, over many lines.
        let line = "y".repeat(1000);
        let mut big = String::from("--\nPath = a\nType = VMDK\nComment = \n{\n");
        for _ in 0..1100 {
            big.push_str(&line);
            big.push('\n');
        }
        assert_eq!(read(&made(&big)).unwrap_err().kind, ErrorKind::Corrupt);
        // Too many keys in a level.
        let mut keys = String::from("--\nPath = a\nType = A\n");
        for n in 0..=MAX_KEYS {
            keys.push_str(&format!("K{n} = 1\n"));
        }
        assert_eq!(read(&made(&keys)).unwrap_err().kind, ErrorKind::Corrupt);
        // Too many in an entry.
        let entry = keys.replace(
            "--\nPath = a\nType = A\n",
            "--\nPath = a\nType = A\n\n----------\n",
        );
        assert_eq!(read(&made(&entry)).unwrap_err().kind, ErrorKind::Corrupt);
        // Too many levels.
        let levels = "--\nPath = a\nType = A\n".repeat(MAX_LEVELS + 1);
        assert_eq!(read(&made(&levels)).unwrap_err().kind, ErrorKind::Corrupt);
        // Too much text in levels: 17 comments of nearly 1 MiB.
        let mut headers = String::new();
        let comment = format!("{}\n", "z".repeat(1023)).repeat(1000);
        for _ in 0..17 {
            headers.push_str("--\nPath = a\nType = A\nComment = \n{\n");
            headers.push_str(&comment);
            headers.push_str("}\n");
        }
        assert_eq!(read(&made(&headers)).unwrap_err().kind, ErrorKind::Corrupt);
    }

    #[test]
    fn entries_count_against_the_limit_as_they_come() {
        let limits = Limits {
            max_entries: Some(16),
            ..Limits::default()
        };
        let err = parse(
            &mut &include_bytes!("testdata/ext4.slt")[..],
            &NameDecoding::default(),
            &limits,
            &mut SimpleCtx::new(),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::LimitExceeded);
    }

    #[test]
    fn cancel() {
        let mut cx = SimpleCtx::new();
        cx.cancel = Some(Arc::new(AtomicBool::new(true)));
        let text = made(&"\n".repeat(2 * CHECK_EVERY as usize));
        let err = parse(
            &mut &text[..],
            &NameDecoding::default(),
            &Limits::default(),
            &mut cx,
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }

    /// A listing of `n` entries, made as it's read, like 7-Zip's pipe.
    struct Pipe {
        n: usize,
        next: usize,
        buf: Vec<u8>,
        at: usize,
    }

    impl Read for Pipe {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.at == self.buf.len() {
                self.buf.clear();
                self.at = 0;
                if self.next == 0 {
                    self.buf
                        .extend_from_slice(&made("--\nPath = a\nType = wim\n\n----------\n"));
                } else if self.next <= self.n {
                    let n = self.next;
                    self.buf.extend_from_slice(
                        format!(
                            "Path = d{}/f{n}.txt\r\nFolder = -\r\nSize = {n}\r\nModified = \
                             2024-05-06 07:08:09.1234567Z\r\nMethod = LZX:15\r\n\r\n",
                            n % 100
                        )
                        .as_bytes(),
                    );
                }
                self.next += 1;
            }
            let n = out.len().min(self.buf.len() - self.at);
            out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    #[test]
    fn reads_as_it_comes() {
        let n = 50_000;
        let mut pipe = std::io::BufReader::new(Pipe {
            n,
            next: 0,
            buf: Vec::new(),
            at: 0,
        });
        let l = parse(
            &mut pipe,
            &NameDecoding::default(),
            &Limits::default(),
            &mut SimpleCtx::new(),
        )
        .unwrap();
        assert_eq!(l.items.len(), n);
        let last = &l.items[n - 1].entry;
        assert_eq!(
            (last.path.as_str(), last.size),
            ("d0/f50000.txt", Some(50_000))
        );
        assert!(
            l.items
                .iter()
                .all(|i| i.entry.method.as_deref() == Some("LZX:15"))
        );
    }

    #[test]
    fn times() {
        let t = |s| parse_time(s).map(|t| since_epoch(Some(t)));
        assert_eq!(
            t("2024-05-06 07:08:09.1234567Z"),
            Some((MTIME, 123_456_700))
        );
        assert_eq!(
            t("2024-05-06 07:08:09.123456789Z"),
            Some((MTIME, nanos(123_456_789)))
        );
        assert_eq!(
            t("2024-05-06 07:08:09.1234567891Z"),
            Some((MTIME, nanos(123_456_789)))
        );
        assert_eq!(t("2024-05-06 07:08:09.00Z"), Some((MTIME, 0)));
        assert_eq!(t("2024-05-06 07:08:09Z"), Some((MTIME, 0)));
        assert_eq!(t("2024-05-06 07:08:09"), Some((MTIME, 0)));
        let before = parse_time("1969-12-31 23:59:59.25Z").unwrap();
        assert_eq!(
            UNIX_EPOCH.duration_since(before).unwrap(),
            Duration::from_millis(750)
        );
        assert!(parse_time("1601-01-01 00:00:00Z").is_some());
        for bad in [
            "",
            "2024-13-01 00:00:00",
            "2024-05-06T07:08:09",
            "2024-05-06 07:08:09.",
            "2024-05-06 07:08:09 Z",
            "2024-05-06 07:08:09Zjunk",
            "+024-05-06 07:08:09",
            "2024-05-06 07:08:6\u{e9}",
            "2024-05-06 24:00:00",
        ] {
            assert_eq!(parse_time(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn modes() {
        assert_eq!(parse_mode("drwxr-xr-x"), Some(0o40755));
        assert_eq!(parse_mode("-rw-r--r--"), Some(0o100644));
        assert_eq!(parse_mode("lrwxrwxrwx"), Some(0o120777));
        assert_eq!(parse_mode("-rwsr-xr-x"), Some(0o104755));
        assert_eq!(parse_mode("-rwSr-Sr-T"), Some(0o107644));
        assert_eq!(parse_mode("dr-xr-xr-t"), Some(0o41555));
        assert_eq!(parse_mode("srw-rw-rw-"), Some(0o140666));
        assert_eq!(parse_mode("?rw-------"), Some(0o600));
        for bad in [
            "",
            "drwxr-xr-y",
            "-wr-r--r--",
            "-rw-r--r-",
            "-rw-r--r--x",
            "xrw-r--r--",
        ] {
            assert_eq!(parse_mode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn attributes() {
        let a = |s| {
            let a = Attributes::parse(s);
            (a.dos, a.mode)
        };
        assert_eq!(a("DLI"), (Some(0x2410), None));
        assert_eq!(a("HS"), (Some(0x6), None));
        assert_eq!(a("RHS8DAdNTsLCOIEV"), (Some(0xFFFF), None));
        assert_eq!(a(""), (None, None));
        // Zip: no letters, the high bits in hex.
        assert_eq!(a(" 01800000"), (Some(0x0180_0000), None));
        // A unix mode after the letters.
        assert_eq!(a("A -rw-r--r--"), (Some(0x20), Some(0o100644)));
        assert_eq!(a("D drwxr-xr-x"), (Some(0x10), Some(0o40755)));
    }

    fn stderr(text: &[u8]) -> (Messages, Error) {
        let m = messages(text);
        let e = m.error(Some(2)).unwrap();
        (m, e)
    }

    #[test]
    fn wrong_passwords() {
        // Each file of a 7z whose data is encrypted.
        let (m, e) = stderr(include_bytes!("testdata/7z-data-wrong-password.err"));
        assert_eq!(m.entries.len(), 3);
        assert_eq!(m.entries[2].path, "tree/sub/nested/deep.txt");
        assert_eq!(e.kind, ErrorKind::WrongPassword);
        assert_eq!(
            e.message,
            "7-Zip: tree/readme.txt: Data Error in encrypted file. Wrong password? (and 2 more)"
        );
        // A 7z whose headers are encrypted: on one line from `l`, two from `t` and `x`.
        for text in [
            &include_bytes!("testdata/7z-headers-wrong-password-l.err")[..],
            &include_bytes!("testdata/7z-headers-wrong-password-t.err")[..],
        ] {
            let (m, e) = stderr(text);
            assert_eq!(
                m.errors.last().unwrap(),
                "Cannot open encrypted archive. Wrong password?"
            );
            assert_eq!(e.kind, ErrorKind::WrongPassword);
            assert_eq!(
                e.message,
                "7-Zip: Cannot open encrypted archive. Wrong password?"
            );
        }
        let (m, e) = stderr(include_bytes!("testdata/zip-aes-wrong-password.err"));
        assert_eq!(m.entries[0].message, "Wrong password");
        assert_eq!(e.kind, ErrorKind::WrongPassword);
    }

    #[test]
    fn damage() {
        let (m, e) = stderr(include_bytes!("testdata/wim-crc.err"));
        assert_eq!(m.entries[0].path, "1/big.bin");
        assert_eq!(e.message, "7-Zip: 1/big.bin: CRC Failed");
        assert_eq!(e.kind, ErrorKind::Corrupt);

        let (m, e) = stderr(include_bytes!("testdata/nsis-data.err"));
        let paths: Vec<_> = m.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["big.bin", "../outside/mtime.txt"]);
        assert_eq!(e.kind, ErrorKind::Corrupt);

        // The archive's flags and an entry's error.
        let (m, e) = stderr(include_bytes!("testdata/cramfs-headers.err"));
        assert_eq!(m.errors, ["Headers Error"]);
        assert_eq!(m.entries[0].message, "Data Error");
        assert_eq!(e.message, "7-Zip: Headers Error");

        // `Cannot open the file as [wim] archive`, and why.
        let (m, e) = stderr(include_bytes!("testdata/wim-truncated.err"));
        assert!(
            m.errors
                .contains(&"Cannot open the file as [wim] archive".to_owned())
        );
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::Corrupt, "7-Zip: Unexpected end of archive")
        );
        let (m, e) = stderr(include_bytes!("testdata/msi-truncated-l.err"));
        assert_eq!(m.warnings, ["There are data after the end of archive"]);
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::Corrupt, "7-Zip: Headers Error")
        );

        let (m, e) = stderr(include_bytes!("testdata/qcow2-truncated.err"));
        assert_eq!(m.entries[0].message, "Unexpected end of data");
        assert_eq!(e.message, "7-Zip: Unexpected end of archive");
        let (_, e) = stderr(include_bytes!("testdata/vhdx-truncated.err"));
        assert_eq!(e.message, "7-Zip: Unexpected end of archive");

        // A cut CHM's files can't be decoded; that it's cut says more.
        let (m, e) = stderr(include_bytes!("testdata/chm-truncated.err"));
        assert_eq!(m.entries[0].kind, ErrorKind::UnsupportedOperation);
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::Corrupt, "7-Zip: Unexpected end of archive")
        );
    }

    #[test]
    fn the_wrong_file() {
        let (m, e) = stderr(include_bytes!("testdata/not-an-archive.err"));
        assert_eq!(
            m.errors,
            ["C:/samples/plain.txt", "Cannot open the file as archive"]
        );
        assert_eq!(e.kind, ErrorKind::UnsupportedFormat);
        assert_eq!(e.message, "7-Zip: Cannot open the file as archive");

        // The archive's path says nothing, whatever its words.
        let (_, e) =
            stderr(b"ERROR: C:/Wrong password/a.7z\r\nCannot open the file as archive\r\n");
        assert_eq!(e.kind, ErrorKind::UnsupportedFormat);
        let (_, e) = stderr(b"ERROR: /data error/a.7z : /data error/a.7z\r\nOdd\r\n");
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::Corrupt, "7-Zip: Odd")
        );

        let (_, e) = stderr(include_bytes!("testdata/missing.err"));
        assert_eq!(e.kind, ErrorKind::NotFound);
        assert_eq!(
            e.message,
            "7-Zip: The system cannot find the file specified."
        );

        let m = messages(include_bytes!("testdata/bad-switch.err"));
        assert_eq!(m.errors, ["Unknown switch: -nosuchswitch"]);
        let e = m.error(Some(7)).unwrap();
        assert_eq!(e.kind, ErrorKind::Io);
        assert_eq!(
            e.message,
            "7-Zip refused its command line (exit code 7): Unknown switch: -nosuchswitch"
        );
    }

    #[test]
    fn names_cant_forge_messages() {
        // Each name holds a `\r` or a line break 7-Zip turned into `_`, then a message.
        let (m, e) = stderr(include_bytes!("testdata/zip-odd-names.err"));
        assert_eq!(m.entries.len(), 11);
        assert!(m.entries.iter().all(|e| e.message == "CRC Failed"));
        assert_eq!(m.entries[1].path, "c\rERROR: Wrong password : d");
        assert_eq!(m.entries[4].path, "h\u{1b}[31mi");
        assert_eq!(m.entries[5].path, "j : k");
        assert_eq!(m.entries[6].path, "ERRORS:");
        assert!(m.errors.is_empty());
        assert_eq!(e.kind, ErrorKind::Corrupt);
        // And each is a name in the listing.
        let l = listing(include_bytes!("testdata/zip-odd-names.slt"));
        for e in &m.entries {
            assert!(l.items.iter().any(|i| i.listed() == e.path), "{:?}", e.path);
        }
    }

    #[test]
    fn exit_codes() {
        assert!(messages(b"").error(Some(0)).is_none());
        let warned = messages(b"\r\nWARNINGS:\r\nThere are data after the end of archive\r\n");
        assert!(warned.error(Some(1)).is_none());
        assert_eq!(warned.warnings.len(), 1);
        assert_eq!(
            messages(b"").error(Some(2)).unwrap().message,
            "7-Zip: failed (exit code 2)"
        );
        assert_eq!(warned.error(Some(2)).unwrap().kind, ErrorKind::Corrupt);
        let e = messages(b"ERROR: Can't allocate required memory!\r\n")
            .error(Some(8))
            .unwrap();
        assert_eq!(e.kind, ErrorKind::LimitExceeded);
        let e = messages(b"\r\nBreak signaled\r\n")
            .error(Some(255))
            .unwrap();
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::Cancelled, "7-Zip was stopped: Break signaled")
        );
        assert_eq!(messages(b"").error(None).unwrap().kind, ErrorKind::Io);
        // Code 0 with an entry's error still fails.
        assert!(
            messages(b"ERROR: CRC Failed : a\r\n")
                .error(Some(0))
                .is_some()
        );
        // An unknown result.
        let m = messages(b"ERROR: Error #12 : a/b\r\n");
        assert_eq!(m.entries[0].message, "Error #12");
        assert_eq!(m.error(Some(2)).unwrap().kind, ErrorKind::Corrupt);
        // The listing's own errors, with stderr's.
        let l = listing(include_bytes!("testdata/pe-nsis.slt"));
        let mut m = messages(b"");
        m.extend(l.messages());
        assert_eq!(
            m.error(Some(2)).unwrap().message,
            "7-Zip: Unexpected end of archive"
        );
    }

    #[test]
    fn kinds() {
        assert_eq!(
            classify("Headers Error in encrypted archive. Wrong password?"),
            ErrorKind::WrongPassword
        );
        assert_eq!(
            classify("Unsupported Method"),
            ErrorKind::UnsupportedOperation
        );
        assert_eq!(
            classify("Cannot open the file as [VMDK] archive"),
            ErrorKind::UnsupportedFormat
        );
        assert_eq!(classify("Is not archive"), ErrorKind::UnsupportedFormat);
        assert_eq!(
            classify("Dangerous link path was ignored"),
            ErrorKind::Unsafe
        );
        assert_eq!(classify("Access is denied."), ErrorKind::Io);
        assert_eq!(classify("something else"), ErrorKind::Corrupt);
    }

    /// One way to change a listing: what to do, where (a fraction of its length), and a byte.
    fn mutation() -> impl Strategy<Value = (u8, u32, u8)> {
        (0u8..9, any::<u32>(), any::<u8>())
    }

    const LINES: &[&str] = &[
        "{",
        "}",
        "--",
        "----",
        "----------",
        "",
        "ERRORS:",
        "WARNINGS:",
        "Path = x",
        "ERROR = ",
        "Comment = ",
        "Size = 1",
        "Folder = +",
        "Type = Ext",
        "ERROR: x",
    ];

    fn mutate(text: &[u8], changes: &[(u8, u32, u8)]) -> Vec<u8> {
        let mut t = text.to_vec();
        for &(op, at, byte) in changes {
            let at = (at as usize) % (t.len() + 1);
            match op {
                0 if at < t.len() => t[at] = byte,
                1 => t.insert(at, byte),
                2 => {
                    let end = (at + usize::from(byte)).min(t.len());
                    t.drain(at..end);
                }
                3 => t.truncate(at),
                4 | 5 => {
                    let line = LINES[usize::from(byte) % LINES.len()];
                    let at = t[..at]
                        .iter()
                        .rposition(|&b| b == b'\n')
                        .map_or(0, |n| n + 1);
                    let crlf = if op == 4 { "\r\n" } else { "\n" };
                    t.splice(at..at, format!("{line}{crlf}").into_bytes());
                }
                6 => {
                    // Repeats a line.
                    let start = t[..at]
                        .iter()
                        .rposition(|&b| b == b'\n')
                        .map_or(0, |n| n + 1);
                    let end = t[at..]
                        .iter()
                        .position(|&b| b == b'\n')
                        .map_or(t.len(), |n| at + n + 1);
                    let line = t[start..end].to_vec();
                    t.splice(start..start, line);
                }
                7 => {
                    // Puts in a piece of another sample: a listing in a comment, say.
                    let other = sample(usize::from(byte) % SAMPLES);
                    let from = (at * 7919) % (other.len() + 1);
                    let piece = &other[from..(from + 4096).min(other.len())];
                    t.splice(at..at, piece.iter().copied());
                }
                _ => {
                    if at < t.len() {
                        t[at] ^= 1 << (byte % 8);
                    }
                }
            }
        }
        t
    }

    fn exercise(text: &[u8]) {
        let limits = Limits {
            max_entries: Some(10_000),
            ..Limits::default()
        };
        if let Ok(l) = parse(
            &mut &text[..],
            &NameDecoding::default(),
            &limits,
            &mut SimpleCtx::new(),
        ) {
            for (n, i) in l.items.iter().enumerate() {
                assert_eq!(i.entry.id, n);
            }
            assert!(l.levels.len() <= MAX_LEVELS);
        }
        let m = messages(text);
        for code in [Some(0), Some(1), Some(2), Some(7), Some(8), Some(255), None] {
            let _ = m.error(code);
        }
    }

    proptest! {
        #[test]
        fn changed_samples_never_panic(
            which in 0..SAMPLES,
            changes in prop::collection::vec(mutation(), 1..12),
        ) {
            exercise(&mutate(sample(which), &changes));
        }

        #[test]
        fn any_bytes_never_panic(text in prop::collection::vec(any::<u8>(), 0..4096)) {
            exercise(&text);
        }

        #[test]
        fn any_lines_never_panic(
            lines in prop::collection::vec((0..LINES.len(), "[ -~\r\t\u{EF80}-\u{EFFF}]{0,12}"), 0..200),
        ) {
            let mut text = String::new();
            for (n, tail) in lines {
                text.push_str(LINES[n]);
                text.push_str(&tail);
                text.push_str("\r\n");
            }
            exercise(text.as_bytes());
        }
    }
}
