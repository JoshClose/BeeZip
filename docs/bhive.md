# The `.bhive` archive format, version 1

`.bhive` is BeeZip's archive format. This is its specification: everything a program needs to
read or write one. A reader needs Zstandard, LZMA2 and XXH3, all of them published and widely
implemented, and this document. [`bhive_reader.py`](bhive_reader.py) is a second reader, in
Python with only the standard library, which BeeZip's tests run against BeeZip's own archives.

- **Status:** a draft until BeeZip 0.8.0 is released. Version 1 is frozen by that release: later
  versions may add coders and features behind flags (§3.1), and every BeeZip reads every
  released version.
- **Why it is built this way** is in [`M13.md`](M13.md), with the measurements behind it.
- **Words:** "must" binds writers; a reader refuses a file that breaks a "must" where §9 says so.

## 1. The design in short

- **Cells.** The files' bytes are packed end to end into *cells* of up to 256 MiB, usually a few
  MiB. Each cell is compressed alone, so any cell can be decoded without another, and several at
  once.
- **Extents.** A file is a list of *extents*, each a run of bytes in one cell. A big file has
  extents in several cells; a file that repeats bytes stored earlier has extents into the cell
  that holds them, so the bytes are stored once.
- **The index** comes last and lists every cell and every entry. A footer at the end of the file
  says where it is. A writer never seeks, so an archive can be written to a pipe; a reader
  starts from the end.
- **Records.** Each cell is preceded by a record with its lengths and checksum, and the entries
  that were completed in it. If the index is lost (a download cut short), the cells before the
  cut can still be listed and extracted from the records alone (§8).

## 2. Conventions

- **Integers** are unsigned and little-endian unless said otherwise: `u8`, `u16`, `u32`, `u64`.
- **`uvarint`** is an unsigned integer below 2^64 in LEB128: seven bits a byte, lowest first, the
  high bit set on every byte but the last. Writers must use the shortest form. More than ten
  bytes, or a value of 2^64 or more, is an error.
- **`svarint`** is a signed integer, zigzag-coded into a `uvarint`: `(n << 1) ^ (n >> 63)`.
- **Offsets** count bytes from the start of the file.
- **Checksums** are XXH3-64 with seed 0 and the default secret, as the
  [xxHash specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md)
  defines it, stored as a `u64`. The checksum of no bytes is `0x2D06800538D394C2`.
- **Reserved** fields and bits: writers must write 0. Readers ignore reserved *fields* and refuse
  reserved *bits* that are set, as §9 lists.

## 3. The file

```
header                16 bytes
cell block            a record, then the cell's data     ┐ any number,
  ...                                                    ┘ cells numbered from 0
index block           a head, then the index
footer                16 bytes
```

Nothing else is in the file: each part starts where the one before ends, and the footer ends
the file.

**A file may be added to in place** by writing more cell blocks after the footer, then a new
index block and footer. BeeZip doesn't write such files yet, but a reader must read
them: it finds the last index from the end of the file, that index's cell table (§6) names
every cell wherever it lies, and earlier index blocks and footers are dead bytes.

### 3.1 Header

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic: `89 42 48 49 56 45 0D 0A` (`\x89BHIVE\r\n`) |
| 8 | 2 | version: `1` |
| 10 | 2 | reserved |
| 12 | 4 | features: a `u32` of bits. Version 1 defines none |

- **The magic's** high bit and line ending expose a transfer that stripped the eighth bit or
  rewrote line endings.
- **A reader must refuse** a version it doesn't know, and a file with a feature bit it doesn't
  know: a feature changes how the file must be read.

### 3.2 Footer

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | index offset: where the index block's head starts |
| 8 | 8 | magic, as in the header |

## 4. Cells

### 4.1 Cell block

A record head of 48 bytes, the journal (§7), then the cell's data.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag: `42 48 43 4C` (`BHCL`) |
| 4 | 4 | number: the cell's number. The first cell block of a file is 0, the next 1, and so on |
| 8 | 4 | raw length: the cell's bytes once decoded, at most 268,435,456 (256 MiB) |
| 12 | 4 | stored length: the bytes of cell data in the file |
| 16 | 1 | coder (§4.2) |
| 17 | 1 | coder parameter (§4.2) |
| 18 | 1 | journal coder: `0` stored, `1` Zstandard |
| 19 | 1 | reserved |
| 20 | 4 | journal items: how many items the journal holds |
| 24 | 4 | journal raw length |
| 28 | 4 | journal stored length: the bytes of journal in the file |
| 32 | 8 | cell checksum: of the cell's raw bytes |
| 40 | 8 | record checksum: of bytes 0 to 39 of this head followed by the journal as stored |

- **A cell may be empty** (raw length 0, stored length 0, coder 0): a record that only carries
  a journal, for entries that add no bytes, such as folders at the end of an archive.
- **A stored journal** has equal raw and stored lengths. A Zstandard one is one frame, under the
  rules of coder 1 below, whatever its length.

### 4.2 Coders

| Coder | Cell data | Parameter |
|---|---|---|
| 0, stored | the raw bytes. Stored length equals raw length | 0 |
| 1, Zstandard | one Zstandard frame ([RFC 8878](https://www.rfc-editor.org/rfc/rfc8878)) | 0 |
| 2, LZMA2 | one raw LZMA2 stream, as in `.xz` and `.7z`: chunks, ended by a `00` byte | the dictionary size |

- **Zstandard:** exactly one frame, no skippable frames, no dictionary, a window of at most
  128 MiB (which every decoder accepts by default). It must decode to exactly the raw length.
  Writers should put the content size in the frame header.
- **LZMA2:** the parameter `p` is the dictionary size as `.xz` encodes it, from 0 to 32:
  `(2 | (p & 1)) << (p / 2 + 11)` bytes, so 0 is 4 KiB and 32 is 256 MiB. The stream holds no
  header of its own: the chunks carry their properties. It must decode to exactly the raw
  length, and nothing may follow its end byte.
- **A coded cell must be smaller than its raw bytes:** for coders 1 and 2, stored length is less
  than raw length. A writer stores a cell that doesn't shrink.
- **A reader can bound its memory before it decodes:** a cell's raw length, plus for LZMA2 the
  dictionary size.

## 5. Index block

A head of 32 bytes, then the index.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag: `42 48 49 58` (`BHIX`) |
| 4 | 1 | coder: `0` stored, `1` Zstandard |
| 5 | 3 | reserved |
| 8 | 8 | stored length: the bytes of index in the file |
| 16 | 8 | raw length |
| 24 | 8 | index checksum: of the index's raw bytes |

- **The footer follows the index at once:** index offset + 32 + stored length + 16 is the
  file's length.
- **A Zstandard index** is one frame, under the rules of coder 1 (§4.2), whatever its length.

## 6. The index

The index's raw bytes, in this order:

| Part | Encoding |
|---|---|
| cell count | `uvarint` |
| cell table | 26 bytes for each cell, in number order |
| entry count | `uvarint` |
| entries | one item (§7) each |
| sections | to the end of the index |

**A cell in the table:**

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | offset of the cell's data |
| 8 | 4 | stored length |
| 12 | 4 | raw length |
| 16 | 1 | coder |
| 17 | 1 | coder parameter |
| 18 | 8 | cell checksum |

- **The table is in file order and nothing overlaps:** each cell's data starts at least 48 bytes
  (a record head) after the cell before it ends, the first at offset 64 or later, and the last
  ends at or before the index block.
- **The index alone is enough to read the archive.** A reader that has it never reads a record.
  The table repeats what the records say; a writer must keep the two the same.
- **Entries are in archive order,** the order the writer was given them. Two entries may have
  the same path; a reader extracting both keeps the later.

**Sections** carry what later versions add without changing how the rest is read. Each is a
`uvarint` id, a `uvarint` length, and that many bytes. A reader skips the ids it doesn't know.
Version 1 defines one:

| Id | Length | Holds |
|---|---|---|
| 1 | 1 | the level the writer was asked for, to show to people: `0` None, `1` Fast, `2` Balanced, `3` High, `4` Max. It changes nothing in how the file is read |

## 7. Items

An item describes one entry: a file, a folder or a symbolic link. The index's entries are
items, and so is a journal: the items of the entries completed while its cell was being
filled, one after another, in order.

| Part | Encoding | Present |
|---|---|---|
| flags | `u8` | always |
| path | `uvarint` length, then that many bytes | always |
| modification time | `svarint` seconds, `uvarint` nanoseconds | flag bit 2 |
| creation time | `svarint` seconds, `uvarint` nanoseconds | flag bit 3 |
| Unix mode | `uvarint` | flag bit 4 |
| DOS attributes | `uvarint` | flag bit 5 |
| extent count | `uvarint` | files |
| extents | for each: `uvarint` cell, `uvarint` offset, `uvarint` length | files |
| link target | `uvarint` length, then that many bytes | symbolic links |

**Flags:**

| Bits | Meaning |
|---|---|
| 0–1 | kind: `0` file, `1` folder, `2` symbolic link. `3` is not used |
| 2 | has a modification time |
| 3 | has a creation time |
| 4 | has a Unix mode |
| 5 | has DOS attributes |
| 6–7 | reserved |

- **Paths** are UTF-8, with `/` between components. A writer should write none that is empty,
  starts or ends with `/`, or has an empty component, `.`, `..` or a NUL. A backslash is a
  character of a name like any other, as it is on Unix. A reader treats a path as it treats
  any archive's: as untrusted. It should replace bytes that aren't UTF-8 rather than fail.
- **Times** count from 1970-01-01T00:00:00Z, without leap seconds: whole seconds, which may be
  negative, and nanoseconds from 0 to 999,999,999 added to them.
- **The Unix mode** is `st_mode`: the permission bits, and the file type bits if the writer has
  them. It is at most 2^32 − 1. A reader takes the entry's kind from the flags, never from the
  mode.
- **DOS attributes** are the low 16 bits of a Windows file's attributes (read-only is bit 0,
  hidden bit 1, system bit 2, archive bit 5).
- **Extents,** one after another, are the file's bytes: `length` bytes at `offset` of cell
  `cell`'s raw bytes. A length is at least 1, and an extent lies wholly inside its cell. The
  file's size is the sum of the lengths, below 2^64. A file of no bytes has no extents.
- **Extents may share bytes.** Two files, or two extents of one file, may name the same bytes
  of a cell. That is how repeated content is stored once, so an archive may hold far more
  bytes than its cells do (§9).
- **A link's target** is the text the link holds, with `/` between components. Readers apply
  their own rules to where a link may point.
- **Not stored in version 1:** hard links as such (a writer stores each name as a file, and
  the bytes once), extended attributes, alternate data streams, ACLs, owners, devices.

**In a journal,** an item's extents name only the record's own cell or earlier ones: an entry
is written into the journal of the cell that was being filled when the entry was completed, and
every byte of it is in the file by then. Every entry of the archive is in exactly one journal,
and the journals taken in cell order list the entries in the index's order.

## 8. Recovery

When the footer or the index is missing or damaged, a reader may rebuild what it can from the
records. It must tell the user that the archive is incomplete.

1. Start at offset 16, after the header, with cell number 0.
2. At a `BHCL` tag, read the record head. Check the number, the lengths against §4 and the end
   of the file, and the record checksum. If the record, its journal and its cell's data are all
   within the file, take the cell and the journal's items, and go on after the cell's data with
   the next number.
3. At a `BHIX` tag, read the index head; if the block and a footer after it are within the file,
   skip them and go on (the file was added to in place, §3). An index block that passes its
   checksum may be used for everything before it.
4. Anything else ends the scan: the end of the file, a tag that is neither, a record that fails
   a check.

Every entry found this way is complete: its bytes are in cells before the cut. A file that was
being written across several cells when the archive was cut is not listed.

## 9. What a reader must check

A reader must refuse the file, or the part named, when:

- **The header:** the magic is wrong; the version or a feature bit is unknown.
- **The footer and index head:** a magic or tag is wrong; the index block and footer don't end
  the file exactly; the index coder is unknown; the index doesn't decode to its raw length or
  fails its checksum.
- **The cell table:** a cell is out of order, overlaps another or the index block, or lies
  outside the file; a raw length is over 256 MiB; a coder is unknown; a parameter is not 0 for
  coders 0 and 1 or is over 32 for coder 2; a stored length isn't the raw length for coder 0,
  or isn't smaller for coders 1 and 2.
- **An item:** a reserved flag bit is set; the kind is 3; nanoseconds are 1,000,000,000 or
  more; a mode or attributes don't fit in 32 bits; an extent has length 0, names a cell that
  isn't in the table, or runs past its cell's raw length; a file's size overflows; in a
  journal, an extent names a later cell.
- **The index as a whole:** a count is larger than the bytes left could hold; bytes are left
  that aren't whole sections.
- **A cell, when it is decoded:** it doesn't decode to exactly its raw length, bytes are left
  over in its stored data, or it fails its checksum. Only the files with extents in that cell
  are lost; the rest of the archive is read.

And a reader should, for its own safety:

- **Bound memory before allocating:** a cell's raw length and dictionary, the index's raw
  length, a journal's raw length.
- **Bound what it extracts.** Because extents may share bytes, a small archive can describe a
  very large tree. BeeZip applies its limits on the extracted size, on the ratio of that size
  to the archive's, and on the number of entries.
- **Treat paths and link targets as untrusted,** as for any archive format.

## 10. Notes for writers

None of this is needed to read a file; it describes what BeeZip writes.

- **Levels.** None stores every cell, in cells of 4 MiB; only the index and the journals are
  compressed. Fast and Balanced use Zstandard at levels 3 and 6 in cells of 4 and 8 MiB. High
  and Max use LZMA2 at xz's presets 6 and 9 in cells of 16 and 64 MiB, with the dictionary no
  larger than the cell.
- **Filling cells.** Files are packed in the order given. A file that fits in a cell is never
  split across two; a bigger one fills cells. At None a file of up to 4 MiB is therefore one
  plain run of bytes in the archive.
- **Repeated content.** From Fast up, BeeZip cuts each file into chunks at content-defined
  points (a gear rolling hash: at least 4 KiB, about 16 KiB, at most 64 KiB) and stores a chunk
  whose BLAKE3 it has seen before as an extent into the cell that holds it. Chunks under
  512 bytes are stored where they fall. Neither the chunking nor the hash is part of the format:
  a reader sees only extents.
- **Cells that barely shrink** are stored, so that reading them back is a copy: below Max, a
  cell that isn't smaller by a sixty-fourth. At High, a cell is first tried with Zstandard 3,
  and stored if that saves under 2 %, without LZMA2's time being spent on it.
- **Edits** (add, remove, rename) write a new file and swap it in. A cell is copied as it
  is stored, under its new number and behind a new record, while at least half its raw
  bytes are still used; one that keeps less is decoded and what is left stored again; one
  that nothing uses is dropped. Each kept entry goes into the journal of a cell no earlier
  than its bytes, in the entries' order, so the records list the archive as before.
- **The same input gives the same bytes** on any number of threads: files are placed in order
  on one thread, and only reading, hashing and compressing are shared out.

## 11. Examples

Two small archives, byte for byte. Both are in BeeZip's repository
(`tests/fixtures/bhive/spec-empty.bhive` and `spec-small.bhive`), where a test checks that the
bytes listed here are the files', and that BeeZip and `bhive_reader.py` read them as described.
Neither holds compressed data, so every byte can be accounted for. Each line is an offset, the
bytes there, and what they are.

**An archive of nothing:** a header, an index block and a footer, 66 bytes.

<!-- bytes of spec-empty.bhive -->
```
0000  89 42 48 49 56 45 0d 0a              magic
0008  01 00                                version 1
000a  00 00                                reserved
000c  00 00 00 00                          features: none
; the index block
0010  42 48 49 58                          tag "BHIX"
0014  00                                   coder 0: the index is stored
0015  00 00 00                             reserved
0018  02 00 00 00 00 00 00 00              stored length 2
0020  02 00 00 00 00 00 00 00              raw length 2
0028  05 55 28 1f 0e 23 25 33              index checksum, of the 2 bytes that follow
0030  00                                   the index: no cells
0031  00                                   no entries
; the footer
0032  10 00 00 00 00 00 00 00              index offset 16
003a  89 42 48 49 56 45 0d 0a              magic
```

**A folder, two files and a link,** 332 bytes. `docs/a.txt` holds `honey` and a line feed,
`docs/b.txt` holds `honeycomb` and a line feed, and the cell stores only the second: the first
file is two extents of it.

<!-- bytes of spec-small.bhive -->
```
0000  89 42 48 49 56 45 0d 0a              magic
0008  01 00                                version 1
000a  00 00                                reserved
000c  00 00 00 00                          features: none
; cell block 0: the record head
0010  42 48 43 4c                          tag "BHCL"
0014  00 00 00 00                          number 0
0018  0a 00 00 00                          raw length 10
001c  0a 00 00 00                          stored length 10
0020  00                                   coder 0: stored
0021  00                                   coder parameter
0022  00                                   journal coder 0: stored
0023  00                                   reserved
0024  04 00 00 00                          journal items 4
0028  5b 00 00 00                          journal raw length 91
002c  5b 00 00 00                          journal stored length 91
0030  14 37 98 42 06 65 4e 0e              cell checksum, of the cell's 10 bytes
0038  12 96 db 66 7b 11 f9 47              record checksum, of the 40 bytes above and the journal
; the journal: four items
0040  05                                   flags: a folder (1) with a modification time (4)
0041  04 64 6f 63 73                       path, 4 bytes: "docs"
0046  80 e4 ad 95 0d                       seconds 1,767,225,600: 2026-01-01T00:00:00Z
004b  00                                   nanoseconds 0
004c  04                                   flags: a file (0) with a modification time (4)
004d  0a 64 6f 63 73 2f 61 2e 74 78 74     path, 10 bytes: "docs/a.txt"
0058  80 e4 ad 95 0d 00                    the same time
005e  02                                   2 extents
005f  00 00 05                             cell 0, offset 0, length 5: "honey"
0062  00 09 01                             cell 0, offset 9, length 1: the line feed
0065  14                                   flags: a file with a modification time (4) and a Unix mode (16)
0066  0a 64 6f 63 73 2f 62 2e 74 78 74     path: "docs/b.txt"
0071  82 e4 ad 95 0d                       seconds 1,767,225,601
0076  80 ca b5 ee 01                       nanoseconds 500,000,000
007b  a4 83 02                             Unix mode 0o100644
007e  01                                   1 extent
007f  00 00 0a                             cell 0, offset 0, length 10: the whole cell
0082  06                                   flags: a link (2) with a modification time (4)
0083  06 6c 61 74 65 73 74                 path: "latest"
008a  80 e4 ad 95 0d 00                    time
0090  0a 64 6f 63 73 2f 62 2e 74 78 74     target, 10 bytes: "docs/b.txt"
; the cell's data
009b  68 6f 6e 65 79 63 6f 6d 62 0a        "honeycomb" and a line feed
; the index block
00a5  42 48 49 58                          tag "BHIX"
00a9  00                                   coder 0: stored
00aa  00 00 00                             reserved
00ad  77 00 00 00 00 00 00 00              stored length 119
00b5  77 00 00 00 00 00 00 00              raw length 119
00bd  48 6a ae 52 fc 9b e9 17              index checksum
; the index
00c5  01                                   1 cell
00c6  9b 00 00 00 00 00 00 00              its data is at offset 155
00ce  0a 00 00 00                          stored length 10
00d2  0a 00 00 00                          raw length 10
00d6  00                                   coder 0
00d7  00                                   coder parameter
00d8  14 37 98 42 06 65 4e 0e              cell checksum
00e0  04                                   4 entries
00e1  05 04 64 6f 63 73 80 e4 ad 95 0d 00  the four items, as in the journal
00ed  04 0a 64 6f 63 73 2f 61 2e 74 78 74
00f9  80 e4 ad 95 0d 00 02 00 00 05 00 09
0105  01 14 0a 64 6f 63 73 2f 62 2e 74 78
0111  74 82 e4 ad 95 0d 80 ca b5 ee 01 a4
011d  83 02 01 00 00 0a 06 06 6c 61 74 65
0129  73 74 80 e4 ad 95 0d 00 0a 64 6f 63
0135  73 2f 62 2e 74 78 74
; the footer
013c  a5 00 00 00 00 00 00 00              index offset 165
0144  89 42 48 49 56 45 0d 0a              magic
```
