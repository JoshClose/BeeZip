# The `.bhive` archive format, version 1

`.bhive` is BeeZip's archive format. This is its specification: everything a program needs to
read or write one. A reader needs Zstandard, LZMA2 and XXH3, all of them published and widely
implemented, and this document. Encrypted archives (§12) and signatures (§13) need standard
primitives too: AES-256-GCM, SHA-256, HMAC, HKDF and Argon2id, and the public-key algorithms of
the slots and signatures a reader supports. [`bhive_reader.py`](bhive_reader.py) is a second
reader, in Python with only the standard library, which BeeZip's tests run against BeeZip's own
archives.

- **Status:** a draft until BeeZip 0.8.0 is released. Version 1 is frozen by that release: later
  versions may add coders and features behind flags (§3.1), and every BeeZip reads every
  released version. Encryption (§12) and signatures (§13) are drafts until BeeZip 0.9.0 is
  released, and part of version 1 from then.
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
| 12 | 4 | features: a `u32` of bits. Bit 0: the archive is encrypted (§12). The others are reserved |

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
Writers write sections in increasing order of id, each id at most once. An even id describes
the contents, and signatures cover it (§13.1); an odd id describes the file or who can open
it, and they don't. Version 1 defines:

| Id | Length | Holds |
|---|---|---|
| 1 | 1 | the level the writer was asked for, to show to people: `0` None, `1` Fast, `2` Balanced, `3` High, `4` Max. It changes nothing in how the file is read |
| 2 | 32 a cell | the SHA-256 of each cell's stored bytes (§13.2) |
| 3 | any | the signatures (§13.3) |
| 5 | any | in an encrypted archive, what each slot is, for people (§12.9) |

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
- **An encrypted archive** (§12.10) and **cell digests** (§13.2): as those sections say.

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

## 12. Encryption

An archive with feature bit 0 set is encrypted. Everything about its contents is sealed: paths,
sizes, times, attributes, checksums, which bytes repeat, and the bytes themselves. What stays
in the clear is that it is an encrypted `.bhive`, its size, how many cells it has and roughly
how big they are, and how many slots it has and of which kinds. Why it is built this way is
in [`M14.md`](M14.md).

```
header                16 bytes, features bit 0
key block             'BHKY': the suite, the archive id, the slots, the header MAC
cell block            'BHCE': the sealed record, then the sealed cell     ┐ any number,
  ...                                                                     ┘ cells numbered from 0
index block           'BHIE': a salt, then the sealed index
footer                16 bytes, as in §3.2
```

The footer's index offset is where the `BHIE` block starts. A file may be added to in place as
§3 says, with `BHCE` blocks, then a new `BHIE` block and footer.

### 12.1 Primitives

Suite 1, the only one so far:

- **AES-256-GCM** ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)) with
  12-byte nonces. A sealed message is its ciphertext followed by its 16-byte tag.
- **SHA-256, HMAC-SHA256** and **HKDF-SHA256** ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)).
  `HKDF(ikm, salt, info)` below is Extract then Expand, 32 bytes unless said.
- **Labels** are ASCII with no terminator: `"bhive1 mac"` is 10 bytes.
- **Random values** (keys, ids, salts) come from a cryptographic random generator.

### 12.2 Keys

The **file key** `K` is 32 random bytes. Everything is sealed under keys derived from it:

| Key | Derivation |
|---|---|
| header MAC key | `HKDF(K, archive id, "bhive1 mac")` |
| record key | `HKDF(K, archive id, "bhive1 record")` |
| a cell's key | `HKDF(K, the cell's id, "bhive1 cell")` |
| the index key | `HKDF(K, the index block's salt, "bhive1 index")` |

- **The archive id** is 32 random bytes, new for every file written: an edit that writes a new
  file gives it a new id, though it keeps `K` and the slots.
- **A cell's id** is 32 random bytes, new for every cell a writer packs. A cell copied as it is
  stored into another file (an edit) keeps its id and its sealed bytes; a cell decoded and
  stored again gets a new id. An id never seals two different contents.

### 12.3 Key block

Right after the header.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag: `42 48 4B 59` (`BHKY`) |
| 4 | 1 | suite: `1` |
| 5 | 1 | reserved |
| 6 | 2 | slot count, 1 to 64 |
| 8 | 4 | slots length: the bytes of slots that follow, at most 65,536 |
| 12 | 32 | archive id |
| 44 | n | the slots (§12.4), one after another |
| 44 + n | 32 | header MAC |

The **header MAC** is HMAC-SHA256 under the header MAC key over the file's first 60 + n bytes:
the header and the key block up to the MAC. It is what binds the slots, and the file key, to
the archive: a reader checks it as soon as a slot gives it `K`, before it uses anything else.

### 12.4 Slots

A slot opens the archive: it holds `K` wrapped under a key that only its secret `S` gives.
Every slot of an archive opens it.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | kind (§12.5) |
| 1 | 1 | reserved |
| 2 | 2 | body length: the bytes after these 4 |
| 4 | p | public part, as the kind says |
| 4 + p | 32 | commitment |
| 36 + p | 48 | the file key, wrapped |

From the slot's secret `S`:

1. `context = SHA-256("bhive1 slot" ‖ the slot's first 4 + p bytes ‖ recipient key)`, where the
   recipient key is the X25519 or EC public key for kinds 3, 6 and 7 (§12.5), and nothing
   for the others.
2. `PRK = HMAC-SHA256(key = context, message = S)`: HKDF's Extract, with the context as salt.
3. `wrap key ‖ commitment = HKDF-Expand(PRK, "bhive1 slot", 64)`.
4. The wrapped file key is AES-256-GCM of `K` under the wrap key, with a nonce of 12 zero bytes
   and the slot's first 4 + p bytes as associated data. A wrap key seals only this.

A reader compares the commitment first, in constant time: a different one means the secret is
not this slot's, and it tries the next. A matching commitment whose wrapped key fails to open,
or a `K` whose header MAC fails, means the file is damaged. Step 2 is what Windows computes
inside CNG with `BCRYPT_KDF_HMAC` and the context as `KDF_HMAC_KEY`, so a smart card's or TPM's
shared secret never leaves it.

A reader skips slots of kinds it doesn't know (the header MAC covers them), and says the
archive was made by a newer program when no slot it knows is left.

### 12.5 Slot kinds

| Kind | Opened by | Public part | `S` |
|---|---|---|---|
| 1 | a password | 48 bytes: `13`, 3 reserved, memory (`u32`, KiB), passes (`u32`), lanes (`u32`), salt (32) | Argon2id |
| 2 | a recovery key | a salt (32) | the key's 16 bytes |
| 3 | an X25519 private key | the ephemeral share (32) | the X25519 shared secret |
| 4 | an X-Wing private key | the X-Wing ciphertext (1,120) | the X-Wing shared secret |
| 5 | an RSA private key | tag (4), ciphertext length (`u16`), ciphertext | 32 random bytes |
| 6 | an EC P-256 private key | tag (4), the ephemeral public key (65) | the ECDH shared secret (32) |
| 7 | an EC P-384 private key | tag (4), the ephemeral public key (97) | the ECDH shared secret (48) |
| 8 | a FIDO2 authenticator | flags (`u8`), reserved (`u8`), credential id length (`u16`) and id, relying party length (`u8`) and id, salt (32) | the hmac-secret output (32) |

- **1, a password.** `S` is Argon2id ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106),
  version `0x13`) of the password in Unicode NFC as UTF-8, with the slot's salt, memory, passes
  and lanes, a 32-byte tag, and no secret or associated data. Readers refuse memory over
  4,194,304 KiB (4 GiB) or under 8 KiB a lane, passes outside 1 to 16, lanes outside 1 to 16.
  BeeZip writes 1,048,576 KiB, 2 passes and 4 lanes (Standard), or 2,097,152 KiB, 3 passes and
  4 lanes (Strong).
- **2, a recovery key.** 16 random bytes `k`, shown as 8 groups of 6 digits joined by hyphens:
  group `i` is `(k[2i] + 256 × k[2i + 1]) × 11`, with leading zeros. A reader takes any
  separators, needs 48 digits, and refuses a group that isn't a multiple of 11 or is 720,896 or
  more. The salt makes each slot's context its own.
- **3, X25519** ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)). The writer makes a fresh
  secret `e`; the share is `X25519(e, 9)` and `S = X25519(e, recipient)`; the reader computes
  `X25519(its secret, share)`. An all-zero `S` is refused. The recipient key in the context is
  the recipient's 32-byte public key. The slot doesn't say whose it is: a reader tries its keys.
- **4, X-Wing** ([draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/),
  ML-KEM-768 with X25519). The ciphertext and `S` are X-Wing's Encapsulate of the recipient's
  1,216-byte public key; the reader decapsulates with its 32-byte X-Wing private key. Anonymous,
  as kind 3.
- **5, RSA.** `S` is 32 random bytes, encrypted with RSAES-OAEP
  ([RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)), SHA-256 and MGF1 with SHA-256, and an
  empty label. The ciphertext is as long as the modulus: 256 bytes or more (2,048 bits or
  more), at most 1,024.
- **6 and 7, EC.** The writer makes a fresh key pair on the curve; the public part holds its
  public key uncompressed (`04 ‖ x ‖ y`), and `S` is the x-coordinate of the shared point,
  big-endian (SEC 1 §3.3.1). The recipient key in the context is the recipient's public key,
  uncompressed. A reader refuses a point that isn't on the curve.
- **Tags** (kinds 5 to 7) say which certificate or key a slot is for, so that a reader finds the
  right one before asking for a PIN: the first 4 bytes of HMAC-SHA256 with key
  `SHA-256(SPKI)` over `"bhive1 tag" ‖ kind ‖ the ciphertext or ephemeral public key`, where
  SPKI is the recipient's SubjectPublicKeyInfo in DER (a certificate's, or a key's that has
  none). Only someone with that public key can tell which slot is whose.
- **8, FIDO2.** `S` is the authenticator's hmac-secret output
  ([CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)
  §12.5) for the credential, relying party and salt in the slot. Flag bit 0 clear: the salt
  goes to the authenticator as it is. Bit 0 set: the salt is a WebAuthn PRF input, and the
  authenticator gets `SHA-256("WebAuthn PRF" ‖ 00 ‖ salt)`, as WebAuthn's `prf` extension
  does. Bit 1: user verification is required (BeeZip always sets it). The other bits are
  reserved. A credential id is 1 to 1,023 bytes, a relying party id 1 to 253.

### 12.6 Cell blocks

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag: `42 48 43 45` (`BHCE`) |
| 4 | 4 | sealed record length, r |
| 8 | 4 | sealed cell length, c |
| 12 | r | the sealed record |
| 12 + r | c | the sealed cell |

- **The sealed record** is AES-256-GCM under the record key of the cell's id (32 bytes), its
  §4.1 record head (48 bytes, from its `BHCL` tag to its record checksum) and its journal as
  stored. The nonce is the block's offset in the file as a `u64` and 4 zero bytes; the
  associated data is the block's first 12 bytes. So `r` is 96 more than the journal's stored
  length.
- **The sealed cell** is the cell's stored bytes, sealed under the cell's key in segments
  (§12.8). The record head's stored length is the length before sealing.

### 12.7 Index block

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | tag: `42 48 49 45` (`BHIE`) |
| 4 | 4 | reserved |
| 8 | 8 | sealed length, s |
| 16 | 32 | salt: 32 random bytes, new for every index block |
| 48 | s | the sealed index |

- **The footer follows at once:** index offset + 48 + s + 16 is the file's length.
- **The sealed index** is a §5 index block, its 32-byte head and its stored index, sealed
  under the index key in segments (§12.8), each with the header MAC and the block's first 48
  bytes as associated data.
- **The index inside** is §6's, with two differences. Each cell-table row is 58 bytes: §6's 26,
  then the cell's id. A row's offset is where its sealed cell starts, and its stored length is
  before sealing. And it may carry section 5 (§12.9).
- **The table's order rule** (§6) becomes: each sealed cell starts at least 108 bytes (a block
  head and the smallest sealed record) after the one before it ends, the first at least 108
  bytes after the key block, and the last ends at or before the index block.

### 12.8 Segments

A cell's stored bytes and an index block's plaintext are each sealed in segments of 1,048,576
bytes (1 MiB), the last one shorter or as long; no bytes at all are one empty segment.
Segment `i`, from 0, is AES-256-GCM under its key with the nonce `i` as a `u64`, 3 zero bytes,
and `01` for the last segment or `00` for the others. Each segment is checked before any of
its bytes are used, so a cut, reordered or swapped segment fails, and a decoder never sees a
byte that hasn't been checked.

A reader splits a sealed length `c` into `n = max(1, ⌈c / 1,048,592⌉)` segments: all but the
last are 1,048,592 bytes (1 MiB and a tag), and the last is the rest, which must be at least
16 bytes, and more than 16 when `n` is more than 1.

Cells are sealed with no associated data, so a cell can be copied into another file as it is;
the index, which names every cell by its id, holds them to this archive.

### 12.9 Slot descriptions (index section 5)

What each slot is, for people who can open the archive, and for rebuilding the slots when the
file key changes. A `uvarint` count, the slot count, then for each slot in the key block's
order a `uvarint` length and that many bytes of fields: each a `uvarint` tag, a `uvarint`
length and the value, tags in increasing order, each at most once.

| Tag | Value |
|---|---|
| 1 | a label: UTF-8, what the writer called this way in ("Password", a person's name) |
| 2 | the recipient's public key: 32 bytes (kind 3) or 1,216 (kind 4) |
| 3 | the recipient's certificate in DER, or the SubjectPublicKeyInfo of a key with none (kinds 5 to 7) |
| 4 | empty: this way in is bound to one machine (a TPM key, Windows Hello) |

A reader skips tags it doesn't know. Descriptions are what the writer said, and play no part
in opening the archive.

### 12.10 What a reader checks

In addition to §9, a reader must refuse the file, or the part named, when:

- **The key block:** the tag is wrong, the suite is unknown, the slot count is 0 or over 64,
  the slots length is over 65,536 or isn't the sum of the slots, a slot's body is shorter than
  80 bytes or its public part doesn't have its kind's length, a password slot's costs are over
  the limits (§12.5).
- **The header MAC** fails once a slot has opened: the file is damaged, whichever slot it was.
- **A sealed part** fails: the record before its journal is read, each segment before its bytes
  are used. A segment that fails loses its cell's files, as a checksum does (§9); a failing
  index loses the archive, as in §9.
- **The index block:** the tag is wrong, or it and the footer don't end the file exactly.

**Recovery** (§8) goes frame by frame, given a way in: from the end of the key block, at a
`BHCE` tag the record opens with its offset as the nonce, which gives the cell's id and
record; at a `BHIE` tag the block is skipped by its sealed length.

### 12.11 Example

`spec-small.bhive`'s folder, files and link, encrypted, with one slot: the password `honey`, at
a cost far below what BeeZip writes so that a test can open it quickly. The file key, ids and
salts are listed in `tests/fixtures/bhive-m14/vectors.json` (`sealed_example`), with the
plaintexts, and every slot kind has its own vector there (`slots`), as do the keys (`keys`) and
a two-segment cell (`segments`). Those are made by
`tests/fixtures/bhive-m14/make-vectors.py`, a separate implementation in Python. Inside the
sealed index the cell's row is offset `0x01a7`, the cell's id, and §6's other fields, and the
index ends with section 5, labelling the slot `Password`. 726 bytes:

<!-- bytes of spec-sealed.bhive -->
```
0000  89 42 48 49 56 45 0d 0a              magic
0008  01 00                                version 1
000a  00 00                                reserved
000c  01 00 00 00                          features: bit 0, encrypted
; the key block
0010  42 48 4b 59                          tag "BHKY"
0014  01                                   suite 1: AES-256-GCM, HKDF-SHA256, HMAC-SHA256
0015  00                                   reserved
0016  01 00                                1 slot
0018  84 00 00 00                          slots length 132
001c  63 ca d1 2e ad 70 08 88 bf 7e 93 24  archive id
0028  f2 b4 a7 5e 72 0b 3f 04 4d 51 2b b5
0034  28 8e 4a c8 4c 7c d9 b8
; slot 0: a password
003c  01                                   kind 1: a password
003d  00                                   reserved
003e  80 00                                body length 128
0040  13                                   Argon2 version 0x13
0041  00 00 00                             reserved
0044  00 01 00 00                          memory 256 KiB (BeeZip writes 1 GiB or 2 GiB)
0048  02 00 00 00                          2 passes
004c  04 00 00 00                          4 lanes
0050  5f 3c df 76 37 49 08 d2 e4 4a 6d 10  salt
005c  3e 99 c1 e2 66 10 1d 47 aa 38 7c db
0068  e7 68 b4 80 b4 20 da 98
0070  25 c2 24 33 da cb 27 42 89 7d a0 3b  commitment
007c  e7 3e 13 93 eb c6 bc e3 1e 79 67 76
0088  26 8a 4b 04 f7 39 44 4b
0090  46 a7 ed 33 41 7c cf af 05 29 5d 22  the file key, wrapped, and its tag
009c  67 0d c9 d1 c4 52 ae b7 df 06 7f e4
00a8  a6 c5 75 8a 11 16 60 1f dc 9f 1f f4
00b4  6e 8b 63 fb 8e 6e 6a 0e 99 48 bc b3
00c0  22 64 ec 7a 12 78 2e f9 06 a6 43 bb  header MAC, of the 60 + 132 bytes above
00cc  11 f9 00 73 13 e4 f1 a2 54 90 73 cb
00d8  ac a1 d0 4f f2 41 e0 3a
; cell block 0
00e0  42 48 43 45                          tag "BHCE"
00e4  bb 00 00 00                          sealed record length 187
00e8  1a 00 00 00                          sealed cell length 26
00ec  29 a3 b3 f8 69 91 c8 37 a2 d3 ca cb  the sealed record: cell id, record head, journal, tag
00f8  51 d8 bb d4 13 5b e5 de a3 70 3e ea
0104  18 f1 2b f7 19 d5 d9 b5 3f 77 7d 39
0110  36 84 86 8b 00 36 57 41 77 aa 3c 34
011c  24 f2 f8 f9 82 b1 41 b1 70 11 9e 97
0128  1f ac 49 3d 94 38 62 bc 94 b8 b6 4e
0134  b3 68 9d 4d 4c 29 75 f5 8e 72 6b 3d
0140  ad 35 2e e7 1d 96 7a ed 48 3b 0c 19
014c  52 f8 d3 2c 33 5b 4a e8 b6 a1 da 1b
0158  29 70 f4 90 11 7c 98 d1 12 f1 aa 06
0164  14 26 71 ad 54 3e 67 aa 27 4e 42 21
0170  02 2c 3f fb 52 02 59 fc 61 3b 91 fa
017c  7b 04 3a 9a c4 23 e3 23 bf 78 84 d9
0188  37 25 8f 1d 41 34 ca 30 5a b6 43 f3
0194  d2 dd 13 77 23 00 0c 24 44 d6 03 0c
01a0  16 a0 ca 1b ad 87 50
01a7  01 1e c1 cf 51 16 d1 1f 9c ee f5 da  the sealed cell: one segment of 10 bytes, and its tag
01b3  1c 74 3f 90 8c 7c e1 b2 6d ac f1 52
01bf  c5 a0
; the index block
01c1  42 48 49 45                          tag "BHIE"
01c5  00 00 00 00                          reserved
01c9  d5 00 00 00 00 00 00 00              sealed length 213
01d1  ca b2 e0 4a 20 77 69 c0 c9 f8 62 5d  salt
01dd  2a 4d 9b e7 9a 14 b1 0f 50 0d 40 41
01e9  0c ad 4d 2c 95 be ad e6
01f1  5d f5 8d eb 07 73 3e 24 2d 3f 14 4e  the sealed index: its head, the index, and the tag
01fd  47 66 ba fd f9 4e cc 08 53 d9 b8 1b
0209  55 3e 02 93 27 b7 24 33 4e d9 b3 8a
0215  70 fb 3c 1c e6 9d 8c 3a f5 d0 a6 49
0221  21 e4 6a f4 b4 1b 1a 00 12 79 41 d5
022d  2f 0e 44 1a 7e 13 11 b7 17 cc b7 55
0239  0f 28 62 39 e1 4c 6c 19 06 df 1f 6f
0245  a7 c5 a1 df 3c 5d 33 2c ac 63 97 97
0251  95 2f 7a b2 fe 52 26 94 3d e9 93 8b
025d  a3 8e 54 1b ba 85 5e c5 ef 1a 09 43
0269  6d 03 af 2c 88 8c fe d9 57 61 6c f6
0275  18 37 f7 23 e5 a0 22 01 fc 2f 63 16
0281  18 5a 59 69 05 bd 7f d4 22 57 69 d3
028d  04 11 cf 33 a9 4b d5 fe c4 98 6c 1f
0299  87 ed 48 f0 56 77 28 db ee 8f 8d 0e
02a5  29 a9 98 a7 15 39 ac 0d bc 92 01 ab
02b1  8b 47 49 21 6b 99 4f e9 52 ee be 5e
02bd  c6 75 8a a1 4b 63 ef 48 0e
; the footer
02c6  c1 01 00 00 00 00 00 00              index offset 449
02ce  89 42 48 49 56 45 0d 0a              magic
```

## 13. Signatures

A signature says who made an archive's contents, and that they haven't changed since. Any
`.bhive` can carry any number, encrypted or not. They are two index sections, not a feature: a
reader that doesn't know them skips them and reads the archive, unchecked.

### 13.1 What is signed

The *manifest*, which covers the contents and nothing about where they lie: SHA-256 of

| Part | Bytes |
|---|---|
| a label | `"bhive1 manifest"` |
| the cells | the cell count as a `u64`; then for each cell, in number order: raw length (`u32`), coder (`u8`), coder parameter (`u8`), checksum (`u64`) |
| the entries | the entry count as a `u64`, the entries' length in bytes as a `u64`, and the entries exactly as the index encodes them |
| the even sections | for each section with an even id, in the index's order: its id and length as `uvarint`s, and its bytes |

Section 2 is even, so the cells' digests, and through them every stored byte, are covered.
Cell offsets, cell ids, the sealing, the slots and section 5 are not. So adding or removing a
way in, a new file key, and encrypting a signed archive keep its signatures, as long as the
cells are kept in order; any change to the entries or the cells drops them.

### 13.2 Cell digests (index section 2)

32 bytes for each cell in the table, in order: the SHA-256 of its stored bytes, before any
sealing. A reader that knows section 2 checks each cell against it before decoding it; a cell
that doesn't match is damaged, as for a checksum (§9). A section 2 whose length isn't 32 times
the cell count is refused, and the archive's signatures with it.

### 13.3 Signature section (index section 3)

A `uvarint` count, then for each signature a `uvarint` length and that many bytes:

| Part | Encoding |
|---|---|
| algorithm | `u8` (§13.4) |
| reserved | `u8` |
| signer | `uvarint` length and bytes: the public key, or the certificates |
| signed attributes | `uvarint` length and bytes |
| signature | `uvarint` length and bytes |
| unsigned attributes | `uvarint` length and bytes |

- **Attributes** are fields, each a `uvarint` tag, a `uvarint` length and the value, tags in
  increasing order, each at most once. A reader keeps the ones it doesn't know and ignores
  them.
- **Signed attribute 1** is the time the signer says it signed, as `svarint` seconds since
  1970-01-01T00:00:00Z. It is claimed, not proved.
- **Unsigned attribute 1** is reserved for an RFC 3161 time-stamp token over the SHA-256 of the
  signature bytes. BeeZip doesn't write it yet.
- **The message signed** is 113 bytes: `"bhive1 signature"`, the algorithm byte, the manifest,
  the SHA-256 of the signer bytes, and the SHA-256 of the signed attributes' bytes.

### 13.4 Algorithms

| Algorithm | Signer | Signature |
|---|---|---|
| 1, ML-DSA-65 and Ed25519 | the Ed25519 public key (32) and the ML-DSA-65 public key (1,952) | Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) of the message (64), then ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) of the message with the context `"bhive1"` (3,309). Both must verify |
| 2, RSA-PSS | certificates | RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-byte salt; as long as the modulus (2,048 bits or more) |
| 3, RSA PKCS #1 v1.5 | certificates | RSASSA-PKCS1-v1_5 with SHA-256, for keys that can't do PSS |
| 4, ECDSA P-256 | certificates | ECDSA with SHA-256: `r ‖ s`, 32 bytes each |
| 5, ECDSA P-384 | certificates | ECDSA with SHA-384: `r ‖ s`, 48 bytes each |

- **Certificates** as a signer are a `uvarint` count, 1 to 8, then each certificate as a
  `uvarint` length and its DER, the signer's first and the ones that issued it after. The
  signature is checked with the first one's public key.
- **A signature verifies** when its algorithm is known, its signature checks against the
  message, and section 2 is present and whole. A reader reports a signature of an unknown
  algorithm as one it couldn't check, not as one that failed.
- **Whom to trust** is for the program that reads, not the format: BeeZip trusts your own
  keys, your contacts, and certificates whose chain the system trusts (`M14.md` §11).

### 13.5 For people

Not needed to read a file; how BeeZip shows and writes signing keys.

- **A fingerprint** is the first 10 bytes of the SHA-256 of the signer bytes, in base32
  ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)) as 16 characters in groups of four:
  `VCPC-QSVP-2XKC-VCIZ`.
- **A BeeZip signing key** (algorithm 1) is written as Bech32 with no length limit (BIP 173's
  checksum): the public key as `bzsig1…` of its 1,984 signer bytes, the private key as
  `BZSIG-SECRET-KEY-1…` of its Ed25519 seed and ML-DSA-65 seed, 32 bytes each.

### 13.6 Example

`tests/fixtures/bhive-m14/spec-signed.bhive` is `spec-small.bhive` with sections 2 and 3 after
its entries, 5,744 bytes, signed with algorithm 1 at 2026-01-01T00:00:00Z by the key whose
seeds are in `vectors.json` (`signed_example`), with the manifest, the message, both halves of
the signature and the fingerprint above. ML-DSA-65 is signed deterministically there so the
bytes can be made again; BeeZip signs with fresh randomness, as FIPS 204 recommends. Any reader
of version 1 reads it as it reads `spec-small.bhive`.
