#Requires -Version 7
<#
.SYNOPSIS
Fetches M5's third-party fixtures for cpio, ar, RPM, CAB, LHA, .Z, lzop and ISO into
tests/fixtures/thirdparty/{libarchive/<fmt>,delharc,packages}, and records them in manifest.json
(docs/M5.md §10).

.DESCRIPTION
  libarchive 3.8.11 (BSD-2-Clause)  libarchive's, bsdcpio's, bsdcat's and bsdtar's test/*.uu at
                                    the v3.8.11 tag, uudecoded, into libarchive/<fmt>/. The
                                    broken ones go to libarchive/<fmt>/broken/ and aren't in the
                                    manifest; broken/README.md says what each must fail with.
  delharc 0.8.0 (MIT OR Apache-2.0) a subset of the crate's tests/ archives (most copied from
                                    lhasa), at the v0.8.0 tag, into delharc/.
  packages (MIT)                    four small noarch packages of python3-six from Fedora,
                                    AlmaLinux (EL 8), Ubuntu and Debian, into packages/.

Every file is checked against the SHA-256 below. The expected entries come from 7-Zip 26.00
(`7z l -slt`, and `7z x` for the bytes) where it reads the format, cross-checked against
oracles.py, which parses the headers itself (7-Zip alone for ISO, whose names and Rock Ridge
links it reads); any disagreement stops the script unless the
fixture's `note` explains it. Where 7-Zip can't read a fixture, the record says in `note` where
its values came from instead: liblzo2 (WSL's, through ctypes) for lzop, delharc 0.8.0 for the
LHA methods 7-Zip lacks (the table in $delharcData, made by a throwaway program against
delharc = "=0.8.0" and checked against delharc's own tests), libarchive's test sources, or
oracles.py. `7z_test` is what `7z t` said of the fixture.

Needs WSL (Ubuntu 24.04: python3, liblzo2-2, dpkg-deb and gzip) for lzop and the debs, and
Windows' Python 3.14 (`python`) for oracles.py, whose zstd comes from the standard library.

.PARAMETER Record
Print the SHA-256 table for the files as fetched, instead of checking it.
#>
param([switch]$Record)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sevenZip = 'C:\Program Files\7-Zip\7z.exe'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$tag = 'v3.8.11'
$laBase = "https://raw.githubusercontent.com/libarchive/libarchive/$tag"
$dhTag = 'v0.8.0'
$dhBase = "https://raw.githubusercontent.com/royaltm/rust-delharc/$dhTag"
$out = Join-Path $PSScriptRoot 'thirdparty'
$oracle = Join-Path $PSScriptRoot 'oracles.py'
# kojipkgs and the vaults turn browsers' user agents away (Anubis).
$agent = 'curl/8.9.1'

$lzop = '7-Zip doesn''t read lzop: decoded by WSL''s liblzo2 (lzo1x_decompress_safe, through oracles.py, every checksum checked), then listed by 7-Zip and Python''s tarfile.'
$nosym = '7-Zip 26.00 lists nothing: the first member, dir, has nonsense rdev fields (0xBB and 0x15B0036, as GNU cpio left them), which 7-Zip takes for a bad header, so it skips to the trailer. Entries from oracles.py; bsdcpio reads it (test_gcpio_compat.c).'

# libarchive's test files: `src` is the path at the tag without `.uu`. `chain` is what BeeZip
# detects; `encoding` the name encoding that reads the names right; `broken` the error BeeZip
# must give instead of a listing.
$la = @(
    # cpio: every header variant, hard links, legacy names, and every codec.
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_bin_be.cpio'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_bin_le.cpio'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_gcpio_compat_ref.bin'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_gcpio_compat_ref.crc'; chain = 'cpio'
        note = '7-Zip reports a CRC error on `symlink`: GNU cpio writes 0 as a symlink''s checksum and sums regular files only (libarchive doesn''t check it). Entries from 7-Zip''s listing and oracles.py; a crc reader should check regular files'' sums only.' }
    @{ dir = 'cpio'; src = 'cpio/test/test_gcpio_compat_ref.newc'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_gcpio_compat_ref_nosym.bin'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_gcpio_compat_ref_nosym.crc'; chain = 'cpio'; note = $nosym }
    @{ dir = 'cpio'; src = 'cpio/test/test_gcpio_compat_ref_nosym.newc'; chain = 'cpio'; note = $nosym }
    @{ dir = 'cpio'; src = 'cpio/test/test_option_f.cpio'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_option_m.cpio'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_compat_cpio_1.cpio'; chain = 'cpio'
        note = 'foo1 and foo2 share an inode but have nlink 1, so they aren''t links; bar2 (nlink 2, no data) links to bar1, which carries the data first (libarchive''s test_compat_cpio.c). 7-Zip reports a headers error and extracts bar2 empty; entries from oracles.py, the other bytes matching 7-Zip''s.' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_symlink_trailer.cpio'; chain = 'cpio'
        note = 'The only member is a symlink named TRAILER!!! with a 128 KiB body: the name ends the archive, so nothing is listed (libarchive''s test_read_format_cpio_symlink_trailer.c).' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_filename_cp866.cpio'; chain = 'cpio'; encoding = 'cp866' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_filename_koi8r.cpio'; chain = 'cpio'; encoding = 'koi8-r' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_filename_eucjp.cpio'; chain = 'cpio'; encoding = 'euc-jp' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_filename_utf8_jp.cpio'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_filename_utf8_ru.cpio'; chain = 'cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.gz'; chain = 'gzip → cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.bz2'; chain = 'bzip2 → cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.xz'; chain = 'xz → cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.lzma'; chain = 'lzma → cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.lz'; chain = 'lzip → cpio'
        note = '7-Zip doesn''t read lzip: decoded by oracles.py (Python''s raw LZMA1 decoder, the member''s CRC-32 and size checked), then listed by 7-Zip and oracles.py.' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.zst'; chain = 'zstd → cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.lz4'; chain = 'lz4 → cpio'
        note = '7-Zip doesn''t read lz4: decoded by oracles.py''s LZ4 frame decoder, then listed by 7-Zip and oracles.py.' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.Z'; chain = 'compress → cpio' }
    @{ dir = 'cpio'; src = 'cpio/test/test_extract.cpio.lzo'; chain = 'lzop → cpio'
        note = '7-Zip doesn''t read lzop: decoded by WSL''s liblzo2 (lzo1x_decompress_safe, through oracles.py), then listed by 7-Zip and oracles.py.' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_afio_header.part1.cpio'; broken = 'UnsupportedFormat'
        why = 'afio''s large ASCII header (`070727`), which BeeZip doesn''t read; libarchive reads it across both parts (test_read_format_cpio_afio.c).' }
    @{ dir = 'cpio'; src = 'libarchive/test/test_read_format_cpio_afio_header.part2.cpio'; broken = 'UnsupportedFormat'
        why = 'The rest of part1''s member: no header at the start.' }

    # ar
    @{ dir = 'ar'; src = 'libarchive/test/test_read_format_ar.ar'; chain = 'ar' }

    # RPM
    @{ dir = 'rpm'; src = 'libarchive/test/test_read_format_cpio_svr4_gzip_rpm.rpm'; chain = 'rpm' }
    @{ dir = 'rpm'; src = 'libarchive/test/test_read_format_cpio_svr4_bzip2_rpm.rpm'; chain = 'rpm' }
    @{ dir = 'rpm'; src = 'libarchive/test/test_read_format_huge_rpm.rpm'; broken = 'Corrupt'
        why = 'Truncated: its header asks for 34 359 738 384 bytes of the 10 256 there are (test_read_format_huge_rpm.c). Must fail before allocating. 7-Zip opens it as tar.' }

    # CAB
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_1.cab'; chain = 'cab' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_2.cab'; chain = 'cab' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_3.cab'; chain = 'cab' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_filename_cp932.cab'; chain = 'cab'; encoding = 'cp932' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_lzx_16bit.cab'; chain = 'cab'
        data = @{ 'lzx16.bin' = 'ABABABABABABABAB' }
        note = '7-Zip 26.00 reports a data error; the bytes are libarchive''s test_read_format_cab_lzx_16bit.c''s ("ABABABABABABABAB"), which libarchive and lzxd decode (docs/M5.md §16).' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_lzx_e8.cab'; chain = 'cab' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_lzx_literal_control.cab'; chain = 'cab'
        note = 'The valid twin of broken/test_read_format_cab_lzx_invalid_history.cab: x is two zero bytes (test_read_format_cab_lzx_invalid_history.c).' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_multi.p1.cab'; chain = 'cab'
        parts = @('test_read_format_cab_multi.p2.cab') }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_multi.p2.cab'; part = $true }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_skip_across_folders.cab'; chain = 'cab' }
    @{ dir = 'cab'; src = 'libarchive/test/test_fuzz.cab'; chain = 'cab'
        note = 'test_fuzz.c''s seed: a well-formed LZX:18 cabinet, which the test mutates.' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_lzx_invalid_history.cab'; broken = 'Reads (should be Corrupt)'
        why = 'An LZX match reaches back before the start of the output (`LZX decompression failed (-25)` in libarchive); 7-Zip reports a data error. lzxd 0.2.7 decodes it as zeros instead, and a cabinet has no checksum of its decoded data, so BeeZip reads it (on the upstream list).' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_lzx_oob.cab'; broken = 'UnsupportedFormat or Corrupt'
        why = 'Malformed LZX state that read out of bounds in libarchive (test_read_format_cab_lzx_oob.c only checks it survives); 7-Zip can''t open it.' }
    @{ dir = 'cab'; src = 'libarchive/test/test_read_format_cab_skip_malformed.cab'; broken = 'UnsupportedFormat or Corrupt'
        why = 'A malformed payload that crashed libarchive''s skip (test_read_format_cab_skip_malformed.c); 7-Zip can''t open it.' }

    # LHA
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_header0.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_header1.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_header2.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_header3.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_lh0.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_lh6.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_lh7.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_filename_cp932.lzh'; chain = 'lzh'; encoding = 'cp932' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_filename_utf16.lzh'; chain = 'lzh'
        note = 'Names from oracles.py: the UTF-16 headers (0x44, 0x45) win; 7-Zip ignores them and shows ______. Two names (テスト, "test" in katakana) are stored only in CP932, so "auto" on a US system reads them as Windows-1252 (ƒeƒXƒg), as recorded here; libarchive''s test_read_format_lha_filename_utf16.c expects テスト, reading them in CP932. The bytes are 7-Zip''s, each matching its CRC-16.' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_amiga_script.lha'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_bugfix_0.lzh'; chain = 'lzh' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_fuzz.lzh'; broken = '29 entries, or Corrupt'
        why = 'test_fuzz.c''s seed, not malformed as such: one archive of 29 entries in header levels 0 to 3 (the same six, symlinks included, at each level, then INSTALL), ended by its zero byte, with nine more archives run on after it. delharc 0.8.0 reads the 29, every CRC-16 good, and stops at the end mark; 7-Zip lists 18 with a headers error (it can''t read level 3). Duplicate names keep it out of the manifest.' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_oversize_header.lzh'; broken = 'Corrupt'
        why = 'The 19th header is larger than the file allows (test_read_format_lha_oversize_header.c: 18 entries, then ARCHIVE_FATAL).' }
    @{ dir = 'lzh'; src = 'libarchive/test/test_read_format_lha_symlink_missing_target.lzh'; broken = 'Corrupt'
        why = 'A symlink entry whose name lacks the `|target` part; libarchive fails that entry and reads `second` after it (test_read_format_lha_symlink_missing_target.c). `second`''s level-0 header has no CRC field, an old variant libarchive takes and delharc refuses, so BeeZip fails the archive there. 7-Zip reports a headers error.' }
    @{ dir = 'lzh'; src = 'tar/test/test_copy_data_warning.lzh'; broken = 'Corrupt'
        why = 'file1''s data fails its CRC-16 (tar/test/test_copy_data_warning.c); 7-Zip reports a data error.' }

    # Unix .Z
    @{ dir = 'compress'; src = 'cat/test/test_expand.Z'; chain = 'compress' }
    @{ dir = 'compress'; src = 'libarchive/test/test_read_format_raw.data.Z'; chain = 'compress' }
    @{ dir = 'compress'; src = 'libarchive/test/test_compat_mac-1.tar.Z'; chain = 'compress → tar' }
    @{ dir = 'compress'; src = 'tar/test/test_extract.tar.Z'; chain = 'compress → tar' }
    @{ dir = 'compress'; src = 'libarchive/test/test_read_format_gtar_filename_koi8r.tar.Z'; chain = 'compress → tar'; encoding = 'koi8-r' }
    @{ dir = 'compress'; src = 'libarchive/test/test_read_format_ustar_filename_eucjp.tar.Z'; chain = 'compress → tar'; encoding = 'euc-jp' }

    # ISO 9660: Joliet, Rock Ridge (old and new), relocation, multi-extent, zisofs, and the
    # crafted images of libarchive's fixes. Most are compressed with compress(1), as libarchive
    # keeps them.
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso.iso.Z'; chain = 'compress → iso'
        note = 'An empty image: libarchive''s test_read_format_iso_Z.c lists only its root.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_2.iso.Z'; chain = 'compress → iso' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_3.iso.Z'; chain = 'compress → iso' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_joliet.iso.Z'; chain = 'compress → iso'
        expect = { param($s) foreach ($e in $s) { if ($e.path -eq 'symlink') { [ordered]@{ path = 'symlink'; kind = 'symlink'; target = 'long-joliet-file-name.textfile' } } else { $e } } }
        note = '7-Zip 26.00 reads the Joliet tree, where symlink is an empty file; Rock Ridge makes it a link to long-joliet-file-name.textfile, as libarchive''s test_read_format_isojoliet_rr.c reads it.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_joliet_by_nero.iso.Z'; chain = 'compress → iso' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_joliet_long.iso.Z'; chain = 'compress → iso' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_joliet_rockridge.iso.Z'; chain = 'compress → iso'
        expect = { param($s) foreach ($e in $s) { if ($e.path -eq 'symlink') { [ordered]@{ path = 'symlink'; kind = 'symlink'; target = 'long-joliet-file-name.textfile' } } else { $e } } }
        note = '7-Zip 26.00 reads the Joliet tree, where symlink is an empty file; Rock Ridge makes it a link to long-joliet-file-name.textfile, as libarchive''s test_read_format_isojoliet_rr.c reads it.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_multi_extent.iso.Z'; chain = 'compress → iso' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge.iso.Z'; chain = 'compress → iso'
        expect = { param($s) foreach ($e in $s) { $t = @{ symlink3 = '/tmp/..'; symlink6 = '/tmp//..' }[$e.path]; if ($t) { $e.target = $t }; $e } }
        note = '7-Zip 26.00 ends symlink3''s and symlink6''s targets with a /, which this older mkisofs''s SL entries don''t have; the targets are libarchive''s (test_read_format_isorr_compress.c).' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_ce.iso.Z'; chain = 'compress → iso'
        expect = {
            param($s)
            $made = @()
            foreach ($n in 151, 152, 153) {
                $bytes = [Text.Encoding]::ASCII.GetBytes("hello $n`n") + [byte[]]::new(4080)
                $made += [ordered]@{ path = 'a' * $n; kind = 'file'; size = $bytes.Length; sha256 = Sha256 $bytes }
            }
            foreach ($n in 1..3) { $made += [ordered]@{ path = "sym$n"; kind = 'symlink'; target = 'a' * (150 + $n) } }
            $made
        }
        note = '7-Zip 26.00 doesn''t follow the continuation areas (CE) the long names and link targets are in: it lists the names cut to 146 characters and the links empty. The entries are what test_read_format_isorr_ce.c''s script makes: "hello 151" to "hello 153" and 4 080 zero bytes, under names of 151 to 153 a''s, and links to them.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_new.iso.Z'; chain = 'compress → iso' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_rr_moved.iso.Z'; chain = 'compress → iso'
        relocated = @{ 'rr_moved/dir8' = 'dir1/dir2/dir3/dir4/dir5/dir6/dir7/dir8' }
        note = 'Rock Ridge relocated dir1/…/dir7/dir8 to rr_moved/dir8 (CL, PL and RE entries). 7-Zip 26.00 lists it there, with an empty file where it belongs; the paths here are libarchive''s (test_read_format_isorr_rr_moved.c), which put it back, with 7-Zip''s bytes.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_cl_re_control.iso.Z'; chain = 'compress → iso'
        note = 'rr_moved/B is marked relocated (RE), but no folder points at it (no CL), so it stays in rr_moved, as 7-Zip lists it; libarchive''s test_read_format_iso_rockridge_cl_re_cycle.c reads it to the end.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_xorriso.iso.Z'; chain = 'compress → iso' }
    @{ dir = 'iso'; src = 'libarchive/test/test_fuzz_1.iso.Z'; chain = 'compress → iso'
        note = 'test_fuzz.c''s seed: 203 folders nested one in another, which the test mutates.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_zisofs.iso.Z'; broken = 'UnsupportedOperation'
        why = 'file and hardlink are zisofs-compressed (Rock Ridge ZF): listed with their real size (12 345 684 bytes), and extracting either is UnsupportedOperation, as BeeZip doesn''t decompress zisofs (docs/M5.md §5.9). 7-Zip lists their compressed bytes.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_joliet_overlong.iso.Z'; broken = 'Reads'
        why = 'Joliet names past the 103 characters libarchive takes (test_read_format_isojoliet_long.c reads them cut, as in joliet_long); 7-Zip can''t open it. BeeZip lists the same three entries as test_read_format_iso_joliet_long.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_joliet_utf16be_cycle.iso.Z'; broken = 'Reads (lists nothing)'
        why = 'The Joliet tree loops back on itself (test_read_format_iso_joliet_utf16be_cycle.c: libarchive fails with "Pathname is too long"). hadris reads the Joliet root as empty, so nothing is listed; no hang.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_joliet_utf16be_overflow.iso'; broken = 'Reads'
        why = 'A Joliet path longer than libarchive''s buffer (test_read_format_iso_joliet_utf16be_overflow.c: "Pathname is too long"). BeeZip lists the six folders; extraction makes the path if the file system takes it.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_ce_loop.iso.Z'; broken = 'Corrupt'
        why = 'A Rock Ridge continuation area (CE) that points at itself (test_read_format_isorr_ce_loop.c: ARCHIVE_FATAL). hadris lists the entry under its ISO 9660 name; opening it fails.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_ce_overflow.iso.Z'; broken = 'Corrupt'
        why = 'A CE entry whose offset and length run past its block (test_read_format_iso_rockridge_ce_overflow.c: "Invalid parameter in SUSP "CE" extension").' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_cl_re_cycle.iso.Z'; broken = 'Reads'
        why = 'Relocated folders (CL and RE) that point at each other (test_read_format_iso_rockridge_cl_re_cycle.c: ARCHIVE_FATAL). hadris doesn''t follow the loop: the folders are listed where they are stored, in rr_moved; no hang.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_sl_leak.iso'; broken = 'Corrupt'
        why = 'compress(1) data despite its name, cut short: the .Z stream fails, as in 7-Zip ("Data Error"). libarchive''s test_read_format_iso_rockridge_sl_leak.c only checks that a symlink''s SL entries don''t leak.' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_rockridge_zf_overflow.iso'; broken = 'Corrupt'
        why = 'A ZF entry cut short in the root''s continuation area, which over-read libarchive''s buffer (test_read_format_iso_rockridge_zf_overflow.c).' }
    @{ dir = 'iso'; src = 'libarchive/test/test_read_format_iso_zisofs_overflow.iso'; broken = 'Corrupt'
        why = 'A zisofs header with a block size of 4 bytes and a size of 0xFFFFFFF9 (test_read_format_iso_zisofs_overflow.c). hadris refuses the directory record.' }

    # lzop
    @{ dir = 'lzop'; src = 'libarchive/test/test_compat_lzop_1.tar.lzo'; chain = 'lzop → tar'; note = $lzop }
    @{ dir = 'lzop'; src = 'libarchive/test/test_compat_lzop_2.tar.lzo'; chain = 'lzop → tar'
        note = "$lzop The tar in several blocks (test_compat_lzop.c)." }
    @{ dir = 'lzop'; src = 'libarchive/test/test_compat_lzop_3.tar.lzo'; chain = 'lzop → tar'
        note = "$lzop Junk after the stream, which lzop ignores: a stream ends where no lzop signature follows (test_compat_lzop.c)." }
    @{ dir = 'lzop'; src = 'libarchive/test/test_read_filter_lzop.tar.lzo'; chain = 'lzop → tar'; note = $lzop }
    @{ dir = 'lzop'; src = 'libarchive/test/test_read_filter_lzop_multiple_parts.tar.lzo'; chain = 'lzop → tar'
        note = "$lzop 26 lzop streams, one after another." }
    @{ dir = 'lzop'; src = 'tar/test/test_extract.tar.lzo'; chain = 'lzop → tar'; note = $lzop }
)

# delharc's tests (most copied from lhasa): `src` is under tests/ at the tag; the file keeps its
# folder in its name. `tool` is the archiver, from delharc's tests/README.md.
$dh = @(
    @{ src = 'lharc113/lh1.lzh'; tool = 'LHarc 1.13c (MS-DOS)' }
    @{ src = 'lha_amiga_122/lh4.lzh'; tool = 'LHA 1.22 (AmigaOS)' }
    @{ src = 'lha213/lh5.lzh'; tool = 'LHA 2.13 (MS-DOS)' }
    @{ src = 'lha_amiga_212/lh6.lzh'; tool = 'LHA 2.12 (AmigaOS)' }
    @{ src = 'lha_unix114i/h2_lh7.lzh'; tool = 'LHA for Unix 1.14i' }
    @{ src = 'lha_unix114i/h1_symlink.lzh'; tool = 'LHA for Unix 1.14i' }
    @{ src = 'lha_unix114i/h1_subdir.lzh'; tool = 'LHA for Unix 1.14i' }
    @{ src = 'unlha32/h2_lhx.lzh'; tool = 'UNLHA32.DLL 2.67a (Windows)' }
    @{ src = 'generated/lzs/lzs.lzs'; tool = 'generated for delharc''s tests' }
    @{ src = 'larc333/lz4.lzs'; tool = 'LArc 3.33 (MS-DOS)' }
    @{ src = 'larc333/lz5.lzs'; tool = 'LArc 3.33 (MS-DOS)' }
    @{ src = 'lharc_atari_313a/h2_lz5.lzh'; tool = 'LHarc 3.13a (Atari TOS)' }
    @{ src = 'pmarc2/pm0.pma'; tool = 'PMarc2 (MSX-DOS)' }
    @{ src = 'pmarc124/pm1.pma'; tool = 'PMarc 1.24 (CP/M)' }
    # pm2.pma's one file is called `GPL-2.`, which Windows can't create; this one has a comment.
    @{ src = 'pmarc2/comment.pma'; tool = 'PMarc2 (MSX-DOS)' }
    @{ src = 'lha_os2_208/h3_lh5.lzh'; tool = 'LHA 2.08 (OS/2)' }
    @{ src = 'lha_os2_208/h3_subdir.lzh'; tool = 'LHA 2.08 (OS/2)' }
    @{ src = 'lha_os9_211c/h1_lh1.lzh'; tool = 'LHA 2.11c (OS-9)' }
    @{ src = 'lha_x68k_213/h2_subdir.lzh'; tool = 'LHA 2.13 (Human68K)' }
    @{ src = 'maclha_224/l2_subdir.lzh'; tool = 'MacLHA 2.24 (Classic Mac OS)' }
    @{ src = 'morphos_lha_2717/h2_lh6.lzh'; tool = 'LHA 2.7.17 (MorphOS)' }
    @{ src = 'explzh_723/h2_subdir.lzh'; tool = 'ExpLZH 7.23 (Windows)' }
    @{ src = 'regression/unixsep.lzh'; tool = 'made by hand for lhasa''s tests' }
    @{ src = 'regression/truncated.lzh'; broken = 'Corrupt'; why = 'An -lh5- archive cut short (lhasa''s regression set).' }
    @{ src = 'regression/evil_pm2.lzh'; broken = 'Corrupt'; why = 'Overflowed an array in -pm2- decoders (GHSA-j2m3-h278-rrg9).' }
    @{ src = 'regression/dotdot.lzh'; broken = 'Unsafe'; why = '`../evil1.txt` and `foo/../../evil2.txt`: listing works; extraction must skip both (Traversal), then fail with Unsafe.' }
    @{ src = 'regression/symlink2.lzh'; broken = 'Unsafe'; why = 'A symlink `etc` to `../../etc`, then `etc/passwd` through it: listing works; extraction must refuse the link (LinkOutside, or LinksDisabled) and must not write through it (OutsideDest).' }
    @{ src = 'regression/symlink3.lzh'; broken = 'Unsafe'; why = 'A symlink `etc` to `/tmp`, then `etc/passwd` through it: as symlink2.' }
    @{ src = 'regression/clusterfuzz-1.bin'; broken = 'Corrupt or UnsupportedFormat'; why = 'Made delharc''s LhaV2Decoder panic (delharc issue 7).' }
    @{ src = 'regression/fuzz-10-1.bin'; broken = 'Corrupt or UnsupportedFormat'; why = 'Made delharc''s LhaHeader::read panic (delharc issue 10).' }
    @{ src = 'unlha32/lh2.lzh'; broken = 'UnsupportedFormat'; why = '-lh2-, which delharc doesn''t decode: listing works, reading the file must fail.' }
)
foreach ($d in $dh) { $d.name = ($d.src -replace '/', '-') }

# MIT-licensed noarch packages, from URLs that stay: koji keeps every build tagged into a release,
# the vault and snapshot.debian.org every one ever published, and Launchpad's librarian its files.
$pkgs = @(
    @{ name = 'python3-six-1.17.0-7.fc43.noarch.rpm'; chain = 'rpm'; version = '1.17.0-7.fc43'; distro = 'Fedora 43'; compressor = 'zstd'
        url = 'https://kojipkgs.fedoraproject.org/packages/python-six/1.17.0/7.fc43/noarch/python3-six-1.17.0-7.fc43.noarch.rpm' }
    @{ name = 'python3-six-1.11.0-8.el8.noarch.rpm'; chain = 'rpm'; version = '1.11.0-8.el8'; distro = 'AlmaLinux 8.4 (EL 8)'; compressor = 'xz'
        url = 'https://vault.almalinux.org/8.4/BaseOS/x86_64/os/Packages/python3-six-1.11.0-8.el8.noarch.rpm' }
    @{ name = 'python3-six_1.16.0-4_all.deb'; chain = 'deb'; version = '1.16.0-4'; distro = 'Ubuntu 24.04 (noble)'; compressor = 'zstd'
        url = 'https://launchpadlibrarian.net/618871417/python3-six_1.16.0-4_all.deb' }
    @{ name = 'python3-six_1.17.0-1_all.deb'; chain = 'deb'; version = '1.17.0-1'; distro = 'Debian unstable (2024-12-05)'; compressor = 'xz'
        url = 'https://snapshot.debian.org/archive/debian/20241205T143941Z/pool/main/s/six/python3-six_1.17.0-1_all.deb' }
)

$sha256 = @{
    'libarchive/cpio/test_read_format_cpio_bin_be.cpio' = 'edbeebcf109a958a46971f8c82f7fc1b9d17fd2d8d9e3eeb59bcbd96ab7c2cec'
    'libarchive/cpio/test_read_format_cpio_bin_le.cpio' = '02ad9b464d4c8c0986ea23954239a9d93b24532f0c1b4b368e46b20cd0cacee4'
    'libarchive/cpio/test_gcpio_compat_ref.bin' = '6405a4fe846a89fdf112b3a8c20c4d95aebdb2cb3abb364e4b280515389e4d1e'
    'libarchive/cpio/test_gcpio_compat_ref.crc' = 'a809a12411b0857ee117281a4b071effa9e5abc71527a7a2c6f57df04fed9696'
    'libarchive/cpio/test_gcpio_compat_ref.newc' = 'ba3d04baf5d08006767bb4181bbaa91523cb02b5c0f0a363cc523467fe0cfc06'
    'libarchive/cpio/test_gcpio_compat_ref_nosym.bin' = 'f2d2c10a21388a0d600df7db211d96edef36628a0813ba881c0f822d42247303'
    'libarchive/cpio/test_gcpio_compat_ref_nosym.crc' = 'd7b87ce714ea673ac7ce8cd7f15554f00913273d5a2d65a25b04233538ec316d'
    'libarchive/cpio/test_gcpio_compat_ref_nosym.newc' = '1a02ad7edd393d5e603b8b2def774f73c17ee13f9a113708ca214af2e6ef8cea'
    'libarchive/cpio/test_option_f.cpio' = '8dad03b9b56572d559b6b50f4d86a6325f58768f6a81e2b9f2887551e5f709ac'
    'libarchive/cpio/test_option_m.cpio' = '5c91fd6796fe53cc086c7f839b987368a266ae9819d776ddd9ad386462cf45be'
    'libarchive/cpio/test_compat_cpio_1.cpio' = 'a2c34c28f8f2cf17c4084255b47659c2d5a70efd47e4943169e5cb8287dca370'
    'libarchive/cpio/test_read_format_cpio_symlink_trailer.cpio' = 'b709186cdcdbe659582e48f6b7baf6167b60e9a2a60c564de65537015ca14d18'
    'libarchive/cpio/test_read_format_cpio_filename_cp866.cpio' = 'dbea706dc27d4e7c4dbb14afe55f41b500fa92de7e80a4445779b84b786d2f63'
    'libarchive/cpio/test_read_format_cpio_filename_koi8r.cpio' = '956154e1040af818aa3d07aec6417132ede4bc887a46ed6f31743b8e160760a5'
    'libarchive/cpio/test_read_format_cpio_filename_eucjp.cpio' = 'a16efc1a3d1833925a3eb97befa570d920cb9b3f8b4f009285af12ab935c1744'
    'libarchive/cpio/test_read_format_cpio_filename_utf8_jp.cpio' = 'e4b1061e0b75492a8e43a8e86f9f8b619b030eff3f17489b7782322fec8a4803'
    'libarchive/cpio/test_read_format_cpio_filename_utf8_ru.cpio' = 'fa6864b267240c5748a39eb3cdb129f51dfb22a6219dff388a1e9cf742185874'
    'libarchive/cpio/test_extract.cpio.gz' = '0ead9ccf504d9b837366beb3451fe1810ed7a7e3926499166dcc4a7c1f766859'
    'libarchive/cpio/test_extract.cpio.bz2' = 'fe7c159e4085d26bbc987b15fd365c161e2e8cc636a863a52d79a5265bee2c9a'
    'libarchive/cpio/test_extract.cpio.xz' = 'afa9e058aa39eab6d02c2c4a0354ef0275ff95b24b196831569ef04fec160e77'
    'libarchive/cpio/test_extract.cpio.lzma' = '114a0c6eb6ed59c6000b9fdbea225996db276b0721384d527fe5adf8ba29595e'
    'libarchive/cpio/test_extract.cpio.lz' = 'deae7dd960a6900b17fb5459defb85255cff4d0260dca3d6093f80f04cee53c0'
    'libarchive/cpio/test_extract.cpio.zst' = '6593bc90dfa4d558d150dfd40d95d33e3dc156489d60ff9904b49342d8fc6932'
    'libarchive/cpio/test_extract.cpio.lz4' = '3aabe3d01c551346c07d0b90879ac76d9c774043b0ae8fbaa470e38d4d3ef37f'
    'libarchive/cpio/test_extract.cpio.Z' = 'b013864103dd9cc2ea112c3ac5b4b8f9d5509818fe0cacad179c77ab802e5111'
    'libarchive/cpio/test_extract.cpio.lzo' = '9809177a586e80e78a25142a9007ea1324415918823119ac75ef9d3462797919'
    'libarchive/cpio/broken/test_read_format_cpio_afio_header.part1.cpio' = '74ac6ec4bec66a1c2c2a59075f835df6bc14b099c98e03f67bbf61be2be22574'
    'libarchive/cpio/broken/test_read_format_cpio_afio_header.part2.cpio' = '58c7ea66ff5d8733ab8e63a1b35da504f5996707b66e04af30776a9f3baa9b86'
    'libarchive/ar/test_read_format_ar.ar' = '5f75baa148624d9646d67c95363373ae6478f8a9c326474ebbf00e2e13119092'
    'libarchive/rpm/test_read_format_cpio_svr4_gzip_rpm.rpm' = 'dcc4f3ab933335bf3822d94079fdf4f0b7ac4c65773ca8e9a973a1cec7c553d6'
    'libarchive/rpm/test_read_format_cpio_svr4_bzip2_rpm.rpm' = 'd652b81accaeaf5761b807971fd9ca75f00ebaeefad237a80f08f7764a24b66c'
    'libarchive/rpm/broken/test_read_format_huge_rpm.rpm' = '1cde03b9af6585c8e49e4065b88ac36573ad8bfb570c70422d3ecad34d77f4bc'
    'libarchive/cab/test_read_format_cab_1.cab' = '0672797c111fca020fefe1b4b86de410f0eed36b52482a5bd282527392124d0e'
    'libarchive/cab/test_read_format_cab_2.cab' = 'c1a19b9c5f0d185079292ebb7ac0378e773d5ffd92e3b118c111178200064d85'
    'libarchive/cab/test_read_format_cab_3.cab' = 'e0e679fc38b64ee633dd9d162518f498f70252a10b7670ec7932dfe750cbcea8'
    'libarchive/cab/test_read_format_cab_filename_cp932.cab' = '8ec3c22099c581595f48ad21fa2bfbdbb7026a21a9f2958375532b826e4cd805'
    'libarchive/cab/test_read_format_cab_lzx_16bit.cab' = 'b4f405c3053cff3b268c666b2e87a5e516e756791f3a8fcdb2aeac472de78f39'
    'libarchive/cab/test_read_format_cab_lzx_e8.cab' = '94e940b88b42e83f62847e728c47e4fa86bebed7f34913d8822279f618f248f8'
    'libarchive/cab/test_read_format_cab_lzx_literal_control.cab' = '228bd4b6ed1f4f6c531434f77fb81e0c23609f334e6c1980ab16fc453df954bb'
    'libarchive/cab/test_read_format_cab_multi.p1.cab' = '0dad014b11a122d08a4cb7aca1c76f8bd07cc730f0f7733bc1a885464d5ba33f'
    'libarchive/cab/test_read_format_cab_multi.p2.cab' = '4f92ee4ff26d063fd99c28b62f638982d8c6c9d9f82fabef52e8607a8ffa038d'
    'libarchive/cab/test_read_format_cab_skip_across_folders.cab' = '5f229a37e749d1eac7b6a779745739894a65fc36e116df49b2a0ffc94f386aec'
    'libarchive/cab/test_fuzz.cab' = 'c6017283be7cf4f4f659637d15ad6e15366d15994d6b878c57b01f5cfa048cdd'
    'libarchive/cab/broken/test_read_format_cab_lzx_invalid_history.cab' = '8921c790dc52db1f5822ec21db0095b70b71b79140b13d04e1dcab0d1d0d7346'
    'libarchive/cab/broken/test_read_format_cab_lzx_oob.cab' = '553422109814a20be3c6f5c08ace46c2c0661e14d4d93af4161f8992810ce138'
    'libarchive/cab/broken/test_read_format_cab_skip_malformed.cab' = '97d41d21b7ced0826c890d28ae88c0e3b59b6965ad035cd5e31c4d5ecbe39cdf'
    'libarchive/lzh/test_read_format_lha_header0.lzh' = '286b32e0f5c98016944681e4694b0c7be5c0575570c876d6fc63195a09d3c508'
    'libarchive/lzh/test_read_format_lha_header1.lzh' = '094084407fa7b6cf4b9e1d32ac122ce122e4637867400ca21a44977b9b08ad16'
    'libarchive/lzh/test_read_format_lha_header2.lzh' = '12bcc4b3e8ac6f81af82f4dc191133fb1cdc1b802e1c63f710c294a463f457c7'
    'libarchive/lzh/test_read_format_lha_header3.lzh' = 'd36f9beaf7d1aa482315e810c8cfca327975ffd31a05082004102327310e419d'
    'libarchive/lzh/test_read_format_lha_lh0.lzh' = '35fa46a93d8fb0c1697afcc8c0aea0ad355e37296cfda8e87e36d6f61ea8f4cd'
    'libarchive/lzh/test_read_format_lha_lh6.lzh' = '99cbc14499cc88361e9182a4912263ae27bcba888f7fe30c00995ab96752421b'
    'libarchive/lzh/test_read_format_lha_lh7.lzh' = 'c3aa72e18b294c271737803cedf889f289c4f215d16a192044525d930b045cb6'
    'libarchive/lzh/test_read_format_lha_filename_cp932.lzh' = 'c94008b2e0202872a61a48db1815fa09cb9f7f93e754d989d2e26d0e20bf699f'
    'libarchive/lzh/test_read_format_lha_filename_utf16.lzh' = '74a780be3a808b4ba98a14949ea2c40ec06a9b58b1b895897b0502b8da19cabd'
    'libarchive/lzh/test_read_format_lha_amiga_script.lha' = '12a653dd759676789939fa49828430e42a6c48e540908539a9b231b0400aea73'
    'libarchive/lzh/test_read_format_lha_bugfix_0.lzh' = '2d13865aefb2a03a3a6270dab0d4fb9beb254d9326ea3e334cdd64877a90ad41'
    'libarchive/lzh/broken/test_fuzz.lzh' = '25137cfbe66842d2cf5158b146654fc80b52c19a8c42d28db73060e1a2e12be0'
    'libarchive/lzh/broken/test_read_format_lha_oversize_header.lzh' = 'dbb48ff170971dc908191714f4b8ea65b13eb3513c0c3165cf94f4a2c7b00bf1'
    'libarchive/lzh/broken/test_read_format_lha_symlink_missing_target.lzh' = '4870bccfb36c430626ff3670472e51efe789291823413d34558d71d799130ea4'
    'libarchive/lzh/broken/test_copy_data_warning.lzh' = '8afacd774f9785aeb30b2d916c41303968c6df20f553148c416a5f4986018e3f'
    'libarchive/compress/test_expand.Z' = '1ad18eec0a8d3104e86b22db3aa448bd29fc795ca72c04fbb7506ff41a372170'
    'libarchive/compress/test_read_format_raw.data.Z' = '98bb864eb5fb58004b1395c7f72f27766d4edd5989a6b25fc963fb97370fd2e3'
    'libarchive/compress/test_compat_mac-1.tar.Z' = '7329670459c4d4c0017eb17c875426dfa3b92f531c8d52b9d1dfa99f8b6bd6ab'
    'libarchive/compress/test_extract.tar.Z' = '58933a6173aee1b6bcb514e5108e19bdf085cf3c6bcc2deb8a0782905d0f2ba7'
    'libarchive/compress/test_read_format_gtar_filename_koi8r.tar.Z' = 'b90d6958c9bffea388edf4183f36361e7fccd3a8088df8454b8e259c752aff8f'
    'libarchive/compress/test_read_format_ustar_filename_eucjp.tar.Z' = 'e64381d485033b54dedcd672789934a595b03e1961957499006277a5c73a35c0'
    'libarchive/lzop/test_compat_lzop_1.tar.lzo' = '567cc57516e5781966d734eacfde57995b476945b2a5efbe5aaf1f6a7035d118'
    'libarchive/lzop/test_compat_lzop_2.tar.lzo' = '2af625439600206743ab9b2bbb46481c6bcbbbb918f1069cc079cfb89f6246a9'
    'libarchive/lzop/test_compat_lzop_3.tar.lzo' = '53ad4162c25eacd2f4c621d3bb065507b8bc13769f14eb901929bd85db8fb564'
    'libarchive/lzop/test_read_filter_lzop.tar.lzo' = '103485dc1d666a526d59dab900238d5113b832fd201aeade58f1dfa30c0fb4cd'
    'libarchive/lzop/test_read_filter_lzop_multiple_parts.tar.lzo' = '7a1646375deceaebdd94f3857094fddfc95803d48a654cbe7dbbd7107f81d2fd'
    'libarchive/lzop/test_extract.tar.lzo' = '2a5548f0a439226d07a1791fb1343b9ca210c71b535929122e5e1b4e8928695c'
    'libarchive/iso/test_read_format_iso.iso.Z' = '88be44fd2ca7f0cf78450b3753ad97b5e1157abed3d0ba81ca40426b3975945d'
    'libarchive/iso/test_read_format_iso_2.iso.Z' = 'ec84d2bb05264f790d54df03610c839c8a0420e8a600a5755d4aae272d43dbc2'
    'libarchive/iso/test_read_format_iso_3.iso.Z' = 'b141ed3589d9c4aa47b058a4892b3f188f3b6a4156e7f25c6081ee1f6226d5fe'
    'libarchive/iso/test_read_format_iso_joliet.iso.Z' = '7f90168680a93e01852cbe95b1922448d961da2179c7c37ca8351a0be15b0359'
    'libarchive/iso/test_read_format_iso_joliet_by_nero.iso.Z' = '964c71e92a9e01650d517a8062e6d899cdd02e4a077ee21d16d78c035a96e714'
    'libarchive/iso/test_read_format_iso_joliet_long.iso.Z' = 'a9a5f78cc042db159abf8cc9f0d4808fa64c75dd7bfeaf1bc2f75eb102e8eafe'
    'libarchive/iso/broken/test_read_format_iso_joliet_overlong.iso.Z' = 'eb9ed2af2d0fd1fa3d6ab88d615f85301a61749efc347fd72784111d66e7501f'
    'libarchive/iso/test_read_format_iso_joliet_rockridge.iso.Z' = 'd87b024de68f18644eace37173ee893cf7ed6625538f10e73e250eb84f4e7e2b'
    'libarchive/iso/test_read_format_iso_multi_extent.iso.Z' = 'af63f873999370e62a1e9bcc9028d7a84beaf344ae49b7c8b5b76dee7b8b3ffa'
    'libarchive/iso/test_read_format_iso_rockridge.iso.Z' = '28da594060dba109318cab4f3c98f965051919650e936b5328a611758c6fad87'
    'libarchive/iso/test_read_format_iso_rockridge_ce.iso.Z' = 'd9625d9bb011f58c712bffa009f0919b5bf5c545ec8c22434a0f739946f0f10d'
    'libarchive/iso/test_read_format_iso_rockridge_new.iso.Z' = 'f988ef331122b61192894d60c5aed4c11de1068414c7a3d36c1abd56452145ed'
    'libarchive/iso/test_read_format_iso_rockridge_rr_moved.iso.Z' = 'c852c5dfed1b10956e579666f082e0531685fe25e52d92e4e1126094a7253135'
    'libarchive/iso/test_read_format_iso_rockridge_cl_re_control.iso.Z' = 'b86a1ea2b8c56ab3a6bcdc68aeae59d38bb093b65c4c2adb773a2af378823cf8'
    'libarchive/iso/test_read_format_iso_xorriso.iso.Z' = 'c5022d338d8d20e7d0f439b92cb4016c731a1e6a983f24ea53f3ddf025917498'
    'libarchive/iso/test_fuzz_1.iso.Z' = '84ce90af0cae13703e816265dfa7a9c07a643a2e7db55974c62a317fac5544ac'
    'libarchive/iso/broken/test_read_format_iso_zisofs.iso.Z' = '8b223e4abe9876d895a56d960560868d7fce4f53420934a1e269c22f69b757fe'
    'libarchive/iso/broken/test_read_format_iso_joliet_utf16be_cycle.iso.Z' = '3d6786e1171a7814fb07ecb8499c8c6964214c967cb48082f25479cc0f2df8c0'
    'libarchive/iso/broken/test_read_format_iso_joliet_utf16be_overflow.iso' = '9924be42f57e76649671400f07af91dd2022e91f3653aa0a8d426b4a8f83c25b'
    'libarchive/iso/broken/test_read_format_iso_rockridge_ce_loop.iso.Z' = '1b195f0f5fce768a3a8aa7ac88f5dadf1a370634c3b6a1372396745a6219d1bb'
    'libarchive/iso/broken/test_read_format_iso_rockridge_ce_overflow.iso.Z' = 'f153ff4ec16050af877ab13ad71e5bd6fcc379009ad55319a61f2a0133dadf5f'
    'libarchive/iso/broken/test_read_format_iso_rockridge_cl_re_cycle.iso.Z' = 'f8dc684af7cf005f05bb1a21578741a5a406b9e082e0b4ee33538ac8788d650e'
    'libarchive/iso/broken/test_read_format_iso_rockridge_sl_leak.iso' = 'b3cb97c3ba4e9fca1175677ab72278cac376f7bdf96c9f5f927639f21e771c8e'
    'libarchive/iso/broken/test_read_format_iso_rockridge_zf_overflow.iso' = '12105639da0b4b066d355943a7339f035a67e25c54a4f00fc5ca9fa5dca1f6c7'
    'libarchive/iso/broken/test_read_format_iso_zisofs_overflow.iso' = 'bdffba8002dc943334ae15b6fd8eece8dac7bbee165bc0f09217dd1d1bc49c5b'
    'delharc/lharc113-lh1.lzh' = '594af58cb27d6a80e9bebd108cc82a8ab881a4b5549e4fc10379fbf7a0d83069'
    'delharc/lha_amiga_122-lh4.lzh' = '287586d14f052cb1e128cc87f6277a3da6e88431369e65c815666a67718e065c'
    'delharc/lha213-lh5.lzh' = '7f10d0be69536733217e984e4ff81d8980f2df06822581d7c006257bfad34851'
    'delharc/lha_amiga_212-lh6.lzh' = '1910a6d4dfe5db3b1ceaf0fb6f2ec5f245d084cc5262c04777c1889e6791afb0'
    'delharc/lha_unix114i-h2_lh7.lzh' = '9583432d69fe54dc705b87144a4f7a638f4df5843a0e79e769d962680b5a0d5c'
    'delharc/lha_unix114i-h1_symlink.lzh' = 'c0ab6915a5a8066fed193243b86b546730aab75bb99c47efefacfb4e3a628b22'
    'delharc/lha_unix114i-h1_subdir.lzh' = 'dd2762d29f818a740217c7bb608e47a05edff6dad436d3460174722fda60de00'
    'delharc/unlha32-h2_lhx.lzh' = 'c9ab661c5502714f9556be89617bddff237e0e21e72657dc019707aed9751d9b'
    'delharc/generated-lzs-lzs.lzs' = 'a7a0ff6acfef86a49300e4f0dcfbe7a61ba21d05b1585809e5a393ce5635c3b3'
    'delharc/larc333-lz4.lzs' = '98f1a694411d13524b61be587bafc432f8206b24d2858aa58c686b2c6e3bbcd2'
    'delharc/larc333-lz5.lzs' = 'ebacc5d6fa4f35ef4e2ff7176e9867e410e4dfc5922b5bcfb804185954e1ab89'
    'delharc/lharc_atari_313a-h2_lz5.lzh' = 'ce0350b065fc180046742fde2ce5289d2991cf04a4aa9f09987e8ee91987a776'
    'delharc/pmarc2-pm0.pma' = 'b9dc05a9dd49b19c02d5e08bf8eb7fca584d280ed0083eefcd45c6314e4003ad'
    'delharc/pmarc124-pm1.pma' = '13dfdbd992c2fac4964b3028c646aa68eb7a4a941a4224c4837058c3771b6346'
    'delharc/pmarc2-comment.pma' = '7e0875fcc3d331c6e483d2a1b5e640f797d021395780eba7aac7b6d9d5a34866'
    'delharc/lha_os2_208-h3_lh5.lzh' = 'd980d1ddc47323fc860b0fb7829d72ce26afbe1f3f59f89e52f0eda54f425212'
    'delharc/lha_os2_208-h3_subdir.lzh' = '201051c47213d0964c596d40f574486dbb683665b2ba2a27a81bae69e3a9b655'
    'delharc/lha_os9_211c-h1_lh1.lzh' = 'f36369c9ad7ba0f29cfe9f68b0a514f69ee372d625f2000b195940cce30fe639'
    'delharc/lha_x68k_213-h2_subdir.lzh' = 'a8018c620ddb082b42d8a3f33ab8ff67ebdb709b47b67c4db8dde5f2a0168662'
    'delharc/maclha_224-l2_subdir.lzh' = '0e2bb1458f2651ea10d922c4592c31b7471304c0b07f8410a6754e4adf5ee9e2'
    'delharc/morphos_lha_2717-h2_lh6.lzh' = '6bcd547338e5730150104c2aa59efa670899feaf7cac7d8bc33b53fffb367793'
    'delharc/explzh_723-h2_subdir.lzh' = 'a06dbcc6bb6ee2a2196ec359a595987198399295af6239ce8c29080dbd00cfe0'
    'delharc/regression-unixsep.lzh' = '647bbbef96e83afa324947baea541fcea0e6f1de19d9611dee37985cf977739a'
    'delharc/broken/regression-truncated.lzh' = 'fc576d9d9085440678cee554c568f66012b82a911419fd26284902e1f5345404'
    'delharc/broken/regression-evil_pm2.lzh' = '78c597281b572642e91853befe516cfa244b65e9bd877a082bc92cc12dbdb87f'
    'delharc/broken/regression-dotdot.lzh' = '8c5328bbc97636ede12c7f45286062556296594510eb367e99d32687f294290d'
    'delharc/broken/regression-symlink2.lzh' = '949a342ab9a399e7e7ec2b61b6def15e4f3869007e9c83e65551bdb512c722a3'
    'delharc/broken/regression-symlink3.lzh' = '782f575584950effa64bea73fb8a2136bbf0bf48fe0b1ed8541fb4bdf67b492e'
    'delharc/broken/regression-clusterfuzz-1.bin' = 'bace2c62959ca61f3bfd4c6ac9c6476175ed0209836bad86e18383f6acf7e7c6'
    'delharc/broken/regression-fuzz-10-1.bin' = '66ecacbc5eb759e9b8d47bcd027f506014990ea094cd135081c3724871ff57bc'
    'delharc/broken/unlha32-lh2.lzh' = '16e1cba85552ddc930442874dbfd42c0042547da482793e31ac2aaf819dc765e'
    'delharc/LICENSE-MIT' = '78573d550901a931d792f2868ceed0b1903a82ed396636ae06b4c525650706fa'
    'delharc/LICENSE-APACHE' = 'b4ed40d1f4816fa0479e806383b26a55118a755f9b64f59f9715de884c1cff2e'
    'packages/python3-six-1.17.0-7.fc43.noarch.rpm' = 'd48369881b238e2f726f24a2585e1c197a6558a25e94f77ac05c0477e41fb70f'
    'packages/python3-six-1.11.0-8.el8.noarch.rpm' = 'e1e991d21adfbfdcf10a961f7cf69937626e201a382e6d4586aa461010f68f74'
    'packages/python3-six_1.16.0-4_all.deb' = '54e6bb624a89feccbcf6bc16f0641b9aa24231dd1988d4e0b50f430b44a7a1ae'
    'packages/python3-six_1.17.0-1_all.deb' = 'cd1caa92b2860d1de83311cb77f9fab1ee66034ef997cc436d41a1707458666d'
}

# What delharc 0.8.0 decodes from every LHA fixture: for each file entry in archive order (not
# directories or symlinks), its size and SHA-256. They come from a throwaway program
# (`delharc = { version = "=0.8.0", features = ["lhx", "no-unsafe-assertions"] }`) that read each
# entry to the end, checked its CRC-16 with crc_check(), and printed its length, CRC-32 and
# SHA-256; every CRC-32 matched the one delharc's tests/*.rs give for the file. They're the
# bytes where 7-Zip can't decode the method, and a third opinion where it can.
$delharcData = @{
    'libarchive/lzh/test_read_format_lha_amiga_script.lha' = @(@(873, 'e7d990eaa0ee9cdf9c14507f18607c6294412e823afa4422039f4481d1dfeb0a'), @(615, 'a5f6144d25e9b4d7b4fc6c761ff743cdf0ec092c79872357fae5bc47a51088d2'))
    'libarchive/lzh/test_read_format_lha_bugfix_0.lzh' = @(, @(776, '5f59ec737fc007a0857687637352e03eb945ae15a178682f70c33b1599587e25'))
    'libarchive/lzh/test_read_format_lha_filename_cp932.lzh' = @(@(8, 'c10ea15c5a50c023e587aa64e25c1dd409adb5e2fad9c446d72288950893612e'), @(4, 'a330395cc0a53ad1207736546afff4735940937564bbf75ce1edad40780d9139'))
    'libarchive/lzh/test_read_format_lha_filename_utf16.lzh' = @(@(12, 'd4a6e95ceab1fdc8a6b219e2f36f68916bc9c01fe9592be7582c4f8b6c392598'), @(25, '6326406408427b69be4d4efe45662ec781d78024e6e1b16be80cda1b1f96926b'), @(12, 'd4a6e95ceab1fdc8a6b219e2f36f68916bc9c01fe9592be7582c4f8b6c392598'), @(12, 'd4a6e95ceab1fdc8a6b219e2f36f68916bc9c01fe9592be7582c4f8b6c392598'))
    'libarchive/lzh/test_read_format_lha_header0.lzh' = @(@(60, 'd0c504f06bbd64d183524eb35e5482ee5d966d456b905a24147165b2904d301b'), @(78, '60f47caf717b06cf21b3bbb7775e49269a1b5cd6b94bba62da29a2ecb048ccf2'))
    'libarchive/lzh/test_read_format_lha_header1.lzh' = @(@(60, 'd0c504f06bbd64d183524eb35e5482ee5d966d456b905a24147165b2904d301b'), @(78, '60f47caf717b06cf21b3bbb7775e49269a1b5cd6b94bba62da29a2ecb048ccf2'))
    'libarchive/lzh/test_read_format_lha_header2.lzh' = @(@(60, 'd0c504f06bbd64d183524eb35e5482ee5d966d456b905a24147165b2904d301b'), @(78, '60f47caf717b06cf21b3bbb7775e49269a1b5cd6b94bba62da29a2ecb048ccf2'))
    'libarchive/lzh/test_read_format_lha_header3.lzh' = @(@(60, 'd0c504f06bbd64d183524eb35e5482ee5d966d456b905a24147165b2904d301b'), @(78, '60f47caf717b06cf21b3bbb7775e49269a1b5cd6b94bba62da29a2ecb048ccf2'))
    'libarchive/lzh/test_read_format_lha_lh0.lzh' = @(@(60, 'd0c504f06bbd64d183524eb35e5482ee5d966d456b905a24147165b2904d301b'), @(78, '60f47caf717b06cf21b3bbb7775e49269a1b5cd6b94bba62da29a2ecb048ccf2'))
    'libarchive/lzh/test_read_format_lha_lh6.lzh' = @(@(60, 'd0c504f06bbd64d183524eb35e5482ee5d966d456b905a24147165b2904d301b'), @(78, '60f47caf717b06cf21b3bbb7775e49269a1b5cd6b94bba62da29a2ecb048ccf2'))
    'libarchive/lzh/test_read_format_lha_lh7.lzh' = @(@(60, 'd0c504f06bbd64d183524eb35e5482ee5d966d456b905a24147165b2904d301b'), @(78, '60f47caf717b06cf21b3bbb7775e49269a1b5cd6b94bba62da29a2ecb048ccf2'))
    'delharc/explzh_723-h2_subdir.lzh' = @(, @(12, 'a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447'))
    'delharc/generated-lzs-lzs.lzs' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/larc333-lz4.lzs' = @(, @(6829, '5c423e9bdf915d23972369959f5a71bfbcc1d32d09fb8d7198755861d289966e'))
    'delharc/larc333-lz5.lzs' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lha_amiga_122-lh4.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lha_amiga_212-lh6.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lha_os2_208-h3_lh5.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lha_os2_208-h3_subdir.lzh' = @(, @(14, '13dd7774cadfb09f8732ec2cc183916c9d0304dc6e7fa6640f6cefefae4cba12'))
    'delharc/lha_os9_211c-h1_lh1.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lha_unix114i-h1_subdir.lzh' = @(, @(12, 'a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447'))
    'delharc/lha_unix114i-h1_symlink.lzh' = @()
    'delharc/lha_unix114i-h2_lh7.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lha_x68k_213-h2_subdir.lzh' = @(, @(12, 'a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447'))
    'delharc/lha213-lh5.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lharc_atari_313a-h2_lz5.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/lharc113-lh1.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/maclha_224-l2_subdir.lzh' = @(, @(256, '0c5c76c4ab0b88815f3b77ac9e8fac869afbcd966fcd5aabe7c89b5cc303c2b0'))
    'delharc/morphos_lha_2717-h2_lh6.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
    'delharc/pmarc124-pm1.pma' = @(, @(25284, '66875d5ccf1f362902a3a14fad934fcb69522cc2a2b4f5a84978fe2569c33e45'))
    'delharc/pmarc2-comment.pma' = @(, @(128, '481cc3b501c83a210c1840b9ec898a90c529de8fe3555c720656b620b56cea72'))
    'delharc/pmarc2-pm0.pma' = @(, @(6912, '0cb1a4b3dbb909a803100a92240a61163d99dee10a8329876a6b7996bdc9a27b'))
    'delharc/regression-unixsep.lzh' = @(, @(12, 'a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447'))
    'delharc/unlha32-h2_lhx.lzh' = @(, @(18092, '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'))
}

function Sha256([byte[]]$bytes) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

# uudecode: a "begin" line, then lines whose first character gives their length.
function Decode-Uu([string]$text) {
    $lines = $text -split "`r?`n"
    $i = 0
    while ($i -lt $lines.Length -and -not $lines[$i].StartsWith('begin ')) { $i++ }
    $buf = [IO.MemoryStream]::new()
    for ($i++; $i -lt $lines.Length -and $lines[$i] -ne 'end'; $i++) {
        $l = $lines[$i]
        if ($l.Length -eq 0) { continue }
        $n = ([int]$l[0] - 32) -band 63
        if ($n -eq 0) { continue }
        $bytes = [byte[]]::new([math]::Ceiling($n / 3) * 3)
        $k = 0
        for ($j = 1; $k -lt $n; $j += 4) {
            $c = [int[]]::new(4)
            for ($q = 0; $q -lt 4; $q++) {
                $c[$q] = if ($j + $q -lt $l.Length) { ([int]$l[$j + $q] - 32) -band 63 } else { 0 }
            }
            $bytes[$k++] = (($c[0] -shl 2) -bor ($c[1] -shr 4)) -band 255
            $bytes[$k++] = ((($c[1] -band 15) -shl 4) -bor ($c[2] -shr 2)) -band 255
            $bytes[$k++] = ((($c[2] -band 3) -shl 6) -bor $c[3]) -band 255
        }
        $buf.Write($bytes, 0, $n)
    }
    , $buf.ToArray()
}

function Get-Bytes([string]$url) {
    $r = Invoke-WebRequest $url -UserAgent $agent
    $ms = [IO.MemoryStream]::new()
    $r.RawContentStream.CopyTo($ms)
    , $ms.ToArray()
}

$work = Join-Path ([IO.Path]::GetTempPath()) "beezip-libarchive-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory $work | Out-Null
$fetched = [ordered]@{}

function Save([string]$dir, [string]$name, [byte[]]$bytes) {
    $hash = Sha256 $bytes
    $key = "$dir/$name"
    if (-not $Record) {
        if (-not $sha256.ContainsKey($key)) { throw "no SHA-256 recorded for $key" }
        if ($sha256[$key] -ne $hash) { throw "$key has SHA-256 $hash, expected $($sha256[$key])" }
    }
    $fetched[$key] = $hash
    New-Item -ItemType Directory -Force (Join-Path $work $dir) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $work "$dir/$name"), $bytes)
}

foreach ($f in $la) {
    $f.name = Split-Path -Leaf $f.src
    $f.folder = if ($f.Contains('broken')) { "libarchive/$($f.dir)/broken" } else { "libarchive/$($f.dir)" }
    $text = (Invoke-WebRequest "$laBase/$($f.src).uu").Content
    if ($text -is [byte[]]) { $text = [Text.Encoding]::Latin1.GetString($text) }
    Save $f.folder $f.name (Decode-Uu $text)
}
foreach ($d in $dh) {
    $d.folder = if ($d.Contains('broken')) { 'delharc/broken' } else { 'delharc' }
    Save $d.folder $d.name (Get-Bytes "$dhBase/tests/$($d.src)")
}
foreach ($l in 'LICENSE-MIT', 'LICENSE-APACHE') { Save 'delharc' $l (Get-Bytes "$dhBase/$l") }
foreach ($p in $pkgs) { Save 'packages' $p.name (Get-Bytes $p.url) }

if ($Record) {
    '$sha256 = @{'
    foreach ($f in $fetched.GetEnumerator()) { "    '$($f.Key)' = '$($f.Value)'" }
    '}'
    Remove-Item -Recurse -Force $work
    return
}

# Tools ----------------------------------------------------------------------------------------

function Wsl-Path([string]$p) {
    $full = [IO.Path]::GetFullPath($p)
    '/mnt/' + $full.Substring(0, 1).ToLowerInvariant() + ($full.Substring(2) -replace '\\', '/')
}

function Oracle([string[]]$arguments) {
    $json = & python -I $oracle @arguments | Out-String
    $r = $json | ConvertFrom-Json -AsHashtable
    if ($LASTEXITCODE -ne 0 -or $r.ContainsKey('error')) { throw "oracles.py $arguments failed: $json" }
    $r
}

function Wsl-Oracle([string[]]$arguments) {
    $json = & wsl -e python3 -I (Wsl-Path $oracle) @arguments | Out-String
    $r = $json | ConvertFrom-Json -AsHashtable
    if ($LASTEXITCODE -ne 0 -or $r.ContainsKey('error')) { throw "WSL oracles.py $arguments failed: $json" }
    $r
}

function New-Dir([string]$what) {
    $d = Join-Path $work "$what-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    New-Item -ItemType Directory $d | Out-Null
    $d
}

# A stream decoded: 7-Zip for the codecs it has, oracles.py for lz4 and lzip, liblzo2 for lzop.
function Decompress([string]$codec, [string]$path) {
    $dest = New-Dir 'inner'
    $file = Join-Path $dest 'data'
    switch ($codec) {
        { $_ -in 'lz4', 'lzip' } { Oracle @('decompress', $codec, $path, $file) | Out-Null }
        'lzop' { Wsl-Oracle @('decompress', 'lzop', (Wsl-Path $path), (Wsl-Path $file)) | Out-Null }
        default {
            & $sevenZip e -y -sccUTF-8 "-o$dest" $path | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "7z e $path failed" }
            $got = @(Get-ChildItem $dest -File)
            if ($got.Count -ne 1) { throw "7z e $path gave $($got.Count) files" }
            Move-Item $got[0].FullName $file
            if ($codec -eq 'compress') {
                # A second decoder: gzip reads .Z too.
                $z = & wsl -e sh -c 'gzip -dc < "$1" | sha256sum' sh (Wsl-Path $path)
                if ($LASTEXITCODE -ne 0 -or ($z -split ' ')[0] -ne (Sha256 ([IO.File]::ReadAllBytes($file)))) {
                    throw "gzip and 7-Zip decode $path differently"
                }
            }
        }
    }
    $file
}

# What `7z t` said: "ok", "ok, with warnings: ...", "errors: ...", or "can't open it".
function Test-7z([string]$path, [string]$type) {
    $t = @(if ($type) { "-t$type" })
    $log = @(& $sevenZip t -sccUTF-8 @t $path 2>&1 | ForEach-Object { "$_".Trim() })
    $code = $LASTEXITCODE
    if ($log -match '^(Open ERROR: )?Can(no|\x27)t open the file as (\[\w+\] )?archive$') { return "can't open it" }
    $msgs = @($log | ForEach-Object { ($_.Replace($path, '') -replace '^(ERROR|Open ERROR|WARNING):\s*', '').Trim() } |
        Where-Object { $_ -match '(Error|There are (some )?data after|Unexpected end|Unsupported Method|CRC Failed|Is not archive)' } |
        Where-Object { $_ -notmatch '^(ERRORS?:|Archives with Errors|Sub items Errors|Open Errors)' } | Select-Object -Unique)
    if ($code -eq 0 -and $msgs.Count -eq 0) { return 'ok' }
    if ($code -eq 0) { return "ok, with warnings: $($msgs -join '; ')" }
    "errors: $($msgs -join '; ')"
}

# What 7-Zip lists and extracts: files and symlinks, in archive order; with `-crc`, each file's
# CRC-16 too. `$type` makes 7-Zip open it as that format or not at all (it finds the gzip file
# stored in a LArc archive, for one).
function List-7z([string]$path, [switch]$crc, [string]$type) {
    $t = @(if ($type) { "-t$type" })
    $list = & $sevenZip l -slt -sccUTF-8 @t $path 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    $items = @()
    $cur = $null
    $seenTail = $false
    foreach ($line in $list) {
        if ($line -eq '----------') { $seenTail = $true; continue }
        if (-not $seenTail) { continue }
        if ($line -match '^Path = (.*)$') {
            if ($cur) { $items += , $cur }
            $cur = @{ Path = $Matches[1] }
        } elseif ($cur -and $line -match '^(\w[\w ]*) = (.*)$') {
            $cur[$Matches[1]] = $Matches[2]
        }
    }
    if ($cur) { $items += , $cur }
    $entries = @()
    foreach ($it in $items) {
        if ($it['Folder'] -eq '+') { continue }
        # As format::normalize has it: no leading ./ or /.
        $rel = ($it.Path -replace '\\', '/') -replace '^(\./|/)+', ''
        $link = if ($it.ContainsKey('Symbolic Link')) { $it['Symbolic Link'] } else { '' }
        $mode = if ($it.ContainsKey('Mode')) { $it['Mode'] } else { '' }
        if ($link -or $mode -like 'l*') {
            $entries += [ordered]@{ path = $rel; kind = 'symlink'; target = ($link -replace '\\', '/') }
            continue
        }
        if ($mode -and $mode -notlike '-*') { continue }
        $hard = if ($it.ContainsKey('Hard Link')) { $it['Hard Link'] } else { '' }
        $bytes = Read-7z $path $(if ($hard) { $hard } else { $it.Path }) $type
        if ($null -eq $bytes) {
            # 7-Zip couldn't extract it.
            $entries += [ordered]@{ path = $rel; kind = 'file'; size = $null; sha256 = $null }
            continue
        }
        $e = [ordered]@{ path = $rel; kind = 'file'; size = $bytes.Length; sha256 = Sha256 $bytes }
        if ($crc) { $e.crc16 = Crc16 $bytes }
        $entries += $e
    }
    , $entries
}

# One entry's bytes, extracted alone (-ssc: names that differ in case are different entries), or
# $null when 7-Zip fails.
function Read-7z([string]$archive, [string]$entry, [string]$type) {
    $dest = New-Dir 'x'
    $t = @(if ($type) { "-t$type" })
    & $sevenZip x -y -ssc -sccUTF-8 @t "-o$dest" $archive -- $entry 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return $null }
    $got = @(Get-ChildItem -Recurse -File $dest)
    if ($got.Count -ne 1) { return $null }
    , [IO.File]::ReadAllBytes($got[0].FullName)
}

# CRC-16/ARC, LHA's.
$crcTable = [int[]]::new(256)
for ($n = 0; $n -lt 256; $n++) {
    $c = $n
    for ($i = 0; $i -lt 8; $i++) { $c = if ($c -band 1) { ($c -shr 1) -bxor 0xA001 } else { $c -shr 1 } }
    $crcTable[$n] = $c
}
function Crc16([byte[]]$data) {
    $crc = 0
    foreach ($b in $data) { $crc = ($crc -shr 8) -bxor $crcTable[($crc -bxor $b) -band 255] }
    $crc
}

# Differences between two listings, matched by path, or by order when `$byOrder` (names in a
# legacy code page, which 7-Zip reads in another).
function Compare-Listings($mine, $theirs, [switch]$byOrder) {
    $diffs = @()
    if ($byOrder) {
        if ($mine.Count -ne $theirs.Count) { return , @("$($mine.Count) entries against 7-Zip's $($theirs.Count)") }
        for ($i = 0; $i -lt $mine.Count; $i++) { $diffs += Compare-Entry $mine[$i] $theirs[$i] }
        return , $diffs
    }
    foreach ($m in $mine) {
        $t = @($theirs | Where-Object { $_.path -eq $m.path })
        if ($t.Count -eq 0) { $diffs += "7-Zip doesn't list $($m.path)"; continue }
        $diffs += Compare-Entry $m $t[0]
    }
    foreach ($t in $theirs) {
        if (-not ($mine | Where-Object { $_.path -eq $t.path })) { $diffs += "7-Zip lists $($t.path), oracles.py doesn't" }
    }
    , $diffs
}

function Compare-Entry($m, $t) {
    if ($m.kind -ne $t.kind) { return "$($m.path): $($m.kind), 7-Zip says $($t.kind)" }
    if ($m.kind -eq 'symlink') {
        if ($m.target -ne $t.target) { return "$($m.path): target $($m.target), 7-Zip says $($t.target)" }
        return @()
    }
    if ($m.size -ne $t.size) { return "$($m.path): $($m.size) bytes, 7-Zip says $($t.size)" }
    if ($m.Contains('sha256') -and $m.sha256 -ne $t.sha256) { return "$($m.path): bytes differ from 7-Zip's" }
    @()
}

function Entry($e) {
    if ($e.kind -eq 'symlink') { return [ordered]@{ path = $e.path; kind = 'symlink'; target = $e.target } }
    [ordered]@{ path = $e.path; kind = 'file'; size = [long]$e.size; sha256 = $e.sha256 }
}

# Expected entries ---------------------------------------------------------------------------

# Two entries Windows can't both extract: names equal but for case, with different contents.
function Assert-Extractable($entries, [string]$file) {
    $seen = @{}
    foreach ($e in $entries) {
        $k = $e.path.ToLowerInvariant()
        $v = if ($e.kind -eq 'symlink') { "-> $($e.target)" } else { $e.sha256 }
        if ($seen.ContainsKey($k) -and $seen[$k] -ne $v) { throw "$($file): $($e.path) collides with another entry on Windows" }
        $seen[$k] = $v
    }
}

# What BeeZip must list for fixture `$f` at `$path`: entries, links, and the cross-check's
# differences (which only a `note` may leave standing).
function Expected($f, [string]$path) {
    $enc = if ($f.Contains('encoding')) { $f.encoding } else { 'auto' }
    $layers = @($f.chain -split ' → ')
    $fmt = $layers[-1]
    $diffs = @()
    $notes = @()

    if ($fmt -in 'compress', 'lzop') {
        $data = [IO.File]::ReadAllBytes((Decompress $fmt $path))
        $e = [ordered]@{ path = '*'; kind = 'file'; size = $data.Length; sha256 = Sha256 $data }
        return @{ entries = @($e); hardlinks = 0; diffs = @(); notes = @(); info = $null }
    }
    $inner = if ($layers.Count -gt 1) { Decompress $layers[0] $path } else { $path }

    switch ($fmt) {
        { $_ -in 'cpio', 'tar', 'ar' } {
            $p = Oracle @('list', $fmt, $inner, $enc)
            $s = List-7z $inner
            if ($null -eq $s) { $diffs += "7-Zip can't list it" } else { $diffs += Compare-Listings $p.entries $s -byOrder:($enc -ne 'auto') }
        }
        'rpm' {
            $p = Oracle @('list', 'rpm', $path, $enc)
            # 7-Zip shows the payload as one file (-trpm: without opening it too); then the cpio
            # inside it.
            $x = New-Dir 'rpm'
            & $sevenZip x -y -trpm -sccUTF-8 "-o$x" $path | Out-Null
            $payload = @(Get-ChildItem $x -File)
            $s = $null
            if ($LASTEXITCODE -eq 0 -and $payload.Count -eq 1) {
                $x2 = New-Dir 'payload'
                & $sevenZip x -y -sccUTF-8 "-o$x2" $payload[0].FullName | Out-Null
                $cpio = @(Get-ChildItem $x2 -File)
                if ($LASTEXITCODE -eq 0 -and $cpio.Count -eq 1) { $s = List-7z $cpio[0].FullName }
            }
            if ($null -eq $s) { $diffs += "7-Zip can't list its payload" } else { $diffs += Compare-Listings $p.entries $s }
        }
        'deb' {
            $p = Deb-Listing $path
            $diffs += $p.diffs
        }
        'cab' {
            $more = @(if ($f.Contains('parts')) { $f.parts | ForEach-Object { Join-Path (Split-Path $path) $_ } })
            $p = Oracle (@('list', 'cab', $path, $enc) + $more)
            $s = List-7z $path
            $files = @($p.entries)
            for ($i = 0; $i -lt $files.Count; $i++) {
                $e = $files[$i]
                if ($f.Contains('data') -and $f.data.ContainsKey($e.path)) {
                    $bytes = [Text.Encoding]::ASCII.GetBytes($f.data[$e.path])
                    if ($bytes.Length -ne $e.size) { throw "$($f.name): $($e.path)'s bytes from the test source have the wrong size" }
                    $e.sha256 = Sha256 $bytes
                    $diffs += "$($e.path): bytes from libarchive's test source"
                    continue
                }
                if ($null -eq $s -or $s.Count -ne $files.Count) { throw "$($f.name): 7-Zip lists $(if ($s) { $s.Count } else { 'nothing' }), oracles.py $($files.Count)" }
                if ($enc -eq 'auto' -and $s[$i].path -ne $e.path) { $diffs += "$($e.path): 7-Zip calls it $($s[$i].path)" }
                if ($s[$i].size -ne $e.size) { $diffs += "$($e.path): $($e.size) bytes, 7-Zip extracted $($s[$i].size)" }
                $e.sha256 = $s[$i].sha256
            }
        }
        'iso' {
            # 7-Zip reads Rock Ridge and Joliet names and Rock Ridge's links itself.
            $s = List-7z $inner
            if ($null -eq $s) { throw "$($f.name): 7-Zip can't list it" }
            if ($f.Contains('relocated')) {
                # Each relocated folder back where it belongs, and the empty file 7-Zip shows
                # there dropped.
                $moved = @()
                foreach ($e in $s) {
                    if ($f.relocated.Values -contains $e.path) { continue }
                    foreach ($k in $f.relocated.Keys) {
                        if ($e.path.StartsWith("$k/")) { $e.path = $f.relocated[$k] + $e.path.Substring($k.Length) }
                    }
                    $moved += $e
                }
                $s = $moved
                $diffs += 'relocated folders put back'
            }
            if ($f.Contains('expect')) {
                # Where 7-Zip is wrong, the answer from libarchive's tests (the fixture's note).
                $s = @(& $f.expect $s)
                $diffs += 'entries from libarchive''s test'
            }
            $p = @{ entries = $s; hardlinks = 0; others = @() }
        }
        'lzh' {
            $p = Oracle @('list', 'lzh', $path, $enc)
            $s = List-7z $path -crc -type lzh
            $sFiles = @(if ($s) { $s | Where-Object { $_.kind -eq 'file' } })
            $files = @($p.entries | Where-Object { $_.kind -eq 'file' })
            $key = "$($f.folder)/$($f.name)"
            $fromDelharc = @()
            $unconfirmed = @()
            for ($i = 0; $i -lt $files.Count; $i++) {
                $e = $files[$i]
                # 7-Zip's entry: by name, or by position when the names differ (7-Zip ignores
                # UTF-16 names, and reads legacy ones in another code page).
                $theirs = $sFiles | Where-Object { $_.path -eq $e.path } | Select-Object -First 1
                if (-not $theirs -and $sFiles.Count -eq $files.Count) {
                    $theirs = $sFiles[$i]
                    if ($enc -eq 'auto') { $diffs += "$($e.path): 7-Zip calls it $($theirs.path)" }
                }
                # 7-Zip's bytes count only if they pass the header's CRC-16.
                $ok7 = $theirs -and $null -ne $theirs.sha256 -and $theirs.size -eq $e.size -and $theirs.crc16 -eq $e.crc16
                $dhv = if ($delharcData.ContainsKey($key)) { $delharcData[$key][$i] } else { $null }
                if ($dhv -and ($dhv[0] -ne $e.size)) { throw "$($key): delharc decoded $($dhv[0]) bytes of $($e.path), the header says $($e.size)" }
                if (-not $ok7) { $unconfirmed += $e.method }
                if ($e.Contains('sha256')) {
                    # Stored: oracles.py hashed it, and checked its CRC-16.
                    if ($ok7 -and $theirs.sha256 -ne $e.sha256) { $diffs += "$($e.path): 7-Zip extracts other bytes" }
                } elseif ($ok7) {
                    $e.sha256 = $theirs.sha256
                } elseif ($dhv) {
                    $e.sha256 = $dhv[1]
                    $fromDelharc += $e.method
                } else {
                    throw "$($key): 7-Zip can't decode $($e.path) ($($e.method)), and delharc's table has nothing for it"
                }
                if ($dhv -and $e.sha256 -ne $dhv[1]) { $diffs += "$($e.path): delharc decodes other bytes" }
            }
            if ($unconfirmed.Count) {
                $what = if ($null -eq $s) { "can't open this archive ($($p.info.methods -join ', '), header level $($p.info.levels -join ', '))" } else { "can't decode $(($unconfirmed | Select-Object -Unique) -join ', ')" }
                $from = if ($fromDelharc.Count) { "the bytes are delharc 0.8.0's, each checked against its CRC-16 and delharc's tests' CRC-32s" } else { "the bytes are stored, read by oracles.py and checked against their CRC-16s and delharc 0.8.0's" }
                $notes += "7-Zip 26.00 $($what): names from oracles.py; $from."
            }
            if (@($p.entries | Where-Object { $_.kind -eq 'symlink' }).Count) {
                $notes += 'Symlinks (-lhd- with S_IFLNK, named `link|target`) from oracles.py; 7-Zip lists them as folders.'
            }
        }
    }
    if ($p.others.Count) { throw "$($f.name): devices or FIFOs ($($p.others -join ', ')), which extraction would skip" }
    $entries = @($p.entries | ForEach-Object { Entry $_ })
    Assert-Extractable $entries $f.name
    @{ entries = $entries; hardlinks = [int]$p.hardlinks; diffs = @($diffs | Where-Object { $_ }); notes = $notes; info = $p['info'] }
}

# A deb as `dpkg-deb -R` unpacks it, hashed in WSL; its hard links counted in data.tar; and
# 7-Zip's view of data.tar and control.tar beside it.
function Deb-Listing([string]$path) {
    $x = New-Dir 'deb'
    & wsl -e dpkg-deb -R (Wsl-Path $path) (Wsl-Path (Join-Path $x 'root'))
    if ($LASTEXITCODE -ne 0) { throw "dpkg-deb -R $path failed" }
    $p = Wsl-Oracle @('tree', (Wsl-Path (Join-Path $x 'root')))
    $tar = Join-Path $x 'data.tar'
    & wsl -e sh -c 'dpkg-deb --fsys-tarfile "$1" > "$2"' sh (Wsl-Path $path) (Wsl-Path $tar)
    if ($LASTEXITCODE -ne 0) { throw "dpkg-deb --fsys-tarfile $path failed" }
    $t = Oracle @('list', 'tar', $tar)
    $p.hardlinks = $t.hardlinks
    $p.others = $t.others
    # 7-Zip: the ar's members (-tar: as an ar, without opening data.tar too), then each tar.
    $m = New-Dir 'members'
    & $sevenZip x -y -tar -sccUTF-8 "-o$m" $path | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z x $path failed" }
    $members = @(Get-ChildItem $m -File | Sort-Object Name | ForEach-Object Name)
    $seven = @()
    foreach ($member in Get-ChildItem $m -File) {
        if ($member.Name -match '^(data|control)\.tar(\..+)?$') {
            $prefix = if ($Matches[1] -eq 'control') { 'DEBIAN/' } else { '' }
            $inner = $member.FullName
            if ($Matches[2]) {
                $d = New-Dir 'tar'
                & $sevenZip e -y -sccUTF-8 "-o$d" $member.FullName | Out-Null
                $inner = (Get-ChildItem $d -File)[0].FullName
            }
            foreach ($e in (List-7z $inner)) { $e.path = $prefix + $e.path; $seven += $e }
        }
    }
    $p.diffs = Compare-Listings $p.entries $seven
    # The package's licence, from its copyright file (DEP-5: "License: ...").
    $copyright = Get-ChildItem -Recurse -File (Join-Path $x 'root/usr/share/doc') -Filter copyright | Select-Object -First 1
    $licenses = @(Get-Content $copyright.FullName | Where-Object { $_ -match '^License: ' } | ForEach-Object { $_ -replace '^License: ', '' } | Select-Object -Unique)
    $control = Get-Content (Join-Path $x 'root/DEBIAN/control')
    $version = ($control | Where-Object { $_ -match '^Version: ' }) -replace '^Version: ', ''
    $package = ($control | Where-Object { $_ -match '^Package: ' }) -replace '^Package: ', ''
    $p.info = @{ members = $members; license = $licenses -join ', '; nevra = "$package-$version" }
    $p
}

$records = [Collections.Generic.List[object]]::new()
$log = [Collections.Generic.List[string]]::new()

function Add-Record($f, [string]$producer, [string]$command) {
    $key = "$($f.folder)/$($f.name)"
    $path = Join-Path $work $key
    $x = Expected $f $path
    $notes = @(@($(if ($f.Contains('note')) { $f.note })) + $x.notes | Where-Object { $_ })
    if ($x.diffs.Count -and -not $notes) { throw "$($key): oracles.py and 7-Zip disagree, with no note to say why:`n  $($x.diffs -join "`n  ")" }
    foreach ($d in $x.diffs) { $log.Add("$($key): $d") }
    $seven = Test-7z $path $(if ($f.chain -eq 'lzh') { 'lzh' })
    $log.Add("$($key): 7z t $seven")
    $fx = [ordered]@{
        file = $key; producer = $producer; command = $command; chain = $f.chain
        password = $null; utc_mtimes = $false; hardlinks = $x.hardlinks
        symlinks = @($x.entries | Where-Object { $_.kind -eq 'symlink' }).Count
    }
    if ($f.Contains('parts')) { $fx.parts = @($f.parts | ForEach-Object { "$($f.folder)/$_" }) }
    if ($f.Contains('encoding')) { $fx.encoding = $f.encoding }
    if ($notes) { $fx.note = $notes -join ' ' }
    $fx['7z_test'] = $seven
    $fx.entries = @($x.entries)
    $records.Add($fx)
    $x
}

# Every fixture is tried before giving up, so one run shows every problem.
$failures = [Collections.Generic.List[string]]::new()
function Try-Record($f, [string]$producer, [string]$command) {
    try { Add-Record $f $producer $command } catch { $failures.Add("$($f.folder)/$($f.name): $_"); $null }
}
foreach ($f in $la) {
    if ($f.Contains('broken') -or $f.Contains('part')) { continue }
    Try-Record $f "from libarchive 3.8.11's tests" "$($f.src).uu at $tag, uudecoded" | Out-Null
}
foreach ($d in $dh) {
    if ($d.Contains('broken')) { continue }
    $d.chain = 'lzh'
    Try-Record $d "$($d.tool), from delharc 0.8.0's tests" "tests/$($d.src) at $dhTag" | Out-Null
}
foreach ($p in $pkgs) {
    $p.folder = 'packages'
    $x = Try-Record $p "$($p.distro)'s package" $p.url
    if (-not $x) { continue }
    # The compressor is the point of each package: check it's the one wanted.
    if ($p.chain -eq 'rpm') {
        $p.license = $x.info.license
        if ($x.info.payload_compressor -ne $p.compressor) { throw "$($p.name)'s payload is $($x.info.payload_compressor), not $($p.compressor)" }
    } else {
        $p.license = $x.info.license
        $ext = @{ zstd = 'zst'; xz = 'xz' }[$p.compressor]
        if ($x.info.members -notcontains "data.tar.$ext") { throw "$($p.name) holds $($x.info.members -join ', '), not data.tar.$ext" }
    }
    if ($p.license -notin 'MIT', 'Expat') { $failures.Add("$($p.name) is under $($p.license), not MIT") }
    if ($x.info.nevra -notlike "python3-six-$($p.version)*") { $failures.Add("$($p.name) is $($x.info.nevra), not python3-six $($p.version)") }
}
if ($failures.Count) {
    $log
    Remove-Item -Recurse -Force $work
    throw "$($failures.Count) fixtures failed:`n$($failures -join "`n")"
}

# The READMEs beside the files -----------------------------------------------------------------

# Lines as UTF-8 with LF endings.
function Write-Text([string]$path, [string[]]$lines) {
    [IO.File]::WriteAllText($path, ($lines -join "`n") + "`n")
}

function Broken-Readme([string]$folder, [string]$source, $list) {
    $lines = @(
        '# Broken fixtures', '', $source
        'They aren''t in manifest.json: each must fail as below, without a panic, a hang or a large'
        'allocation. fetch-libarchive.ps1 writes this file.', ''
        '| File | Expected | Why |', '|---|---|---|'
    )
    foreach ($b in $list) { $lines += "| ``$($b.name)`` | $($b.broken) | $($b.why) |" }
    Write-Text (Join-Path $work "$folder/README.md") $lines
}
foreach ($group in $la | Where-Object { $_.Contains('broken') } | Group-Object { $_.dir }) {
    Broken-Readme "libarchive/$($group.Name)/broken" 'From libarchive 3.8.11''s tests (BSD-2-Clause, see ../../COPYING).' $group.Group
}
Broken-Readme 'delharc/broken' 'From delharc 0.8.0''s tests (MIT OR Apache-2.0, see ../LICENSE-MIT and ../LICENSE-APACHE; most come from lhasa''s regression set).' @($dh | Where-Object { $_.Contains('broken') })

$lines = @(
    '# delharc test archives', ''
    'From delharc 0.8.0 (https://github.com/royaltm/rust-delharc, tag v0.8.0), MIT OR Apache-2.0:'
    'LICENSE-MIT and LICENSE-APACHE are its licence files. delharc''s tests/README.md says most of'
    'its archives were copied from lhasa (https://github.com/fragglet/lhasa, ISC). Each file here is'
    'tests/<folder>/<name> there, renamed <folder>-<name>. fetch-libarchive.ps1 writes this file.', ''
    '| File | Made by |', '|---|---|'
)
foreach ($d in $dh | Where-Object { -not $_.Contains('broken') }) { $lines += "| ``$($d.name)`` | $($d.tool) |" }
Write-Text (Join-Path $work 'delharc/README.md') $lines

$lines = @(
    '# Packages', ''
    'Small noarch packages of six (Python 2 and 3 compatibility, MIT), as their distributions'
    'publish them, so the fixtures carry no copyleft code. Each package''s own licence field says'
    'so: the RPM header''s License tag, the deb''s usr/share/doc/python3-six/copyright.'
    'fetch-libarchive.ps1 fetches them and writes this file.', ''
    '| File | Package | From | Compressed with | Licence | Source |', '|---|---|---|---|---|---|'
)
foreach ($p in $pkgs) {
    $licence = if ($p.license -eq 'Expat') { 'Expat (MIT)' } else { $p.license }
    $what = if ($p.chain -eq 'rpm') { "$($p.compressor) (PAYLOADCOMPRESSOR)" } else { "$($p.compressor) (data.tar.$(@{ zstd = 'zst'; xz = 'xz' }[$p.compressor]))" }
    $lines += "| ``$($p.name)`` | python3-six $($p.version) | $($p.distro) | $what | $licence | $($p.url) |"
}
Write-Text (Join-Path $work 'packages/NOTICE.md') $lines

# Copy into place, and merge the records into the manifest: this script owns libarchive/<fmt>/,
# delharc/ and packages/; fetch-rar.ps1 and make-thirdparty.ps1 the rest.
$folders = @($fetched.Keys | ForEach-Object { $_.Substring(0, $_.LastIndexOf('/')) } | Select-Object -Unique)
foreach ($dir in $folders) {
    $target = Join-Path $out $dir
    New-Item -ItemType Directory -Force $target | Out-Null
    Get-ChildItem $target -File | Remove-Item -Force
    Get-ChildItem (Join-Path $work $dir) -File | Copy-Item -Destination $target
}
$manifestPath = Join-Path $PSScriptRoot 'manifest.json'
$manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json -AsHashtable
$mine = { param($file) $file -match '^libarchive/(cpio|ar|rpm|cab|lzh|compress|lzop|iso)/' -or $file -like 'delharc/*' -or $file -like 'packages/*' }
# The new records go where the old ones were, so a rerun leaves the order alone.
$old = @($manifest.fixtures)
$at = 0
while ($at -lt $old.Count -and -not (& $mine $old[$at].file)) { $at++ }
$before = @(if ($at -gt 0) { $old[0..($at - 1)] })
$after = @($old | Select-Object -Skip $at | Where-Object { -not (& $mine $_.file) })
$manifest.fixtures = $before + $records + $after
($manifest | ConvertTo-Json -Depth 6) -replace "`r`n", "`n" | Set-Content -NoNewline $manifestPath
$log
Remove-Item -Recurse -Force $work
$size = ($folders | ForEach-Object { Get-ChildItem -File (Join-Path $out $_) } | Measure-Object Length -Sum).Sum
"fetched $($fetched.Count) files ($([math]::Round($size / 1KB)) KiB), $($records.Count) in the manifest"
