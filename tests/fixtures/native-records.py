"""The records of what BeeZip's own readers list from the 7-Zip backend's images (docs/M7.md §10).

Since M7 BeeZip reads FAT, NTFS, ext, HFS+, APFS, GPT and MBR disks and MSI installers itself,
since M8 WIM images (docs/M8.md §5; an LZMS one only on Windows, so wimlib-solid.esd has no
native record here: tests/wim.rs reads wimlib's LZMS images natively on Windows), since M9 CHM
help files (docs/M9.md), and since M10 CramFS images and NSIS installers (docs/M10.md).
make-7z.sh records what 7-Zip lists from its images (`"backend": "7-zip"`), and the fixture test
reads those through 7-Zip. This script derives, from each of those records, what BeeZip's own
reader must list from the same image (`"native": true`): the same files with the same bytes, as
7-Zip extracted them, under the names BeeZip gives them. Nothing here comes from BeeZip's output.

What differs from 7-Zip's view:
- 7-Zip's pseudo entries go: ext's `[SYS]/Journal`; HFS+'s volume-name folder, which BeeZip
  doesn't list (as for a DMG). HFS+'s decomposed names are listed composed.
- A second name of a file is a hard link (7-Zip lists a second file): ext's and NTFS's
  `hard-readme.txt`.
- A disk of several partitions lists each readable one as a folder: gpt-fat-ext4.img's
  `0.data/` (the FAT12 of fat12.img) and `1.linux/` (an ext4 of the same tree).
- An MSI's files are named by where they install, not by their File keys.
- A WIM's `[1].xml` goes; a second name of a hard link group is a hard link.

Run it after make-7z.sh: `python tests/fixtures/native-records.py`. It owns the 7zip/ records
with `"native": true` and puts them after the 7-Zip records; make-cramfs.sh's cramfs/ records are
native too, and its own.
"""

import copy
import json
import os
import unicodedata

here = os.path.dirname(os.path.abspath(__file__))
manifest_path = os.path.join(here, 'manifest.json')
with open(manifest_path, encoding='utf-8') as f:
    manifest = json.load(f)
old = manifest['fixtures']
by_file = {r['file']: r for r in old if r.get('backend') == '7-zip'}

NOTE = ('Entries are what BeeZip\'s own reader lists (docs/M7.md), derived by native-records.py '
        'from the 7-Zip record of the same file: the same bytes, as `7z x` extracts them. ')


def files(record, drop=(), prefix='', strip=''):
    """The record's entries, without 7-Zip's pseudo entries and `drop`, renamed."""
    out = []
    for e in record['entries']:
        p = e['path']
        if (p.startswith('[SYSTEM]/$BadClus:') or p.startswith('[SYS]/') or p in drop
                or p == '[1].xml'):
            continue
        if strip:
            if not p.startswith(strip):
                continue
            p = p[len(strip):]
        e = copy.deepcopy(e)
        e['path'] = prefix + p
        out.append(e)
    return out


def native(file, levels, entries, hardlinks, symlinks, note, utc=None):
    r = copy.deepcopy(by_file[file])
    r.pop('backend', None)
    r.pop('7z_test', None)
    r['native'] = True
    r['levels'] = levels
    r['hardlinks'] = hardlinks
    r['symlinks'] = symlinks
    if utc is not None:
        r['utc_mtimes'] = utc
    r['note'] = NOTE + note
    r['entries'] = entries
    return r


records = []
for name in ('fat12.img', 'fat32.img'):
    f = '7zip/' + name
    records.append(native(f, ['fat'], files(by_file[f]), 0, 0,
                          'FAT holds local times with no zone, which BeeZip lists as written, so '
                          'files have no `mtime` here.'))
f = '7zip/mbr-fat.img'
records.append(native(f, ['mbr', 'fat'], files(by_file[f]), 0, 0,
                      'A disk with one partition opens straight into its file system, as 7-Zip '
                      'opens it.'))
for name in ('ext2.img', 'ext4.img'):
    f = '7zip/' + name
    records.append(native(f, ['ext'], files(by_file[f]), 1, 2,
                          'hard-readme.txt and readme.txt are one inode: the second name met is '
                          "a hard link. 7-Zip's `[SYS]/Journal` isn't listed."))
for name, levels in (('ntfs.img', ['ntfs']), ('gpt-ntfs.img', ['gpt', 'ntfs'])):
    f = '7zip/' + name
    records.append(native(f, levels, files(by_file[f]), 2, 2,
                          'System files are under `[SYSTEM]/` as 7-Zip lists them, without '
                          '`$BadClus:$Bad`. hard-readme.txt and readme.txt are one file record: '
                          "the second name in the folder's index order (readme.txt) is a hard "
                          'link, and so is its alternate stream readme.txt:hidden, which 7-Zip '
                          'lists only with `-sns`.'))
f = '7zip/gpt-fat-ext4.img'
fat = files(by_file['7zip/fat12.img'], prefix='0.data/')
ext = files(by_file['7zip/ext4.img'], prefix='1.linux/')
records.append(native(f, ['gpt'], fat + ext, 1, 2,
                      'A disk of several partitions lists each one BeeZip reads as a folder named '
                      'as 7-Zip names the partition, without its extension: 0.data/ is fat12.img '
                      'and 1.linux/ an ext4 of the same tree without a journal.'))
# Virtual disks (docs/M8.md §3): the disk inside, as its raw image lists.
for kind in ('vmdk', 'qcow2', 'vdi'):
    f = '7zip/gpt-fat-ext4.' + kind
    records.append(native(f, [kind, 'gpt'], copy.deepcopy(fat + ext), 1, 2,
                          f'BeeZip reads the {kind.upper()} itself and lists the disk inside as '
                          'gpt-fat-ext4.img lists: 0.data/ and 1.linux/ as folders (7-Zip lists '
                          'the two partitions as files).'))
for name in ('mbr-fat.vhd', 'mbr-fat-fixed.vhd'):
    f = '7zip/' + name
    records.append(native(f, ['vhd', 'mbr', 'fat'], files(by_file[f]), 0, 0,
                          'BeeZip reads the VHD itself; the disk inside has one partition, so it '
                          'opens straight into its file system, as 7-Zip opens it.'))
f = '7zip/gpt-ntfs.vhdx'
records.append(native(f, ['vhdx', 'gpt', 'ntfs'], files(by_file[f]), 2, 2,
                      'BeeZip reads the VHDX itself; inside, as gpt-ntfs.img lists.'))
f = '7zip/dmg-hfs.hfs'
hfs = files(by_file[f], strip='BeeZip HFS/')
for e in hfs:
    e['path'] = unicodedata.normalize('NFC', e['path'])
records.append(native(f, ['hfs'], hfs, 0, 1,
                      "The volume's files are listed from its root, as a DMG's are, without "
                      "7-Zip's folder named after the volume, and with HFS+'s decomposed names "
                      'composed (7-Zip lists them as stored).'))
f = '7zip/dmg-apfs.apfs'
records.append(native(f, ['apfs'], files(by_file[f]), 0, 1,
                      "The container's first volume, as a DMG's."))
f = '7zip/wixl.msi'
msi_names = {
    'readme': 'LocalAppDataFolder/BeeZip fixture/readme.txt',
    'empty': 'LocalAppDataFolder/BeeZip fixture/empty.txt',
    'random': 'LocalAppDataFolder/BeeZip fixture/random.bin',
    # wixl 0.103 empties a non-ASCII name under code page 65001 (docs/M7.md §15), so the file
    # is named by its key.
    'cjk': 'LocalAppDataFolder/BeeZip fixture/cjk',
}
msi = files(by_file[f])
for e in msi:
    e['path'] = msi_names[e['path']]
records.append(native(f, ['msi', 'cab'], msi, 0, 0,
                      'Files are named by the folder they install to and their File table names '
                      '(7-Zip lists their keys).'))

f = '7zip/tree.wim'
records.append(native(f, ['wim'], files(by_file[f]), 0, 0,
                      'BeeZip reads WIM images itself since M8 (docs/M8.md §5). One image, at the '
                      'top, as 7-Zip lists it; 7-Zip wrote the hard link pair as two files.'))
f = '7zip/wimlib.wim'
records.append(native(f, ['wim'], files(by_file[f]), 1, 3,
                      'Two images, the folders 1/ and 2/ as 7-Zip names them, without its '
                      "`[1].xml`. hard-readme.txt and readme.txt are one hard link group: the "
                      'second name in the image (readme.txt) is a hard link.'))

f = '7zip/chmcmd.chm'
records.append(native(f, ['chm'], files(by_file[f]), 0, 0,
                      'BeeZip reads CHM help files itself since M9 (docs/M9.md). The same files '
                      "as 7-Zip lists, CHM's own (#SYSTEM, $OBJINST…) among them, and the folder "
                      'pages, which 7-Zip lists as a 0-byte entry, as a folder.'))

for comp in ('lzma', 'zlib', 'bzip2'):
    f = '7zip/nsis-%s.exe' % comp
    records.append(native(f, ['nsis'], files(by_file[f]), 0, 0,
                          'BeeZip reads NSIS installers itself since M10 (docs/M10.md): the same '
                          'files 7-Zip lists, with exact sizes.'))

f = '7zip/cramfs.img'
records.append(native(f, ['cramfs'], files(by_file[f]), 0, 2,
                      'BeeZip reads CramFS images itself since M10 (docs/M10.md). CramFS has no '
                      "hard links: hard-readme.txt is a file of its own, which shares readme.txt's "
                      'data.'))

mine = lambda r: r.get('native') is True and r['file'].startswith('7zip/')
rest = [r for r in old if not mine(r)]
last = max(i for i, r in enumerate(rest) if r.get('backend') == '7-zip')
manifest['fixtures'] = rest[:last + 1] + records + rest[last + 1:]
with open(manifest_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest, indent=2, ensure_ascii=False))
print(f'{len(records)} native records')
