#!/bin/bash
# Makes tests/fixtures/thirdparty/cramfs/ for BeeZip's own CramFS reader (docs/M10.md §8), then
# merges their records into manifest.json (this script owns cramfs/). Run it from the
# repository, with Docker running and 7-Zip installed, in WSL or Git Bash:
#
#   bash tests/fixtures/make-cramfs.sh
#
# The images are made in make-7z.sh's container (make-7z.Dockerfile, beezip-fixtures-7z), which
# runs this script again with --inside. Tools: mkfs.cramfs 2.39.3 (util-linux) and python3 3.12
# with its lzma module. The data comes from seeded Random()s; CramFS stores no times, so a rerun
# writes the same bytes.
#
# thirdparty/cramfs/, one tree with every kind of node (files of 0 to 64 KiB, runs of zeros,
# non-ASCII and 248-byte names, 20 nested folders, an empty folder, five links, a character and a
# block device, a FIFO and a socket) as mkfs.cramfs writes it:
#   le.img            little-endian, 4 KiB blocks (mkfs.cramfs's defaults, with a name and an
#                     edition)
#   be.img            big-endian (-N big)
#   holes.img         all-zero blocks as holes (-z), which 7-Zip 26.00 fails as "Data Error"
#   pad.img           after a 512-byte boot block (-p), which 7-Zip can't open
#   b16k.img          16 KiB blocks (-b 16384), whose files of more than 4 KiB 7-Zip fails as
#                     "Unsupported Method"
# and two crafted here, since no tool on Linux writes them:
#   ext-ptrs.img      Linux 4.15's extended block pointers: a stored block, a direct stored one,
#                     a direct compressed one, then plain ones after them
#   sevenzip-lzma.img 7-Zip's own variant, LZMA blocks with a method in flag bits 14-15: BeeZip
#                     hands it to 7-Zip (docs/M10.md §5.3), so it has no record here
#
# The records' entries come from the tree the images were made from, not from 7-Zip, which
# reads few of them; le.img and be.img are checked against what 7-Zip extracts from them.
set -euo pipefail

# ---------------------------------------------------------------------------------------------
# In the container (root).
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    out=/fixtures/thirdparty/cramfs
    W=/work/tree
    rm -rf "$out" /work
    mkdir -p "$out" "$W"
    cd "$W"

    python3 -I - <<'PY'
import os, random, socket
r = random.Random(2026)
deep = 'deep/' + '/'.join('d%02d' % i for i in range(20))
files = {
    'readme.txt': b'hello cramfs\n',
    'empty.txt': b'',
    'same-as-readme.txt': b'hello cramfs\n',
    'exact4096.bin': r.randbytes(4096),
    'exact4097.bin': r.randbytes(4097),
    'zeros-64k.bin': bytes(65536),
    'holes.bin': r.randbytes(4096) + bytes(8192) + r.randbytes(4096) + bytes(100),
    'text.txt': b''.join(b'line %d of a text file that compresses well\n' % i for i in range(2500)),
    'random-20k.bin': r.randbytes(20000),
    deep + '/bottom.txt': b'bottom\n',
    'café-ñandú.txt': 'latin\n'.encode(),
    '名前.txt': 'cjk\n'.encode(),
    'bee-\U0001F41D.txt': 'emoji\n'.encode(),
    'n' * 244 + '.txt': b'a name of 248 bytes\n',
    'sub/inner/a.txt': b'a\n',
    'sub/b.txt': b'b\n',
}
for p, d in files.items():
    os.makedirs(os.path.dirname(p) or '.', exist_ok=True)
    open(p, 'wb').write(d)
os.makedirs('empty-dir', exist_ok=True)
s = socket.socket(socket.AF_UNIX)
s.bind('socket')
s.close()
PY
    ln -s readme.txt link-rel
    ln -s /etc/passwd link-abs
    ln -s does/not/exist link-dangling
    ln -s ../readme.txt sub/link-up
    ln -s "$(printf 't%.0s' $(seq 200))" link-long
    mknod chardev c 1 3
    mknod blockdev b 8 1
    mkfifo fifo
    chmod 4755 exact4096.bin
    chmod 0600 empty.txt

    mk() { local name=$1; shift; mkfs.cramfs "$@" "$W" "$out/$name" >/dev/null; }
    mk le.img -n BeeZipCramfs -e 7
    mk be.img -N big
    mk holes.img -z
    mk pad.img -p
    mk b16k.img -b 16384

    python3 -I - "$out" "$W" <<'PY'
import hashlib, json, lzma, os, stat, struct, sys, zlib
out, W = sys.argv[1:3]

# The tree's entries, as the records list them.
entries = []
for dirpath, dirs, names in os.walk(W):
    dirs.sort()
    for n in sorted(dirs + names):
        p = os.path.join(dirpath, n)
        rel = os.path.relpath(p, W)
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode):
            entries.append({'path': rel, 'kind': 'symlink', 'target': os.readlink(p)})
        elif stat.S_ISDIR(st.st_mode):
            if n in dirs:
                entries.append({'path': rel, 'kind': 'folder'})
        elif stat.S_ISREG(st.st_mode):
            d = open(p, 'rb').read()
            entries.append({'path': rel, 'kind': 'file', 'size': len(d),
                            'sha256': hashlib.sha256(d).hexdigest()})
        else:
            entries.append({'path': rel, 'kind': 'other'})
tree = entries

# Crafted images, laid out as Linux reads them (fs/cramfs/inode.c): the superblock and root
# inode, one folder, then each file's block pointers and blocks.
BLK = 4096
UNC, DIRECT = 1 << 31, 1 << 30

def inode(mode, size, namelen, offset):
    return struct.pack('<III', mode, size, (namelen // 4) | (offset // 4) << 6)

def image(files, flags, blocks):
    names = [n.encode() + b'\0' * (-len(n.encode()) % 4) for n, _ in files]
    dir_at = 76
    dir_len = sum(12 + len(n) for n in names)
    at = dir_at + dir_len
    blobs, offsets = [], []
    for name, data in files:
        count = -(-len(data) // BLK)
        tab, body = blocks(data, at + 4 * count)
        blob = tab + body
        blob += b'\0' * (-len(blob) % 4)
        offsets.append(at)
        blobs.append(blob)
        at += len(blob)
    d = bytearray(struct.pack('<IIII', 0x28CD3D45, 0, flags, 0) + b'Compressed ROMFS')
    d += struct.pack('<IIII', 0, 0, 0, len(files) + 1) + b'crafted'.ljust(16, b'\0')
    d += inode(0o40755, dir_len, 0, dir_at)
    for (name, data), n, off in zip(files, names, offsets):
        d += inode(0o100644, len(data), len(n), off) + n
    for b in blobs:
        d += b
    d += b'\0' * (-len(d) % BLK)
    struct.pack_into('<I', d, 4, len(d))
    struct.pack_into('<I', d, 32, zlib.crc32(bytes(d)))
    return bytes(d)

def ext_mixed(data, data_at):
    """Block 0 stored; block 1 direct and stored; block 2 direct, compressed after its 16-bit
    length; then plain blocks, the first of them right after the direct one."""
    tab, body, pos = b'', b'', data_at
    for i in range(0, len(data), BLK):
        b, k = data[i:i + BLK], i // BLK
        if k == 0:
            body += b
            pos += len(b)
            tab += struct.pack('<I', pos | UNC)
        elif k in (1, 2):
            pad = -pos % 4
            body += b'\0' * pad
            pos += pad
            start = pos
            if k == 1:
                body += b
                pos += len(b)
                tab += struct.pack('<I', (start >> 2) | DIRECT | UNC)
            else:
                c = zlib.compress(b, 9)
                body += struct.pack('<H', len(c)) + c
                pos += 2 + len(c)
                tab += struct.pack('<I', (start >> 2) | DIRECT)
        else:
            c = zlib.compress(b, 9)
            body += c
            pos += len(c)
            tab += struct.pack('<I', pos)
    return tab, body

def seven_lzma(data, data_at):
    """7-Zip's variant: per block, LZMA's properties, the block's size, then raw LZMA."""
    tab, body, end = b'', b'', data_at
    for i in range(0, len(data), BLK):
        b = data[i:i + BLK]
        alone = lzma.compress(b, format=lzma.FORMAT_ALONE)
        rec = alone[:5] + struct.pack('<I', len(b)) + alone[13:]
        body += rec
        end += len(rec)
        tab += struct.pack('<I', end)
    return tab, body

text = b''.join(b'cramfs line %d\n' % i for i in range(3000))
crafted = [('mixed.txt', text), ('small.txt', b'small\n')]
open(os.path.join(out, 'ext-ptrs.img'), 'wb').write(image(crafted, 1 | 2 | 0x800, ext_mixed))
open(os.path.join(out, 'sevenzip-lzma.img'), 'wb').write(image(crafted, 1 | 2 | 2 << 14, seven_lzma))
crafted_tree = [{'path': n, 'kind': 'file', 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest()}
                for n, d in crafted]

json.dump({'tree': tree, 'crafted': crafted_tree},
          open('/work/records.json', 'w', encoding='utf-8'), ensure_ascii=False)
for f in sorted(os.listdir(out)):
    size = os.path.getsize(os.path.join(out, f))
    assert size < 100_000, (f, size)
PY
    cp /work/records.json "$out/records.json"
    chown -R "${HOST_IDS:-0:0}" "$out" || true
    exit 0
fi

# ---------------------------------------------------------------------------------------------
# On the host.
here="$(cd "$(dirname "$0")" && pwd)"
command -v docker >/dev/null
# Docker Desktop on Windows takes `C:/…` from Git Bash; WSL's paths go as they are.
host() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
docker image inspect beezip-fixtures-7z >/dev/null 2>&1 ||
    docker build -q -t beezip-fixtures-7z - < "$here/make-7z.Dockerfile" >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm -e HOST_IDS="$(id -u):$(id -g)" \
    -v "$(host "$here"):/fixtures" beezip-fixtures-7z bash /fixtures/make-cramfs.sh --inside

# le.img and be.img against what 7-Zip extracts from them.
sz="${SEVENZIP:-$(command -v 7z || command -v 7zz || echo '/c/Program Files/7-Zip/7z.exe')}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
out="$here/thirdparty/cramfs"
for n in le be; do
    # Links 7-Zip calls dangerous make it exit 2; the files are still written.
    "$sz" x -y -bso0 -bsp0 -bse0 -o"$(host "$tmp/$n")" "$(host "$out/$n.img")" || true
done
python -I - "$(host "$here")" "$(host "$tmp")" "$("$sz" i | grep -m1 -o '7-Zip[^:]*[0-9][0-9]*\.[0-9]*')" <<'PY'
import hashlib, json, os, sys
here, tmp, seven = sys.argv[1:4]
out = os.path.join(here, 'thirdparty', 'cramfs')
rec = json.load(open(os.path.join(out, 'records.json'), encoding='utf-8'))
os.remove(os.path.join(out, 'records.json'))
tree, crafted = rec['tree'], rec['crafted']

# 7-Zip for Windows writes a CramFS name's bytes in the OEM code page (437 here). The 248-byte
# name is past Windows' 260-character paths.
def seven_name(n, p):
    if os.name != 'nt':
        return os.path.join(tmp, n, p)
    full = os.path.abspath(os.path.join(tmp, n, p.encode('utf-8').decode('cp437')))
    return '\\\\?\\' + full.replace('/', '\\')

for n in ('le', 'be'):
    for e in tree:
        if e['kind'] != 'file':
            continue
        p = seven_name(n, e['path'])
        got = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        assert got == e['sha256'], (n, e['path'])

producer = 'mkfs.cramfs 2.39.3 (util-linux, Ubuntu 24.04 in Docker)'
NOTE = ("BeeZip's own reader (docs/M10.md). The entries are the tree the image was made from "
        '(make-cramfs.sh); ')
counts = lambda es: {
    'hardlinks': 0,
    'symlinks': sum(e['kind'] == 'symlink' for e in es),
    'others': sum(e['kind'] == 'other' for e in es),
}
images = [
    ('le.img', 'mkfs.cramfs -n BeeZipCramfs -e 7 tree le.img',
     "7-Zip extracts the same files (checked by make-cramfs.sh)."),
    ('be.img', 'mkfs.cramfs -N big tree be.img',
     "a big-endian machine's; 7-Zip extracts the same files (checked by make-cramfs.sh)."),
    ('holes.img', 'mkfs.cramfs -z tree holes.img',
     'all-zero blocks are holes, which 7-Zip 26.00 fails as "Data Error".'),
    ('pad.img', 'mkfs.cramfs -p tree pad.img',
     "after a 512-byte boot block, where 7-Zip 26.00 doesn't look for the superblock."),
    ('b16k.img', 'mkfs.cramfs -b 16384 tree b16k.img',
     '16 KiB blocks, which 7-Zip 26.00 reads as 4 KiB ones ("Unsupported Method" on every '
     'file of more than one).'),
]
records = []
for f, command, note in images:
    records.append(dict({
        'file': 'cramfs/' + f, 'producer': producer, 'command': command, 'chain': 'cramfs',
        'native': True, 'levels': ['cramfs'], 'password': None, 'utc_mtimes': False,
    }, **counts(tree), note=NOTE + note, entries=tree))
records.append(dict({
    'file': 'cramfs/ext-ptrs.img', 'producer': 'make-cramfs.sh (Python, after Linux 4.15)',
    'command': 'crafted: mixed.txt as a stored block, a direct stored one, a direct compressed '
               'one, then plain ones',
    'chain': 'cramfs', 'native': True, 'levels': ['cramfs'], 'password': None,
    'utc_mtimes': False,
}, **counts(crafted), note=NOTE + "Linux 4.15's extended block pointers, which no tool on Linux "
   'writes and 7-Zip 26.00 reads as a block size.', entries=crafted))

manifest_path = os.path.join(here, 'manifest.json')
manifest = json.load(open(manifest_path, encoding='utf-8'))
old = manifest['fixtures']
mine = lambda r: r['file'].startswith('cramfs/')
at = next((i for i, r in enumerate(old) if mine(r)), len(old))
manifest['fixtures'] = old[:at] + records + [r for r in old[at:] if not mine(r)]
with open(manifest_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest, indent=2, ensure_ascii=False))

readme = '''# CramFS fixtures

Made by `tests/fixtures/make-cramfs.sh` (docs/M10.md §8) from one seeded tree with every kind of
node: files of 0 to 64 KiB, runs of zeros, non-ASCII and 248-byte names, 20 nested folders, an
empty folder, five links, a character and a block device, a FIFO and a socket. Their records in
`manifest.json` list that tree; BeeZip reads every image itself.

| File | Made by | What it is |
|---|---|---|
| `le.img` | mkfs.cramfs 2.39.3 `-n BeeZipCramfs -e 7` | little-endian, 4 KiB blocks |
| `be.img` | mkfs.cramfs `-N big` | big-endian |
| `holes.img` | mkfs.cramfs `-z` | all-zero blocks as holes (7-Zip 26.00: "Data Error") |
| `pad.img` | mkfs.cramfs `-p` | after a 512-byte boot block (7-Zip can't open it) |
| `b16k.img` | mkfs.cramfs `-b 16384` | 16 KiB blocks (7-Zip: "Unsupported Method") |
| `ext-ptrs.img` | make-cramfs.sh | Linux 4.15's extended block pointers: stored, direct stored, direct compressed and plain blocks |
| `sevenzip-lzma.img` | make-cramfs.sh | 7-Zip's own LZMA variant, which BeeZip hands to 7-Zip; no record |

%s extracts the same files from `le.img` and `be.img` (checked by the script).
''' % seven
open(os.path.join(out, 'README.md'), 'w', encoding='utf-8', newline='\n').write(readme)
print(len(records), 'records;', len(tree), 'entries in the tree')
PY
ls -l "$out"
