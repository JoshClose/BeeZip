#!/bin/bash
# Makes tests/fixtures/thirdparty/wim/ and the WIM images of tests/fixtures/malicious/ for
# BeeZip's own WIM reader (docs/M8.md §5, §9). Run it from the repository, with Docker running,
# in WSL or Git Bash:
#
#   bash tests/fixtures/make-wim.sh
#
# The images are made in make-7z.sh's container (make-7z.Dockerfile, beezip-fixtures-7z), which
# runs this script again with --inside. Tools: wimlib-imagex 1.14.4, libfaketime 0.9.10 and
# python3 3.12. Deterministic where wimlib allows: it runs under a frozen libfaketime clock,
# single-threaded; the data comes from seeded Random()s; each image's GUID, which wimlib draws at
# random, is fixed afterwards (a split set's parts share theirs), as make-7z.sh does. The times
# wimlib takes from a tree's files on Linux besides their modified time (creation, access) come
# from a clock libfaketime doesn't reach, so those images' bytes differ by a few from run to run;
# never their files, which is what expected.json records. ntfs.wim's come from the volume.
#
# thirdparty/wim/, each under 100 KB, from the tree below (`tree`), its `sub` folder, a smaller
# tree without the large files (`small`), an empty folder, and thirdparty/ntfs/rich.img:
#   xpress.wim            XPRESS in 32 KiB chunks
#   lzx-64k.wim           LZX in 64 KiB chunks
#   lzms.wim              LZMS, not solid (read on Windows only)
#   solid-lzms.esd        solid LZMS, as Windows' ESDs are (Windows only)
#   solid-lzx.wim         solid LZX
#   solid-xpress.wim      solid XPRESS
#   multi-solid.wim       two images, the tree and `extra`, each appended as a solid resource of
#                         its own: LZX, then XPRESS (their data laid end to end in table order;
#                         extra/readme.txt is the tree's readme.txt, in the first)
#                         These three are Windows only too: with --solid and no --compress,
#                         wimlib compresses the images' metadata with LZMS.
#   multi-solid.esd       the same in LZMS (Windows only)
#   multi.wim             three images, LZX: the tree, its sub folder, an empty folder
#   empty-image.wim       one image of an empty folder
#   no-images.wim         small, its only image deleted
#   check.wim             small, XPRESS, with an integrity table (--check)
#   none.wim              small, stored
#   split.swm, split2.swm the tree in LZX, split in two parts
#   chunk-256m.esd        solid LZMS in chunks of 256 MiB, of a tree whose 65 MiB of zeros fill
#                         one chunk past the 64 MiB BeeZip read before M11 (docs/M11.md §6.1)
#   xpress2-flag.wim      xpress.wim with the header's later XPRESS flag (0x200000), crafted
#   clookup.wim           xpress.wim with its lookup table flagged compressed (one chunk, stored)
#   spanned.wim           xpress.wim with every data resource flagged spanned, which wimlib and
#                         7-Zip ignore
#   ntfs.wim              rich.img captured by wimlib's NTFS capture (libntfs-3g), LZX: streams,
#                         hard links, symlinks, a junction, a WSL symlink, a WIMBoot (WOF) file,
#                         EFS flags, Interix files; without compressed/random.bin,
#                         compressed/mixed.bin and sparse.bin, whose random bytes don't compress
#   expected.json         what each image holds, from the trees themselves (not from any reader):
#                         every file's size and SHA-256, link targets as created, hard link
#                         groups, folders, times
#
# The tree: the names make-7z.sh's has (Unicode, spaces, a hard link pair), a second hard link
# pair, a file with its time to 100 ns, text of several chunks, x86 code (LZX's E8 translation),
# zeros, random bytes (chunks stored as they are), two files with the same data that aren't
# links, symlinks relative, absolute into the tree (which wimlib's --rpfix fixes), absolute out
# of it, relative out of it and dangling, and a path 20 folders deep.
#
# malicious/, each refused cleanly or read within limits (crates/beezip-core/tests/malicious/
# wim.rs); edits of images made here:
#   wim-folder-loop.wim     none.wim's sub/nested lists the root's folder list as its own (its
#                           metadata's SHA-1 redone)
#   wim-solid-1tb.esd       solid-xpress.wim's solid resource claims 1 TB of data
#   wim-chunk-back.wim      xpress.wim's text.txt: its chunk table goes back
#   wim-chunk-1g.esd        solid-xpress.wim's solid resource in chunks of 1 GiB, claiming 2 GiB
# and three inputs the M8 spike's fuzzer found (target/m8-spikes/wim/repro/), copied as they
# are, not made here: wim-spike-panic.wim (a stored solid chunk shorter than it says, which
# panicked the prototype), wim-spike-hang.wim (each blob decoding its 64 MiB chunk again) and
# wim-spike-slow.wim (slow on a loaded machine).
set -euo pipefail

faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
    NO_FAKE_STAT=1)

# ---------------------------------------------------------------------------------------------
# In the container (root).
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    out=/fixtures/thirdparty/wim
    mal=/fixtures/malicious
    W=/work
    rm -rf "$out" "$W"
    mkdir -p "$out" "$W"

    python3 -I - "$W" <<'PY'
import os, random, sys
W = sys.argv[1]
rnd = random.Random(1234)
E = 1767225600  # 2026-01-01T00:00:00Z

def tree(T, big):
    os.makedirs(f'{T}/sub/nested')
    os.makedirs(f'{T}/Ünïcödé dir')
    open(f'{T}/readme.txt', 'wb').write(b'hello, beezip!\n')
    os.link(f'{T}/readme.txt', f'{T}/hard-readme.txt')
    open(f'{T}/empty.txt', 'wb').close()
    open(f'{T}/bee-🐝.txt', 'wb').write(b'buzz!\n')
    open(f'{T}/café-ñandú.txt', 'wb').write(b'accents\n')
    open(f'{T}/名前.txt', 'wb').write(b'jp!\n')
    open(f'{T}/Ünïcödé dir/日本語.txt', 'wb').write(b'nihongo text :)\n\n')
    open(f'{T}/with space.txt', 'wb').write(b'spaces!\n')
    open(f'{T}/sub/nested/deep.txt', 'wb').write(b'deep\n')
    os.link(f'{T}/sub/nested/deep.txt', f'{T}/sub/deep-link.txt')
    open(f'{T}/mtime.txt', 'wb').write(b'a fine time\n')
    dup = b''.join(b'duplicate line %d\n' % i for i in range(150))
    open(f'{T}/dup-a.txt', 'wb').write(dup)
    open(f'{T}/sub/dup-b.txt', 'wb').write(dup)
    if big:
        text = b''.join(b'line %06d: the quick brown fox jumps over the lazy dog %d\n'
                        % (i, i * i % 977) for i in range(2600))
        open(f'{T}/text.txt', 'wb').write(text)
        code = bytearray()
        for i in range(3000):
            code += b'\x55\x48\x89\xe5\xe8' + (i * 37 % 65536).to_bytes(4, 'little') + b'\x5d\xc3\x90'
        open(f'{T}/code.bin', 'wb').write(code)
        open(f'{T}/zeros.bin', 'wb').write(bytes(70000))
        open(f'{T}/random.bin', 'wb').write(rnd.randbytes(4096))
        os.symlink('readme.txt', f'{T}/link-to-readme')
        os.symlink('nested', f'{T}/sub/link-to-nested')
        os.symlink(f'{T}/sub/nested/deep.txt', f'{T}/abs-link-inside')
        os.symlink('/etc/hostname', f'{T}/abs-link-outside')
        os.symlink('../../outside.txt', f'{T}/sub/rel-link-outside')
        os.symlink('missing-target', f'{T}/dangling')
        d = f'{T}/deep'
        for i in range(20):
            d = f'{d}/d{i:02d}'
        os.makedirs(d)
        open(f'{d}/' + 'n' * 200 + '.txt', 'wb').write(b'deep down\n')
    for dirpath, dirs, files in os.walk(T, topdown=False):
        for n in files + dirs:
            os.utime(os.path.join(dirpath, n), (E, E), follow_symlinks=False)
    os.utime(T, (E, E))
    t = 1715000000123456789
    os.utime(f'{T}/mtime.txt', ns=(t, t))

tree(f'{W}/tree', True)
tree(f'{W}/small', False)
os.makedirs(f'{W}/empty')
# Data the tree doesn't have, so that appending it makes a second solid resource.
os.makedirs(f'{W}/extra')
open(f'{W}/extra/readme.txt', 'wb').write(b'hello, beezip!\n')
open(f'{W}/extra/more.txt', 'wb').write(
    b''.join(b'more text, line %05d, of the second image\n' % i for i in range(700)))
open(f'{W}/extra/noise.bin', 'wb').write(rnd.randbytes(1500))
for n in os.listdir(f'{W}/extra'):
    os.utime(f'{W}/extra/{n}', (E, E))
os.utime(f'{W}/empty', (E, E))
# More than 64 MiB that compresses to nothing, for chunks past the size BeeZip once capped.
os.makedirs(f'{W}/big')
with open(f'{W}/big/zeros-65m.bin', 'wb') as f:
    f.truncate(65 * 1024 * 1024 + 1)
open(f'{W}/big/readme.txt', 'wb').write(b'hello, beezip!\n')
for n in os.listdir(f'{W}/big'):
    os.utime(f'{W}/big/{n}', (E, E))
os.utime(f'{W}/big', (E, E))
PY

    cd "$W"
    cap() { "${faked[@]}" wimcapture "$@" --threads=1 >/dev/null; }
    app() { "${faked[@]}" wimappend "$@" --threads=1 >/dev/null; }
    cap tree "$out/xpress.wim" Tree --compress=XPRESS
    cap tree "$out/lzx-64k.wim" Tree --compress=LZX --chunk-size=65536
    cap tree "$out/lzms.wim" Tree --compress=LZMS
    cap tree "$out/solid-lzms.esd" Tree --solid
    cap tree "$out/solid-lzx.wim" Tree --solid --solid-compress=LZX
    cap tree "$out/solid-xpress.wim" Tree --solid --solid-compress=XPRESS
    cap tree "$out/multi-solid.wim" Tree --solid --solid-compress=LZX
    app extra "$out/multi-solid.wim" Extra --solid --solid-compress=XPRESS
    cap tree "$out/multi-solid.esd" Tree --solid
    app extra "$out/multi-solid.esd" Extra --solid
    cap tree "$out/multi.wim" Tree --compress=LZX
    app tree/sub "$out/multi.wim" Sub
    app empty "$out/multi.wim" Empty
    cap empty "$out/empty-image.wim" Empty --compress=LZX
    cap small "$out/no-images.wim" Small --compress=none
    "${faked[@]}" wimdelete "$out/no-images.wim" 1 >/dev/null
    cap small "$out/check.wim" Small --compress=XPRESS --check
    cap small "$out/none.wim" Small --compress=none
    cap tree "$W/split-whole.wim" Tree --compress=LZX
    # Two parts: each at most about 60 % of the whole.
    size=$(stat -c %s "$W/split-whole.wim")
    part=$(python3 -I -c "print(f'{$size * 0.6 / 1048576:.4f}')")
    "${faked[@]}" wimsplit "$W/split-whole.wim" "$out/split.swm" "$part" >/dev/null
    test -f "$out/split2.swm" && ! test -f "$out/split3.swm"
    printf '[ExclusionList]\n/compressed/random.bin\n/compressed/mixed.bin\n/sparse.bin\n' \
        > "$W/ntfs.cfg"
    cp /fixtures/thirdparty/ntfs/rich.img "$W/rich.img"
    cap "$W/rich.img" "$out/ntfs.wim" Rich --compress=LZX --config="$W/ntfs.cfg"
    cap big "$out/chunk-256m.esd" Big --solid --solid-chunk-size=268435456

    # The GUIDs, fixed; the expected contents, from the trees; the damaged images.
    python3 -I - "$out" "$mal" "$W" <<'PY'
import hashlib, json, os, struct, sys, uuid
out, mal, W = sys.argv[1:]

def set_guid(path, n):
    with open(path, 'r+b') as f:
        f.seek(24)
        f.write(uuid.UUID(f'6d7a6970-6265-457a-8970-{n:012x}').bytes_le)

# M11's images get GUIDs of their own, so the others' stay as they were.
M11 = ['chunk-256m.esd']
names = sorted(f for f in os.listdir(out) if f.endswith(('.wim', '.esd', '.swm')) and f not in M11)
for i, f in enumerate(names):
    set_guid(os.path.join(out, f), 0x500 + (0 if f.startswith('split') else i + 1))
for i, f in enumerate(M11):
    set_guid(os.path.join(out, f), 0x5F0 + i)

def listing(root):
    """What the folder at `root` holds: every entry under it, as BeeZip should list it."""
    rows = []
    inodes = {}
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for n in sorted(dirs) + sorted(files):
            p = os.path.join(d, n)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            st = os.lstat(p)
            row = {'path': rel, 'mtime_ns': st.st_mtime_ns}
            if os.path.islink(p):
                row.update(kind='symlink', target=os.readlink(p))
            elif os.path.isdir(p):
                row.update(kind='folder')
            else:
                data = open(p, 'rb').read()
                row.update(kind='file', size=len(data), sha256=hashlib.sha256(data).hexdigest())
                if st.st_nlink > 1:
                    row['link_group'] = inodes.setdefault(st.st_ino, len(inodes) + 1)
            rows.append(row)
    return rows

roots = {'tree': 'tree', 'sub': 'tree/sub', 'small': 'small', 'empty': 'empty',
         'extra': 'extra', 'big': 'big'}
trees = {name: listing(os.path.join(W, path)) for name, path in roots.items()}
fixtures = [
    {'file': 'xpress.wim', 'images': ['tree'], 'method': 'XPRESS'},
    {'file': 'lzx-64k.wim', 'images': ['tree'], 'method': 'LZX'},
    {'file': 'lzms.wim', 'images': ['tree'], 'method': 'LZMS', 'lzms': True},
    {'file': 'solid-lzms.esd', 'images': ['tree'], 'method': 'LZMS', 'lzms': True, 'solid': 1},
    {'file': 'solid-lzx.wim', 'images': ['tree'], 'method': 'LZX', 'lzms': True, 'solid': 1},
    {'file': 'solid-xpress.wim', 'images': ['tree'], 'method': 'XPRESS', 'lzms': True,
     'solid': 1},
    {'file': 'multi-solid.wim', 'images': ['tree', 'extra'], 'method': 'LZX', 'lzms': True,
     'solid': 2},
    {'file': 'multi-solid.esd', 'images': ['tree', 'extra'], 'method': 'LZMS', 'lzms': True,
     'solid': 2},
    {'file': 'multi.wim', 'images': ['tree', 'sub', 'empty'], 'method': 'LZX'},
    {'file': 'empty-image.wim', 'images': ['empty'], 'method': 'LZX'},
    {'file': 'no-images.wim', 'images': [], 'method': 'Store'},
    {'file': 'check.wim', 'images': ['small'], 'method': 'XPRESS', 'integrity': True},
    {'file': 'none.wim', 'images': ['small'], 'method': 'Store'},
    {'file': 'split.swm', 'images': ['tree'], 'method': 'LZX', 'parts': 2},
    {'file': 'split2.swm', 'images': ['tree'], 'method': 'LZX', 'parts': 2},
    {'file': 'chunk-256m.esd', 'images': ['big'], 'method': 'LZMS', 'lzms': True, 'solid': 1},
    {'file': 'xpress2-flag.wim', 'images': ['tree'], 'method': 'XPRESS'},
    {'file': 'clookup.wim', 'images': ['tree'], 'method': 'XPRESS'},
    {'file': 'spanned.wim', 'images': ['tree'], 'method': 'XPRESS'},
]
manifest = {
    'note': 'Made by tests/fixtures/make-wim.sh. `trees` is what each source folder holds, read '
            'from the folder itself: paths from its root, links as created (absolute ones point '
            'into /work/tree when inside it), hard link groups numbered per tree, times in ns.',
    'roots': {name: f'{W}/{path}' for name, path in roots.items()},
    'trees': trees,
    'fixtures': fixtures,
}
with open(os.path.join(out, 'expected.json'), 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest, indent=1, ensure_ascii=False))

# ---- Damaged images.
def u16(b, at): return struct.unpack_from('<H', b, at)[0]
def u32(b, at): return struct.unpack_from('<I', b, at)[0]
def u64(b, at): return struct.unpack_from('<Q', b, at)[0]
def res(b, at):
    sf = u64(b, at)
    return sf & ((1 << 56) - 1), sf >> 56, u64(b, at + 8), u64(b, at + 16)

def lookup(b):
    size, flags, off, orig = res(b, 48)
    return [(off + i, *res(b, off + i), b[off + i + 30:off + i + 50]) for i in range(0, size, 50)]

# ---- Variants 7-Zip reads and no writer is known for (docs/M11.md §6.1), from xpress.wim.
x = open(os.path.join(out, 'xpress.wim'), 'rb').read()
# The header's later XPRESS flag, 0x200000, in place of 0x20000.
b = bytearray(x)
struct.pack_into('<I', b, 16, (u32(b, 16) & ~0x20000) | 0x200000)
open(os.path.join(out, 'xpress2-flag.wim'), 'wb').write(b)
# The lookup table flagged compressed: one chunk, as long as its data, so stored.
b = bytearray(x)
b[55] |= 0x4
open(os.path.join(out, 'clookup.wim'), 'wb').write(b)
# Every data resource flagged spanned.
b = bytearray(x)
for e in lookup(b):
    if not e[2] & 2:
        b[e[0] + 7] |= 0x8
open(os.path.join(out, 'spanned.wim'), 'wb').write(b)

# A folder list met twice: sub/nested's list is the root's.
b = bytearray(open(os.path.join(out, 'none.wim'), 'rb').read())
meta = next(e for e in lookup(b) if e[2] & 2)
at_entry, msize, _, moff, _, _ = meta
m = b[moff:moff + msize]
def dentries(m, at):
    while True:
        ln = u64(m, at)
        if ln == 0:
            return
        nlen = u16(m, at + 100)
        name = m[at + 102:at + 102 + nlen].decode('utf-16-le')
        yield at, name
        nxt = (at + ln + 7) & ~7
        for _ in range(u16(m, at + 96)):
            nxt = (nxt + u64(m, nxt) + 7) & ~7
        at = nxt
root = (u32(m, 0) + 7) & ~7
root_list = u64(m, root + 16)
sub = next(a for a, n in dentries(m, root_list) if n == 'sub')
nested = next(a for a, n in dentries(m, u64(m, sub + 16)) if n == 'nested')
struct.pack_into('<Q', m, nested + 16, root_list)
b[moff:moff + msize] = m
b[at_entry + 30:at_entry + 50] = hashlib.sha1(m).digest()
open(os.path.join(mal, 'wim-folder-loop.wim'), 'wb').write(b)

# A solid resource that claims 1 TB.
b = bytearray(open(os.path.join(out, 'solid-xpress.wim'), 'rb').read())
solid = next(e for e in lookup(b) if e[2] & 0x10 and e[4] == 1 << 32)
struct.pack_into('<Q', b, solid[3], 1 << 40)
open(os.path.join(mal, 'wim-solid-1tb.esd'), 'wb').write(b)

# A chunk table that goes back: text.txt's, whose data is several chunks.
b = bytearray(open(os.path.join(out, 'xpress.wim'), 'rb').read())
text = open(os.path.join(W, 'tree/text.txt'), 'rb').read()
want = hashlib.sha1(text).digest()
e = next(e for e in lookup(b) if bytes(e[5]) == want)
_, size, flags, off, orig, _ = e
assert flags & 4 and orig > 3 * 32768, (flags, orig)
struct.pack_into('<I', b, off + 4, u32(b, off) - 1)
open(os.path.join(mal, 'wim-chunk-back.wim'), 'wb').write(b)

# A solid resource in chunks of 1 GiB, claiming 2 GiB: each chunk takes 1 GiB of
# `decoder_memory` to decode.
b = bytearray(open(os.path.join(out, 'solid-xpress.wim'), 'rb').read())
solid = next(e for e in lookup(b) if e[2] & 0x10 and e[4] == 1 << 32)
struct.pack_into('<QI', b, solid[3], 2 << 30, 1 << 30)
open(os.path.join(mal, 'wim-chunk-1g.esd'), 'wb').write(b)
for f in names + M11:
    assert os.path.getsize(os.path.join(out, f)) < 100_000, f
PY
    chown -R "${HOST_IDS:-0:0}" "$out" "$mal"/wim-folder-loop.wim "$mal"/wim-solid-1tb.esd \
        "$mal"/wim-chunk-back.wim "$mal"/wim-chunk-1g.esd || true
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
    -v "$(host "$here"):/fixtures" beezip-fixtures-7z bash /fixtures/make-wim.sh --inside
