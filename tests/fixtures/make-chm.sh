#!/bin/bash
# Makes tests/fixtures/thirdparty/chm/ for BeeZip's own CHM reader (docs/M9.md §8). Run it from
# the repository, with Docker running and 7-Zip installed, in WSL or Git Bash:
#
#   bash tests/fixtures/make-chm.sh
#
# The help files are made in make-7z.sh's container (make-7z.Dockerfile, beezip-fixtures-7z),
# which runs this script again with --inside. Tools: chmcmd 3.2.2 (Free Pascal), Halibut 1.3,
# libfaketime 0.9.10 and python3 3.12. The data comes from seeded Random()s, and the times the
# compilers write (the ITSF header's, #SYSTEM's code 10) are zeroed afterwards, as make-7z.sh
# does for its chmcmd.chm.
#
# thirdparty/chm/, each under 100 KB:
#   chmcmd-chunks.chm   240 small pages under long names, a few of them Unicode: a directory of
#                       several listing chunks and an index, whose header names chunk 1 as the
#                       first listing chunk though chunk 0 is one (docs/UPSTREAM.md)
#   chmcmd-big.chm      about 290 KB of text over 36 pages, 12 KB of random bytes and 100 KB of
#                       zeros: several reset intervals, and a last frame whose LZX runs past
#                       section 1's stated end
#   halibut.chm         a Halibut document of four chapters: Halibut's own LZX encoder
#   lzxc-v3.chm, reset-v3.chm, transform-guid.chm, section-renamed.chm
#                       chmcmd-chunks.chm with its LZX control data, then its reset table, as
#                       version 3, its Transform/List naming another GUID, and its compressed
#                       section named MSCompressee: crafted, since no compiler is known to write
#                       them, and read as 7-Zip reads them (docs/M11.md §6.1)
#   expected.json       every file 7-Zip extracts from each (path, size, SHA-256): the oracle
#                       BeeZip's reader is checked against (crates/beezip-core/tests/chm.rs). The
#                       chmcmd trees' own files are checked against it first, here.
set -euo pipefail

faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
    NO_FAKE_STAT=1)

# ---------------------------------------------------------------------------------------------
# In the container (root).
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    out=/fixtures/thirdparty/chm
    W=/work
    rm -rf "$out" "$W"
    mkdir -p "$out" "$W"

    python3 -I - "$W" <<'PY'
import hashlib, json, os, random, sys
W = sys.argv[1]
rnd = random.Random(2026)
WORDS = ('bee hive comb honey wax cell queen drone worker nectar pollen flower meadow summer '
         'archive folder file frame window reset section header chunk index table help topic '
         'café ñandú über naïve smörgåsbord').split()

def text(n):
    out, line = [], []
    while sum(map(len, out)) < n:
        line.append(rnd.choice(WORDS))
        if len(line) > 12:
            out.append(' '.join(line) + '.\n')
            line = []
    return ''.join(out)

def page(title, body):
    return ('<html><head><meta charset="utf-8"><title>%s</title></head><body><h1>%s</h1>'
            '<p>%s</p></body></html>\n' % (title, title, body)).encode('utf-8')

trees = {}
def write(tree, rel, data):
    p = os.path.join(W, tree, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'wb').write(data)
    trees.setdefault(tree, {})[rel] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

# Many entries: several listing chunks.
files = ['index.htm']
write('chunks', 'index.htm', page('Chunks', 'Many small pages.'))
for i in range(240):
    name = 'topics/section-%02d/a-topic-with-a-rather-long-name-%03d.htm' % (i // 20, i)
    files.append(name)
    write('chunks', name, page('Topic %d' % i, text(60)))
for name in ('topics/café-ñandú.htm', 'topics/名前.htm', 'topics/with space.htm'):
    files.append(name)
    write('chunks', name, page(name, text(40)))
files.append('images/noise.bin')
write('chunks', 'images/noise.bin', rnd.randbytes(3000))
open(os.path.join(W, 'chunks.files'), 'w').write('\n'.join(files) + '\n')

# Much content: several reset intervals.
files = ['index.htm']
write('big', 'index.htm', page('Big', 'Several reset intervals.'))
for i in range(36):
    name = 'pages/page-%02d.htm' % i
    files.append(name)
    write('big', name, page('Page %d' % i, text(8000)))
files += ['data/noise.bin', 'data/zeros.bin']
write('big', 'data/noise.bin', rnd.randbytes(12_000))
write('big', 'data/zeros.bin', bytes(100_000))
open(os.path.join(W, 'big.files'), 'w').write('\n'.join(files) + '\n')

# Halibut's document: four chapters of paragraphs.
doc = ['\\cfg{input-charset}{UTF-8}', '', '\\title BeeZip test help', '']
for c in range(4):
    doc += ['\\C{chapter%d} Chapter %d' % (c, c), '']
    for p in range(30):
        doc += [text(600).replace('\n', ' '), '']
    doc += ['\\H{chapter%d-more} More of chapter %d' % (c, c), '', text(900).replace('\n', ' '), '']
open(os.path.join(W, 'halibut.but'), 'w', encoding='utf-8').write('\n'.join(doc) + '\n')

json.dump(trees, open('/fixtures/thirdparty/chm/trees.json', 'w'), indent=1, ensure_ascii=False)
PY

    for t in chunks big; do
        printf '[OPTIONS]\nCompiled file=%s.chm\nDefault topic=index.htm\nTitle=BeeZip %s fixture\n\n[FILES]\n' \
            "$t" "$t" > "$W/$t/$t.hhp"
        cat "$W/$t.files" >> "$W/$t/$t.hhp"
        (cd "$W/$t" && "${faked[@]}" chmcmd "$t.hhp" >/dev/null)
        cp "$W/$t/$t.chm" "$out/chmcmd-$t.chm"
    done
    (cd "$W" && "${faked[@]}" halibut --chm=halibut.chm halibut.but)
    cp "$W/halibut.chm" "$out/halibut.chm"

    # The times: the ITSF header's, and #SYSTEM's code 10 (it's in section 0, stored).
    python3 -I - "$out" <<'PY'
import os, struct, sys
out = sys.argv[1]

def encint(d, p):
    v = 0
    while True:
        c = d[p]; p += 1; v = (v << 7) | (c & 0x7f)
        if c & 0x80 == 0:
            return v, p

def entries(d):
    do, dl = struct.unpack_from('<QQ', d, 0x48)
    co = struct.unpack_from('<Q', d, 0x58)[0]
    hl, cs = struct.unpack_from('<I', d, do + 8)[0], struct.unpack_from('<I', d, do + 0x10)[0]
    n = struct.unpack_from('<I', d, do + 0x2c)[0]
    for i in range(n):
        c = d[do + hl + i * cs: do + hl + (i + 1) * cs]
        if c[:4] != b'PMGL':
            continue
        end, p = cs - struct.unpack_from('<I', c, 4)[0], 0x14
        while p < end:
            k, p = encint(c, p); name = bytes(c[p:p + k]); p += k
            s, p = encint(c, p); o, p = encint(c, p); ln, p = encint(c, p)
            yield name, s, co + o, ln

for f in sorted(os.listdir(out)):
    if not f.endswith('.chm'):
        continue
    path = os.path.join(out, f)
    d = bytearray(open(path, 'rb').read())
    d[16:20] = bytes(4)
    for name, s, at, ln in entries(d):
        if name == b'/#SYSTEM' and s == 0:
            p = at + 4
            while p + 4 <= at + ln:
                code, n = struct.unpack_from('<HH', d, p)
                if code == 10:
                    d[p + 4:p + 4 + n] = bytes(n)
                p += 4 + n
    open(path, 'wb').write(d)
    assert len(d) < 100_000, (f, len(d))

# Variants 7-Zip reads and no compiler is known to write (docs/M11.md §6.1).
base = open(os.path.join(out, 'chmcmd-chunks.chm'), 'rb').read()
where = {name: (at, ln) for name, s, at, ln in entries(base) if s == 0}
CD = b'::DataSpace/Storage/MSCompressed/ControlData'
RT = (b'::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}'
      b'/InstanceData/ResetTable')
TL = b'::DataSpace/Storage/MSCompressed/Transform/List'

def variant(name, edit):
    d = bytearray(base)
    edit(d)
    open(os.path.join(out, name), 'wb').write(d)

variant('lzxc-v3.chm', lambda d: struct.pack_into('<I', d, where[CD][0] + 8, 3))
variant('reset-v3.chm', lambda d: struct.pack_into('<I', d, where[RT][0], 3))

def other_transform(d):
    at, ln = where[TL]
    g = '7FC28940'.encode('utf-16-le')
    i = d.find(g, at, at + ln)
    assert i >= 0
    d[i:i + len(g)] = '7FC28941'.encode('utf-16-le')
variant('transform-guid.chm', other_transform)

def renamed(d):
    # Every MSCompressed, in the directory's names (UTF-8) and in the NameList (UTF-16): same
    # length, so the listing chunks keep their layout.
    for old, new in ((b'MSCompressed', b'MSCompressee'),
                     ('MSCompressed'.encode('utf-16-le'), 'MSCompressee'.encode('utf-16-le'))):
        i = d.find(old)
        while i >= 0:
            d[i:i + len(old)] = new
            i = d.find(old, i + 1)
variant('section-renamed.chm', renamed)
PY
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
    -v "$(host "$here"):/fixtures" beezip-fixtures-7z bash /fixtures/make-chm.sh --inside

# What 7-Zip extracts from each: expected.json.
sz="${SEVENZIP:-$(command -v 7z || command -v 7zz || echo '/c/Program Files/7-Zip/7z.exe')}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
out="$here/thirdparty/chm"
for f in "$out"/*.chm; do
    n="$(basename "$f" .chm)"
    "$sz" x -y -bso0 -bsp0 -o"$(host "$tmp/$n")" "$(host "$f")"
done
python -I - "$(host "$out")" "$(host "$tmp")" "$("$sz" i | grep -m1 -o '7-Zip[^:]*[0-9][0-9]*\.[0-9]*')" <<'PY'
import hashlib, json, os, sys
out, tmp, seven = sys.argv[1:4]
trees = json.load(open(os.path.join(out, 'trees.json'), encoding='utf-8'))
os.remove(os.path.join(out, 'trees.json'))
producers = {
    'chmcmd-chunks.chm': 'chmcmd 3.2.2 (Free Pascal, Ubuntu 24.04 in Docker)',
    'chmcmd-big.chm': 'chmcmd 3.2.2 (Free Pascal, Ubuntu 24.04 in Docker)',
    'halibut.chm': 'Halibut 1.3 (Ubuntu 24.04 in Docker)',
}
for v in ('lzxc-v3.chm', 'reset-v3.chm', 'transform-guid.chm', 'section-renamed.chm'):
    producers[v] = "make-chm.sh, crafted from chmcmd-chunks.chm"
fixtures = {}
for f in sorted(os.listdir(out)):
    if not f.endswith('.chm'):
        continue
    root = os.path.join(tmp, f[:-4])
    files = {}
    for dirpath, _, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            data = open(p, 'rb').read()
            files[rel] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    tree = 'chunks' if 'crafted' in producers[f] else {
        'chmcmd-chunks.chm': 'chunks', 'chmcmd-big.chm': 'big'}.get(f)
    for rel, want in trees.get(tree, {}).items():
        assert files.get(rel) == want, (f, rel, files.get(rel), want)
    fixtures[f] = {
        'producer': producers[f],
        'files': [dict(path=p, **files[p]) for p in sorted(files)],
    }
note = ('Every file %s extracts from each help file (`7z x`), with its size and SHA-256; the '
        "chmcmd fixtures' own pages were checked against the trees they were compiled from by "
        'make-chm.sh. BeeZip lists the same files, and its folders besides.' % seven)
json.dump({'note': note, 'fixtures': fixtures},
          open(os.path.join(out, 'expected.json'), 'w', encoding='utf-8', newline='\n'),
          indent=1, ensure_ascii=False)
print({f: len(v['files']) for f, v in fixtures.items()})
PY
ls -l "$out"
