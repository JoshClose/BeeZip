#!/bin/bash
# Makes tests/fixtures/thirdparty/nsis/ for BeeZip's own NSIS reader (docs/M10.md §8), then
# merges their records into manifest.json (this script owns nsis/). Run it from the repository,
# with Docker running and 7-Zip installed, in WSL or Git Bash:
#
#   bash tests/fixtures/make-nsis.sh
#
# The installers are made in make-7z.sh's container (make-7z.Dockerfile, beezip-fixtures-7z),
# which runs this script again with --inside. Tools: makensis 3.09 (Ubuntu 24.04's nsis, with
# its x86 and amd64 stubs and plugins), libfaketime 0.9.10 and python3 3.12. The data comes
# from a seeded Random(), the files' times are set, and makensis runs under a frozen clock, so a
# rerun writes the same bytes.
#
# thirdparty/nsis/, one script built seven ways, each under 150 KB:
#   u-zlib.exe         Unicode, zlib, not solid
#   u-bzip2-solid.exe  Unicode, NSIS's bzip2, solid
#   u-lzma-solid.exe   Unicode, LZMA, solid
#   a-bzip2.exe        ANSI, bzip2, not solid (a tree without names ANSI can't hold)
#   a-zlib-solid.exe   ANSI, zlib, solid
#   x64-lzma.exe       64-bit (Target amd64-unicode), LZMA, not solid
#   u-nocrc.exe        Unicode, LZMA, solid, CRCCheck off
# The script puts files under $INSTDIR, a subfolder, $INSTDIR\$0, $PLUGINSDIR, $SYSDIR,
# $APPDATA\BeeZip and $TEMP; renames one (/oname); stores one twice (shared data); writes an
# empty file (FileOpen and FileClose); calls a plugin (nsExec, which makensis adds); and writes
# its uninstaller.
#
# The records list what 7-Zip 26.00 extracts from each installer (`7z x`), checked first
# against the tree the script installs: the uninstaller and the plugin come from makensis.
set -euo pipefail

faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
    NO_FAKE_STAT=1)

# ---------------------------------------------------------------------------------------------
# In the container (root).
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    out=/fixtures/thirdparty/nsis
    rm -rf "$out" /work
    mkdir -p "$out" /work/tree /work/tree-ansi /work/extra
    cd /work

    python3 -I - <<'PY'
import json, os, random, shutil
r = random.Random(2026)
T, A, E = '/work/tree', '/work/tree-ansi', '/work/extra'
files = {
    'readme.txt': b'hello nsis\n',
    'empty.txt': b'',
    'random-20k.bin': r.randbytes(20_000),
    'text.txt': b''.join(b'line %d of a text file for nsis\n' % i for i in range(1500)),
    'café-ñandú.txt': 'latin\n'.encode(),
    '名前.txt': 'cjk\n'.encode(),
    'bee-\U0001F41D.txt': 'emoji\n'.encode(),
    'sub/inner/a.txt': b'a\n',
}
for p, d in files.items():
    for root in (T, A):
        if root == A and not all(ord(c) < 256 for c in p):
            continue
        full = os.path.join(root, p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, 'wb').write(d)
for n in ('sys.txt', 'app.txt', 'temp.txt', 'plugin-data.bin', 'splash.bmp'):
    open(os.path.join(E, n), 'wb').write(n.encode() * 20 + r.randbytes(100))
PY
    find /work/tree /work/tree-ansi /work/extra -type f -exec touch -d '2026-01-01 00:00:00' {} +
    touch -d '2024-05-06 07:08:08' /work/tree/readme.txt /work/tree-ansi/readme.txt

    mk() { # name, header lines, compressor, tree
        local name=$1 head=$2 comp=$3 tree=$4
        cat > "/work/$name.nsi" <<NSI
$head
SetCompressor $comp
Name "BeeZip $name"
OutFile "$out/$name.exe"
InstallDir "\$LOCALAPPDATA\\BeeZip $name"
RequestExecutionLevel user
Page directory
Page instfiles
Function .onInit
  InitPluginsDir
  File "/oname=\$PLUGINSDIR\\splash.bmp" "/work/extra/splash.bmp"
FunctionEnd
Section "Main"
  SetOutPath "\$INSTDIR"
  File /r "$tree/*.*"
  File "/oname=renamed.txt" "$tree/readme.txt"
  SetOutPath "\$INSTDIR\\again"
  File "$tree/readme.txt"
  SetOutPath "\$PLUGINSDIR"
  File "/work/extra/plugin-data.bin"
  SetOutPath "\$SYSDIR"
  File "/work/extra/sys.txt"
  SetOutPath "\$APPDATA\\BeeZip"
  File "/work/extra/app.txt"
  SetOutPath "\$TEMP"
  File "/work/extra/temp.txt"
  StrCpy \$0 "dynamic"
  SetOutPath "\$INSTDIR\\\$0"
  File "$tree/readme.txt"
  FileOpen \$1 "\$INSTDIR\\created-empty.txt" w
  FileClose \$1
  nsExec::Exec "cmd /c echo"
  WriteUninstaller "\$INSTDIR\\uninstall.exe"
SectionEnd
Section "un.Uninstall"
  Delete "\$INSTDIR\\uninstall.exe"
SectionEnd
NSI
        "${faked[@]}" makensis -V1 -INPUTCHARSET UTF8 "/work/$name.nsi" > "/work/$name.log" 2>&1 ||
            { echo "makensis failed on $name"; cat "/work/$name.log"; exit 1; }
    }
    mk u-zlib "Unicode true" zlib /work/tree
    mk u-bzip2-solid "Unicode true" "/SOLID bzip2" /work/tree
    mk u-lzma-solid "Unicode true" "/SOLID lzma" /work/tree
    mk a-bzip2 "Unicode false" bzip2 /work/tree-ansi
    mk a-zlib-solid "Unicode false" "/SOLID zlib" /work/tree-ansi
    mk x64-lzma "Target amd64-unicode" lzma /work/tree
    mk u-nocrc "Unicode true
CRCCheck off" "/SOLID lzma" /work/tree

    # The trees' files and times, for the host's check.
    python3 -I - <<'PY'
import hashlib, json, os
def tree(root):
    out = {}
    for d, _, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            data = open(p, 'rb').read()
            out[os.path.relpath(p, root)] = {
                'sha256': hashlib.sha256(data).hexdigest(),
                'mtime': int(os.stat(p).st_mtime),
            }
    return out
json.dump({'tree': tree('/work/tree'), 'tree-ansi': tree('/work/tree-ansi'),
           'extra': tree('/work/extra')},
          open('/fixtures/thirdparty/nsis/trees.json', 'w', encoding='utf-8'), ensure_ascii=False)
PY
    for f in "$out"/*.exe; do
        size=$(stat -c %s "$f")
        [ "$size" -lt 150000 ] || { echo "$f is $size bytes"; exit 1; }
    done
    chown -R "${HOST_IDS:-0:0}" "$out" || true
    exit 0
fi

# ---------------------------------------------------------------------------------------------
# On the host.
here="$(cd "$(dirname "$0")" && pwd)"
command -v docker >/dev/null
host() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
docker image inspect beezip-fixtures-7z >/dev/null 2>&1 ||
    docker build -q -t beezip-fixtures-7z - < "$here/make-7z.Dockerfile" >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm -e HOST_IDS="$(id -u):$(id -g)" \
    -v "$(host "$here"):/fixtures" beezip-fixtures-7z bash /fixtures/make-nsis.sh --inside

# What 7-Zip extracts from each, checked against the trees: the records.
sz="${SEVENZIP:-$(command -v 7z || command -v 7zz || echo '/c/Program Files/7-Zip/7z.exe')}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
out="$here/thirdparty/nsis"
for f in "$out"/*.exe; do
    n="$(basename "$f" .exe)"
    "$sz" x -y -bso0 -bsp0 -o"$(host "$tmp/$n")" "$(host "$f")"
done
python -I - "$(host "$here")" "$(host "$tmp")" "$("$sz" i | grep -m1 -o '7-Zip[^:]*[0-9][0-9]*\.[0-9]*')" <<'PY'
import datetime, hashlib, json, os, sys
here, tmp, seven = sys.argv[1:4]
out = os.path.join(here, 'thirdparty', 'nsis')
trees = json.load(open(os.path.join(out, 'trees.json'), encoding='utf-8'))
os.remove(os.path.join(out, 'trees.json'))

def rfc3339(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%S.000000000Z')

# Where the script puts each file, from the tree it installs.
def placed(tree):
    want = {}
    for rel, f in trees[tree].items():
        want[rel.replace(os.sep, '/')] = f
    for name, src in (('renamed.txt', 'readme.txt'), ('again/readme.txt', 'readme.txt'),
                      ('$0/readme.txt', 'readme.txt')):
        want[name] = trees[tree][src]
    for name, src in (('$PLUGINSDIR/plugin-data.bin', 'plugin-data.bin'),
                      ('$PLUGINSDIR/splash.bmp', 'splash.bmp'), ('$SYSDIR/sys.txt', 'sys.txt'),
                      ('$APPDATA/BeeZip/app.txt', 'app.txt'), ('$TEMP/temp.txt', 'temp.txt')):
        want[name] = trees['extra'][src]
    return want

builds = {
    'u-zlib.exe': ('tree', 'Unicode true; SetCompressor zlib'),
    'u-bzip2-solid.exe': ('tree', 'Unicode true; SetCompressor /SOLID bzip2'),
    'u-lzma-solid.exe': ('tree', 'Unicode true; SetCompressor /SOLID lzma'),
    'a-bzip2.exe': ('tree-ansi', 'Unicode false; SetCompressor bzip2'),
    'a-zlib-solid.exe': ('tree-ansi', 'Unicode false; SetCompressor /SOLID zlib'),
    'x64-lzma.exe': ('tree', 'Target amd64-unicode; SetCompressor lzma'),
    'u-nocrc.exe': ('tree', 'Unicode true; CRCCheck off; SetCompressor /SOLID lzma'),
}
records = []
for f, (tree, how) in builds.items():
    root = os.path.join(tmp, f[:-4])
    got = {}
    for d, _, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            data = open(p, 'rb').read()
            got[os.path.relpath(p, root).replace(os.sep, '/')] = (len(data), hashlib.sha256(data).hexdigest())
    want = placed(tree)
    for name, w in want.items():
        assert got.get(name, (0, None))[1] == w['sha256'], (f, name)
    extra = sorted(set(got) - set(want))
    assert extra == ['$PLUGINSDIR/nsExec.dll', 'created-empty.txt', 'uninstall.exe'], (f, extra)
    entries = []
    for name in sorted(got):
        size, sha = got[name]
        e = {'path': name, 'kind': 'file', 'size': size, 'sha256': sha}
        # makensis stores a File's time (to 2 s); none for its plugin, the uninstaller and the
        # empty file.
        if name in want and name != '$PLUGINSDIR/splash.bmp':
            e['mtime'] = rfc3339(want[name]['mtime'])
        entries.append(e)
    records.append({
        'file': 'nsis/' + f,
        'producer': 'makensis 3.09 (Ubuntu 24.04 in Docker)',
        'command': 'makensis -INPUTCHARSET UTF8 (%s; see make-nsis.sh)' % how,
        'chain': 'nsis', 'native': True, 'levels': ['nsis'], 'password': None,
        'utc_mtimes': False, 'hardlinks': 0, 'symlinks': 0,
        'note': ("BeeZip's own reader (docs/M10.md). The entries are what %s extracts, checked "
                 "against the tree the script installs by make-nsis.sh; the uninstaller is the "
                 'stub with its icon patched, then its data, and nsExec.dll is the plugin '
                 'makensis adds.' % seven),
        'entries': entries,
    })

manifest_path = os.path.join(here, 'manifest.json')
manifest = json.load(open(manifest_path, encoding='utf-8'))
old = manifest['fixtures']
mine = lambda r: r['file'].startswith('nsis/')
at = next((i for i, r in enumerate(old) if mine(r)), len(old))
manifest['fixtures'] = old[:at] + records + [r for r in old[at:] if not mine(r)]
with open(manifest_path, 'w', encoding='utf-8', newline='\n') as fh:
    fh.write(json.dumps(manifest, indent=2, ensure_ascii=False))

readme = '''# NSIS fixtures

Made by `tests/fixtures/make-nsis.sh` (docs/M10.md §8) with makensis 3.09: one script built
seven ways. It puts files under `$INSTDIR`, a subfolder, `$INSTDIR\\$0`, `$PLUGINSDIR`, `$SYSDIR`,
`$APPDATA\\BeeZip` and `$TEMP`; renames one (`/oname`); stores one twice; writes an empty file
(`FileOpen` and `FileClose`); calls a plugin (nsExec); and writes its uninstaller.

| File | Strings | Compressor | Solid |
|---|---|---|---|
| `u-zlib.exe` | Unicode | zlib | no |
| `u-bzip2-solid.exe` | Unicode | bzip2 | yes |
| `u-lzma-solid.exe` | Unicode | LZMA | yes |
| `a-bzip2.exe` | ANSI | bzip2 | no |
| `a-zlib-solid.exe` | ANSI | zlib | yes |
| `x64-lzma.exe` | Unicode, 64-bit | LZMA | no |
| `u-nocrc.exe` | Unicode, `CRCCheck off` | LZMA | yes |

Their records in `manifest.json` list what %s extracts from each, checked by the script
against the tree it installs. BeeZip reads every one itself.
''' % seven
open(os.path.join(out, 'README.md'), 'w', encoding='utf-8', newline='\n').write(readme)
print(len(records), 'records', {r['file']: len(r['entries']) for r in records})
PY
ls -l "$out"
