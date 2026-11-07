#!/bin/bash
# Makes tests/fixtures/thirdparty/linux/ (docs/M5.md §10): GNU ar archives from binutils' ar, and
# debs from dpkg-deb in each compression, then merges their records into manifest.json. Run it
# from Windows, in the repository:
#
#   wsl -e bash tests/fixtures/make-linux.sh
#
# Tools (WSL's Ubuntu 24.04, 2026-11-06): GNU ar and as 2.42 (binutils), dpkg-deb 1.22.6,
# python3 3.12, and Windows' 7-Zip 26.00 through WSL's interop for `7z t`.
#
# Everything is made in a temporary folder on WSL's own disk with fixed times (SOURCE_DATE_EPOCH,
# touch -d) and deterministic ar headers, so a rerun writes the same bytes. The expected entries
# come from the tools themselves: `ar t` and `ar p` for ar, `dpkg-deb -R` (and its data.tar's
# hard links) for debs; tests/fixtures/oracles.py must agree with them.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/thirdparty/linux"
seven='/mnt/c/Program Files/7-Zip/7z.exe'
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export SOURCE_DATE_EPOCH=1767225600 # 2026-01-01T00:00:00Z
export LC_ALL=C.UTF-8 TZ=UTC
stamp="@$SOURCE_DATE_EPOCH"

command -v ar as dpkg-deb python3 >/dev/null
[ -x "$seven" ] || { echo "no 7-Zip at $seven" >&2; exit 1; }

cd "$work"
mkdir -p made/broken src

# The files: text, 4 KiB of fixed pseudo-random bytes, an empty file, and a tiny object file.
printf 'Hello, BeeZip!\n' > src/hello.txt
python3 -I -c 'import random, sys; sys.stdout.buffer.write(random.Random(42).randbytes(4096))' > src/random.bin
: > src/empty.txt
printf 'a member whose name is past 15 bytes\n' > src/a-member-with-a-long-name.txt
printf 'another\n' > src/another-long-member-name.txt
printf '\t.globl beezip_symbol\n\t.data\nbeezip_symbol:\n\t.byte 1\n' > src/symbol.s
as -o src/symbol.o src/symbol.s
touch -h -d "$stamp" src/*

# ar: deterministic headers (D: zero times, uids and gids, mode 644).
(
    cd src
    ar rcD ../made/ar-plain.a hello.txt random.bin empty.txt
    ar rcD ../made/ar-longnames.a hello.txt a-member-with-a-long-name.txt another-long-member-name.txt
    ar rcsD ../made/ar-symtab.a symbol.o hello.txt
    ar rcTD ../made/broken/ar-thin.a hello.txt random.bin
)

# deb: a package tree with maintainer scripts, a symlink, a hard link, a name past 100 bytes and
# non-ASCII names.
pkg="$work/pkg"
share="$pkg/usr/share/beezip-fixture"
long="$share/directory-with-a-long-name-0123456789/another-long-directory-name-abcdefghij"
mkdir -p "$pkg/DEBIAN" "$long" "$share/ünïcödé"
cat > "$pkg/DEBIAN/control" <<'CONTROL'
Package: beezip-fixture
Version: 1.0
Architecture: all
Maintainer: BeeZip tests <tests@beezip.invalid>
Section: misc
Priority: optional
Description: a small package for BeeZip's tests
 It holds a symlink, a hard link, a name past 100 bytes and non-ASCII names.
CONTROL
printf '#!/bin/sh\nset -e\nexit 0\n' > "$pkg/DEBIAN/postinst"
chmod 755 "$pkg/DEBIAN/postinst"
cp src/hello.txt src/random.bin src/empty.txt "$share/"
ln -s hello.txt "$share/link-to-hello"
ln "$share/hello.txt" "$share/hard-hello"
printf 'a long path\n' > "$long/file-with-a-long-name-past-100-characters.txt"
printf 'non-ASCII names\n' > "$share/ünïcödé/名前.txt"
find "$pkg" -exec touch -h -d "$stamp" {} +
chmod -R go-w "$pkg"
for z in gzip xz zstd none; do
    dpkg-deb --root-owner-group -Z"$z" --build "$pkg" "made/deb-$z.deb" >/dev/null
done

mkdir -p "$out/broken"
find "$out" -maxdepth 2 -type f \( -name '*.a' -o -name '*.deb' -o -name 'README.md' \) -delete
cp made/*.a made/*.deb "$out/"
cp made/broken/* "$out/broken/"
cat > "$out/broken/README.md" <<'README'
# Broken fixtures

Made by make-linux.sh. They aren't in manifest.json: each must fail as below, without a panic, a
hang or a large allocation.

| File | Expected | Why |
|---|---|---|
| `ar-thin.a` | UnsupportedFormat | A GNU thin archive (`ar rcT`): it starts `!<thin>` and its members are names of other files, not data. |
README

# The records, merged into manifest.json: this script owns linux/.
python3 -I -B - "$here" "$work/made" "$(ar --version | head -n 1)" "$(dpkg-deb --version | head -n 1)" "$seven" <<'PY'
import io, json, os, re, subprocess, sys, tempfile
here, made, ar_version, dpkg_version, seven = sys.argv[1:6]
sys.path.insert(0, here)
import oracles

ar_name = 'GNU ar ' + ar_version.split()[-1] + ' (binutils, Ubuntu 24.04 in WSL)'
dpkg_name = 'dpkg-deb ' + re.search(r'version (\S+)', dpkg_version).group(1) + ' (Ubuntu 24.04 in WSL)'


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def test_7z(path):
    """What `7z t` said, as fetch-libarchive.ps1 records it."""
    win = run('wslpath', '-w', path).decode().strip()
    p = subprocess.run([seven, 't', '-sccUTF-8', win], capture_output=True)
    lines = [l.strip() for l in (p.stdout + p.stderr).decode('utf-8', 'replace').splitlines()]
    if any(re.match(r"^(Open ERROR: )?Can(no|')t open the file as (\[\w+\] )?archive$", l) for l in lines):
        return "can't open it"
    msgs = []
    for l in lines:
        l = re.sub(r'^(ERROR|Open ERROR|WARNING):\s*', '', l.replace(win, '')).strip()
        if re.search(r'(Error|There are (some )?data after|Unexpected end|Unsupported Method|CRC Failed|Is not archive)', l) \
                and not re.match(r'^(ERRORS?:|Archives with Errors|Sub items Errors|Open Errors)', l) and l not in msgs:
            msgs.append(l)
    if p.returncode == 0 and not msgs:
        return 'ok'
    if p.returncode == 0:
        return 'ok, with warnings: ' + '; '.join(msgs)
    return 'errors: ' + '; '.join(msgs)


def entry(e):
    if e['kind'] == 'symlink':
        return {'path': e['path'], 'kind': 'symlink', 'target': e['target']}
    return {'path': e['path'], 'kind': 'file', 'size': e['size'], 'sha256': e['sha256']}


def record(name, producer, command, chain, listing):
    path = os.path.join(made, name)
    entries = [entry(e) for e in listing['entries']]
    return {
        'file': 'linux/' + name, 'producer': producer, 'command': command, 'chain': chain,
        'password': None, 'utc_mtimes': False, 'hardlinks': listing['hardlinks'],
        'symlinks': sum(1 for e in entries if e['kind'] == 'symlink'),
        '7z_test': test_7z(path), 'entries': entries,
    }


def ar_listing(path, want_members):
    names = run('ar', 't', path).decode('utf-8').splitlines()
    listing = oracles.result([oracles.file_entry(n, run('ar', 'p', path, n)) for n in names], 0)
    mine = oracles.ar_list(open(path, 'rb').read(), None)
    if mine['entries'] != listing['entries']:
        raise SystemExit(f'{path}: oracles.py and ar disagree')
    # The raw member names, to check the archive has the table it was made for.
    data = open(path, 'rb').read()
    raw, pos = [], 8
    while pos + 60 <= len(data):
        raw.append(data[pos:pos + 16].rstrip(b' '))
        pos += 60 + int(data[pos + 48:pos + 58])
        pos += pos % 2
    for m in want_members:
        if m not in raw:
            raise SystemExit(f'{path} has no {m!r} member: {raw}')
    return listing


def deb_listing(path):
    tmp = tempfile.mkdtemp()
    root = os.path.join(tmp, 'root')
    run('dpkg-deb', '-R', path, root)
    listing = oracles.tree_list(root)
    tar = oracles.tar_list(io.BytesIO(run('dpkg-deb', '--fsys-tarfile', path)), None)
    if tar['others']:
        raise SystemExit(f'{path}: devices or FIFOs in data.tar')
    data = sorted((e['path'], e.get('sha256'), e.get('target')) for e in listing['entries'] if not e['path'].startswith('DEBIAN/'))
    if data != sorted((e['path'], e.get('sha256'), e.get('target')) for e in tar['entries']):
        raise SystemExit(f'{path}: dpkg-deb -R and data.tar disagree')
    listing['hardlinks'] = tar['hardlinks']
    members = run('ar', 't', path).decode().split()
    return listing, members


records = [
    record('ar-plain.a', ar_name, 'ar rcD ar-plain.a hello.txt random.bin empty.txt', 'ar',
           ar_listing(os.path.join(made, 'ar-plain.a'), [])),
    record('ar-longnames.a', ar_name, 'ar rcD ar-longnames.a hello.txt a-member-with-a-long-name.txt another-long-member-name.txt',
           'ar', ar_listing(os.path.join(made, 'ar-longnames.a'), [b'//'])),
    record('ar-symtab.a', ar_name, 'as -o symbol.o symbol.s; ar rcsD ar-symtab.a symbol.o hello.txt', 'ar',
           ar_listing(os.path.join(made, 'ar-symtab.a'), [b'/'])),
]
want = {'gzip': 'gz', 'xz': 'xz', 'zstd': 'zst', 'none': None}
for z, ext in want.items():
    name = f'deb-{z}.deb'
    listing, members = deb_listing(os.path.join(made, name))
    data = 'data.tar' + ('.' + ext if ext else '')
    if members[0] != 'debian-binary' or data not in members:
        raise SystemExit(f'{name} holds {members}, not {data}')
    records.append(record(name, dpkg_name, f'dpkg-deb --root-owner-group -Z{z} --build pkg {name}', 'deb', listing))

manifest_path = os.path.join(here, 'manifest.json')
with open(manifest_path, encoding='utf-8') as f:
    manifest = json.load(f)
old = manifest['fixtures']
mine = lambda r: r['file'].startswith('linux/')
# The new records go where the old ones were, so a rerun leaves the order alone.
at = next((i for i, r in enumerate(old) if mine(r)), len(old))
manifest['fixtures'] = old[:at] + records + [r for r in old[at:] if not mine(r)]
with open(manifest_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest, indent=2, ensure_ascii=False))
for r in records:
    print(f"{r['file']}: {len(r['entries'])} entries, {r['hardlinks']} hard links, {r['symlinks']} symlinks; 7z t {r['7z_test']}")
PY
du -cb "$out"/*.a "$out"/*.deb "$out"/broken/* | tail -n 1
