#!/bin/bash
# Makes the macOS package fixtures (docs/M6.md §10) on macOS, which nobody here has: run by
# .github/workflows/make-pkg.yml on GitHub's macos-latest runner, as
#
#   bash tests/fixtures/make-pkg.sh OUT
#
# OUT (the workflow's artifact) gets:
#   pkg/*.pkg           the packages, for tests/fixtures/thirdparty/pkg/macos/
#   pkg-manifest.json   each package as `pkgutil --expand` (its XAR's files) and as
#                       `pkgutil --expand-full` lay it out: every file's size and SHA-256, every
#                       symlink's target, every empty folder; and what each Payload and Scripts is:
#                       its first bytes, and the first bytes inside once gzip or pbzx is undone
#   tools.txt           sw_vers, uname, xar's version, the commands, what was skipped
#   expand/, full/      the two expansions, for a look
#
# The packages: pkgbuild's component package of BeeZip's fixture tree with the default compression
# (whatever this macOS gives: the manifest says which), with --compression legacy, with
# --compression latest for macOS 12 (pbzx), and with --large-payload too (its payload is named
# LargeSegmentedPayload), and productbuild's product archives of the default, the latest and the
# large one. A step macOS refuses is skipped and noted in tools.txt rather than failing the run.
# The packages aren't signed. No option of macOS 26's pkgbuild writes an Apple Archive payload.
#
# The tree: text, an empty file, 4 KiB of Python's Random(42), an executable, a file two folders
# down, an empty folder, a name with accents, a symlink; every time 2026-01-01T00:00:00Z. The
# scripts: preinstall and postinstall.
#
#   bash tests/fixtures/make-pkg.sh --describe OUT
#
# writes pkg-manifest.json alone, from OUT's pkg/, expand/ and full/ and commands.tsv, laid out as
# above (merge-pkg.py's test makes such a layout without a Mac).
#
# Written for macOS's /bin/bash 3.2 and python3.
set -euo pipefail

describe() {
    python3 -I -B - "$1" <<'PY'
import hashlib, json, lzma, os, platform, stat, struct, sys, zlib
out = sys.argv[1]

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def walk(root):
    """Files (size, SHA-256), symlinks (target) and empty folders under root, paths /-separated."""
    files, links, empty = {}, {}, []
    for dp, dns, fns in os.walk(root):
        rel = os.path.relpath(dp, root)
        for n in list(dns):
            if os.path.islink(os.path.join(dp, n)):
                dns.remove(n)
                fns.append(n)
        if not dns and not fns and rel != '.':
            empty.append(rel.replace(os.sep, '/'))
        for n in fns:
            p = os.path.join(dp, n)
            r = os.path.relpath(p, root).replace(os.sep, '/')
            if stat.S_ISLNK(os.lstat(p).st_mode):
                links[r] = os.readlink(p)
            else:
                with open(p, 'rb') as f:
                    d = f.read()
                files[r] = {'size': len(d), 'sha256': sha256(d)}
    return {'files': files, 'links': links, 'empty': sorted(empty)}

def inside(data):
    """What a Payload or Scripts is: its wrapping, and the first bytes inside."""
    if data[:2] == b'\x1f\x8b':
        return 'gzip', zlib.decompressobj(31).decompress(data, 64)[:8]
    if data[:4] == b'pbzx':
        size, packed = struct.unpack_from('>QQ', data, 12)
        chunk = data[28:28 + packed]
        return 'pbzx', (chunk if packed == size else lzma.LZMADecompressor().decompress(chunk, 64))[:8]
    return 'none', data[:8]

def kind(head):
    if head[:6] == b'070707':
        return 'cpio (odc)'
    if head[:6] in (b'070701', b'070702'):
        return 'cpio (newc)'
    if head[:4] in (b'AA01', b'YAA1'):
        return 'Apple Archive'
    return 'unknown'

commands = {}
if os.path.exists(os.path.join(out, 'commands.tsv')):
    for line in open(os.path.join(out, 'commands.tsv'), encoding='utf-8').read().splitlines():
        name, cmd = line.split('\t', 1)
        commands[name] = cmd
packages = []
for name in sorted(os.listdir(os.path.join(out, 'pkg'))):
    if not name.endswith('.pkg'):
        continue
    stem = name[:-4]
    flat = walk(os.path.join(out, 'expand', stem))
    # None when pkgutil couldn't expand it (merge-pkg.py then leaves the package out).
    full = walk(os.path.join(out, 'full', stem)) if os.path.isdir(os.path.join(out, 'full', stem)) else None
    members = {}
    for rel in flat['files']:
        if rel.rsplit('/', 1)[-1] in ('Payload', 'LargeSegmentedPayload', 'Scripts'):
            with open(os.path.join(out, 'expand', stem, *rel.split('/')), 'rb') as f:
                data = f.read()
            wrap, head = inside(data)
            members[rel] = {'magic': data[:8].hex(), 'wrapping': wrap, 'inner_magic': head.hex(), 'inner': kind(head)}
    packages.append({'file': name, 'command': commands.get(name, ''), 'flat': flat, 'full': full, 'members': members})
with open(os.path.join(out, 'pkg-manifest.json'), 'w', encoding='utf-8') as f:
    json.dump({'platform': platform.platform(), 'packages': packages}, f, indent=1, ensure_ascii=False)
PY
}

if [ "${1:-}" = --describe ]; then
    describe "${2:?usage: make-pkg.sh --describe OUT}"
    exit 0
fi

out="${1:?usage: make-pkg.sh OUT}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export LC_ALL=en_US.UTF-8 TZ=UTC
stamp=202601010000 # touch -t: 2026-01-01T00:00:00Z

mkdir -p "$out/pkg" "$out/expand" "$out/full"
out="$(cd "$out" && pwd)"
: > "$out/commands.tsv"
tools="$out/tools.txt"
{
    sw_vers
    echo
    uname -a
    echo
    xar --version 2>&1 || true
    echo
} > "$tools"

note() {
    echo "$*" | tee -a "$tools" >&2
}

python3 -I -B - "$work" <<'PY'
import os, random, sys
work = sys.argv[1]
tree = os.path.join(work, 'tree')
def put(rel, data, mode=0o644):
    p = os.path.join(tree, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'wb') as f:
        f.write(data)
    os.chmod(p, mode)
put('readme.txt', b'Hello, BeeZip!\n')
put('empty.txt', b'')
put('text.txt', ''.join('line %d of a compressible file\n' % i for i in range(120)).encode())
put('random.bin', random.Random(42).randbytes(4096))
put('tool.sh', b'#!/bin/sh\necho BeeZip\n', 0o755)
put('sub/nested/deep.txt', b'deep\n')
put('Ünïcödé café.txt', 'non-ASCII names\n'.encode())
os.makedirs(os.path.join(tree, 'emptydir'))
os.symlink('readme.txt', os.path.join(tree, 'link-to-readme'))
scripts = os.path.join(work, 'scripts')
os.makedirs(scripts)
for n, body in (('preinstall', b'#!/bin/sh\nexit 0\n'), ('postinstall', b'#!/bin/sh\necho installed\nexit 0\n')):
    with open(os.path.join(scripts, n), 'wb') as f:
        f.write(body)
    os.chmod(os.path.join(scripts, n), 0o755)
PY
find "$work/tree" "$work/scripts" -exec touch -h -t "$stamp" {} +

# pkg NAME TOOL ARGS...: runs TOOL with OUT/pkg/NAME last, and records the command.
pkg() {
    local name="$1" tool="$2"
    shift 2
    rm -f "$out/pkg/$name"
    if "$tool" "$@" "$out/pkg/$name" >/dev/null; then
        printf '%s\t%s %s %s\n' "$name" "$tool" "$*" "$name" | sed "s|$work/||g; s|$out/pkg/||g" >> "$out/commands.tsv"
    else
        note "skipped $name: $tool $* failed"
        rm -f "$out/pkg/$name"
    fi
}
common=(--root "$work/tree" --identifier org.beezip.fixture --version 1.0 --install-location /usr/local/beezip-fixture
    --scripts "$work/scripts")
pkg component.pkg pkgbuild "${common[@]}"
pkg component-legacy.pkg pkgbuild "${common[@]}" --compression legacy
# --compression needs --min-os-version (pkgbuild on macOS 26 refuses it alone). `latest` for macOS 12
# gives a pbzx payload of odc cpio; --large-payload (files of 8 GiB and more, macOS 12 and up) an
# LargeSegmentedPayload, pbzx too, which pkgutil --expand-full expands under that name.
pkg component-latest.pkg pkgbuild "${common[@]}" --compression latest --min-os-version 12.0
pkg component-large.pkg pkgbuild "${common[@]}" --compression latest --min-os-version 12.0 --large-payload
[ -f "$out/pkg/component.pkg" ] && pkg product.pkg productbuild --package "$out/pkg/component.pkg"
[ -f "$out/pkg/component-latest.pkg" ] && pkg product-latest.pkg productbuild --package "$out/pkg/component-latest.pkg"
[ -f "$out/pkg/component-large.pkg" ] && pkg product-large.pkg productbuild --package "$out/pkg/component-large.pkg"

# Each package as pkgutil lays it out: --expand (the XAR's files) and --expand-full.
for p in "$out"/pkg/*.pkg; do
    stem="$(basename "$p" .pkg)"
    pkgutil --expand "$p" "$out/expand/$stem" || note "pkgutil --expand $stem failed"
    pkgutil --expand-full "$p" "$out/full/$stem" || note "pkgutil --expand-full $stem failed"
    {
        echo "== $stem: xar -tf"
        xar -tf "$p" 2>&1 || true
        echo "== $stem: pkgutil --payload-files"
        pkgutil --payload-files "$p" 2>&1 || true
    } >> "$tools"
done
cat "$out/commands.tsv" >> "$tools"
describe "$out"
ls -lR "$out/pkg"
