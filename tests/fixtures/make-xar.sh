#!/bin/bash
# Makes tests/fixtures/thirdparty/xar/ and thirdparty/pkg/ (docs/M6.md §10): XARs from xar 1.6.1
# and bsdtar in every compression and checksum, XARs from Windows' own tar.exe, and macOS flat
# packages made without a Mac; then merges their records into manifest.json. Run it from Windows,
# in the repository, with Docker Desktop running, from Git Bash or WSL:
#
#   bash tests/fixtures/make-xar.sh
#
# The Linux-made files are made in a container (make-xar.Dockerfile, built here as
# beezip-fixtures-xar), which runs this script again with --inside. Tools: xar 1.6.1 (mackyle/xar
# 66d451d, built in the image), bsdtar 3.7.2 (Ubuntu 24.04's libarchive-tools), mkbom (bomutils
# c247002), GNU cpio 2.15, gzip 1.12, Python 3.12 (the pbzx writer), libfaketime 0.9.10. Then, on
# Windows: tar.exe (bsdtar 3.8.9, Windows' own) makes two XARs of an ASCII-only tree (it crashes on
# other names), and 7-Zip 26.00 tests every file (`7z t`) and extracts each XAR for a cross-check.
#
# The tree: text, an empty file, 4 KiB of Python's Random(42), an executable, a file two folders
# down, an empty folder, names in CJK, an emoji and accents (xar and bsdtar store them in base64), a
# symlink, a dangling symlink, a symlink to a folder and a hard link; every time
# 2026-01-01T00:00:00Z but mtime.txt's, 2024-05-06T07:08:09Z.
#
# The packages hold a Payload tree (an executable, a symlink, a folder with nothing in it, a name
# with accents) and two scripts: a component package (Bom, PackageInfo, Payload and Scripts, the
# last two gzip'd cpio in odc format, as pkgbuild writes them), a product archive (Distribution, a
# Resources file and the component in a folder) and a component whose Payload is pbzx, Apple's
# chunked xz, from a writer here. Bom, PackageInfo and Distribution are stored gzip'd, Payload and
# Scripts as they are, as Apple's tools store them.
#
# Deterministic: a rerun writes the same bytes. The trees are on a tmpfs mounted noatime, made in a
# fixed order (so the inode numbers are the same); xar and bsdtar run under a frozen clock (the
# TOC's creation time) and with a small LD_PRELOAD shim that gives every stat() one device number
# and one change time, which no syscall can set; cpio runs with --renumber-inodes --ignore-devno,
# gzip with -n. tar.exe's XARs can't be made the same way: their TOCs' creation, change and access
# times and inode numbers are fixed afterwards (the TOC deflated again by Python's zlib, its
# checksum made again).
#
# Expected entries are the source trees' files, links and empty folders: xar -x and bsdtar -x must
# extract them from every XAR, and a package's layout is what `pkgutil --expand-full` makes of it
# (Payload and Scripts as folders of their cpio contents, the rest as files), which the container
# makes with xar -x and cpio -i; the records note what 7-Zip 26.00 gets wrong.
set -euo pipefail

E=1767225600 # 2026-01-01T00:00:00Z

# ---------------------------------------------------------------------------------------------
# In the container (root): the archives, into /out/{xar,pkg}; their facts, as /out/facts.json.
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    out=/out
    mkdir -p "$out/xar" "$out/pkg"

    # The shim: one device number and one change time for every stat().
    cat > /tmp/fixstat.c <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#define CTIME 1767225600
static void fix(struct stat *st) {
    st->st_dev = makedev(0, 64);
    st->st_ctim.tv_sec = CTIME;
    st->st_ctim.tv_nsec = 0;
}
static void fix64(struct stat64 *st) {
    st->st_dev = makedev(0, 64);
    st->st_ctim.tv_sec = CTIME;
    st->st_ctim.tv_nsec = 0;
}
#define WRAP(T, F, name, params, args)                       \
    int name params {                                        \
        static int (*real) params;                           \
        if (!real) real = (int (*) params)dlsym(RTLD_NEXT, #name); \
        int r = real args;                                   \
        if (r == 0) F(st);                                   \
        return r;                                            \
    }
WRAP(struct stat, fix, stat, (const char *p, struct stat *st), (p, st))
WRAP(struct stat, fix, lstat, (const char *p, struct stat *st), (p, st))
WRAP(struct stat, fix, fstat, (int fd, struct stat *st), (fd, st))
WRAP(struct stat, fix, fstatat, (int d, const char *p, struct stat *st, int f), (d, p, st, f))
WRAP(struct stat64, fix64, stat64, (const char *p, struct stat64 *st), (p, st))
WRAP(struct stat64, fix64, lstat64, (const char *p, struct stat64 *st), (p, st))
WRAP(struct stat64, fix64, fstat64, (int fd, struct stat64 *st), (fd, st))
WRAP(struct stat64, fix64, fstatat64, (int d, const char *p, struct stat64 *st, int f), (d, p, st, f))
int statx(int d, const char *p, int f, unsigned int mask, struct statx *st) {
    static int (*real)(int, const char *, int, unsigned int, struct statx *);
    if (!real) real = (int (*)(int, const char *, int, unsigned int, struct statx *))dlsym(RTLD_NEXT, "statx");
    int r = real(d, p, f, mask, st);
    if (r == 0) {
        st->stx_dev_major = 0;
        st->stx_dev_minor = 64;
        st->stx_ctime.tv_sec = CTIME;
        st->stx_ctime.tv_nsec = 0;
    }
    return r;
}
C
    gcc -shared -fPIC -O2 -o /tmp/fixstat.so /tmp/fixstat.c -ldl
    fixed=(env LD_PRELOAD="/tmp/fixstat.so:/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"
        FAKETIME='2026-01-01 00:00:00' NO_FAKE_STAT=1)

    W=/work
    cd "$W"
    # The tree, in a fixed order. readme.txt's hard link is made after it, so a tmpfs (which
    # lists a folder newest first) gives xar and bsdtar hard-readme.txt first: that one holds the data.
    T=$W/tree
    mkdir -p "$T/sub/nested" "$T/emptydir" "$T/Ünïcödé"
    printf 'Hello, BeeZip!\n' > "$T/readme.txt"
    : > "$T/empty.txt"
    python3 -I -c "import sys; sys.stdout.write(''.join('line %d of a compressible file\n' % i for i in range(120)))" > "$T/text.txt"
    python3 -I -c 'import random, sys; sys.stdout.buffer.write(random.Random(42).randbytes(4096))' > "$T/random.bin"
    printf 'known mtime\n' > "$T/mtime.txt"
    printf '#!/bin/sh\necho BeeZip\n' > "$T/exec.sh"
    chmod 0755 "$T/exec.sh"
    printf 'deep\n' > "$T/sub/nested/deep.txt"
    printf 'CJK\n' > "$T/Ünïcödé/日本語.txt"
    printf 'emoji\n' > "$T/bee-🐝.txt"
    printf 'accents\n' > "$T/café.txt"
    ln -s readme.txt "$T/link-to-readme"
    ln -s does/not/exist "$T/dangling"
    ln -s nested "$T/sub/link-to-nested"
    ln "$T/readme.txt" "$T/hard-readme.txt"
    find "$T" -exec touch -h -d "@$E" {} +
    touch -d '2024-05-06 07:08:09 UTC' "$T/mtime.txt"

    # XAR: xar 1.6.1 in every compression and checksum, bsdtar in its own.
    x() { # name, then xar's options
        local n=$1
        shift
        # (xar warns that MD5 is obsolete, and of each file without a checksum.)
        (cd "$T" && "${fixed[@]}" xar -c -f "$out/xar/$n" "$@" . 2>/dev/null)
    }
    x xar-none-sha1.xar --compression=none
    x xar-gzip-sha256.xar --compression=gzip --toc-cksum=sha256 --file-cksum=sha256
    x xar-bzip2-md5.xar --compression=bzip2 --toc-cksum=md5 --file-cksum=md5
    x xar-xz-sha1.xar --compression=xz
    x xar-lzma-sha512.xar --compression=lzma --toc-cksum=sha512 --file-cksum=sha512
    x xar-gzip-none.xar --compression=gzip --toc-cksum=none --file-cksum=none
    b() { # name, then bsdtar's xar options
        local n=$1
        shift
        (cd "$T" && "${fixed[@]}" bsdtar -c -f "$out/xar/$n" --format xar "$@" .)
    }
    b bsdtar-gzip-sha1.xar
    b bsdtar-lzma-md5.xar --options xar:compression=lzma,xar:checksum=md5,xar:toc-checksum=md5
    b bsdtar-xz-none.xar --options xar:compression=xz,xar:checksum=none,xar:toc-checksum=none
    b bsdtar-none-md5.xar --options xar:compression=none,xar:checksum=md5,xar:toc-checksum=md5

    # Packages. The Payload's tree and the scripts, owned by root:admin (0:80) as in a real one.
    P=$W/pkg
    R=$P/root
    S=$P/scripts
    mkdir -p "$R/usr/local/bin" "$R/usr/local/share/hello/empty" "$S"
    printf '#!/bin/sh\necho hello\n' > "$R/usr/local/bin/hello"
    chmod 0755 "$R/usr/local/bin/hello"
    python3 -I -c "import sys; sys.stdout.write('readme ' * 600 + '\n')" > "$R/usr/local/share/hello/README"
    printf 'accents\n' > "$R/usr/local/share/hello/Ünïcödé.txt"
    ln -s ../share/hello/README "$R/usr/local/bin/hello-readme"
    printf '#!/bin/sh\nexit 0\n' > "$S/preinstall"
    printf '#!/bin/sh\necho installed\nexit 0\n' > "$S/postinstall"
    chmod 0755 "$S/preinstall" "$S/postinstall"
    find "$R" "$S" -exec touch -h -d "@$E" {} +
    cpio_of() { # folder: its cpio (odc), "." first, as pkgbuild writes it
        (cd "$1" && find . | LC_ALL=C sort | cpio -o --quiet -H odc --owner 0:80 --renumber-inodes --ignore-devno)
    }
    cpio_of "$R" > "$P/payload.cpio"
    cpio_of "$S" > "$P/scripts.cpio"
    C=$P/component
    mkdir -p "$C"
    gzip -9n < "$P/payload.cpio" > "$C/Payload"
    gzip -9n < "$P/scripts.cpio" > "$C/Scripts"
    "${fixed[@]}" mkbom -u 0 -g 80 "$R" "$C/Bom"
    n=$(find "$R" | wc -l)
    kb=$(du -sk --apparent-size "$R" | cut -f1)
    cat > "$C/PackageInfo" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<pkg-info overwrite-permissions="true" relocatable="false" identifier="org.beezip.fixture.hello" postinstall-action="none" version="1.0" format-version="2" generator-version="make-xar.sh" install-location="/" auth="root">
    <payload numberOfFiles="$n" installKBytes="$kb"/>
    <bundle-version/>
    <upgrade-bundle/>
    <update-bundle/>
    <atomic-update-bundle/>
    <strict-identifier/>
    <relocate/>
    <scripts>
        <preinstall file="./preinstall"/>
        <postinstall file="./postinstall"/>
    </scripts>
</pkg-info>
EOF
    D=$P/product
    mkdir -p "$D/hello.pkg" "$D/Resources/en.lproj"
    cp -p "$C"/* "$D/hello.pkg/"
    cat > "$D/Distribution" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>BeeZip fixture</title>
    <welcome file="Welcome.txt"/>
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
    <choices-outline>
        <line choice="default">
            <line choice="org.beezip.fixture.hello"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="org.beezip.fixture.hello" visible="false">
        <pkg-ref id="org.beezip.fixture.hello"/>
    </choice>
    <pkg-ref id="org.beezip.fixture.hello" version="1.0" onConclusion="none" installKBytes="$kb">#hello.pkg</pkg-ref>
</installer-gui-script>
EOF
    printf 'Installs a fixture of BeeZip'"'"'s tests.\n' > "$D/Resources/en.lproj/Welcome.txt"
    # pbzx: Apple's layout (a 16 MiB chunk size; each chunk xz, or stored when xz doesn't shrink
    # it): the magic, the chunk size, then per chunk its size, its packed size and its bytes.
    Z=$P/pbzx
    mkdir -p "$Z"
    cp -p "$C/Bom" "$C/PackageInfo" "$C/Scripts" "$Z/"
    python3 -I - "$P/payload.cpio" "$Z/Payload" <<'PY'
import lzma, struct, sys
data = open(sys.argv[1], 'rb').read()
CHUNK = 1 << 24
out = bytearray(b'pbzx' + struct.pack('>Q', CHUNK))
for i in range(0, max(len(data), 1), CHUNK):
    c = data[i:i + CHUNK]
    z = lzma.compress(c, format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE, preset=6)
    out += struct.pack('>QQ', len(c), len(z) if len(z) < len(c) else len(c)) + (z if len(z) < len(c) else c)
open(sys.argv[2], 'wb').write(out)
PY
    find "$P" -exec touch -h -d "@$E" {} +
    # Bom, PackageInfo and Distribution gzip'd, Payload and Scripts as they are.
    raw='^(.*/)?(Payload|Scripts)$'
    (cd "$C" && "${fixed[@]}" xar -c -f "$out/pkg/component.pkg" --compression=gzip --no-compress="$raw" Bom PackageInfo Payload Scripts)
    (cd "$D" && "${fixed[@]}" xar -c -f "$out/pkg/product.pkg" --compression=gzip --no-compress="$raw" Distribution Resources hello.pkg)
    (cd "$Z" && "${fixed[@]}" xar -c -f "$out/pkg/pbzx.pkg" --compression=gzip --no-compress="$raw" Bom PackageInfo Payload Scripts)

    {
        dpkg-query -W -f '${Package} ${Version}\n' libarchive-tools cpio gzip libfaketime
        xar --version | head -n 1
        python3 -I -c 'import sys; print("python3", sys.version.split()[0])'
    } > "$out/versions.txt"

    # The facts: the trees, each XAR's table of contents, what xar and bsdtar extract, and each
    # package as `pkgutil --expand-full` lays it out (xar -x, then cpio -i of Payload and Scripts).
    python3 -I -B - "$W" "$out" <<'PY'
import base64, bz2, hashlib, json, lzma, os, stat, struct, subprocess, sys, tempfile, zlib
import xml.etree.ElementTree as ET
work, out = sys.argv[1:3]

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def show(b):
    """A name's bytes as text: UTF-8, with any other byte as \\xNN."""
    return b.decode('utf-8', 'backslashreplace')

def walk(root):
    """Files (size, SHA-256, mtime), symlinks (target) and empty folders under root."""
    files, links, empty = {}, {}, []
    root = root.encode()
    for dp, dns, fns in os.walk(root):
        rel = os.path.relpath(dp, root)
        for n in list(dns):
            p = os.path.join(dp, n)
            if os.path.islink(p):
                dns.remove(n)
                fns.append(n)
        if not dns and not fns and rel != b'.':
            empty.append(show(rel))
        for n in fns:
            p = os.path.join(dp, n)
            r = show(os.path.relpath(p, root))
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                links[r] = show(os.readlink(p))
            else:
                with open(p, 'rb') as f:
                    d = f.read()
                files[r] = {'size': len(d), 'sha256': sha256(d), 'mtime': int(st.st_mtime)}
    return {'files': files, 'links': links, 'empty': sorted(empty)}

def decode(enc, raw):
    """A file's data, decoded here by its encoding style: an oracle apart from xar and bsdtar."""
    if enc == 'application/octet-stream':
        return raw
    if enc in ('application/x-gzip', 'application/zlib'):
        return zlib.decompress(raw)
    if enc == 'application/x-bzip2':
        return bz2.decompress(raw)
    if enc in ('application/x-xz', 'application/x-lzma'):
        # xar 1.6.1 writes x-lzma in xz's format, libarchive in .lzma's: Python's lzma tells them apart.
        return lzma.decompress(raw, format=lzma.FORMAT_AUTO)
    raise ValueError(enc)

def toc(path):
    """The header and table of contents: checksum, each file's name, type, link, encoding."""
    with open(path, 'rb') as f:
        d = f.read()
    magic, hsize, ver, clen, ulen, alg = struct.unpack('>4sHHQQI', d[:28])
    name = d[28:hsize].split(b'\0', 1)[0].decode() if hsize > 28 else None
    x = ET.fromstring(zlib.decompress(d[hsize:hsize + clen]))
    t = x.find('toc')
    ck = t.find('checksum')
    entries = []
    def visit(el, prefix):
        for fe in el.findall('file'):
            nm = fe.find('name')
            n = base64.b64decode(nm.text).decode() if nm.get('enctype') == 'base64' else nm.text
            ty = fe.find('type')
            e = {'path': prefix + n, 'type': ty.text, 'link': ty.get('link'), 'base64': nm.get('enctype') == 'base64'}
            ln = fe.find('link')
            if ln is not None:
                e['target'], e['target_type'] = ln.text, ln.get('type')
            data = fe.find('data')
            if data is not None:
                e['encoding'] = data.find('encoding').get('style')
                a = data.find('archived-checksum')
                x = data.find('extracted-checksum')
                e['file_cksum'] = a.get('style') if a is not None else None
                at = hsize + clen + int(data.findtext('offset'))
                raw = d[at:at + int(data.findtext('length'))]
                plain = decode(e['encoding'], raw)
                e['data'] = {'size': len(plain), 'sha256': sha256(plain), 'stored_size': int(data.findtext('size')),
                             'checksums_ok': all(c is None or hashlib.new(c.get('style'), b).hexdigest() == c.text
                                                 for c, b in ((a, raw), (x, plain)))}
            entries.append(e)
            visit(fe, prefix + n + '/')
    visit(t, '')
    return {'header_size': hsize, 'cksum_alg': alg, 'cksum_name': name, 'toc_cksum': ck.get('style') if ck is not None else None,
            'creation_time': t.findtext('creation-time'), 'entries': entries,
            'trailing': len(d) - (hsize + clen) - max([0] + [int(fe.findtext('data/offset')) + int(fe.findtext('data/length'))
                                                             for fe in t.iter('file') if fe.find('data') is not None]
                                                            + ([int(ck.findtext('offset')) + int(ck.findtext('size'))] if ck is not None else []))}

def extract(cmd, path):
    d = tempfile.mkdtemp()
    p = subprocess.run(cmd(path, d), capture_output=True)
    w = walk(d)
    subprocess.run(['rm', '-rf', d])
    return {'exit': p.returncode, 'stderr': p.stderr.decode('utf-8', 'replace')[-500:], **w}

XAR_X = lambda path, d: ['xar', '-x', '-f', path, '-C', d]
BSDTAR_X = lambda path, d: ['bsdtar', '-x', '-f', path, '-C', d]

def pbzx(data):
    if data[:4] != b'pbzx':
        raise SystemExit('not pbzx')
    pos, out = 12, bytearray()
    while pos < len(data):
        size, packed = struct.unpack_from('>QQ', data, pos)
        pos += 16
        chunk = data[pos:pos + packed]
        pos += packed
        out += chunk if packed == size else lzma.decompress(chunk, format=lzma.FORMAT_XZ)
    return bytes(out)

def expand_full(path):
    """`pkgutil --expand-full`: the XAR's files, with each Payload and Scripts made a folder of
    its cpio's contents (gzip'd or pbzx)."""
    d = tempfile.mkdtemp()
    subprocess.run(['xar', '-x', '-f', path, '-C', d], check=True)
    kinds = {}
    for dp, dns, fns in os.walk(d):
        for n in fns:
            if n not in ('Payload', 'Scripts'):
                continue
            p = os.path.join(dp, n)
            with open(p, 'rb') as f:
                raw = f.read()
            if raw[:2] == b'\x1f\x8b':
                kinds[os.path.relpath(p, d)] = 'gzip'
                data = zlib.decompress(raw, 31)
            elif raw[:4] == b'pbzx':
                kinds[os.path.relpath(p, d)] = 'pbzx'
                data = pbzx(raw)
            else:
                raise SystemExit(f'{path}: {n} is neither gzip nor pbzx')
            os.remove(p)
            os.mkdir(p)
            subprocess.run(['cpio', '-i', '-d', '--quiet', '--no-absolute-filenames', '-H', 'odc'], cwd=p, input=data, check=True)
    w = walk(d)
    subprocess.run(['rm', '-rf', d])
    w['kinds'] = kinds
    return w

facts = {'tree': walk(os.path.join(work, 'tree')), 'archives': {}}
P = os.path.join(work, 'pkg')
facts['pkg'] = {k: walk(os.path.join(P, k)) for k in ('root', 'scripts', 'component', 'product', 'pbzx')}
for n in sorted(os.listdir(os.path.join(out, 'xar'))):
    p = os.path.join(out, 'xar', n)
    facts['archives'][f'xar/{n}'] = {'toc': toc(p), 'xar': extract(XAR_X, p), 'bsdtar': extract(BSDTAR_X, p)}
for n in sorted(os.listdir(os.path.join(out, 'pkg'))):
    p = os.path.join(out, 'pkg', n)
    facts['archives'][f'pkg/{n}'] = {'toc': toc(p), 'expanded': expand_full(p)}
with open(os.path.join(out, 'facts.json'), 'w', encoding='utf-8') as f:
    json.dump(facts, f, indent=1, ensure_ascii=False)
PY
    exit 0
fi

# ---------------------------------------------------------------------------------------------
# On Windows (Git Bash or WSL): the container, tar.exe's XARs, 7-Zip, the records and READMEs.
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
export MSYS_NO_PATHCONV=1
# Docker Desktop takes WSL's paths as they are, and Git Bash's as Windows paths.
if command -v wslpath >/dev/null 2>&1; then
    hostpath() { echo "$1"; }
else
    hostpath() { (cd "$(dirname "$1")" && echo "$(pwd -W)/$(basename "$1")"); }
fi
py=
for p in python3 python; do
    if "$p" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then py=$p; break; fi
done
[ -n "$py" ] || { echo "no Python 3.10 or newer" >&2; exit 1; }
command -v docker >/dev/null

work="$repo/target/make-xar"
rm -rf "$work"
mkdir -p "$work/made"
docker build -q -t beezip-fixtures-xar - < "$here/make-xar.Dockerfile" >/dev/null
docker run --rm --tmpfs /work:rw,noatime -v "$(hostpath "$here/make-xar.sh"):/make-xar.sh:ro" \
    -v "$(hostpath "$work/made"):/out" beezip-fixtures-xar bash /make-xar.sh --inside

"$py" -I -B - "$(hostpath "$here")" "$(hostpath "$work")" <<'PY'
import base64, datetime, hashlib, json, os, re, shutil, struct, subprocess, sys, tempfile, zlib
here, work = sys.argv[1:3]
tp = os.path.join(here, 'thirdparty')
made = os.path.join(work, 'made')
facts = json.load(open(os.path.join(made, 'facts.json'), encoding='utf-8'))
versions = dict(l.split(' ', 1) for l in open(os.path.join(made, 'versions.txt'), encoding='utf-8').read().splitlines())
E = 1767225600

if os.name == 'nt':
    SEVEN = r'C:\Program Files\7-Zip\7z.exe'
    TAR = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'tar.exe')
    def wpath(p):
        return os.path.abspath(p)
else:
    SEVEN = '/mnt/c/Program Files/7-Zip/7z.exe'
    TAR = '/mnt/c/Windows/System32/tar.exe'
    def wpath(p):
        return subprocess.run(['wslpath', '-w', p], check=True, capture_output=True, text=True).stdout.strip()
for exe in (SEVEN, TAR):
    if not os.path.exists(exe):
        raise SystemExit(f'no {exe}')
seven_version = re.search(r'7-Zip (?:\(\w\) )?([\d.]+)', subprocess.run([SEVEN], capture_output=True).stdout.decode('utf-8', 'replace')).group(1)
tar_version = re.search(r'libarchive ([\d.]+)', subprocess.run([TAR, '--version'], capture_output=True, text=True).stdout).group(1)

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def rfc3339(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000000000Z')

# tar.exe's XARs: an ASCII-only tree on NTFS (bsdtar 3.8.9 for Windows crashes on any other
# name), with the hard link; no symlinks, which Windows makes only in Developer Mode.
win = os.path.join(work, 'win')
wt = os.path.join(win, 'tree')
def put(rel, data, mtime=E):
    p = os.path.join(wt, *rel.split('/'))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'wb') as f:
        f.write(data)
    os.utime(p, (mtime, mtime))
import random
put('readme.txt', b'Hello, BeeZip!\n')
put('empty.txt', b'')
put('text.txt', ''.join('line %d of a compressible file\n' % i for i in range(120)).encode())
put('random.bin', random.Random(42).randbytes(4096))
put('mtime.txt', b'known mtime\n', 1714979289)
put('sub/nested/deep.txt', b'deep\n')
os.makedirs(os.path.join(wt, 'emptydir'))
os.link(os.path.join(wt, 'readme.txt'), os.path.join(wt, 'hard-readme.txt'))
for dp, dns, fns in os.walk(wt, topdown=False):
    for n in dns:
        os.utime(os.path.join(dp, n), (E, E))
os.utime(wt, (E, E))
WIN_TREE = {}
for dp, dns, fns in os.walk(wt):
    for n in fns:
        p = os.path.join(dp, n)
        with open(p, 'rb') as f:
            d = f.read()
        WIN_TREE[os.path.relpath(p, wt).replace(os.sep, '/')] = {'size': len(d), 'sha256': sha256(d), 'mtime': int(os.stat(p).st_mtime)}

def fix_toc(path):
    """tar.exe's TOC as it would be with a frozen clock and fixed files: its creation time, every
    file's change and access times 2026-01-01T00:00:00Z and inode numbers counted from 1, deflated
    again by Python's zlib at level 6 (tar.exe's zlib, Chromium's fork, packs the same level
    differently), the TOC's checksum made again, and libarchive's stray bytes after the heap (as
    many as the checksum has: the packed TOC's first ones) copied again."""
    with open(path, 'rb') as f:
        d = bytearray(f.read())
    magic, hsize, ver, clen, ulen, alg = struct.unpack('>4sHHQQI', d[:28])
    packed = bytes(d[hsize:hsize + clen])
    text = zlib.decompress(packed).decode('utf-8')
    text = re.sub(r'<creation-time>[^<]*</creation-time>', '<creation-time>2026-01-01T00:00:00</creation-time>', text)
    text = re.sub(r'<(ctime|atime)>[^<]*</\1>', r'<\1>2026-01-01T00:00:00Z</\1>', text)
    inodes = {}
    text = re.sub(r'<inode>(\d+)</inode>', lambda m: f'<inode>{inodes.setdefault(m.group(1), len(inodes) + 1)}</inode>', text)
    new = zlib.compress(text.encode('utf-8'), 6)
    heap = hsize + clen
    rest = d[heap:]
    ck = re.search(r'<checksum style="(\w+)">\s*<offset>(\d+)</offset>\s*<size>(\d+)</size>', text)
    tail = 0
    if ck:
        off, tail = int(ck.group(2)), int(ck.group(3))
        rest[off:off + tail] = hashlib.new(ck.group(1), new).digest()
    if tail:
        if bytes(rest[-tail:]) != packed[:tail]:
            raise SystemExit(f'{path}: no copy of the TOC\'s start after the heap')
        rest[-tail:] = new[:tail]
    d = d[:8] + struct.pack('>QQ', len(new), len(text.encode('utf-8'))) + d[24:hsize] + new + rest
    with open(path, 'wb') as f:
        f.write(d)

TAREXE = [('tarexe-gzip-sha1.xar', []), ('tarexe-bzip2-md5.xar', ['--options', 'xar:compression=bzip2,xar:checksum=md5,xar:toc-checksum=md5'])]
for n, opts in TAREXE:
    dest = os.path.join(made, 'xar', n)
    p = subprocess.run([TAR, '-c', '-f', wpath(dest), '--format', 'xar'] + opts + ['-C', wpath(wt), '.'], capture_output=True)
    if p.returncode:
        raise SystemExit(f'tar.exe {n}: {p.stderr}')
    fix_toc(dest)

# The files in thirdparty/xar/ and thirdparty/pkg/ (not pkg/macos/, merge-pkg.py's) are replaced.
for d in ('xar', 'pkg'):
    os.makedirs(os.path.join(tp, d), exist_ok=True)
    for n in os.listdir(os.path.join(tp, d)):
        if os.path.isfile(os.path.join(tp, d, n)):
            os.remove(os.path.join(tp, d, n))
    for n in os.listdir(os.path.join(made, d)):
        shutil.copyfile(os.path.join(made, d, n), os.path.join(tp, d, n))

def tarexe_x(path):
    """The files tar.exe extracts."""
    d = tempfile.mkdtemp(dir=work)
    subprocess.run([TAR, '-x', '-f', wpath(path), '-C', wpath(d)], check=True, capture_output=True)
    got = {}
    for dp, dns, fns in os.walk(d):
        for n in fns:
            with open(os.path.join(dp, n), 'rb') as f:
                data = f.read()
            got[os.path.relpath(os.path.join(dp, n), d).replace(os.sep, '/')] = (len(data), sha256(data))
    shutil.rmtree(d)
    return got

def test_7z(path):
    """What `7z t` said, as make-7z.sh records it."""
    w = wpath(path)
    p = subprocess.run([SEVEN, 't', '-sccUTF-8', w], capture_output=True)
    lines = [l.strip() for l in (p.stdout + p.stderr).decode('utf-8', 'backslashreplace').splitlines()]
    if any(re.match(r"^(Open ERROR: )?Can(no|')t open the file as (\[\w+\] )?archive$", l) for l in lines):
        return "can't open it"
    msgs = []
    for l in lines:
        l = re.sub(r'^(ERROR|Open ERROR|WARNING):\s*', '', l.replace(w, '')).strip()
        if re.search(r'(Error|There are (some )?data after|Unexpected end|Unsupported Method|CRC Failed|Is not archive)', l) \
                and not re.match(r'^(ERRORS?:|Archives with Errors|Sub items Errors|Open Errors)', l) and l not in msgs:
            msgs.append(l)
    if p.returncode == 0 and not msgs:
        return 'ok'
    return ('ok, with warnings: ' if p.returncode == 0 else 'errors: ') + '; '.join(msgs)

def extract_7z(path):
    """The files `7z x -snl` writes (symlinks as links where Windows allows them)."""
    d = tempfile.mkdtemp(dir=work)
    p = subprocess.run([SEVEN, 'x', '-y', '-snl', '-bso0', '-bsp0', '-o' + wpath(d), '--', wpath(path)], capture_output=True)
    got = {}
    for dp, dns, fns in os.walk(d):
        for n in fns:
            q = os.path.join(dp, n)
            if os.path.islink(q):
                continue
            with open(q, 'rb') as f:
                data = f.read()
            got[os.path.relpath(q, d).replace(os.sep, '/')] = {'size': len(data), 'sha256': sha256(data)}
    shutil.rmtree(d)
    return p.returncode, got

records, problems = [], []
def check(cond, msg):
    if not cond:
        problems.append(msg)

def key(v):
    return (v['size'], v['sha256'])

def seven_note(rel, want, t=None):
    """What 7-Zip makes of the files: the same, or what it gets wrong."""
    path = os.path.join(tp, rel)
    rc, got = extract_7z(path)
    tested = test_7z(path)
    v = f'7-Zip {seven_version}'
    if 'Unsupported Method' in tested and t:
        encs = sorted({e['encoding'] for e in t['entries'] if e.get('encoding', 'application/octet-stream') != 'application/octet-stream'})
        said = f'{v} doesn\'t decode {", ".join(encs)} (Unsupported Method), so it isn\'t the oracle for the data'
        if any(e['base64'] for e in t['entries']):
            said += '; it shows base64 names undecoded'
        if 'CRC Error' in tested:
            said += f'; it calls the {t["toc_cksum"].upper()} TOC checksum a CRC error'
        return said + '.'
    wrong, empty, missing, renamed = [], [], [], []
    for p, w in sorted(want.items()):
        if p in got and key(got[p]) == key(w):
            continue
        if p in got:
            (empty if got[p]['size'] == 0 else wrong).append(f'`{p}`')
            continue
        other = [q for q, x in got.items() if key(x) == key(w) and q not in want]
        (renamed.append(f'`{p}` as `{other[0]}`') if other else missing.append(f'`{p}`'))
    if not (wrong or empty or missing or renamed):
        return f'{v} extracts the same files.'
    said = []
    if renamed:
        said.append('shows base64 names undecoded (' + ', '.join(renamed) + ')')
    if empty:
        said.append('extracts ' + ', '.join(empty) + ' empty' + (' (the hard link and the file it links)' if len(empty) == 2 else ''))
    if wrong:
        said.append('extracts other bytes for ' + ', '.join(wrong))
    if missing:
        said.append('can\'t extract ' + ', '.join(missing))
    return f'{v} ' + '; '.join(said) + ', so it isn\'t the oracle for those.'

def record(rel, producer, command, chain, entries, note, symlinks, hardlinks):
    r = {'file': rel, 'producer': producer, 'command': command, 'chain': chain, 'password': None, 'utc_mtimes': False,
         'hardlinks': hardlinks, 'symlinks': symlinks, 'note': note, '7z_test': test_7z(os.path.join(tp, rel)),
         'entries': entries}
    records.append(r)
    return r

def file_entry(path, v, mtime=True):
    e = {'path': path, 'kind': 'file', 'size': v['size'], 'sha256': v['sha256']}
    if mtime:
        e['mtime'] = rfc3339(v['mtime'])
    return e

def entries_of(tree, mtimes=True):
    order = lambda p: (p.count('/'), p)
    out = [file_entry(p, tree['files'][p], mtimes) for p in sorted(tree['files'], key=order)]
    out += [{'path': p, 'kind': 'symlink', 'target': t} for p, t in sorted(tree.get('links', {}).items(), key=lambda x: order(x[0]))]
    out += [{'path': p, 'kind': 'folder'} for p in sorted(tree.get('empty', []))]
    return out

def same_tree(got, tree):
    return ({p: key(v) for p, v in got['files'].items()} == {p: key(v) for p, v in tree['files'].items()}
            and got['links'] == tree.get('links', {}) and sorted(got['empty']) == sorted(tree.get('empty', [])))

def tool_note(who, got, tree):
    """What a tool's extraction got wrong, for a note ('' when nothing)."""
    if same_tree(got, tree):
        return ''
    if not got['files'] and got['exit']:
        err = got['stderr'].strip().splitlines()[-1] if got['stderr'].strip() else f'exit {got["exit"]}'
        return f' {who} can\'t open it ({err}).'
    said = []
    missing = [p for p in sorted(tree['files']) if p not in got['files']]
    wrong = [p for p in sorted(tree['files']) if p in got['files'] and key(got['files'][p]) != key(tree['files'][p])]
    extra = [p for p in sorted(got['files']) if p not in tree['files']]
    if missing:
        said.append('doesn\'t write ' + ', '.join(f'`{p}`' for p in missing))
    if wrong:
        said.append('writes other bytes for ' + ', '.join(f'`{p}`' for p in wrong))
    if extra:
        said.append('writes ' + ', '.join(f'`{p}`' for p in extra))
    lost = [p for p in sorted(tree.get('links', {})) if got['links'].get(p) != tree['links'][p]]
    if lost:
        said.append('makes other links for ' + ', '.join(f'`{p}`' for p in lost))
    return f' {who} ' + '; '.join(said) + '.'

def toc_check(rel, t, tree):
    """The TOC (read and decoded by the container's Python) holds the tree: every file's data, the
    checksums right, the links' targets, the empty folder."""
    files = {e['path']: e for e in t['entries'] if 'data' in e}
    check({p: key(e['data']) for p, e in files.items()} == {p: key(v) for p, v in tree['files'].items() if p in files},
          f'{rel}: the TOC\'s data decodes to something else')
    check(all(e['data']['checksums_ok'] and e['data']['stored_size'] == e['data']['size'] for e in files.values()),
          f'{rel}: a checksum or size in the TOC is wrong')
    # An empty file has no data, nor has a hard link but the one holding it.
    nodata = sorted(p for p in tree['files'] if p not in files and tree['files'][p]['size'])
    check(all(next(e for e in t['entries'] if e['path'] == p)['type'] == 'hardlink' for p in nodata), f'{rel}: {nodata} have no data')
    check({e['path']: e['target'] for e in t['entries'] if e['type'] == 'symlink'} == tree.get('links', {}),
          f'{rel}: the TOC\'s links')
    dirs = {e['path'] for e in t['entries'] if e['type'] == 'directory'}
    check(set(tree.get('empty', [])) <= dirs, f'{rel}: the TOC lacks an empty folder')

COMMANDS = {
    'xar-none-sha1.xar': 'xar -c -f xar-none-sha1.xar --compression=none .',
    'xar-gzip-sha256.xar': 'xar -c -f xar-gzip-sha256.xar --compression=gzip --toc-cksum=sha256 --file-cksum=sha256 .',
    'xar-bzip2-md5.xar': 'xar -c -f xar-bzip2-md5.xar --compression=bzip2 --toc-cksum=md5 --file-cksum=md5 .',
    'xar-xz-sha1.xar': 'xar -c -f xar-xz-sha1.xar --compression=xz .',
    'xar-lzma-sha512.xar': 'xar -c -f xar-lzma-sha512.xar --compression=lzma --toc-cksum=sha512 --file-cksum=sha512 .',
    'xar-gzip-none.xar': 'xar -c -f xar-gzip-none.xar --compression=gzip --toc-cksum=none --file-cksum=none .',
    'bsdtar-gzip-sha1.xar': 'bsdtar -c -f bsdtar-gzip-sha1.xar --format xar .',
    'bsdtar-lzma-md5.xar': 'bsdtar -c -f bsdtar-lzma-md5.xar --format xar --options xar:compression=lzma,xar:checksum=md5,xar:toc-checksum=md5 .',
    'bsdtar-xz-none.xar': 'bsdtar -c -f bsdtar-xz-none.xar --format xar --options xar:compression=xz,xar:checksum=none,xar:toc-checksum=none .',
    'bsdtar-none-md5.xar': 'bsdtar -c -f bsdtar-none-md5.xar --format xar --options xar:compression=none,xar:checksum=md5,xar:toc-checksum=md5 .',
}
TAREXE_CKSUM = [('tarexe-gzip-sha1.xar', 'sha1'), ('tarexe-bzip2-md5.xar', 'md5')]

def stray_note(cksum):
    """libarchive copies the packed TOC's first bytes after the heap, as many as its checksum has."""
    n = {'sha1': 20, 'md5': 16}.get(cksum or 'none', 0)
    return (f' libarchive writes {n} stray bytes after the heap (as many as the TOC\'s checksum has: the packed TOC\'s '
            'first ones).') if n else ''

ENC = {'application/octet-stream': 'none', 'application/x-gzip': 'gzip', 'application/zlib': 'zlib (gzip, RFC 6713\'s name)',
       'application/x-bzip2': 'bzip2', 'application/x-xz': 'xz', 'application/x-lzma': 'lzma'}

def summary(t):
    encs = sorted({ENC.get(e['encoding'], e['encoding']) for e in t['entries'] if 'encoding' in e and e.get('encoding')})
    fcks = sorted({e['file_cksum'] or 'none' for e in t['entries'] if 'encoding' in e})
    return (f'Data {", ".join(encs)}; the TOC\'s checksum {t["toc_cksum"] or "none"}' +
            (f' (header type {t["cksum_alg"]}, named {t["cksum_name"]} in a {t["header_size"]}-byte header)' if t['cksum_alg'] == 3 else '') +
            f', files\' {", ".join(fcks)}')

# XAR -----------------------------------------------------------------------------------------
tree = facts['tree']
xar_ver = 'xar ' + versions['xar']
PRODUCER = {
    'xar': f"{xar_ver} (mackyle/xar 66d451d, built in Docker on Ubuntu 24.04)",
    'bsdtar': f"bsdtar {versions['libarchive-tools'].split('-')[0]} (Ubuntu 24.04's libarchive-tools, in Docker)",
    'tarexe': f"bsdtar {tar_version} (Windows' tar.exe)",
}
COMMON = ('Entries are the source tree\'s files, symlinks and empty folder, which the tool that made it extracts and '
          'whose data the TOC reader in make-xar.sh decodes, every checksum matching; each file\'s `mtime` is the time the '
          'TOC holds (utc_mtimes is false: mtime.txt is 2024-05-06T07:08:09Z, every other file 2026-01-01T00:00:00Z). '
          'hard-readme.txt and readme.txt are one file: the TOC gives the first its data '
          '(`<type link="original">hardlink</type>`) and the second none (`<type link="ID">`), so BeeZip lists one hard '
          'link.')
for rel, f in sorted(facts['archives'].items()):
    if not rel.startswith('xar/'):
        continue
    n = rel[4:]
    t = f['toc']
    tool = n.split('-')[0]
    if tool == 'tarexe':
        continue
    toc_check(rel, t, tree)
    # The tool that made it must extract the tree; the other one's misreadings go in the note.
    check(same_tree(f[tool], tree), f'{rel}: {tool} -x extracts something else:{tool_note(tool + " -x", f[tool], tree)}')
    other = 'bsdtar' if tool == 'xar' else 'xar'
    b64 = sorted(e['path'] for e in t['entries'] if e['base64'])
    links = {e['path']: (e['type'], e['link']) for e in t['entries'] if e['type'] == 'hardlink'}
    check(sorted(v[1] == 'original' for v in links.values()) == [False, True], f'{rel}: hard links {links}')
    want = {p: v for p, v in tree['files'].items()}
    note = (COMMON + f' {summary(t)}. Names stored in base64: ' + ', '.join(f'`{p}`' for p in b64) + '.')
    if tool == 'bsdtar':
        note += ' bsdtar marks every symlink\'s target `broken`.' + stray_note(t['toc_cksum'])
    note += (tool_note(f'{other} -x' if other == 'bsdtar' else 'xar -x', f[other], tree) or
             f' {other} -x extracts the same.')
    note += ' ' + seven_note(rel, want, t)
    record(rel, PRODUCER[tool], COMMANDS[n] + ' (in the tree, under a frozen clock and the stat shim)', 'xar',
           entries_of(tree), note, symlinks=len(tree['links']), hardlinks=1)

# tar.exe's: the Windows tree; xar and bsdtar in the container would extract the same, 7-Zip here.
win_tree = {'files': WIN_TREE, 'links': {}, 'empty': ['emptydir']}
for n, opts in TAREXE:
    rel = f'xar/{n}'
    check(tarexe_x(os.path.join(tp, rel)) == {p: key(v) for p, v in WIN_TREE.items()}, f'{rel}: tar.exe -x extracts something else')
    note = ('Entries are the files of an ASCII-only tree on NTFS (Windows\' bsdtar 3.8.9 crashes on any other name) with '
            'the same files as the others\' but for the links: hard-readme.txt is a hard link to readme.txt, as above. '
            'Each file\'s `mtime` is the time the TOC holds. Windows gives every run its own creation, change and access '
            'times and inode numbers, so those are fixed afterwards, and the TOC deflated again by Python\'s zlib (level 6, '
            'as tar.exe\'s, whose zlib packs it differently) with its checksum made again; the device number tar.exe '
            'writes is the volume\'s serial number taken as a signed number, which can be negative. tar.exe -x extracts '
            'the same files.' + stray_note(dict(TAREXE_CKSUM)[n]) + ' ' + seven_note(rel, WIN_TREE))
    record(rel, PRODUCER['tarexe'], f'tar.exe -c -f {n} --format xar ' + ' '.join(opts) + (' ' if opts else '') +
           '-C tree . (the TOC\'s times and inode numbers fixed afterwards, the TOC deflated again)', 'xar',
           entries_of(win_tree), note, symlinks=0, hardlinks=1)

# pkg -----------------------------------------------------------------------------------------
pk = facts['pkg']
def layout(base, payload=True):
    """A component as `pkgutil --expand-full` lays it out under `base`: its files, and Payload and
    Scripts as folders of what's in them."""
    files, links, empty = {}, {}, []
    for p, v in pk['component']['files'].items():
        if p not in ('Payload', 'Scripts'):
            files[base + p] = v
    for p, v in pk['root']['files'].items():
        files[f'{base}Payload/{p}'] = v
    for p, t in pk['root']['links'].items():
        links[f'{base}Payload/{p}'] = t
    empty += [f'{base}Payload/{p}' for p in pk['root']['empty']]
    for p, v in pk['scripts']['files'].items():
        files[f'{base}Scripts/{p}'] = v
    return {'files': files, 'links': links, 'empty': empty}

PKGS = {
    'component.pkg': ('a component package: Bom, PackageInfo, and Payload and Scripts as gzip\'d cpio (odc)', layout('')),
    'product.pkg': ('a product archive: Distribution, Resources/en.lproj/Welcome.txt and the component as the folder hello.pkg',
                    None),
    'pbzx.pkg': ('a component package whose Payload is pbzx (one xz chunk, Apple\'s 16 MiB chunk size) and whose Scripts is '
                 'gzip\'d cpio', None),
}
prod = layout('hello.pkg/')
prod['files']['Distribution'] = pk['product']['files']['Distribution']
prod['files']['Resources/en.lproj/Welcome.txt'] = pk['product']['files']['Resources/en.lproj/Welcome.txt']
PKGS['product.pkg'] = (PKGS['product.pkg'][0], prod)
pz = layout('')
for p in ('Bom', 'PackageInfo'):
    pz['files'][p] = pk['pbzx']['files'][p]
PKGS['pbzx.pkg'] = (PKGS['pbzx.pkg'][0], pz)
LAYOUT = ('Entries are the package as `pkgutil --expand-full` lays it out, which the container makes with xar -x and cpio -i: '
          'Payload and Scripts are folders of their cpio\'s contents (each entry under the folder without its leading `./`, '
          'the cpio\'s own `.` being the folder), the other files are as the XAR holds them. Files have no `mtime`.')
for n, (what, want) in PKGS.items():
    rel = f'pkg/{n}'
    f = facts['archives'][rel]
    got = f['expanded']
    for p, v in want['files'].items():
        v.pop('mtime', None)
    check({p: key(v) for p, v in got['files'].items()} == {p: key(v) for p, v in want['files'].items()},
          f'{rel}: expands to {sorted(got["files"])}, not {sorted(want["files"])}')
    check(got['links'] == want['links'], f'{rel}: links {got["links"]}')
    check(sorted(got['empty']) == sorted(want['empty']), f'{rel}: empty folders {got["empty"]}')
    kinds = ', '.join(f'{p} {k}' for p, k in sorted(got['kinds'].items()))
    t = f['toc']
    rc, seven = extract_7z(os.path.join(tp, rel))
    note = (f'{what[0].upper()}{what[1:]}. {LAYOUT} Payload and Scripts: {kinds}. The XAR\'s members: {summary(t)}. '
            f'7-Zip {seven_version} extracts ' + ', '.join(f'`{p}`' for p in sorted(seven)) + ': it doesn\'t expand a '
            'Payload or Scripts (a component package it opens as its Payload\'s gzip member), so it isn\'t the oracle '
            'for the layout.')
    entries = entries_of(want, mtimes=False)
    record(rel, f"{xar_ver}, mkbom (bomutils c247002) and GNU cpio {versions['cpio'].split('+')[0].split('-')[0]} (in Docker)",
           {'component.pkg': 'xar -c -f component.pkg --compression=gzip --no-compress=\'^(.*/)?(Payload|Scripts)$\' Bom PackageInfo Payload Scripts',
            'product.pkg': 'xar -c -f product.pkg --compression=gzip --no-compress=\'^(.*/)?(Payload|Scripts)$\' Distribution Resources hello.pkg',
            'pbzx.pkg': 'xar -c -f pbzx.pkg --compression=gzip --no-compress=\'^(.*/)?(Payload|Scripts)$\' Bom PackageInfo Payload Scripts'}[n]
           + ' (Payload and Scripts: find . | sort | cpio -o -H odc --owner 0:80 --renumber-inodes --ignore-devno, then gzip -9n '
           'or the pbzx writer; Bom: mkbom -u 0 -g 80 root Bom; under a frozen clock and the stat shim)',
           'pkg', entries, note, symlinks=len(want['links']), hardlinks=0)

if problems:
    raise SystemExit('\n'.join(problems))

# manifest.json: this script's records (xar/ and pkg/, but pkg/macos/, merge-pkg.py's) go where
# the first of them was.
mine = lambda r: r['file'].startswith(('xar/', 'pkg/')) and not r['file'].startswith('pkg/macos/')
path = os.path.join(here, 'manifest.json')
manifest = json.load(open(path, encoding='utf-8'))
old = manifest['fixtures']
at = next((i for i, r in enumerate(old) if mine(r)), len(old))
manifest['fixtures'] = old[:at] + records + [r for r in old[at:] if not mine(r)]
if 'make-xar.sh' not in manifest['note']:
    manifest['note'] = manifest['note'].replace('fetch-libarchive.ps1 and make-linux.sh',
                                                'fetch-libarchive.ps1, make-linux.sh, make-7z.sh, make-retro.sh and make-xar.sh')
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(manifest, indent=2, ensure_ascii=False))

# READMEs.
def size(n):
    return f'{n / 1024:.1f} KiB' if n >= 1024 else f'{n} B'
def table(prefix):
    rows = ['| File | Size | Made by | Command |', '|---|---|---|---|']
    for r in records:
        if r['file'].startswith(prefix):
            n = r['file'][len(prefix):]
            rows.append(f"| `{n}` | {size(os.path.getsize(os.path.join(tp, r['file'])))} | {r['producer']} | "
                        f"`{r['command'].split(' (')[0]}` |")
    return '\n'.join(rows)
HEAD = ('Made by `tests/fixtures/make-xar.sh` (docs/M6.md §10), in Docker (make-xar.Dockerfile) and with\n'
        'Windows\' own tar.exe, which also writes this file and the records in `manifest.json`; a rerun writes\n'
        'the same bytes.\n\n')
xar_readme = f'''# XAR fixtures

{HEAD}The tree: `readme.txt`, `empty.txt`, `text.txt`, `random.bin` (4 KiB of Python's Random(42)),
`mtime.txt`, `exec.sh` (0755), `sub/nested/deep.txt`, the empty folder `emptydir`,
`Ünïcödé/日本語.txt`, `bee-🐝.txt` and `café.txt` (both tools store the CJK and emoji names in
base64, the others as they are), the symlinks
`link-to-readme`, `dangling` (to `does/not/exist`) and `sub/link-to-nested` (to a folder), and
`hard-readme.txt`, a hard link to `readme.txt`; every time 2026-01-01T00:00:00Z but mtime.txt's,
2024-05-06T07:08:09Z. tar.exe's XARs hold the ASCII-only files and the hard link: bsdtar 3.8.9 for
Windows crashes on any other name, and Windows makes symlinks only in Developer Mode.

xar and bsdtar ran under a frozen clock and an LD_PRELOAD shim giving every stat() one device
number and change time; tar.exe's TOCs have their creation, change and access times and inode
numbers fixed afterwards. Between them the files cover every compression (none, gzip as x-gzip
and as RFC 6713's zlib, bzip2, xz, and lzma in both xar's xz-format and libarchive's .lzma-format
flavours) and every checksum (none, MD5, SHA-1, SHA-256 and SHA-512, the last two in xar's
64-byte header). 7-Zip {seven_version} reads XAR but not x-xz or x-lzma, shows base64 names undecoded,
extracts xar's hard links empty and calls a SHA-512 TOC a CRC error: each record's note says which
files it gets wrong.

{table('xar/')}
'''
pkg_readme = f'''# macOS package fixtures

Made by `tests/fixtures/make-xar.sh` (docs/M6.md §10) in Docker (make-xar.Dockerfile), without a
Mac, which also writes this file and the records in `manifest.json`; a rerun writes the same bytes.
`macos/` holds packages made by pkgbuild and productbuild on GitHub's macOS runner
(`.github/workflows/make-pkg.yml`, merged by `merge-pkg.py`, which owns those records).

Each package's Payload holds `usr/local/bin/hello` (0755), the symlink `usr/local/bin/hello-readme`
(to `../share/hello/README`), `usr/local/share/hello/README`, `usr/local/share/hello/Ünïcödé.txt`
and the empty folder `usr/local/share/hello/empty`; its Scripts `preinstall` and `postinstall`.
Payload and Scripts are cpio in odc format (`find . | sort | cpio -o -H odc --owner 0:80`), gzip'd
as pkgbuild writes them, or, in `pbzx.pkg`, the Payload pbzx: Apple's chunked xz (the magic, the
16 MiB chunk size, then per chunk its size, packed size and bytes), from a writer in the script.
The Bom is mkbom's (bomutils), PackageInfo and Distribution are written by hand; Bom, PackageInfo
and Distribution are stored gzip'd in the XAR, Payload and Scripts as they are, as Apple's tools
store them. The packages aren't signed.

BeeZip lists a package as `pkgutil --expand-full` lays it out: Payload and Scripts become folders
of their cpio's contents, everything else stays a file; a product archive's components are folders
expanded the same way. The records hold that layout, made in the container with xar -x and cpio -i.

{table('pkg/')}
'''
for d, text in (('xar', xar_readme), ('pkg', pkg_readme)):
    with open(os.path.join(tp, d, 'README.md'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
for r in records:
    print(f"{r['file']}: {len(r['entries'])} entries; 7z t {r['7z_test']}")
print(f'{len(records)} records')
PY
du -cb "$here/thirdparty/xar" "$here/thirdparty/pkg" | tail -n 1
