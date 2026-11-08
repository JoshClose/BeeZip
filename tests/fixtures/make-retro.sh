#!/bin/bash
# Makes tests/fixtures/thirdparty/arj/, zoo/ and arc/ (docs/M6.md §10) with the original tools,
# writes the records of those and of unarc-rs's samples in thirdparty/unarc/ (copied in by hand,
# left as they are), and merges them into manifest.json. Run it from Windows, in the repository,
# with Docker Desktop running, from Git Bash or WSL:
#
#   bash tests/fixtures/make-retro.sh
#
# The archives are made in a container (make-retro.Dockerfile, built here as
# beezip-fixtures-retro), which runs this script again with --inside. Tools (Debian packages,
# 2026-11-07): arj 3.10.22 (Debian 12's 3.10.22-26), arc 5.21q (Debian 12's 5.21q-12, built for
# i386: on amd64 it made only stored entries), zoo 2.10 (Debian 9's 2.10-28, the last Debian with
# it), unar and lsar 1.10.1 (Debian 12's unar 1.10.7+ds1+really1.10.1) and acefile 0.6.12 (Python)
# as oracles, libfaketime 0.9.10 for arj's archive times. Then, on Windows, 7-Zip 26.00 tests
# every file (`7z t`) and extracts the ARJ archives for a cross-check.
#
# The trees: text, an empty file, fixed pseudo-random bytes (Python's Random), a file two folders
# down and an empty folder, every time 2026-01-01T00:00:00Z but mtime.txt's, 2024-05-06T07:08:09Z;
# ARC's tree is flat, with DOS names, and data chosen so that arc picks each method. Everything is
# made on a tmpfs (so arj meets files in the same order every time), with arj under a frozen
# clock and its accessed and created times left out (-j$), and the bytes zoo leaves uninitialised
# zeroed, so a rerun writes the same bytes.
#
# Expected entries are the source trees' files, which the tool that made each archive must
# extract (`arj x`, `zoo x//`, `arc x`) and whose headers (read here by Python, independently of
# the tools) must name; ARC's data is also decoded here. unar must agree where it can (it reads
# only an ARJ set's first volume, flattens a Unix ARJ's folders, fails a squeezed entry whose end
# code is cut and crashes on some ARC archives: the records' notes say where). For unarc-rs's
# samples the expected bytes are what arj (with -v for volumes), zoo, arc and acefile extract,
# checked against each entry's CRC, against unar and against the ARC decoder here; unarc-rs's
# tests compare most of them with its LICENSE, the Apache-2.0 text, LICENSE-APACHE here.
set -euo pipefail

E=1767225600 # 2026-01-01T00:00:00Z

# ---------------------------------------------------------------------------------------------
# In the container (root): the archives, into /out/{arj,zoo,arc}; their facts, as /out/facts.json.
if [ "${1:-}" = --inside ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
    faked=(env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME='2026-01-01 00:00:00'
        NO_FAKE_STAT=1)
    out=/out
    mkdir -p "$out/arj" "$out/zoo" "$out/arc"
    W=/work
    cd "$W"

    # The trees. ARC's names are DOS names, and its data is chosen by what arc does with it:
    # TEXT.TXT crunches (squashes with q), RUNS.DAT crunches (packs with q: squashing doesn't
    # look for runs), SQZ.DAT and CUT.DAT are squeezed (arc 5.21q never writes a squeezed
    # stream's last partial byte: SQZ.DAT's end code happens to end on a byte, CUT.DAT's is cut
    # short), RANDOM.BIN and the small ones are stored.
    python3 -I - "$W" <<'PY'
import os, random, sys
w = sys.argv[1]
def put(path, data):
    path = os.path.join(w.encode(), path if isinstance(path, bytes) else path.encode())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
text = b''.join(b'line %d: the quick brown fox jumps over the lazy dog\n' % i for i in range(80))
for t in ('tree',):
    put(f'{t}/readme.txt', b'Hello, BeeZip!\n')
    put(f'{t}/empty.txt', b'')
    put(f'{t}/text.txt', text)
    put(f'{t}/random.bin', random.Random(42).randbytes(1024))
    put(f'{t}/mtime.txt', b'known mtime\n')
    put(f'{t}/sub/nested/deep.txt', b'deep\n')
os.makedirs(os.path.join(w, 'tree', 'emptydir'))
# A volume set of three: 21 000 bytes that don't compress, in volumes of 10 000 (ARJ's least).
put('vol/readme.txt', b'Hello, BeeZip!\n')
put('vol/random.bin', random.Random(7).randbytes(21000))
# Names in CP437, as an ARJ made on DOS holds them: café.txt and Ünïcödé/ñandú.txt.
put(b'names/caf\x82.txt', b'CP437 name\n')
put(b'names/\x9an\x8bc\x94d\x82/\xa4and\xa3.txt', b'CP437 folder\n')
r = random.Random(42)
put('arc/README.TXT', b'Hello, BeeZip!\n')
put('arc/EMPTY.TXT', b'')
put('arc/TEXT.TXT', text)
put('arc/RUNS.DAT', b''.join(bytes([r.randrange(256)]) * r.randrange(20, 60) for _ in range(40)))
put('arc/RANDOM.BIN', random.Random(42).randbytes(1024))
put('arc/SQZ.DAT', bytes(random.Random(8).choices(b'ABCDEFGH', k=2001)))
put('arc/CUT.DAT', bytes(random.Random(8).choices(b'ABCDEFGH', k=2000)))
PY
    find tree vol names arc -exec touch -h -d "@$E" {} +
    touch -d '2024-05-06 07:08:09 UTC' tree/mtime.txt

    # ARJ: every method, -jm, garbled, a volume set, DOS-compatible (-2d), CP437 names. -a1 adds
    # folders; -j$ leaves out the accessed and created times (the latter is the change time).
    arj() { "${faked[@]}" /usr/bin/arj "$@" >/dev/null; }
    (
        cd tree
        for m in 0 1 2 3 4; do arj a -r -a1 -j\$ -y -m$m "$out/arj/m$m.arj" '*'; done
        arj a -r -a1 -j\$ -y -jm "$out/arj/jm.arj" '*'
        arj a -r -a1 -j\$ -y -m1 -gbeezip "$out/arj/garbled.arj" '*'
        arj a -r -a1 -j\$ -y -m1 -2d "$out/arj/dos.arj" '*'
    )
    (cd vol && arj a -j\$ -y -m1 -v10000 "$out/arj/volumes.arj" readme.txt random.bin)
    (cd names && arj a -r -j\$ -y -m1 "$out/arj/names-cp437.arj" '*')

    # ZOO: stored (f), LZW (the default) and LH5 (h), the files named one by one.
    zfiles=(readme.txt empty.txt text.txt random.bin mtime.txt sub/nested/deep.txt)
    (
        cd tree
        zoo af "$out/zoo/stored.zoo" "${zfiles[@]}" >/dev/null
        zoo a "$out/zoo/lzw.zoo" "${zfiles[@]}" >/dev/null
        zoo ah "$out/zoo/lh5.zoo" "${zfiles[@]}" >/dev/null
    )
    # zoo leaves the bytes after the NUL of an entry's 13-byte short name uninitialised (stack
    # garbage, different every run): they're zeroed, and the entry's CRC-16 (of its bytes, the
    # CRC field zeroed) made again.
    python3 -I - "$out"/zoo/*.zoo <<'PY'
import struct, sys
def crc16(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc
for path in sys.argv[1:]:
    with open(path, 'r+b') as f:
        d = bytearray(f.read())
        pos = struct.unpack_from('<I', d, 24)[0]
        while True:
            nxt = struct.unpack_from('<I', d, pos + 6)[0]
            if nxt == 0:
                break
            name = pos + 38
            end = d.index(0, name, name + 13)
            d[end:name + 13] = bytes(name + 13 - end)
            vlen = struct.unpack_from('<H', d, pos + 51)[0]
            d[pos + 54:pos + 56] = b'\0\0'
            struct.pack_into('<H', d, pos + 54, crc16(d[pos:pos + 56 + vlen]))
            pos = nxt
        f.seek(0)
        f.write(d)
PY

    # ARC: arc shortens an archive's name to a DOS name, so they're made under short names.
    afiles=(README.TXT EMPTY.TXT TEXT.TXT RUNS.DAT SQZ.DAT RANDOM.BIN)
    (
        cd arc
        /usr/bin/arc a C.ARC "${afiles[@]}" >/dev/null
        /usr/bin/arc aq S.ARC "${afiles[@]}" >/dev/null
        /usr/bin/arc agBEEZIP G.ARC README.TXT TEXT.TXT >/dev/null
        /usr/bin/arc a X.ARC CUT.DAT >/dev/null
        mv C.ARC "$out/arc/crunched.arc"
        mv S.ARC "$out/arc/squashed.arc"
        mv G.ARC "$out/arc/garbled.arc"
        mv X.ARC "$out/arc/squeeze-cut.arc"
    )

    {
        dpkg-query -W -f '${Package} ${Version}\n' arj arc zoo unar libfaketime
        python3 -I -c 'import acefile, sys; print("acefile", acefile.__version__); print("python3", sys.version.split()[0])'
    } > "$out/versions.txt"

    # The facts: the source trees, each archive's headers (read here), what the tool that made
    # it, unar and (for ARC) the decoder here extract, and what the tools' own tests say.
    python3 -I -B - "$W" "$out" /unarc <<'PY'
import datetime, hashlib, json, os, struct, subprocess, sys, tempfile, zlib
work, out, unarc = sys.argv[1:4]

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def rfc3339(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000000000Z')

def files_under(root, start=None):
    """Every file under root: its path (bytes, relative to start), size and SHA-256."""
    start = start or root
    got = {}
    for dp, dns, fns in os.walk(root.encode()):
        for n in fns:
            p = os.path.join(dp, n)
            with open(p, 'rb') as f:
                d = f.read()
            got[os.path.relpath(p, start.encode()).decode('latin-1')] = {'size': len(d), 'sha256': sha256(d)}
    return got

def tree(root):
    """The source tree: files (with times) and empty folders, paths as latin-1 of the bytes."""
    files, empty = {}, []
    for dp, dns, fns in os.walk(root.encode()):
        rel = os.path.relpath(dp, root.encode())
        if not dns and not fns and rel != b'.':
            empty.append(rel.decode('latin-1'))
        for n in fns:
            p = os.path.join(dp, n)
            with open(p, 'rb') as f:
                d = f.read()
            files[os.path.relpath(p, root.encode()).decode('latin-1')] = {
                'size': len(d), 'sha256': sha256(d), 'mtime': int(os.stat(p).st_mtime)}
    return {'files': files, 'empty': sorted(empty)}

def run(cmd, cwd=None, inp=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, input=inp, timeout=120)
    return p.returncode, (p.stdout + p.stderr).decode('utf-8', 'replace')

# ARJ headers -----------------------------------------------------------------------------------
HOSTS = {0: 'MS-DOS', 2: 'UNIX', 10: 'WIN95', 11: 'WIN32'}

def dos_time(v):
    return (((v >> 25) & 0x7F) + 1980, (v >> 21) & 0x0F, (v >> 16) & 0x1F, (v >> 11) & 0x1F, (v >> 5) & 0x3F, (v & 0x1F) * 2)

def arj_headers(data):
    """The main header and each entry's: name bytes, host, flags, method, type, time, sizes, CRC."""
    pos = data.index(b'\x60\xea')
    out, first = [], True
    while True:
        if data[pos:pos + 2] != b'\x60\xea':
            raise SystemExit(f'ARJ: no header at {pos}')
        size = struct.unpack_from('<H', data, pos + 2)[0]
        if size == 0:
            return out
        basic = data[pos + 4:pos + 4 + size]
        if zlib.crc32(basic) != struct.unpack_from('<I', data, pos + 4 + size)[0]:
            raise SystemExit(f'ARJ: header CRC at {pos}')
        pos += 8 + size
        while True:
            n = struct.unpack_from('<H', data, pos)[0]
            pos += 2
            if n == 0:
                break
            pos += n + 4
        ver, minver, host, flags, method, ftype, mod, dt, packed, osize, crc = struct.unpack_from('<BBBBBBBIIII', basic, 1)
        name = basic[basic[0]:].split(b'\0', 1)[0]
        h = {'name': name.decode('latin-1'), 'host': HOSTS.get(host, str(host)), 'flags': flags, 'method': method,
             'type': ftype, 'dt': dt, 'packed': packed, 'size': osize, 'crc32': crc}
        if host == 2:
            h['unix_time'] = dt
        else:
            h['dos_time'] = dos_time(dt)
        out.append(h)
        if not first:
            pos += packed
        first = False

# ZOO headers -----------------------------------------------------------------------------------
def zoo_headers(data):
    tag, start = struct.unpack_from('<II', data, 20)
    if tag != 0xFDC4A7DC:
        raise SystemExit('ZOO: no tag')
    out, pos, seen = [], start, set()
    while True:
        if pos in seen:
            raise SystemExit('ZOO: loop')
        seen.add(pos)
        (tag, typ, method, nxt, offset, date, time, crc, org, now, maj, mnr, deleted, struc, cmt, cmtsize,
         fname) = struct.unpack_from('<IBBIIHHHIIBBBBIH13s', data, pos)
        if tag != 0xFDC4A7DC:
            raise SystemExit(f'ZOO: no tag at {pos}')
        if nxt == 0:
            return out
        e = {'method': method, 'size': org, 'packed': now, 'crc16': crc, 'deleted': deleted,
             'dos_time': dos_time(date << 16 | time), 'tz': None, 'fname': fname.split(b'\0', 1)[0], 'lfname': b'', 'dirname': b''}
        if typ == 2:
            vlen, e['tz'] = struct.unpack_from('<HB', data, pos + 51)
            p = pos + 56
            if vlen:
                nl, dl = data[p], data[p + 1]
                e['lfname'] = data[p + 2:p + 2 + nl].split(b'\0', 1)[0]
                e['dirname'] = data[p + 2 + nl:p + 2 + nl + dl].split(b'\0', 1)[0]
        name = e['lfname'] or e['fname']
        e['path'] = (e['dirname'] + b'/' + name if e['dirname'] else name).decode('latin-1')
        for k in ('fname', 'lfname', 'dirname'):
            e[k] = e[k].decode('latin-1')
        out.append(e)
        pos = nxt

# ARC: headers and an independent decoder (stored, packed, squeezed, crunched, squashed) ---------
class Corrupt(Exception):
    pass

def crc16(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

def unrle90(data):
    # DLE n repeats the last byte n-1 more times; DLE 0 is a DLE, which a later run doesn't repeat.
    out, last, i = bytearray(), 0, 0
    while i < len(data):
        b = data[i]
        i += 1
        if b != 0x90:
            out.append(b)
            last = b
            continue
        if i >= len(data):
            raise Corrupt('DLE at the end')
        n = data[i]
        i += 1
        out += b'\x90' if n == 0 else bytes([last]) * (n - 1)
    return bytes(out)

def unsqueeze(data):
    """The symbols before the end code, and whether the end code was there whole."""
    n = struct.unpack_from('<h', data, 0)[0]
    if not 0 <= n <= 256 or 2 + 4 * n > len(data):
        raise Corrupt(f'{n} nodes')
    nodes = [struct.unpack_from('<hh', data, 2 + 4 * k) for k in range(n)]
    bits, out, p = data[2 + 4 * n:], bytearray(), 0
    if n == 0:
        return bytes(out), True
    while True:
        node = 0
        while node >= 0:
            if p >= len(bits) * 8:
                return bytes(out), False
            if node >= n:
                raise Corrupt('node past the table')
            node = nodes[node][(bits[p >> 3] >> (p & 7)) & 1]
            p += 1
        if -(node + 1) == 256:
            return bytes(out), True
        out.append(-(node + 1))

def unlzw(data, maxbits):
    """compress's LZW: 9 bits up to maxbits, CLEAR = 256, codes in groups of eight that a width
    change or a CLEAR skips to the end of."""
    total, maxmax = len(data) * 8, 1 << maxbits
    n_bits, free_ent, oldcode, finchar = 9, 257, -1, 0
    maxcode = (1 << n_bits) - 1
    prefix, suffix, out = {}, {}, bytearray()
    seg = p = 0
    def align(p, seg, n):
        g = n * 8
        p = seg + (p - seg + g - 1) // g * g
        return p, p
    while p + n_bits <= total:
        if free_ent > maxcode:
            p, seg = align(p, seg, n_bits)
            n_bits += 1
            maxcode = maxmax if n_bits == maxbits else (1 << n_bits) - 1
            continue
        code = 0
        for k in range(n_bits):
            code |= ((data[(p + k) >> 3] >> ((p + k) & 7)) & 1) << k
        p += n_bits
        if oldcode == -1:
            if code >= 256:
                raise Corrupt('first code')
            finchar = oldcode = code
            out.append(code)
            continue
        if code == 256:
            prefix.clear()
            suffix.clear()
            free_ent = 256
            p, seg = align(p, seg, n_bits)
            n_bits, maxcode = 9, 511
            continue
        incode, stack = code, bytearray()
        if code >= free_ent:
            if code > free_ent:
                raise Corrupt('code past the table')
            stack.append(finchar)
            code = oldcode
        while code >= 256:
            stack.append(suffix[code])
            code = prefix[code]
        finchar = code
        stack.append(code)
        out += stack[::-1]
        if free_ent < maxmax:
            prefix[free_ent], suffix[free_ent] = oldcode, finchar
            free_ent += 1
        oldcode = incode
    return bytes(out)

ARC_METHODS = {1: 'stored (old)', 2: 'stored', 3: 'packed', 4: 'squeezed', 8: 'crunched', 9: 'squashed',
               10: 'crushed', 11: 'distilled'}

def arc_entries(data, password=None):
    out, pos = [], 0
    while True:
        if data[pos] != 0x1A:
            raise SystemExit(f'ARC: no marker at {pos}')
        method = data[pos + 1]
        if method == 0:
            return out
        if method == 1:
            name, packed, date, time, crc = struct.unpack_from('<13sIHHH', data, pos + 2)
            size, pos = packed, pos + 27
        else:
            name, packed, date, time, crc, size = struct.unpack_from('<13sIHHHI', data, pos + 2)
            pos += 29
        raw = data[pos:pos + packed]
        pos += packed
        if password:
            raw = bytes(b ^ password.encode()[k % len(password)] for k, b in enumerate(raw))
        e = {'path': name.split(b'\0', 1)[0].decode('latin-1'), 'method': ARC_METHODS.get(method, str(method)),
             'packed': packed, 'size': size, 'crc16': crc, 'dos_time': dos_time(date << 16 | time)}
        try:
            whole = True
            if method in (1, 2):
                d = raw
            elif method == 3:
                d = unrle90(raw)
            elif method == 4:
                sym, whole = unsqueeze(raw)
                d = unrle90(sym)
            elif method == 8:
                if raw[:1] != b'\x0c':
                    raise Corrupt('not 12 bits')
                d = unrle90(unlzw(raw[1:], 12))
            elif method == 9:
                d = unlzw(raw, 13)
            else:
                raise Corrupt('a method this decoder leaves out')
            e['decoded'] = {'size': len(d), 'sha256': sha256(d), 'crc_ok': crc16(d) == crc and len(d) == size,
                            'end_code': whole}
        except Corrupt as x:
            e['decoded'] = {'error': str(x)}
        out.append(e)

# Extraction by the tools ---------------------------------------------------------------------
def extract(kind, path, password=None):
    """What the tool that reads `kind` extracts: (exit code, its message, files). ZOO and ARC write
    where a name says, so they extract two folders down and paths are relative to that."""
    d = tempfile.mkdtemp()
    x = os.path.join(d, 'a', 'b')
    os.makedirs(x)
    if kind == 'arj':
        cmd = ['arj', 'x', '-y', '-v'] + ([f'-g{password}'] if password else []) + [path, x + '/']
        rc, msg = run(cmd)
    elif kind == 'zoo':
        rc, msg = run(['zoo', 'x//O', path], cwd=x)
    elif kind == 'arc':
        rc, msg = run(['arc', 'xo' + (f'g{password}' if password else ''), path], cwd=x)
    files = files_under(d, x)
    subprocess.run(['rm', '-rf', d])
    return rc, msg.strip().splitlines()[-1] if msg.strip() else '', files

def tool_test(kind, path, password=None):
    if kind == 'arj':
        rc, msg = run(['arj', 't', '-y', '-v'] + ([f'-g{password}'] if password else []) + [path])
    elif kind == 'zoo':
        rc, msg = run(['zoo', 'xN', path])
    elif kind == 'arc':
        rc, msg = run(['arc', 't' + (f'g{password}' if password else ''), path])
    lines = [l.strip() for l in msg.splitlines() if l.strip()]
    return {'exit': rc, 'last': lines[-1] if lines else ''}

def unar(path, password=None):
    """unar's extraction. It crashes on some ARC archives, and not every time, so it runs five
    times: the files are from a run that didn't crash, if one didn't."""
    runs = []
    for _ in range(5):
        d = tempfile.mkdtemp()
        try:
            rc, msg = run(['unar', '-q', '-f', '-D', '-o', d] + (['-p', password] if password else []) + [path])
        except subprocess.TimeoutExpired:
            rc, msg = 'timeout', ''
        runs.append({'exit': rc, 'files': files_under(d), 'failed': [l.strip() for l in msg.splitlines() if 'Failed' in l]})
        subprocess.run(['rm', '-rf', d])
    crashed = [r for r in runs if isinstance(r['exit'], int) and r['exit'] < 0]
    best = next((r for r in runs if r not in crashed), runs[-1])
    best['crashed'] = -crashed[0]['exit'] if crashed else None
    return best

def ace(path):
    import acefile
    out = []
    with acefile.open(path) as a:
        for m in a.getmembers():
            e = {'path': m.filename, 'size': m.size, 'dir': m.is_dir(), 'dos_time': list(m.datetime.timetuple()[:6]),
                 'comptype': m.comptype, 'compqual': m.compqual}
            if not m.is_dir():
                d = a.read(m)
                e.update(sha256=sha256(d), read=len(d), test=a.test(m))
            out.append(e)
        info = {'solid': a.is_solid(), 'multivolume': a.is_multivolume(), 'volumes': a.volumes_loaded,
                'cversion': a.cversion, 'platform': a.platform}
    return {'entries': out, 'info': info}

facts = {'trees': {t: tree(os.path.join(work, t)) for t in ('tree', 'vol', 'names', 'arc')}, 'archives': {}}
def gather(rel, kind, path, password=None):
    with open(path, 'rb') as f:
        data = f.read()
    f = {'kind': kind, 'size': len(data)}
    if kind == 'arj':
        hs = arj_headers(data)
        f['main'], f['headers'] = hs[0], hs[1:]
    elif kind == 'zoo':
        f['headers'] = zoo_headers(data)
    elif kind == 'arc':
        f['headers'] = arc_entries(data, password)
    if kind == 'ace':
        f['acefile'] = ace(path)
    else:
        rc, last, files = extract(kind, path, password)
        f['tool'] = {'exit': rc, 'last': last, 'files': files}
        f['tool_test'] = tool_test(kind, path, password)
        f['unar'] = unar(path, password)
    facts['archives'][rel] = f

PASSWORDS = {'arj/garbled.arj': 'beezip', 'arc/garbled.arc': 'BEEZIP',
             'unarc/arj/license_crypted.arj': 'secret', 'unarc/arc/license_cypted.arc': 'SECRET'}
for kind in ('arj', 'zoo', 'arc'):
    for n in sorted(os.listdir(os.path.join(out, kind))):
        if n.endswith('.' + kind):
            gather(f'{kind}/{n}', kind, os.path.join(out, kind, n), PASSWORDS.get(f'{kind}/{n}'))
for kind in ('arj', 'ace', 'zoo', 'arc', 'broken'):
    for n in sorted(os.listdir(os.path.join(unarc, kind))):
        ext = n.rsplit('.', 1)[-1].lower()
        k = {'pak': 'arc'}.get(ext, ext)
        if k in ('arj', 'ace', 'zoo', 'arc'):
            gather(f'unarc/{kind}/{n}', k, os.path.join(unarc, kind, n), PASSWORDS.get(f'unarc/{kind}/{n}'))
with open(os.path.join(out, 'facts.json'), 'w', encoding='utf-8') as f:
    json.dump(facts, f, indent=1, ensure_ascii=False)
PY
    exit 0
fi

# ---------------------------------------------------------------------------------------------
# On Windows (Git Bash or WSL): the container, the copies, 7-Zip, the records and the READMEs.
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

work="$repo/target/make-retro"
rm -rf "$work"
mkdir -p "$work/made"
docker build -q -t beezip-fixtures-retro - < "$here/make-retro.Dockerfile" >/dev/null
docker run --rm --tmpfs /work -v "$(hostpath "$here/make-retro.sh"):/make-retro.sh:ro" \
    -v "$(hostpath "$here/thirdparty/unarc"):/unarc:ro" -v "$(hostpath "$work/made"):/out" \
    beezip-fixtures-retro bash /make-retro.sh --inside

for d in arj zoo arc; do
    rm -rf "${here:?}/thirdparty/$d"
    mkdir -p "$here/thirdparty/$d"
    cp "$work/made/$d"/* "$here/thirdparty/$d/"
done

"$py" -I -B - "$(hostpath "$here")" "$(hostpath "$work")" <<'PY'
import datetime, hashlib, json, os, re, shutil, subprocess, sys, tempfile
here, work = sys.argv[1:3]
tp = os.path.join(here, 'thirdparty')
facts = json.load(open(os.path.join(work, 'made', 'facts.json'), encoding='utf-8'))
trees = facts['trees']
versions = dict(l.split(' ', 1) for l in open(os.path.join(work, 'made', 'versions.txt'), encoding='utf-8').read().splitlines())

if os.name == 'nt':
    SEVEN = r'C:\Program Files\7-Zip\7z.exe'
    def wpath(p):
        return os.path.abspath(p)
else:
    SEVEN = '/mnt/c/Program Files/7-Zip/7z.exe'
    def wpath(p):
        return subprocess.run(['wslpath', '-w', p], check=True, capture_output=True, text=True).stdout.strip()
if not os.path.exists(SEVEN):
    raise SystemExit(f'no 7-Zip at {SEVEN}')
seven_version = re.search(r'7-Zip (?:\(\w\) )?([\d.]+)', subprocess.run([SEVEN], capture_output=True).stdout.decode('utf-8', 'replace')).group(1)

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def test_7z(path):
    """What `7z t` said, as make-7z.sh records it."""
    w = wpath(path)
    p = subprocess.run([SEVEN, 't', '-sccUTF-8', w], capture_output=True)
    lines = [l.strip() for l in (p.stdout + p.stderr).decode('utf-8', 'replace').splitlines()]
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
    """The files `7z x` writes, and its exit code."""
    d = tempfile.mkdtemp(dir=work)
    p = subprocess.run([SEVEN, 'x', '-y', '-bso0', '-bsp0', '-o' + wpath(d), '--', wpath(path)], capture_output=True)
    got = {}
    for dp, dns, fns in os.walk(d):
        for n in fns:
            with open(os.path.join(dp, n), 'rb') as f:
                data = f.read()
            got[os.path.relpath(os.path.join(dp, n), d).replace(os.sep, '/')] = {'size': len(data), 'sha256': sha256(data)}
    shutil.rmtree(d)
    return p.returncode, got

def rfc3339(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000000000Z')

def as_dos(t):
    """A Unix time read as an MS-DOS one, as 7-Zip 26.00 reads a Unix-host ARJ's times."""
    y, mo, d, h, mi, s = ((t >> 25) & 0x7F) + 1980, (t >> 21) & 0x0F, (t >> 16) & 0x1F, (t >> 11) & 0x1F, (t >> 5) & 0x3F, (t & 0x1F) * 2
    return f'{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}'

def ver(pkg):
    return re.match(r'(?:\d+:)?(\d+(?:\.\d+)*[a-z]?)', versions[pkg]).group(1)

PRODUCER = {
    'arj': f"ARJ {ver('arj')} (Debian 12's arj {versions['arj']}, in Docker)",
    'zoo': f"zoo {ver('zoo')} (Debian 9's zoo {versions['zoo']}, in Docker)",
    'arc': f"ARC {ver('arc')} (Debian 12's arc:i386 {versions['arc']}, in Docker)",
}
UNAR = f"unar {versions['unar'].split('really')[-1].split('-')[0]}"

def norm(p):
    p = p.replace('\\', '/')
    while p.startswith('./'):
        p = p[2:]
    return p

def file_entry(path, info, mtime=None):
    e = {'path': path, 'kind': 'file', 'size': info['size'], 'sha256': info['sha256']}
    if mtime is not None:
        e['mtime'] = rfc3339(mtime)
    return e

def same(a, b):
    return {k: (v['size'], v['sha256']) for k, v in a.items()} == {k: (v['size'], v['sha256']) for k, v in b.items()}

records, problems = [], []
def check(cond, msg):
    if not cond:
        problems.append(msg)

def record(rel, producer, command, chain, entries, note, password=None, parts=(), encoding=None, utc=False):
    r = {'file': rel, 'producer': producer, 'command': command, 'chain': chain, 'password': password,
         'utc_mtimes': utc, 'hardlinks': 0, 'symlinks': 0}
    if parts:
        r['parts'] = list(parts)
    if encoding:
        r['encoding'] = encoding
    r['note'] = note
    r['7z_test'] = test_7z(os.path.join(tp, rel))
    r['entries'] = entries
    records.append(r)
    return r

def unar_note(f, want, show=lambda p: p):
    """What unar made of the expected files, for a note: the same, other names, failures, a crash.
    Paths here are latin-1 of a name's bytes; `show` turns an expected one into its name, and
    unar writes UTF-8."""
    u = f['unar']
    got = {norm(k): v for k, v in u['files'].items()}
    key = lambda v: (v['size'], v['sha256'])
    renamed, failed = [], []
    for p, v in sorted(want.items()):
        if p in got and key(got[p]) == key(v):
            continue
        other = [q for q, w in got.items() if key(w) == key(v) and q not in want]
        if other:
            renamed.append(f'`{show(p)}` as `{other[0].encode("latin-1").decode("utf-8", "replace")}`')
        else:
            failed.append(f'`{show(p)}`')
    crash = f' It crashes on it in some runs (signal {u["crashed"]}).' if u['crashed'] else ''
    if not renamed and not failed and u['exit'] == 0:
        return f'{UNAR} extracts the same.{crash}'
    said = []
    if renamed:
        said.append('names ' + ', '.join(renamed))
    if failed:
        said.append('fails ' + ', '.join(failed))
    if u['exit'] != 0 and not failed and not u['crashed']:
        said.append(f'exits {u["exit"]}')
    rest = '; the rest it extracts the same.' if len(failed) + len(renamed) < len(want) else '.'
    return f'{UNAR} ' + ' and '.join(said) + rest + crash

# ARJ -----------------------------------------------------------------------------------------
TIMES = ' utc_mtimes is false: mtime.txt is 2024-05-06T07:08:09Z, every other file 2026-01-01T00:00:00Z.'
def arj_unix_note():
    return (f' A Unix-host ARJ holds Unix times, and each file\'s `mtime` is that; 7-Zip {seven_version} reads them as MS-DOS '
            f'times (2026-01-01T00:00:00Z as {as_dos(1767225600)}, 2024-05-06T07:08:09Z as {as_dos(1714979289)}), as '
            'unarc-rs 0.8.1 does; unar and arj read them right.')

def arj_mine(name, command, src, note='', password=None, parts=(), encoding=None, host='UNIX', check7z=True):
    rel = f'arj/{name}'
    f = facts['archives'][rel]
    t = trees[src]
    want = {norm(k): v for k, v in t['files'].items()}
    # The headers name every file and folder, with the right host, sizes and CRCs.
    files = [h for h in f['headers'] if h['type'] != 3]
    dirs = {h['name'] for h in f['headers'] if h['type'] == 3}
    if parts:
        # A file split over volumes has a header in each; the first holds its start.
        files = [h for h in files if not h['flags'] & 0x08]
    check(sorted(h['name'] for h in files) == sorted(want), f'{rel}: headers name {[h["name"] for h in files]}')
    check(all(h['host'] == host for h in f['headers']), f'{rel}: hosts {[h["host"] for h in f["headers"]]}')
    tool = {norm(k): v for k, v in f['tool']['files'].items()}
    check(same(tool, want), f'{rel}: arj x extracts {tool}')
    check(f['tool_test']['exit'] == 0, f'{rel}: arj t says {f["tool_test"]}')
    entries = []
    for k in sorted(want, key=lambda p: (p.count('/'), p)):
        mtime = t['files'][k]['mtime'] if host == 'UNIX' else None
        if host == 'UNIX':
            h = next(h for h in files if h['name'] == k)
            check(h['unix_time'] == mtime, f'{rel}: {k} holds {h["unix_time"]}')
        enc = k.encode('latin-1').decode(encoding) if encoding else k
        entries.append(file_entry(enc, want[k], mtime))
    for d in t['empty']:
        check(d in dirs, f'{rel}: no folder {d}')
        entries.append({'path': d, 'kind': 'folder'})
    notes = []
    if check7z:
        rc, got = extract_7z(os.path.join(tp, rel))
        if encoding:
            got = {k: v for k, v in got.items()}
        if rc == 0 and same(got, {k.encode('latin-1').decode(encoding) if encoding else k: v for k, v in want.items()}):
            notes.append(f'7-Zip {seven_version} extracts the same.')
        elif encoding:
            notes.append(f'7-Zip {seven_version} extracts the same bytes, under names decoded in this machine\'s code page.')
        else:
            notes.append(f'7-Zip {seven_version}\'s `7z x` exits {rc} and extracts {len(got)} files.')
    notes.append(unar_note(f, want, (lambda p: p.encode('latin-1').decode(encoding)) if encoding else (lambda p: p)))
    times = (arj_unix_note() + (TIMES if src == 'tree' else '')) if host == 'UNIX' else ''
    lead = ('Entries are the source tree\'s files, which arj itself extracts and whose headers name them' +
            ('; an empty folder is an entry of kind `folder`.' if t['empty'] else '.'))
    record(rel, PRODUCER['arj'], command + ' (in the tree, under a frozen clock)', 'arj', entries,
           ' '.join([lead + times + note] + notes).strip(), password, [f'arj/{p}' for p in parts], encoding)

A = 'arj a -r -a1 -j$ -y'
for m in range(5):
    arj_mine(f'm{m}.arj', f'{A} -m{m} m{m}.arj *', 'tree', f' Method {m}' + (' (stored).' if m == 0 else '.'))
arj_mine('jm.arj', f'{A} -jm jm.arj *', 'tree', ' Method 1 with -jm, maximum compression.')
arj_mine('garbled.arj', f'{A} -m1 -gbeezip garbled.arj *', 'tree',
         ' Garbled with the password `beezip` (method 1, every byte XORed with the password and a modifier).',
         password='beezip', check7z=False)
facts_g = facts['archives']['arj/garbled.arj']
check(all(h['flags'] & 1 for h in facts_g['headers']), 'arj/garbled.arj: not every entry is garbled')
records[-1]['note'] += f' 7-Zip {seven_version} reads its listing but not its data (Unsupported Method).'
arj_mine('dos.arj', f'{A} -m1 -2d dos.arj *', 'tree',
         ' Made with -2d, ARJ/DOS compatibility: the host is MS-DOS and times are MS-DOS times (local times: the '
         'container ran in UTC), which depend on the reader\'s time zone, so files have no `mtime`.', host='MS-DOS')
vparts = sorted(p for p in os.listdir(os.path.join(tp, 'arj')) if re.fullmatch(r'volumes\.a\d\d', p))
check(vparts == ['volumes.a01', 'volumes.a02'], f'arj/volumes: parts {vparts}')
arj_mine('volumes.arj', 'arj a -j$ -y -m1 -v10000 volumes.arj readme.txt random.bin', 'vol',
         ' A volume set of three (volumes of 10 000 bytes, the least ARJ makes): random.bin starts in volumes.arj, fills '
         'volumes.a01 and ends in volumes.a02. arj x -v extracts it whole.', parts=vparts, check7z=False)
records[-1]['note'] = records[-1]['note'].replace(f'{UNAR} fails `random.bin`; the rest it extracts the same.',
                                                  f'{UNAR} and 7-Zip {seven_version} read only volumes.arj: random.bin\'s first part.')
arj_mine('names-cp437.arj', 'arj a -r -j$ -y -m1 names-cp437.arj *', 'names',
         ' The names are CP437 bytes, as ARJ on DOS stores them (arj on Linux stores a name\'s bytes as they are): '
         'café.txt and Ünïcödé/ñandú.txt, so `encoding` is cp437. Without -a1 the folder isn\'t an entry of its own.',
         encoding='cp437')

# ZOO -----------------------------------------------------------------------------------------
ZOO_TIMES = (' ZOO holds MS-DOS times (local times: the container ran in UTC, and zoo wrote a time zone field of '
             '{tz}), so files have no `mtime`; mtime.txt is 2024-05-06T07:08:09Z, every other file 2026-01-01T00:00:00Z.')
ZOO_METHODS = {0: 'stored', 1: 'LZW', 2: 'LH5'}
for name, cmd, method in [('stored.zoo', 'zoo af', 0), ('lzw.zoo', 'zoo a', 1), ('lh5.zoo', 'zoo ah', 2)]:
    rel = f'zoo/{name}'
    f = facts['archives'][rel]
    t = trees['tree']
    want = {k: v for k, v in t['files'].items()}
    hs = f['headers']
    check(sorted(norm(h['path']) for h in hs) == sorted(want), f'{rel}: headers name {[h["path"] for h in hs]}')
    used = {h['path']: ZOO_METHODS[h['method']] for h in hs}
    check(used['text.txt'] == ZOO_METHODS[method] and set(used.values()) <= {'stored', ZOO_METHODS[method]}, f'{rel}: methods {used}')
    tool = {norm(k): v for k, v in f['tool']['files'].items()}
    check(same(tool, want), f'{rel}: zoo x extracts {tool}')
    entries = [file_entry(k, want[k]) for k in sorted(want, key=lambda p: (p.count('/'), p))]
    tzs = sorted({str(h['tz']) for h in hs})
    note = ('Entries are the source tree\'s files, which zoo itself extracts and whose headers name them (ZOO stores no '
            'folders). ' + ', '.join(f'{p} {m}' for p, m in sorted(used.items())) + (': zoo stores what doesn\'t shrink.' if method else '.') +
            ZOO_TIMES.format(tz=', '.join(tzs)) + ' ' + unar_note(f, want) + f' 7-Zip {seven_version} doesn\'t read ZOO.')
    record(rel, PRODUCER['zoo'], f'{cmd} {name} readme.txt empty.txt text.txt random.bin mtime.txt sub/nested/deep.txt '
           '(in the tree; the uninitialised bytes after each short name\'s NUL zeroed afterwards, with the entry\'s CRC)',
           'zoo', entries, note)

# ARC -----------------------------------------------------------------------------------------
ARC_TIMES = ' ARC holds MS-DOS times (local times: the container ran in UTC), so files have no `mtime`.'
def arc_mine(name, cmd, files, methods, note, password=None):
    rel = f'arc/{name}'
    f = facts['archives'][rel]
    t = trees['arc']
    want = {k: t['files'][k] for k in files}
    hs = f['headers']
    check([h['path'] for h in hs] == sorted(files), f'{rel}: headers name {[h["path"] for h in hs]}')
    got_methods = {h['path']: h['method'] for h in hs}
    check(got_methods == methods, f'{rel}: methods {got_methods}')
    for h in hs:
        d = h['decoded']
        check(d.get('crc_ok') and (d['size'], d['sha256']) == (want[h['path']]['size'], want[h['path']]['sha256']),
              f'{rel}: the decoder here reads {h["path"]} as {d}')
    tool = {norm(k): v for k, v in f['tool']['files'].items()}
    check(same(tool, want), f'{rel}: arc x extracts {tool}')
    check(f['tool_test']['exit'] == 0 and 'No errors' in f['tool_test']['last'], f'{rel}: arc t says {f["tool_test"]}')
    listed = ', '.join(f'{p} {m}' for p, m in sorted(got_methods.items()))
    entries = [file_entry(k, want[k]) for k in sorted(want)]
    lead = (f'Entries are the source files, which arc itself extracts (and tests) and the ARC decoder in make-retro.sh '
            f'reads, each matching its CRC-16: {listed}.')
    record(rel, PRODUCER['arc'], cmd + ' (in the folder, under a short name: arc shortens an archive\'s name to a DOS '
           'name)', 'arc', entries, ' '.join([lead + note + ARC_TIMES, unar_note(f, want), f'7-Zip {seven_version} doesn\'t read ARC.']),
           password)
    return hs

AF = ['README.TXT', 'EMPTY.TXT', 'TEXT.TXT', 'RUNS.DAT', 'SQZ.DAT', 'RANDOM.BIN']
hs = arc_mine('crunched.arc', 'arc a crunched.arc ' + ' '.join(AF), AF,
              {'README.TXT': 'stored', 'EMPTY.TXT': 'stored', 'TEXT.TXT': 'crunched', 'RUNS.DAT': 'crunched',
               'SQZ.DAT': 'squeezed', 'RANDOM.BIN': 'stored'},
              ' arc picks each file\'s method by what packs smallest: crunching (LZW after RLE) unless squeezing (Huffman '
              'after RLE) wins. arc 5.21q never writes a squeezed stream\'s last partial byte; SQZ.DAT\'s end code '
              'ends on a byte, so it\'s whole.')
check(all(h['decoded'].get('end_code') for h in hs), 'arc/crunched.arc: an end code is cut')
arc_mine('squashed.arc', 'arc aq squashed.arc ' + ' '.join(AF), AF,
         {'README.TXT': 'stored', 'EMPTY.TXT': 'stored', 'TEXT.TXT': 'squashed', 'RUNS.DAT': 'packed',
          'SQZ.DAT': 'squeezed', 'RANDOM.BIN': 'stored'},
         ' q squashes (13-bit LZW, no RLE) instead of crunching, so runs pack (RLE alone) better.')
arc_mine('garbled.arc', 'arc agBEEZIP garbled.arc README.TXT TEXT.TXT', ['README.TXT', 'TEXT.TXT'],
         {'README.TXT': 'stored', 'TEXT.TXT': 'crunched'},
         ' Encrypted with the password `BEEZIP`: every entry\'s data XORed with it, with nothing in the headers to say '
         'so. arc upper-cases a password, as ARC on DOS did: `arc agbeezip` encrypts with BEEZIP too.',
         password='BEEZIP')
hs = arc_mine('squeeze-cut.arc', 'arc a squeeze-cut.arc CUT.DAT', ['CUT.DAT'], {'CUT.DAT': 'squeezed'},
              ' arc 5.21q never writes a squeezed stream\'s last partial byte, so CUT.DAT\'s end code is cut short: '
              'every byte of the data is there and matches the CRC, and arc reads it, stopping at the end of the '
              'entry. A reader that stops at the entry\'s size, or at its end, reads it.')
check(not hs[0]['decoded'].get('end_code'), 'arc/squeeze-cut.arc: the end code is whole')

# unarc-rs's samples --------------------------------------------------------------------------
LICENSE = {'size': 11357, 'sha256': sha256(open(os.path.join(tp, 'unarc', 'LICENSE-APACHE'), 'rb').read())}
UNARC_PRODUCER = 'from unarc-rs 0.8.1\'s tests'
unarc_rows = []
def unarc_row(rel, made, what):
    unarc_rows.append((rel, made, what))

def unarc_record(rel, chain, made, command, entries, note, password=None, parts=()):
    unarc_row(rel, made, '; '.join(f'`{e["path"]}`' for e in entries) + ('' if not password else f' (password `{password}`)'))
    return record(f'unarc/{rel}', f'{made}, {UNARC_PRODUCER}', command, chain, entries, note, password,
                  [f'unarc/{p}' for p in parts])

def sample(rel):
    return facts['archives'][f'unarc/{rel}']

# ARJ samples: arj (with -v) extracts them; their CRC-32s are checked by arj t.
for n in ('stored.arj', 'method1.arj', 'method2.arj', 'method3.arj', 'method4.arj'):
    f = sample(f'arj/{n}')
    h = f['headers'][0]
    tool = {norm(k): v for k, v in f['tool']['files'].items()}
    check(tool == {'LICENSE': LICENSE} and f['tool_test']['exit'] == 0, f'unarc/arj/{n}: {tool} {f["tool_test"]}')
    t = h['unix_time']
    unarc_record(f'arj/{n}', 'arj', f'ARJ 3.10 on Unix (method {h["method"]})', f'tests/arj/{n} at 0.8.1',
                 [file_entry('LICENSE', LICENSE, t)],
                 f'LICENSE is unarc-rs\'s Apache-2.0 text (LICENSE-APACHE here), as its tests say; arj extracts it. A '
                 f'Unix-host ARJ: `mtime` is the Unix time it holds, {rfc3339(t)[:19]}Z, which 7-Zip {seven_version} '
                 f'and unarc-rs 0.8.1 read as the MS-DOS time {as_dos(t)}. ' + unar_note(f, {'LICENSE': LICENSE}))
f = sample('arj/license_crypted.arj')
check({norm(k): v for k, v in f['tool']['files'].items()} == {'LICENSE': LICENSE}, f'license_crypted: {f["tool"]}')
unarc_record('arj/license_crypted.arj', 'arj', 'ARJ on MS-DOS (method 1, garbled)', 'tests/arj/license_crypted.arj at 0.8.1',
             [file_entry('LICENSE', LICENSE)],
             'Garbled. unarc-rs\'s tests don\'t give its password; XORing its data with method1.arj\'s (the same packed '
             'bytes) gives `secret`, with which arj extracts LICENSE. MS-DOS times, so no `mtime`. '
             + unar_note(f, {'LICENSE': LICENSE}) + f' 7-Zip {seven_version} doesn\'t decode garbled data.', password='secret')
f = sample('arj/test_file.arj')
tool = {norm(k): v for k, v in f['tool']['files'].items()}
check(list(tool) == ['TEST.ICY'] and tool['TEST.ICY']['size'] == 29813, f'test_file: {tool}')
unarc_record('arj/test_file.arj', 'arj', 'ARJ on MS-DOS (method 1, three volumes)', 'tests/arj/multi/test_file.arj, .a01 and .a02 at 0.8.1',
             [file_entry('TEST.ICY', tool['TEST.ICY'])],
             'A volume set of three: TEST.ICY (29 813 bytes) runs through all three. `arj x -v` extracts it; '
             f'{UNAR} and 7-Zip {seven_version} read only the first volume\'s 11 109 bytes. MS-DOS times, so no `mtime`.',
             parts=['arj/test_file.a01', 'arj/test_file.a02'])

# ACE samples: acefile reads and tests them; unar extracts nothing.
for n, made in (('license1.ace', 'ACE 2.0 for Win32, ACE 1.0 methods'), ('license2.ace', 'ACE 2.0 for Win32, ACE 2.0 methods'),
                ('unarc.ace', 'ACE for MS-DOS (three volumes)')):
    f = sample(f'ace/{n}')
    a = f['acefile']
    check(all(e.get('test') and e['read'] == e['size'] for e in a['entries'] if not e['dir']), f'unarc/ace/{n}: {a}')
    entries = [file_entry(e['path'], {'size': e['size'], 'sha256': e['sha256']}) for e in a['entries'] if not e['dir']]
    parts = ['ace/unarc.c00', 'ace/unarc.c01'] if n == 'unarc.ace' else []
    check(a['info']['volumes'] == 1 + len(parts), f'unarc/ace/{n}: {a["info"]}')
    lic = ' (unarc-rs\'s Apache-2.0 text)' if entries[0]['sha256'] == LICENSE['sha256'] else ''
    unarc_record(f'ace/{n}', 'ace', made, f'tests/ace/{"multi/" if parts else ""}{n} at 0.8.1', entries,
                 f'acefile {ver("acefile") if "acefile" in versions else "0.6.12"} lists, reads and tests it'
                 f'{lic}; {UNAR} extracts nothing from ACE and 7-Zip {seven_version} doesn\'t read it. ACE holds MS-DOS '
                 'times, so no `mtime`.' + (' A volume set of three (.ace, .c00, .c01).' if parts else ''), parts=parts)

# ZOO: default.zoo only; high_per.zoo and store.zoo name their file ../license (broken list).
f = sample('zoo/default.zoo')
check({norm(k): v for k, v in f['tool']['files'].items()} == {'license': LICENSE}, f'default.zoo: {f["tool"]}')
unarc_record('zoo/default.zoo', 'zoo', 'zoo (LZW)', 'tests/zoo/default.zoo at 0.8.1', [file_entry('license', LICENSE)],
             'zoo extracts `license`, unarc-rs\'s Apache-2.0 text. ZOO holds MS-DOS times (and a time zone of 127, '
             f'unknown), so no `mtime`. {unar_note(f, {"license": LICENSE})} 7-Zip {seven_version} doesn\'t read ZOO.')
for n in ('high_per.zoo', 'store.zoo'):
    f = sample(f'zoo/{n}')
    check([h['path'] for h in f['headers']] == ['../license'], f'{n}: {f["headers"]}')
    check({k: v for k, v in f['tool']['files'].items()} == {'../license': LICENSE}, f'{n}: {f["tool"]}')
    unarc_row(f'zoo/{n}', 'zoo (LH5)' if n == 'high_per.zoo' else 'zoo (stored)',
              '`../license`: its folder is stored as `..`. In the broken list, not the manifest: it lists and tests, '
              'and extraction must refuse it (Unsafe). zoo writes it to ../license.')

# ARC samples: the decoder here, arc and unar agree on each.
ARC_SAMPLES = [('cpm.arc', 'ARC (CP/M programs, squeezed and packed)'), ('crunch.arc', 'ARC (crunched)'),
               ('crunch2.arc', 'ARC (crunched)'), ('crunch_clear.arc', 'ARC 5.21q `arc aw` (crunched, the table cleared)'),
               ('squashed.arc', 'ARC (squashed)'), ('squash_clear.arc', 'ARC 5.21q `arc awq` (squashed, the table full)'),
               ('store.arc', 'ARC (stored)'), ('license_cypted.arc', 'ARC (crunched, encrypted)'),
               ('license_crunched.pak', 'PAK (crunched)'), ('license_squashed.pak', 'PAK (squashed)')]
for n, made in ARC_SAMPLES:
    f = sample(f'arc/{n}')
    pw = 'SECRET' if n == 'license_cypted.arc' else None
    tool = {norm(k): v for k, v in f['tool']['files'].items()}
    entries = []
    for h in f['headers']:
        d = h['decoded']
        check(d.get('crc_ok') and d.get('end_code'), f'unarc/arc/{n}: {h}')
        check(tool.get(h['path']) == {'size': d['size'], 'sha256': d['sha256']}, f'unarc/arc/{n}: arc extracts {tool}')
        entries.append(file_entry(h['path'], d))
    methods = ', '.join(f'{h["path"]} {h["method"]}' for h in f['headers'])
    lic = ' LICENSE is unarc-rs\'s Apache-2.0 text.' if any(e['sha256'] == LICENSE['sha256'] for e in entries) else ''
    extra = ' Encrypted with `SECRET` (unarc-rs\'s tests\' password).' if pw else ''
    if n.startswith('crunch_clear') or n.startswith('squash_clear'):
        extra += ' SHIFT1.TXT is LICENSE, 12 000 bytes from a 23-letter alphabet, then LICENSE again: the change makes ARC reset (or fill) the table.'
    unarc_record(f'arc/{n}', 'arc', made, f'tests/{"pak" if n.endswith(".pak") else "arc"}/{n} at 0.8.1', entries,
                 f'{methods}: the ARC decoder in make-retro.sh and arc 5.21q extract the same bytes, matching the CRC-16s.'
                 f'{lic}{extra} ARC holds MS-DOS times, so files have no `mtime`. ' + unar_note(f, {e['path']: e for e in entries}) +
                 f' 7-Zip {seven_version} doesn\'t read ARC.', password=pw)
for n, made, method in (('license.pak', 'PAK (distilled)', 'distilled'), ('license_crushed.pak', 'PAK (crushed)', 'crushed')):
    f = sample(f'arc/{n}')
    check([h['method'] for h in f['headers']] == [method], f'{n}: {f["headers"]}')
    unarc_row(f'arc/{n}', made, f'`LICENSE`, {method}, a PAK method BeeZip refuses (docs/M6.md §4.1). In the broken '
              'list, not the manifest: it lists, and reading LICENSE must fail as unsupported.')
for n, why in (('wrongcrc32.arj', 'stored.arj with a wrong CRC-32'), ('wrongcrc16.zoo', 'store.zoo with a wrong CRC-16'),
               ('wrongcrc16.arc', 'store.arc with a wrong CRC-16')):
    f = sample(f'broken/{n}')
    unarc_row(f'broken/{n}', 'unarc-rs\'s tests', f'{why}: testing it must fail (Corrupt).')

if problems:
    raise SystemExit('\n'.join(problems))

# manifest.json: this script's records (arj/, zoo/, arc/, unarc/) go where the first of them was.
mine = lambda r: r['file'].startswith(('arj/', 'zoo/', 'arc/', 'unarc/'))
path = os.path.join(here, 'manifest.json')
manifest = json.load(open(path, encoding='utf-8'))
old = manifest['fixtures']
at = next((i for i, r in enumerate(old) if mine(r)), len(old))
manifest['fixtures'] = old[:at] + records + [r for r in old[at:] if not mine(r)]
if 'make-retro.sh' not in manifest['note']:
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
            files = [n] + [p[len(prefix):] for p in r.get('parts', [])]
            total = sum(os.path.getsize(os.path.join(tp, prefix, x)) for x in files)
            rows.append(f"| `{'`, `'.join(files)}` | {size(total)} | {r['producer']} | `{r['command'].split(' (')[0]}` |")
    return '\n'.join(rows)
TREE = ('`readme.txt`, `empty.txt`, `text.txt` (80 lines of text), `random.bin` (1 KiB of Python\'s Random(42)), '
        '`mtime.txt` and `sub/nested/deep.txt`, and the empty folder `emptydir`; every time 2026-01-01T00:00:00Z but '
        'mtime.txt\'s, 2024-05-06T07:08:09Z')
HEAD = ('Made by `tests/fixtures/make-retro.sh` (docs/M6.md §10) in Docker (make-retro.Dockerfile), which\n'
        'also writes this file and the records in `manifest.json`; a rerun writes the same bytes.\n\n')
readmes = {
    'arj': f'''# ARJ fixtures

{HEAD}The tree: {TREE}. `volumes.arj` holds `readme.txt` and 21 000 bytes that don't compress,
`names-cp437.arj` two files with CP437 names (`café.txt`, `Ünïcödé/ñandú.txt`).

arj on Linux writes Unix-host archives: their times are Unix times, which 7-Zip and unarc-rs read
as MS-DOS times (decades off); the records hold the true ones. `-j$` leaves out the accessed and
created times, which would make every run different, and arj ran under a frozen clock for the
archive's own times. `dos.arj` (-2d) is an MS-DOS-host archive with MS-DOS times.

{table('arj/')}
''',
    'zoo': f'''# ZOO fixtures

{HEAD}The tree: {TREE.split(', and the empty folder')[0]}; ZOO stores no folders, so each file is
named on the command line.

zoo 2.10 leaves the bytes after the NUL of an entry's 13-byte short name uninitialised (stack
garbage, different every run); make-retro.sh zeroes them and makes the entry's CRC-16 again.

{table('zoo/')}
''',
    'arc': f'''# ARC fixtures

{HEAD}ARC stores names only (DOS names, no folders), and arc 5.21q picks each file's method
itself, so the files are chosen for what arc does with them: `TEXT.TXT` (80 lines of text)
crunches or squashes, `RUNS.DAT` (runs of bytes) crunches or packs, `SQZ.DAT` and `CUT.DAT` (2 001
and 2 000 bytes from an 8-letter alphabet) are squeezed, `RANDOM.BIN`, `README.TXT` and
`EMPTY.TXT` are stored. arc is Debian's i386 build: on amd64 it made only stored entries.

arc 5.21q never writes a squeezed stream's last partial byte: `SQZ.DAT`'s end code happens to end
on a byte, `CUT.DAT`'s (`squeeze-cut.arc`) is cut short, though all its data is there, and arc
reads it. unar 1.10.1 fails `CUT.DAT` and crashes part-way through `crunched.arc` and
`squashed.arc`; the records' notes say what it extracts.

{table('arc/')}
''',
}
for d, text in readmes.items():
    with open(os.path.join(tp, d, 'README.md'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
rows = '\n'.join(f'| `{rel}` | {made} | {what} |' for rel, made, what in unarc_rows)
unarc_readme = f'''# unarc-rs test archives

From unarc-rs 0.8.1 (https://github.com/mkrueger/unarc-rs, the crate's `tests/` folder), MIT OR
Apache-2.0: LICENSE-MIT and LICENSE-APACHE here. The crate ships only the Apache text; the MIT
text names its author, Mike Krüger. BeeZip reads ARJ, ACE and ZOO with code taken in from
unarc-rs (docs/M6.md §4); these are its samples, copied unchanged, the PAK ones in `arc/`, the
volume sets beside the rest. `broken/` holds the ones whose CRCs are wrong on purpose.
`make-retro.sh` writes this file and their records in `manifest.json`, from what arj, zoo, arc
and acefile extract (checked against each entry's CRC, unar 1.10.1 and an ARC decoder in the
script); unarc-rs's tests compare most of them with its LICENSE, the Apache-2.0 text.

Seven files aren't in the manifest, but in `broken_fixtures_fail_as_they_should`: the three in
`broken/`, `zoo/high_per.zoo` and `zoo/store.zoo` (whose file is `../license`), and the PAK
archives in methods BeeZip refuses (`arc/license.pak`, `arc/license_crushed.pak`).

| File | Made by | What it holds |
|---|---|---|
{rows}
'''
with open(os.path.join(tp, 'unarc', 'README.md'), 'w', encoding='utf-8', newline='\n') as f:
    f.write(unarc_readme)

for r in records:
    print(f"{r['file']}: {len(r['entries'])} entries; 7z t {r['7z_test']}")
print(f'{len(records)} records')
PY
du -cb "$here/thirdparty/arj" "$here/thirdparty/zoo" "$here/thirdparty/arc" | tail -n 1
