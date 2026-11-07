"""Second opinions on the M5 fixtures (docs/M5.md §10), for fetch-libarchive.ps1 and
make-linux.sh. Standard library only; runs on Windows' Python 3.14 and WSL's 3.12. Run it with
`python -I`: the files it reads are downloads.

  oracles.py list FORMAT FILE [ENCODING]   what BeeZip must list, as JSON on stdout
  oracles.py decompress CODEC IN OUT       one stream, for the codecs 7-Zip lacks
  oracles.py tree DIR                      the files and symlinks under DIR, as `list` prints them

FORMAT is cpio, ar, tar, rpm, lzh or cab. The listing follows docs/M5.md §5: files and symlinks
only, paths /-separated without a leading ./ or /, names decoded as BeeZip decodes them
(`ENCODING`, or "auto": UTF-8 when valid, otherwise Windows-1252, the US system's ANSI page),
and hard links as BeeZip counts them. Each entry carries its data's size and SHA-256 when this
script can get at the data (stored data; LHA's and CAB's compressed methods are left to 7-Zip
or delharc, and their entries carry `crc16` or nothing instead).

CODEC is lz4 (frames), lzip, lzop (liblzo2 through ctypes, so WSL only), or one of Python's
own: gzip, bzip2, xz, lzma, zstd (Python 3.14).
"""
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import stat
import struct
import sys
import tarfile
import zlib

# BeeZip's encoding names (crates/beezip-core/src/names.rs) as Python codecs.
CODECS = {
    'utf-8': 'utf-8', 'cp437': 'cp437', 'cp850': 'cp850', 'cp852': 'cp852', 'cp866': 'cp866',
    'cp874': 'cp874', 'cp932': 'cp932', 'cp936': 'gbk', 'cp949': 'cp949', 'cp950': 'cp950',
    'cp1250': 'cp1250', 'cp1251': 'cp1251', 'cp1252': 'cp1252', 'cp1253': 'cp1253',
    'cp1254': 'cp1254', 'cp1255': 'cp1255', 'cp1256': 'cp1256', 'cp1257': 'cp1257',
    'cp1258': 'cp1258', 'koi8-r': 'koi8_r', 'koi8-u': 'koi8_u', 'iso-8859-1': 'latin-1',
    'iso-8859-2': 'iso8859_2', 'iso-8859-5': 'iso8859_5', 'iso-8859-7': 'iso8859_7',
    'euc-jp': 'euc_jp', 'gb18030': 'gb18030',
}


class Corrupt(Exception):
    pass


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def cp1252(raw):
    # WHATWG's windows-1252 (encoding_rs): the five bytes cp1252 leaves undefined are C1 controls.
    return ''.join(bytes([b]).decode('cp1252', errors='ignore') or chr(b) for b in raw)


def decode(raw, encoding):
    """A name as BeeZip decodes one not marked as UTF-8 (names.rs, `NameDecoding::decode`)."""
    if raw.isascii():
        return raw.decode('ascii')
    if not encoding or encoding == 'auto':
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return cp1252(raw)
    return raw.decode(CODECS[encoding], errors='replace')


def normalize(path):
    """format::normalize: `\\` -> `/`, no leading ./ or /, no trailing /."""
    p = path.replace('\\', '/')
    while True:
        if p.startswith('./'):
            p = p[2:]
        elif p.startswith('/'):
            p = p[1:]
        else:
            break
    return p.rstrip('/')


def file_entry(path, data, **more):
    e = {'path': path, 'kind': 'file', 'size': len(data), 'sha256': sha256(data)}
    e.update(more)
    return e


def link_entry(path, target):
    return {'path': path, 'kind': 'symlink', 'target': target}


def result(entries, hardlinks, others=(), info=None):
    out = {
        'entries': entries,
        'hardlinks': hardlinks,
        'symlinks': sum(1 for e in entries if e['kind'] == 'symlink'),
        'others': list(others),
    }
    if info:
        out['info'] = info
    return out


# cpio (docs/M5.md §5.2) ---------------------------------------------------------------------

def align(n, a):
    return (n + a - 1) // a * a


def cpio_members(data):
    """Every member before TRAILER!!!, in order."""
    pos = 0
    out = []
    while True:
        magic = data[pos:pos + 6]
        if magic in (b'070701', b'070702'):
            h = data[pos:pos + 110]
            if len(h) < 110:
                raise Corrupt('short newc header')
            f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            ino, mode, _uid, _gid, nlink, _mtime, size, dmaj, dmin, _rmaj, _rmin, namesize, check = f
            name = data[pos + 110:pos + 110 + namesize].rstrip(b'\0')
            pos = align(pos + 110 + namesize, 4)
            body = data[pos:pos + size]
            pos = align(pos + size, 4)
            fmt = 'newc' if magic == b'070701' else 'crc'
            m = dict(fmt=fmt, name=name, mode=mode, ino=ino, dev=(dmaj, dmin), nlink=nlink,
                     data=body, check=check)
        elif magic == b'070707':
            h = data[pos:pos + 76]
            if len(h) < 76:
                raise Corrupt('short odc header')
            dev, ino, mode = int(h[6:12], 8), int(h[12:18], 8), int(h[18:24], 8)
            nlink = int(h[36:42], 8)
            namesize, size = int(h[59:65], 8), int(h[65:76], 8)
            name = data[pos + 76:pos + 76 + namesize].rstrip(b'\0')
            pos += 76 + namesize
            body = data[pos:pos + size]
            pos += size
            m = dict(fmt='odc', name=name, mode=mode, ino=ino, dev=(dev,), nlink=nlink, data=body)
        elif magic == b'070727':
            raise Corrupt('afio large ASCII header (070727), which BeeZip does not read')
        elif data[pos:pos + 2] in (b'\xc7\x71', b'\x71\xc7'):
            order = '<' if data[pos] == 0xC7 else '>'
            if len(data) < pos + 26:
                raise Corrupt('short binary header')
            v = struct.unpack(order + '13H', data[pos:pos + 26])
            _magic, dev, ino, mode, _uid, _gid, nlink, _rdev, _mt1, _mt2, namesize, s1, s2 = v
            size = (s1 << 16) | s2
            name = data[pos + 26:pos + 26 + namesize].rstrip(b'\0')
            pos = align(pos + 26 + namesize, 2)
            body = data[pos:pos + size]
            pos = align(pos + size, 2)
            m = dict(fmt='bin-le' if order == '<' else 'bin-be', name=name, mode=mode, ino=ino,
                     dev=(dev,), nlink=nlink, data=body)
        else:
            raise Corrupt(f'no cpio header at {pos}')
        if m['name'] == b'TRAILER!!!':
            return out, pos
        if len(m['data']) != size:
            raise Corrupt(f'{m["name"]!r} is cut short')
        out.append(m)


def cpio_list(data, encoding):
    members, end = cpio_members(data)
    # newc and crc: a group of members sharing an inode carries its data in one (normally the
    # last); that one is the file, the others are links to it. odc and binary: each carries its
    # own data.
    groups = {}
    for i, m in enumerate(members):
        if m['fmt'] in ('newc', 'crc') and stat.S_ISREG(m['mode']) and m['nlink'] > 1:
            groups.setdefault((m['dev'], m['ino']), []).append(i)
    shared = {}
    links = set()
    for idx in groups.values():
        holder = [i for i in idx if members[i]['data']]
        if len(holder) > 1:
            raise Corrupt(f'two members of one hard-link group carry data: {idx}')
        holder = holder[0] if holder else idx[-1]
        for i in idx:
            shared[i] = members[holder]['data']
            if i != holder:
                links.add(i)
    entries, others = [], []
    bad_checks = []
    for i, m in enumerate(members):
        path = normalize(decode(m['name'], encoding))
        kind = stat.S_IFMT(m['mode'])
        if m['fmt'] == 'crc' and (sum(m['data']) & 0xFFFFFFFF) != m['check']:
            bad_checks.append(path)
        if kind == stat.S_IFREG:
            entries.append(file_entry(path, shared.get(i, m['data'])))
        elif kind == stat.S_IFLNK:
            entries.append(link_entry(path, decode(m['data'], encoding)))
        elif kind != stat.S_IFDIR:
            others.append(path)
    info = {'formats': sorted({m['fmt'] for m in members}), 'trailing': len(data) - end}
    if bad_checks:
        info['bad_checksums'] = bad_checks
    return result(entries, len(links), others, info)


# ar (docs/M5.md §5.3) -----------------------------------------------------------------------

def ar_members(data):
    if not data.startswith(b'!<arch>\n'):
        if data.startswith(b'!<thin>\n'):
            raise Corrupt('thin archive')
        raise Corrupt('not an ar archive')
    pos = 8
    names = b''
    out = []
    while pos + 60 <= len(data):
        h = data[pos:pos + 60]
        if h[58:60] != b'`\n':
            raise Corrupt(f'bad ar header at {pos}')
        raw = h[0:16].rstrip(b' ')
        size = int(h[48:58].strip() or b'0')
        body = data[pos + 60:pos + 60 + size]
        pos = align(pos + 60 + size, 2)
        if raw in (b'/', b'/SYM64/', b'__.SYMDEF', b'__.SYMDEF SORTED'):
            continue
        if raw == b'//':
            names = body
            continue
        if raw.startswith(b'#1/'):
            n = int(raw[3:])
            name, body = body[:n].rstrip(b'\0'), body[n:]
            if name in (b'__.SYMDEF', b'__.SYMDEF SORTED', b'__.SYMDEF_64', b'__.SYMDEF_64 SORTED'):
                continue
        elif raw.startswith(b'/') and raw[1:].isdigit():
            off = int(raw[1:])
            end = names.index(b'\n', off)
            name = names[off:end].rstrip(b'/')
        else:
            name = raw[:-1] if raw.endswith(b'/') else raw
        out.append((name, body))
    return out


def ar_list(data, encoding):
    entries = [file_entry(decode(n, encoding), b) for n, b in ar_members(data)]
    return result(entries, 0)


# tar ----------------------------------------------------------------------------------------

def tar_list(fileobj, encoding, prefix=''):
    enc = CODECS.get(encoding or 'utf-8', 'utf-8') if encoding and encoding != 'auto' else 'utf-8'
    errors = 'strict' if encoding and encoding != 'auto' else 'surrogateescape'
    t = tarfile.open(fileobj=fileobj, mode='r:', encoding=enc, errors=errors)
    members = t.getmembers()
    datas = {}
    entries, others = [], []
    hard = 0

    def name(m):
        n = m.name
        if errors == 'surrogateescape':
            n = decode(n.encode('utf-8', 'surrogateescape'), encoding)
        return prefix + normalize(n)

    for m in members:
        if m.isfile():
            datas[normalize(m.name)] = t.extractfile(m).read()
    for m in members:
        p = name(m)
        if m.isfile():
            entries.append(file_entry(p, datas[normalize(m.name)]))
        elif m.islnk():
            hard += 1
            entries.append(file_entry(p, datas[normalize(m.linkname)]))
        elif m.issym():
            target = m.linkname
            if errors == 'surrogateescape':
                target = decode(target.encode('utf-8', 'surrogateescape'), encoding)
            entries.append(link_entry(p, target))
        elif not m.isdir():
            others.append(p)
    return result(entries, hard, others)


# RPM (docs/M5.md §5.4) ----------------------------------------------------------------------

def rpm_header(data, pos):
    if data[pos:pos + 3] != b'\x8e\xad\xe8':
        raise Corrupt(f'no RPM header at {pos}')
    nindex, hsize = struct.unpack('>II', data[pos + 8:pos + 16])
    index = pos + 16
    store = index + 16 * nindex
    tags = {}
    for i in range(nindex):
        tag, typ, off, count = struct.unpack('>IIII', data[index + 16 * i:index + 16 * i + 16])
        p = store + off
        if typ in (2, 3, 4, 5):
            w, f = {2: (1, 'B'), 3: (2, 'H'), 4: (4, 'I'), 5: (8, 'Q')}[typ]
            v = list(struct.unpack(f'>{count}{f}', data[p:p + w * count]))
        elif typ in (6, 8, 9):
            v = []
            for _ in range(count):
                e = data.index(b'\0', p)
                v.append(data[p:e])
                p = e + 1
            if typ == 6:
                v = v[0]
        elif typ == 7:
            v = data[p:p + count]
        else:
            v = data[p:p + count]
        tags[tag] = v
    return tags, store + hsize


def decompress_bytes(codec, data):
    if codec == 'gzip':
        return gzip.decompress(data)
    if codec == 'bzip2':
        return bz2.decompress(data)
    if codec == 'xz':
        return lzma.decompress(data, format=lzma.FORMAT_XZ)
    if codec == 'lzma':
        return lzma.decompress(data, format=lzma.FORMAT_ALONE)
    if codec == 'zstd':
        from compression import zstd  # Python 3.14
        return zstd.decompress(data)
    if codec == 'lz4':
        return lz4_frames(data)
    if codec == 'lzip':
        return lzip(data)
    if codec == 'lzop':
        return lzop(data)
    raise SystemExit(f'unknown codec {codec}')


def rpm_info(data):
    if data[:4] != b'\xed\xab\xee\xdb':
        raise Corrupt('no RPM lead')
    _sig, end = rpm_header(data, 96)
    end = align(end, 8)
    tags, payload = rpm_header(data, end)
    s = lambda t: tags[t].decode() if t in tags else None
    info = {
        'nevra': f'{s(1000)}-{s(1001)}-{s(1002)}.{s(1022)}',
        'payload_format': s(1124),
        'payload_compressor': s(1125) or 'gzip',
        'payload_offset': payload,
        'license': s(1014),
    }
    return tags, info


def rpm_list(data, encoding):
    tags, info = rpm_info(data)
    if 1117 in tags:
        dirs = tags[1118]
        names = [dirs[d] + b for d, b in zip(tags[1116], tags[1117])]
    else:
        names = tags.get(1027, [])
    n = len(names)
    sizes = tags.get(5008) or tags.get(1028) or [0] * n
    modes = tags.get(1030, [0] * n)
    flags = tags.get(1037, [0] * n)
    linktos = tags.get(1036, [b''] * n)
    devs = tags.get(1095, [0] * n)
    inos = tags.get(1096, list(range(n)))
    cpio = decompress_bytes(info['payload_compressor'], data[info['payload_offset']:])
    members, _ = cpio_members(cpio)
    body = {normalize(m['name'].decode('utf-8', 'surrogateescape')): m for m in members}
    # The last of each group of regular files sharing (device, inode), in header order, is the
    # file; the others are links to it.
    last = {}
    for i in range(n):
        if stat.S_ISREG(modes[i]) and not flags[i] & 0x40:
            last[(devs[i], inos[i])] = i
    entries, others = [], []
    hard = 0
    ghosts = []
    for i in range(n):
        path = normalize(decode(names[i], encoding))
        if flags[i] & 0x40:
            ghosts.append(path)
            continue
        kind = stat.S_IFMT(modes[i])
        key = normalize(names[i].decode('utf-8', 'surrogateescape'))
        if kind == stat.S_IFREG:
            holder = last[(devs[i], inos[i])]
            hkey = normalize(names[holder].decode('utf-8', 'surrogateescape'))
            d = body[hkey]['data']
            if len(d) != sizes[holder]:
                raise Corrupt(f'{hkey}: {len(d)} bytes in the payload, {sizes[holder]} in the header')
            if holder != i:
                hard += 1
                if body.get(key) and body[key]['data']:
                    raise Corrupt(f'{key} is a link but carries data')
            entries.append(file_entry(path, d))
        elif kind == stat.S_IFLNK:
            target = decode(linktos[i], encoding)
            if key in body and body[key]['data'] != linktos[i]:
                raise Corrupt(f'{key}: the payload and the header disagree on the target')
            entries.append(link_entry(path, target))
        elif kind != stat.S_IFDIR:
            others.append(path)
    info['files'] = n
    info['ghosts'] = ghosts
    info['payload_members'] = len(members)
    return result(entries, hard, others, info)


# LHA (docs/M5.md §5.6) ----------------------------------------------------------------------

def crc16(data, crc=0):
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def lha_headers(data):
    """Each header: method, level, os, raw name bytes, UTF-16 name, unix mode, sizes, CRC-16, and
    the stored data for -lh0-/-lz4-/-pm0-."""
    pos = 0
    out = []
    while pos < len(data):
        if data[pos] == 0:
            break
        if pos + 22 > len(data):
            raise Corrupt('short LHA header')
        method = data[pos + 2:pos + 7]
        level = data[pos + 20]
        ext = []
        name = b''
        mode = None
        os_id = None
        if level == 0 or level == 1:
            hsize = data[pos] + 2
            packed, orig = struct.unpack('<II', data[pos + 7:pos + 15])
            nlen = data[pos + 21]
            name = data[pos + 22:pos + 22 + nlen]
            q = pos + 22 + nlen
            crc = struct.unpack('<H', data[q:q + 2])[0]
            q += 2
            if level == 0:
                # LHa for UNIX's extension: 'U', a minor version, the mtime, then the mode.
                if hsize > q - pos:
                    os_id = data[q]
                    if os_id == ord('U') and hsize - (q - pos) >= 12:
                        mode = struct.unpack('<H', data[q + 6:q + 8])[0]
                body = pos + hsize
            else:
                os_id = data[q]
                q = pos + hsize - 2
                nxt = struct.unpack('<H', data[q:q + 2])[0]
                q += 2
                while nxt:
                    ext.append((data[q], data[q + 1:q + nxt - 2]))
                    packed -= nxt
                    q2 = q + nxt - 2
                    nxt = struct.unpack('<H', data[q2:q2 + 2])[0]
                    q = q2 + 2
                body = q
        elif level == 2 or level == 3:
            if level == 2:
                hsize = struct.unpack('<H', data[pos:pos + 2])[0]
                q = pos + 26
                nxt = struct.unpack('<H', data[pos + 24:pos + 26])[0]
                w = 2
            else:
                hsize = struct.unpack('<I', data[pos + 24:pos + 28])[0]
                q = pos + 32
                nxt = struct.unpack('<I', data[pos + 28:pos + 32])[0]
                w = 4
            packed, orig = struct.unpack('<II', data[pos + 7:pos + 15])
            crc = struct.unpack('<H', data[pos + 21:pos + 23])[0]
            os_id = data[pos + 23]
            while nxt:
                ext.append((data[q], data[q + 1:q + nxt - w]))
                q2 = q + nxt - w
                nxt = int.from_bytes(data[q2:q2 + w], 'little')
                q = q2 + w
            body = pos + hsize
        else:
            raise Corrupt(f'LHA header level {level}')
        dirname = None
        uname = udir = None
        ext_name = False
        # Amiga's LHA (and level 0 with no OS) put a file note after a NUL in the name.
        if os_id == ord('A') or (level == 0 and os_id is None):
            name = name.split(b'\0', 1)[0]
        for t, d in ext:
            if t == 0x01:
                name = d.split(b'\0', 1)[0] if os_id == ord('A') else d
                ext_name = bool(d)
            elif t == 0x02:
                dirname = d
            elif t == 0x44:
                uname = d.decode('utf-16-le')
            elif t == 0x45:
                udir = d.decode('utf-16-le')
            elif t == 0x50:
                mode = struct.unpack('<H', d[:2])[0]
            elif t == 0x42:
                packed, orig = struct.unpack('<QQ', d[:16])
        stored = data[body:body + packed] if method in (b'-lh0-', b'-lz4-', b'-pm0-') else None
        # delharc's is_directory(): -lhd-, or an empty -lh0- whose name ends with a separator
        # (or is missing, with a directory given).
        is_dir = method == b'-lhd-'
        if method == b'-lh0-' and orig == 0 and not ext_name:
            is_dir = name[-1:] in (b'/', b'\\', b'\xff') if name else dirname is not None
        out.append(dict(method=method.decode('latin-1'), level=level, os=os_id, name=name, is_dir=is_dir,
                        dirname=dirname, uname=uname, udir=udir, mode=mode, packed=packed,
                        size=orig, crc=crc, stored=stored))
        pos = body + packed
    return out


def lha_list(data, encoding):
    entries, others = [], []
    info = {'methods': [], 'levels': [], 'os': []}
    for h in lha_headers(data):
        for k, v in (('methods', h['method']), ('levels', h['level']),
                     ('os', chr(h['os']) if h['os'] and 32 < h['os'] < 127 else h['os'])):
            if v not in info[k]:
                info[k].append(v)
        # Bytes: the directory's 0xFF separators, then the name's `\`, become `/`.
        if h['uname'] is not None or h['udir'] is not None:
            name = h['uname'] if h['uname'] is not None else decode(h['name'], encoding)
            d = h['udir'] if h['udir'] is not None else (
                decode_dir(h['dirname'], encoding) if h['dirname'] else '')
            d = d.replace('￿', '/')
        else:
            name = decode(h['name'], encoding)
            d = decode_dir(h['dirname'], encoding) if h['dirname'] else ''
        if d and not d.endswith('/'):
            d += '/'
        full = (d + name).replace('\\', '/')
        is_dir = h['is_dir']
        mode = h['mode']
        if is_dir and mode is not None and stat.S_ISLNK(mode):
            link, _, target = full.partition('|')
            entries.append(link_entry(normalize(link), target))
            continue
        if is_dir:
            continue
        if mode is not None and not stat.S_ISREG(mode) and stat.S_IFMT(mode):
            others.append(normalize(full))
            continue
        e = {'path': normalize(full), 'kind': 'file', 'size': h['size'], 'crc16': h['crc'],
             'method': h['method']}
        if h['stored'] is not None and len(h['stored']) == h['size']:
            e['sha256'] = sha256(h['stored'])
            if crc16(h['stored']) != h['crc']:
                raise Corrupt(f'{full}: stored data fails its CRC-16')
        entries.append(e)
    return result(entries, 0, others, info)


def decode_dir(raw, encoding):
    return '/'.join(decode(p, encoding) for p in raw.split(b'\xff'))


# CAB (docs/M5.md §5.5) ----------------------------------------------------------------------

def cab_files(data):
    if data[:4] != b'MSCF':
        raise Corrupt('no CAB header')
    coff_files = struct.unpack('<I', data[16:20])[0]
    c_folders, c_files, flags = struct.unpack('<HHH', data[26:32])
    pos = 36
    if flags & 4:
        cb_header = struct.unpack('<H', data[pos:pos + 2])[0]
        pos += 4 + cb_header
    links = {}
    for bit, key in ((1, 'prev'), (2, 'next')):
        if flags & bit:
            e = data.index(b'\0', pos)
            links[key] = data[pos:e].decode('latin-1')
            pos = data.index(b'\0', e + 1) + 1
    out = []
    pos = coff_files
    for _ in range(c_files):
        size, off, folder, _date, _time, attrs = struct.unpack('<IIHHHH', data[pos:pos + 16])
        e = data.index(b'\0', pos + 16)
        out.append(dict(name=data[pos + 16:e], size=size, offset=off, folder=folder, attrs=attrs))
        pos = e + 1
    return out, links, c_folders


def cab_list(data, encoding, more=()):
    """`more`: the set's other cabinets, in order. A file continued from the cabinet before
    (folder 0xFFFD or 0xFFFF) is listed once, from the cabinet it starts in."""
    entries = []
    info = {'cabinets': []}
    for i, cab in enumerate([data] + list(more)):
        files, links, folders = cab_files(cab)
        info['cabinets'].append({'files': len(files), 'folders': folders, **links})
        for f in files:
            if i > 0 and f['folder'] in (0xFFFD, 0xFFFF):
                continue
            utf = bool(f['attrs'] & 0x80)
            name = f['name'].decode('utf-8', 'replace') if utf else decode(f['name'], encoding)
            entries.append({'path': normalize(name), 'kind': 'file', 'size': f['size']})
    return result(entries, 0, (), info)


# Codecs 7-Zip lacks -------------------------------------------------------------------------

def lz4_block(src, out):
    i = 0
    while i < len(src):
        token = src[i]
        i += 1
        n = token >> 4
        if n == 15:
            while True:
                b = src[i]
                i += 1
                n += b
                if b != 255:
                    break
        out += src[i:i + n]
        i += n
        if i >= len(src):
            break
        off = src[i] | src[i + 1] << 8
        i += 2
        if off == 0 or off > len(out):
            raise Corrupt('lz4 offset')
        m = token & 15
        if m == 15:
            while True:
                b = src[i]
                i += 1
                m += b
                if b != 255:
                    break
        m += 4
        start = len(out) - off
        for k in range(m):
            out.append(out[start + k])


def lz4_frames(data):
    out = bytearray()
    pos = 0
    while pos < len(data):
        magic = struct.unpack('<I', data[pos:pos + 4])[0]
        if 0x184D2A50 <= magic <= 0x184D2A5F:
            pos += 8 + struct.unpack('<I', data[pos + 4:pos + 8])[0]
            continue
        if magic != 0x184D2204:
            raise Corrupt('lz4 magic')
        flg = data[pos + 4]
        pos += 6 + (8 if flg & 8 else 0) + (4 if flg & 1 else 0) + 1
        frame = bytearray()
        while True:
            size = struct.unpack('<I', data[pos:pos + 4])[0]
            pos += 4
            if size == 0:
                break
            blk = data[pos:pos + (size & 0x7FFFFFFF)]
            pos += size & 0x7FFFFFFF
            if size & 0x80000000:
                frame += blk
            else:
                lz4_block(blk, frame)
            if flg & 0x10:
                pos += 4
        if flg & 4:
            pos += 4
        out += frame
    return bytes(out)


def lzip(data):
    out = bytearray()
    pos = 0
    while pos < len(data):
        if data[pos:pos + 4] != b'LZIP':
            raise Corrupt('lzip magic')
        b = data[pos + 5]
        dict_size = (1 << (b & 0x1F)) - ((1 << (b & 0x1F)) // 16) * ((b >> 5) & 7)
        d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[
            {'id': lzma.FILTER_LZMA1, 'dict_size': dict_size, 'lc': 3, 'lp': 0, 'pb': 2}])
        member = d.decompress(data[pos + 6:])
        used = len(data) - pos - 6 - len(d.unused_data)
        trailer = data[pos + 6 + used:pos + 6 + used + 20]
        crc, size, msize = struct.unpack('<IQQ', trailer)
        if crc != zlib.crc32(member) or size != len(member):
            raise Corrupt('lzip trailer')
        out += member
        pos += msize
    return bytes(out)


LZOP_MAGIC = b'\x89LZO\x00\r\n\x1a\n'


def lzop(buf):
    """lzop's container, with liblzo2's lzo1x_decompress_safe for the blocks (WSL)."""
    import ctypes
    lib = ctypes.CDLL('liblzo2.so.2')
    usize = ctypes.c_size_t

    def block(src, n):
        out = ctypes.create_string_buffer(n)
        got = usize(n)
        r = lib.lzo1x_decompress_safe(src, usize(len(src)), out, ctypes.byref(got), None)
        if r != 0 or got.value != n:
            raise Corrupt(f'lzo1x_decompress_safe returned {r}')
        return out.raw[:n]

    adler = lambda b: zlib.adler32(b) & 0xFFFFFFFF
    out = bytearray()
    pos = 0
    while pos < len(buf):
        if buf[pos:pos + 9] != LZOP_MAGIC:
            if out:
                break
            raise Corrupt('lzop magic')
        pos += 9
        start = pos
        version = struct.unpack('>H', buf[pos:pos + 2])[0]
        pos += 4 + (2 if version >= 0x0940 else 0)
        pos += 1 + (1 if version >= 0x0940 else 0)
        flags = struct.unpack('>I', buf[pos:pos + 4])[0]
        pos += 4
        if flags & 0x800:
            pos += 4
        pos += 4 + 4 + (4 if version >= 0x0940 else 0)
        pos += 1 + buf[pos]
        want = zlib.crc32(buf[start:pos]) if flags & 0x1000 else adler(buf[start:pos])
        if struct.unpack('>I', buf[pos:pos + 4])[0] != want & 0xFFFFFFFF:
            raise Corrupt('lzop header checksum')
        pos += 4
        if flags & 0x40:
            n = struct.unpack('>I', buf[pos:pos + 4])[0]
            pos += 4 + n + 4
        while True:
            dlen = struct.unpack('>I', buf[pos:pos + 4])[0]
            pos += 4
            if dlen == 0:
                break
            slen = struct.unpack('>I', buf[pos:pos + 4])[0]
            pos += 4
            sums = []
            for flag, kind in ((1, 'ad'), (0x100, 'cd'), (2, 'ac'), (0x200, 'cc')):
                if flags & flag and (kind[1] == 'd' or slen < dlen):
                    sums.append((kind, struct.unpack('>I', buf[pos:pos + 4])[0]))
                    pos += 4
            src = buf[pos:pos + slen]
            pos += slen
            d = src if slen == dlen else block(src, dlen)
            for kind, v in sums:
                b = d if kind[1] == 'd' else src
                got = adler(b) if kind[0] == 'a' else zlib.crc32(b) & 0xFFFFFFFF
                if got != v:
                    raise Corrupt(f'lzop {kind} checksum')
            out += d
    return bytes(out)


# A directory, as dpkg-deb -R leaves it ------------------------------------------------------

def tree_list(root):
    entries = []
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files + [x for x in dirs if os.path.islink(os.path.join(d, x))]):
            full = os.path.join(d, name)
            rel = os.path.relpath(full, root).replace(os.sep, '/')
            if os.path.islink(full):
                entries.append(link_entry(rel, os.readlink(full)))
            elif os.path.isfile(full):
                with open(full, 'rb') as f:
                    entries.append(file_entry(rel, f.read()))
    return result(entries, 0)


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    cmd = argv[1]
    if cmd == 'list':
        fmt, path = argv[2], argv[3]
        encoding = argv[4] if len(argv) > 4 else None
        with open(path, 'rb') as f:
            data = f.read()
        if fmt == 'cpio':
            r = cpio_list(data, encoding)
        elif fmt == 'ar':
            r = ar_list(data, encoding)
        elif fmt == 'tar':
            r = tar_list(io.BytesIO(data), encoding)
        elif fmt == 'rpm':
            r = rpm_list(data, encoding)
        elif fmt == 'lzh':
            r = lha_list(data, encoding)
        elif fmt == 'cab':
            more = []
            for p in argv[5:]:
                with open(p, 'rb') as f:
                    more.append(f.read())
            r = cab_list(data, encoding, more)
        else:
            raise SystemExit(f'unknown format {fmt}')
    elif cmd == 'decompress':
        with open(argv[3], 'rb') as f:
            data = decompress_bytes(argv[2], f.read())
        with open(argv[4], 'wb') as f:
            f.write(data)
        r = {'size': len(data), 'sha256': sha256(data)}
    elif cmd == 'tree':
        r = tree_list(argv[2])
    else:
        raise SystemExit(__doc__)
    json.dump(r, sys.stdout, indent=1)
    sys.stdout.write('\n')


if __name__ == '__main__':
    try:
        main(sys.argv)
    except (Corrupt, struct.error, IndexError, ValueError, EOFError, lzma.LZMAError, OSError) as e:
        print(json.dumps({'error': f'{type(e).__name__}: {e}'}))
        sys.exit(3)
