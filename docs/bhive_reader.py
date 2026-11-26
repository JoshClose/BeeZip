#!/usr/bin/env python3
"""A reader for .bhive archives, written from docs/bhive.md alone.

It shares no code with BeeZip and uses only Python's standard library (3.14 or later, for
Zstandard). BeeZip's tests run it against BeeZip's own archives: if the two agree, the
specification is enough to read the format. It opens encrypted archives (§12) with every way in
that a typed secret or a key file gives, and checks signatures (§13).

    python bhive_reader.py list    ARCHIVE [options]
    python bhive_reader.py test    ARCHIVE [options]
    python bhive_reader.py extract ARCHIVE DIRECTORY [options]
    python bhive_reader.py verify  ARCHIVE [options]
    python bhive_reader.py slots   ARCHIVE [options]

`list` prints one entry a line: kind, size, modification time and creation time (seconds and
nanoseconds since 1970, or `-`), Unix mode and DOS attributes (octal and hex, or `-`), path, and
a link's target, separated by tabs. `test` reads every cell and checks the signatures. `verify`
prints a line for each signature: `checked`, `failed` or `unchecked` (it couldn't be checked, and
why), its algorithm, the signer's fingerprint, the time the signer claims, and the signer.
`slots` prints an encrypted archive's ways in, and their labels once it is open.

Options:
    --recover               rebuild what the records hold when the index is lost (§8)
    --password TEXT         open an encrypted archive with this password
    --password-file FILE    ... with the first line of FILE (`-` reads standard input)
    --recovery-key DIGITS   ... with this recovery key
    --identity FILE         ... with the private keys in FILE: age identities
                            (AGE-SECRET-KEY-1..., AGE-SECRET-KEY-PQ-1...), or an RSA, P-256 or
                            P-384 key in PEM or DER (PKCS #8, plain or under a password; PKCS #1;
                            SEC 1). May be given more than once
    --key-password TEXT     the password of a key file under one (PKCS #8 with PBES2)

Exit codes: 0 when all went well; 1 when the file breaks the specification, a cell or a
signature fails, or the archive is incomplete; 2 for a command line it can't follow; 3 when the
archive is encrypted and nothing given opens it.

It is slow, on purpose simple, and checks everything §9, §12.10 and §13 ask a reader to check.
It isn't constant-time, which is fine for opening one's own archives on one's own machine. It
doesn't check certificate chains: a signature made with a certificate is checked against that
certificate's key, and whom to trust is for the person reading.
"""

import base64
import hashlib
import hmac
import lzma
import os
import struct
import sys
import unicodedata
from array import array
from compression import zstd

MAGIC = b"\x89BHIVE\r\n"
MAX_CELL = 256 << 20
MASK = (1 << 64) - 1


class Bad(Exception):
    """The file breaks the specification."""


class Locked(Exception):
    """The archive is encrypted, and nothing given opens it."""


class Usage(Exception):
    """A command line, or a key file named on it, that this reader can't take."""


# XXH3-64, seed 0, the default secret (xxHash's doc/xxhash_spec.md).

SECRET = bytes.fromhex(
    "b8fe6c3923a44bbe7c01812cf721ad1cded46de9839097db7240a4a4b7b3671f"
    "cb79e64eccc0e578825ad07dccff7221b8084674f743248ee03590e6813a264c"
    "3c2852bb91c300cb88d0658b1b532ea371644897a20df94e3819ef46a9deacd8"
    "a8fa763fe39c343ff9dcbbc7c70b4f1d8a51e04bcdb45931c89f7ec9d9787364"
    "eac5ac8334d3ebc3c581a0fffa1363eb170ddd51b7f0da49d316552629d4689e"
    "2b16be587d47a1fc8ff8b8d17ad031ce45cb3a8f95160428afd7fbcabb4b407e"
)
P32_1, P32_2, P32_3 = 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D
P64_1, P64_2, P64_3 = 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9
P64_4, P64_5 = 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5
PMX1, PMX2 = 0x165667919E3779F9, 0x9FB21C651E98DF25


def _u32(b, at):
    return struct.unpack_from("<I", b, at)[0]


def _u64(b, at):
    return struct.unpack_from("<Q", b, at)[0]


def _fold(a, b):
    p = a * b
    return (p & MASK) ^ (p >> 64)


def _avalanche(h):
    h ^= h >> 37
    h = (h * PMX1) & MASK
    return h ^ (h >> 32)


def _mix16(data, at, secret_at):
    lo = _u64(data, at) ^ _u64(SECRET, secret_at)
    hi = _u64(data, at + 8) ^ _u64(SECRET, secret_at + 8)
    return _fold(lo, hi)


def _stripe(acc, data, at, secret_at):
    values = struct.unpack_from("<8Q", data, at)
    keys = struct.unpack_from("<8Q", SECRET, secret_at)
    for i in range(8):
        key = values[i] ^ keys[i]
        acc[i ^ 1] = (acc[i ^ 1] + values[i]) & MASK
        acc[i] = (acc[i] + (key & 0xFFFFFFFF) * (key >> 32)) & MASK


def xxh3_64(data):
    n = len(data)
    if n == 0:
        h = _u64(SECRET, 56) ^ _u64(SECRET, 64)
        h ^= h >> 33
        h = (h * P64_2) & MASK
        h ^= h >> 29
        h = (h * P64_3) & MASK
        return h ^ (h >> 32)
    if n <= 3:
        combined = (data[0] << 16) | (data[n >> 1] << 24) | data[n - 1] | (n << 8)
        h = combined ^ (_u32(SECRET, 0) ^ _u32(SECRET, 4))
        h ^= h >> 33
        h = (h * P64_2) & MASK
        h ^= h >> 29
        h = (h * P64_3) & MASK
        return h ^ (h >> 32)
    if n <= 8:
        flip = _u64(SECRET, 8) ^ _u64(SECRET, 16)
        h = (_u32(data, n - 4) + (_u32(data, 0) << 32)) ^ flip
        h ^= (((h << 49) | (h >> 15)) & MASK) ^ (((h << 24) | (h >> 40)) & MASK)
        h = (h * PMX2) & MASK
        h ^= (h >> 35) + n
        h = (h * PMX2) & MASK
        return h ^ (h >> 28)
    if n <= 16:
        lo = _u64(data, 0) ^ (_u64(SECRET, 24) ^ _u64(SECRET, 32))
        hi = _u64(data, n - 8) ^ (_u64(SECRET, 40) ^ _u64(SECRET, 48))
        swapped = int.from_bytes(lo.to_bytes(8, "little"), "big")
        return _avalanche((n + swapped + hi + _fold(lo, hi)) & MASK)
    if n <= 128:
        acc = (n * P64_1) & MASK
        if n > 32:
            if n > 64:
                if n > 96:
                    acc += _mix16(data, 48, 96) + _mix16(data, n - 64, 112)
                acc += _mix16(data, 32, 64) + _mix16(data, n - 48, 80)
            acc += _mix16(data, 16, 32) + _mix16(data, n - 32, 48)
        acc += _mix16(data, 0, 0) + _mix16(data, n - 16, 16)
        return _avalanche(acc & MASK)
    if n <= 240:
        acc = (n * P64_1) & MASK
        for i in range(8):
            acc += _mix16(data, 16 * i, 16 * i)
        acc = _avalanche(acc & MASK)
        for i in range(8, n // 16):
            acc += _mix16(data, 16 * i, 16 * (i - 8) + 3)
        acc += _mix16(data, n - 16, 119)
        return _avalanche(acc & MASK)
    acc = [P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1]
    blocks = (n - 1) // 1024
    for block in range(blocks):
        for s in range(16):
            _stripe(acc, data, block * 1024 + s * 64, s * 8)
        keys = struct.unpack_from("<8Q", SECRET, 128)
        for i in range(8):
            a = acc[i]
            acc[i] = (((a ^ (a >> 47)) ^ keys[i]) * P32_1) & MASK
    for s in range(((n - 1) - 1024 * blocks) // 64):
        _stripe(acc, data, blocks * 1024 + s * 64, s * 8)
    _stripe(acc, data, n - 64, 121)
    h = (n * P64_1) & MASK
    for i in range(4):
        h += _fold(acc[2 * i] ^ _u64(SECRET, 11 + 16 * i), acc[2 * i + 1] ^ _u64(SECRET, 19 + 16 * i))
    return _avalanche(h & MASK)


# =================================================================================================
# Cryptography for encrypted (§12) and signed (§13) archives, from the published standards, over
# Python's integers and hashlib (SHA-2, SHA-3, SHAKE, BLAKE2b). Each part names its standard.
# =================================================================================================


def sha256(data):
    return hashlib.sha256(data).digest()


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# AES (FIPS 197) and AES-256-GCM (NIST SP 800-38D), §12.1.
#
# `encrypt_block` is AES a block at a time. `_ctr_wide` encrypts every counter block of up to
# 1 MiB at once: the state is four integers, one per AES row, each holding that row's four bytes
# of every block, so SubBytes is one bytes.translate, ShiftRows a rotation inside each 32-bit
# lane, and MixColumns a few shifts and XORs, each over the whole buffer. GHASH uses Shoup's
# 8-bit tables, 16 lookups a block.

M32 = 0xFFFFFFFF
WIDE_BLOCKS = 65536  # 1 MiB a pass


class AuthError(Exception):
    """An AEAD tag that doesn't match: a wrong key, or changed bytes."""


def _xt(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _make_sbox():
    exp, log, x = [0] * 255, [0] * 256, 1
    for i in range(255):
        exp[i], log[x] = x, i
        x ^= _xt(x)  # times the generator 3
    sbox = bytearray(256)
    for a in range(256):
        inv = exp[(255 - log[a]) % 255] if a else 0
        s = inv
        for k in range(1, 5):
            s ^= ((inv << k) | (inv >> (8 - k))) & 0xFF
        sbox[a] = s ^ 0x63
    return bytes(sbox)


SBOX = _make_sbox()
INV_SBOX = bytes(SBOX.index(i) for i in range(256))


def expand_key(key):
    """AES's round keys, as 16-byte strings."""
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("an AES key is 16, 24 or 32 bytes")
    rounds = nk + 6
    w = [key[4 * i : 4 * i + 4] for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = bytes((SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]))
            rcon = _xt(rcon)
        elif nk > 6 and i % nk == 4:
            t = bytes(SBOX[b] for b in t)
        w.append(_xor(w[i - nk], t))
    return [b"".join(w[4 * r : 4 * r + 4]) for r in range(rounds + 1)]


def encrypt_block(rks, block):
    s = bytearray(_xor(block, rks[0]))
    for rnd in range(1, len(rks)):
        s = bytearray(SBOX[b] for b in s)
        s = bytearray(s[(i + 4 * (i % 4)) % 16] for i in range(16))  # ShiftRows
        if rnd != len(rks) - 1:
            for c in range(0, 16, 4):  # MixColumns
                a0, a1, a2, a3 = s[c : c + 4]
                t = a0 ^ a1 ^ a2 ^ a3
                s[c] ^= t ^ _xt(a0 ^ a1)
                s[c + 1] ^= t ^ _xt(a1 ^ a2)
                s[c + 2] ^= t ^ _xt(a2 ^ a3)
                s[c + 3] ^= t ^ _xt(a3 ^ a0)
        s = bytearray(_xor(s, rks[rnd]))
    return bytes(s)


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = (a << 1) ^ (0x11B if a & 0x80 else 0)
        b >>= 1
    return r


def decrypt_block(rks, block):
    """AES's inverse cipher, for key files under a password (AES-CBC, PBES2)."""
    s = bytearray(_xor(block, rks[-1]))
    for rnd in range(len(rks) - 2, -1, -1):
        s = bytearray(INV_SBOX[s[(i - 4 * (i % 4)) % 16]] for i in range(16))  # InvShiftRows, InvSubBytes
        s = bytearray(_xor(s, rks[rnd]))
        if rnd:
            for c in range(0, 16, 4):  # InvMixColumns
                a = s[c : c + 4]
                for i in range(4):
                    s[c + i] = (_gmul(a[i], 14) ^ _gmul(a[(i + 1) % 4], 11)
                                ^ _gmul(a[(i + 2) % 4], 13) ^ _gmul(a[(i + 3) % 4], 9))  # fmt: skip
    return bytes(s)


def _ctr_simple(rks, j0, data):
    prefix, c0 = j0[:12], int.from_bytes(j0[12:], "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        ctr = prefix + ((c0 + 1 + i // 16) & M32).to_bytes(4, "big")
        out += _xor(data[i : i + 16], encrypt_block(rks, ctr))
    return bytes(out)


class _Wide:
    """Masks and round keys repeated for n blocks."""

    def __init__(self, rks, n):
        self.n = n
        ones = int.from_bytes(b"\x01\0\0\0" * n, "little")
        self.m7f = ones * 0x7F7F7F7F
        self.m01 = ones * 0x01010101
        self.low = [ones * ((1 << (32 - 8 * r)) - 1) for r in range(4)]
        self.high = [ones * (M32 ^ ((1 << (32 - 8 * r)) - 1)) for r in range(4)]
        self.rk = [
            [ones * int.from_bytes(bytes((k[r], k[r + 4], k[r + 8], k[r + 12])), "little") for r in range(4)]
            for k in rks
        ]


def _encrypt_rows(w, rows):
    nbytes = 4 * w.n
    m7f, m01, low, high = w.m7f, w.m01, w.low, w.high
    s0, s1, s2, s3 = (rows[r] ^ w.rk[0][r] for r in range(4))
    last = len(w.rk) - 1
    for rnd in range(1, last + 1):
        s0, s1, s2, s3 = (  # SubBytes
            int.from_bytes(x.to_bytes(nbytes, "little").translate(SBOX), "little") for x in (s0, s1, s2, s3)
        )
        # ShiftRows: row r moves left by r columns, a rotation inside each 32-bit lane.
        s1 = ((s1 >> 8) & low[1]) | ((s1 << 24) & high[1])
        s2 = ((s2 >> 16) & low[2]) | ((s2 << 16) & high[2])
        s3 = ((s3 >> 24) & low[3]) | ((s3 << 8) & high[3])
        if rnd != last:
            # MixColumns: b_i = a_i ^ t ^ xtime(a_i ^ a_(i+1)), the rows being the a_i.
            t = s0 ^ s1 ^ s2 ^ s3
            u0, u1, u2, u3 = s0 ^ s1, s1 ^ s2, s2 ^ s3, s3 ^ s0
            s0 ^= t ^ ((u0 & m7f) << 1) ^ (((u0 >> 7) & m01) * 0x1B)
            s1 ^= t ^ ((u1 & m7f) << 1) ^ (((u1 >> 7) & m01) * 0x1B)
            s2 ^= t ^ ((u2 & m7f) << 1) ^ (((u2 >> 7) & m01) * 0x1B)
            s3 ^= t ^ ((u3 & m7f) << 1) ^ (((u3 >> 7) & m01) * 0x1B)
        k = w.rk[rnd]
        s0, s1, s2, s3 = s0 ^ k[0], s1 ^ k[1], s2 ^ k[2], s3 ^ k[3]
    return s0, s1, s2, s3


def _ctr_wide(rks, j0, data, cache):
    prefix, c0 = j0[:12], int.from_bytes(j0[12:], "big")
    out = bytearray()
    for at in range(0, len(data), 16 * WIDE_BLOCKS):
        chunk = data[at : at + 16 * WIDE_BLOCKS]
        n = (len(chunk) + 15) // 16
        w = cache.get(n)
        if w is None:
            w = cache[n] = _Wide(rks, n)
        first = (c0 + 1 + at // 16) & M32  # inc32: the low 32 bits wrap
        if first + n <= 1 << 32:
            ctr = array("I", range(first, first + n))
        else:
            ctr = array("I", [*range(first, 1 << 32), *range(n - ((1 << 32) - first))])
        if ctr.itemsize != 4:
            raise RuntimeError("array('I') isn't 32 bits here")
        if sys.byteorder == "little":
            ctr.byteswap()  # the counters are big-endian
        ctr = ctr.tobytes()
        rows = []
        for r in range(4):
            buf = bytearray(bytes((prefix[r], prefix[r + 4], prefix[r + 8], 0)) * n)
            buf[3::4] = ctr[r::4]
            rows.append(int.from_bytes(buf, "little"))
        rows = _encrypt_rows(w, rows)
        ks = bytearray(16 * n)
        for r in range(4):
            rb = rows[r].to_bytes(4 * n, "little")
            for c in range(4):
                ks[r + 4 * c :: 16] = rb[c::4]
        out += (int.from_bytes(chunk, "big") ^ int.from_bytes(ks[: len(chunk)], "big")).to_bytes(len(chunk), "big")
    return bytes(out)


R_GCM = 0xE1 << 120


def _ghash_tables(hkey):
    """T[k][b] = (byte b at position k) times H, for k = 0..15."""
    v = int.from_bytes(hkey, "big")
    bit = []  # bit[i] = x^i times H
    for _ in range(128):
        bit.append(v)
        v = (v >> 1) ^ R_GCM if v & 1 else v >> 1
    tables = []
    for k in range(16):
        t = [0] * 256
        for b in range(1, 256):
            low = b & -b  # the byte's lowest set bit; its bit 7 is x^(8k)
            t[b] = t[b ^ low] ^ bit[8 * k + 7 - (low.bit_length() - 1)]
        tables.append(t)
    return tables


def _ghash(tables, data):
    """GHASH over data, a multiple of 16 bytes."""
    (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15) = tables
    y = 0
    fb = int.from_bytes
    mv = memoryview(data)
    for i in range(0, len(data), 16):
        y ^= fb(mv[i : i + 16], "big")
        b = y.to_bytes(16, "big")
        y = (
            t0[b[0]] ^ t1[b[1]] ^ t2[b[2]] ^ t3[b[3]] ^ t4[b[4]] ^ t5[b[5]] ^ t6[b[6]] ^ t7[b[7]]
            ^ t8[b[8]] ^ t9[b[9]] ^ t10[b[10]] ^ t11[b[11]] ^ t12[b[12]] ^ t13[b[13]] ^ t14[b[14]] ^ t15[b[15]]
        )  # fmt: skip
    return y


def _pad16(b):
    return bytes(b) + bytes(-len(b) % 16)


class AesGcm:
    """AES-GCM under one key, with 12-byte nonces. A sealed message is the ciphertext and its 16-byte tag."""

    def __init__(self, key, wide=True):
        self.rks = expand_key(key)
        self.tables = _ghash_tables(encrypt_block(self.rks, bytes(16)))
        self.wide = wide
        self._cache = {}

    def _j0(self, iv):
        if len(iv) == 12:
            return bytes(iv) + b"\0\0\0\1"
        if not iv:
            raise ValueError("GCM needs a nonce")
        return _ghash(self.tables, _pad16(iv) + (8 * len(iv)).to_bytes(16, "big")).to_bytes(16, "big")

    def _ctr(self, j0, data):
        if self.wide and len(data) > 256:
            return _ctr_wide(self.rks, j0, data, self._cache)
        return _ctr_simple(self.rks, j0, data)

    def _tag(self, j0, aad, ct):
        lens = (8 * len(aad)).to_bytes(8, "big") + (8 * len(ct)).to_bytes(8, "big")
        s = _ghash(self.tables, _pad16(aad) + _pad16(ct) + lens)
        return (s ^ int.from_bytes(encrypt_block(self.rks, j0), "big")).to_bytes(16, "big")

    def seal(self, iv, plaintext, aad=b""):
        j0 = self._j0(iv)
        ct = self._ctr(j0, plaintext)
        return ct + self._tag(j0, aad, ct)

    def open(self, iv, sealed, aad=b""):
        """The plaintext, once the tag checks; AuthError otherwise."""
        if len(sealed) < 16:
            raise AuthError("shorter than a tag")
        j0 = self._j0(iv)
        ct, tag = sealed[:-16], sealed[-16:]
        if not hmac.compare_digest(self._tag(j0, aad, ct), tag):
            raise AuthError("the tag doesn't match")
        return self._ctr(j0, ct)


# HKDF-SHA256 (RFC 5869), §12.1: Extract, then Expand.


def hkdf_expand(prk, info, length=32):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hkdf(ikm, salt, info, length=32):
    return hkdf_expand(hmac.new(salt, ikm, hashlib.sha256).digest(), info, length)


# Argon2id (RFC 9106), §12.5 kind 1. BLAKE2b comes from hashlib; H' and G are written here.
#
# Memory is one buffer of 1 KiB blocks. G runs as straight-line code over 128 variables made from
# `_G_readable`'s loops (`_make_fast_g`). The lanes of a slice are independent, so above 64 MiB
# each lane runs in a process of its own, over shared memory, waiting for the others at the end
# of every slice.

ARGON2_VERSION, ARGON2ID, SYNC_POINTS = 0x13, 2, 4


def _h_prime(x, outlen):
    """The variable-length hash H' (RFC 9106 §3.3)."""
    x = struct.pack("<I", outlen) + x
    if outlen <= 64:
        return hashlib.blake2b(x, digest_size=outlen).digest()
    r = (outlen + 31) // 32 - 2
    v = hashlib.blake2b(x).digest()
    out = [v[:32]]
    for _ in range(r - 1):
        v = hashlib.blake2b(v).digest()
        out.append(v[:32])
    out.append(hashlib.blake2b(v, digest_size=outlen - 32 * r).digest())
    return b"".join(out)


_P_ORDER = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
            (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))  # fmt: skip
_ROWS = [[16 * i + k for k in range(16)] for i in range(8)]
_COLS = [[2 * i + 16 * (k // 2) + (k % 2) for k in range(16)] for i in range(8)]


def _gb(v, a, b, c, d):
    """BLAKE2b's G with Argon2's multiplications (RFC 9106 §3.6)."""

    def fbla(x, y):
        return (x + y + 2 * (x & M32) * (y & M32)) & MASK

    def rotr(x, n):
        return ((x >> n) | (x << (64 - n))) & MASK

    v[a] = fbla(v[a], v[b])
    v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = fbla(v[c], v[d])
    v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = fbla(v[a], v[b])
    v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = fbla(v[c], v[d])
    v[b] = rotr(v[b] ^ v[c], 63)


def _G_readable(r_words):
    """P on each row of R, then on each column; Z (the caller XORs R back in)."""
    v = list(r_words)
    for group in _ROWS + _COLS:
        for a, b, c, d in _P_ORDER:
            _gb(v, group[a], group[b], group[c], group[d])
    return v


def _make_fast_g():
    """`_G_readable` unrolled into one function."""
    lines = ["def _G(r):", "    (" + ", ".join(f"w{i}" for i in range(128)) + ",) = r"]
    for group in _ROWS + _COLS:
        for a, b, c, d in _P_ORDER:
            a, b, c, d = (f"w{group[k]}" for k in (a, b, c, d))
            for x, y, z, rot in ((a, b, d, 32), (c, d, b, 24), (a, b, d, 16), (c, d, b, 63)):
                lines.append(f"    {x} = ({x} + {y} + ((({x} & {M32}) * ({y} & {M32})) << 1)) & {MASK}")
                lines.append(f"    {z} ^= {x}")
                lines.append(f"    {z} = (({z} >> {rot}) | ({z} << {64 - rot})) & {MASK}")
    lines.append("    return (" + ", ".join(f"w{i}" for i in range(128)) + ",)")
    ns = {}
    exec(compile("\n".join(lines), "<argon2 G>", "exec"), ns)
    return ns["_G"]


_G = _make_fast_g()
_PACK = struct.Struct("<128Q")


def _fill(mem, prev, ref, cur, xor_old, g):
    """mem[cur] = G(mem[prev], mem[ref]), XORed into the old mem[cur] after the first pass."""
    fb = int.from_bytes
    rx = fb(mem[prev : prev + 1024], "little") ^ fb(mem[ref : ref + 1024], "little")
    z = fb(_PACK.pack(*g(_PACK.unpack(rx.to_bytes(1024, "little")))), "little") ^ rx
    if xor_old:
        z ^= fb(mem[cur : cur + 1024], "little")
    mem[cur : cur + 1024] = z.to_bytes(1024, "little")


def _g2(words, g):
    """G(0, G(0, block)), for the data-independent addresses."""
    for _ in range(2):
        words = [a ^ b for a, b in zip(g(words), words)]
    return words


def _argon2_segment(mem, pas, sl, lane, p, t, m, q, seg, g=_G):
    """Fills one lane's segment of one slice (RFC 9106 §3.4)."""
    independent = pas == 0 and sl < SYNC_POINTS // 2
    start = 2 if pas == 0 and sl == 0 else 0
    if independent:
        inp = [pas, lane, sl, m, t, ARGON2ID, 0] + [0] * 121
        addresses = None
    for idx in range(start, seg):
        col = sl * seg + idx
        cur = 1024 * (lane * q + col)
        prev = cur - 1024 if col else 1024 * (lane * q + q - 1)
        if independent:
            if addresses is None or idx % 128 == 0:
                inp[6] += 1
                addresses = _g2(inp, g)
            rand = addresses[idx % 128]
        else:
            rand = struct.unpack_from("<Q", mem, prev)[0]
        ref_lane = lane if pas == 0 and sl == 0 else (rand >> 32) % p
        same = ref_lane == lane
        if pas == 0:
            area = sl * seg + idx - 1 if same else sl * seg - (1 if idx == 0 else 0)
            first = 0
        else:
            area = q - seg + idx - 1 if same else q - seg - (1 if idx == 0 else 0)
            first = 0 if sl == SYNC_POINTS - 1 else (sl + 1) * seg
        x = ((rand & M32) * (rand & M32)) >> 32
        rel = area - 1 - ((area * x) >> 32)
        _fill(mem, prev, 1024 * (ref_lane * q + (first + rel) % q), cur, pas > 0, g)


def _argon2_lane(name, lane, p, t, m, q, seg, barrier):
    """One lane, in a process of its own."""
    from multiprocessing import shared_memory

    shm = shared_memory.SharedMemory(name=name, track=False)
    try:
        mem = shm.buf
        for pas in range(t):
            for sl in range(SYNC_POINTS):
                _argon2_segment(mem, pas, sl, lane, p, t, m, q, seg)
                barrier.wait()
        del mem
    finally:
        shm.close()


def argon2id(password, salt, t, m_kib, p, tag_len=32, secret=b"", ad=b"", processes=None, readable=False):
    """Argon2id's tag. `processes`: a process per lane (by default above 64 MiB, when there's more than one CPU)."""
    h0 = hashlib.blake2b(
        struct.pack("<6I", p, tag_len, m_kib, t, ARGON2_VERSION, ARGON2ID)
        + struct.pack("<I", len(password)) + password
        + struct.pack("<I", len(salt)) + salt
        + struct.pack("<I", len(secret)) + secret
        + struct.pack("<I", len(ad)) + ad
    ).digest()  # fmt: skip
    m = 4 * p * (m_kib // (4 * p))  # whole segments
    q = m // p
    seg = q // SYNC_POINTS
    if processes is None:
        processes = p > 1 and m_kib >= 1 << 16 and (os.cpu_count() or 1) > 1 and not readable

    def first_blocks(mem):
        for lane in range(p):
            for j in (0, 1):
                off = 1024 * (lane * q + j)
                mem[off : off + 1024] = _h_prime(h0 + struct.pack("<II", j, lane), 1024)

    def final_tag(mem):
        c = 0
        for lane in range(p):
            off = 1024 * (lane * q + q - 1)
            c ^= int.from_bytes(mem[off : off + 1024], "little")
        return _h_prime(c.to_bytes(1024, "little"), tag_len)

    if not processes:
        g = _G_readable if readable else _G
        mem = bytearray(1024 * m)
        first_blocks(mem)
        for pas in range(t):
            for sl in range(SYNC_POINTS):
                for lane in range(p):
                    _argon2_segment(mem, pas, sl, lane, p, t, m, q, seg, g)
        return final_tag(mem)

    import multiprocessing
    from multiprocessing import shared_memory

    shm = shared_memory.SharedMemory(create=True, size=1024 * m)
    try:
        mem = shm.buf
        first_blocks(mem)
        barrier = multiprocessing.Barrier(p)
        workers = [
            multiprocessing.Process(target=_argon2_lane, args=(shm.name, lane, p, t, m, q, seg, barrier))
            for lane in range(p)
        ]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        if any(w.exitcode for w in workers):
            raise RuntimeError("an Argon2 lane's process failed")
        tag = final_tag(mem)
        del mem
        return tag
    finally:
        shm.close()
        shm.unlink()


# X25519 (RFC 7748 §5), §12.5 kind 3: the Montgomery ladder.

X_P = 2**255 - 19


def x25519(scalar, u_bytes):
    if len(scalar) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 takes 32-byte inputs")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)  # the top bit is masked (§5)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = x2 + z2, x2 - z2
        aa, bb = a * a % X_P, b * b % X_P
        e = aa - bb
        c, d = x3 + z3, x3 - z3
        da, cb = d * a % X_P, c * b % X_P
        x3 = (da + cb) ** 2 % X_P
        z3 = x1 * (da - cb) ** 2 % X_P
        x2 = aa * bb % X_P
        z2 = e * (aa + 121665 * e) % X_P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, X_P - 2, X_P) % X_P).to_bytes(32, "little")


def x25519_public(private):
    return x25519(private, (9).to_bytes(32, "little"))


# ML-KEM-768 (FIPS 203) and X-Wing (draft-connolly-cfrg-xwing-kem-10), §12.5 kind 4.
# KeyGen from a seed, Encaps with its randomness given, Decaps with implicit rejection.

KQ = 3329
KK, KETA1, KETA2, KDU, KDV = 3, 2, 2, 10, 4
MLKEM_EK_LEN = 384 * KK + 32  # 1184
MLKEM_CT_LEN = 32 * (KDU * KK + KDV)  # 1088


def _brv(i, bits):
    return int(f"{i:0{bits}b}"[::-1], 2)


KZETAS = [pow(17, _brv(i, 7), KQ) for i in range(128)]
KGAMMAS = [pow(17, 2 * _brv(i, 7) + 1, KQ) for i in range(128)]


def _kG(x):
    d = hashlib.sha3_512(x).digest()
    return d[:32], d[32:]


def _kH(x):
    return hashlib.sha3_256(x).digest()


def _kprf(eta, s, b):
    return hashlib.shake_256(s + bytes((b,))).digest(64 * eta)


def _kntt(f):
    f, i, length = list(f), 1, 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            z = KZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = z * f[j + length] % KQ
                f[j + length] = (f[j] - t) % KQ
                f[j] = (f[j] + t) % KQ
        length >>= 1
    return f


def _kintt(f):
    f, i, length = list(f), 127, 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            z = KZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % KQ
                f[j + length] = z * (f[j + length] - t) % KQ
        length <<= 1
    return [x * 3303 % KQ for x in f]  # 3303 = 128^-1


def _kdot(avec, bvec):
    """The sum of avec[j] times bvec[j], in the NTT domain (FIPS 203 Algorithm 11)."""
    out = [0] * 256
    for i in range(128):
        g = KGAMMAS[i]
        c0 = c1 = 0
        for a, b in zip(avec, bvec):
            a0, a1, b0, b1 = a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1]
            c0 += a0 * b0 + a1 * b1 * g
            c1 += a0 * b1 + a1 * b0
        out[2 * i], out[2 * i + 1] = c0 % KQ, c1 % KQ
    return out


def _ksample_ntt(seed34):
    """FIPS 203 Algorithm 7, rejection sampling from SHAKE128."""
    xof, n = hashlib.shake_128(seed34), 840
    buf, pos, out = xof.digest(n), 0, []
    while True:
        while pos + 3 <= n:
            b0, b1, b2 = buf[pos], buf[pos + 1], buf[pos + 2]
            pos += 3
            for d in (b0 | ((b1 & 15) << 8), (b1 >> 4) | (b2 << 4)):
                if d < KQ:
                    out.append(d)
                    if len(out) == 256:
                        return out
        n *= 2
        buf = xof.digest(n)


def _kcbd2(data):
    """FIPS 203 Algorithm 8 for eta = 2: 128 bytes to 256 coefficients."""
    out = []
    for b in data:
        out.append(((b & 1) + (b >> 1 & 1) - (b >> 2 & 1) - (b >> 3 & 1)) % KQ)
        out.append(((b >> 4 & 1) + (b >> 5 & 1) - (b >> 6 & 1) - (b >> 7 & 1)) % KQ)
    return out


def _kmatrix(rho, transpose=False):
    a = [[_ksample_ntt(rho + bytes((j, i))) for j in range(KK)] for i in range(KK)]
    return [list(col) for col in zip(*a)] if transpose else a


def _pack(f, bits):
    x = 0
    for c in reversed(f):
        x = (x << bits) | c
    return x.to_bytes(32 * bits, "little")


def _unpack(b, bits):
    x, mask = int.from_bytes(b, "little"), (1 << bits) - 1
    return [(x >> (bits * i)) & mask for i in range(256)]


def _kcompress(f, d):
    return [((c << d) + KQ // 2) // KQ & ((1 << d) - 1) for c in f]


def _kdecompress(f, d):
    return [(c * KQ + (1 << (d - 1))) >> d for c in f]


def _kvec_encode(v):
    return b"".join(_pack(p, 12) for p in v)


def _kvec_decode(b):
    return [[c % KQ for c in _unpack(b[384 * i : 384 * (i + 1)], 12)] for i in range(KK)]


def _kpke_encrypt(ek, m, r):
    t = _kvec_decode(ek[: 384 * KK])
    at = _kmatrix(ek[384 * KK :], transpose=True)
    y = [_kntt(_kcbd2(_kprf(KETA1, r, i))) for i in range(KK)]
    e1 = [_kcbd2(_kprf(KETA2, r, KK + i)) for i in range(KK)]
    e2 = _kcbd2(_kprf(KETA2, r, 2 * KK))
    u = [[(x + z) % KQ for x, z in zip(_kintt(_kdot(at[i], y)), e1[i])] for i in range(KK)]
    mu = _kdecompress(_unpack(m, 1), 1)
    v = [(x + z + w) % KQ for x, z, w in zip(_kintt(_kdot(t, y)), e2, mu)]
    return b"".join(_pack(_kcompress(p, KDU), KDU) for p in u) + _pack(_kcompress(v, KDV), KDV)


def mlkem_keygen(seed):
    """(ek, dk) from the 64-byte seed d || z (FIPS 203 Algorithm 16)."""
    d, z = seed[:32], seed[32:64]
    rho, sigma = _kG(d + bytes((KK,)))
    a = _kmatrix(rho)
    s = [_kntt(_kcbd2(_kprf(KETA1, sigma, i))) for i in range(KK)]
    e = [_kntt(_kcbd2(_kprf(KETA1, sigma, KK + i))) for i in range(KK)]
    t = [[(x + y) % KQ for x, y in zip(_kdot(a[i], s), e[i])] for i in range(KK)]
    ek = _kvec_encode(t) + rho
    return ek, _kvec_encode(s) + ek + _kH(ek) + z


def mlkem_encaps(ek, m):
    """(K, ciphertext) for the 32 bytes of randomness m (FIPS 203 Algorithm 17), ek checked first."""
    if len(ek) != MLKEM_EK_LEN or _kvec_encode(_kvec_decode(ek[: 384 * KK])) != ek[: 384 * KK]:
        raise ValueError("not an ML-KEM-768 encapsulation key")
    k, r = _kG(m + _kH(ek))
    return k, _kpke_encrypt(ek, m, r)


def mlkem_decaps(dk, c):
    """K for the ciphertext c, or the implicit rejection's (FIPS 203 Algorithm 18)."""
    if len(c) != MLKEM_CT_LEN or len(dk) != 768 * KK + 96:
        raise ValueError("an ML-KEM-768 input of the wrong length")
    dk_pke, ek = dk[: 384 * KK], dk[384 * KK : 768 * KK + 32]
    h, z = dk[768 * KK + 32 : 768 * KK + 64], dk[768 * KK + 64 :]
    if _kH(ek) != h:
        raise ValueError("an ML-KEM decapsulation key whose hash doesn't check")
    u = [_kdecompress(_unpack(c[320 * i : 320 * (i + 1)], KDU), KDU) for i in range(KK)]
    v = _kdecompress(_unpack(c[320 * KK :], KDV), KDV)
    s = _kvec_decode(dk_pke)
    w = [(x - y) % KQ for x, y in zip(v, _kintt(_kdot(s, [_kntt(p) for p in u])))]
    m = _pack(_kcompress(w, 1), 1)
    k, r = _kG(m + h)
    rejected = hashlib.shake_256(z + c).digest(32)
    return k if hmac.compare_digest(_kpke_encrypt(ek, m, r), c) else rejected


XWING_LABEL = b"\\.//^\\"


def _xwing_expand(sk):
    e = hashlib.shake_256(sk).digest(96)
    ek_m, dk_m = mlkem_keygen(e[:64])
    sk_x = e[64:96]
    return dk_m, sk_x, ek_m, x25519_public(sk_x)


def xwing_public(sk):
    """The 1,216-byte X-Wing public key of a 32-byte private key."""
    _, _, ek_m, pk_x = _xwing_expand(sk)
    return ek_m + pk_x


def _xwing_combine(ss_m, ss_x, ct_x, pk_x):
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def xwing_encaps(pk, eseed):
    """(shared secret, ciphertext) for the 64 bytes of randomness eseed; for writing test files."""
    pk_m, pk_x = pk[:1184], pk[1184:1216]
    ct_x = x25519_public(eseed[32:64])
    ss_m, ct_m = mlkem_encaps(pk_m, eseed[:32])
    return _xwing_combine(ss_m, x25519(eseed[32:64], pk_x), ct_x, pk_x), ct_m + ct_x


def xwing_decaps(sk, ct):
    if len(ct) != 1120 or len(sk) != 32:
        raise ValueError("an X-Wing input of the wrong length")
    dk_m, sk_x, _, pk_x = _xwing_expand(sk)
    ct_m, ct_x = ct[:1088], ct[1088:]
    return _xwing_combine(mlkem_decaps(dk_m, ct_m), x25519(sk_x, ct_x), ct_x, pk_x)


# P-256 and P-384 (SEC 1, FIPS 186-5): ECDH for §12.5 kinds 6 and 7, ECDSA for §13.4
# algorithms 4 and 5. Jacobian coordinates; the cofactor is 1, so a point on the curve is enough.


class Curve:
    def __init__(self, name, oid, p, b, gx, gy, n, hash_name):
        self.name, self.oid, self.p, self.a, self.b, self.g, self.n = name, oid, p, -3, b, (gx, gy), n
        self.size = (p.bit_length() + 7) // 8
        self.hash_name = hash_name


P256 = Curve(
    "P-256", "1.2.840.10045.3.1.7",
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "sha256",
)  # fmt: skip
P384 = Curve(
    "P-384", "1.3.132.0.34",
    2**384 - 2**128 - 2**96 + 2**32 - 1,
    0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    "sha384",
)  # fmt: skip
CURVES = {c.oid: c for c in (P256, P384)}


def _double(c, X, Y, Z):
    p = c.p
    if not Y or not Z:
        return 0, 1, 0
    zz = Z * Z % p
    m = 3 * (X - zz) * (X + zz) % p  # a = -3
    yy = Y * Y % p
    s = 4 * X * yy % p
    x3 = (m * m - 2 * s) % p
    return x3, (m * (s - x3) - 8 * yy * yy) % p, 2 * Y * Z % p


def _add(c, X1, Y1, Z1, X2, Y2, Z2):
    p = c.p
    if not Z1:
        return X2, Y2, Z2
    if not Z2:
        return X1, Y1, Z1
    z1z1, z2z2 = Z1 * Z1 % p, Z2 * Z2 % p
    u1, u2 = X1 * z2z2 % p, X2 * z1z1 % p
    s1, s2 = Y1 * Z2 * z2z2 % p, Y2 * Z1 * z1z1 % p
    hh, r = (u2 - u1) % p, (s2 - s1) % p
    if not hh:
        return _double(c, X1, Y1, Z1) if not r else (0, 1, 0)
    h2 = hh * hh % p
    h3 = hh * h2 % p
    v = u1 * h2 % p
    x3 = (r * r - h3 - 2 * v) % p
    return x3, (r * (v - x3) - s1 * h3) % p, Z1 * Z2 * hh % p


def _jmul(c, k, point):
    x, y = point
    R = (0, 1, 0)
    for bit in bin(k)[2:]:
        R = _double(c, *R)
        if bit == "1":
            R = _add(c, *R, x, y, 1)
    return R


def _affine(c, R):
    X, Y, Z = R
    if not Z:
        return None
    zi = pow(Z, -1, c.p)
    return X * zi * zi % c.p, Y * zi * zi * zi % c.p


def ec_multiply(c, k, point):
    """k times point, affine in and out; None for the point at infinity."""
    return _affine(c, _jmul(c, k, point))


def ec_point(c, data):
    """An uncompressed point, 04 || x || y, on the curve (SEC 1 §2.3.4); None otherwise."""
    n = c.size
    if len(data) != 1 + 2 * n or data[0] != 4:
        return None
    x, y = int.from_bytes(data[1 : 1 + n], "big"), int.from_bytes(data[1 + n :], "big")
    if not (x < c.p and y < c.p and (y * y - x * x * x - c.a * x - c.b) % c.p == 0):
        return None
    return x, y


def ec_encode(c, point):
    return b"\x04" + point[0].to_bytes(c.size, "big") + point[1].to_bytes(c.size, "big")


def ecdh_x(c, d, point):
    """The x-coordinate of d times point, big-endian (SEC 1 §3.3.1)."""
    r = ec_multiply(c, d, point)
    if r is None:
        raise ValueError("an ECDH result at infinity")
    return r[0].to_bytes(c.size, "big")


def ecdsa_verify(c, point, message, signature):
    """ECDSA (FIPS 186-5 §6.4.2) of message under the curve's hash, the signature r || s."""
    n, size = c.n, c.size
    if len(signature) != 2 * size:
        return False
    r, s = int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
    if not (0 < r < n and 0 < s < n):
        return False
    digest = hashlib.new(c.hash_name, message).digest()
    e = int.from_bytes(digest, "big") >> max(0, 8 * len(digest) - n.bit_length())
    w = pow(s, -1, n)
    x = _affine(c, _add(c, *_jmul(c, e * w % n, c.g), *_jmul(c, r * w % n, point)))
    return x is not None and x[0] % n == r


# RSA (RFC 8017): RSAES-OAEP for §12.5 kind 5; RSASSA-PSS and RSASSA-PKCS1-v1_5 for §13.4
# algorithms 2 and 3. SHA-256 throughout, MGF1 with SHA-256, an empty label, a 32-byte salt.


class RsaKey:
    def __init__(self, n, e, d, p, q, dp, dq, qinv):
        self.n, self.e, self.d, self.p, self.q, self.dp, self.dq, self.qinv = n, e, d, p, q, dp, dq, qinv
        self.size = (n.bit_length() + 7) // 8


def _mgf1(seed, length):
    out, i = b"", 0
    while len(out) < length:
        out += sha256(seed + i.to_bytes(4, "big"))
        i += 1
    return out[:length]


def rsa_oaep_decrypt(key, ct):
    """The message (RFC 8017 §7.1.2), or None: one answer for every kind of failure."""
    k = key.size
    if len(ct) != k or k < 66:
        return None
    c = int.from_bytes(ct, "big")
    if c >= key.n:
        return None
    m1, m2 = pow(c, key.dp, key.p), pow(c, key.dq, key.q)
    em = (m2 + (key.qinv * (m1 - m2) % key.p) * key.q).to_bytes(k, "big")
    seed = _xor(em[1:33], _mgf1(em[33:], 32))
    db = _xor(em[33:], _mgf1(seed, k - 33))
    rest = db[32:].lstrip(b"\0")
    if not (hmac.compare_digest(db[:32], sha256(b"")) and em[0] == 0 and rest[:1] == b"\x01"):
        return None
    return rest[1:]


def rsa_pss_verify(n, e, message, signature):
    """RSASSA-PSS-VERIFY (§8.1.2) with EMSA-PSS (§9.1.2): SHA-256, MGF1 with SHA-256, salt 32."""
    if len(signature) != (n.bit_length() + 7) // 8:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    m = pow(s, e, n)
    if m.bit_length() > em_bits or em_len < 32 + 32 + 2:
        return False
    em = m.to_bytes(em_len, "big")
    if em[-1] != 0xBC:
        return False
    masked, h = em[: em_len - 33], em[em_len - 33 : -1]
    zero_bits = 8 * em_len - em_bits
    if zero_bits and masked[0] >> (8 - zero_bits):
        return False
    db = bytearray(_xor(masked, _mgf1(h, em_len - 33)))
    db[0] &= 0xFF >> zero_bits
    pad = em_len - 32 - 32 - 2
    if db[:pad] != bytes(pad) or db[pad] != 1:
        return False
    return hmac.compare_digest(sha256(bytes(8) + sha256(message) + db[-32:]), h)


SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_pkcs1_verify(n, e, message, signature):
    """RSASSA-PKCS1-v1_5-VERIFY (§8.2.2) with SHA-256."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    t = SHA256_DIGEST_INFO + sha256(message)
    want = b"\0\x01" + b"\xff" * (k - len(t) - 3) + b"\0" + t
    return hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), want)


# Ed25519 (RFC 8032), §13.4 algorithm 1, checked as ring 0.17 checks it (bhive.md §13.4): the
# equation without the cofactor, [S]B = R + [k]A, with S below the group order and R compared to
# the canonical encoding of [S]B - [k]A, so a non-canonical R fails. A is decoded as BoringSSL's
# ge_frombytes_vartime decodes it: y may be p or more, and x = 0 may carry either sign; A of
# small order is allowed. k hashes the signature's and the key's bytes as they are given.

ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, -1, ED_P) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
ED_ZERO = (0, 1, 1, 0)


def _ed_add(P, Q):
    """Extended coordinates, a = -1 (RFC 8032 §5.1.4); complete, so it doubles too."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % ED_P
    b = (y1 + x1) * (y2 + x2) % ED_P
    c = 2 * t1 * t2 * ED_D % ED_P
    d = 2 * z1 * z2 % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P


def _ed_mul(k, P):
    Q = ED_ZERO
    while k:
        if k & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        k >>= 1
    return Q


def _ed_encode(P):
    x, y, z, _ = P
    zi = pow(z, -1, ED_P)
    x, y = x * zi % ED_P, y * zi % ED_P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _ed_decode(s):
    """A point from 32 bytes, leniently as ring takes a public key; None if there's none."""
    y = (int.from_bytes(s, "little") & ((1 << 255) - 1)) % ED_P
    u, v = (y * y - 1) % ED_P, (ED_D * y * y + 1) % ED_P
    x = u * pow(v, 3, ED_P) * pow(u * pow(v, 7, ED_P), (ED_P - 5) // 8, ED_P) % ED_P
    vxx = v * x * x % ED_P
    if vxx != u:
        if vxx != (-u) % ED_P:
            return None
        x = x * ED_SQRT_M1 % ED_P
    if x & 1 != s[31] >> 7:
        x = (-x) % ED_P
    return x, y, 1, x * y % ED_P


ED_B = _ed_decode((4 * pow(5, -1, ED_P) % ED_P).to_bytes(32, "little"))


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= ED_L:
        return False
    a = _ed_decode(public)
    if a is None:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % ED_L
    minus_a = ((-a[0]) % ED_P, a[1], a[2], (-a[3]) % ED_P)
    return _ed_encode(_ed_add(_ed_mul(s, ED_B), _ed_mul(k, minus_a))) == signature[:32]


# ML-DSA-65 verification (FIPS 204 Algorithms 3 and 8), §13.4 algorithm 1.

DQ, D_BITS = 8380417, 13
TAU, LAMBDA, GAMMA1, GAMMA2, DK, DL, ETA, OMEGA = 49, 192, 1 << 19, (8380417 - 1) // 32, 6, 5, 4, 55
BETA = TAU * ETA
MLDSA_PUBLIC_LEN = 32 + 320 * DK  # 1,952
MLDSA_SIGNATURE_LEN = LAMBDA // 4 + 640 * DL + OMEGA + DK  # 3,309
DZETAS = [pow(1753, _brv(i, 8), DQ) for i in range(256)]


def _dntt(w):
    """FIPS 204 Algorithm 41."""
    w, m, length = list(w), 0, 128
    while length >= 1:
        for start in range(0, 256, 2 * length):
            m += 1
            z = DZETAS[m]
            for j in range(start, start + length):
                t = z * w[j + length] % DQ
                w[j + length] = (w[j] - t) % DQ
                w[j] = (w[j] + t) % DQ
        length //= 2
    return w


def _dintt(w):
    """FIPS 204 Algorithm 42."""
    w, m, length = list(w), 256, 1
    while length < 256:
        for start in range(0, 256, 2 * length):
            m -= 1
            z = DQ - DZETAS[m]
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % DQ
                w[j + length] = z * (t - w[j + length]) % DQ
        length *= 2
    return [x * 8347681 % DQ for x in w]  # 8347681 = 256^-1


def _rej_ntt_poly(seed):
    """FIPS 204 Algorithm 30, from SHAKE128."""
    xof, n = hashlib.shake_128(seed), 840
    buf, pos, out = xof.digest(n), 0, []
    while len(out) < 256:
        if pos + 3 > n:
            n *= 2
            buf = xof.digest(n)
        z = buf[pos] | buf[pos + 1] << 8 | (buf[pos + 2] & 0x7F) << 16
        pos += 3
        if z < DQ:
            out.append(z)
    return out


def _sample_in_ball(seed):
    """FIPS 204 Algorithm 29: TAU coefficients of +1 or -1, from SHAKE256."""
    xof, n = hashlib.shake_256(seed), 136
    buf = xof.digest(n)
    signs, pos, c = int.from_bytes(buf[:8], "little"), 8, [0] * 256
    for i in range(256 - TAU, 256):
        while True:
            if pos >= n:
                n *= 2
                buf = xof.digest(n)
            j = buf[pos]
            pos += 1
            if j <= i:
                break
        c[i] = c[j]
        c[j] = DQ - 1 if (signs >> (i + TAU - 256)) & 1 else 1
    return c


def _hint_unpack(y):
    """FIPS 204 Algorithm 21; None for a malformed hint."""
    h, index = [[0] * 256 for _ in range(DK)], 0
    for i in range(DK):
        if y[OMEGA + i] < index or y[OMEGA + i] > OMEGA:
            return None
        first = index
        while index < y[OMEGA + i]:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    if any(y[index:OMEGA]):
        return None
    return h


def _use_hint(h, r):
    """FIPS 204 Algorithms 36 and 40, for GAMMA2 = (q - 1) / 32."""
    r0 = r % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if r - r0 == DQ - 1:
        r1, r0 = 0, r0 - 1
    else:
        r1 = (r - r0) // (2 * GAMMA2)
    if h:
        return (r1 + 1) % 16 if r0 > 0 else (r1 - 1) % 16
    return r1


def mldsa65_verify(public, message, signature, context=b""):
    """ML-DSA.Verify of message with its context string."""
    if len(public) != MLDSA_PUBLIC_LEN or len(signature) != MLDSA_SIGNATURE_LEN or len(context) > 255:
        return False
    rho = public[:32]
    t1 = [_unpack(public[32 + 320 * i : 32 + 320 * (i + 1)], 10) for i in range(DK)]
    c_tilde = signature[: LAMBDA // 4]
    at = LAMBDA // 4
    z = [[GAMMA1 - v for v in _unpack(signature[at + 640 * i : at + 640 * (i + 1)], 20)] for i in range(DL)]
    h = _hint_unpack(signature[at + 640 * DL :])
    if h is None or max(abs(x) for p in z for x in p) >= GAMMA1 - BETA:
        return False
    tr = hashlib.shake_256(public).digest(64)
    mu = hashlib.shake_256(tr + bytes([0, len(context)]) + context + message).digest(64)
    c = _dntt(_sample_in_ball(c_tilde))
    zh = [_dntt([x % DQ for x in p]) for p in z]
    w1 = b""
    for r in range(DK):
        t1h = _dntt([(x << D_BITS) % DQ for x in t1[r]])
        acc = [-ci * ti for ci, ti in zip(c, t1h)]
        for s in range(DL):
            a = _rej_ntt_poly(rho + bytes([s, r]))
            acc = [x + ai * zi for x, ai, zi in zip(acc, a, zh[s])]
        w = _dintt([x % DQ for x in acc])
        w1 += _pack([_use_hint(hb, x) for hb, x in zip(h[r], w)], 4)
    return hmac.compare_digest(c_tilde, hashlib.shake_256(mu + w1).digest(LAMBDA // 4))


# DER (X.690), just enough for key files, SubjectPublicKeyInfo and certificates (RFC 5280).

OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"


def der(data, at=0):
    """The element at `at`: (tag, contents, where the next one starts)."""
    if at + 2 > len(data):
        raise ValueError("DER that ends early")
    tag, n = data[at], data[at + 1]
    at += 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4 or at + k > len(data):
            raise ValueError("a DER length this reader doesn't take")
        n = int.from_bytes(data[at : at + k], "big")
        at += k
    if at + n > len(data):
        raise ValueError("a DER element that runs past its end")
    return tag, bytes(data[at : at + n]), at + n


def der_items(contents):
    out, at = [], 0
    while at < len(contents):
        tag, v, at = der(contents, at)
        out.append((tag, v))
    return out


def der_one(data, tag):
    """The contents of the one element that data holds, which must have this tag."""
    t, v, end = der(data)
    if t != tag or end != len(data):
        raise ValueError("not the DER element expected")
    return v


def der_oid(v):
    parts, n = [v[0] // 40, v[0] % 40], 0
    for b in v[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def der_int(v):
    return int.from_bytes(v, "big", signed=True)


def spki_key(contents):
    """A SubjectPublicKeyInfo's key, from its contents: ("rsa", n, e), ("ec", curve, point bytes), or (oid,)."""
    items = der_items(contents)
    alg = der_items(items[0][1])
    oid = der_oid(alg[0][1])
    bits = items[1][1]
    if items[1][0] != 0x03 or not bits or bits[0]:
        raise ValueError("a public key that isn't a whole BIT STRING")
    if oid == OID_RSA:
        n, e = (der_int(v) for _, v in der_items(der_one(bits[1:], 0x30)))
        return "rsa", n, e
    if oid == OID_EC:
        curve = CURVES.get(der_oid(alg[1][1])) if len(alg) > 1 and alg[1][0] == 0x06 else None
        return ("ec", curve, bits[1:]) if curve else (f"{oid} on another curve",)
    return (oid,)


NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
             "1.2.840.113549.1.9.1": "E"}  # fmt: skip


def der_name(contents):
    parts = []
    for _, rdn in der_items(contents):
        for _, atv in der_items(rdn):
            (_, oid), (tag, v) = der_items(atv)[:2]
            text = v.decode("utf-16-be" if tag == 0x1E else "utf-8", "replace")
            parts.append(f"{NAME_OIDS.get(der_oid(oid), der_oid(oid))}={text}")
    return ", ".join(parts)


def certificate(data):
    """An X.509 certificate's subject, issuer and public key (its chain isn't checked)."""
    tbs = der_items(der_items(der_one(data, 0x30))[0][1])
    i = 1 if tbs[0][0] == 0xA0 else 0  # the version, when it isn't 1
    return {"subject": der_name(tbs[i + 4][1]), "issuer": der_name(tbs[i + 2][1]), "key": spki_key(tbs[i + 5][1])}


def _rsa_private(contents):
    f = [der_int(v) for t, v in der_items(contents) if t == 0x02]
    if len(f) != 9 or f[0] != 0:
        raise ValueError("an RSA private key that isn't of two primes")
    return RsaKey(*f[1:])


class EcKey:
    def __init__(self, curve, d):
        if not 0 < d < curve.n:
            raise ValueError("an EC private key out of range")
        self.curve, self.d = curve, d
        self.public = ec_encode(curve, ec_multiply(curve, d, curve.g))


def _ec_private(contents, curve):
    """SEC 1's ECPrivateKey: version 1, the key, then [0] the curve and [1] the public key, both optional."""
    items = der_items(contents)
    if items[0] != (0x02, b"\x01") or items[1][0] != 0x04:
        raise ValueError("an EC private key of a layout this reader doesn't know")
    for tag, v in items[2:]:
        if tag == 0xA0:
            curve = CURVES.get(der_oid(der_one(v, 0x06)))
    if curve is None:
        raise ValueError("an EC private key on a curve this reader doesn't know")
    return EcKey(curve, int.from_bytes(items[1][1], "big"))


def pkcs8_key(data):
    """A PrivateKeyInfo (RFC 5208): an RsaKey or an EcKey."""
    items = der_items(der_one(data, 0x30))
    if len(items) < 3 or items[0][0] != 0x02 or items[1][0] != 0x30 or items[2][0] != 0x04:
        raise ValueError("not a PKCS #8 private key")
    alg = der_items(items[1][1])
    oid = der_oid(alg[0][1])
    if oid == OID_RSA:
        return _rsa_private(der_one(items[2][1], 0x30))
    if oid == OID_EC:
        curve = CURVES.get(der_oid(alg[1][1])) if len(alg) > 1 and alg[1][0] == 0x06 else None
        return _ec_private(der_one(items[2][1], 0x30), curve)
    raise ValueError(f"a private key of algorithm {oid}, which no slot opens")


# Key files under a password: PBES2 (RFC 8018) with PBKDF2 or scrypt, and AES-CBC.

PRFS = {f"1.2.840.113549.2.{i}": h for i, h in ((7, "sha1"), (8, "sha224"), (9, "sha256"), (10, "sha384"), (11, "sha512"))}
CBC_KEYS = {"2.16.840.1.101.3.4.1.2": 16, "2.16.840.1.101.3.4.1.22": 24, "2.16.840.1.101.3.4.1.42": 32}


def pbes2_decrypt(data, password):
    """An EncryptedPrivateKeyInfo's PrivateKeyInfo."""
    (_, alg), (_, sealed) = der_items(der_one(data, 0x30))
    (_, scheme), (_, params) = der_items(alg)
    if der_oid(scheme) != "1.2.840.113549.1.5.13":
        raise ValueError("a key file under a scheme other than PBES2")
    (_, kdf), (_, cipher) = der_items(params)
    (_, kdf_oid), (_, kdf_params) = der_items(kdf)
    (_, c_oid), (_, iv) = der_items(cipher)
    klen = CBC_KEYS.get(der_oid(c_oid))
    if klen is None:
        raise ValueError("a key file under a cipher other than AES-CBC")
    p = der_items(kdf_params)
    if der_oid(kdf_oid) == "1.2.840.113549.1.5.12":  # PBKDF2
        prf = "sha1"
        for tag, v in p[2:]:
            if tag == 0x30:
                prf = PRFS[der_oid(der_items(v)[0][1])]
        key = hashlib.pbkdf2_hmac(prf, password, p[0][1], der_int(p[1][1]), klen)
    elif der_oid(kdf_oid) == "1.3.6.1.4.1.11591.4.11":  # scrypt (RFC 7914 §7)
        n, r, par = (der_int(v) for _, v in p[1:4])
        key = hashlib.scrypt(password, salt=p[0][1], n=n, r=r, p=par, maxmem=128 * r * (n + par + 2), dklen=klen)
    else:
        raise ValueError("a key file under a key derivation other than PBKDF2 or scrypt")
    if len(sealed) % 16 or not sealed:
        raise ValueError("a key file whose sealed key isn't whole AES blocks")
    rks, out, prev = expand_key(key), bytearray(), iv
    for i in range(0, len(sealed), 16):
        block = sealed[i : i + 16]
        out += _xor(decrypt_block(rks, block), prev)
        prev = block
    pad = out[-1]
    if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("a key file that doesn't open: the wrong password?")
    return bytes(out[:-pad])


# Bech32 (BIP 173) without its length limit, for age's keys (§12.5 kinds 3 and 4).

B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def bech32_decode(text):
    """(human-readable part, bytes) of a Bech32 string; ValueError if it isn't one."""
    if text != text.lower() and text != text.upper():
        raise ValueError("Bech32 in mixed case")
    s = text.lower()
    at = s.rfind("1")
    if at < 1 or len(s) - at < 7:
        raise ValueError("not Bech32")
    hrp, values = s[:at], [B32.index(ch) for ch in s[at + 1 :]]
    if _polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values) != 1:
        raise ValueError("a Bech32 string whose checksum doesn't match")
    acc = bits = 0
    out = bytearray()
    for v in values[:-6]:
        acc, bits = (acc << 5) | v, bits + 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 255)
    if bits >= 5 or acc & ((1 << bits) - 1):
        raise ValueError("Bech32 with padding left over")
    return hrp, bytes(out)


# =================================================================================================
# The format.
# =================================================================================================


class Bytes:
    """A cursor over bytes that never runs past their end."""

    def __init__(self, data):
        self.data, self.pos = data, 0

    def left(self):
        return len(self.data) - self.pos

    def take(self, n):
        if n > self.left():
            raise Bad("the data ends in the middle of a field")
        self.pos += n
        return self.data[self.pos - n : self.pos]

    def uvarint(self):
        value = 0
        for i in range(10):
            b = self.take(1)[0]
            if i == 9 and b > 1:
                break
            value |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                if i and not b:  # a last byte of 0 makes a longer form of a smaller number (§2)
                    raise Bad("a number not in its shortest form")
                return value
        raise Bad("a number of more than 64 bits")

    def svarint(self):
        u = self.uvarint()
        return (u >> 1) ^ -(u & 1)

    def block(self):
        return self.take(self.uvarint())

    def stamp(self):
        seconds, nanos = self.svarint(), self.uvarint()
        if nanos >= 1_000_000_000:
            raise Bad("a time with a second's worth of nanoseconds or more")
        return seconds, nanos

    def u32(self, what):
        value = self.uvarint()
        if value >= 1 << 32:
            raise Bad(f"{what} of more than 32 bits")
        return value


def fields(data):
    """Tagged fields (§12.9, §13.3): tag, length and value, tags strictly increasing. {tag: value}."""
    b, out, last = Bytes(data), {}, None
    while b.left():
        tag = b.uvarint()
        if last is not None and tag <= last:
            raise Bad("fields out of order")
        out[tag], last = b.block(), tag
    return out


def unzstd(stored, raw_len, what):
    d = zstd.ZstdDecompressor()
    try:
        raw = d.decompress(stored)
    except zstd.ZstdError as e:
        raise Bad(f"{what} doesn't decode ({e})") from None
    if not d.eof or d.unused_data or len(raw) != raw_len:
        raise Bad(f"{what} isn't one Zstandard frame of its raw length")
    return raw


SEGMENT = 1 << 20


def sealed_len(n):
    """The length of n bytes sealed in segments (§12.8): a tag for each MiB, one at least."""
    return n + 16 * max(1, -(-n // SEGMENT))


def open_segments(key, sealed, aad, what):
    """The plaintext of a cell or an index sealed in segments (§12.8), each checked before use."""
    full = SEGMENT + 16
    n = max(1, -(-len(sealed) // full))
    last = len(sealed) - (n - 1) * full
    if last < 16 or (n > 1 and last == 16):
        raise Bad(f"{what} isn't sealed in segments of the lengths §12.8 gives")
    g, out = AesGcm(key), bytearray()
    for i in range(n):
        nonce = struct.pack("<Q", i) + bytes(3) + bytes([i == n - 1])
        try:
            out += g.open(nonce, sealed[i * full : (i + 1) * full], aad)
        except AuthError:
            raise Bad(f"{what} doesn't open: its segment {i} was changed, moved or cut") from None
    return bytes(out)


class Cell:
    def __init__(self, offset, stored, raw, coder, param, checksum, cid=None):
        self.offset, self.stored, self.raw = offset, stored, raw
        self.coder, self.param, self.checksum = coder, param, checksum
        self.cid = cid  # in an encrypted archive, the cell's id (§12.2); its data is sealed
        if raw > MAX_CELL:
            raise Bad("a cell over 256 MiB")
        ok = {
            0: param == 0 and stored == raw,
            1: param == 0 and stored < raw,
            2: param <= 32 and stored < raw,
        }.get(coder)
        if ok is None:
            raise Bad(f"a cell with coder {coder}")
        if not ok:
            raise Bad("a cell whose lengths or parameter break its coder's rules")

    def size(self):
        """Its bytes in the file: stored, or sealed (§12.6)."""
        return self.stored if self.cid is None else sealed_len(self.stored)

    def decode(self, archive, number):
        what = f"cell {number}"
        if self.offset + self.size() > archive.len:
            raise Bad(f"{what} runs past the end of the file")
        stored = archive.at(self.offset, self.size())
        if self.cid is not None:
            key = hkdf(archive.envelope.file_key, self.cid, b"bhive1 cell")
            stored = open_segments(key, stored, b"", what)
        if archive.digests is not None and sha256(stored) != archive.digests[number]:
            raise Bad(f"{what} doesn't match its digest (§13.2)")
        if self.coder == 0:
            raw = stored
        elif self.coder == 1:
            raw = unzstd(stored, self.raw, what)
        else:
            size = (2 | (self.param & 1)) << (self.param // 2 + 11)
            d = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": size}]
            )
            try:
                raw = d.decompress(stored)
            except lzma.LZMAError as e:
                raise Bad(f"{what} doesn't decode ({e})") from None
            if not d.eof or d.unused_data or len(raw) != self.raw:
                raise Bad(f"{what} isn't one LZMA2 stream of its raw length")
        if xxh3_64(raw) != self.checksum:
            raise Bad(f"{what} fails its checksum")
        return raw


class Entry:
    KINDS = {0: "file", 1: "folder", 2: "link"}

    def __init__(self, b, cells):
        flags = b.take(1)[0]
        if flags & 0xC0 or flags & 3 == 3:
            raise Bad("an entry with flags or a kind version 1 doesn't have")
        self.kind = self.KINDS[flags & 3]
        self.path = b.block().decode("utf-8", "replace")
        self.modified = b.stamp() if flags & 4 else None
        self.created = b.stamp() if flags & 8 else None
        self.mode = b.u32("a Unix mode") if flags & 16 else None
        self.attributes = b.u32("DOS attributes") if flags & 32 else None
        self.extents, self.size, self.target = [], 0, None
        if self.kind == "file":
            count = b.uvarint()
            if count > b.left() // 3:
                raise Bad("a file with more extents than there are bytes for")
            for _ in range(count):
                cell, offset, length = b.uvarint(), b.uvarint(), b.uvarint()
                if cell >= len(cells):
                    raise Bad(f"an extent in cell {cell}, which isn't there")
                if length == 0 or offset + length > cells[cell].raw:
                    raise Bad("an extent of no bytes, or past the end of its cell")
                self.extents.append((cell, offset, length))
                self.size += length
            if self.size >= 1 << 64:
                raise Bad("a file of 2^64 bytes or more")
        elif self.kind == "link":
            self.target = b.block().decode("utf-8", "replace")


# Encryption: the key block, the slots and the keys that open them (§12.3 to §12.5).


class Keys:
    """What the command line gives to open an encrypted archive with."""

    def __init__(self):
        self.passwords, self.recovery, self.x25519, self.xwing, self.rsa, self.ec = [], [], [], [], [], []

    def any(self):
        return any((self.passwords, self.recovery, self.x25519, self.xwing, self.rsa, self.ec))

    def add_recovery_key(self, text):
        """A recovery key's 16 bytes from its 48 digits, whatever separates them (§12.5 kind 2)."""
        digits = "".join(c for c in text if c.isdigit())
        if len(digits) != 48:
            raise Usage("a recovery key is 48 digits")
        key = bytearray()
        for i in range(8):
            g = int(digits[6 * i : 6 * i + 6])
            if g % 11 or g >= 720_896:
                raise Usage(f"the recovery key's group {i + 1} has a typo")
            key += (g // 11).to_bytes(2, "little")
        self.recovery.append(bytes(key))

    def add_file(self, path, password=None):
        """The private keys in an age identity file, or a PEM or DER key file."""
        try:
            data = open(path, "rb").read()
        except OSError as e:
            raise Usage(f"{path}: {e.strerror}") from None
        found = len(self.x25519) + len(self.xwing) + len(self.rsa) + len(self.ec)
        try:
            if b"-----BEGIN" in data:
                self._add_pem(data.decode("ascii", "replace"), password)
            elif b"AGE-SECRET-KEY-" in data:
                for line in data.decode("ascii", "replace").splitlines():
                    line = line.strip()
                    if line.startswith("AGE-SECRET-KEY-"):
                        self._add_age(line)
            else:
                self._add_der(data, password)
        except (ValueError, KeyError, IndexError) as e:
            raise Usage(f"{path}: {e}") from None
        if len(self.x25519) + len(self.xwing) + len(self.rsa) + len(self.ec) == found:
            raise Usage(f"{path}: no private key this reader can use")

    def _add_age(self, line):
        hrp, key = bech32_decode(line)
        if len(key) != 32 or hrp not in ("age-secret-key-", "age-secret-key-pq-"):
            raise ValueError("not an age identity of 32 bytes")
        if hrp == "age-secret-key-":
            self.x25519.append((key, x25519_public(key)))
        else:
            self.xwing.append(key)

    def _add(self, key):
        (self.rsa if isinstance(key, RsaKey) else self.ec).append(key)

    def _add_pem(self, text, password):
        lines = [ln.strip() for ln in text.splitlines()]
        for i, line in enumerate(lines):
            if not (line.startswith("-----BEGIN ") and line.endswith("-----")):
                continue
            label = line[11:-5]
            end = lines.index(f"-----END {label}-----", i)
            body = lines[i + 1 : end]
            if any(":" in ln for ln in body):
                raise ValueError("a PEM key under a legacy password; `openssl pkcs8 -topk8` converts it")
            data = base64.b64decode("".join(body), validate=True)
            if label == "PRIVATE KEY":
                self._add(pkcs8_key(data))
            elif label == "ENCRYPTED PRIVATE KEY":
                if password is None:
                    raise ValueError("a key file under a password: give --key-password")
                self._add(pkcs8_key(pbes2_decrypt(data, password.encode())))
            elif label == "RSA PRIVATE KEY":
                self._add(_rsa_private(der_one(data, 0x30)))
            elif label == "EC PRIVATE KEY":
                self._add(_ec_private(der_one(data, 0x30), None))

    def _add_der(self, data, password):
        reads = [pkcs8_key, lambda d: _rsa_private(der_one(d, 0x30)), lambda d: _ec_private(der_one(d, 0x30), None)]
        if password is not None:
            reads.insert(0, lambda d: pkcs8_key(pbes2_decrypt(d, password.encode())))
        for read in reads:
            try:
                self._add(read(data))
                return
            except (ValueError, KeyError, IndexError):
                pass
        raise ValueError("not a key file this reader knows, or one under a password (--key-password)")


class Slot:
    """A slot (§12.4): its kind, its first 4 + p bytes, its public part, commitment and wrapped key."""

    NAMES = {1: "password", 2: "recovery key", 3: "X25519 key", 4: "X-Wing key", 5: "RSA key",
             6: "EC P-256 key", 7: "EC P-384 key", 8: "security key"}  # fmt: skip

    def __init__(self, data):
        self.kind = data[0]
        self.framed, self.public = data[:-80], data[4:-80]
        self.commitment, self.wrapped = data[-80:-48], data[-48:]
        p = self.public
        # Each kind's public part, filled exactly (§12.5, §12.10).
        if self.kind == 1:
            if len(p) != 48 or p[0] != 0x13:
                raise Bad("a password slot that isn't Argon2id version 0x13 with its 48 bytes")
            m, t, lanes = struct.unpack_from("<III", p, 4)
            if m > 4 << 20 or m < 8 * lanes or not 1 <= t <= 16 or not 1 <= lanes <= 16:
                raise Bad(f"a password slot whose cost is over the limits ({m} KiB, {t} passes, {lanes} lanes)")
        elif self.kind in (2, 3) and len(p) != 32 or self.kind == 4 and len(p) != 1120:
            raise Bad(f"a {self.NAMES[self.kind]} slot whose public part isn't its length")
        elif self.kind == 5:
            if len(p) < 6 or len(p) != 6 + struct.unpack_from("<H", p, 4)[0] or not 256 <= len(p) - 6 <= 1024:
                raise Bad("an RSA slot whose ciphertext doesn't fill it, or isn't 256 to 1,024 bytes")
        elif self.kind in (6, 7) and len(p) != 4 + (65 if self.kind == 6 else 97):
            raise Bad("an EC slot whose public part isn't its length")
        elif self.kind == 8:
            n = struct.unpack_from("<H", p, 2)[0] if len(p) >= 4 else 0
            rp = p[4 + n] if len(p) > 4 + n else 0
            if not 1 <= n <= 1023 or not 1 <= rp <= 253 or len(p) != 4 + n + 1 + rp + 32:
                raise Bad("a security-key slot whose fields don't fill it")

    def describe(self):
        p = self.public
        if self.kind == 1:
            m, t, lanes = struct.unpack_from("<III", p, 4)
            return f"Argon2id, {m} KiB, {t} passes, {lanes} lanes"
        if self.kind in (5, 6, 7):
            return f"tag {p[:4].hex()}"
        if self.kind == 8:
            n = struct.unpack_from("<H", p, 2)[0]
            return f"relying party {p[5 + n : 5 + n + p[4 + n]].decode('utf-8', 'replace')}, credential {p[4 : 4 + n].hex()}"
        return "" if self.kind in self.NAMES else "a kind this reader doesn't know"

    def secrets(self, keys):
        """(S, recipient key) for each of the given keys that could be this slot's (§12.5)."""
        p = self.public
        if self.kind == 1:
            m, t, lanes = struct.unpack_from("<III", p, 4)
            for pw in keys.passwords:
                if m >= 1 << 16:
                    print(f"bhive_reader: Argon2id at {m >> 10} MiB, {t} passes: a minute or more", file=sys.stderr)
                yield argon2id(unicodedata.normalize("NFC", pw).encode(), p[16:48], t, m, lanes), b""
        elif self.kind == 2:
            for key in keys.recovery:
                yield key, b""
        elif self.kind == 3:
            for sk, pk in keys.x25519:
                s = x25519(sk, p)
                if s == bytes(32):
                    raise Bad("an X25519 slot whose shared secret is zero")
                yield s, pk
        elif self.kind == 4:
            for seed in keys.xwing:
                yield xwing_decaps(seed, p), b""
        elif self.kind == 5:
            for key in keys.rsa:
                s = rsa_oaep_decrypt(key, p[6:])
                if s is not None:
                    yield s, b""
        elif self.kind in (6, 7):
            curve = P256 if self.kind == 6 else P384
            point = ec_point(curve, p[4:])
            for key in keys.ec:
                if key.curve is curve:
                    if point is None:
                        raise Bad("an EC slot whose ephemeral key isn't on its curve")
                    yield ecdh_x(curve, key.d, point), key.public

    def open(self, key_id, secret, recipient=b""):
        """The file key, or None when the secret isn't this slot's (§12.4 steps 1 to 4)."""
        context = sha256(b"bhive1 slot" + key_id + self.framed + recipient)
        okm = hkdf_expand(hmac.new(context, secret, hashlib.sha256).digest(), b"bhive1 slot", 64)
        if not hmac.compare_digest(okm[32:], self.commitment):
            return None
        try:
            return AesGcm(okm[:32]).open(bytes(12), self.wrapped, self.framed)
        except AuthError:
            raise Bad("a slot that knows the secret but whose file key doesn't open: the file is damaged") from None


def slot_tag(spki, kind, rest):
    """The 4-byte tag of a slot of kind 5 to 7 for the key whose SubjectPublicKeyInfo is spki (§12.5)."""
    return hmac.new(sha256(spki), b"bhive1 tag" + bytes([kind]) + rest, hashlib.sha256).digest()[:4]


class KeyBlock:
    """The key block (§12.3), checked before any key is tried with it (§12.10)."""

    def __init__(self, archive):
        head = archive.at(16, 60)
        if head[:4] != b"BHKY":
            raise Bad("an encrypted archive without its key block")
        if head[4] != 1:
            raise Bad(f"an archive encrypted with suite {head[4]}, which this reader doesn't know")
        count, length = struct.unpack_from("<HI", head, 6)
        if not 1 <= count <= 64 or length > 65_536:
            raise Bad(f"a key block of {count} slots in {length} bytes")
        self.archive_id, self.key_id = head[12:44], head[44:60]
        body = archive.at(76, length + 32)
        slots, self.mac, self.end = body[:length], body[length:], 76 + length + 32
        self.slots, pos = [], 0
        for _ in range(count):
            if pos + 4 > length:
                raise Bad("slots that don't fill the slots length")
            n = struct.unpack_from("<H", slots, pos + 2)[0]
            if n < 80 or pos + 4 + n > length:
                raise Bad("a slot shorter than 80 bytes, or longer than the slots")
            self.slots.append(Slot(slots[pos : pos + 4 + n]))
            pos += 4 + n
        if pos != length:
            raise Bad("slots that don't fill the slots length")
        if sum(s.kind == 1 for s in self.slots) > 4:
            raise Bad("more than 4 password slots")

    def unlock(self, archive, keys):
        """The archive's keys, from the first slot a given key opens, once the header MAC checks."""
        known = [s for s in self.slots if s.kind in Slot.NAMES]
        if not known:
            raise Bad("made by a newer program: no way in is of a kind this reader knows")
        # Passwords last: Argon2id takes a while (§12.5).
        for slot in sorted(known, key=lambda s: s.kind == 1):
            for secret, recipient in slot.secrets(keys):
                k = slot.open(self.key_id, secret, recipient)
                if k is None:
                    continue
                mac_key = hkdf(k, self.archive_id, b"bhive1 mac")
                start = archive.at(0, self.end - 32)
                if not hmac.compare_digest(hmac.new(mac_key, start, hashlib.sha256).digest(), self.mac):
                    raise Bad("the header MAC fails: the file is damaged")
                return Envelope(k, self)
        ways = ", ".join(sorted({Slot.NAMES[s.kind] for s in known}))
        if not keys.any():
            raise Locked(f"the archive is encrypted: its ways in are {ways}")
        raise Locked(f"nothing given opens the archive: its ways in are {ways}")


class Envelope:
    """An open encrypted archive's keys (§12.2)."""

    def __init__(self, file_key, block):
        self.file_key, self.mac = file_key, block.mac
        self.record_key = hkdf(file_key, block.archive_id, b"bhive1 record")

    def open_record(self, offset, head, sealed):
        """A cell block's record (§12.6): the cell's id, its record head and its journal as stored."""
        try:
            plain = AesGcm(self.record_key).open(head[12:24], sealed, head + struct.pack("<Q", offset))
        except AuthError:
            raise Bad("a sealed record that doesn't open") from None
        return plain[:32], plain[32:80], plain[80:]


# Signatures (§13).

ALGORITHMS = {1: "ML-DSA-65 and Ed25519", 2: "RSA-PSS", 3: "RSA PKCS #1 v1.5", 4: "ECDSA P-256", 5: "ECDSA P-384"}


def fingerprint(signer):
    """The first 10 bytes of the signer bytes' SHA-256, in base32, in groups of four (§13.5)."""
    b32 = base64.b32encode(sha256(signer)[:10]).decode()
    return "-".join(b32[i : i + 4] for i in range(0, 16, 4))


class Signature:
    """One signature of section 3 and what checking it found: checked, failed or unchecked."""

    def __init__(self, algorithm=None, signer=b"", time=None):
        self.algorithm, self.signer, self.time = algorithm, signer, time
        self.status, self.why, self.who = "unchecked", "", ""

    def line(self):
        name = ALGORITHMS.get(self.algorithm, f"algorithm {self.algorithm}" if self.algorithm is not None else "-")
        fp = fingerprint(self.signer) if self.signer else "-"
        time = "-" if self.time is None else str(self.time)
        return "\t".join((self.status, name, fp, time, self.who or "-", self.why or "-"))


def check_signature(record, manifest, digests_whole):
    """Checks one signature record (§13.3, §13.4) against the archive's manifest."""
    sig = Signature()
    try:
        b = Bytes(record)
        sig.algorithm = b.take(1)[0]
        b.take(1)
        sig.signer, attrs, value, unsigned = b.block(), b.block(), b.block(), b.block()
        if b.left():
            raise Bad("bytes after its last field")
        signed = fields(attrs)
        fields(unsigned)
        if 1 in signed:
            t = Bytes(signed[1])
            sig.time = t.svarint()
            if t.left():
                raise Bad("a time with bytes after it")
    except Bad as e:
        sig.why = f"a signature that doesn't parse: {e}"
        return sig
    if sig.algorithm not in ALGORITHMS:
        sig.why = f"algorithm {sig.algorithm}, which this reader doesn't know"
        return sig
    critical = [t for t in signed if t % 2 and t != 1]
    if critical:
        sig.why = f"a critical signed attribute this reader doesn't know ({critical[0]})"
        return sig
    message = b"bhive1 signature" + bytes([sig.algorithm]) + manifest + sha256(sig.signer) + sha256(attrs)
    if sig.algorithm == 1:
        sig.who = "a BeeZip signing key"
        if len(sig.signer) != 32 + MLDSA_PUBLIC_LEN:
            sig.why = "a signing key of the wrong length"
            return sig
        ok = len(value) == 64 + MLDSA_SIGNATURE_LEN
        ok = ok and ed25519_verify(sig.signer[:32], message, value[:64])
        ok = ok and mldsa65_verify(sig.signer[32:], message, value[64:], b"bhive1")
    else:
        try:
            b = Bytes(sig.signer)
            count = b.uvarint()
            if not 1 <= count <= 8:
                raise Bad(f"{count} certificates")
            certs = [b.block() for _ in range(count)]
            if b.left():
                raise Bad("bytes after the certificates")
            cert = certificate(certs[0])
        except (Bad, ValueError, IndexError) as e:
            sig.why = f"a signer whose certificates don't parse: {e}"
            return sig
        sig.who = f"{cert['subject']} (issued by {cert['issuer']}; its chain isn't checked)"
        key = cert["key"]
        if sig.algorithm in (2, 3):
            if key[0] != "rsa" or not 2048 <= key[1].bit_length() <= 8192 or not (key[2] & 1 and 3 <= key[2] < 1 << 32):
                sig.why = "a certificate whose key isn't RSA of 2,048 to 8,192 bits with an odd exponent below 2^32"
                return sig
            verify = rsa_pss_verify if sig.algorithm == 2 else rsa_pkcs1_verify
            ok = verify(key[1], key[2], message, value)
        else:
            curve = P256 if sig.algorithm == 4 else P384
            point = ec_point(curve, key[2]) if key[0] == "ec" and key[1] is curve else None
            if point is None:
                sig.why = f"a certificate whose key isn't a {curve.name} point"
                return sig
            ok = ecdsa_verify(curve, point, message, value)
    if not digests_whole:
        sig.why = "section 2, the cells' digests, is missing or not whole"
        return sig
    sig.status = "checked" if ok else "failed"
    if not ok:
        sig.why = "the archive changed after it was signed, or the signature is damaged"
    return sig


class Archive:
    def __init__(self, path, recover=False, keys=None, unlock=True):
        self.f = open(path, "rb")
        self.len = os.fstat(self.f.fileno()).st_size
        header = self.f.read(16)
        if len(header) < 16 or header[:8] != MAGIC:
            raise Bad("not a .bhive file")
        version, _, features = struct.unpack_from("<HHI", header, 8)
        if version != 1 or features & ~1:
            raise Bad(f"version {version} with features {features:#x}: not for this reader")
        self.version, self.features = version, features
        self.keyblock = self.envelope = self.incomplete = self.level = None
        self.digests = self.descriptions = None
        self.cells, self.entries, self.sections, self.entry_bytes, self.raw = [], [], [], b"", None
        self.cache = (None, None)
        # Where cells can start, and the least a cell's data lies after the end of the one before.
        self.start, self.gap = 16, 48
        if features & 1:
            self.keyblock = KeyBlock(self)
            self.start, self.gap = self.keyblock.end, 120
            if not unlock:
                return
            self.envelope = self.keyblock.unlock(self, keys or Keys())
        try:
            self.read_index()
        except Bad as e:
            if not recover:
                raise
            self.incomplete = str(e)
            self.recover()

    def at(self, offset, n):
        self.f.seek(offset)
        data = self.f.read(n)
        if len(data) != n:
            raise Bad("the file ends too soon")
        return data

    def read_index(self):
        if self.len < self.start + 48:
            raise Bad("the file is too short to hold an index")
        footer = self.at(self.len - 16, 16)
        if footer[8:] != MAGIC:
            raise Bad("the file doesn't end with a footer")
        offset = _u64(footer, 0)
        if offset < self.start or offset > self.len - 48:
            raise Bad("the footer points outside the file")
        if self.envelope is None:
            head = self.at(offset, 32)
            coder, stored, raw_len, checksum = self.index_head(head)
            if offset + 32 + stored + 16 != self.len:
                raise Bad("the index and the footer don't end the file")
            raw = self.at(offset + 32, stored)
            row = 26
        else:
            # The sealed index (§12.7): a salt, then the inner index block sealed in segments.
            head = self.at(offset, 48)
            sealed = _u64(head, 8)
            if head[:4] != b"BHIE" or sealed > self.len or offset + 48 + sealed + 16 != self.len:
                raise Bad("not an encrypted index block, or one that doesn't end the file with the footer")
            key = hkdf(self.envelope.file_key, head[16:48], b"bhive1 index")
            plain = open_segments(key, self.at(offset + 48, sealed), self.envelope.mac + head, "the index")
            if len(plain) < 32:
                raise Bad("a sealed index shorter than its head")
            coder, stored, raw_len, checksum = self.index_head(plain[:32])
            if stored != len(plain) - 32:
                raise Bad("a sealed index whose head doesn't measure what follows it")
            raw = plain[32:]
            row = 58
        if coder:
            raw = unzstd(raw, raw_len, "the index")
        if xxh3_64(raw) != checksum:
            raise Bad("the index fails its checksum")
        self.raw = raw

        b = Bytes(raw)
        count = b.uvarint()
        if count > b.left() // row:
            raise Bad("a cell table larger than the index")
        self.cells, end = [], self.start
        for n in range(count):
            fields_ = b.take(row)
            cell = Cell(*struct.unpack_from("<QIIBBQ", fields_), cid=fields_[26:] if row == 58 else None)
            if cell.offset < end + self.gap or cell.offset + cell.size() > offset:
                raise Bad(f"cell {n} overlaps what is around it")
            end = cell.offset + cell.size()
            self.cells.append(cell)
        count = b.uvarint()
        if count > b.left() // 2:
            raise Bad("more entries than the index has bytes for")
        start = b.pos
        self.entries = [Entry(b, self.cells) for _ in range(count)]
        self.entry_bytes = raw[start : b.pos]
        # Sections (§6): strictly increasing ids; the head bytes kept for the manifest (§13.1).
        self.sections = []
        while b.left():
            at = b.pos
            ident, body = b.uvarint(), b.block()
            if self.sections and ident <= self.sections[-1][0]:
                raise Bad("index sections out of order")
            self.sections.append((ident, raw[at : b.pos - len(body)], body))
        sections = {ident: body for ident, _, body in self.sections}
        if len(sections.get(1, b"")) == 1:
            self.level = sections[1][0]
        if 2 in sections and len(sections[2]) == 32 * len(self.cells):
            self.digests = [sections[2][32 * i : 32 * i + 32] for i in range(len(self.cells))]
        if self.keyblock and 5 in sections:
            self.descriptions = self.read_descriptions(sections[5])

    @staticmethod
    def index_head(head):
        if head[:4] != b"BHIX" or head[4] > 1:
            raise Bad("not an index block, or one with an unknown coder")
        stored, raw_len, checksum = struct.unpack_from("<QQQ", head, 8)
        if not head[4] and stored != raw_len:
            raise Bad("a stored index with two lengths")
        return head[4], stored, raw_len, checksum

    def read_descriptions(self, body):
        """Section 5 (§12.9): each slot's fields, or None when it doesn't describe these slots."""
        try:
            b = Bytes(body)
            if b.uvarint() != len(self.keyblock.slots):
                return None
            out = [fields(b.block()) for _ in self.keyblock.slots]
            return None if b.left() else out
        except Bad:
            return None

    def recover(self):
        """What the records before the cells still list (§8, and §12.10 for an encrypted archive)."""
        self.cells, self.entries, self.level, self.sections, self.digests = [], [], None, [], None
        pos = self.start
        while pos + 4 <= self.len:
            tag = self.at(pos, 4)
            try:
                if tag in (b"BHIX", b"BHIE") and pos + 48 <= self.len:
                    if self.envelope is None and tag == b"BHIX":
                        end = pos + 48 + self.index_head(self.at(pos, 32))[1]
                    elif self.envelope is not None and tag == b"BHIE":
                        end = pos + 64 + _u64(self.at(pos, 16), 8)
                    else:
                        break
                    if end > self.len:
                        break
                    pos = end
                    continue
                cid = None
                if self.envelope is None:
                    if tag != b"BHCL" or pos + 48 > self.len:
                        break
                    head = self.at(pos, 48)
                    jstored = _u32(head, 28)
                    if pos + 48 + jstored > self.len:
                        break
                    journal, data_at = self.at(pos + 48, jstored), pos + 48 + jstored
                else:
                    if tag != b"BHCE" or pos + 24 > self.len:
                        break
                    block = self.at(pos, 24)
                    r, c = struct.unpack_from("<II", block, 4)
                    if r < 96 or pos + 24 + r + c > self.len:
                        break
                    cid, head, journal = self.envelope.open_record(pos, block, self.at(pos + 24, r))
                    data_at = pos + 24 + r
                    if head[:4] != b"BHCL" or _u32(head, 28) != len(journal) or c != sealed_len(_u32(head, 12)):
                        break
                number, raw, stored, coder, param, jcoder, _, items, jraw, jstored, checksum, check = (
                    struct.unpack_from("<IIIBBBBIIIQQ", head, 4)
                )
                if number != len(self.cells) or jcoder > 1 or (not jcoder and jraw != jstored):
                    break
                cell = Cell(data_at, stored, raw, coder, param, checksum, cid)
                if cell.offset + cell.size() > self.len:
                    break
                if xxh3_64(head[:40] + journal) != check:
                    break
                if jcoder:
                    journal = unzstd(journal, jraw, "a journal")
                b = Bytes(journal)
                cells = self.cells + [cell]
                entries = [Entry(b, cells) for _ in range(items)]
                if b.left():
                    break
            except Bad:
                break
            self.cells, pos = cells, cell.offset + cell.size()
            self.entries += entries

    def cell(self, n):
        if self.cache[0] != n:
            self.cache = (n, self.cells[n].decode(self, n))
        return self.cache[1]

    def read(self, entry):
        """The file's bytes, piece by piece."""
        for cell, offset, length in entry.extents:
            yield self.cell(cell)[offset : offset + length]

    def manifest(self):
        """What signatures sign (§13.1): the contents, nothing about where they lie."""
        h = hashlib.sha256(b"bhive1 manifest")
        h.update(struct.pack("<HI", self.version, self.features & ~1))
        h.update(struct.pack("<Q", len(self.cells)))
        for c in self.cells:
            h.update(struct.pack("<IBBQ", c.raw, c.coder, c.param, c.checksum))
        h.update(struct.pack("<QQ", len(self.entries), len(self.entry_bytes)) + self.entry_bytes)
        for ident, head, body in self.sections:
            if ident % 2 == 0:
                h.update(head + body)
        return h.digest()

    def signatures(self):
        """Section 3's signatures, each checked (§13.3): [] when the archive isn't signed."""
        body = next((body for ident, _, body in self.sections if ident == 3), None)
        if body is None:
            return []
        try:
            if len(body) > 1 << 20:
                raise Bad("a signature section over 1 MiB")
            b = Bytes(body)
            count = b.uvarint()
            if not 1 <= count <= 16:
                raise Bad(f"{count} signatures")
            records = [b.block() for _ in range(count)]
            if b.left():
                raise Bad("bytes after the last signature")
        except Bad as e:
            sig = Signature()
            sig.why = f"a signature section that doesn't parse: {e}"
            return [sig]
        manifest = self.manifest()
        return [check_signature(r, manifest, self.digests is not None) for r in records]


def safe(path):
    """The path's components, or None for one this reader won't write."""
    parts = path.split("/")
    for part in parts:
        if part in ("", ".", "..") or any(c in part for c in '\\:\0'):
            return None
    return parts


def stamp(t):
    return "-" if t is None else f"{t[0]}.{t[1]:09d}"


def set_time(target, modified):
    """Gives a file its time, if this system can hold it (Windows holds none before 1601)."""
    if modified:
        ns = modified[0] * 1_000_000_000 + modified[1]
        try:
            os.utime(target, ns=(ns, ns))
        except (OSError, OverflowError):
            pass


OPTIONS = ("--password", "--password-file", "--recovery-key", "--identity", "--key-password")


def parse(argv):
    """(command, archive, directory or None, --recover, Keys), or Usage."""
    words, values, recover = [], {o: [] for o in OPTIONS}, False
    args = iter(argv[1:])
    for a in args:
        if a == "--recover":
            recover = True
        elif a in values:
            value = next(args, None)
            if value is None:
                raise Usage(f"{a} needs a value")
            values[a].append(value)
        elif a.startswith("--"):
            raise Usage(f"an option this reader doesn't know: {a}")
        else:
            words.append(a)
    commands = {"list": 2, "test": 2, "extract": 3, "verify": 2, "slots": 2}
    if not words or commands.get(words[0]) != len(words):
        raise Usage("a command and its arguments, as below")
    keys = Keys()
    keys.passwords += values["--password"]
    for name in values["--password-file"]:
        try:
            text = sys.stdin.read() if name == "-" else open(name, encoding="utf-8").read()
        except OSError as e:
            raise Usage(f"{name}: {e.strerror}") from None
        keys.passwords.append(text.splitlines()[0] if text else "")
    for text in values["--recovery-key"]:
        keys.add_recovery_key(text)
    password = values["--key-password"][-1] if values["--key-password"] else None
    for name in values["--identity"]:
        keys.add_file(name, password)
    return words[0], words[1], words[2] if len(words) > 2 else None, recover, keys


def main(argv):
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")  # paths and § in any console
    try:
        command, path, root, recover, keys = parse(argv)
    except Usage as e:
        print(f"bhive_reader: {e}\n{__doc__}", file=sys.stderr)
        return 2
    try:
        archive = Archive(path, recover, keys, unlock=command != "slots" or keys.any())
    except Locked as e:
        print(f"bhive_reader: {e}", file=sys.stderr)
        return 3
    except Bad as e:
        print(f"bhive_reader: {e}", file=sys.stderr)
        return 1
    if archive.incomplete:
        print(f"bhive_reader: the archive is incomplete ({archive.incomplete})", file=sys.stderr)
    out = open(sys.stdout.fileno(), "w", encoding="utf-8", newline="\n", closefd=False)
    failed = 0

    if command == "slots":
        if archive.keyblock is None:
            out.write("not encrypted\n")
        for i, slot in enumerate(archive.keyblock.slots if archive.keyblock else []):
            label = ""
            if archive.descriptions and 1 in archive.descriptions[i]:
                label = archive.descriptions[i][1].decode("utf-8", "replace")
            name = Slot.NAMES.get(slot.kind, f"kind {slot.kind}")
            out.write("\t".join((str(i), name, slot.describe() or "-", label or "-")) + "\n")
        out.flush()
        return 1 if archive.incomplete else 0

    signatures = archive.signatures() if not archive.incomplete else []
    if command == "verify":
        if archive.incomplete:
            out.write("unsigned\trecovered from its records, without an index to check against (§13)\n")
        elif not signatures:
            out.write("unsigned\n")
        for sig in signatures:
            out.write(sig.line() + "\n")
        out.flush()
        return 0 if signatures and all(s.status == "checked" for s in signatures) else 1
    for i, sig in enumerate(signatures):
        why = f" ({sig.why})" if sig.why else ""
        who = f", {sig.who}, {fingerprint(sig.signer)}" if sig.signer else ""
        print(f"bhive_reader: signature {i + 1}: {sig.status}{who}{why}", file=sys.stderr)

    if command == "list":
        for e in archive.entries:
            mode = "-" if e.mode is None else f"{e.mode:o}"
            attributes = "-" if e.attributes is None else f"{e.attributes:x}"
            fields_ = [e.kind, str(e.size), stamp(e.modified), stamp(e.created), mode, attributes, e.path]
            if e.target is not None:
                fields_.append(e.target)
            out.write("\t".join(fields_) + "\n")
        out.flush()
    elif command == "test":
        failed += sum(s.status == "failed" for s in signatures)
        for n in range(len(archive.cells)):
            try:
                archive.cell(n)
            except Bad as e:
                print(f"bhive_reader: {e}", file=sys.stderr)
                failed += 1
    else:
        folders = []
        os.makedirs(root, exist_ok=True)
        for e in archive.entries:
            parts = safe(e.path)
            if parts is None:
                print(f"bhive_reader: skipped an unsafe path: {e.path!r}", file=sys.stderr)
                continue
            target = os.path.join(root, *parts)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if e.kind == "folder":
                os.makedirs(target, exist_ok=True)
                folders.append((target, e))
                continue
            if e.kind == "link":
                # Only a link that stays beside or below itself.
                if safe(e.target) is None:
                    print(f"bhive_reader: skipped a link: {e.path!r}", file=sys.stderr)
                    continue
                os.symlink(e.target, target)
                continue
            try:
                with open(target, "wb") as f:
                    for piece in archive.read(e):
                        f.write(piece)
            except Bad as bad:
                print(f"bhive_reader: {e.path}: {bad}", file=sys.stderr)
                os.remove(target)
                failed += 1
                continue
            set_time(target, e.modified)
        for target, e in reversed(folders):
            set_time(target, e.modified)
    return 1 if failed or archive.incomplete else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
