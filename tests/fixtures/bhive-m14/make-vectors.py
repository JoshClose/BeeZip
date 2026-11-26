"""Makes docs/bhive.md §12 and §13's test vectors and example archives (docs/M14.md §10, PR 0).

    python -I make-vectors.py --crypto <dir> [--mldsa <exe>]

`--crypto` is a folder of standard-library-only primitives (AES-256-GCM, Argon2id, X25519,
P-256/P-384, ML-KEM-768, X-Wing), the M14 spike's, which the Python reader takes over in PR B.
`--mldsa` is a small program that prints an ML-DSA-65 public key for a seed, and signs a
message deterministically (`ml-dsa` 0.1.2); without it, the vectors keep the values in
vectors.json. Writes vectors.json, spec-sealed.bhive and spec-signed.bhive next to itself,
and prints the listing of spec-sealed.bhive for the specification.

Every "random" value is SHAKE-256 of a label, so anyone can make the same bytes.
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))


def rnd(label, n):
    return hashlib.shake_256(b"bhive1 vector " + label.encode()).digest(n)


# --- primitives that the crypto folder doesn't have ----------------------------------------

def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hkdf(ikm, salt, info, length=32):
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def uvarint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def svarint(n):
    return uvarint(((n << 1) ^ (n >> 63)) & (2**64 - 1))


# Ed25519 (RFC 8032 §5.1), affine, for one signature.
ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P


def _ed_add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = ED_D * x1 * x2 * y1 * y2 % ED_P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, ED_P - 2, ED_P) % ED_P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, ED_P - 2, ED_P) % ED_P
    return x3, y3


def _ed_mul(k, pt):
    r = (0, 1)
    while k:
        if k & 1:
            r = _ed_add(r, pt)
        pt = _ed_add(pt, pt)
        k >>= 1
    return r


def _ed_base():
    y = 4 * pow(5, ED_P - 2, ED_P) % ED_P
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P:
        x = x * pow(2, (ED_P - 1) // 4, ED_P) % ED_P
    if x & 1:
        x = ED_P - x
    return x, y


ED_B = _ed_base()


def _ed_enc(pt):
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_public(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _ed_enc(_ed_mul(a, ED_B))


def ed25519_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = _ed_enc(_ed_mul(a, ED_B))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % ED_L
    big_r = _ed_enc(_ed_mul(r, ED_B))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % ED_L
    return big_r + ((r + k * a) % ED_L).to_bytes(32, "little")


# Bech32 (BIP 173) without the 90-character limit, as age writes keys.
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


def bech32(hrp, data):
    hrp_l = hrp.lower()
    acc, bits, five = 0, 0, []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
    if bits:
        five.append((acc << (5 - bits)) & 31)
    exp = [ord(c) >> 5 for c in hrp_l] + [0] + [ord(c) & 31 for c in hrp_l]
    pm = _polymod(exp + five + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    s = hrp_l + "1" + "".join(B32[d] for d in five + chk)
    return s.upper() if hrp != hrp_l else s


# A little DER, for key files and SubjectPublicKeyInfo.
def der(tag, body):
    n = len(body)
    if n < 128:
        ln = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(nb)]) + nb
    return bytes([tag]) + ln + body


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return der(0x02, b)


def der_oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, bytes(out))


SEQ, NULL = 0x30, b"\x05\x00"
RSA_OID, EC_OID = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1"
CURVE_OID = {"P-256": "1.2.840.10045.3.1.7", "P-384": "1.3.132.0.34"}


def rsa_spki(n, e):
    alg = der(SEQ, der_oid(RSA_OID) + NULL)
    return der(SEQ, alg + der(0x03, b"\0" + der(SEQ, der_int(n) + der_int(e))))


def rsa_pkcs8(n, e, d, p, q):
    body = b"".join(der_int(v) for v in (0, n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)))
    alg = der(SEQ, der_oid(RSA_OID) + NULL)
    return der(SEQ, der_int(0) + alg + der(0x04, der(SEQ, body)))


def ec_spki(curve, point):
    alg = der(SEQ, der_oid(EC_OID) + der_oid(CURVE_OID[curve]))
    return der(SEQ, alg + der(0x03, b"\0" + point))


def ec_pkcs8(curve, d, size, point):
    inner = der(SEQ, der_int(1) + der(0x04, d.to_bytes(size, "big")) + der(0xA1, der(0x03, b"\0" + point)))
    alg = der(SEQ, der_oid(EC_OID) + der_oid(CURVE_OID[curve]))
    return der(SEQ, der_int(0) + alg + der(0x04, inner))


def is_prime(n):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def det_prime(label, bits):
    i = 0
    while True:
        c = int.from_bytes(rnd(f"{label} {i}", bits // 8), "big") | (3 << (bits - 2)) | 1
        if c % 65537 != 1 and is_prime(c):
            return c
        i += 1


def oaep_encrypt(n, e, msg, seed):
    k = (n.bit_length() + 7) // 8
    lhash = hashlib.sha256(b"").digest()
    db = lhash + b"\0" * (k - len(msg) - 2 * 32 - 2) + b"\x01" + msg

    def mgf1(s, ln):
        out, c = b"", 0
        while len(out) < ln:
            out += hashlib.sha256(s + c.to_bytes(4, "big")).digest()
            c += 1
        return out[:ln]

    masked_db = bytes(a ^ b for a, b in zip(db, mgf1(seed, k - 33)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, mgf1(masked_db, 32)))
    em = b"\0" + masked_seed + masked_db
    return pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")


def mgf1(s, ln):
    out, c = b"", 0
    while len(out) < ln:
        out += hashlib.sha256(s + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:ln]


def oaep_decrypt(n, d, ct):
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(ct, "big"), d, n).to_bytes(k, "big")
    masked_seed, masked_db = em[1:33], em[33:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, mgf1(masked_db, 32)))
    db = bytes(a ^ b for a, b in zip(masked_db, mgf1(seed, k - 33)))
    assert em[0] == 0 and db[:32] == hashlib.sha256(b"").digest()
    return db[db.index(b"\x01", 32) + 1:]


# --- the format ----------------------------------------------------------------------------

def make_slot(kind, public, secret, file_key, key_id, recipient_key=b""):
    head = bytes([kind, 0]) + struct.pack("<H", len(public) + 80)
    framed = head + public
    context = hashlib.sha256(b"bhive1 slot" + key_id + framed + recipient_key).digest()
    prk = hmac.new(context, secret, hashlib.sha256).digest()
    okm = hkdf_expand(prk, b"bhive1 slot", 64)
    wrap, commitment = okm[:32], okm[32:]
    wrapped = AesGcm(wrap).seal(b"\0" * 12, file_key, framed)
    slot = framed + commitment + wrapped
    return slot, {
        "slot": slot.hex(),
        "secret": secret.hex(),
        "context": context.hex(),
        "prk": prk.hex(),
        "wrap_key": wrap.hex(),
        "commitment": commitment.hex(),
    }


def tag_of(spki, kind, rest):
    return hmac.new(hashlib.sha256(spki).digest(), b"bhive1 tag" + bytes([kind]) + rest, hashlib.sha256).digest()[:4]


SEGMENT = 1 << 20


def seal_segments(key, data, aad):
    g = AesGcm(key)
    n = max(1, -(-len(data) // SEGMENT))
    out = bytearray()
    for i in range(n):
        piece = data[i * SEGMENT:(i + 1) * SEGMENT]
        nonce = struct.pack("<Q", i) + b"\0\0\0" + bytes([1 if i == n - 1 else 0])
        out += g.seal(nonce, piece, aad)
    return bytes(out)


def key_block(archive_id, key_id, slots, mac_key):
    body = b"".join(slots)
    kb = b"BHKY" + bytes([1, 0]) + struct.pack("<HI", len(slots), len(body)) + archive_id + key_id + body
    mac = hmac.new(mac_key, HEADER_ENC + kb, hashlib.sha256).digest()
    return kb + mac, mac


MAGIC = bytes.fromhex("894248495645 0d0a".replace(" ", ""))
HEADER_ENC = MAGIC + struct.pack("<HHI", 1, 0, 1)


def spec_small():
    """spec-small.bhive's parts, read from the fixture."""
    b = open(os.path.join(ROOT, "tests", "fixtures", "bhive", "spec-small.bhive"), "rb").read()
    head = b[0x10:0x40]
    journal = b[0x40:0x9B]
    cell = b[0x9B:0xA5]
    raw = b[0xC5:0x13C]
    # cell count (1), one 26-byte row, entry count (1), the items; no sections.
    row = raw[1:27]
    assert raw[0] == 1 and raw[27] == 4
    items = raw[28:]
    return b, head, journal, cell, row, items


def sealed_example(out):
    """spec-small's contents behind a password, "honey", at a tiny Argon2 cost."""
    _, head, journal, cell, row, items = spec_small()
    file_key = rnd("file key", 32)
    key_id = rnd("key id", 16)
    archive_id = rnd("archive id", 32)
    salt = rnd("password salt", 32)
    m, t, p = 256, 2, 4
    secret = argon2id(b"honey", salt, t, m, p, 32)
    public = bytes([0x13, 0, 0, 0]) + struct.pack("<III", m, t, p) + salt
    slot, sv = make_slot(1, public, secret, file_key, key_id)
    mac_key = hkdf(file_key, archive_id, b"bhive1 mac")
    record_key = hkdf(file_key, archive_id, b"bhive1 record")
    kb, mac = key_block(archive_id, key_id, [slot], mac_key)
    f = bytearray(HEADER_ENC + kb)

    cell_id = rnd("cell id 0", 32)
    cell_key = hkdf(file_key, cell_id, b"bhive1 cell")
    sealed_cell = seal_segments(cell_key, cell, b"")
    block_at = len(f)
    record_pt = cell_id + head + journal
    r = len(record_pt) + 16
    nonce = rnd("record nonce 0", 12)
    block_head = b"BHCE" + struct.pack("<II", r, len(sealed_cell)) + nonce
    aad = block_head + struct.pack("<Q", block_at)
    sealed_record = AesGcm(record_key).seal(nonce, record_pt, aad)
    f += block_head + sealed_record
    cell_at = len(f)
    f += sealed_cell

    # The index: the row's offset is the sealed cell's, and the cell id follows the row.
    new_row = struct.pack("<Q", cell_at) + row[8:] + cell_id
    desc = uvarint(1) + (lambda d: uvarint(len(d)) + d)(uvarint(1) + uvarint(8) + b"Password")
    sections = uvarint(5) + uvarint(len(desc)) + desc
    raw = uvarint(1) + new_row + uvarint(4) + items + sections
    from bhive_reader import xxh3_64

    index_head = b"BHIX" + bytes([0, 0, 0, 0]) + struct.pack("<QQQ", len(raw), len(raw), xxh3_64(raw))
    inner = index_head + raw
    index_salt = rnd("index salt", 32)
    index_key = hkdf(file_key, index_salt, b"bhive1 index")
    sealed_len = len(inner) + 16 * max(1, -(-len(inner) // SEGMENT))
    ib_head = b"BHIE" + b"\0" * 4 + struct.pack("<Q", sealed_len) + index_salt
    sealed_index = seal_segments(index_key, inner, mac + ib_head)
    assert len(sealed_index) == sealed_len
    index_at = len(f)
    f += ib_head + sealed_index
    f += struct.pack("<Q", index_at) + MAGIC
    out["sealed_example"] = {
        "password": "honey",
        "file_key": file_key.hex(),
        "key_id": key_id.hex(),
        "archive_id": archive_id.hex(),
        "mac_key": mac_key.hex(),
        "record_key": record_key.hex(),
        "header_mac": mac.hex(),
        "cell_id": cell_id.hex(),
        "record_nonce": nonce.hex(),
        "cell_key": cell_key.hex(),
        "index_salt": index_salt.hex(),
        "index_key": index_key.hex(),
        "slot": sv,
        "index_raw": raw.hex(),
        "record_plain": record_pt.hex(),
    }
    return bytes(f), {
        "key_block": (16, len(kb), len(slot)),
        "block": (block_at, r, len(sealed_cell)),
        "index": (index_at, sealed_len),
    }


def listing(f, parts):
    lines = []

    def emit(at, data, what, wrap=12):
        first = True
        for i in range(0, len(data), wrap):
            chunk = data[i:i + wrap]
            hx = " ".join(f"{b:02x}" for b in chunk)
            lines.append(f"{at + i:04x}  {hx:<35}  {what if first else ''}".rstrip())
            first = False

    def field(at, size, what):
        emit(at, f[at:at + size], what)
        return at + size

    at = 0
    at = field(at, 8, "magic")
    at = field(at, 2, "version 1")
    at = field(at, 2, "reserved")
    at = field(at, 4, "features: bit 0, encrypted")
    lines.append("; the key block")
    at = field(at, 4, 'tag "BHKY"')
    at = field(at, 1, "suite 1: AES-256-GCM, HKDF-SHA256, HMAC-SHA256")
    at = field(at, 1, "reserved")
    at = field(at, 2, "1 slot")
    at = field(at, 4, "slots length 132")
    at = field(at, 32, "archive id")
    at = field(at, 16, "key id")
    lines.append("; slot 0: a password")
    at = field(at, 1, "kind 1: a password")
    at = field(at, 1, "reserved")
    at = field(at, 2, "body length 128")
    at = field(at, 1, "Argon2 version 0x13")
    at = field(at, 3, "reserved")
    at = field(at, 4, "memory 256 KiB (BeeZip writes 1 GiB or 2 GiB)")
    at = field(at, 4, "2 passes")
    at = field(at, 4, "4 lanes")
    at = field(at, 32, "salt")
    at = field(at, 32, "commitment")
    at = field(at, 48, "the file key, wrapped, and its tag")
    at = field(at, 32, "header MAC, of the 76 + 132 bytes above")
    lines.append("; cell block 0")
    block_at, r, c = parts["block"]
    assert at == block_at
    at = field(at, 4, 'tag "BHCE"')
    at = field(at, 4, f"sealed record length {r}")
    at = field(at, 4, f"sealed cell length {c}")
    at = field(at, 12, "the record's nonce")
    at = field(at, r, "the sealed record: cell id, record head, journal, tag")
    at = field(at, c, "the sealed cell: one segment of 10 bytes, and its tag")
    lines.append("; the index block")
    index_at, s = parts["index"]
    assert at == index_at
    at = field(at, 4, 'tag "BHIE"')
    at = field(at, 4, "reserved")
    at = field(at, 8, f"sealed length {s}")
    at = field(at, 32, "salt")
    at = field(at, s, "the sealed index: its head, the index, and the tag")
    lines.append("; the footer")
    at = field(at, 8, f"index offset {index_at}")
    at = field(at, 8, "magic")
    assert at == len(f)
    return "\n".join(lines)


def slot_vectors(out):
    fk = rnd("slot file key", 32)
    kid = rnd("slot key id", 16)
    v = {"file_key": fk.hex(), "key_id": kid.hex()}

    pw_nfd = unicodedata.normalize("NFD", "Grüße, Jürgen")
    salt = rnd("slot password salt", 32)
    m, t, p = 256, 2, 4
    secret = argon2id(unicodedata.normalize("NFC", pw_nfd).encode(), salt, t, m, p, 32)
    public = bytes([0x13, 0, 0, 0]) + struct.pack("<III", m, t, p) + salt
    _, sv = make_slot(1, public, secret, fk, kid)
    v["password"] = {"password_as_typed_nfd": pw_nfd, "memory_kib": m, "passes": t, "lanes": p, **sv}

    key = rnd("recovery key", 16)
    groups = [(key[2 * i] + 256 * key[2 * i + 1]) * 11 for i in range(8)]
    digits = "-".join(f"{g:06d}" for g in groups)
    _, sv = make_slot(2, rnd("recovery salt", 32), key, fk, kid)
    v["recovery_key"] = {"digits": digits, "key": key.hex(), **sv}

    sk = rnd("x25519 recipient", 32)
    pk = x25519.public_key(sk)
    esk = rnd("x25519 ephemeral", 32)
    share = x25519.public_key(esk)
    ss = x25519.x25519(esk, pk)
    _, sv = make_slot(3, share, ss, fk, kid, pk)
    v["x25519"] = {
        "recipient_secret": sk.hex(), "recipient_public": pk.hex(),
        "recipient_text": bech32("age", pk), "secret_text": bech32("AGE-SECRET-KEY-", sk),
        "ephemeral_secret": esk.hex(), **sv,
    }

    seed = rnd("xwing recipient", 32)
    xpk = xwing.public_key(seed)
    eseed = rnd("xwing encapsulation", 64)
    ss, ct = xwing.encaps_derand(xpk, eseed)
    assert xwing.decaps(seed, ct) == ss
    _, sv = make_slot(4, ct, ss, fk, kid)
    v["xwing"] = {
        "recipient_seed": seed.hex(), "recipient_public": xpk.hex(),
        "recipient_text": bech32("age1pq", xpk), "secret_text": bech32("AGE-SECRET-KEY-PQ-", seed),
        "encapsulation_seed": eseed.hex(), **sv,
    }

    e = 65537
    pr, qr = det_prime("rsa p", 1024), det_prime("rsa q", 1024)
    n = pr * qr
    d = pow(e, -1, (pr - 1) * (qr - 1))
    spki = rsa_spki(n, e)
    s = rnd("rsa secret", 32)
    ctr = oaep_encrypt(n, e, s, rnd("rsa oaep seed", 32))
    assert oaep_decrypt(n, d, ctr) == s
    tag = tag_of(spki, 5, ctr)
    public = tag + struct.pack("<H", len(ctr)) + ctr
    _, sv = make_slot(5, public, s, fk, kid)
    v["rsa"] = {
        "pkcs8": rsa_pkcs8(n, e, d, pr, qr).hex(), "spki": spki.hex(),
        "oaep_seed": rnd("rsa oaep seed", 32).hex(), "tag": tag.hex(), **sv,
    }

    for kind, c, name in ((6, ecdh.P256, "P-256"), (7, ecdh.P384, "P-384")):
        dr = int.from_bytes(rnd(f"{name} recipient", c.size + 8), "big") % (c.n - 1) + 1
        qx, qy = ecdh.multiply(c, dr, c.g)
        q = b"\x04" + qx.to_bytes(c.size, "big") + qy.to_bytes(c.size, "big")
        de = int.from_bytes(rnd(f"{name} ephemeral", c.size + 8), "big") % (c.n - 1) + 1
        ex, ey = ecdh.multiply(c, de, c.g)
        eph = b"\x04" + ex.to_bytes(c.size, "big") + ey.to_bytes(c.size, "big")
        z = ecdh.shared_x(c, de, q)
        assert z == ecdh.shared_x(c, dr, eph)
        spki = ec_spki(name, q)
        tag = tag_of(spki, kind, eph)
        _, sv = make_slot(kind, tag + eph, z, fk, kid, q)
        v[name.lower().replace("-", "")] = {
            "pkcs8": ec_pkcs8(name, dr, c.size, q).hex(), "spki": spki.hex(),
            "recipient_public": q.hex(), "ephemeral_scalar": f"{de:x}", "tag": tag.hex(), **sv,
        }

    cred = rnd("fido2 credential", 48)
    rp = b"beezip"
    salt = rnd("fido2 salt", 32)
    hs = rnd("fido2 hmac-secret output", 32)
    public = bytes([0b10, 0]) + struct.pack("<H", len(cred)) + cred + bytes([len(rp)]) + rp + salt
    _, sv = make_slot(8, public, hs, fk, kid)
    v["fido2"] = {
        "credential_id": cred.hex(), "rp_id": rp.decode(), "salt": salt.hex(),
        "note": "secret stands for the authenticator's hmac-secret output for the salt", **sv,
    }
    out["slots"] = v


def key_vectors(out):
    fk = rnd("schedule file key", 32)
    aid = rnd("schedule archive id", 32)
    cid = rnd("schedule cell id", 32)
    isalt = rnd("schedule index salt", 32)
    data = bytes(i % 251 for i in range(SEGMENT + 5))
    ck = hkdf(fk, cid, b"bhive1 cell")
    sealed = seal_segments(ck, data, b"")
    out["keys"] = {
        "file_key": fk.hex(), "archive_id": aid.hex(), "cell_id": cid.hex(), "index_salt": isalt.hex(),
        "mac_key": hkdf(fk, aid, b"bhive1 mac").hex(),
        "record_key": hkdf(fk, aid, b"bhive1 record").hex(),
        "cell_key": ck.hex(),
        "index_key": hkdf(fk, isalt, b"bhive1 index").hex(),
    }
    out["segments"] = {
        "plaintext": "bytes i % 251 for i in 0..1,048,581 (1 MiB and 5 bytes)",
        "key": ck.hex(), "sealed_length": len(sealed),
        "sealed_sha256": hashlib.sha256(sealed).hexdigest(),
        "tag_0": sealed[SEGMENT:SEGMENT + 16].hex(), "tag_1": sealed[-16:].hex(),
    }


def mldsa(exe, args):
    return subprocess.run([exe, *args], check=True, capture_output=True, text=True).stdout.split()


def signed_example(out, exe, previous):
    small, head, journal, cell, row, items = spec_small()
    digests = hashlib.sha256(cell).digest()
    sec2 = uvarint(2) + uvarint(len(digests)) + digests
    # The manifest.
    header = struct.pack("<HI", 1, 0 & ~1)
    cells = struct.pack("<Q", 1) + row[12:16] + row[16:18] + row[18:26]
    entries = struct.pack("<QQ", 4, len(items)) + items
    manifest = hashlib.sha256(b"bhive1 manifest" + header + cells + entries + sec2).digest()

    ed_seed = rnd("signing ed25519", 32)
    ml_seed = rnd("signing ml-dsa-65", 32)
    ed_pub = ed25519_public(ed_seed)
    if exe:
        (ml_pub,) = mldsa(exe, [ml_seed.hex()])
        ml_pub = bytes.fromhex(ml_pub)
    else:
        ml_pub = bytes.fromhex(previous["signed_example"]["mldsa_public"])
    signer = ed_pub + ml_pub
    attrs = uvarint(1) + uvarint(len(svarint(1767225600))) + svarint(1767225600)
    msg = b"bhive1 signature" + bytes([1]) + manifest + hashlib.sha256(signer).digest() + hashlib.sha256(attrs).digest()
    ed_sig = ed25519_sign(ed_seed, msg)
    if exe:
        ml_sig = bytes.fromhex(mldsa(exe, [ml_seed.hex(), msg.hex(), b"bhive1".hex()])[1])
    else:
        ml_sig = bytes.fromhex(previous["signed_example"]["mldsa_signature"])
    sig = ed_sig + ml_sig

    def lv(b):
        return uvarint(len(b)) + b

    record = bytes([1, 0]) + lv(signer) + lv(attrs) + lv(sig) + lv(b"")
    sec3_body = uvarint(1) + lv(record)
    sec3 = uvarint(3) + uvarint(len(sec3_body)) + sec3_body
    raw = small[0xC5:0x13C] + sec2 + sec3
    from bhive_reader import xxh3_64

    index_at = 0xA5
    ih = b"BHIX" + bytes(4) + struct.pack("<QQQ", len(raw), len(raw), xxh3_64(raw))
    f = small[:index_at] + ih + raw + struct.pack("<Q", index_at) + MAGIC
    fp = hashlib.sha256(signer).digest()[:10]
    import base64

    b32 = base64.b32encode(fp).decode()
    out["signed_example"] = {
        "manifest": manifest.hex(),
        "cell_digest": digests.hex(),
        "ed25519_seed": ed_seed.hex(), "ed25519_public": ed_pub.hex(),
        "mldsa_seed": ml_seed.hex(), "mldsa_public": ml_pub.hex(),
        "signer_text": bech32("bzsig", signer),
        "secret_text": bech32("BZSIG-SECRET-KEY-", ed_seed + ml_seed),
        "fingerprint": "-".join(b32[i:i + 4] for i in range(0, 16, 4)),
        "signed_attributes": attrs.hex(),
        "message": msg.hex(),
        "ed25519_signature": ed_sig.hex(),
        "mldsa_signature": ml_sig.hex(),
        "section_3": sec3.hex(),
        "index_raw": raw.hex(),
        "rsa_pss_and_ecdsa_note": "algorithms 2-5 sign the same 113-byte message for their algorithm byte; only the message is BeeZip's",
    }
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crypto", required=True)
    ap.add_argument("--mldsa")
    a = ap.parse_args()
    sys.path.insert(0, a.crypto)
    sys.path.insert(0, os.path.join(ROOT, "docs"))
    global AesGcm, argon2id, x25519, xwing, ecdh
    from aesgcm import AesGcm
    from argon2id import argon2id
    import x25519
    import xwing
    import ecdh

    # RFC 8032 §7.1, test 1.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert ed25519_public(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert ed25519_sign(seed, b"")[:8].hex() == "e5564300c360ac72"

    path = os.path.join(HERE, "vectors.json")
    previous = json.load(open(path)) if os.path.exists(path) else {}
    out = {"note": "docs/bhive.md §12 and §13. Made by make-vectors.py; every random value is SHAKE-256 of a label."}
    key_vectors(out)
    slot_vectors(out)
    sealed, parts = sealed_example(out)
    signed = signed_example(out, a.mldsa, previous)
    open(os.path.join(HERE, "spec-sealed.bhive"), "wb").write(sealed)
    open(os.path.join(HERE, "spec-signed.bhive"), "wb").write(signed)
    with open(path, "w", newline="\n") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(listing(sealed, parts))
    print(f"; {len(sealed)} bytes; spec-signed.bhive {len(signed)} bytes")


if __name__ == "__main__":
    main()
