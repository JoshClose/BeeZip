"""Tests docs/bhive_reader.py, the reader written from the specification alone (docs/M14.md, PR B).

    python -I tests/bhive_reader/test_reader.py [-v]

What it checks: every vector of tests/fixtures/bhive-m14 (vectors.json, ed25519-edges.json) and
a few published ones; every .bhive under tests/fixtures (the M13 fixtures as their manifest says,
BeeZip's encrypted fixtures as sealed.json says, cut and changed as BeeZip's tests change them,
the M14 examples, the malicious files); encrypted archives with every kind of slot, written with
make-vectors.py's writer and opened with every key file a slot can be opened with; signatures
that OpenSSL made with certificates (openssl.json, from make-openssl.py); and malformed archives,
refused or reported as docs/bhive.md §9, §12.10 and §13 say.
"""

import functools
import hashlib
import importlib.util
import itertools
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
M14 = os.path.join(FIXTURES, "bhive-m14")
READER = os.path.join(ROOT, "docs", "bhive_reader.py")
sys.path.insert(0, os.path.join(ROOT, "docs"))  # -I leaves it out

import bhive_reader as r  # noqa: E402

_spec = importlib.util.spec_from_file_location("make_vectors", os.path.join(M14, "make-vectors.py"))
mv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mv)  # the writer of the encrypted variants


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def whole(path):
    with open(path, "rb") as f:
        return f.read()


V = load(os.path.join(M14, "vectors.json"))
EDGES = load(os.path.join(M14, "ed25519-edges.json"))
OPENSSL = load(os.path.join(HERE, "openssl.json"))
h = bytes.fromhex
uv = mv.uvarint

# One Argon2id per password and slot: the same slot is opened many times below.
ARGON2 = r.argon2id
r.argon2id = functools.lru_cache(maxsize=None)(r.argon2id)

TMP = tempfile.mkdtemp(prefix="bhive-reader-")
_names = itertools.count()


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def write(data, suffix=".bhive", mode="wb"):
    path = os.path.join(TMP, f"{next(_names)}{suffix}")
    with open(path, mode) as f:
        f.write(data)
    return path


def in_python(code):
    """What this code prints, run with `r` as the reader in a Python of its own, which `-c` keeps
    from loading this file again in the processes it starts."""
    code = f"import sys\nsys.path.insert(0, {os.path.join(ROOT, 'docs')!r})\nimport bhive_reader as r\n{code}"
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=300)
    return p.stdout.strip() or p.stderr


def keys(passwords=(), recovery=(), files=(), key_password=None):
    k = r.Keys()
    k.passwords += passwords
    for text in recovery:
        k.add_recovery_key(text)
    for path in files:
        k.add_file(path, key_password)
    return k


def read(data, k=None, recover=False):
    """The archive, with every cell read (and so checked)."""
    a = r.Archive(write(data), recover, k)
    for n in range(len(a.cells)):
        a.cell(n)
    return a


LEVELS = ["none", "fast", "balanced", "high", "max"]
SEALED_FIXTURES = load(os.path.join(FIXTURES, "bhive", "sealed.json"))["fixtures"]
SMALL = whole(os.path.join(FIXTURES, "bhive", "spec-small.bhive"))
SEALED = whole(os.path.join(M14, "spec-sealed.bhive"))
SIGNED = whole(os.path.join(M14, "spec-signed.bhive"))
HONEY = keys(["honey"])


def listing(a):
    return [(e.kind, e.path, e.size, e.modified, e.created, e.mode, e.attributes, e.target) for e in a.entries]


def contents(a):
    return [b"".join(a.read(e)) for e in a.entries]


SMALL_LIST = listing(read(SMALL))


def plain(sections=b"", items=None):
    """spec-small.bhive with these index sections after its entries (and these entries)."""
    _, _, _, _, row, small_items = mv.spec_small()
    raw = uv(1) + row + uv(4) + (small_items if items is None else items) + sections
    head = b"BHIX" + bytes(4) + struct.pack("<QQQ", len(raw), len(raw), r.xxh3_64(raw))
    return SMALL[:0xA5] + head + raw + struct.pack("<Q", 0xA5) + mv.MAGIC


def section(ident, body):
    return uv(ident) + uv(len(body)) + body


def lv(b):
    return uv(len(b)) + b


DIGESTS = section(2, h(V["signed_example"]["cell_digest"]))
SECTION_3 = h(V["signed_example"]["section_3"])
ATTRS = h(V["signed_example"]["signed_attributes"])


def record(alg, signer, sig, attrs=ATTRS, unsigned=b"", extra=b""):
    return bytes([alg, 0]) + lv(signer) + lv(attrs) + lv(sig) + lv(unsigned) + extra


def signatures(*records):
    return section(3, uv(len(records)) + b"".join(lv(x) for x in records))


SIGNER_1 = h(V["signed_example"]["ed25519_public"]) + h(V["signed_example"]["mldsa_public"])
SIG_1 = h(V["signed_example"]["ed25519_signature"]) + h(V["signed_example"]["mldsa_signature"])


def statuses(data, k=None):
    a = r.Archive(write(data), keys=k)
    a.f.close()
    return [(s.status, s.why) for s in a.signatures()]


def sealed(slots=None, sections=b"", items=None, inner_hook=None, label="reader test"):
    """spec-small's contents encrypted under the slot vectors' file key, with all eight of their slots."""
    names = ("password", "recovery_key", "x25519", "xwing", "rsa", "p256", "p384", "fido2")
    if slots is None:
        slots = [h(V["slots"][n]["slot"]) for n in names]
    return mv.sealed_archive(
        h(V["slots"]["file_key"]), h(V["slots"]["key_id"]), mv.rnd(f"{label} archive id", 32), slots, sections,
        mv.rnd(f"{label} cell id", 32), mv.rnd(f"{label} nonce", 12), mv.rnd(f"{label} salt", 32), items, inner_hook,
    )[0]  # fmt: skip


def rehead(raw):
    """An inner index block for these raw bytes, its lengths and checksum made to fit."""
    return b"BHIX" + bytes(4) + struct.pack("<QQQ", len(raw), len(raw), r.xxh3_64(raw)) + raw


class Published(unittest.TestCase):
    """A few of the primitives' published vectors (the PR checked them against all of them)."""

    def test_aes_fips_197(self):
        rks = r.expand_key(bytes(range(32)))
        self.assertEqual(r.encrypt_block(rks, h("00112233445566778899aabbccddeeff")), h("8ea2b7ca516745bfeafc49904b496089"))
        self.assertEqual(r.decrypt_block(rks, h("8ea2b7ca516745bfeafc49904b496089")), h("00112233445566778899aabbccddeeff"))

    def test_hkdf_rfc_5869(self):
        okm = r.hkdf(bytes([0x0B] * 22), h("000102030405060708090a0b0c"), h("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(okm, h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))

    def test_argon2id_rfc_9106(self):
        want = h("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        args = (bytes([1] * 32), bytes([2] * 16), 3, 32, 4)
        kw = {"secret": bytes([3] * 8), "ad": bytes([4] * 12)}
        self.assertEqual(ARGON2(*args, **kw, processes=False), want)
        self.assertEqual(ARGON2(*args, **kw, readable=True), want)
        # A process per lane, from a Python of its own: here, each lane would load this file again.
        got = in_python(f"print(r.argon2id(*{args!r}, **{kw!r}, processes=True).hex())")
        self.assertEqual(got, want.hex())

    def test_argon2id_a_lane_that_dies(self):
        # One lane's process killed: the others are stopped, and the parent says so, without
        # waiting for them forever at the next sync point.
        got = in_python(
            "import multiprocessing, threading, time\n"
            "result = []\n"
            "def run():\n"
            "    try:\n"
            "        r.argon2id(b'password', b'somesalt' * 2, 16, 16384, 4, processes=True)\n"
            "        result.append('finished')\n"
            "    except RuntimeError as e:\n"
            "        result.append(str(e))\n"
            "t = threading.Thread(target=run, daemon=True)\n"
            "t.start()\n"
            "deadline = time.monotonic() + 60\n"
            "while len(multiprocessing.active_children()) < 4 and time.monotonic() < deadline:\n"
            "    time.sleep(0.05)\n"
            "multiprocessing.active_children()[0].kill()\n"
            "t.join(60)\n"
            "for p in multiprocessing.active_children():\n"
            "    p.kill()\n"
            "print(result[0] if result else 'still waiting')\n"
        )
        self.assertEqual(got, "an Argon2 lane's process failed")

    def test_x25519_rfc_7748(self):
        k = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(r.x25519(k, u), h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"))

    def test_ed25519_rfc_8032(self):
        for seed, pub, msg, sig in (
            ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
             "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
             "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        ):  # fmt: skip
            self.assertEqual(mv.ed25519_public(h(seed)), h(pub))
            self.assertTrue(r.ed25519_verify(h(pub), h(msg), h(sig)))
            self.assertFalse(r.ed25519_verify(h(pub), h(msg) + b"!", h(sig)))

    def test_ed25519_edges_as_ring(self):
        # These are what ring 0.17.14 itself answered when the PR was made (docs/bhive.md §13.4).
        for c in EDGES["cases"]:
            with self.subTest(c["name"]):
                self.assertEqual(r.ed25519_verify(h(c["public"]), h(c["message"]), h(c["signature"])), c["valid"])


class Vectors(unittest.TestCase):
    """tests/fixtures/bhive-m14/vectors.json, which make-vectors.py made (bhive.md §12.11, §13.6)."""

    def test_keys(self):
        k = V["keys"]
        fk = h(k["file_key"])
        self.assertEqual(r.hkdf(fk, h(k["archive_id"]), b"bhive1 mac"), h(k["mac_key"]))
        self.assertEqual(r.hkdf(fk, h(k["archive_id"]), b"bhive1 record"), h(k["record_key"]))
        self.assertEqual(r.hkdf(fk, h(k["cell_id"]), b"bhive1 cell"), h(k["cell_key"]))
        self.assertEqual(r.hkdf(fk, h(k["index_salt"]), b"bhive1 index"), h(k["index_key"]))

    def test_segments(self):
        s = V["segments"]
        data = bytes(i % 251 for i in range(r.SEGMENT + 5))
        key = h(s["key"])
        sealed_ = mv.seal_segments(key, data, b"")
        self.assertEqual(len(sealed_), s["sealed_length"])
        self.assertEqual(r.sealed_len(len(data)), s["sealed_length"])
        self.assertEqual(hashlib.sha256(sealed_).hexdigest(), s["sealed_sha256"])
        self.assertEqual(sealed_[r.SEGMENT : r.SEGMENT + 16], h(s["tag_0"]))
        self.assertEqual(sealed_[-16:], h(s["tag_1"]))
        self.assertEqual(r.open_segments(key, sealed_, b"", "the cell"), data)
        full = r.SEGMENT + 16
        for bad in (
            sealed_[:full],  # cut after the first segment: it isn't marked last
            sealed_[:-1],  # a byte short
            sealed_[full:] + sealed_[:full],  # reordered
            sealed_[:5] + bytes([sealed_[5] ^ 1]) + sealed_[6:],
            sealed_[:full] + sealed_[full : full + 16],  # a last segment of nothing but a tag
        ):
            with self.assertRaises(r.Bad):
                r.open_segments(key, bad, b"", "the cell")
        self.assertEqual(r.open_segments(key, mv.seal_segments(key, b"", b""), b"", "x"), b"")  # one empty segment
        with self.assertRaises(r.Bad):
            r.open_segments(key, mv.seal_segments(key, b"", b""), b"aad", "x")

    def test_slots(self):
        sv = V["slots"]
        fk, kid = h(sv["file_key"]), h(sv["key_id"])

        def opens(name, secret, recipient=b""):
            v = sv[name]
            slot = r.Slot(h(v["slot"]))
            self.assertEqual(h(v["secret"]), secret, name)
            context = hashlib.sha256(b"bhive1 slot" + kid + slot.framed + recipient).digest()
            self.assertEqual(context, h(v["context"]), name)
            prk = r.hmac.new(context, secret, hashlib.sha256).digest()
            self.assertEqual(prk, h(v["prk"]), name)
            okm = r.hkdf_expand(prk, b"bhive1 slot", 64)
            self.assertEqual((okm[:32], okm[32:]), (h(v["wrap_key"]), h(v["commitment"])), name)
            self.assertEqual(slot.commitment, h(v["commitment"]), name)
            self.assertEqual(slot.open(kid, secret, recipient), fk, name)
            self.assertIsNone(slot.open(kid, bytes(len(secret)), recipient), name)
            return slot

        v = sv["password"]
        typed = unicodedata.normalize("NFC", v["password_as_typed_nfd"]).encode()
        slot = r.Slot(h(v["slot"]))
        opens("password", r.argon2id(typed, slot.public[16:48], v["passes"], v["memory_kib"], v["lanes"]))
        self.assertEqual(slot.describe(), "Argon2id, 256 KiB, 2 passes, 4 lanes")

        k = keys(recovery=[sv["recovery_key"]["digits"]])
        self.assertEqual(k.recovery, [h(sv["recovery_key"]["key"])])
        opens("recovery_key", k.recovery[0])

        v = sv["x25519"]
        k = keys(files=[write(f"# a test key\n{v['secret_text']}\n".encode())])
        (sk, pk), = k.x25519
        self.assertEqual((sk, pk), (h(v["recipient_secret"]), h(v["recipient_public"])))
        self.assertEqual(r.bech32_decode(v["recipient_text"]), ("age", pk))
        slot = r.Slot(h(v["slot"]))
        self.assertEqual(r.x25519_public(h(v["ephemeral_secret"])), slot.public)
        opens("x25519", r.x25519(sk, slot.public), pk)

        v = sv["xwing"]
        k = keys(files=[write(v["secret_text"].encode())])
        self.assertEqual(k.xwing, [h(v["recipient_seed"])])
        self.assertEqual(r.xwing_public(k.xwing[0]), h(v["recipient_public"]))
        self.assertEqual(r.bech32_decode(v["recipient_text"]), ("age1pq", h(v["recipient_public"])))
        opens("xwing", r.xwing_decaps(k.xwing[0], r.Slot(h(v["slot"])).public))
        self.assertEqual(r.xwing_encaps(h(v["recipient_public"]), h(v["encapsulation_seed"])), (h(v["secret"]), r.Slot(h(v["slot"])).public))

        v = sv["rsa"]
        key = r.pkcs8_key(h(v["pkcs8"]))
        slot = r.Slot(h(v["slot"]))
        opens("rsa", r.rsa_oaep_decrypt(key, slot.public[6:]))
        self.assertEqual(r.slot_tag(h(v["spki"]), 5, slot.public[6:]), h(v["tag"]))
        self.assertEqual(slot.public[:4], h(v["tag"]))

        for name, curve, kind in (("p256", r.P256, 6), ("p384", r.P384, 7)):
            v = sv[name]
            key = r.pkcs8_key(h(v["pkcs8"]))
            self.assertIs(key.curve, curve)
            self.assertEqual(key.public, h(v["recipient_public"]))
            slot = r.Slot(h(v["slot"]))
            eph = slot.public[4:]
            self.assertEqual(r.ec_encode(curve, r.ec_multiply(curve, int(v["ephemeral_scalar"], 16), curve.g)), eph)
            opens(name, r.ecdh_x(curve, key.d, r.ec_point(curve, eph)), key.public)
            self.assertEqual(r.slot_tag(h(v["spki"]), kind, eph), h(v["tag"]))
            self.assertEqual(slot.public[:4], h(v["tag"]))

        v = sv["fido2"]
        slot = opens("fido2", h(v["secret"]))
        cred = h(v["credential_id"])
        self.assertEqual(slot.public, bytes([2, 0]) + struct.pack("<H", len(cred)) + cred + b"\x06beezip" + h(v["salt"]))
        self.assertEqual(slot.describe(), f"relying party beezip, credential {v['credential_id']}")

    def test_sealed_example(self):
        se = V["sealed_example"]
        a = read(SEALED, HONEY)
        self.assertEqual(listing(a), SMALL_LIST)
        self.assertEqual(contents(a), contents(read(SMALL)))
        self.assertEqual(a.envelope.file_key, h(se["file_key"]))
        self.assertEqual(a.keyblock.archive_id, h(se["archive_id"]))
        fk, aid = h(se["file_key"]), h(se["archive_id"])
        self.assertEqual(r.hkdf(fk, aid, b"bhive1 mac"), h(se["mac_key"]))
        self.assertEqual(r.hkdf(fk, h(se["cell_id"]), b"bhive1 cell"), h(se["cell_key"]))
        self.assertEqual(r.hkdf(fk, h(se["index_salt"]), b"bhive1 index"), h(se["index_key"]))
        self.assertEqual(SEALED[0xFC:0x108], h(se["record_nonce"]))
        self.assertEqual(SEALED[0x1ED:0x20D], h(se["index_salt"]))
        self.assertEqual(a.raw, h(se["index_raw"]))
        slot = a.keyblock.slots[0]
        self.assertEqual(slot.framed + slot.commitment + slot.wrapped, h(se["slot"]["slot"]))
        self.assertEqual(r.argon2id(se["password"].encode(), slot.public[16:48], 2, 256, 4), h(se["slot"]["secret"]))
        self.assertEqual(a.keyblock.mac, h(se["header_mac"]))
        self.assertEqual(a.keyblock.key_id, h(se["key_id"]))
        self.assertEqual(a.envelope.record_key, h(se["record_key"]))
        self.assertEqual(a.cells[0].cid, h(se["cell_id"]))
        self.assertEqual([d[1] for d in a.descriptions], [b"Password"])
        # The record, which a reader with the index never needs (§6).
        cid, head, journal = a.envelope.open_record(0xF0, SEALED[0xF0:0x108], SEALED[0x108:0x1C3])
        self.assertEqual(cid + head + journal, h(se["record_plain"]))

    def test_signed_example(self):
        se = V["signed_example"]
        a = read(SIGNED)
        self.assertEqual(listing(a), SMALL_LIST)
        self.assertEqual(a.manifest(), h(se["manifest"]))
        self.assertEqual(a.raw, h(se["index_raw"]))
        self.assertEqual(mv.ed25519_public(h(se["ed25519_seed"])), h(se["ed25519_public"]))
        self.assertEqual(r.bech32_decode(se["secret_text"]), ("bzsig-secret-key-", h(se["ed25519_seed"]) + h(se["mldsa_seed"])))
        self.assertEqual(a.digests, [h(se["cell_digest"])])
        self.assertEqual([x[2] for x in a.sections if x[0] == 3], [SECTION_3[3:]])
        (sig,) = a.signatures()
        self.assertEqual((sig.status, sig.algorithm, sig.time), ("checked", 1, 1767225600))
        self.assertEqual(sig.signer, SIGNER_1)
        self.assertEqual(r.fingerprint(sig.signer), se["fingerprint"])
        self.assertEqual(r.bech32_decode(se["signer_text"]), ("bzsig", SIGNER_1))
        msg = h(se["message"])
        self.assertEqual(msg, b"bhive1 signature\x01" + a.manifest() + hashlib.sha256(SIGNER_1).digest() + hashlib.sha256(ATTRS).digest())
        self.assertTrue(r.ed25519_verify(SIGNER_1[:32], msg, h(se["ed25519_signature"])))
        self.assertTrue(r.mldsa65_verify(SIGNER_1[32:], msg, h(se["mldsa_signature"]), b"bhive1"))
        self.assertFalse(r.mldsa65_verify(SIGNER_1[32:], msg, h(se["mldsa_signature"]), b"bhive2"))
        self.assertFalse(r.mldsa65_verify(SIGNER_1[32:], msg + b"!", h(se["mldsa_signature"]), b"bhive1"))


class Fixtures(unittest.TestCase):
    """Every .bhive under tests/fixtures."""

    def as_recorded(self, a, fx):
        """The archive holds what its record in manifest.json or sealed.json says."""
        self.assertEqual(a.signatures(), [])
        want = [(e["kind"], e["path"], e.get("size", 0)) for e in fx["entries"]]
        self.assertEqual([(e.kind, e.path, e.size) for e in a.entries], want)
        for e, w in zip(a.entries, fx["entries"]):
            self.assertEqual(e.modified, tuple(w["modified"]) if w.get("modified") else None, e.path)
            self.assertEqual(e.created, tuple(w["created"]) if w.get("created") else None, e.path)
            self.assertEqual((e.mode, e.attributes, e.target), (w.get("mode"), w.get("attributes"), w.get("target")))
            if "sha256" in w:
                self.assertEqual(hashlib.sha256(b"".join(a.read(e))).hexdigest(), w["sha256"], e.path)
        if "level" in fx and not a.incomplete:
            self.assertEqual(a.level, LEVELS.index(fx["level"]))

    def test_m13_fixtures_as_their_manifest_says(self):
        for fx in load(os.path.join(FIXTURES, "bhive", "manifest.json"))["fixtures"]:
            with self.subTest(fx["file"]):
                a = read(whole(os.path.join(FIXTURES, "bhive", fx["file"])), recover=fx.get("recover", False))
                self.assertEqual(bool(a.incomplete), fx.get("recover", False))
                self.assertIsNone(a.keyblock)
                self.as_recorded(a, fx)

    def test_sealed_fixtures_as_their_record_says(self):
        """BeeZip's encrypted fixtures (sealed.json): each opens with every password and the
        recovery key its record lists, holds what it says, and opens with nothing else."""
        self.assertEqual(len(SEALED_FIXTURES), 7)
        for fx in SEALED_FIXTURES:
            data = whole(os.path.join(FIXTURES, "bhive", fx["file"]))
            ways = [keys([p]) for p in fx["passwords"]]
            labels = [b"Password"] * len(ways)
            if "recovery_key" in fx:
                ways.append(keys(recovery=[fx["recovery_key"]]))
                labels.append(b"Recovery key")
            self.assertTrue(ways, fx["file"])
            for i, k in enumerate(ways):
                with self.subTest(fx["file"], way=i):
                    a = read(data, k)
                    self.assertIsNotNone(a.keyblock)
                    self.assertEqual([d[1] for d in a.descriptions], labels)
                    self.as_recorded(a, fx)
            for k in (None, keys(["Honey"]), keys(recovery=["000000-" * 7 + "000000"])):
                with self.subTest(fx["file"], way="a wrong one"), self.assertRaises(r.Locked):
                    read(data, k)

    def test_m14_examples(self):
        self.assertEqual(listing(read(SEALED, HONEY)), SMALL_LIST)
        self.assertEqual(listing(read(SIGNED)), SMALL_LIST)
        with self.assertRaises(r.Locked):
            read(SEALED)
        with self.assertRaises(r.Locked):
            read(SEALED, keys(["Honey"]))

    def test_malicious(self):
        refused = {
            "bhive-extent-past-cell.bhive", "bhive-extent-no-cell.bhive", "bhive-cells-overlap.bhive",
            "bhive-entries-2-60.bhive", "bhive-cells-2-60.bhive", "bhive-cell-over-256m.bhive", "bhive-index-more.bhive",
            "bhive-footer-outside.bhive", "bhive-footer-in-cell.bhive", "bhive-version-2.bhive", "bhive-feature.bhive",
            "bhive-cut-index.bhive", "bhive-raw-more.bhive", "bhive-raw-less.bhive", "bhive-cut-cell.bhive",
            "bhive-cut-footer.bhive", "bhive-cut-header.bhive", "bhive-cut-index-head.bhive", "bhive-cut-journal.bhive",
            "bhive-cut-record.bhive",
        }  # fmt: skip
        folder = os.path.join(FIXTURES, "malicious")
        names = sorted(n for n in os.listdir(folder) if n.endswith(".bhive"))
        self.assertTrue(refused <= set(names))
        for name in names:
            with self.subTest(name):
                data = whole(os.path.join(folder, name))
                if name in refused:
                    with self.assertRaises(r.Bad):
                        read(data)
                elif len(data) < 1 << 20:  # the others are hostile but well formed, or refused
                    try:
                        a = r.Archive(write(data))
                        a.f.close()
                    except r.Bad:
                        pass


class Encrypted(unittest.TestCase):
    """Every way in a key file or a typed secret gives (§12.5), and what a reader refuses (§12.10)."""

    def test_every_kind_of_slot_opens_the_archive(self):
        sv, of = V["slots"], OPENSSL["key_files"]
        labels = [b"Password", b"Recovery key", b"Ann", b"Bea", b"RSA", b"P-256", b"P-384", b"YubiKey"]
        desc = uv(8) + b"".join(lv(uv(1) + lv(x)) for x in labels)
        data = sealed(sections=section(5, desc))
        pkcs8_pem = lambda name: write(  # noqa: E731
            ("-----BEGIN PRIVATE KEY-----\n" + __import__("base64").encodebytes(h(sv[name]["pkcs8"])).decode() + "-----END PRIVATE KEY-----\n").encode(),
            ".pem",
        )
        ways = {
            "password, typed in NFD": keys([sv["password"]["password_as_typed_nfd"]]),
            "recovery key": keys(recovery=[sv["recovery_key"]["digits"].replace("-", " ")]),
            "age X25519 identity": keys(files=[write(sv["x25519"]["secret_text"].encode())]),
            "age post-quantum identity": keys(files=[write(sv["xwing"]["secret_text"].encode())]),
            "RSA, PKCS #8 DER": keys(files=[write(h(sv["rsa"]["pkcs8"]), ".der")]),
            "RSA, PKCS #8 PEM": keys(files=[pkcs8_pem("rsa")]),
            "RSA, PKCS #1": keys(files=[write(of["rsa"]["pkcs1"].encode())]),
            "RSA, PBKDF2": keys(files=[write(of["rsa"]["pbkdf2"].encode())], key_password="bee"),
            "P-256, SEC 1": keys(files=[write(of["p256"]["sec1"].encode())]),
            "P-256, scrypt": keys(files=[write(of["p256"]["scrypt"].encode())], key_password="bee"),
            "P-384, PKCS #8 DER": keys(files=[write(h(sv["p384"]["pkcs8"]), ".der")]),
            "P-384, PBKDF2": keys(files=[write(of["p384"]["pbkdf2"].encode())], key_password="bee"),
            "P-384, scrypt": keys(files=[write(of["p384"]["scrypt"].encode())], key_password="bee"),
        }
        for what, k in ways.items():
            with self.subTest(what):
                a = read(data, k)
                self.assertEqual(listing(a), SMALL_LIST)
                self.assertEqual([d[1] for d in a.descriptions], labels)
        with self.assertRaises(r.Locked) as e:
            read(data)
        self.assertIn("security key", str(e.exception))
        with self.assertRaises(r.Usage):
            keys(files=[write(of["rsa"]["pbkdf2"].encode())], key_password="wasp")
        with self.assertRaises(r.Usage):
            keys(files=[write(of["rsa"]["pbkdf2"].encode())])
        with self.assertRaises(r.Usage):
            keys(recovery=["356774-427328-015675-503074-433114-110891-467621-387916"])  # a typo
        with self.assertRaises(r.Usage):
            keys(recovery=["356774-427328"])
        # A key that isn't this archive's: none of its slots opens.
        with self.assertRaises(r.Locked):
            read(data, keys(files=[write(mv.bech32("AGE-SECRET-KEY-", bytes(range(32))).encode())]))

    def test_each_changed_byte_is_refused_or_found(self):
        """A changed byte in the key block or the index refuses the archive; in a sealed cell it
        fails that cell. The cell block's head and record are read only when recovering (§6)."""
        for at in range(len(SEALED)):
            for bit in (0x01, 0x80):
                data = SEALED[:at] + bytes([SEALED[at] ^ bit]) + SEALED[at + 1 :]
                with self.subTest(at=hex(at), bit=bit):
                    if 0xF0 <= at < 0x1C3:
                        self.assertEqual(listing(read(data, HONEY)), SMALL_LIST)
                        a = r.Archive(write(data[: 0x1DD]), True, HONEY)  # the index cut off: recover
                        self.assertEqual(a.entries, [])
                    elif 0x1C3 <= at < 0x1DD:
                        a = r.Archive(write(data), keys=HONEY)
                        self.assertEqual(listing(a), SMALL_LIST)
                        with self.assertRaises(r.Bad):
                            a.cell(0)
                    else:
                        with self.assertRaises((r.Bad, r.Locked)):
                            read(data, HONEY)

    def test_cut_short(self):
        for n in range(len(SEALED)):
            with self.subTest(n):
                with self.assertRaises((r.Bad, r.Locked)):
                    read(SEALED[:n], HONEY)
        # From its records, given a way in (§12.10).
        a = r.Archive(write(SEALED[:0x1DD]), True, HONEY)
        self.assertTrue(a.incomplete)
        self.assertEqual(listing(a), SMALL_LIST)
        self.assertEqual(contents(a), contents(read(SMALL)))
        a = r.Archive(write(SEALED[:0x1DC]), True, HONEY)
        self.assertEqual(a.entries, [])

    def test_a_sealed_fixture_cut_or_changed(self):
        """BeeZip's sealed-recovery.bhive, cut and changed as BeeZip's own tests change theirs:
        refused, and what recovery still finds in its record (§12.7, §12.10)."""
        fx = next(f for f in SEALED_FIXTURES if f["file"] == "sealed-recovery.bhive")
        data = whole(os.path.join(FIXTURES, "bhive", fx["file"]))
        k = keys(recovery=[fx["recovery_key"]])
        good = read(data, k)
        want, got = listing(good), contents(good)
        (cell,) = good.cells
        index_at = struct.unpack_from("<Q", data, len(data) - 16)[0]
        self.assertEqual(index_at, cell.offset + cell.size())

        def recovered(data):
            a = r.Archive(write(data), True, k)
            self.assertTrue(a.incomplete)
            return listing(a), contents(a)

        # Cut: refused; recovered, the cell once it is whole, and nothing before.
        for n in [*range(0, len(data), 97), len(data) - 1]:
            with self.subTest(cut=n):
                with self.assertRaises((r.Bad, r.Locked)):
                    read(data[:n], k)
                if n < good.start:
                    with self.assertRaises((r.Bad, r.Locked)):
                        r.Archive(write(data[:n]), True, k)
                else:
                    self.assertEqual(recovered(data[:n]), (want, got) if n >= index_at else ([], []))
        # The sealed index changed: refused, and recovered from the record.
        index = bytearray(data)
        index[index_at + 60] ^= 1
        with self.assertRaises(r.Bad):
            read(bytes(index), k)
        self.assertEqual(recovered(bytes(index)), (want, got))
        # The sealed index's length anything but its own, up to u64's largest: refused, and the
        # block is skipped by it when recovering.
        s = struct.unpack_from("<Q", data, index_at + 8)[0]
        for wrong in (0, s - 1, s + 1, len(data), len(data) + 1, (1 << 64) - 1):
            with self.subTest(length=wrong):
                b = data[: index_at + 8] + struct.pack("<Q", wrong) + data[index_at + 16 :]
                with self.assertRaises(r.Bad):
                    read(b, k)
                self.assertEqual(recovered(b), (want, got))
        # The record changed: the index doesn't need it; without the index, nothing is found.
        record = bytearray(data)
        record[cell.offset - 40] ^= 1
        a = read(bytes(record), k)
        self.assertEqual((listing(a), contents(a)), (want, got))
        record[index_at + 60] ^= 1
        self.assertEqual(recovered(bytes(record)), ([], []))

    def test_a_cell_from_another_archive_under_the_same_key(self):
        """Two archives under one file key, each cell with its own id: a cell moved from one into
        the other, in the same place and of the same length, doesn't open (§12.6)."""
        pw = keys([V["slots"]["password"]["password_as_typed_nfd"]])
        slots = [h(V["slots"]["password"]["slot"])]
        one, two = sealed(slots, label="one"), sealed(slots, label="two")
        (a,), (b,) = read(one, pw).cells, read(two, pw).cells
        self.assertEqual((a.offset, a.size()), (b.offset, b.size()))
        moved = one[: a.offset] + two[b.offset : b.offset + b.size()] + one[a.offset + a.size() :]
        archive = r.Archive(write(moved), keys=pw)
        self.assertEqual(listing(archive), SMALL_LIST)
        with self.assertRaises(r.Bad):
            archive.cell(0)

    def test_key_block_rules(self):
        kb = SEALED[16:0xF0]

        def with_key_block(new):
            return SEALED[:16] + new + SEALED[0xF0:]

        def patched(at, value):
            return with_key_block(kb[:at] + value + kb[at + len(value) :])

        slot = kb[60:-32]
        refused = {
            "the tag": patched(0, b"BHKX"),
            "suite 2": patched(4, b"\x02"),
            "no slots": patched(6, struct.pack("<H", 0)),
            "65 slots": patched(6, struct.pack("<H", 65)),
            "two slots counted, one there": patched(6, struct.pack("<H", 2)),
            "a slots length over 64 KiB": patched(8, struct.pack("<I", 65_537)),
            "a slots length past the slot": patched(8, struct.pack("<I", 133)),
            "a body under 80 bytes": patched(62, struct.pack("<H", 79)),
            "Argon2 version 0x10": patched(64, b"\x10"),
            "memory over 4 GiB": patched(68, struct.pack("<I", (4 << 20) + 1)),
            "memory under 8 KiB a lane": patched(68, struct.pack("<I", 31)),
            "no passes": patched(72, struct.pack("<I", 0)),
            "17 passes": patched(72, struct.pack("<I", 17)),
            "no lanes": patched(76, struct.pack("<I", 0)),
            "17 lanes": patched(76, struct.pack("<I", 17)),
            "five password slots": with_key_block(
                kb[:6] + struct.pack("<HI", 5, 5 * len(slot)) + kb[12:60] + slot * 5 + kb[-32:]
            ),
            "the header MAC": patched(len(kb) - 1, bytes([kb[-1] ^ 1])),
            "the wrapped key": patched(len(kb) - 33, bytes([kb[-33] ^ 1])),
        }
        for what, data in refused.items():
            with self.subTest(what):
                with self.assertRaises(r.Bad):
                    read(data, HONEY)
        # Each kind's public part fills it exactly.
        for name, cut in (("x25519", 1), ("xwing", 1), ("rsa", 1), ("p256", 1), ("p384", 1), ("fido2", 1), ("recovery_key", 1)):
            s = bytearray(h(V["slots"][name]["slot"]))
            s[2:4] = struct.pack("<H", struct.unpack_from("<H", s, 2)[0] - cut)
            del s[4]
            with self.subTest(name), self.assertRaises(r.Bad):
                r.Slot(bytes(s))
        # A slot of a kind this reader doesn't know is skipped; alone, it says a newer program made it.
        unknown = bytes([9, 0]) + struct.pack("<H", 90) + bytes(90)
        password = h(V["slots"]["password"]["slot"])
        self.assertEqual(listing(read(sealed([unknown, password]), keys([V["slots"]["password"]["password_as_typed_nfd"]]))), SMALL_LIST)
        with self.assertRaises(r.Bad) as e:
            read(sealed([unknown]), HONEY)
        self.assertIn("newer program", str(e.exception))

    def test_bad_points_and_shares_are_refused(self):
        sv = V["slots"]
        fk, kid = h(sv["file_key"]), h(sv["key_id"])
        # An EC slot whose ephemeral key is off the curve, tried with a P-256 key.
        public = b"\0\0\0\0\x04" + bytes(64)
        bad_ec, _ = mv.make_slot(6, public, bytes(32), fk, kid)
        with self.assertRaises(r.Bad):
            read(sealed([bad_ec]), keys(files=[write(h(sv["p256"]["pkcs8"]), ".der")]))
        # An X25519 slot with a share of small order.
        bad_x, _ = mv.make_slot(3, bytes(32), bytes(32), fk, kid)
        with self.assertRaises(r.Bad):
            read(sealed([bad_x]), keys(files=[write(sv["x25519"]["secret_text"].encode())]))

    def test_index_rules(self):
        pw = keys([V["slots"]["password"]["password_as_typed_nfd"]])
        slots = [h(V["slots"]["password"]["slot"])]
        good = sealed(slots)
        self.assertEqual(listing(read(good, pw)), SMALL_LIST)

        def raw_hook(fn):
            return lambda inner: rehead(fn(inner[32:]))

        offset = struct.unpack_from("<Q", good, len(good) - 16)[0]
        cases = {
            "an inner head that measures more": lambda inner: inner[:8] + struct.pack("<Q", len(inner) - 31) + inner[16:],
            "an inner head that measures less": lambda inner: inner[:8] + struct.pack("<Q", len(inner) - 33) + inner[16:],
            "an inner head of another tag": lambda inner: b"BHIE" + inner[4:],
            "a cell closer than 120 bytes to the key block": raw_hook(
                lambda raw: raw[:1] + struct.pack("<Q", struct.unpack_from("<Q", raw, 1)[0] - 100) + raw[9:]
            ),
            "a cell that runs into the index block": raw_hook(
                lambda raw: raw[:1] + struct.pack("<Q", offset - 25) + raw[9:]
            ),
            "26-byte rows": raw_hook(lambda raw: raw[:27] + raw[59:]),
            "sections out of order": raw_hook(lambda raw: raw + section(4, b"") + section(2, bytes(32))),
            "a section twice": raw_hook(lambda raw: raw + section(4, b"") + section(4, b"")),
            "a number not in its shortest form": raw_hook(lambda raw: raw[:59] + b"\x84\x00" + raw[60:]),
            "bytes that aren't a section": raw_hook(lambda raw: raw + b"\x07"),
        }
        for what, hook in cases.items():
            with self.subTest(what), self.assertRaises(r.Bad):
                read(sealed(slots, inner_hook=hook), pw)
        # Section 5 whose count isn't the slot count is ignored.
        a = read(sealed(slots, sections=section(5, uv(2) + lv(b"") + lv(b""))), pw)
        self.assertIsNone(a.descriptions)
        # The index block's own fields.
        at = offset
        for what, data in {
            "its tag": good[:at] + b"BHIX" + good[at + 4 :],
            "its sealed length": good[:at + 8] + struct.pack("<Q", 1 << 40) + good[at + 16 :],
            "its reserved bytes, which its seal covers": good[:at + 4] + b"\x01" + good[at + 5 :],
        }.items():
            with self.subTest(what), self.assertRaises(r.Bad):
                read(data, pw)

    def test_encrypting_keeps_the_signature(self):
        pw = keys([V["slots"]["password"]["password_as_typed_nfd"]])
        slots = [h(V["slots"]["password"]["slot"])]
        signed = DIGESTS + SECTION_3 + section(5, uv(1) + lv(uv(1) + lv(b"Password")))
        a = read(sealed(slots, sections=signed), pw)
        self.assertEqual(a.manifest(), h(V["signed_example"]["manifest"]))
        self.assertEqual([s.status for s in a.signatures()], ["checked"])
        _, _, _, _, _, items = mv.spec_small()
        changed = items.replace(b"docs/a.txt", b"docs/A.txt")
        a = read(sealed(slots, sections=signed, items=changed), pw)
        self.assertEqual([s.status for s in a.signatures()], ["failed"])


class Signatures(unittest.TestCase):
    """Section 3 checked as §13 says: checked, failed, or couldn't check and why."""

    def test_the_algorithms(self):
        signed = []
        for name, s in OPENSSL["signers"].items():
            cert, sig = h(s["certificate"]), h(s["signature"])
            rec = record(s["algorithm"], uv(1) + lv(cert), sig)
            signed.append(rec)
            with self.subTest(name):
                got = statuses(plain(DIGESTS + signatures(rec)))
                if name == "2 rsa1024":
                    self.assertEqual(got[0][0], "unchecked")
                    self.assertIn("2,048 to 8,192", got[0][1])
                    continue
                self.assertEqual(got, [("checked", "")])
                bad = sig[:-1] + bytes([sig[-1] ^ 1])
                self.assertEqual(statuses(plain(DIGESTS + signatures(record(s["algorithm"], uv(1) + lv(cert), bad))))[0][0], "failed")
                # The same signature under another algorithm byte signs another message.
                other = {2: 3, 3: 2, 4: 5, 5: 4}[s["algorithm"]]
                self.assertNotEqual(statuses(plain(DIGESTS + signatures(record(other, uv(1) + lv(cert), sig))))[0][0], "checked")
        # Six signers on one archive, and the archive changed after: every one fails.
        signed.append(record(1, SIGNER_1, SIG_1))
        got = [s for s, _ in statuses(plain(DIGESTS + signatures(*signed)))]
        self.assertEqual(got, ["checked"] * 4 + ["unchecked", "checked"])
        _, _, _, _, _, items = mv.spec_small()
        got = [s for s, _ in statuses(plain(DIGESTS + signatures(*signed), items.replace(b"docs/a.txt", b"docs/A.txt")))]
        self.assertEqual(got, ["failed"] * 4 + ["unchecked", "failed"])

    def test_what_is_and_isnt_checked(self):
        good = record(1, SIGNER_1, SIG_1)
        p384 = OPENSSL["signers"]["5 p384"]
        cases = {
            "the example": (DIGESTS + signatures(good), "checked", ""),
            "unsigned attributes added": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1, unsigned=uv(1) + lv(b"token") + uv(8) + lv(b""))), "checked", ""),
            "a signature byte changed": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1[:100] + b"\0" + SIG_1[101:])), "failed", ""),
            "the Ed25519 half changed": (DIGESTS + signatures(record(1, SIGNER_1, bytes(64) + SIG_1[64:])), "failed", ""),
            "a signature cut short": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1[:-1])), "failed", ""),
            "an even signed attribute unknown, so signed differently": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1, attrs=ATTRS + uv(2) + lv(b"x"))), "failed", ""),
            "a critical signed attribute unknown": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1, attrs=ATTRS + uv(3) + lv(b"x"))), "unchecked", "critical"),
            "signed attributes out of order": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1, attrs=uv(2) + lv(b"") + ATTRS)), "unchecked", "parse"),
            "a time with a byte after it": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1, attrs=uv(1) + lv(ATTRS[2:] + b"\0"))), "unchecked", "parse"),
            "bytes after the record": (DIGESTS + signatures(record(1, SIGNER_1, SIG_1, extra=b"\0")), "unchecked", "parse"),
            "an algorithm unknown": (DIGESTS + signatures(record(9, SIGNER_1, SIG_1)), "unchecked", "algorithm 9"),
            "a signing key of the wrong length": (DIGESTS + signatures(record(1, SIGNER_1[:-1], SIG_1)), "unchecked", "length"),
            "no cell digests": (signatures(good), "unchecked", "section 2"),
            "cell digests of the wrong length": (section(2, bytes(31)) + signatures(good), "unchecked", "section 2"),
            "a cell digest changed": (section(2, bytes(32)) + signatures(good), "failed", ""),
            "no signatures in section 3": (DIGESTS + section(3, uv(0)), "unchecked", "0 signatures"),
            "17 signatures": (DIGESTS + section(3, uv(17) + lv(good) * 17), "unchecked", "17 signatures"),
            "a count past the records": (DIGESTS + section(3, uv(2) + lv(good)), "unchecked", "parse"),
            "bytes after the records": (DIGESTS + section(3, uv(1) + lv(good) + b"\0"), "unchecked", "parse"),
            "a P-384 certificate for P-256": (DIGESTS + signatures(record(4, uv(1) + lv(h(p384["certificate"])), h(p384["signature"])[:64])), "unchecked", "P-256"),
            "an RSA algorithm for an EC certificate": (DIGESTS + signatures(record(2, uv(1) + lv(h(p384["certificate"])), bytes(256))), "unchecked", "RSA"),
            "no certificates": (DIGESTS + signatures(record(2, uv(0), bytes(256))), "unchecked", "certificates"),
            "nine certificates": (DIGESTS + signatures(record(2, uv(9) + lv(h(p384["certificate"])) * 9, bytes(256))), "unchecked", "certificates"),
            "a certificate that isn't one": (DIGESTS + signatures(record(2, uv(1) + lv(b"\x30\x03\x02\x01\x00"), bytes(256))), "unchecked", "certificates"),
        }  # fmt: skip
        for what, (sections, status, why) in cases.items():
            with self.subTest(what):
                (got,) = statuses(plain(sections))
                self.assertEqual(got[0], status, got[1])
                self.assertIn(why, got[1])
        with self.subTest("over 1 MiB"):
            (got,) = statuses(plain(DIGESTS + signatures(record(1, SIGNER_1, SIG_1, unsigned=uv(2) + lv(bytes(1 << 20))))))
            self.assertEqual(got[0], "unchecked")

    def test_cells_are_checked_against_their_digests(self):
        a = r.Archive(write(plain(section(2, bytes(32)))))
        with self.assertRaises(r.Bad) as e:
            a.cell(0)
        self.assertIn("digest", str(e.exception))
        # A digest section of the wrong length isn't used, and doesn't refuse the file.
        self.assertEqual(listing(read(plain(section(2, bytes(33))))), SMALL_LIST)
        # Version 1 readers skip sections 2 and 3: the M13 rules still refuse what they did.
        with self.assertRaises(r.Bad):
            read(plain(section(3, b"") + section(2, b"")))

    def test_a_changed_cell_fails_the_signatures(self):
        # The signature checks against the index; the cell, read, doesn't match the digest it signs.
        a = r.Archive(write(changed_cell(SIGNED)))
        sigs = a.signatures()
        self.assertEqual([s.status for s in sigs], ["checked"])
        a.unchanged(sigs)
        a.f.close()
        self.assertEqual([(s.status, s.why) for s in sigs], [("failed", "the archive changed after it was signed: cell 0 doesn't match its digest (§13.2)")])
        # Sealed, the changed cell doesn't open.
        pw = keys([V["slots"]["password"]["password_as_typed_nfd"]])
        a = r.Archive(write(changed_cell(sealed([h(V["slots"]["password"]["slot"])], sections=DIGESTS + SECTION_3), pw)), keys=pw)
        sigs = a.signatures()
        a.unchanged(sigs)
        a.f.close()
        self.assertEqual(sigs[0].status, "failed")
        self.assertIn("changed after it was signed: cell 0 doesn't open", sigs[0].why)
        # Unchanged, every cell is read and the signature still checks.
        a = r.Archive(write(SIGNED))
        sigs = a.signatures()
        a.unchanged(sigs)
        a.f.close()
        self.assertEqual([(s.status, s.why) for s in sigs], [("checked", "")])

    def test_what_isnt_printable_is_escaped(self):
        self.assertEqual(r.shown("a\nb\tc\x1b[0m‮\x85 é"), "a\\nb\\tc\\x1b[0m\\u202e\\x85 é")
        cert = OPENSSL["signers"]["2 rsa"]
        name = b"BeeZip test rsa"
        forged = b"x\nchecked\tRSA\t-"
        self.assertEqual(len(forged), len(name))
        der = h(cert["certificate"])
        self.assertIn(name, der)
        (sig,) = r.Archive(write(plain(DIGESTS + signatures(record(2, uv(1) + lv(der.replace(name, forged)), h(cert["signature"])))))).signatures()
        self.assertEqual(sig.status, "failed")
        self.assertIn("CN=x\\nchecked\\tRSA\\t-", sig.who)
        self.assertNotIn("\n", sig.line())
        self.assertEqual(sig.line().count("\t"), 5)


def changed_cell(data, k=None):
    """The archive with the first byte of its first cell's data changed."""
    a = r.Archive(write(data), keys=k)
    at = a.cells[0].offset
    a.f.close()
    return data[:at] + bytes([data[at] ^ 1]) + data[at + 1 :]


class CommandLine(unittest.TestCase):
    def run_reader(self, *args, stdin=None):
        p = subprocess.run([sys.executable, "-I", READER, *args], input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr

    def test_opening(self):
        sealed_path, small_path = write(SEALED), write(SMALL)
        code, small_out, _ = self.run_reader("list", small_path)
        self.assertEqual(code, 0)
        self.assertEqual(self.run_reader("list", sealed_path, "--password", "honey")[:2], (0, small_out))
        self.assertEqual(self.run_reader("list", sealed_path, "--password-file", write(b"honey\r\n", ".txt"))[:2], (0, small_out))
        self.assertEqual(self.run_reader("list", sealed_path, "--password-file", "-", stdin="honey\n")[:2], (0, small_out))
        self.assertEqual(self.run_reader("test", sealed_path, "--password", "honey")[0], 0)
        self.assertEqual(self.run_reader("list", sealed_path)[0], 3)
        self.assertEqual(self.run_reader("list", sealed_path, "--password", "bee")[0], 3)
        self.assertEqual(self.run_reader("list", sealed_path, "--recovery-key", "1-2-3")[0], 2)
        self.assertEqual(self.run_reader("list", sealed_path, "--recovery-key", "²" * 48)[0], 2)  # digits, but not 0 to 9
        self.assertEqual(self.run_reader("list", sealed_path, "--identity", write(b"nothing", ".txt"))[0], 2)
        self.assertEqual(self.run_reader("list", sealed_path, "--colour")[0], 2)
        self.assertEqual(self.run_reader("extract", sealed_path)[0], 2)
        code, out, _ = self.run_reader("slots", sealed_path)
        self.assertEqual((code, out), (0, "0\tpassword\tArgon2id, 256 KiB, 2 passes, 4 lanes\t-\n"))
        code, out, _ = self.run_reader("slots", sealed_path, "--password", "honey")
        self.assertEqual((code, out), (0, "0\tpassword\tArgon2id, 256 KiB, 2 passes, 4 lanes\tPassword\n"))
        self.assertEqual(self.run_reader("slots", small_path)[1], "not encrypted\n")
        # A password that isn't ASCII, as UTF-8 from standard input and from a file Notepad saved
        # with a byte order mark; and a label whose control characters are escaped.
        nfd = V["slots"]["password"]["password_as_typed_nfd"]
        nfc = unicodedata.normalize("NFC", nfd)
        label = section(5, uv(1) + lv(uv(1) + lv(b"a\nb\tc\x1b[31m")))
        own_path = write(sealed([h(V["slots"]["password"]["slot"])], sections=label))
        self.assertEqual(self.run_reader("list", own_path, "--password-file", "-", stdin=nfd + "\n")[:2], (0, small_out))
        self.assertEqual(self.run_reader("list", own_path, "--password-file", write(b"\xef\xbb\xbf" + nfc.encode() + b"\r\n", ".txt"))[:2], (0, small_out))
        self.assertEqual(self.run_reader("list", own_path, "--password-file", write(nfc.encode("cp1252"), ".txt"))[0], 2)
        code, out, _ = self.run_reader("slots", own_path, "--password", nfc)
        self.assertEqual((code, out), (0, "0\tpassword\tArgon2id, 256 KiB, 2 passes, 4 lanes\ta\\nb\\tc\\x1b[31m\n"))
        if os.name != "nt":  # the archive's link needs a privilege on Windows
            dest = os.path.join(TMP, "out")
            self.assertEqual(self.run_reader("extract", sealed_path, dest, "--password", "honey")[0], 0)
            self.assertEqual(whole(os.path.join(dest, "docs", "b.txt")), b"honeycomb\n")

    def test_verify(self):
        code, out, _ = self.run_reader("verify", write(SIGNED))
        self.assertEqual((code, out), (0, "checked\tML-DSA-65 and Ed25519\tVCPC-QSVP-2XKC-VCIZ\t1767225600\ta BeeZip signing key\t-\n"))
        self.assertEqual(self.run_reader("verify", write(SMALL))[:2], (1, "unsigned\n"))
        code, out, err = self.run_reader("test", write(plain(section(2, bytes(32)) + SECTION_3)))
        self.assertEqual(code, 1)
        self.assertIn("signature 1: failed", err)
        self.assertIn("doesn't match its digest", err)
        code, out, err = self.run_reader("list", write(plain(section(2, bytes(32)) + SECTION_3)))
        self.assertEqual(code, 0)  # a signature that fails warns: it doesn't block (docs/M14.md decision 26)
        self.assertIn("signature 1: failed", err)
        cert = OPENSSL["signers"]["2 rsa"]
        code, out, _ = self.run_reader("verify", write(plain(DIGESTS + signatures(record(2, uv(1) + lv(h(cert["certificate"])), h(cert["signature"]))))))
        self.assertEqual(code, 0)
        self.assertIn("CN=BeeZip test rsa", out)
        self.assertIn("its chain isn't checked", out)
        # A name in the certificate can't make a line of its own.
        forged = h(cert["certificate"]).replace(b"BeeZip test rsa", b"x\nchecked\tRSA\t-")
        code, out, err = self.run_reader("test", write(plain(DIGESTS + signatures(record(2, uv(1) + lv(forged), h(cert["signature"]))))))
        self.assertEqual(code, 1)
        self.assertEqual([ln for ln in err.splitlines() if "signature" in ln and "x\\nchecked\\tRSA\\t-" in ln and ": failed" in ln], err.splitlines())

    def test_a_changed_cell_under_a_signature(self):
        # The index and its signature as they were signed, and a byte of the cell changed.
        path = write(changed_cell(SIGNED))
        code, out, _ = self.run_reader("verify", path)
        self.assertEqual(code, 1)
        self.assertEqual(out, "failed\tML-DSA-65 and Ed25519\tVCPC-QSVP-2XKC-VCIZ\t1767225600\ta BeeZip signing key\tthe archive changed after it was signed: cell 0 doesn't match its digest (§13.2)\n")
        code, _, err = self.run_reader("test", path)
        self.assertEqual(code, 1)
        self.assertIn("bhive_reader: cell 0 doesn't match its digest", err)
        self.assertIn("signature 1: failed", err)
        self.assertIn("changed after it was signed", err)
        code, _, err = self.run_reader("list", path)
        self.assertEqual(code, 0)
        self.assertIn("signature 1: checked", err)
        self.assertIn("the cells aren't read", err)
        if os.name != "nt":  # the archive's link needs a privilege on Windows
            code, _, err = self.run_reader("extract", path, os.path.join(TMP, "changed"))
            self.assertEqual(code, 1)
            self.assertIn("signature 1: failed", err)


if __name__ == "__main__":
    unittest.main()
