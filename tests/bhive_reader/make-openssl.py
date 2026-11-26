"""Makes openssl.json: certificates, signatures and key files made by OpenSSL, for test_reader.py.

    python -I make-openssl.py

It needs `openssl` (3.0 or later) on PATH and runs it in a temporary folder. The certificates
are self-signed test certificates and their keys are test keys, made for these tests only. What
they sign is the message of docs/bhive.md §13.3 for spec-signed.bhive's manifest (vectors.json's
`signed_example`), with each algorithm's byte, so the reader checks signatures that another
implementation made. The key files are vectors.json's RSA and EC slot keys, written by OpenSSL in
the formats a reader of key files meets: PKCS #8 under a password (PBKDF2 and scrypt), PKCS #1,
SEC 1.
"""

import base64
import hashlib
import json
import os
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
V = json.load(open(os.path.join(ROOT, "tests", "fixtures", "bhive-m14", "vectors.json"), encoding="utf-8"))


def uvarint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def der_signature_to_raw(sig, size):
    """ECDSA's DER SEQUENCE { r, s } as r || s."""
    assert sig[0] == 0x30
    at, out = 2 if sig[1] < 0x80 else 3, b""
    for _ in range(2):
        assert sig[at] == 2
        n = sig[at + 1]
        out += int.from_bytes(sig[at + 2 : at + 2 + n], "big").to_bytes(size, "big")
        at += 2 + n
    return out


def main():
    manifest = bytes.fromhex(V["signed_example"]["manifest"])
    attrs = bytes.fromhex(V["signed_example"]["signed_attributes"])
    out = {"note": __doc__.split("\n\n")[2].replace("\n", " ").strip(), "signers": {}, "key_files": {}}
    with tempfile.TemporaryDirectory() as d:
        p = lambda name: os.path.join(d, name)  # noqa: E731
        keys = {
            "rsa": ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            "rsa1024": ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"],
            "p256": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            "p384": ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
        }
        for name, args in keys.items():
            openssl(*args, "-out", p(name + ".key"))
            subj = f"/CN=BeeZip test {name}/O=test keys, not for use"
            openssl("req", "-new", "-x509", "-key", p(name + ".key"), "-subj", subj, "-days", "3650",
                    "-outform", "DER", "-out", p(name + ".der"))  # fmt: skip
        for alg, name in ((2, "rsa"), (3, "rsa"), (4, "p256"), (5, "p384"), (2, "rsa1024")):
            cert = open(p(name + ".der"), "rb").read()
            signer = uvarint(1) + uvarint(len(cert)) + cert
            msg = b"bhive1 signature" + bytes([alg]) + manifest + hashlib.sha256(signer).digest() + hashlib.sha256(attrs).digest()
            open(p("msg"), "wb").write(msg)
            if alg == 2:
                sig = openssl("pkeyutl", "-sign", "-inkey", p(name + ".key"), "-rawin", "-digest", "sha256",
                              "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "rsa_pss_saltlen:32",
                              "-pkeyopt", "rsa_mgf1_md:sha256", "-in", p("msg"))  # fmt: skip
            elif alg == 3:
                sig = openssl("dgst", "-sha256", "-sign", p(name + ".key"), p("msg"))
            else:
                sig = openssl("dgst", "-sha256" if alg == 4 else "-sha384", "-sign", p(name + ".key"), p("msg"))
                sig = der_signature_to_raw(sig, 32 if alg == 4 else 48)
            out["signers"][f"{alg} {name}"] = {"algorithm": alg, "certificate": cert.hex(), "signature": sig.hex()}
        # vectors.json's slot keys in other key-file formats.
        for name in ("rsa", "p256", "p384"):
            der = bytes.fromhex(V["slots"][name]["pkcs8"])
            pem = "-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(der).decode() + "-----END PRIVATE KEY-----\n"
            open(p(name + ".pem"), "w").write(pem)
            files = out["key_files"][name] = {}
            files["pbkdf2"] = openssl("pkcs8", "-topk8", "-in", p(name + ".pem"), "-v2", "aes-256-cbc",
                                      "-v2prf", "hmacWithSHA256", "-passout", "pass:bee").decode()  # fmt: skip
            files["scrypt"] = openssl("pkcs8", "-topk8", "-in", p(name + ".pem"), "-scrypt", "-passout", "pass:bee").decode()
            if name == "rsa":
                files["pkcs1"] = openssl("rsa", "-in", p(name + ".pem"), "-traditional").decode()
            else:
                files["sec1"] = openssl("ec", "-in", p(name + ".pem")).decode()
    with open(os.path.join(HERE, "openssl.json"), "w", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
