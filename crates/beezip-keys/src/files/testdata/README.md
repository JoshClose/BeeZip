# Test keys and certificates

These are **test keys**, published on purpose: never trust them for anything. `rsa.key`,
`p256.key` and `p384.key` are the keys of `tests/fixtures/bhive-m14/vectors.json` (`slots`), so
the vectors' slots open with them; the rest were made from them with OpenSSL 3.5. Each is valid
from 2020 to 2126, so a machine whose clock is behind still finds it valid, except
`rsa-expired.crt`:

| File | What |
|---|---|
| `rsa.crt`, `rsa.der` | self-signed, RSA-2048, key usage digitalSignature and keyEncipherment |
| `rsa-pkcs1.key` | `rsa.key` as PKCS #1 (`RSA PRIVATE KEY`) |
| `rsa-sign-only.crt` | the same key, key usage digitalSignature only: can't be encrypted to |
| `rsa-expired.crt` | the same key, valid only in 2020 |
| `rsa1024.crt` | another key, RSA-1024: too small (its key isn't kept) |
| `p256.crt`, `p384.crt` | self-signed, key usage digitalSignature and keyAgreement |
| `p256-sec1.key` | `p256.key` as SEC 1 (`EC PRIVATE KEY`) |
| `p256-ecdsa.crt` | `p256.key`, key usage digitalSignature only: an ECDSA certificate |
| `p256.pub` | `p256.key`'s public key alone (`PUBLIC KEY`) |
| `p384-encrypted.key` | `p384.key` as encrypted PKCS #8 (PBES2, PBKDF2-SHA256, AES-256-CBC), password `honey` |
| `chain.pem` | `p256.key`'s certificate issued by a test CA, then the CA's certificate (its key isn't kept) |
