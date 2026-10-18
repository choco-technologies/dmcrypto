#!/usr/bin/env python3
"""
Makes tests/vectors.h: expected results of the algorithms, computed by Python's
hashlib / hmac and the `cryptography` package (OpenSSL) over inputs that
tests/dmcrypto_test.c rebuilds with the same pattern function. Run again when
the set of cases changes:

    pip install cryptography
    python3 tests/fixtures/make_vectors.py
"""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "vectors.h")

HASHES = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
CRYPTO_HASH = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}

HASH_LENGTHS = [0, 1, 3, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 200, 1000]
HMAC_KEY_LENGTHS = [0, 1, 20, 64, 65, 131, 200]
CBC_LENGTHS = [16, 32, 48, 160]
CTR_LENGTHS = [1, 15, 16, 17, 33, 100]
KEY_SIZES = [16, 24, 32]
AEAD_CASES = [(0, 0), (0, 16), (20, 0), (20, 5), (13, 16), (16, 33), (0, 100)]   # (aad, plaintext)


def pat(n, seed):
    """the same function as pattern() in tests/dmcrypto_test.c"""
    return bytes(((i * 131 + seed * 17 + (i >> 2)) & 0xFF) for i in range(n))


def arr(name, data, comment):
    body = ", ".join(f"0x{b:02x}" for b in data)
    lines, cur = [], ""
    for tok in body.split(", "):
        if len(cur) + len(tok) > 92:
            lines.append("    " + cur.rstrip(", ") + ",")
            cur = ""
        cur += tok + ", "
    lines.append("    " + cur.rstrip(", "))
    return f"/* {comment} */\nstatic const uint8_t {name}[{len(data)}] =\n{{\n" + "\n".join(lines) + "\n};\n\n"


def main():
    s = ("/* Made by tests/fixtures/make_vectors.py (hashlib, OpenSSL via `cryptography`) - do not edit,\n"
         " * run it again. Inputs: pattern(n, seed) of dmcrypto_test.c. */\n"
         "#ifndef DMCRYPTO_VECTORS_H\n#define DMCRYPTO_VECTORS_H\n\n#include <stdint.h>\n\n")

    for name, fn in HASHES.items():
        data = b"".join(fn(pat(n, 1)).digest() for n in HASH_LENGTHS)
        s += arr(f"vec_hash_{name}", data, f"{name} of pattern(n, 1), n in HASH_LENGTHS, one digest after another")
        macs = b"".join(hmac.new(pat(k, 2), pat(50, 3), fn).digest() for k in HMAC_KEY_LENGTHS)
        s += arr(f"vec_hmac_{name}", macs, f"HMAC-{name}(key = pattern(k, 2), msg = pattern(50, 3)), k in HMAC_KEY_LENGTHS")

    # PBKDF2: RFC 6070 (SHA-1) and others
    s += arr("vec_pbkdf2_sha1_1", hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 1, 20), "PBKDF2-HMAC-SHA1(password, salt, 1, 20) - RFC 6070")
    s += arr("vec_pbkdf2_sha1_4096", hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 4096, 20), "PBKDF2-HMAC-SHA1(password, salt, 4096, 20) - RFC 6070")
    s += arr("vec_pbkdf2_sha1_wpa", hashlib.pbkdf2_hmac("sha1", b"ThisIsAPassword", b"ThisIsASSID", 4096, 32), "WPA2 PSK: PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)")
    s += arr("vec_pbkdf2_sha256", hashlib.pbkdf2_hmac("sha256", pat(70, 4), pat(20, 5), 100, 70), "PBKDF2-HMAC-SHA256(pattern(70,4), pattern(20,5), 100, 70)")
    s += arr("vec_pbkdf2_sha512", hashlib.pbkdf2_hmac("sha512", b"pw", pat(150, 6), 10, 100), "PBKDF2-HMAC-SHA512(pw, pattern(150,6), 10, 100)")

    # HKDF
    def hkdf(alg, ikm, salt, info, n):
        return HKDF(algorithm=CRYPTO_HASH[alg](), length=n, salt=salt, info=info).derive(ikm)
    s += arr("vec_hkdf_sha256_rfc", hkdf("sha256", bytes([0x0b] * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)), 42), "HKDF-SHA256 - RFC 5869 test case 1")
    s += arr("vec_hkdf_sha256_nosalt", hkdf("sha256", pat(40, 7), None, b"", 100), "HKDF-SHA256(pattern(40,7), no salt, no info, 100)")
    s += arr("vec_hkdf_sha512", hkdf("sha512", pat(33, 8), pat(10, 9), pat(30, 10), 200), "HKDF-SHA512(pattern(33,8), pattern(10,9), pattern(30,10), 200)")

    # AES-CBC (no padding) and AES-CTR
    cbc = b""
    for k in KEY_SIZES:
        for n in CBC_LENGTHS:
            enc = Cipher(algorithms.AES(pat(k, 11)), modes.CBC(pat(16, 12))).encryptor()
            cbc += enc.update(pat(n, 13)) + enc.finalize()
    s += arr("vec_aes_cbc", cbc, "AES-CBC encrypt(key = pattern(k,11), iv = pattern(16,12), pattern(n,13)), k in KEY_SIZES, n in CBC_LENGTHS")
    ctr = b""
    for k in KEY_SIZES:
        for n in CTR_LENGTHS:
            enc = Cipher(algorithms.AES(pat(k, 14)), modes.CTR(pat(16, 15))).encryptor()
            ctr += enc.update(pat(n, 16)) + enc.finalize()
    s += arr("vec_aes_ctr", ctr, "AES-CTR(key = pattern(k,14), counter = pattern(16,15), pattern(n,16)), k in KEY_SIZES, n in CTR_LENGTHS")
    # a counter that carries across bytes: ... ff ff -> ... 01 00 00
    carry = bytes([0] * 13 + [0xFF, 0xFF, 0xFE])
    enc = Cipher(algorithms.AES(pat(16, 17)), modes.CTR(carry)).encryptor()
    s += arr("vec_aes_ctr_carry", enc.update(pat(80, 18)) + enc.finalize(), "AES-128-CTR from counter 00..00 ff ff fe, pattern(80,18): the counter carries")

    # AEAD: ciphertext followed by the tag, per case
    gcm = b""
    for k in KEY_SIZES:
        for aad, n in AEAD_CASES:
            gcm += AESGCM(pat(k, 19)).encrypt(pat(12, 20), pat(n, 21), pat(aad, 22))
    s += arr("vec_aes_gcm", gcm, "AES-GCM encrypt(key = pattern(k,19), nonce = pattern(12,20), pt = pattern(n,21), aad = pattern(a,22)) = ciphertext | 16-byte tag, k in KEY_SIZES, (a, n) in AEAD_CASES")
    cc = b""
    for aad, n in AEAD_CASES:
        cc += ChaCha20Poly1305(pat(32, 23)).encrypt(pat(12, 24), pat(n, 25), pat(aad, 26))
    s += arr("vec_chacha_poly", cc, "ChaCha20-Poly1305 encrypt(key = pattern(32,23), nonce = pattern(12,24), pt = pattern(n,25), aad = pattern(a,26)) = ciphertext | tag, (a, n) in AEAD_CASES")
    # RFC 8439 section 2.8.2
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    s += arr("vec_chacha_poly_rfc", ChaCha20Poly1305(key).encrypt(nonce, pt, aad), "ChaCha20-Poly1305 - RFC 8439 section 2.8.2 (ciphertext | tag)")

    s += "#endif /* DMCRYPTO_VECTORS_H */\n"
    open(OUT, "w").write(s)
    print(f"{OUT}: {len(s)} bytes")


if __name__ == "__main__":
    main()
