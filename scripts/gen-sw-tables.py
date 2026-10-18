#!/usr/bin/env python3
"""
Makes src/port/sw/sha_tables.h and aes_tables.h: the constants of SHA-2 (the
fractional parts of the square / cube roots of the first primes) and AES (the
S-boxes, from the GF(2^8) inverse and the affine map), computed - not typed
in - so they cannot carry a typo. Run again only if the tables must change:

    python3 scripts/gen-sw-tables.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "src/port/sw")


def primes(n):
    out, c = [], 2
    while len(out) < n:
        if all(c % p for p in out):
            out.append(c)
        c += 1
    return out


def iroot(x, k):
    """floor of the k-th root of x"""
    lo, hi = 0, 1 << ((x.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def frac_root(p, k, bits):
    """the first `bits` bits of the fractional part of the k-th root of p"""
    return iroot(p << (k * bits), k) & ((1 << bits) - 1)


def array(name, ctype, values, width, per_line):
    lines = []
    for i in range(0, len(values), per_line):
        lines.append("    " + ", ".join(f"0x{v:0{width}x}" for v in values[i:i + per_line]) + ",")
    return f"static const {ctype} {name}[{len(values)}] =\n{{\n" + "\n".join(lines) + "\n};\n\n"


def sha_tables():
    p = primes(80)
    s = "/* Made by scripts/gen-sw-tables.py - do not edit. */\n#ifndef DMCRYPTO_SHA_TABLES_H\n#define DMCRYPTO_SHA_TABLES_H\n\n#include <stdint.h>\n\n"
    s += "/* SHA-256: the cube roots of the first 64 primes, the square roots of the first 8 */\n"
    s += array("sha256_k", "uint32_t", [frac_root(x, 3, 32) for x in p[:64]], 8, 6)
    s += array("sha256_init", "uint32_t", [frac_root(x, 2, 32) for x in p[:8]], 8, 4)
    s += "/* SHA-512: the cube roots of the first 80 primes, the square roots of the first 8 */\n"
    s += array("sha512_k", "uint64_t", [frac_root(x, 3, 64) for x in p[:80]], 16, 3)
    s += array("sha512_init", "uint64_t", [frac_root(x, 2, 64) for x in p[:8]], 16, 2)
    s += "/* SHA-384: the square roots of the 9th to 16th primes */\n"
    s += array("sha384_init", "uint64_t", [frac_root(x, 2, 64) for x in p[8:16]], 16, 2)
    s += "#endif /* DMCRYPTO_SHA_TABLES_H */\n"
    open(os.path.join(OUT, "sha_tables.h"), "w").write(s)


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


def aes_tables():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if gmul(a, b) == 1:
                inv[a] = b
    sbox = []
    for a in range(256):
        x = inv[a]
        y = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            y ^= x
        sbox.append(y ^ 0x63)
    isbox = [0] * 256
    for i, v in enumerate(sbox):
        isbox[v] = i
    s = "/* Made by scripts/gen-sw-tables.py - do not edit. */\n#ifndef DMCRYPTO_AES_TABLES_H\n#define DMCRYPTO_AES_TABLES_H\n\n#include <stdint.h>\n\n"
    s += array("aes_sbox", "uint8_t", sbox, 2, 16)
    s += array("aes_isbox", "uint8_t", isbox, 2, 16)
    s += "#endif /* DMCRYPTO_AES_TABLES_H */\n"
    open(os.path.join(OUT, "aes_tables.h"), "w").write(s)


if __name__ == "__main__":
    sha_tables()
    aes_tables()
    print("wrote sha_tables.h, aes_tables.h in", OUT)
