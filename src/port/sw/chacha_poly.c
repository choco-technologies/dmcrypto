#include "sw.h"

/* ChaCha20 and Poly1305, and their AEAD construction (RFC 8439) */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void store_le64(uint8_t *p, uint64_t v)
{
    store_le32(p, (uint32_t)v);
    store_le32(p + 4, (uint32_t)(v >> 32));
}

#define QR(a, b, c, d)                      \
    a += b; d ^= a; d = ROL32(d, 16);       \
    c += d; b ^= c; b = ROL32(b, 12);       \
    a += b; d ^= a; d = ROL32(d, 8);        \
    c += d; b ^= c; b = ROL32(b, 7)

static void chacha_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], uint8_t out[64])
{
    uint32_t s[16], x[16];

    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;     /* "expand 32-byte k" */
    for (int i = 0; i < 8; i++)
        s[4 + i] = key[i];
    s[12] = counter;
    s[13] = nonce[0]; s[14] = nonce[1]; s[15] = nonce[2];
    for (int i = 0; i < 16; i++)
        x[i] = s[i];

    for (int round = 0; round < 10; round++)
    {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++)
        store_le32(out + 4 * i, x[i] + s[i]);
}

typedef struct
{
    uint32_t key[8];
    uint32_t nonce[3];
} chacha_t;

static void chacha_setup(chacha_t *c, const uint8_t *key, const uint8_t *nonce)
{
    for (int i = 0; i < 8; i++)
        c->key[i] = load_le32(key + 4 * i);
    for (int i = 0; i < 3; i++)
        c->nonce[i] = load_le32(nonce + 4 * i);
}

static void chacha_xor(const chacha_t *c, uint32_t counter, const uint8_t *in, uint8_t *out, size_t size)
{
    uint8_t block[64];

    for (size_t off = 0; off < size; off += 64, counter++)
    {
        size_t n = (size - off < 64) ? size - off : 64;
        chacha_block(c->key, counter, c->nonce, block);
        for (size_t i = 0; i < n; i++)
            out[off + i] = (uint8_t)(in[off + i] ^ block[i]);
    }
    sw_wipe(block, sizeof(block));
}

/* ---- Poly1305: 26-bit limbs ---- */

typedef struct
{
    uint32_t r[5], h[5], pad[4];
    uint8_t  buf[16];
    size_t   used;
} poly_t;

static void poly_init(poly_t *p, const uint8_t key[32])
{
    p->r[0] = (load_le32(key) ) & 0x3ffffff;
    p->r[1] = (load_le32(key + 3) >> 2) & 0x3ffff03;
    p->r[2] = (load_le32(key + 6) >> 4) & 0x3ffc0ff;
    p->r[3] = (load_le32(key + 9) >> 6) & 0x3f03fff;
    p->r[4] = (load_le32(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++)
        p->h[i] = 0;
    for (int i = 0; i < 4; i++)
        p->pad[i] = load_le32(key + 16 + 4 * i);
    p->used = 0;
}

static void poly_block(poly_t *p, const uint8_t m[16], uint32_t hibit)
{
    uint32_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];

    h0 += (load_le32(m)) & 0x3ffffff;
    h1 += (load_le32(m + 3) >> 2) & 0x3ffffff;
    h2 += (load_le32(m + 6) >> 4) & 0x3ffffff;
    h3 += (load_le32(m + 9) >> 6) & 0x3ffffff;
    h4 += (load_le32(m + 12) >> 8) | hibit;

    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    p->h[0] = h0; p->h[1] = h1; p->h[2] = h2; p->h[3] = h3; p->h[4] = h4;
}

static void poly_update(poly_t *p, const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        p->buf[p->used++] = data[i];
        if (p->used == 16)
        {
            poly_block(p, p->buf, 1u << 24);
            p->used = 0;
        }
    }
}

static void poly_final(poly_t *p, uint8_t tag[16])
{
    if (p->used != 0)
    {
        p->buf[p->used++] = 1;
        while (p->used < 16)
            p->buf[p->used++] = 0;
        poly_block(p, p->buf, 0);
    }

    uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4], c;

    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    /* h + -p, selecting h if h < p */
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;     /* all ones when h >= p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    /* h = h % 2^128, then + pad */
    uint64_t f;
    h0 = (h0 | (h1 << 26));
    h1 = ((h1 >> 6) | (h2 << 20));
    h2 = ((h2 >> 12) | (h3 << 14));
    h3 = ((h3 >> 18) | (h4 << 8));

    f = (uint64_t)h0 + p->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + p->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + p->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + p->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store_le32(tag, h0);
    store_le32(tag + 4, h1);
    store_le32(tag + 8, h2);
    store_le32(tag + 12, h3);
}

/* ---- AEAD ---- */

static void aead_tag(const chacha_t *c, const uint8_t *aad, size_t aad_size, const uint8_t *cipher, size_t size,
                     uint8_t tag[16])
{
    static const uint8_t zeros[16] = { 0 };
    uint8_t otk[64];
    uint8_t lengths[16];
    poly_t poly;

    chacha_block(c->key, 0, c->nonce, otk);             /* the one-time Poly1305 key */
    poly_init(&poly, otk);
    poly_update(&poly, aad, aad_size);
    poly_update(&poly, zeros, (16 - aad_size % 16) % 16);
    poly_update(&poly, cipher, size);
    poly_update(&poly, zeros, (16 - size % 16) % 16);
    store_le64(lengths, aad_size);
    store_le64(lengths + 8, size);
    poly_update(&poly, lengths, 16);
    poly_final(&poly, tag);

    sw_wipe(otk, sizeof(otk));
    sw_wipe(&poly, sizeof(poly));
}

int sw_chacha_poly_encrypt(const void *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                           const uint8_t *in, size_t size, uint8_t *out, uint8_t *tag)
{
    chacha_t c;

    chacha_setup(&c, key, nonce);
    chacha_xor(&c, 1, in, out, size);                   /* in and out may be the same */
    aead_tag(&c, aad, aad_size, out, size, tag);
    sw_wipe(&c, sizeof(c));
    return 0;
}

int sw_chacha_poly_decrypt(const void *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                           const uint8_t *in, size_t size, const uint8_t *tag, uint8_t *out)
{
    chacha_t c;
    uint8_t expected[16];
    int ok;

    chacha_setup(&c, key, nonce);
    aead_tag(&c, aad, aad_size, in, size, expected);    /* over the ciphertext, before decrypting */
    ok = sw_equal(expected, tag, 16);
    if (ok)
        chacha_xor(&c, 1, in, out, size);
    sw_wipe(&c, sizeof(c));
    return ok ? 0 : 1;
}
