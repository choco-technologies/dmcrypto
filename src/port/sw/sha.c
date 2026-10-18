#include "sw.h"
#include "sha_tables.h"

/* SHA-1, SHA-256, SHA-384, SHA-512 (FIPS 180-4) */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint32_t load32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t load64(const uint8_t *p)
{
    return ((uint64_t)load32(p) << 32) | load32(p + 4);
}

static void store32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store64(uint8_t *p, uint64_t v)
{
    store32(p, (uint32_t)(v >> 32));
    store32(p + 4, (uint32_t)v);
}

/* ---- SHA-1 ---- */

static void sha1_block(sw_sha1_t *s, const uint8_t *block)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = load32(block + 4 * i);
    for (int i = 16; i < 80; i++)
        w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4];
    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
        uint32_t t = ROL32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
}

/* ---- SHA-256 ---- */

static void sha256_block(sw_sha256_t *s, const uint8_t *block)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = load32(block + 4 * i);
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++)
    {
        uint32_t t1 = h + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + sha256_k[i] + w[i];
        uint32_t t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

/* ---- SHA-512 / SHA-384 ---- */

static void sha512_block(sw_sha512_t *s, const uint8_t *block)
{
    uint64_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = load64(block + 8 * i);
    for (int i = 16; i < 80; i++)
    {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint64_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 80; i++)
    {
        uint64_t t1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + sha512_k[i] + w[i];
        uint64_t t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

/* ---- Generic part ---- */

size_t sw_hash_size(dmcrypto_hash_alg_t alg)
{
    switch (alg)
    {
        case DMCRYPTO_HASH_SHA1:   return 20;
        case DMCRYPTO_HASH_SHA256: return 32;
        case DMCRYPTO_HASH_SHA384: return 48;
        case DMCRYPTO_HASH_SHA512: return 64;
        default:                   return 0;
    }
}

size_t sw_hash_block_size(dmcrypto_hash_alg_t alg)
{
    return (alg == DMCRYPTO_HASH_SHA384 || alg == DMCRYPTO_HASH_SHA512) ? 128 : 64;
}

int sw_hash_init(sw_hash_t *ctx, dmcrypto_hash_alg_t alg)
{
    ctx->alg = alg;
    switch (alg)
    {
        case DMCRYPTO_HASH_SHA1:
            ctx->u.sha1.h[0] = 0x67452301; ctx->u.sha1.h[1] = 0xEFCDAB89; ctx->u.sha1.h[2] = 0x98BADCFE;
            ctx->u.sha1.h[3] = 0x10325476; ctx->u.sha1.h[4] = 0xC3D2E1F0;
            ctx->u.sha1.bytes = 0;
            return 0;
        case DMCRYPTO_HASH_SHA256:
            for (int i = 0; i < 8; i++)
                ctx->u.sha256.h[i] = sha256_init[i];
            ctx->u.sha256.bytes = 0;
            return 0;
        case DMCRYPTO_HASH_SHA384:
            for (int i = 0; i < 8; i++)
                ctx->u.sha512.h[i] = sha384_init[i];
            ctx->u.sha512.bytes = 0;
            return 0;
        case DMCRYPTO_HASH_SHA512:
            for (int i = 0; i < 8; i++)
                ctx->u.sha512.h[i] = sha512_init[i];
            ctx->u.sha512.bytes = 0;
            return 0;
        default:
            return -1;
    }
}

static void compress(sw_hash_t *ctx, const uint8_t *block)
{
    switch (ctx->alg)
    {
        case DMCRYPTO_HASH_SHA1:   sha1_block(&ctx->u.sha1, block);     break;
        case DMCRYPTO_HASH_SHA256: sha256_block(&ctx->u.sha256, block); break;
        default:                   sha512_block(&ctx->u.sha512, block); break;
    }
}

static uint8_t *buffer_of(sw_hash_t *ctx, uint64_t **bytes)
{
    switch (ctx->alg)
    {
        case DMCRYPTO_HASH_SHA1:   *bytes = &ctx->u.sha1.bytes;   return ctx->u.sha1.buf;
        case DMCRYPTO_HASH_SHA256: *bytes = &ctx->u.sha256.bytes; return ctx->u.sha256.buf;
        default:                   *bytes = &ctx->u.sha512.bytes; return ctx->u.sha512.buf;
    }
}

void sw_hash_update(sw_hash_t *ctx, const void *data, size_t size)
{
    const uint8_t *in = data;
    uint64_t *bytes;
    uint8_t *buf = buffer_of(ctx, &bytes);
    size_t block = sw_hash_block_size(ctx->alg);
    size_t used = (size_t)(*bytes % block);

    *bytes += size;
    if (used != 0)
    {
        size_t take = block - used;
        if (take > size)
            take = size;
        for (size_t i = 0; i < take; i++)
            buf[used + i] = in[i];
        in += take;
        size -= take;
        if (used + take < block)
            return;
        compress(ctx, buf);
    }
    for (; size >= block; in += block, size -= block)
        compress(ctx, in);
    for (size_t i = 0; i < size; i++)
        buf[i] = in[i];
}

void sw_hash_final(sw_hash_t *ctx, uint8_t *digest)
{
    uint64_t *bytes;
    uint8_t *buf = buffer_of(ctx, &bytes);
    size_t block = sw_hash_block_size(ctx->alg);
    size_t length_size = (block == 128) ? 16 : 8;
    uint64_t bits = *bytes << 3;
    uint64_t bits_high = *bytes >> 61;
    size_t used = (size_t)(*bytes % block);

    buf[used++] = 0x80;
    if (used > block - length_size)
    {
        for (; used < block; used++)
            buf[used] = 0;
        compress(ctx, buf);
        used = 0;
    }
    for (; used < block - length_size; used++)
        buf[used] = 0;
    if (block == 128)
    {
        store64(buf + 112, bits_high);
        store64(buf + 120, bits);
    }
    else
    {
        store64(buf + 56, bits);
    }
    compress(ctx, buf);

    size_t words = sw_hash_size(ctx->alg);
    if (ctx->alg == DMCRYPTO_HASH_SHA1)
    {
        for (size_t i = 0; i < 5; i++)
            store32(digest + 4 * i, ctx->u.sha1.h[i]);
    }
    else if (ctx->alg == DMCRYPTO_HASH_SHA256)
    {
        for (size_t i = 0; i < 8; i++)
            store32(digest + 4 * i, ctx->u.sha256.h[i]);
    }
    else
    {
        uint8_t full[64];
        for (size_t i = 0; i < 8; i++)
            store64(full + 8 * i, ctx->u.sha512.h[i]);
        for (size_t i = 0; i < words; i++)
            digest[i] = full[i];
        sw_wipe(full, sizeof(full));
    }
    sw_wipe(ctx, sizeof(*ctx));
}
