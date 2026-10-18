#include "sw.h"

/* AES-GCM (NIST SP 800-38D), 96-bit nonces. GHASH is the bitwise
 * multiplication in GF(2^128): small, and slow next to a table version. */

static void gf_mul(uint8_t x[16], const uint8_t h[16])
{
    uint8_t z[16] = { 0 };
    uint8_t v[16];

    for (int i = 0; i < 16; i++)
        v[i] = h[i];
    for (int i = 0; i < 128; i++)
    {
        if ((x[i / 8] >> (7 - (i % 8))) & 1)
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        uint8_t carry = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        v[0] >>= 1;
        if (carry)
            v[0] ^= 0xE1;
    }
    for (int i = 0; i < 16; i++)
        x[i] = z[i];
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t size)
{
    for (size_t off = 0; off < size; off += 16)
    {
        size_t n = (size - off < 16) ? size - off : 16;
        for (size_t i = 0; i < n; i++)
            y[i] ^= data[off + i];                  /* a short last block is zero padded */
        gf_mul(y, h);
    }
}

static void store_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--)
    {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static void inc32(uint8_t counter[16])
{
    for (int i = 15; i >= 12; i--)
        if (++counter[i] != 0)
            break;
}

/* The counter-mode keystream over in, starting at counter (already incremented past J0) */
static void gctr(const sw_aes_t *aes, uint8_t counter[16], const uint8_t *in, uint8_t *out, size_t size)
{
    uint8_t block[16];

    for (size_t off = 0; off < size; off += 16)
    {
        size_t n = (size - off < 16) ? size - off : 16;
        sw_aes_encrypt_block(aes, counter, block);
        for (size_t i = 0; i < n; i++)
            out[off + i] = (uint8_t)(in[off + i] ^ block[i]);
        inc32(counter);
    }
    sw_wipe(block, sizeof(block));
}

/* tag = E(K, J0) ^ GHASH(aad, ciphertext, lengths) */
static void compute_tag(const sw_aes_t *aes, const uint8_t h[16], const uint8_t j0[16], const uint8_t *aad,
                        size_t aad_size, const uint8_t *cipher, size_t size, uint8_t tag[16])
{
    uint8_t y[16] = { 0 };
    uint8_t lengths[16];
    uint8_t mask[16];

    ghash_update(y, h, aad, aad_size);
    ghash_update(y, h, cipher, size);
    store_be64(lengths, (uint64_t)aad_size * 8);
    store_be64(lengths + 8, (uint64_t)size * 8);
    ghash_update(y, h, lengths, 16);
    sw_aes_encrypt_block(aes, j0, mask);
    for (int i = 0; i < 16; i++)
        tag[i] = (uint8_t)(y[i] ^ mask[i]);
    sw_wipe(mask, sizeof(mask));
}

static int setup(sw_aes_t *aes, uint8_t h[16], uint8_t j0[16], const void *key, size_t key_size, const uint8_t *nonce)
{
    static const uint8_t zero[16] = { 0 };

    if (sw_aes_init(aes, key, key_size) != 0)
        return -1;
    sw_aes_encrypt_block(aes, zero, h);
    for (int i = 0; i < 12; i++)
        j0[i] = nonce[i];
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;
    return 0;
}

int sw_aes_gcm_encrypt(const void *key, size_t key_size, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                       const uint8_t *in, size_t size, uint8_t *out, uint8_t *tag, size_t tag_size)
{
    sw_aes_t aes;
    uint8_t h[16], j0[16], counter[16], full[16];

    if (setup(&aes, h, j0, key, key_size, nonce) != 0)
        return -1;
    for (int i = 0; i < 16; i++)
        counter[i] = j0[i];
    inc32(counter);
    gctr(&aes, counter, in, out, size);                 /* in and out may be the same */
    compute_tag(&aes, h, j0, aad, aad_size, out, size, full);
    for (size_t i = 0; i < tag_size; i++)
        tag[i] = full[i];

    sw_wipe(&aes, sizeof(aes));
    sw_wipe(h, sizeof(h));
    return 0;
}

int sw_aes_gcm_decrypt(const void *key, size_t key_size, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                       const uint8_t *in, size_t size, const uint8_t *tag, size_t tag_size, uint8_t *out)
{
    sw_aes_t aes;
    uint8_t h[16], j0[16], counter[16], full[16];
    int ok;

    if (setup(&aes, h, j0, key, key_size, nonce) != 0)
        return -1;
    compute_tag(&aes, h, j0, aad, aad_size, in, size, full);    /* over the ciphertext, before anything is decrypted */
    ok = sw_equal(full, tag, tag_size);
    if (ok)
    {
        for (int i = 0; i < 16; i++)
            counter[i] = j0[i];
        inc32(counter);
        gctr(&aes, counter, in, out, size);
    }

    sw_wipe(&aes, sizeof(aes));
    sw_wipe(h, sizeof(h));
    return ok ? 0 : 1;
}
