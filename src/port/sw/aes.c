#include "sw.h"
#include "aes_tables.h"

/* AES (FIPS 197): 128, 192, 256-bit keys; CBC and CTR. Table-free in the
 * rounds (the S-box and byte arithmetic), so small - not the fastest. */

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;

    while (b)
    {
        if (b & 1)
            r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

int sw_aes_init(sw_aes_t *ctx, const void *key, size_t key_size)
{
    const uint8_t *k = key;
    size_t nk;

    switch (key_size)
    {
        case 16: nk = 4; ctx->rounds = 10; break;
        case 24: nk = 6; ctx->rounds = 12; break;
        case 32: nk = 8; ctx->rounds = 14; break;
        default: return -1;
    }

    uint8_t *w = ctx->round_key;
    size_t words = 4 * (size_t)(ctx->rounds + 1);
    for (size_t i = 0; i < 4 * nk; i++)
        w[i] = k[i];

    uint8_t rcon = 1;
    for (size_t i = nk; i < words; i++)
    {
        uint8_t t[4] = { w[4 * (i - 1)], w[4 * (i - 1) + 1], w[4 * (i - 1) + 2], w[4 * (i - 1) + 3] };
        if (i % nk == 0)
        {
            uint8_t first = t[0];
            t[0] = (uint8_t)(aes_sbox[t[1]] ^ rcon);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[first];
            rcon = xtime(rcon);
        }
        else if (nk > 6 && i % nk == 4)
        {
            for (int j = 0; j < 4; j++)
                t[j] = aes_sbox[t[j]];
        }
        for (int j = 0; j < 4; j++)
            w[4 * i + j] = (uint8_t)(w[4 * (i - nk) + j] ^ t[j]);
    }
    return 0;
}

static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
    for (int i = 0; i < 16; i++)
        s[i] ^= rk[i];
}

/* The state is column-major as the input bytes: s[4 * column + row] */

static void shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[1];  s[1] = s[5];  s[5] = s[9];   s[9] = s[13];  s[13] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;     t = s[6];      s[6] = s[14];  s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3];   s[3] = t;
}

static void inv_shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5];   s[5] = s[1];   s[1] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;     t = s[6];      s[6] = s[14];  s[14] = t;
    t = s[3];  s[3] = s[7];  s[7] = s[11];  s[11] = s[15]; s[15] = t;
}

static void mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++)
    {
        uint8_t *p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        p[1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        p[2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        p[3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void inv_mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++)
    {
        uint8_t *p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = (uint8_t)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
        p[1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
        p[2] = (uint8_t)(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
        p[3] = (uint8_t)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
    }
}

void sw_aes_encrypt_block(const sw_aes_t *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];

    for (int i = 0; i < 16; i++)
        s[i] = in[i];
    add_round_key(s, ctx->round_key);
    for (int r = 1; r < ctx->rounds; r++)
    {
        for (int i = 0; i < 16; i++)
            s[i] = aes_sbox[s[i]];
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, ctx->round_key + 16 * r);
    }
    for (int i = 0; i < 16; i++)
        s[i] = aes_sbox[s[i]];
    shift_rows(s);
    add_round_key(s, ctx->round_key + 16 * ctx->rounds);
    for (int i = 0; i < 16; i++)
        out[i] = s[i];
}

void sw_aes_decrypt_block(const sw_aes_t *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];

    for (int i = 0; i < 16; i++)
        s[i] = in[i];
    add_round_key(s, ctx->round_key + 16 * ctx->rounds);
    for (int r = ctx->rounds - 1; r >= 1; r--)
    {
        inv_shift_rows(s);
        for (int i = 0; i < 16; i++)
            s[i] = aes_isbox[s[i]];
        add_round_key(s, ctx->round_key + 16 * r);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    for (int i = 0; i < 16; i++)
        s[i] = aes_isbox[s[i]];
    add_round_key(s, ctx->round_key);
    for (int i = 0; i < 16; i++)
        out[i] = s[i];
}

int sw_cipher_crypt(dmcrypto_cipher_alg_t alg, int encrypt, const void *key, size_t key_size,
                    uint8_t *iv, const uint8_t *in, uint8_t *out, size_t size)
{
    sw_aes_t aes;
    uint8_t block[16];

    if (sw_aes_init(&aes, key, key_size) != 0)
        return -1;

    if (alg == DMCRYPTO_CIPHER_AES_CBC)
    {
        for (size_t off = 0; off + 16 <= size; off += 16)
        {
            if (encrypt)
            {
                for (int i = 0; i < 16; i++)
                    block[i] = (uint8_t)(in[off + i] ^ iv[i]);
                sw_aes_encrypt_block(&aes, block, iv);
                for (int i = 0; i < 16; i++)
                    out[off + i] = iv[i];
            }
            else
            {
                uint8_t cipher[16];
                for (int i = 0; i < 16; i++)
                    cipher[i] = in[off + i];            /* in and out may be the same */
                sw_aes_decrypt_block(&aes, cipher, block);
                for (int i = 0; i < 16; i++)
                {
                    out[off + i] = (uint8_t)(block[i] ^ iv[i]);
                    iv[i] = cipher[i];
                }
            }
        }
    }
    else
    {
        for (size_t off = 0; off < size; off += 16)
        {
            size_t n = (size - off < 16) ? size - off : 16;
            sw_aes_encrypt_block(&aes, iv, block);
            for (size_t i = 0; i < n; i++)
                out[off + i] = (uint8_t)(in[off + i] ^ block[i]);
            for (int i = 15; i >= 0; i--)               /* the counter block, big-endian */
                if (++iv[i] != 0)
                    break;
        }
    }

    sw_wipe(&aes, sizeof(aes));
    sw_wipe(block, sizeof(block));
    return 0;
}
