#include "sw.h"

/* HMAC (RFC 2104), PBKDF2 (RFC 8018), HKDF (RFC 5869) */

int sw_hmac_init(sw_hmac_t *ctx, dmcrypto_hash_alg_t alg, const void *key, size_t key_size)
{
    uint8_t block[128];
    uint8_t digest[DMCRYPTO_HASH_MAX_SIZE];
    size_t block_size = sw_hash_block_size(alg);
    const uint8_t *k = key;

    if (sw_hash_init(&ctx->inner, alg) != 0)
        return -1;
    if (key_size > block_size)
    {
        sw_hash_t keyed;
        sw_hash_init(&keyed, alg);
        sw_hash_update(&keyed, key, key_size);
        sw_hash_final(&keyed, digest);
        k = digest;
        key_size = sw_hash_size(alg);
    }

    for (size_t i = 0; i < block_size; i++)
        block[i] = (uint8_t)((i < key_size ? k[i] : 0) ^ 0x36);
    sw_hash_update(&ctx->inner, block, block_size);

    sw_hash_init(&ctx->outer, alg);
    for (size_t i = 0; i < block_size; i++)
        block[i] = (uint8_t)((i < key_size ? k[i] : 0) ^ 0x5C);
    sw_hash_update(&ctx->outer, block, block_size);

    sw_wipe(block, sizeof(block));
    sw_wipe(digest, sizeof(digest));
    return 0;
}

void sw_hmac_update(sw_hmac_t *ctx, const void *data, size_t size)
{
    sw_hash_update(&ctx->inner, data, size);
}

void sw_hmac_final(sw_hmac_t *ctx, uint8_t *mac)
{
    uint8_t inner[DMCRYPTO_HASH_MAX_SIZE];

    sw_hash_final(&ctx->inner, inner);
    sw_hash_update(&ctx->outer, inner, sw_hash_size(ctx->outer.alg));
    sw_hash_final(&ctx->outer, mac);
    sw_wipe(inner, sizeof(inner));
}

int sw_pbkdf2(dmcrypto_hash_alg_t alg, const void *password, size_t password_size,
              const void *salt, size_t salt_size, uint32_t iterations, uint8_t *out, size_t out_size)
{
    sw_hmac_t base;
    size_t hlen = sw_hash_size(alg);
    uint8_t u[DMCRYPTO_HASH_MAX_SIZE], t[DMCRYPTO_HASH_MAX_SIZE];

    if (sw_hmac_init(&base, alg, password, password_size) != 0)
        return -1;

    for (uint32_t block = 1; out_size > 0; block++)
    {
        uint8_t index[4] = { (uint8_t)(block >> 24), (uint8_t)(block >> 16), (uint8_t)(block >> 8), (uint8_t)block };
        sw_hmac_t h = base;

        sw_hmac_update(&h, salt, salt_size);
        sw_hmac_update(&h, index, sizeof(index));
        sw_hmac_final(&h, u);
        for (size_t i = 0; i < hlen; i++)
            t[i] = u[i];

        for (uint32_t it = 1; it < iterations; it++)
        {
            h = base;
            sw_hmac_update(&h, u, hlen);
            sw_hmac_final(&h, u);
            for (size_t i = 0; i < hlen; i++)
                t[i] ^= u[i];
        }

        size_t take = (out_size < hlen) ? out_size : hlen;
        for (size_t i = 0; i < take; i++)
            out[i] = t[i];
        out += take;
        out_size -= take;
    }

    sw_wipe(&base, sizeof(base));
    sw_wipe(u, sizeof(u));
    sw_wipe(t, sizeof(t));
    return 0;
}

int sw_hkdf(dmcrypto_hash_alg_t alg, const void *ikm, size_t ikm_size, const void *salt, size_t salt_size,
            const void *info, size_t info_size, uint8_t *out, size_t out_size)
{
    sw_hmac_t h;
    size_t hlen = sw_hash_size(alg);
    uint8_t prk[DMCRYPTO_HASH_MAX_SIZE], t[DMCRYPTO_HASH_MAX_SIZE], zeros[DMCRYPTO_HASH_MAX_SIZE] = { 0 };

    /* Extract: PRK = HMAC(salt, IKM), the salt defaults to hlen zeros */
    if (salt == NULL || salt_size == 0)
    {
        salt = zeros;
        salt_size = hlen;
    }
    if (sw_hmac_init(&h, alg, salt, salt_size) != 0)
        return -1;
    sw_hmac_update(&h, ikm, ikm_size);
    sw_hmac_final(&h, prk);

    /* Expand: T(i) = HMAC(PRK, T(i-1) | info | i) */
    size_t previous = 0;
    for (uint8_t counter = 1; out_size > 0; counter++)
    {
        sw_hmac_init(&h, alg, prk, hlen);
        sw_hmac_update(&h, t, previous);
        if (info_size != 0)
            sw_hmac_update(&h, info, info_size);
        sw_hmac_update(&h, &counter, 1);
        sw_hmac_final(&h, t);
        previous = hlen;

        size_t take = (out_size < hlen) ? out_size : hlen;
        for (size_t i = 0; i < take; i++)
            out[i] = t[i];
        out += take;
        out_size -= take;
    }

    sw_wipe(&h, sizeof(h));
    sw_wipe(prk, sizeof(prk));
    sw_wipe(t, sizeof(t));
    return 0;
}
