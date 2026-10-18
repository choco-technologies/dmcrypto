#define DMOD_ENABLE_REGISTRATION ON
#define ENABLE_DIF_REGISTRATIONS ON
#include "dmod_test.h"
#include "dmcrypto.h"
#include "dmcrypto_ioctl.h"
#include "dmdrvi.h"
#include "dmini.h"
#include "vectors.h"
#include <errno.h>
#include <string.h>

/*
 * dmcrypto through its public API, whichever port is loaded: the expected
 * results are Python's (OpenSSL's) - tests/fixtures/make_vectors.py - and the
 * RFCs' own vectors. The inputs are pattern(n, seed), the function the
 * generator has too.
 */

static void pattern(uint8_t *out, size_t n, int seed)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)((i * 131 + (size_t)seed * 17 + (i >> 2)) & 0xFF);
}

static const size_t hash_lengths[]  = { 0, 1, 3, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 200, 1000 };
static const size_t hmac_key_sizes[] = { 0, 1, 20, 64, 65, 131, 200 };
static const size_t cbc_lengths[]   = { 16, 32, 48, 160 };
static const size_t ctr_lengths[]   = { 1, 15, 16, 17, 33, 100 };
static const size_t key_sizes[]     = { 16, 24, 32 };
static const size_t aead_aad[]      = { 0, 0, 20, 20, 13, 16, 0 };
static const size_t aead_len[]      = { 0, 16, 0, 5, 16, 33, 100 };
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* ---- Helpers (dmcrypto itself) ---- */

DMOD_TEST_STEP(equal_compares_all_bytes)
{
    const uint8_t a[4] = { 1, 2, 3, 4 };
    const uint8_t same[4] = { 1, 2, 3, 4 };
    const uint8_t last[4] = { 1, 2, 3, 5 };
    const uint8_t first[4] = { 0, 2, 3, 4 };

    DMOD_TEST_EXPECT_TRUE(dmcrypto_equal(a, same, sizeof(a)));
    DMOD_TEST_EXPECT_FALSE(dmcrypto_equal(a, last, sizeof(a)));
    DMOD_TEST_EXPECT_FALSE(dmcrypto_equal(a, first, sizeof(a)));
    DMOD_TEST_EXPECT_TRUE(dmcrypto_equal(a, last, 0));
}

DMOD_TEST_STEP(wipe_zeroes_the_buffer)
{
    uint8_t secret[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const uint8_t zero[8] = { 0 };

    dmcrypto_wipe(secret, sizeof(secret));
    DMOD_TEST_EXPECT_EQ(memcmp(secret, zero, sizeof(zero)), 0);
    dmcrypto_wipe(NULL, 4);     /* Must not crash */
}

DMOD_TEST_STEP(capabilities_name_the_port)
{
    dmcrypto_caps_t caps;

    memset(&caps, 0xFF, sizeof(caps));
    DMOD_TEST_EXPECT_EQ(dmcrypto_get_capabilities(&caps), 0);
    DMOD_TEST_EXPECT_TRUE(caps.port_name[0] != '\0');
    DMOD_TEST_EXPECT_EQ(caps.accelerated & ~caps.supported, 0);     /* Hardware does what the port has */
    DMOD_TEST_EXPECT_EQ(dmcrypto_get_capabilities(NULL), -EINVAL);
}

/* ---- Random ---- */

static int test_entropy(void *context, void *buffer, size_t size)
{
    int *calls = context;

    (*calls)++;
    if (*calls < 0)
        return -EIO;
    for (size_t i = 0; i < size; i++)
        ((uint8_t *)buffer)[i] = (uint8_t)(0xA0 + i);
    return 0;
}

DMOD_TEST_STEP(random_needs_an_entropy_source)
{
    uint8_t buffer[8];
    int calls = 0;
    dmcrypto_caps_t caps;

    DMOD_TEST_EXPECT_EQ(dmcrypto_set_entropy(NULL, NULL), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_random(buffer, sizeof(buffer)), -ENODEV);
    DMOD_TEST_EXPECT_EQ(dmcrypto_get_capabilities(&caps), 0);
    DMOD_TEST_EXPECT_EQ(caps.supported & DMCRYPTO_CAP_RANDOM, 0);

    DMOD_TEST_EXPECT_EQ(dmcrypto_set_entropy(test_entropy, &calls), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_random(buffer, sizeof(buffer)), 0);
    DMOD_TEST_EXPECT_EQ(buffer[0], 0xA0);
    DMOD_TEST_EXPECT_EQ(buffer[7], 0xA7);
    DMOD_TEST_EXPECT_EQ(calls, 1);
    DMOD_TEST_EXPECT_EQ(dmcrypto_get_capabilities(&caps), 0);
    DMOD_TEST_EXPECT_TRUE((caps.supported & DMCRYPTO_CAP_RANDOM) != 0);

    /* A failing source: the error comes back and nothing half-random is left */
    calls = -5;
    memset(buffer, 0x55, sizeof(buffer));
    DMOD_TEST_EXPECT_EQ(dmcrypto_random(buffer, sizeof(buffer)), -EIO);
    DMOD_TEST_EXPECT_EQ(buffer[0], 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_random(NULL, 4), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_set_entropy(NULL, NULL), 0);
}

/* ---- Hash ---- */

static int check_hash(dmcrypto_hash_alg_t alg, size_t digest_size, const uint8_t *expected)
{
    uint8_t message[1000], digest[DMCRYPTO_HASH_MAX_SIZE];
    size_t length = 0, bad = 0;

    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_size(alg), digest_size);
    for (size_t i = 0; i < COUNT(hash_lengths); i++)
    {
        pattern(message, hash_lengths[i], 1);
        DMOD_TEST_EXPECT_EQ(dmcrypto_hash(alg, message, hash_lengths[i], digest, sizeof(digest), &length), 0);
        bad += (length != digest_size) || memcmp(digest, expected + i * digest_size, digest_size) != 0;
    }
    return (int)bad;
}

DMOD_TEST_STEP(sha1_matches_openssl)    { DMOD_TEST_EXPECT_EQ(check_hash(DMCRYPTO_HASH_SHA1, 20, vec_hash_sha1), 0); }
DMOD_TEST_STEP(sha256_matches_openssl)  { DMOD_TEST_EXPECT_EQ(check_hash(DMCRYPTO_HASH_SHA256, 32, vec_hash_sha256), 0); }
DMOD_TEST_STEP(sha384_matches_openssl)  { DMOD_TEST_EXPECT_EQ(check_hash(DMCRYPTO_HASH_SHA384, 48, vec_hash_sha384), 0); }
DMOD_TEST_STEP(sha512_matches_openssl)  { DMOD_TEST_EXPECT_EQ(check_hash(DMCRYPTO_HASH_SHA512, 64, vec_hash_sha512), 0); }

DMOD_TEST_STEP(multi_part_hash_equals_one_shot)
{
    uint8_t message[1000], once[64], parts[64];
    size_t length = 0;
    const size_t chunks[] = { 1, 7, 64, 100 };

    pattern(message, sizeof(message), 1);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash(DMCRYPTO_HASH_SHA256, message, sizeof(message), once, sizeof(once), &length), 0);
    for (size_t c = 0; c < COUNT(chunks); c++)
    {
        dmcrypto_hash_t h = NULL;
        DMOD_TEST_EXPECT_EQ(dmcrypto_hash_start(DMCRYPTO_HASH_SHA256, &h), 0);
        for (size_t off = 0; off < sizeof(message); off += chunks[c])
        {
            size_t n = (sizeof(message) - off < chunks[c]) ? sizeof(message) - off : chunks[c];
            DMOD_TEST_EXPECT_EQ(dmcrypto_hash_update(h, message + off, n), 0);
        }
        DMOD_TEST_EXPECT_EQ(dmcrypto_hash_finish(h, parts, sizeof(parts), &length), 0);
        DMOD_TEST_EXPECT_EQ(memcmp(once, parts, length), 0);
    }
}

DMOD_TEST_STEP(hash_clone_continues_independently)
{
    uint8_t message[200], expected[32], a[32], b[32];
    size_t length = 0;
    dmcrypto_hash_t h = NULL, clone = NULL;

    pattern(message, sizeof(message), 1);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash(DMCRYPTO_HASH_SHA256, message, 200, expected, sizeof(expected), &length), 0);

    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_start(DMCRYPTO_HASH_SHA256, &h), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_update(h, message, 100), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_clone(h, &clone), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_update(clone, "extra", 5), 0);        /* only the clone sees it */
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_update(h, message + 100, 100), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_finish(h, a, sizeof(a), &length), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(a, expected, 32), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_finish(clone, b, sizeof(b), &length), 0);
    DMOD_TEST_EXPECT_TRUE(memcmp(a, b, 32) != 0);
}

DMOD_TEST_STEP(hash_rejects_bad_arguments)
{
    uint8_t digest[64], small[10];
    size_t length = 0;
    dmcrypto_hash_t h = NULL;

    DMOD_TEST_EXPECT_EQ(dmcrypto_hash(DMCRYPTO_HASH_NONE, "x", 1, digest, sizeof(digest), &length), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash(DMCRYPTO_HASH_SHA256, NULL, 1, digest, sizeof(digest), &length), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash(DMCRYPTO_HASH_SHA256, NULL, 0, digest, sizeof(digest), &length), 0);   /* empty is fine */
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash(DMCRYPTO_HASH_SHA256, "x", 1, small, sizeof(small), &length), -ENOSPC);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_start(DMCRYPTO_HASH_SHA256, NULL), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_start((dmcrypto_hash_alg_t)99, &h), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_size(DMCRYPTO_HASH_NONE), 0);

    /* finish frees the handle on a too small buffer as well */
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_start(DMCRYPTO_HASH_SHA256, &h), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hash_finish(h, small, sizeof(small), &length), -ENOSPC);
    dmcrypto_hash_abort(NULL);      /* Safe */
}

/* ---- HMAC ---- */

static int check_hmac(dmcrypto_hash_alg_t alg, size_t mac_size, const uint8_t *expected)
{
    uint8_t key[200], message[50], mac[DMCRYPTO_HASH_MAX_SIZE], parts[DMCRYPTO_HASH_MAX_SIZE];
    size_t length = 0, bad = 0;

    pattern(message, sizeof(message), 3);
    for (size_t i = 0; i < COUNT(hmac_key_sizes); i++)
    {
        dmcrypto_hmac_t h = NULL;

        pattern(key, hmac_key_sizes[i], 2);
        DMOD_TEST_EXPECT_EQ(dmcrypto_hmac(alg, key, hmac_key_sizes[i], message, sizeof(message), mac, sizeof(mac), &length), 0);
        bad += (length != mac_size) || memcmp(mac, expected + i * mac_size, mac_size) != 0;

        DMOD_TEST_EXPECT_EQ(dmcrypto_hmac_start(alg, key, hmac_key_sizes[i], &h), 0);
        DMOD_TEST_EXPECT_EQ(dmcrypto_hmac_update(h, message, 20), 0);
        DMOD_TEST_EXPECT_EQ(dmcrypto_hmac_update(h, message + 20, 30), 0);
        DMOD_TEST_EXPECT_EQ(dmcrypto_hmac_finish(h, parts, sizeof(parts), &length), 0);
        bad += memcmp(mac, parts, mac_size) != 0;
    }
    return (int)bad;
}

DMOD_TEST_STEP(hmac_sha1_matches_openssl)   { DMOD_TEST_EXPECT_EQ(check_hmac(DMCRYPTO_HASH_SHA1, 20, vec_hmac_sha1), 0); }
DMOD_TEST_STEP(hmac_sha256_matches_openssl) { DMOD_TEST_EXPECT_EQ(check_hmac(DMCRYPTO_HASH_SHA256, 32, vec_hmac_sha256), 0); }
DMOD_TEST_STEP(hmac_sha384_matches_openssl) { DMOD_TEST_EXPECT_EQ(check_hmac(DMCRYPTO_HASH_SHA384, 48, vec_hmac_sha384), 0); }
DMOD_TEST_STEP(hmac_sha512_matches_openssl) { DMOD_TEST_EXPECT_EQ(check_hmac(DMCRYPTO_HASH_SHA512, 64, vec_hmac_sha512), 0); }

/* ---- Key derivation ---- */

DMOD_TEST_STEP(pbkdf2_matches_rfc_6070_and_openssl)
{
    uint8_t out[100], password[70], salt[150];

    DMOD_TEST_EXPECT_EQ(dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA1, "password", 8, "salt", 4, 1, out, 20), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_pbkdf2_sha1_1, 20), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA1, "password", 8, "salt", 4, 4096, out, 20), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_pbkdf2_sha1_4096, 20), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA1, "ThisIsAPassword", 15, "ThisIsASSID", 11, 4096, out, 32), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_pbkdf2_sha1_wpa, 32), 0);

    pattern(password, 70, 4);
    pattern(salt, 20, 5);
    DMOD_TEST_EXPECT_EQ(dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA256, password, 70, salt, 20, 100, out, 70), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_pbkdf2_sha256, 70), 0);
    pattern(salt, 150, 6);
    DMOD_TEST_EXPECT_EQ(dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA512, "pw", 2, salt, 150, 10, out, 100), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_pbkdf2_sha512, 100), 0);

    DMOD_TEST_EXPECT_EQ(dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA1, "p", 1, "s", 1, 0, out, 20), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA1, "p", 1, "s", 1, 1, out, 0), -EINVAL);
}

DMOD_TEST_STEP(hkdf_matches_rfc_5869_and_openssl)
{
    uint8_t out[200], ikm[40], salt[10], info[30], rfc_ikm[22], rfc_salt[13], rfc_info[10];

    memset(rfc_ikm, 0x0b, sizeof(rfc_ikm));
    for (size_t i = 0; i < sizeof(rfc_salt); i++)
        rfc_salt[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(rfc_info); i++)
        rfc_info[i] = (uint8_t)(0xf0 + i);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hkdf(DMCRYPTO_HASH_SHA256, rfc_ikm, 22, rfc_salt, 13, rfc_info, 10, out, 42), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_hkdf_sha256_rfc, 42), 0);

    pattern(ikm, 40, 7);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hkdf(DMCRYPTO_HASH_SHA256, ikm, 40, NULL, 0, NULL, 0, out, 100), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_hkdf_sha256_nosalt, 100), 0);

    pattern(ikm, 33, 8);
    pattern(salt, 10, 9);
    pattern(info, 30, 10);
    DMOD_TEST_EXPECT_EQ(dmcrypto_hkdf(DMCRYPTO_HASH_SHA512, ikm, 33, salt, 10, info, 30, out, 200), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_hkdf_sha512, 200), 0);

    DMOD_TEST_EXPECT_EQ(dmcrypto_hkdf(DMCRYPTO_HASH_SHA256, ikm, 33, NULL, 0, NULL, 0, out, 255 * 32 + 1), -EINVAL);
}

/* ---- AES ---- */

DMOD_TEST_STEP(aes_cbc_matches_openssl_and_decrypts)
{
    uint8_t key[32], iv[16], iv0[16], plain[160], cipher[160], back[160];
    size_t at = 0, bad = 0;

    pattern(iv0, 16, 12);
    for (size_t k = 0; k < COUNT(key_sizes); k++)
    {
        pattern(key, key_sizes[k], 11);
        for (size_t l = 0; l < COUNT(cbc_lengths); l++)
        {
            size_t n = cbc_lengths[l];
            pattern(plain, n, 13);
            memcpy(iv, iv0, 16);
            DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CBC, true, key, key_sizes[k], iv, plain, cipher, n), 0);
            bad += memcmp(cipher, vec_aes_cbc + at, n) != 0;
            at += n;
            memcpy(iv, iv0, 16);
            DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CBC, false, key, key_sizes[k], iv, cipher, back, n), 0);
            bad += memcmp(back, plain, n) != 0;
        }
    }
    DMOD_TEST_EXPECT_EQ(bad, 0);
}

DMOD_TEST_STEP(aes_cbc_chains_across_calls_and_works_in_place)
{
    uint8_t key[16], iv[16], plain[48], whole[48], split[48];

    pattern(key, 16, 11);
    pattern(plain, 48, 13);
    pattern(iv, 16, 12);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CBC, true, key, 16, iv, plain, whole, 48), 0);

    pattern(iv, 16, 12);
    memcpy(split, plain, 48);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CBC, true, key, 16, iv, split, split, 16), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CBC, true, key, 16, iv, split + 16, split + 16, 32), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(whole, split, 48), 0);

    pattern(iv, 16, 12);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CBC, false, key, 16, iv, split, split, 48), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(split, plain, 48), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CBC, true, key, 16, iv, plain, whole, 17), -EINVAL);
}

DMOD_TEST_STEP(aes_ctr_matches_openssl)
{
    uint8_t key[32], iv[16], plain[100], out[100], back[100];
    size_t at = 0, bad = 0;

    for (size_t k = 0; k < COUNT(key_sizes); k++)
    {
        pattern(key, key_sizes[k], 14);
        for (size_t l = 0; l < COUNT(ctr_lengths); l++)
        {
            size_t n = ctr_lengths[l];
            pattern(plain, n, 16);
            pattern(iv, 16, 15);
            DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CTR, true, key, key_sizes[k], iv, plain, out, n), 0);
            bad += memcmp(out, vec_aes_ctr + at, n) != 0;
            at += n;
            pattern(iv, 16, 15);
            DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CTR, false, key, key_sizes[k], iv, out, back, n), 0);
            bad += memcmp(back, plain, n) != 0;
        }
    }
    DMOD_TEST_EXPECT_EQ(bad, 0);
}

DMOD_TEST_STEP(aes_ctr_counter_carries_and_continues)
{
    uint8_t key[16], iv[16] = { 0 }, plain[80], out[80];

    iv[13] = 0xFF; iv[14] = 0xFF; iv[15] = 0xFE;
    pattern(key, 16, 17);
    pattern(plain, 80, 18);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CTR, true, key, 16, iv, plain, out, 80), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_aes_ctr_carry, 80), 0);

    /* the same in two calls: the iv carries the counter on */
    memset(iv, 0, 16);
    iv[13] = 0xFF; iv[14] = 0xFF; iv[15] = 0xFE;
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CTR, true, key, 16, iv, plain, out, 32), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CTR, true, key, 16, iv, plain + 32, out + 32, 48), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_aes_ctr_carry, 80), 0);
}

DMOD_TEST_STEP(cipher_rejects_bad_arguments)
{
    uint8_t key[32] = { 0 }, iv[16] = { 0 }, data[16] = { 0 };

    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CTR, true, key, 15, iv, data, data, 16), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt((dmcrypto_cipher_alg_t)9, true, key, 16, iv, data, data, 16), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_cipher_crypt(DMCRYPTO_CIPHER_AES_CTR, true, key, 16, NULL, data, data, 16), -EINVAL);
}

/* ---- AEAD ---- */

static int check_aead(dmcrypto_aead_alg_t alg, size_t key_size, uint8_t key_seed, uint8_t nonce_seed,
                      uint8_t plain_seed, uint8_t aad_seed, const uint8_t *expected)
{
    uint8_t key[32], nonce[12], aad[20], plain[100], out[100], tag[16], back[100];
    size_t at = 0, bad = 0;

    pattern(key, key_size, key_seed);
    pattern(nonce, 12, nonce_seed);
    for (size_t c = 0; c < COUNT(aead_len); c++)
    {
        size_t a = aead_aad[c], n = aead_len[c];

        pattern(aad, a, aad_seed);
        pattern(plain, n, plain_seed);
        DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(alg, key, key_size, nonce, 12, aad, a, plain, n, out, tag, 16), 0);
        bad += memcmp(out, expected + at, n) != 0;
        bad += memcmp(tag, expected + at + n, 16) != 0;
        at += n + 16;

        DMOD_TEST_EXPECT_EQ(dmcrypto_aead_decrypt(alg, key, key_size, nonce, 12, aad, a, out, n, tag, 16, back), 0);
        bad += memcmp(back, plain, n) != 0;
    }
    return (int)bad;
}

DMOD_TEST_STEP(aes_gcm_matches_openssl)
{
    size_t at = 0, bad = 0;

    for (size_t k = 0; k < COUNT(key_sizes); k++)
    {
        size_t block = 0;
        for (size_t c = 0; c < COUNT(aead_len); c++)
            block += aead_len[c] + 16;
        bad += (size_t)check_aead(DMCRYPTO_AEAD_AES_GCM, key_sizes[k], 19, 20, 21, 22, vec_aes_gcm + at);
        at += block;
    }
    DMOD_TEST_EXPECT_EQ(bad, 0);
}

DMOD_TEST_STEP(chacha20_poly1305_matches_openssl)
{
    DMOD_TEST_EXPECT_EQ(check_aead(DMCRYPTO_AEAD_CHACHA20_POLY1305, 32, 23, 24, 25, 26, vec_chacha_poly), 0);
}

DMOD_TEST_STEP(chacha20_poly1305_matches_rfc_8439)
{
    static const char text[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    static const uint8_t nonce[12] = { 0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    static const uint8_t aad[12] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    uint8_t key[32], out[sizeof(text)], tag[16];
    size_t n = sizeof(text) - 1;

    for (size_t i = 0; i < 32; i++)
        key[i] = (uint8_t)(0x80 + i);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_CHACHA20_POLY1305, key, 32, nonce, 12, aad, 12, text, n, out, tag, 16), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(out, vec_chacha_poly_rfc, n), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(tag, vec_chacha_poly_rfc + n, 16), 0);
}

static int tamper_fails(dmcrypto_aead_alg_t alg, size_t key_size)
{
    uint8_t key[32], nonce[12], aad[8], plain[40], cipher[40], tag[16], out[40];
    int bad = 0;

    pattern(key, key_size, 1);
    pattern(nonce, 12, 2);
    pattern(aad, 8, 3);
    pattern(plain, 40, 4);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(alg, key, key_size, nonce, 12, aad, 8, plain, 40, cipher, tag, 16), 0);

    /* a flipped bit of the ciphertext, of the tag, of the aad: not authentic, nothing returned */
    cipher[3] ^= 1;
    memset(out, 0x77, sizeof(out));
    bad += dmcrypto_aead_decrypt(alg, key, key_size, nonce, 12, aad, 8, cipher, 40, tag, 16, out) != -EBADMSG;
    bad += out[0] != 0 || out[39] != 0;
    cipher[3] ^= 1;
    tag[15] ^= 0x80;
    bad += dmcrypto_aead_decrypt(alg, key, key_size, nonce, 12, aad, 8, cipher, 40, tag, 16, out) != -EBADMSG;
    tag[15] ^= 0x80;
    aad[0] ^= 1;
    bad += dmcrypto_aead_decrypt(alg, key, key_size, nonce, 12, aad, 8, cipher, 40, tag, 16, out) != -EBADMSG;
    aad[0] ^= 1;
    bad += dmcrypto_aead_decrypt(alg, key, key_size, nonce, 12, aad, 8, cipher, 40, tag, 16, out) != 0;
    return bad;
}

DMOD_TEST_STEP(aead_rejects_tampered_messages)
{
    DMOD_TEST_EXPECT_EQ(tamper_fails(DMCRYPTO_AEAD_AES_GCM, 16), 0);
    DMOD_TEST_EXPECT_EQ(tamper_fails(DMCRYPTO_AEAD_AES_GCM, 32), 0);
    DMOD_TEST_EXPECT_EQ(tamper_fails(DMCRYPTO_AEAD_CHACHA20_POLY1305, 32), 0);
}

DMOD_TEST_STEP(aead_works_in_place_and_with_a_short_tag)
{
    uint8_t key[16], nonce[12], buffer[50], plain[50], tag[16], full[16], shorter[8];

    pattern(key, 16, 1);
    pattern(nonce, 12, 2);
    pattern(plain, 50, 4);
    memcpy(buffer, plain, 50);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_AES_GCM, key, 16, nonce, 12, NULL, 0, buffer, 50, buffer, tag, 16), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_decrypt(DMCRYPTO_AEAD_AES_GCM, key, 16, nonce, 12, NULL, 0, buffer, 50, tag, 16, buffer), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(buffer, plain, 50), 0);

    /* a GCM tag of 8 bytes is the first 8 of the full one */
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_AES_GCM, key, 16, nonce, 12, NULL, 0, plain, 50, buffer, full, 16), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_AES_GCM, key, 16, nonce, 12, NULL, 0, plain, 50, buffer, shorter, 8), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(full, shorter, 8), 0);
}

DMOD_TEST_STEP(aead_rejects_bad_arguments)
{
    uint8_t key[32] = { 0 }, nonce[12] = { 0 }, data[16] = { 0 }, tag[16];

    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_AES_GCM, key, 16, nonce, 11, NULL, 0, data, 16, data, tag, 16), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_AES_GCM, key, 20, nonce, 12, NULL, 0, data, 16, data, tag, 16), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_AES_GCM, key, 16, nonce, 12, NULL, 0, data, 16, data, tag, 3), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_CHACHA20_POLY1305, key, 16, nonce, 12, NULL, 0, data, 16, data, tag, 16), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt(DMCRYPTO_AEAD_CHACHA20_POLY1305, key, 32, nonce, 12, NULL, 0, data, 16, data, tag, 8), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmcrypto_aead_encrypt((dmcrypto_aead_alg_t)7, key, 32, nonce, 12, NULL, 0, data, 16, data, tag, 16), -EINVAL);
}

/* ---- The driver: /dev/crypto ---- */

typedef struct
{
    dmod_dmdrvi_create_t    create;
    dmod_dmdrvi_free_t      free;
    dmod_dmdrvi_open_t      open;
    dmod_dmdrvi_close_t     close;
    dmod_dmdrvi_read_t      read;
    dmod_dmdrvi_write_t     write;
    dmod_dmdrvi_ioctl_t     ioctl;
} driver_t;

typedef struct
{
    driver_t            drv;
    dmini_context_t     ini;
    dmdrvi_context_t    ctx;
    dmdrvi_dev_num_t    dev_num;
    void*               handle;
} device_t;

static bool device_open(device_t* dev, const char* ini_text)
{
    Dmod_Context_t* module = Dmod_GetModuleContext("dmcrypto");

    memset(dev, 0, sizeof(*dev));
    if (module == NULL)
        return false;
    dev->drv.create = Dmod_GetDifFunction(module, dmod_dmdrvi_create_sig);
    dev->drv.free   = Dmod_GetDifFunction(module, dmod_dmdrvi_free_sig);
    dev->drv.open   = Dmod_GetDifFunction(module, dmod_dmdrvi_open_sig);
    dev->drv.close  = Dmod_GetDifFunction(module, dmod_dmdrvi_close_sig);
    dev->drv.read   = Dmod_GetDifFunction(module, dmod_dmdrvi_read_sig);
    dev->drv.write  = Dmod_GetDifFunction(module, dmod_dmdrvi_write_sig);
    dev->drv.ioctl  = Dmod_GetDifFunction(module, dmod_dmdrvi_ioctl_sig);
    if (dev->drv.create == NULL || dev->drv.free == NULL || dev->drv.open == NULL || dev->drv.close == NULL ||
        dev->drv.read == NULL || dev->drv.write == NULL || dev->drv.ioctl == NULL)
        return false;

    dev->ini = dmini_create();
    dmini_parse_string(dev->ini, ini_text);
    dmini_set_active_section(dev->ini, "crypto", 0);
    dev->ctx = dev->drv.create(dev->ini, &dev->dev_num);
    if (dev->ctx == NULL)
        return false;
    dev->handle = dev->drv.open(dev->ctx, DMDRVI_O_RDONLY, &dev->dev_num);
    return dev->handle != NULL;
}

static void device_close(device_t* dev)
{
    if (dev->handle != NULL)
        dev->drv.close(dev->ctx, dev->handle);
    if (dev->ctx != NULL)
        dev->drv.free(dev->ctx);
    if (dev->ini != NULL)
        dmini_destroy(dev->ini);
}

/* /dev/zero is a node that returns bytes when read: a source whose output is known */
#define INI_ZERO    "[crypto]\ndriver_name=dmcrypto\nentropy=/dev/zero\n"
#define INI_NONE    "[crypto]\ndriver_name=dmcrypto\nentropy=/dev/does-not-exist\n"
#define INI_EMPTY   "[crypto]\ndriver_name=dmcrypto\nentropy=\n"

DMOD_TEST_STEP(driver_names_the_node_after_its_section)
{
    device_t dev;

    DMOD_TEST_EXPECT_TRUE(device_open(&dev, INI_ZERO));
    DMOD_TEST_EXPECT_EQ(dev.dev_num.flags, DMDRVI_NUM_ALT_NAME);
    DMOD_TEST_EXPECT_EQ(strcmp(dev.dev_num.alt_name, "crypto"), 0);
    device_close(&dev);
}

DMOD_TEST_STEP(driver_reads_random_from_the_entropy_node)
{
    device_t dev;
    uint8_t buffer[16];
    dmcrypto_caps_t caps;

    DMOD_TEST_EXPECT_TRUE(device_open(&dev, INI_ZERO));
    memset(buffer, 0x55, sizeof(buffer));
    DMOD_TEST_EXPECT_EQ(dev.drv.read(dev.ctx, dev.handle, buffer, sizeof(buffer), 0), (dmdrvi_ssize_t)sizeof(buffer));
    DMOD_TEST_EXPECT_EQ(buffer[0], 0);                  /* what /dev/zero gave */
    DMOD_TEST_EXPECT_EQ(buffer[15], 0);

    /* and dmcrypto_random() takes the same source */
    memset(buffer, 0x55, sizeof(buffer));
    DMOD_TEST_EXPECT_EQ(dmcrypto_random(buffer, sizeof(buffer)), 0);
    DMOD_TEST_EXPECT_EQ(buffer[7], 0);

    DMOD_TEST_EXPECT_EQ(dev.drv.ioctl(dev.ctx, dev.handle, DMCRYPTO_IOCTL_GET_CAPABILITIES, &caps), 0);
    DMOD_TEST_EXPECT_TRUE((caps.supported & DMCRYPTO_CAP_RANDOM) != 0);
    DMOD_TEST_EXPECT_EQ(dev.drv.ioctl(dev.ctx, dev.handle, DMCRYPTO_IOCTL_GET_CAPABILITIES, NULL), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dev.drv.ioctl(dev.ctx, dev.handle, 0x7777, &caps), -ENOTTY);
    DMOD_TEST_EXPECT_EQ(dev.drv.write(dev.ctx, dev.handle, buffer, 4, 0), -EROFS);
    device_close(&dev);

    /* the driver took its source with it */
    DMOD_TEST_EXPECT_EQ(dmcrypto_random(buffer, sizeof(buffer)), -ENODEV);
}

DMOD_TEST_STEP(driver_without_a_working_source_says_so)
{
    device_t dev;
    uint8_t buffer[8];

    DMOD_TEST_EXPECT_TRUE(device_open(&dev, INI_NONE));         /* the node is created, the source is not there yet */
    DMOD_TEST_EXPECT_EQ(dev.drv.read(dev.ctx, dev.handle, buffer, sizeof(buffer), 0), -ENODEV);
    device_close(&dev);

    DMOD_TEST_EXPECT_TRUE(device_open(&dev, INI_EMPTY));        /* no source configured: the application's */
    DMOD_TEST_EXPECT_EQ(dev.drv.read(dev.ctx, dev.handle, buffer, sizeof(buffer), 0), -ENODEV);
    device_close(&dev);
}

DMOD_TEST_STEP(driver_has_one_instance)
{
    device_t first, second;

    DMOD_TEST_EXPECT_TRUE(device_open(&first, INI_ZERO));
    DMOD_TEST_EXPECT_FALSE(device_open(&second, INI_ZERO));
    device_close(&second);
    device_close(&first);
}

/* ---- The crypto tool (run as a module, as dmnet's tools are tested) ---- */

DMOD_TEST_STEP(tool_hashes_a_text_and_rejects_an_unknown_algorithm)
{
    char* sha256[] = { "crypto", "hash", "sha256", "-s", "abc" };
    char* md5[] = { "crypto", "hash", "md5", "-s", "abc" };
    char* missing[] = { "crypto", "hash", "sha1", "/does/not/exist" };

    DMOD_TEST_EXPECT_EQ(Dmod_RunModule("crypto", 5, sha256), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("crypto", 5, md5), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("crypto", 4, missing), 0);
    DMOD_TEST_EXPECT_FALSE(Dmod_IsModuleLoaded("crypto"));
}

DMOD_TEST_STEP(tool_random_needs_a_source_and_a_sane_count)
{
    char* random16[] = { "crypto", "random", "16" };
    char* too_many[] = { "crypto", "random", "5000" };
    char* not_a_number[] = { "crypto", "random", "x1" };
    char* help[] = { "crypto", "--help" };
    int calls = 0;

    DMOD_TEST_EXPECT_EQ(dmcrypto_set_entropy(NULL, NULL), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("crypto", 3, random16), 0);     /* no source */
    DMOD_TEST_EXPECT_EQ(dmcrypto_set_entropy(test_entropy, &calls), 0);
    DMOD_TEST_EXPECT_EQ(Dmod_RunModule("crypto", 3, random16), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("crypto", 3, too_many), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("crypto", 3, not_a_number), 0);
    DMOD_TEST_EXPECT_EQ(Dmod_RunModule("crypto", 2, help), 0);
    DMOD_TEST_EXPECT_EQ(dmcrypto_set_entropy(NULL, NULL), 0);
}

DMOD_TEST_STEP(tool_info_needs_the_node)
{
    char* none[] = { "crypto", "info", "/dev/does-not-exist" };

    DMOD_TEST_EXPECT_NE(Dmod_RunModule("crypto", 3, none), 0);
}
