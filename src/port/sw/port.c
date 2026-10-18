#define DMOD_ENABLE_REGISTRATION    ON
#include "dmcrypto_port.h"
#include "dmod.h"
#include "sw.h"
#include <errno.h>

/*
 * The software port: every algorithm in C, for any architecture (the release
 * builds it for each architecture dmod supports). It is also the source of
 * the software parts of the hardware ports: a family's port compiles from
 * here only the algorithm files its hardware lacks (sha.c, hmac.c, aes.c,
 * gcm.c, chacha_poly.c; util.c always).
 *
 * dmcrypto validated the arguments (sizes, algorithms, NULL) before calling.
 */

/* Set by CMake: "sw", "stm32f7", ... - what dmcrypto_get_capabilities() reports */
_Static_assert(sizeof(DMCRYPTO_PORT_LABEL) <= DMCRYPTO_PORT_NAME_MAX, "port label too long");

struct dmcrypto_hash { sw_hash_t hash; };
struct dmcrypto_hmac { sw_hmac_t hmac; };

static dmcrypto_entropy_fn_t g_entropy_source;
static void                 *g_entropy_context;

/* ---- DMOD lifecycle ---- */

int dmod_init(const Dmod_Config_t *Config)
{
    (void)Config;
    Dmod_Printf("dmcrypto port module initialized (%s)\n", DMCRYPTO_PORT_LABEL);
    return 0;
}

int dmod_deinit(void)
{
    g_entropy_source  = NULL;
    g_entropy_context = NULL;
    Dmod_Printf("dmcrypto port module deinitialized (%s)\n", DMCRYPTO_PORT_LABEL);
    return 0;
}

/* ---- Port API ---- */

dmod_dmcrypto_port_api_declaration(1.0, int, _get_capabilities, ( dmcrypto_caps_t* caps ))
{
    caps->supported = DMCRYPTO_CAP_HASH_SHA1 | DMCRYPTO_CAP_HASH_SHA256 | DMCRYPTO_CAP_HASH_SHA384 |
                      DMCRYPTO_CAP_HASH_SHA512 | DMCRYPTO_CAP_HMAC | DMCRYPTO_CAP_PBKDF2 | DMCRYPTO_CAP_HKDF |
                      DMCRYPTO_CAP_CIPHER_AES_CBC | DMCRYPTO_CAP_CIPHER_AES_CTR | DMCRYPTO_CAP_AEAD_AES_GCM |
                      DMCRYPTO_CAP_AEAD_CHACHA20_POLY1305;
    if (g_entropy_source != NULL)
        caps->supported |= DMCRYPTO_CAP_RANDOM;
    caps->accelerated = 0;
    for (size_t i = 0; i < DMCRYPTO_PORT_NAME_MAX; i++)
        caps->port_name[i] = (i < sizeof(DMCRYPTO_PORT_LABEL)) ? DMCRYPTO_PORT_LABEL[i] : '\0';
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _set_entropy, ( dmcrypto_entropy_fn_t source, void* context ))
{
    g_entropy_source  = source;
    g_entropy_context = context;
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _random, ( void* buffer, size_t size ))
{
    if (g_entropy_source == NULL)
        return -ENODEV;
    int result = g_entropy_source(g_entropy_context, buffer, size);
    if (result != 0)
    {
        sw_wipe(buffer, size);      /* nothing half-random is left behind */
        return (result < 0) ? result : -EIO;
    }
    return 0;
}

/* ---- Hash ---- */

dmod_dmcrypto_port_api_declaration(1.0, size_t, _hash_size, ( dmcrypto_hash_alg_t alg ))
{
    return sw_hash_size(alg);
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_start, ( dmcrypto_hash_alg_t alg, dmcrypto_hash_t* hash ))
{
    struct dmcrypto_hash *h = Dmod_Malloc(sizeof(*h));
    if (h == NULL)
        return -ENOMEM;
    if (sw_hash_init(&h->hash, alg) != 0)
    {
        Dmod_Free(h);
        return -ENOTSUP;
    }
    *hash = h;
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_update, ( dmcrypto_hash_t hash, const void* data, size_t size ))
{
    sw_hash_update(&hash->hash, data, size);
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_clone, ( dmcrypto_hash_t source, dmcrypto_hash_t* clone ))
{
    struct dmcrypto_hash *h = Dmod_Malloc(sizeof(*h));
    if (h == NULL)
        return -ENOMEM;
    h->hash = source->hash;
    *clone = h;
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_finish, ( dmcrypto_hash_t hash, void* digest, size_t digest_size, size_t* digest_length ))
{
    size_t size = sw_hash_size(hash->hash.alg);
    int result = 0;

    if (digest_size < size)
    {
        result = -ENOSPC;
    }
    else
    {
        sw_hash_final(&hash->hash, digest);
        *digest_length = size;
    }
    sw_wipe(hash, sizeof(*hash));
    Dmod_Free(hash);
    return result;
}

dmod_dmcrypto_port_api_declaration(1.0, void, _hash_abort, ( dmcrypto_hash_t hash ))
{
    if (hash != NULL)
    {
        sw_wipe(hash, sizeof(*hash));
        Dmod_Free(hash);
    }
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash, ( dmcrypto_hash_alg_t alg, const void* data, size_t size, void* digest, size_t digest_size, size_t* digest_length ))
{
    sw_hash_t h;
    size_t length = sw_hash_size(alg);

    if (digest_size < length)
        return -ENOSPC;
    if (sw_hash_init(&h, alg) != 0)
        return -ENOTSUP;
    sw_hash_update(&h, data, size);
    sw_hash_final(&h, digest);
    *digest_length = length;
    return 0;
}

/* ---- HMAC ---- */

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac_start, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, dmcrypto_hmac_t* hmac ))
{
    struct dmcrypto_hmac *h = Dmod_Malloc(sizeof(*h));
    if (h == NULL)
        return -ENOMEM;
    if (sw_hmac_init(&h->hmac, alg, key, key_size) != 0)
    {
        Dmod_Free(h);
        return -ENOTSUP;
    }
    *hmac = h;
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac_update, ( dmcrypto_hmac_t hmac, const void* data, size_t size ))
{
    sw_hmac_update(&hmac->hmac, data, size);
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac_finish, ( dmcrypto_hmac_t hmac, void* mac, size_t mac_size, size_t* mac_length ))
{
    size_t size = sw_hash_size(hmac->hmac.outer.alg);
    int result = 0;

    if (mac_size < size)
    {
        result = -ENOSPC;
    }
    else
    {
        sw_hmac_final(&hmac->hmac, mac);
        *mac_length = size;
    }
    sw_wipe(hmac, sizeof(*hmac));
    Dmod_Free(hmac);
    return result;
}

dmod_dmcrypto_port_api_declaration(1.0, void, _hmac_abort, ( dmcrypto_hmac_t hmac ))
{
    if (hmac != NULL)
    {
        sw_wipe(hmac, sizeof(*hmac));
        Dmod_Free(hmac);
    }
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, const void* data, size_t size, void* mac, size_t mac_size, size_t* mac_length ))
{
    sw_hmac_t h;
    size_t length = sw_hash_size(alg);

    if (mac_size < length)
        return -ENOSPC;
    if (sw_hmac_init(&h, alg, key, key_size) != 0)
        return -ENOTSUP;
    sw_hmac_update(&h, data, size);
    sw_hmac_final(&h, mac);
    sw_wipe(&h, sizeof(h));
    *mac_length = length;
    return 0;
}

/* ---- Key derivation ---- */

dmod_dmcrypto_port_api_declaration(1.0, int, _pbkdf2_hmac, ( dmcrypto_hash_alg_t alg, const void* password, size_t password_size, const void* salt, size_t salt_size, uint32_t iterations, void* output, size_t output_size ))
{
    return sw_pbkdf2(alg, password, password_size, salt, salt_size, iterations, output, output_size) == 0 ? 0 : -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hkdf, ( dmcrypto_hash_alg_t alg, const void* ikm, size_t ikm_size, const void* salt, size_t salt_size, const void* info, size_t info_size, void* output, size_t output_size ))
{
    return sw_hkdf(alg, ikm, ikm_size, salt, salt_size, info, info_size, output, output_size) == 0 ? 0 : -ENOTSUP;
}

/* ---- Cipher, AEAD ---- */

dmod_dmcrypto_port_api_declaration(1.0, int, _cipher_crypt, ( dmcrypto_cipher_alg_t alg, bool encrypt, const void* key, size_t key_size, uint8_t* iv, const void* input, void* output, size_t size ))
{
    return sw_cipher_crypt(alg, encrypt, key, key_size, iv, input, output, size) == 0 ? 0 : -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _aead_encrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* plaintext, size_t size, void* ciphertext, void* tag, size_t tag_size ))
{
    (void)nonce_size;       /* dmcrypto: 12 */
    if (alg == DMCRYPTO_AEAD_AES_GCM)
        return sw_aes_gcm_encrypt(key, key_size, nonce, aad, aad_size, plaintext, size, ciphertext, tag, tag_size) == 0 ? 0 : -ENOTSUP;
    if (alg == DMCRYPTO_AEAD_CHACHA20_POLY1305)
        return sw_chacha_poly_encrypt(key, nonce, aad, aad_size, plaintext, size, ciphertext, tag) == 0 ? 0 : -ENOTSUP;
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _aead_decrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* ciphertext, size_t size, const void* tag, size_t tag_size, void* plaintext ))
{
    int result;

    (void)nonce_size;
    if (alg == DMCRYPTO_AEAD_AES_GCM)
        result = sw_aes_gcm_decrypt(key, key_size, nonce, aad, aad_size, ciphertext, size, tag, tag_size, plaintext);
    else if (alg == DMCRYPTO_AEAD_CHACHA20_POLY1305)
        result = sw_chacha_poly_decrypt(key, nonce, aad, aad_size, ciphertext, size, tag, plaintext);
    else
        return -ENOTSUP;

    if (result > 0)
    {
        sw_wipe(plaintext, size);       /* not authenticated: nothing of it is returned */
        return -EBADMSG;
    }
    return result == 0 ? 0 : -ENOTSUP;
}
