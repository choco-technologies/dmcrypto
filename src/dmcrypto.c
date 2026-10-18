#define DMOD_ENABLE_REGISTRATION ON
#include "dmod.h"
#include "dmcrypto.h"
#include "dmcrypto_port.h"
#include <errno.h>

/*
 * The public API: it validates the arguments, then calls the port - so a port
 * may assume non-NULL pointers, known algorithms and sizes the algorithm takes.
 */

static bool known_hash(dmcrypto_hash_alg_t alg)
{
    return alg == DMCRYPTO_HASH_SHA1 || alg == DMCRYPTO_HASH_SHA256 ||
           alg == DMCRYPTO_HASH_SHA384 || alg == DMCRYPTO_HASH_SHA512;
}

static size_t digest_size_of(dmcrypto_hash_alg_t alg)
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

/* data may be NULL only when it is empty */
static bool data_ok(const void *data, size_t size)
{
    return data != NULL || size == 0;
}

static bool aes_key_ok(size_t key_size)
{
    return key_size == 16 || key_size == 24 || key_size == 32;
}

dmod_dmcrypto_api_declaration(1.0, int, _get_capabilities, ( dmcrypto_caps_t* caps ))
{
    if (caps == NULL)
        return -EINVAL;
    return dmcrypto_port_get_capabilities(caps);
}

dmod_dmcrypto_api_declaration(1.0, int, _set_entropy, ( dmcrypto_entropy_fn_t source, void* context ))
{
    return dmcrypto_port_set_entropy(source, context);
}

dmod_dmcrypto_api_declaration(1.0, int, _random, ( void* buffer, size_t size ))
{
    if (!data_ok(buffer, size))
        return -EINVAL;
    return size == 0 ? 0 : dmcrypto_port_random(buffer, size);
}

dmod_dmcrypto_api_declaration(1.0, size_t, _hash_size, ( dmcrypto_hash_alg_t alg ))
{
    return digest_size_of(alg);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_start, ( dmcrypto_hash_alg_t alg, dmcrypto_hash_t* hash ))
{
    if (hash == NULL || !known_hash(alg))
        return -EINVAL;
    return dmcrypto_port_hash_start(alg, hash);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_update, ( dmcrypto_hash_t hash, const void* data, size_t size ))
{
    if (hash == NULL || !data_ok(data, size))
        return -EINVAL;
    return dmcrypto_port_hash_update(hash, data, size);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_clone, ( dmcrypto_hash_t source, dmcrypto_hash_t* clone ))
{
    if (source == NULL || clone == NULL)
        return -EINVAL;
    return dmcrypto_port_hash_clone(source, clone);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_finish, ( dmcrypto_hash_t hash, void* digest, size_t digest_size, size_t* digest_length ))
{
    if (hash == NULL)
        return -EINVAL;
    if (digest == NULL || digest_length == NULL)
    {
        dmcrypto_port_hash_abort(hash);     /* the handle is freed on every outcome */
        return -EINVAL;
    }
    return dmcrypto_port_hash_finish(hash, digest, digest_size, digest_length);
}

dmod_dmcrypto_api_declaration(1.0, void, _hash_abort, ( dmcrypto_hash_t hash ))
{
    dmcrypto_port_hash_abort(hash);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash, ( dmcrypto_hash_alg_t alg, const void* data, size_t size, void* digest, size_t digest_size, size_t* digest_length ))
{
    if (!known_hash(alg) || !data_ok(data, size) || digest == NULL || digest_length == NULL)
        return -EINVAL;
    return dmcrypto_port_hash(alg, data, size, digest, digest_size, digest_length);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac_start, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, dmcrypto_hmac_t* hmac ))
{
    if (hmac == NULL || !known_hash(alg) || !data_ok(key, key_size))
        return -EINVAL;
    return dmcrypto_port_hmac_start(alg, key, key_size, hmac);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac_update, ( dmcrypto_hmac_t hmac, const void* data, size_t size ))
{
    if (hmac == NULL || !data_ok(data, size))
        return -EINVAL;
    return dmcrypto_port_hmac_update(hmac, data, size);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac_finish, ( dmcrypto_hmac_t hmac, void* mac, size_t mac_size, size_t* mac_length ))
{
    if (hmac == NULL)
        return -EINVAL;
    if (mac == NULL || mac_length == NULL)
    {
        dmcrypto_port_hmac_abort(hmac);
        return -EINVAL;
    }
    return dmcrypto_port_hmac_finish(hmac, mac, mac_size, mac_length);
}

dmod_dmcrypto_api_declaration(1.0, void, _hmac_abort, ( dmcrypto_hmac_t hmac ))
{
    dmcrypto_port_hmac_abort(hmac);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, const void* data, size_t size, void* mac, size_t mac_size, size_t* mac_length ))
{
    if (!known_hash(alg) || !data_ok(key, key_size) || !data_ok(data, size) || mac == NULL || mac_length == NULL)
        return -EINVAL;
    return dmcrypto_port_hmac(alg, key, key_size, data, size, mac, mac_size, mac_length);
}

dmod_dmcrypto_api_declaration(1.0, int, _pbkdf2_hmac, ( dmcrypto_hash_alg_t alg, const void* password, size_t password_size, const void* salt, size_t salt_size, uint32_t iterations, void* output, size_t output_size ))
{
    if (!known_hash(alg) || !data_ok(password, password_size) || !data_ok(salt, salt_size) ||
        iterations == 0 || output == NULL || output_size == 0)
        return -EINVAL;
    return dmcrypto_port_pbkdf2_hmac(alg, password, password_size, salt, salt_size, iterations, output, output_size);
}

dmod_dmcrypto_api_declaration(1.0, int, _hkdf, ( dmcrypto_hash_alg_t alg, const void* ikm, size_t ikm_size, const void* salt, size_t salt_size, const void* info, size_t info_size, void* output, size_t output_size ))
{
    if (!known_hash(alg) || !data_ok(ikm, ikm_size) || !data_ok(salt, salt_size) || !data_ok(info, info_size) ||
        output == NULL || output_size == 0 || output_size > 255 * digest_size_of(alg))
        return -EINVAL;
    return dmcrypto_port_hkdf(alg, ikm, ikm_size, salt, salt_size, info, info_size, output, output_size);
}

dmod_dmcrypto_api_declaration(1.0, int, _cipher_crypt, ( dmcrypto_cipher_alg_t alg, bool encrypt, const void* key, size_t key_size, uint8_t* iv, const void* input, void* output, size_t size ))
{
    if ((alg != DMCRYPTO_CIPHER_AES_CBC && alg != DMCRYPTO_CIPHER_AES_CTR) || !aes_key_ok(key_size) ||
        key == NULL || iv == NULL || !data_ok(input, size) || !data_ok(output, size) ||
        (alg == DMCRYPTO_CIPHER_AES_CBC && size % DMCRYPTO_AES_BLOCK_SIZE != 0))
        return -EINVAL;
    return size == 0 ? 0 : dmcrypto_port_cipher_crypt(alg, encrypt, key, key_size, iv, input, output, size);
}

static bool aead_args_ok(dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce,
                         size_t nonce_size, const void* aad, size_t aad_size, size_t size, const void* in,
                         const void* out, const void* tag, size_t tag_size)
{
    if (alg != DMCRYPTO_AEAD_AES_GCM && alg != DMCRYPTO_AEAD_CHACHA20_POLY1305)
        return false;
    if (key == NULL || nonce == NULL || nonce_size != DMCRYPTO_AEAD_NONCE_SIZE || tag == NULL)
        return false;
    if (alg == DMCRYPTO_AEAD_AES_GCM ? !(aes_key_ok(key_size) && tag_size >= 4 && tag_size <= 16)
                                     : !(key_size == 32 && tag_size == 16))
        return false;
    return data_ok(aad, aad_size) && data_ok(in, size) && data_ok(out, size);
}

dmod_dmcrypto_api_declaration(1.0, int, _aead_encrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* plaintext, size_t size, void* ciphertext, void* tag, size_t tag_size ))
{
    if (!aead_args_ok(alg, key, key_size, nonce, nonce_size, aad, aad_size, size, plaintext, ciphertext, tag, tag_size))
        return -EINVAL;
    return dmcrypto_port_aead_encrypt(alg, key, key_size, nonce, nonce_size, aad, aad_size, plaintext, size, ciphertext, tag, tag_size);
}

dmod_dmcrypto_api_declaration(1.0, int, _aead_decrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* ciphertext, size_t size, const void* tag, size_t tag_size, void* plaintext ))
{
    if (!aead_args_ok(alg, key, key_size, nonce, nonce_size, aad, aad_size, size, ciphertext, plaintext, tag, tag_size))
        return -EINVAL;
    return dmcrypto_port_aead_decrypt(alg, key, key_size, nonce, nonce_size, aad, aad_size, ciphertext, size, tag, tag_size, plaintext);
}

/* ---- Implemented here, not by the port ---- */

dmod_dmcrypto_api_declaration(1.0, bool, _equal, ( const void* a, const void* b, size_t size ))
{
    const volatile uint8_t *x = a, *y = b;
    uint8_t difference = 0;

    for (size_t i = 0; i < size; i++)
        difference |= (uint8_t)(x[i] ^ y[i]);
    return difference == 0;
}

dmod_dmcrypto_api_declaration(1.0, void, _wipe, ( void* buffer, size_t size ))
{
    volatile uint8_t *p = buffer;

    for (size_t i = 0; p != NULL && i < size; i++)
        p[i] = 0;
}

/* ---- DMOD lifecycle ---- */

int dmod_init(const Dmod_Config_t *Config)
{
    (void)Config;
    return 0;
}

int dmod_deinit(void)
{
    return 0;
}
