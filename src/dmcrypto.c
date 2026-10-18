#define DMOD_ENABLE_REGISTRATION ON
#include "dmod.h"
#include "dmcrypto.h"
#include "dmcrypto_port.h"
#include <errno.h>

/*
 * The public API: it validates, then calls the port. TODO(implementation):
 * check the arguments each function documents (NULL, algorithm and sizes the
 * algorithm takes, buffers big enough) before the call - the port assumes
 * them. For now the functions only forward.
 */

dmod_dmcrypto_api_declaration(1.0, int, _get_capabilities, ( dmcrypto_caps_t* caps ))
{
    return dmcrypto_port_get_capabilities(caps);
}

dmod_dmcrypto_api_declaration(1.0, int, _random, ( void* buffer, size_t size ))
{
    return dmcrypto_port_random(buffer, size);
}

dmod_dmcrypto_api_declaration(1.0, size_t, _hash_size, ( dmcrypto_hash_alg_t alg ))
{
    return dmcrypto_port_hash_size(alg);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_start, ( dmcrypto_hash_alg_t alg, dmcrypto_hash_t* hash ))
{
    return dmcrypto_port_hash_start(alg, hash);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_update, ( dmcrypto_hash_t hash, const void* data, size_t size ))
{
    return dmcrypto_port_hash_update(hash, data, size);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_clone, ( dmcrypto_hash_t source, dmcrypto_hash_t* clone ))
{
    return dmcrypto_port_hash_clone(source, clone);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash_finish, ( dmcrypto_hash_t hash, void* digest, size_t digest_size, size_t* digest_length ))
{
    return dmcrypto_port_hash_finish(hash, digest, digest_size, digest_length);
}

dmod_dmcrypto_api_declaration(1.0, void, _hash_abort, ( dmcrypto_hash_t hash ))
{
    dmcrypto_port_hash_abort(hash);
}

dmod_dmcrypto_api_declaration(1.0, int, _hash, ( dmcrypto_hash_alg_t alg, const void* data, size_t size, void* digest, size_t digest_size, size_t* digest_length ))
{
    return dmcrypto_port_hash(alg, data, size, digest, digest_size, digest_length);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac_start, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, dmcrypto_hmac_t* hmac ))
{
    return dmcrypto_port_hmac_start(alg, key, key_size, hmac);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac_update, ( dmcrypto_hmac_t hmac, const void* data, size_t size ))
{
    return dmcrypto_port_hmac_update(hmac, data, size);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac_finish, ( dmcrypto_hmac_t hmac, void* mac, size_t mac_size, size_t* mac_length ))
{
    return dmcrypto_port_hmac_finish(hmac, mac, mac_size, mac_length);
}

dmod_dmcrypto_api_declaration(1.0, void, _hmac_abort, ( dmcrypto_hmac_t hmac ))
{
    dmcrypto_port_hmac_abort(hmac);
}

dmod_dmcrypto_api_declaration(1.0, int, _hmac, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, const void* data, size_t size, void* mac, size_t mac_size, size_t* mac_length ))
{
    return dmcrypto_port_hmac(alg, key, key_size, data, size, mac, mac_size, mac_length);
}

dmod_dmcrypto_api_declaration(1.0, int, _pbkdf2_hmac, ( dmcrypto_hash_alg_t alg, const void* password, size_t password_size, const void* salt, size_t salt_size, uint32_t iterations, void* output, size_t output_size ))
{
    return dmcrypto_port_pbkdf2_hmac(alg, password, password_size, salt, salt_size, iterations, output, output_size);
}

dmod_dmcrypto_api_declaration(1.0, int, _hkdf, ( dmcrypto_hash_alg_t alg, const void* ikm, size_t ikm_size, const void* salt, size_t salt_size, const void* info, size_t info_size, void* output, size_t output_size ))
{
    return dmcrypto_port_hkdf(alg, ikm, ikm_size, salt, salt_size, info, info_size, output, output_size);
}

dmod_dmcrypto_api_declaration(1.0, int, _cipher_crypt, ( dmcrypto_cipher_alg_t alg, bool encrypt, const void* key, size_t key_size, uint8_t* iv, const void* input, void* output, size_t size ))
{
    return dmcrypto_port_cipher_crypt(alg, encrypt, key, key_size, iv, input, output, size);
}

dmod_dmcrypto_api_declaration(1.0, int, _aead_encrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* plaintext, size_t size, void* ciphertext, void* tag, size_t tag_size ))
{
    return dmcrypto_port_aead_encrypt(alg, key, key_size, nonce, nonce_size, aad, aad_size, plaintext, size, ciphertext, tag, tag_size);
}

dmod_dmcrypto_api_declaration(1.0, int, _aead_decrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* ciphertext, size_t size, const void* tag, size_t tag_size, void* plaintext ))
{
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
