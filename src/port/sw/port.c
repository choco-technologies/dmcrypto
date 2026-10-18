#define DMOD_ENABLE_REGISTRATION    ON
#include "dmcrypto_port.h"
#include "dmod.h"
#include <errno.h>

/*
 * The software port: every algorithm in C, for any architecture (the release
 * builds it for each architecture dmod supports). It is also the source of
 * the software parts of the hardware ports: a family's port compiles from
 * here only the algorithms its hardware lacks.
 *
 * TODO(implementation): the algorithms below return -ENOTSUP until they are
 * written; get_capabilities reports what is really there.
 */

/* Set by CMake: "sw", "stm32f7", ... - what dmcrypto_get_capabilities() reports */
_Static_assert(sizeof(DMCRYPTO_PORT_LABEL) <= DMCRYPTO_PORT_NAME_MAX, "port label too long");


/* ---- DMOD lifecycle ---- */

int dmod_init(const Dmod_Config_t *Config)
{
    (void)Config;
    Dmod_Printf("dmcrypto port module initialized (%s)\n", DMCRYPTO_PORT_LABEL);
    return 0;
}

int dmod_deinit(void)
{
    Dmod_Printf("dmcrypto port module deinitialized (%s)\n", DMCRYPTO_PORT_LABEL);
    return 0;
}

/* ---- Port API ---- */

dmod_dmcrypto_port_api_declaration(1.0, int, _get_capabilities, ( dmcrypto_caps_t* caps ))
{
    /* TODO(implementation): fill in what this port has */
    caps->supported   = 0;
    caps->accelerated = 0;
    for (size_t i = 0; i < DMCRYPTO_PORT_NAME_MAX; i++)
        caps->port_name[i] = (i < sizeof(DMCRYPTO_PORT_LABEL)) ? DMCRYPTO_PORT_LABEL[i] : '\0';
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _random, ( void* buffer, size_t size ))
{
    (void)buffer;
    (void)size;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, size_t, _hash_size, ( dmcrypto_hash_alg_t alg ))
{
    (void)alg;
    /* TODO(implementation) */
    return 0;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_start, ( dmcrypto_hash_alg_t alg, dmcrypto_hash_t* hash ))
{
    (void)alg;
    (void)hash;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_update, ( dmcrypto_hash_t hash, const void* data, size_t size ))
{
    (void)hash;
    (void)data;
    (void)size;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_clone, ( dmcrypto_hash_t source, dmcrypto_hash_t* clone ))
{
    (void)source;
    (void)clone;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash_finish, ( dmcrypto_hash_t hash, void* digest, size_t digest_size, size_t* digest_length ))
{
    (void)hash;
    (void)digest;
    (void)digest_size;
    (void)digest_length;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, void, _hash_abort, ( dmcrypto_hash_t hash ))
{
    (void)hash;
    /* TODO(implementation) */
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hash, ( dmcrypto_hash_alg_t alg, const void* data, size_t size, void* digest, size_t digest_size, size_t* digest_length ))
{
    (void)alg;
    (void)data;
    (void)size;
    (void)digest;
    (void)digest_size;
    (void)digest_length;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac_start, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, dmcrypto_hmac_t* hmac ))
{
    (void)alg;
    (void)key;
    (void)key_size;
    (void)hmac;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac_update, ( dmcrypto_hmac_t hmac, const void* data, size_t size ))
{
    (void)hmac;
    (void)data;
    (void)size;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac_finish, ( dmcrypto_hmac_t hmac, void* mac, size_t mac_size, size_t* mac_length ))
{
    (void)hmac;
    (void)mac;
    (void)mac_size;
    (void)mac_length;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, void, _hmac_abort, ( dmcrypto_hmac_t hmac ))
{
    (void)hmac;
    /* TODO(implementation) */
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hmac, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, const void* data, size_t size, void* mac, size_t mac_size, size_t* mac_length ))
{
    (void)alg;
    (void)key;
    (void)key_size;
    (void)data;
    (void)size;
    (void)mac;
    (void)mac_size;
    (void)mac_length;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _pbkdf2_hmac, ( dmcrypto_hash_alg_t alg, const void* password, size_t password_size, const void* salt, size_t salt_size, uint32_t iterations, void* output, size_t output_size ))
{
    (void)alg;
    (void)password;
    (void)password_size;
    (void)salt;
    (void)salt_size;
    (void)iterations;
    (void)output;
    (void)output_size;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _hkdf, ( dmcrypto_hash_alg_t alg, const void* ikm, size_t ikm_size, const void* salt, size_t salt_size, const void* info, size_t info_size, void* output, size_t output_size ))
{
    (void)alg;
    (void)ikm;
    (void)ikm_size;
    (void)salt;
    (void)salt_size;
    (void)info;
    (void)info_size;
    (void)output;
    (void)output_size;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _cipher_crypt, ( dmcrypto_cipher_alg_t alg, bool encrypt, const void* key, size_t key_size, uint8_t* iv, const void* input, void* output, size_t size ))
{
    (void)alg;
    (void)encrypt;
    (void)key;
    (void)key_size;
    (void)iv;
    (void)input;
    (void)output;
    (void)size;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _aead_encrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* plaintext, size_t size, void* ciphertext, void* tag, size_t tag_size ))
{
    (void)alg;
    (void)key;
    (void)key_size;
    (void)nonce;
    (void)nonce_size;
    (void)aad;
    (void)aad_size;
    (void)plaintext;
    (void)size;
    (void)ciphertext;
    (void)tag;
    (void)tag_size;
    /* TODO(implementation) */
    return -ENOTSUP;
}

dmod_dmcrypto_port_api_declaration(1.0, int, _aead_decrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* ciphertext, size_t size, const void* tag, size_t tag_size, void* plaintext ))
{
    (void)alg;
    (void)key;
    (void)key_size;
    (void)nonce;
    (void)nonce_size;
    (void)aad;
    (void)aad_size;
    (void)ciphertext;
    (void)size;
    (void)tag;
    (void)tag_size;
    (void)plaintext;
    /* TODO(implementation) */
    return -ENOTSUP;
}
