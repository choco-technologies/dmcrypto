#ifndef DMCRYPTO_PORT_H
#define DMCRYPTO_PORT_H

#include "dmod_types.h"
#include "dmcrypto_types.h"
#include "dmcrypto_port_defs.h"

/*
 * What a dmcrypto port implements: dmcrypto_port_<name> for every function
 * below (dmod_dmcrypto_port_api_declaration). dmcrypto validates the
 * arguments before calling it, so a port may assume non-NULL pointers, known
 * algorithm values and sizes the algorithm can take; it returns -ENOTSUP for
 * an algorithm it lacks (and says so in get_capabilities).
 *
 * Software port (src/port/sw): every algorithm in C, for any architecture.
 * Hardware port (src/port/<family>): the family's accelerators for what they
 * do, and the software port's sources - only the algorithms needed - for the
 * rest. Whatever a family's chips have not got is the manifest's concern: it
 * gives the chip the hardware or the software port.
 *
 * A port serializes its own hardware: callers need not. dmod_init() of the
 * port brings the peripheral up, dmod_deinit() releases it.
 */

/**
 * Which algorithms this port has and which of them the hardware does. Clients (dmtls, a secret store) choose what to use from it.
 */
dmod_dmcrypto_port_api(1.0, int, _get_capabilities, ( dmcrypto_caps_t* caps ));

/**
 * Sets the source of random bytes (see dmcrypto_entropy_fn_t); NULL clears it.
 * Until one is set dmcrypto_random() returns -ENODEV - there is no software
 * fallback. The function and its context must stay valid until it is replaced.
 */
dmod_dmcrypto_port_api(1.0, int, _set_entropy, ( dmcrypto_entropy_fn_t source, void* context ));

/**
 * Fills buffer with cryptographically strong random bytes (from the source set by set_entropy(); never a software fallback). -ENODEV when no source was set, -EIO when it fails.
 */
dmod_dmcrypto_port_api(1.0, int, _random, ( void* buffer, size_t size ));

/**
 * Digest size of alg in bytes, 0 for an unknown one.
 */
dmod_dmcrypto_port_api(1.0, size_t, _hash_size, ( dmcrypto_hash_alg_t alg ));

/**
 * Starts a multi-part hash. Finish it with hash_finish() or drop it with hash_abort(); both free the handle.
 */
dmod_dmcrypto_port_api(1.0, int, _hash_start, ( dmcrypto_hash_alg_t alg, dmcrypto_hash_t* hash ));

/**
 * Adds data to the hash.
 */
dmod_dmcrypto_port_api(1.0, int, _hash_update, ( dmcrypto_hash_t hash, const void* data, size_t size ));

/**
 * Copies a running hash (a TLS transcript is finished at several points). The clone is independent.
 */
dmod_dmcrypto_port_api(1.0, int, _hash_clone, ( dmcrypto_hash_t source, dmcrypto_hash_t* clone ));

/**
 * Finishes the hash and frees the handle (also on an error). -ENOSPC when digest_size is below hash_size().
 */
dmod_dmcrypto_port_api(1.0, int, _hash_finish, ( dmcrypto_hash_t hash, void* digest, size_t digest_size, size_t* digest_length ));

/**
 * Drops a hash without a result. Safe with NULL.
 */
dmod_dmcrypto_port_api(1.0, void, _hash_abort, ( dmcrypto_hash_t hash ));

/**
 * One-shot hash.
 */
dmod_dmcrypto_port_api(1.0, int, _hash, ( dmcrypto_hash_alg_t alg, const void* data, size_t size, void* digest, size_t digest_size, size_t* digest_length ));

/**
 * Starts a multi-part HMAC with the key (any length, including 0).
 */
dmod_dmcrypto_port_api(1.0, int, _hmac_start, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, dmcrypto_hmac_t* hmac ));

/**
 * Adds data to the HMAC.
 */
dmod_dmcrypto_port_api(1.0, int, _hmac_update, ( dmcrypto_hmac_t hmac, const void* data, size_t size ));

/**
 * Finishes the HMAC and frees the handle (also on an error).
 */
dmod_dmcrypto_port_api(1.0, int, _hmac_finish, ( dmcrypto_hmac_t hmac, void* mac, size_t mac_size, size_t* mac_length ));

/**
 * Drops an HMAC without a result. Safe with NULL.
 */
dmod_dmcrypto_port_api(1.0, void, _hmac_abort, ( dmcrypto_hmac_t hmac ));

/**
 * One-shot HMAC.
 */
dmod_dmcrypto_port_api(1.0, int, _hmac, ( dmcrypto_hash_alg_t alg, const void* key, size_t key_size, const void* data, size_t size, void* mac, size_t mac_size, size_t* mac_length ));

/**
 * PBKDF2 (RFC 8018) with HMAC-alg: derives output_size bytes. iterations >= 1; a port can take a long time for many (WPA2: 4096 x SHA-1, 32 bytes).
 */
dmod_dmcrypto_port_api(1.0, int, _pbkdf2_hmac, ( dmcrypto_hash_alg_t alg, const void* password, size_t password_size, const void* salt, size_t salt_size, uint32_t iterations, void* output, size_t output_size ));

/**
 * HKDF (RFC 5869) extract-and-expand; output_size at most 255 x hash_size().
 */
dmod_dmcrypto_port_api(1.0, int, _hkdf, ( dmcrypto_hash_alg_t alg, const void* ikm, size_t ikm_size, const void* salt, size_t salt_size, const void* info, size_t info_size, void* output, size_t output_size ));

/**
 * AES-CBC / AES-CTR (key 16, 24 or 32 bytes) over size bytes; input and output may be the same buffer. iv (DMCRYPTO_AES_BLOCK_SIZE bytes) is updated in place, so consecutive calls continue the stream (every call but the last a multiple of 16 bytes).
 */
dmod_dmcrypto_port_api(1.0, int, _cipher_crypt, ( dmcrypto_cipher_alg_t alg, bool encrypt, const void* key, size_t key_size, uint8_t* iv, const void* input, void* output, size_t size ));

/**
 * Authenticated encryption: ciphertext (size bytes, may equal plaintext) and a separate tag of tag_size bytes.
 */
dmod_dmcrypto_port_api(1.0, int, _aead_encrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* plaintext, size_t size, void* ciphertext, void* tag, size_t tag_size ));

/**
 * Verifies the tag, then decrypts. -EBADMSG when it does not match: plaintext is then zeroed, not returned.
 */
dmod_dmcrypto_port_api(1.0, int, _aead_decrypt, ( dmcrypto_aead_alg_t alg, const void* key, size_t key_size, const void* nonce, size_t nonce_size, const void* aad, size_t aad_size, const void* ciphertext, size_t size, const void* tag, size_t tag_size, void* plaintext ));

#endif /* DMCRYPTO_PORT_H */
