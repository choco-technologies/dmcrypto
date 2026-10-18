#ifndef DMCRYPTO_SW_H
#define DMCRYPTO_SW_H

/*
 * The software algorithms, plain C, no allocation, no dmod calls: each
 * .c file is one algorithm family, so a hardware port compiles only the ones
 * its peripherals lack. port.c puts them behind the dmcrypto_port API.
 */

#include <stdint.h>
#include <stddef.h>
#include "dmcrypto_types.h"

/* ---- Hashes (sha.c) ---- */

typedef struct { uint32_t h[5]; uint64_t bytes; uint8_t buf[64]; }  sw_sha1_t;
typedef struct { uint32_t h[8]; uint64_t bytes; uint8_t buf[64]; }  sw_sha256_t;
typedef struct { uint64_t h[8]; uint64_t bytes; uint8_t buf[128]; } sw_sha512_t;   /* SHA-384 too */

typedef struct
{
    dmcrypto_hash_alg_t alg;
    union { sw_sha1_t sha1; sw_sha256_t sha256; sw_sha512_t sha512; } u;
} sw_hash_t;

size_t sw_hash_size(dmcrypto_hash_alg_t alg);               /* 0: unknown */
size_t sw_hash_block_size(dmcrypto_hash_alg_t alg);         /* 64 or 128 */
int    sw_hash_init(sw_hash_t *ctx, dmcrypto_hash_alg_t alg);
void   sw_hash_update(sw_hash_t *ctx, const void *data, size_t size);
void   sw_hash_final(sw_hash_t *ctx, uint8_t *digest);      /* sw_hash_size() bytes */

/* ---- HMAC, PBKDF2, HKDF (hmac.c) ---- */

typedef struct { sw_hash_t inner, outer; } sw_hmac_t;       /* the pads already absorbed */

int  sw_hmac_init(sw_hmac_t *ctx, dmcrypto_hash_alg_t alg, const void *key, size_t key_size);
void sw_hmac_update(sw_hmac_t *ctx, const void *data, size_t size);
void sw_hmac_final(sw_hmac_t *ctx, uint8_t *mac);           /* sw_hash_size() bytes */

int sw_pbkdf2(dmcrypto_hash_alg_t alg, const void *password, size_t password_size,
              const void *salt, size_t salt_size, uint32_t iterations, uint8_t *out, size_t out_size);
int sw_hkdf(dmcrypto_hash_alg_t alg, const void *ikm, size_t ikm_size, const void *salt, size_t salt_size,
            const void *info, size_t info_size, uint8_t *out, size_t out_size);

/* ---- AES (aes.c) ---- */

typedef struct { uint8_t round_key[240]; int rounds; } sw_aes_t;

int  sw_aes_init(sw_aes_t *ctx, const void *key, size_t key_size);      /* 16, 24 or 32 bytes */
void sw_aes_encrypt_block(const sw_aes_t *ctx, const uint8_t in[16], uint8_t out[16]);
void sw_aes_decrypt_block(const sw_aes_t *ctx, const uint8_t in[16], uint8_t out[16]);
int  sw_cipher_crypt(dmcrypto_cipher_alg_t alg, int encrypt, const void *key, size_t key_size,
                     uint8_t *iv, const uint8_t *in, uint8_t *out, size_t size);

/* ---- AEAD (gcm.c, chacha_poly.c); 12-byte nonces ---- */

int sw_aes_gcm_encrypt(const void *key, size_t key_size, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                       const uint8_t *in, size_t size, uint8_t *out, uint8_t *tag, size_t tag_size);
int sw_aes_gcm_decrypt(const void *key, size_t key_size, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                       const uint8_t *in, size_t size, const uint8_t *tag, size_t tag_size, uint8_t *out);
int sw_chacha_poly_encrypt(const void *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                           const uint8_t *in, size_t size, uint8_t *out, uint8_t *tag);
int sw_chacha_poly_decrypt(const void *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
                           const uint8_t *in, size_t size, const uint8_t *tag, uint8_t *out);

/* ---- Helpers ---- */

void sw_wipe(void *buffer, size_t size);
int  sw_equal(const uint8_t *a, const uint8_t *b, size_t size);        /* 1 when equal, constant time */

#endif /* DMCRYPTO_SW_H */
