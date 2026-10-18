#ifndef DMCRYPTO_TYPES_H
#define DMCRYPTO_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Types shared by dmcrypto (the validated public API) and dmcrypto_port (what
 * a port implements). The model is PSA Crypto's - multi-part hash/HMAC with a
 * handle, one-shot AEAD and cipher, key derivation - kept to what a small
 * system needs. Asymmetric operations (ECDH, ECDSA, RSA - dmtls's) are not in
 * version 1.0; they come in 1.1 (see docs/api-reference.md), their
 * capability bits are reserved below.
 */

/* ---- Results: 0 or a negative errno-compatible code ---- */

#define DMCRYPTO_OK             0
/* -EINVAL    a bad argument (NULL, a size the algorithm cannot take)
 * -ENOTSUP   the algorithm is not in this port (see dmcrypto_caps_t)
 * -ENOMEM    no memory for a handle
 * -ENOSPC    the output buffer is too small
 * -EBADMSG   authentication failed (AEAD tag): nothing was decrypted
 * -EBUSY     the hardware is busy and the port cannot wait
 * -EIO       the hardware failed (including the entropy source)             */

/* ---- Algorithms ---- */

typedef enum
{
    DMCRYPTO_HASH_NONE   = 0,
    DMCRYPTO_HASH_SHA1   = 1,       /**< 20 bytes - for HMAC/compatibility, not for new designs */
    DMCRYPTO_HASH_SHA256 = 2,       /**< 32 bytes */
    DMCRYPTO_HASH_SHA384 = 3,       /**< 48 bytes */
    DMCRYPTO_HASH_SHA512 = 4,       /**< 64 bytes */
} dmcrypto_hash_alg_t;

#define DMCRYPTO_HASH_MAX_SIZE      64

typedef enum
{
    DMCRYPTO_CIPHER_AES_CBC = 1,    /**< No padding: the length is a multiple of 16 */
    DMCRYPTO_CIPHER_AES_CTR = 2,    /**< The IV is the 16-byte counter block, big-endian increment */
} dmcrypto_cipher_alg_t;

typedef enum
{
    DMCRYPTO_AEAD_AES_GCM            = 1,   /**< Nonce 12 bytes, tag 16 (or 4..16) bytes */
    DMCRYPTO_AEAD_CHACHA20_POLY1305  = 2,   /**< Nonce 12 bytes, tag 16 bytes */
} dmcrypto_aead_alg_t;

#define DMCRYPTO_AES_BLOCK_SIZE     16
#define DMCRYPTO_AEAD_NONCE_SIZE    12
#define DMCRYPTO_AEAD_TAG_MAX_SIZE  16

/* ---- Capabilities: dmcrypto_get_capabilities() ---- */

/** Bits of dmcrypto_caps_t.supported / .accelerated */
#define DMCRYPTO_CAP_HASH_SHA1          (1u << 0)
#define DMCRYPTO_CAP_HASH_SHA256        (1u << 1)
#define DMCRYPTO_CAP_HASH_SHA384        (1u << 2)
#define DMCRYPTO_CAP_HASH_SHA512        (1u << 3)
#define DMCRYPTO_CAP_HMAC               (1u << 4)   /**< With every hash the port has */
#define DMCRYPTO_CAP_PBKDF2             (1u << 5)
#define DMCRYPTO_CAP_HKDF               (1u << 6)
#define DMCRYPTO_CAP_CIPHER_AES_CBC     (1u << 7)
#define DMCRYPTO_CAP_CIPHER_AES_CTR     (1u << 8)
#define DMCRYPTO_CAP_AEAD_AES_GCM       (1u << 9)
#define DMCRYPTO_CAP_AEAD_CHACHA20_POLY1305 (1u << 10)
#define DMCRYPTO_CAP_RANDOM             (1u << 11)
/* Reserved for 1.1 (asymmetric) */
#define DMCRYPTO_CAP_ECDH               (1u << 16)
#define DMCRYPTO_CAP_ECDSA              (1u << 17)
#define DMCRYPTO_CAP_RSA                (1u << 18)

#define DMCRYPTO_PORT_NAME_MAX          24

typedef struct
{
    char        port_name[DMCRYPTO_PORT_NAME_MAX];  /**< "sw", "stm32f7", ... */
    uint32_t    supported;                          /**< DMCRYPTO_CAP_* the port implements (hardware or software) */
    uint32_t    accelerated;                        /**< ... of them the ones done by hardware */
} dmcrypto_caps_t;

/* ---- Entropy ---- */

/**
 * A source of strong random bytes (a hardware RNG - dmrng's dmrng_fill() - or
 * the board's equivalent). Fills the whole buffer and returns 0, or returns a
 * negative errno. The application hands one to dmcrypto_set_entropy(): dmcrypto
 * itself depends on no RNG driver and has no software fallback (as dmtls).
 * The function must be a plain function of a module, not data in a table.
 */
typedef int (*dmcrypto_entropy_fn_t)(void* context, void* buffer, size_t size);

/* ---- Handles ---- */

typedef struct dmcrypto_hash* dmcrypto_hash_t;      /**< Multi-part hash */
typedef struct dmcrypto_hmac* dmcrypto_hmac_t;      /**< Multi-part HMAC */

#endif /* DMCRYPTO_TYPES_H */
