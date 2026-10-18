# dmcrypto - API reference

Declared in `include/dmcrypto.h` (the public API; types in
`include/dmcrypto_types.h`). `include/dmcrypto_port.h` has the same functions
as `dmcrypto_port_<name>` - what a port implements, and what a caller may call
directly to skip dmcrypto's argument checks.

Results: `0` or a negative errno (`-EINVAL` bad argument, `-ENOTSUP` the port
lacks the algorithm, `-ENOMEM`, `-ENOSPC` output too small, `-EBADMSG` AEAD
tag mismatch, `-EBUSY`, `-EIO` hardware / entropy failure).

| Group | Functions |
|---|---|
| Port | `get_capabilities` (name, supported, accelerated bits) |
| Random | `set_entropy`, `random` (from the source the application sets: `-ENODEV` until then, `-EIO` when it fails; never a software fallback) |
| Hash | `hash_size`, `hash_start` / `_update` / `_clone` / `_finish` / `_abort`, `hash` (SHA-1, SHA-256, SHA-384, SHA-512) |
| HMAC | `hmac_start` / `_update` / `_finish` / `_abort`, `hmac` |
| Key derivation | `pbkdf2_hmac`, `hkdf` |
| Cipher | `cipher_crypt` (AES-CBC without padding, AES-CTR; IV updated in place) |
| AEAD | `aead_encrypt`, `aead_decrypt` (AES-GCM, ChaCha20-Poly1305; a separate tag; plaintext zeroed on `-EBADMSG`) |
| Helpers (dmcrypto itself) | `equal` (constant time), `wipe` |

Multi-part handles (`hash_start`, `hmac_start`) are freed by `_finish` or
`_abort`. A client chooses algorithms from `get_capabilities`: a TLS stack
offers the cipher suites the port has, a secret store takes AES-GCM or falls
back to ChaCha20-Poly1305.

## The driver - `/dev/crypto`

dmcrypto is also a dmdrvi driver (`driver_name=dmcrypto` in a dmdevfs ini;
dmdevfs creates a node only for a configured section, so every board has one -
`configs/board/<board>/crypto.ini`). One instance. The section name is the
node's name. Key:

| Key | Default | |
|---|---|---|
| `entropy` | `/dev/rng` | A node that returns random bytes when read (dmrng's); the driver gives dmcrypto a source that reads it. Empty: no source from the driver (the application's `dmcrypto_set_entropy()`) |

The node: `read()` random bytes (`-ENODEV` without a working source, `-EIO`
when it fails), `write()` `-EROFS`, `ioctl` `DMCRYPTO_IOCTL_GET_CAPABILITIES`
(`dmcrypto_ioctl.h`). The node may be configured before its entropy node
exists: the source is opened at the first use. Nothing else of dmcrypto is a
file interface - hashes, ciphers and the rest are the functions above, called
directly. Removing the driver removes the source it gave.

## Entropy

dmcrypto has no RNG of its own and depends on no RNG driver. The source is the
driver's `entropy=` node, or any `dmcrypto_entropy_fn_t` the application
gives to `dmcrypto_set_entropy()`:

    static int rng(void *context, void *buffer, size_t size)
    {
        (void)context;
        return dmrng_fill(buffer, size);        /* 0 or a negative errno */
    }
    dmcrypto_set_entropy(rng, NULL);

The function must be a plain function of the registering module (not an entry
in a table of initialized data: the dmod loader does not relocate those).
`get_capabilities` reports `DMCRYPTO_CAP_RANDOM` while a source is set.

## The `crypto` tool

`crypto info`, `crypto random N`, `crypto hash ALG FILE | -s TEXT`
(`tools/crypto/README.md`).

## Notes

- AES-CTR / CBC: `iv` is updated in place; a stream continues across calls
  when every call but the last is a multiple of 16 bytes.
- AEAD nonces are 12 bytes; GCM tags 4..16 bytes, ChaCha20-Poly1305 16; the
  decrypt functions check the tag before anything is decrypted.
- The software port is plain C without tables of precomputed data: small
  (about 17 KB loaded on Cortex-M) and not the fastest - a PBKDF2 of WPA2's
  4096 SHA-1 iterations is the most expensive thing a caller is likely to ask.

## Not in 1.0

Asymmetric operations - ECDH, ECDSA, RSA (what dmtls needs) - come in 1.1 as
new functions of the same shape; their capability bits (`DMCRYPTO_CAP_ECDH`,
`_ECDSA`, `_RSA`) are reserved. Keys are passed by value; opaque key handles
(for keys that must not leave a secure element) can be added later without
changing these functions.
