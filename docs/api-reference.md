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

## Entropy

dmcrypto has no RNG of its own and depends on no RNG driver. The application
(a boot script, a service) gives it a `dmcrypto_entropy_fn_t` - e.g. a small
function over `dmrng_fill()`:

    static int rng(void *context, void *buffer, size_t size)
    {
        (void)context;
        return dmrng_fill(buffer, size);        /* 0 or a negative errno */
    }
    dmcrypto_set_entropy(rng, NULL);

The function must be a plain function of the registering module (not an entry
in a table of initialized data: the dmod loader does not relocate those).
`get_capabilities` reports `DMCRYPTO_CAP_RANDOM` while a source is set.

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
