#include "dmod.h"
#include "dmcrypto.h"
#include "dmcrypto_ioctl.h"
#include <errno.h>
#include <string.h>

/**
 * @brief The crypto of the shell: what the port has, random bytes, hashes.
 *
 * Uses dmcrypto's API directly (the hashes), and the /dev/crypto node for
 * `info`. The random bytes are the entropy source dmcrypto was given (the
 * driver's `entropy=` in its ini).
 */

#define DEFAULT_DEVICE      "/dev/crypto"
#define RANDOM_MAX          1024
#define READ_CHUNK          256

static void print_usage(const char *name)
{
    Dmod_Printf("Usage: %s COMMAND [ARGS]\n", name);
    Dmod_Printf("  info [DEVICE]                the port and what it has (default %s)\n", DEFAULT_DEVICE);
    Dmod_Printf("  random N                     N random bytes (1..%d) in hex\n", RANDOM_MAX);
    Dmod_Printf("  hash ALG FILE | -s TEXT      the digest of a file or a text: sha1 sha256 sha384 sha512\n");
}

static void print_hex(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        Dmod_Printf("%02x", data[i]);
    Dmod_Printf("\n");
}

static void print_cap(const dmcrypto_caps_t *caps, uint32_t bit, const char *name)
{
    if ((caps->supported & bit) != 0)
        Dmod_Printf("  %-22s %s\n", name, (caps->accelerated & bit) != 0 ? "hardware" : "software");
}

static int show_info(const char *device)
{
    dmcrypto_caps_t caps;
    void *dev = Dmod_FileOpen(device, "r");

    if (dev == NULL)
    {
        Dmod_Printf("crypto: cannot open %s\n", device);
        return -1;
    }
    int ret = Dmod_Ioctl(dev, DMCRYPTO_IOCTL_GET_CAPABILITIES, &caps);
    Dmod_FileClose(dev);
    if (ret != 0)
        return ret;

    Dmod_Printf("port: %s\n", caps.port_name);
    print_cap(&caps, DMCRYPTO_CAP_HASH_SHA1, "SHA-1");
    print_cap(&caps, DMCRYPTO_CAP_HASH_SHA256, "SHA-256");
    print_cap(&caps, DMCRYPTO_CAP_HASH_SHA384, "SHA-384");
    print_cap(&caps, DMCRYPTO_CAP_HASH_SHA512, "SHA-512");
    print_cap(&caps, DMCRYPTO_CAP_HMAC, "HMAC");
    print_cap(&caps, DMCRYPTO_CAP_PBKDF2, "PBKDF2");
    print_cap(&caps, DMCRYPTO_CAP_HKDF, "HKDF");
    print_cap(&caps, DMCRYPTO_CAP_CIPHER_AES_CBC, "AES-CBC");
    print_cap(&caps, DMCRYPTO_CAP_CIPHER_AES_CTR, "AES-CTR");
    print_cap(&caps, DMCRYPTO_CAP_AEAD_AES_GCM, "AES-GCM");
    print_cap(&caps, DMCRYPTO_CAP_AEAD_CHACHA20_POLY1305, "ChaCha20-Poly1305");
    if ((caps.supported & DMCRYPTO_CAP_RANDOM) != 0)
        print_cap(&caps, DMCRYPTO_CAP_RANDOM, "random");
    else
        Dmod_Printf("  %-22s no entropy source set\n", "random");
    return 0;
}

static int do_random(const char *count)
{
    uint8_t bytes[RANDOM_MAX];
    int n = 0;
    const char *p = count;

    for (; *p >= '0' && *p <= '9' && n <= RANDOM_MAX; p++)
        n = n * 10 + (*p - '0');
    if (p == count || *p != '\0')
        n = 0;

    if (n < 1 || n > RANDOM_MAX)
    {
        Dmod_Printf("crypto: random takes 1..%d bytes\n", RANDOM_MAX);
        return -1;
    }
    int ret = dmcrypto_random(bytes, (size_t)n);
    if (ret != 0)
    {
        Dmod_Printf("crypto: no random bytes (%d) - %s\n", ret,
                    ret == -ENODEV ? "no entropy source (see the driver's ini: entropy=)" : "the source failed");
        return ret;
    }
    print_hex(bytes, (size_t)n);
    dmcrypto_wipe(bytes, sizeof(bytes));
    return 0;
}

static bool algorithm(const char *name, dmcrypto_hash_alg_t *alg)
{
    if (strcmp(name, "sha1") == 0)   { *alg = DMCRYPTO_HASH_SHA1;   return true; }
    if (strcmp(name, "sha256") == 0) { *alg = DMCRYPTO_HASH_SHA256; return true; }
    if (strcmp(name, "sha384") == 0) { *alg = DMCRYPTO_HASH_SHA384; return true; }
    if (strcmp(name, "sha512") == 0) { *alg = DMCRYPTO_HASH_SHA512; return true; }
    return false;
}

static int do_hash(const char *name, const char *source, bool is_text)
{
    dmcrypto_hash_alg_t alg;
    dmcrypto_hash_t hash = NULL;
    uint8_t digest[DMCRYPTO_HASH_MAX_SIZE];
    size_t length = 0;

    if (!algorithm(name, &alg))
    {
        Dmod_Printf("crypto: unknown algorithm '%s' (sha1 sha256 sha384 sha512)\n", name);
        return -1;
    }

    int ret = dmcrypto_hash_start(alg, &hash);
    if (ret != 0)
    {
        Dmod_Printf("crypto: %s is not in this port (%d)\n", name, ret);
        return ret;
    }

    if (is_text)
    {
        ret = dmcrypto_hash_update(hash, source, strlen(source));
    }
    else
    {
        void *file = Dmod_FileOpen(source, "r");
        uint8_t chunk[READ_CHUNK];
        size_t got;

        if (file == NULL)
        {
            dmcrypto_hash_abort(hash);
            Dmod_Printf("crypto: cannot open %s\n", source);
            return -1;
        }
        while (ret == 0 && (got = Dmod_FileRead(chunk, 1, sizeof(chunk), file)) > 0)
            ret = dmcrypto_hash_update(hash, chunk, got);
        Dmod_FileClose(file);
    }

    if (ret != 0)
    {
        dmcrypto_hash_abort(hash);
        return ret;
    }
    ret = dmcrypto_hash_finish(hash, digest, sizeof(digest), &length);
    if (ret == 0)
        print_hex(digest, length);
    return ret;
}

int main(int argc, char **argv)
{
    const char *command = (argc > 1) ? argv[1] : "info";
    int ret;

    if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "help") == 0)
    {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(command, "info") == 0)
        ret = show_info(argc > 2 ? argv[2] : DEFAULT_DEVICE);
    else if (strcmp(command, "random") == 0 && argc > 2)
        ret = do_random(argv[2]);
    else if (strcmp(command, "hash") == 0 && argc > 4 && strcmp(argv[3], "-s") == 0)
        ret = do_hash(argv[2], argv[4], true);
    else if (strcmp(command, "hash") == 0 && argc > 3 && strcmp(argv[3], "-s") != 0)
        ret = do_hash(argv[2], argv[3], false);
    else
    {
        print_usage(argv[0]);
        return -1;
    }

    if (ret != 0 && ret != -1)
        Dmod_Printf("crypto: %s failed (%d)\n", command, ret);
    return ret;
}
