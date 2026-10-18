#define DMOD_ENABLE_REGISTRATION ON
#include "dmod_test.h"
#include "dmcrypto.h"
#include <string.h>

/* The interface only: the algorithms are the port's (see its own tests). */

DMOD_TEST_STEP(equal_compares_all_bytes)
{
    const uint8_t a[4] = { 1, 2, 3, 4 };
    const uint8_t same[4] = { 1, 2, 3, 4 };
    const uint8_t last[4] = { 1, 2, 3, 5 };
    const uint8_t first[4] = { 0, 2, 3, 4 };

    DMOD_TEST_EXPECT_TRUE(dmcrypto_equal(a, same, sizeof(a)));
    DMOD_TEST_EXPECT_FALSE(dmcrypto_equal(a, last, sizeof(a)));
    DMOD_TEST_EXPECT_FALSE(dmcrypto_equal(a, first, sizeof(a)));
    DMOD_TEST_EXPECT_TRUE(dmcrypto_equal(a, last, 0));
}

DMOD_TEST_STEP(wipe_zeroes_the_buffer)
{
    uint8_t secret[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const uint8_t zero[8] = { 0 };

    dmcrypto_wipe(secret, sizeof(secret));
    DMOD_TEST_EXPECT_EQ(memcmp(secret, zero, sizeof(zero)), 0);
    dmcrypto_wipe(NULL, 4);     /* Must not crash */
}

DMOD_TEST_STEP(capabilities_name_the_port)
{
    dmcrypto_caps_t caps;

    memset(&caps, 0xFF, sizeof(caps));
    DMOD_TEST_EXPECT_EQ(dmcrypto_get_capabilities(&caps), 0);
    DMOD_TEST_EXPECT_TRUE(caps.port_name[0] != '\0');
    DMOD_TEST_EXPECT_EQ(caps.accelerated & ~caps.supported, 0);     /* Hardware does what the port has */
}
