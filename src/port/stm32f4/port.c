#define DMOD_ENABLE_REGISTRATION    ON
#include "dmcrypto_port.h"
#include "dmod.h"
#include "../stm32_common/stm32_common.h"

/*
 * dmcrypto port for STM32F4 (CRYP and HASH on the F415/F417/F437/F439 and the like).
 * The algorithms and the API are stm32_common's; this file is the family's
 * module lifecycle and what differs from the other families.
 */

/* ---- DMOD lifecycle ---- */

int dmod_init(const Dmod_Config_t *Config)
{
    (void)Config;
    Dmod_Printf("dmcrypto port module initialized (%s)\n", DMCRYPTO_PORT_LABEL);
    return stm32_crypto_common_init();
}

int dmod_deinit(void)
{
    Dmod_Printf("dmcrypto port module deinitialized (%s)\n", DMCRYPTO_PORT_LABEL);
    stm32_crypto_common_deinit();
    return 0;
}
