#ifndef DMCRYPTO_STM32_COMMON_H
#define DMCRYPTO_STM32_COMMON_H

/*
 * What every STM32 family's dmcrypto port shares: the CRYP (AES, GCM),
 * HASH (SHA, HMAC) and RNG peripheral drivers - their register layouts
 * differ between families only in a few places, which the family's port.c
 * resolves through the hooks below (as in dmspi's stm32_common).
 */

int  stm32_crypto_common_init(void);
void stm32_crypto_common_deinit(void);

/* TODO(implementation): per-family hooks, e.g. which peripherals the family
 * has (STM32F7: CRYP and HASH only on some chips - the manifest decides which
 * chips get this port at all), clock enable bits, DMA channels. */

#endif /* DMCRYPTO_STM32_COMMON_H */
