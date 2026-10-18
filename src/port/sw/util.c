#include "sw.h"

void sw_wipe(void *buffer, size_t size)
{
    volatile uint8_t *p = buffer;

    for (size_t i = 0; i < size; i++)
        p[i] = 0;
}

int sw_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    uint8_t difference = 0;

    for (size_t i = 0; i < size; i++)
        difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0;
}
