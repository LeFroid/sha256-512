#ifndef __SHA_COMMON_H
#define __SHA_COMMON_H

#include <stdint.h>

// Padded message structure, contains message length + message 
typedef struct PaddedMsg {
    size_t length;
    uint8_t *msg;
} PaddedMsg;

// Swaps the byte order of the 32 bit unsigned integer x
static inline void endianSwap32(uint32_t *x)
{
    char *y = (char*)x;
    for (size_t low = 0, high = sizeof(uint32_t) - 1; high > low; ++low, --high)
    {
        y[low]  ^= y[high];
        y[high] ^= y[low];
        y[low]  ^= y[high];
    }
}

// Swaps the byte order of the 64 bit unsigned integer x
static inline void endianSwap64(uint64_t *x)
{
    char *y = (char*)x;
    for (size_t low = 0, high = sizeof(uint64_t) - 1; high > low; ++low, --high)
    {
        y[low]  ^= y[high];
        y[high] ^= y[low];
        y[low]  ^= y[high];
    }
}

// Swaps the byte order of the 128 bit unsigned integer x
static inline void endianSwap128(__uint128_t *x)
{
    char *y = (char*)x;
    for (size_t low = 0, high = sizeof(__uint128_t) - 1; high > low; ++low, --high)
    {
        y[low]  ^= y[high];
        y[high] ^= y[low];
        y[low]  ^= y[high];
    }
}

#endif //__SHA_COMMON_H

