#include <stdint.h>

#include "hash.h"


uint32_t
crap8_hash(const uint8_t *key, uint32_t len)
{
#define c8fold(a, b, y, z) {                      \
    p = (uint32_t)(a) * (uint64_t)(b);            \
    y ^= (uint32_t)p;                             \
    z ^= (uint32_t)(p >> 32); }
#define c8mix(in) { h *= m; c8fold(in, m, k, h ); }

    const uint32_t m = 0x83d2e73b;
    const uint32_t n = 0x97e1cc59;
    const uint32_t *key4 = (const uint32_t *)key;
    uint32_t h = len;
    uint32_t k = n + len;
    uint64_t p;

    while (len >= 8) {
        c8mix(key4[0]);
        c8mix(key4[1]);
        key4 += 2;
        len -= 8;
    }

    if (len >= 4) {
        c8mix(key4[0]) key4 += 1;
        len -= 4;
    }
    if (len > 0)
        c8mix(key4[0] & ((1 << (len * 8)) - 1));

    c8fold(h ^ k, n, k, k);
    return k;
}
