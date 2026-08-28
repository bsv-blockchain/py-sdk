#ifndef BSV_NATIVE_RIPEMD160_H
#define BSV_NATIVE_RIPEMD160_H

#include <stddef.h>

/* input may be NULL only when length is zero; output must point to 20 bytes. */
void bsv_ripemd160(const unsigned char *input, size_t length,
                   unsigned char output[20]);

#endif /* BSV_NATIVE_RIPEMD160_H */
