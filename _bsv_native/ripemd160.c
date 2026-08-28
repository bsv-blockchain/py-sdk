/*
 * Project-maintained implementation of RIPEMD-160.
 *
 * Algorithm specification:
 * H. Dobbertin, A. Bosselaers, B. Preneel,
 * "RIPEMD-160: A Strengthened Version of RIPEMD" (corrected 1996).
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
 *
 * Pseudocode and official test vectors:
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 * https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd160.txt
 *
 * This implementation was authored in this repository with AI assistance.
 * The links above identify the algorithm and its conformance vectors; they are
 * not source-code provenance, and this file is not a vendored copy of the
 * sample C implementation published by Antoon Bosselaers.
 */

#include "ripemd160.h"

#include <stdint.h>
#include <string.h>

static uint32_t rmd_rol(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

static void rmd160_compress(uint32_t h[5], const unsigned char blk[64]) {
    /* Message-word selections r/r' from the specification. */
    static const unsigned char rl[80] = {
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
         7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
         3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
         1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
         4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
    };
    static const unsigned char rr[80] = {
         5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
         6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
        15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
         8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
        12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
    };

    /* Rotation counts s/s' from the specification. */
    static const unsigned char sl[80] = {
        11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
         7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
        11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
        11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
         9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
    };
    static const unsigned char sr[80] = {
         8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
         9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
         9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
        15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
         8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
    };

    uint32_t w[16];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)blk[4*i] | ((uint32_t)blk[4*i+1] << 8) |
               ((uint32_t)blk[4*i+2] << 16) | ((uint32_t)blk[4*i+3] << 24);

    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
    uint32_t t;

    /* The left and right lines correspond directly to the two specification
     * lanes. Unsigned 32-bit overflow is the required modular arithmetic. */
    for (int j = 0; j < 80; j++) {
        uint32_t fl, fr, kl_v, kr_v;
        switch (j >> 4) {
        case 0: fl = bl ^ cl ^ dl;
                fr = br ^ (cr | ~dr);
                kl_v = 0x00000000u; kr_v = 0x50A28BE6u; break;
        case 1: fl = (bl & cl) | (~bl & dl);
                fr = (br & dr) | (cr & ~dr);
                kl_v = 0x5A827999u; kr_v = 0x5C4DD124u; break;
        case 2: fl = (bl | ~cl) ^ dl;
                fr = (br | ~cr) ^ dr;
                kl_v = 0x6ED9EBA1u; kr_v = 0x6D703EF3u; break;
        case 3: fl = (bl & dl) | (cl & ~dl);
                fr = (br & cr) | (~br & dr);
                kl_v = 0x8F1BBCDCu; kr_v = 0x7A6D76E9u; break;
        default:fl = bl ^ (cl | ~dl);
                fr = br ^ cr ^ dr;
                kl_v = 0xA953FD4Eu; kr_v = 0x00000000u; break;
        }
        t = rmd_rol(al + fl + w[rl[j]] + kl_v, sl[j]) + el;
        al = el; el = dl; dl = rmd_rol(cl, 10); cl = bl; bl = t;

        t = rmd_rol(ar + fr + w[rr[j]] + kr_v, sr[j]) + er;
        ar = er; er = dr; dr = rmd_rol(cr, 10); cr = br; br = t;
    }

    /* Parallel-lane combination from the final specification step. */
    t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

void bsv_ripemd160(const unsigned char *input, size_t length,
                   unsigned char output[20]) {
    uint32_t h[5] = {
        0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u
    };
    const unsigned char *ptr = input;
    size_t remaining = length;

    while (remaining >= 64) {
        rmd160_compress(h, ptr);
        ptr += 64;
        remaining -= 64;
    }

    unsigned char pad[128];
    memset(pad, 0, sizeof(pad));
    if (remaining > 0) memcpy(pad, ptr, remaining);
    pad[remaining] = 0x80;

    size_t padlen = (remaining < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)length * 8;
    pad[padlen - 8] = (unsigned char)(bits);
    pad[padlen - 7] = (unsigned char)(bits >> 8);
    pad[padlen - 6] = (unsigned char)(bits >> 16);
    pad[padlen - 5] = (unsigned char)(bits >> 24);
    pad[padlen - 4] = (unsigned char)(bits >> 32);
    pad[padlen - 3] = (unsigned char)(bits >> 40);
    pad[padlen - 2] = (unsigned char)(bits >> 48);
    pad[padlen - 1] = (unsigned char)(bits >> 56);

    rmd160_compress(h, pad);
    if (padlen > 64) rmd160_compress(h, pad + 64);

    for (int i = 0; i < 5; i++) {
        output[4*i]     = (unsigned char)(h[i]);
        output[4*i + 1] = (unsigned char)(h[i] >> 8);
        output[4*i + 2] = (unsigned char)(h[i] >> 16);
        output[4*i + 3] = (unsigned char)(h[i] >> 24);
    }
}
