/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "crypto_hash_sha512.h"
#include "utils.h"

#include <sys/types.h>

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Avoid namespace collisions with BSD <sys/endian.h>. */
#define be64dec _sha512_be64dec
#define be64enc _sha512_be64enc

static inline uint64_t
be64dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint64_t)(p[7]) + ((uint64_t)(p[6]) << 8) +
            ((uint64_t)(p[5]) << 16) + ((uint64_t)(p[4]) << 24) +
            ((uint64_t)(p[3]) << 32) + ((uint64_t)(p[2]) << 40) +
            ((uint64_t)(p[1]) << 48) + ((uint64_t)(p[0]) << 56));
}

static inline void
be64enc(void *pp, uint64_t x)
{
    uint8_t *p = (uint8_t *)pp;

    p[7] = x & 0xff;
    p[6] = (x >> 8) & 0xff;
    p[5] = (x >> 16) & 0xff;
    p[4] = (x >> 24) & 0xff;
    p[3] = (x >> 32) & 0xff;
    p[2] = (x >> 40) & 0xff;
    p[1] = (x >> 48) & 0xff;
    p[0] = (x >> 56) & 0xff;
}

static void
be64enc_vect(unsigned char *dst, const uint64_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 8; i++) {
        be64enc(dst + i * 8, src[i]);
    }
}

static void
be64dec_vect(uint64_t *dst, const unsigned char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 8; i++) {
        dst[i] = be64dec(src + i * 8);
    }
}

#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define SHR(x, n)       (x >> n)
#define ROTR(x, n)      ((x >> n) | (x << (64 - n)))
#define S0(x)           (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x)           (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define s0(x)           (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define s1(x)           (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

#define RND(a, b, c, d, e, f, g, h, k)              \
    t0 = h + S1(e) + Ch(e, f, g) + k;               \
    t1 = S0(a) + Maj(a, b, c);                      \
    d += t0;                                        \
    h  = t0 + t1;

#define RNDr(S, W, i, k)                    \
    RND(S[(80 - i) % 8], S[(81 - i) % 8],   \
        S[(82 - i) % 8], S[(83 - i) % 8],   \
        S[(84 - i) % 8], S[(85 - i) % 8],   \
        S[(86 - i) % 8], S[(87 - i) % 8],   \
        W[i] + k)

static void
SHA512_Transform(uint64_t *state, const unsigned char block[128])
{
    uint64_t W[80];
    uint64_t S[8];
    uint64_t t0, t1;
    int i;

    be64dec_vect(W, block, 128);
    for (i = 16; i < 80; i++) {
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
    }

    memcpy(S, state, 64);

    RNDr(S, W, 0, 0x428a2f98d728ae22ULL);
    RNDr(S, W, 1, 0x7137449123ef65cdULL);
    RNDr(S, W, 2, 0xb5c0fbcfec4d3b2fULL);
    RNDr(S, W, 3, 0xe9b5dba58189dbbcULL);
    RNDr(S, W, 4, 0x3956c25bf348b538ULL);
    RNDr(S, W, 5, 0x59f111f1b605d019ULL);
    RNDr(S, W, 6, 0x923f82a4af194f9bULL);
    RNDr(S, W, 7, 0xab1c5ed5da6d8118ULL);
    RNDr(S, W, 8, 0xd807aa98a3030242ULL);
    RNDr(S, W, 9, 0x12835b0145706fbeULL);
    RNDr(S, W, 10, 0x243185be4ee4b28cULL);
    RNDr(S, W, 11, 0x550c7dc3d5ffb4e2ULL);
    RNDr(S, W, 12, 0x72be5d74f27b896fULL);
    RNDr(S, W, 13, 0x80deb1fe3b1696b1ULL);
    RNDr(S, W, 14, 0x9bdc06a725c71235ULL);
    RNDr(S, W, 15, 0xc19bf174cf692694ULL);
    RNDr(S, W, 16, 0xe49b69c19ef14ad2ULL);
    RNDr(S, W, 17, 0xefbe4786384f25e3ULL);
    RNDr(S, W, 18, 0x0fc19dc68b8cd5b5ULL);
    RNDr(S, W, 19, 0x240ca1cc77ac9c65ULL);
    RNDr(S, W, 20, 0x2de92c6f592b0275ULL);
    RNDr(S, W, 21, 0x4a7484aa6ea6e483ULL);
    RNDr(S, W, 22, 0x5cb0a9dcbd41fbd4ULL);
    RNDr(S, W, 23, 0x76f988da831153b5ULL);
    RNDr(S, W, 24, 0x983e5152ee66dfabULL);
    RNDr(S, W, 25, 0xa831c66d2db43210ULL);
    RNDr(S, W, 26, 0xb00327c898fb213fULL);
    RNDr(S, W, 27, 0xbf597fc7beef0ee4ULL);
    RNDr(S, W, 28, 0xc6e00bf33da88fc2ULL);
    RNDr(S, W, 29, 0xd5a79147930aa725ULL);
    RNDr(S, W, 30, 0x06ca6351e003826fULL);
    RNDr(S, W, 31, 0x142929670a0e6e70ULL);
    RNDr(S, W, 32, 0x27b70a8546d22ffcULL);
    RNDr(S, W, 33, 0x2e1b21385c26c926ULL);
    RNDr(S, W, 34, 0x4d2c6dfc5ac42aedULL);
    RNDr(S, W, 35, 0x53380d139d95b3dfULL);
    RNDr(S, W, 36, 0x650a73548baf63deULL);
    RNDr(S, W, 37, 0x766a0abb3c77b2a8ULL);
    RNDr(S, W, 38, 0x81c2c92e47edaee6ULL);
    RNDr(S, W, 39, 0x92722c851482353bULL);
    RNDr(S, W, 40, 0xa2bfe8a14cf10364ULL);
    RNDr(S, W, 41, 0xa81a664bbc423001ULL);
    RNDr(S, W, 42, 0xc24b8b70d0f89791ULL);
    RNDr(S, W, 43, 0xc76c51a30654be30ULL);
    RNDr(S, W, 44, 0xd192e819d6ef5218ULL);
    RNDr(S, W, 45, 0xd69906245565a910ULL);
    RNDr(S, W, 46, 0xf40e35855771202aULL);
    RNDr(S, W, 47, 0x106aa07032bbd1b8ULL);
    RNDr(S, W, 48, 0x19a4c116b8d2d0c8ULL);
    RNDr(S, W, 49, 0x1e376c085141ab53ULL);
    RNDr(S, W, 50, 0x2748774cdf8eeb99ULL);
    RNDr(S, W, 51, 0x34b0bcb5e19b48a8ULL);
    RNDr(S, W, 52, 0x391c0cb3c5c95a63ULL);
    RNDr(S, W, 53, 0x4ed8aa4ae3418acbULL);
    RNDr(S, W, 54, 0x5b9cca4f7763e373ULL);
    RNDr(S, W, 55, 0x682e6ff3d6b2b8a3ULL);
    RNDr(S, W, 56, 0x748f82ee5defb2fcULL);
    RNDr(S, W, 57, 0x78a5636f43172f60ULL);
    RNDr(S, W, 58, 0x84c87814a1f0ab72ULL);
    RNDr(S, W, 59, 0x8cc702081a6439ecULL);
    RNDr(S, W, 60, 0x90befffa23631e28ULL);
    RNDr(S, W, 61, 0xa4506cebde82bde9ULL);
    RNDr(S, W, 62, 0xbef9a3f7b2c67915ULL);
    RNDr(S, W, 63, 0xc67178f2e372532bULL);
    RNDr(S, W, 64, 0xca273eceea26619cULL);
    RNDr(S, W, 65, 0xd186b8c721c0c207ULL);
    RNDr(S, W, 66, 0xeada7dd6cde0eb1eULL);
    RNDr(S, W, 67, 0xf57d4f7fee6ed178ULL);
    RNDr(S, W, 68, 0x06f067aa72176fbaULL);
    RNDr(S, W, 69, 0x0a637dc5a2c898a6ULL);
    RNDr(S, W, 70, 0x113f9804bef90daeULL);
    RNDr(S, W, 71, 0x1b710b35131c471bULL);
    RNDr(S, W, 72, 0x28db77f523047d84ULL);
    RNDr(S, W, 73, 0x32caab7b40c72493ULL);
    RNDr(S, W, 74, 0x3c9ebe0a15c9bebcULL);
    RNDr(S, W, 75, 0x431d67c49c100d4cULL);
    RNDr(S, W, 76, 0x4cc5d4becb3e42b6ULL);
    RNDr(S, W, 77, 0x597f299cfc657e2aULL);
    RNDr(S, W, 78, 0x5fcb6fab3ad6faecULL);
    RNDr(S, W, 79, 0x6c44198c4a475817ULL);

    for (i = 0; i < 8; i++) {
        state[i] += S[i];
    }

    sodium_memzero((void *) W, sizeof W);
    sodium_memzero((void *) S, sizeof S);
    sodium_memzero((void *) &t0, sizeof t0);
    sodium_memzero((void *) &t1, sizeof t1);
}

static unsigned char PAD[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void
SHA512_Pad(crypto_hash_sha512_state *state)
{
    unsigned char len[16];
    uint64_t r, plen;

    be64enc_vect(len, state->count, 16);

    r = (state->count[1] >> 3) & 0x7f;
    plen = (r < 112) ? (112 - r) : (240 - r);
    crypto_hash_sha512_update(state, PAD, (unsigned long long) plen);

    crypto_hash_sha512_update(state, len, 16);
}

int
crypto_hash_sha512_init(crypto_hash_sha512_state *state)
{
    static const uint64_t sha512_initstate[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    state->count[0] = state->count[1] = (uint64_t) 0U;
    memcpy(state->state, sha512_initstate, sizeof sha512_initstate);

    return 0;
}

int
crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                          const unsigned char *in,
                          unsigned long long inlen)
{
    uint64_t bitlen[2];
    uint64_t r;
    const unsigned char *src = in;

    r = (state->count[1] >> 3) & 0x7f;

    bitlen[1] = ((uint64_t)inlen) << 3;
    bitlen[0] = ((uint64_t)inlen) >> 61;

    /* LCOV_EXCL_START */
    if ((state->count[1] += bitlen[1]) < bitlen[1]) {
        state->count[0]++;
    }
    /* LCOV_EXCL_STOP */
    state->count[0] += bitlen[0];

    if (inlen < 128 - r) {
        memcpy(&state->buf[r], src, inlen);
        return 0;
    }
    memcpy(&state->buf[r], src, 128 - r);
    SHA512_Transform(state->state, state->buf);
    src += 128 - r;
    inlen -= 128 - r;

    while (inlen >= 128) {
        SHA512_Transform(state->state, src);
        src += 128;
        inlen -= 128;
    }
    memcpy(state->buf, src, inlen); /* inlen < 128 */

    return 0;
}

int
crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                         unsigned char *out)
{
    SHA512_Pad(state);
    be64enc_vect(out, state->state, 64);
    sodium_memzero((void *) state, sizeof *state);

    return 0;
}

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                   unsigned long long inlen)
{
    crypto_hash_sha512_state state;

    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, in, inlen);
    crypto_hash_sha512_final(&state, out);

    return 0;
}