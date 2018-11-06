#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>

int crypto_hash_sha512(uint8_t *out,const uint8_t *in,uint64_t inlen);

#endif /* SHA512_H */
