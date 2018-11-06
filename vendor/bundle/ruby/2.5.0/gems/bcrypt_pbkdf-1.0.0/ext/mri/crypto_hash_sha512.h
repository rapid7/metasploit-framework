#include <stdint.h>

typedef struct crypto_hash_sha512_state {
    uint64_t      state[8];
    uint64_t      count[2];
    unsigned char buf[128];
} crypto_hash_sha512_state;

#define crypto_hash_sha512_BYTES 64U
int crypto_hash_sha512_init(crypto_hash_sha512_state *state);
int crypto_hashblocks_sha512(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen);
int
crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                          const unsigned char *in,
                          unsigned long long inlen);
int
crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                         unsigned char *out);

