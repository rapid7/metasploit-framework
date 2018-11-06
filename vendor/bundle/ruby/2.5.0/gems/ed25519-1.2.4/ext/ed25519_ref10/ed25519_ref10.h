#ifndef ED25519_REF10_H
#define ED25519_REF10_H

#include <stdint.h>

#define SECRETKEYBYTES 64
#define PUBLICKEYBYTES 32
#define SIGNATUREBYTES 64

#define ED25519_KEYSIZE_BYTES 32
typedef uint8_t ED25519_KEY[ED25519_KEYSIZE_BYTES];

/* Generate an Ed25519 keypair from a seed value */
int crypto_sign_ed25519_ref10_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

/* Compute an Ed25519 signature over the given message */
int crypto_sign_ed25519_ref10(
  uint8_t *sm, uint64_t *smlen,
  const uint8_t *m, uint64_t mlen,
  const uint8_t *sk
);

/* Verify the given signature is authentic */
int crypto_sign_open_ed25519_ref10(
  uint8_t *m, uint64_t *mlen,
  const uint8_t *sm, uint64_t smlen,
  const uint8_t *pk
);

/* Constant-time comparison function */
int crypto_verify_32(const uint8_t *x,const uint8_t *y);

#endif /* ED25519_REF10_H */
