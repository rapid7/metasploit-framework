#include <string.h>
#include "ed25519_ref10.h"
#include "sha512.h"
#include "ge.h"

int crypto_sign_ed25519_ref10_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    ge_p3 A;

    crypto_hash_sha512(sk, seed, 32);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    ge_scalarmult_base(&A, sk);
    ge_p3_tobytes(pk, &A);

    memmove(sk, seed, 32);
    memmove(sk + 32, pk, 32);

    return 0;
}
