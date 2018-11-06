#include <string.h>
#include "sha512.h"
#include "ed25519_ref10.h"
#include "ge.h"
#include "sc.h"

int crypto_sign_open_ed25519_ref10(
  uint8_t *m, uint64_t *mlen,
  const uint8_t *sm, uint64_t smlen,
  const uint8_t *pk
)
{
  unsigned char pkcopy[32];
  unsigned char rcopy[32];
  unsigned char scopy[32];
  unsigned char h[64];
  unsigned char rcheck[32];
  ge_p3 A;
  ge_p2 R;

  if (smlen < 64) goto badsig;
  if (sm[63] & 224) goto badsig;
  if (ge_frombytes_negate_vartime(&A,pk) != 0) goto badsig;

  memmove(pkcopy,pk,32);
  memmove(rcopy,sm,32);
  memmove(scopy,sm + 32,32);

  memmove(m,sm,smlen);
  memmove(m + 32,pkcopy,32);
  crypto_hash_sha512(h,m,smlen);
  sc_reduce(h);

  ge_double_scalarmult_vartime(&R,h,&A,scopy);
  ge_tobytes(rcheck,&R);
  if (crypto_verify_32(rcheck,rcopy) == 0) {
    memmove(m,m + 64,smlen - 64);
    memset(m + smlen - 64,0,64);
    *mlen = smlen - 64;
    return 0;
  }

badsig:
  *mlen = -1;
  memset(m,0,smlen);
  return -1;
}
