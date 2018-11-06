#ifndef FE_H
#define FE_H

#include "ed25519_ref10.h"

typedef int32_t fe[10];

/*
fe means field element.
Here the field is \Z/(2^255-19).
An element t, entries t[0]...t[9], represents the integer
t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
Bounds on each t[i] vary depending on context.
*/

#define fe_frombytes crypto_sign_ed25519_ref10_fe_frombytes
#define fe_tobytes crypto_sign_ed25519_ref10_fe_tobytes
#define fe_copy crypto_sign_ed25519_ref10_fe_copy
#define fe_isnonzero crypto_sign_ed25519_ref10_fe_isnonzero
#define fe_isnegative crypto_sign_ed25519_ref10_fe_isnegative
#define fe_0 crypto_sign_ed25519_ref10_fe_0
#define fe_1 crypto_sign_ed25519_ref10_fe_1
#define fe_cswap crypto_sign_ed25519_ref10_fe_cswap
#define fe_cmov crypto_sign_ed25519_ref10_fe_cmov
#define fe_add crypto_sign_ed25519_ref10_fe_add
#define fe_sub crypto_sign_ed25519_ref10_fe_sub
#define fe_neg crypto_sign_ed25519_ref10_fe_neg
#define fe_mul crypto_sign_ed25519_ref10_fe_mul
#define fe_sq crypto_sign_ed25519_ref10_fe_sq
#define fe_sq2 crypto_sign_ed25519_ref10_fe_sq2
#define fe_mul121666 crypto_sign_ed25519_ref10_fe_mul121666
#define fe_invert crypto_sign_ed25519_ref10_fe_invert
#define fe_pow22523 crypto_sign_ed25519_ref10_fe_pow22523

extern void fe_frombytes(fe,const unsigned char *);
extern void fe_tobytes(unsigned char *,const fe);

extern void fe_copy(fe,const fe);
extern int fe_isnonzero(const fe);
extern int fe_isnegative(const fe);
extern void fe_0(fe);
extern void fe_1(fe);
extern void fe_cswap(fe,fe,unsigned int);
extern void fe_cmov(fe,const fe,unsigned int);

extern void fe_add(fe,const fe,const fe);
extern void fe_sub(fe,const fe,const fe);
extern void fe_neg(fe,const fe);
extern void fe_mul(fe,const fe,const fe);
extern void fe_sq(fe,const fe);
extern void fe_sq2(fe,const fe);
extern void fe_mul121666(fe,const fe);
extern void fe_invert(fe,const fe);
extern void fe_pow22523(fe,const fe);

#endif
