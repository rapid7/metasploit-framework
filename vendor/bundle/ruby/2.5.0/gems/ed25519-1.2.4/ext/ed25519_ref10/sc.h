#ifndef SC_H
#define SC_H

#include <stdint.h>

/*
The set of scalars is \Z/l
where l = 2^252 + 27742317777372353535851937790883648493.
*/

#define sc_reduce crypto_sign_ed25519_ref10_sc_reduce
#define sc_muladd crypto_sign_ed25519_ref10_sc_muladd

extern void sc_reduce(uint8_t *);
extern void sc_muladd(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *);

#endif
