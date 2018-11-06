#include "crypto_hash_sha512.h"

#define SHA2_CTX crypto_hash_sha512_state

#ifdef SHA512_DIGEST_LENGTH
# undef SHA512_DIGEST_LENGTH
#endif
#define SHA512_DIGEST_LENGTH crypto_hash_sha512_BYTES

inline void SHA512Init(SHA2_CTX* ctx) { crypto_hash_sha512_init(ctx); }
inline void SHA512Update(SHA2_CTX* ctx, const void *in, size_t inlen) { crypto_hash_sha512_update(ctx, in, inlen); }
inline void SHA512Final(uint8_t* out, SHA2_CTX* ctx) { crypto_hash_sha512_final(ctx, out); }

